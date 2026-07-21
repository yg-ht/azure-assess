# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build honest assessment coverage denominators from collected source data."""

from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from azure_findings_reporting import extract_local_assets, retain_asset


COVERAGE_SCHEMA_VERSION = "1.0"
COVERAGE_STATUSES = {"proxy", "unavailable", "not_implemented"}
ASSET_KIND_PRIORITY = {
    "azure_resource": 0,
    "entra_principal": 1,
    "azure_subscription": 2,
    "azure_named_resource": 3,
    "assessment_scope": 4,
}


def payload_records(payload: Any) -> List[Any]:
    """Return top-level records from common Azure and Graph payload shapes."""
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, Mapping) and isinstance(payload.get("value"), list):
        return payload["value"]
    return [payload]


def catalog_item_for_source(
    catalog: Optional[Mapping[str, Any]],
    source_file: str,
) -> Optional[Mapping[str, Any]]:
    """Find a loaded catalog item by its source filename."""
    filename = Path(source_file).name
    for item in (catalog or {}).values():
        if not isinstance(item, Mapping) or not item.get("path"):
            continue
        if Path(item["path"]).name == filename:
            return item
    return None


def select_primary_source(
    source_files: Iterable[str],
    catalog: Optional[Mapping[str, Any]],
) -> Tuple[Optional[str], List[Any]]:
    """Choose the first populated source, falling back to the first loaded source."""
    first_loaded = None
    for source_file in source_files:
        item = catalog_item_for_source(catalog, source_file)
        if item is None or item.get("error") or item.get("data") is None:
            continue
        records = payload_records(item.get("data"))
        if first_loaded is None:
            first_loaded = (source_file, records)
        if records:
            return source_file, records
    return first_loaded or (None, [])


def primary_record_asset(record: Any) -> Optional[Dict[str, Any]]:
    """Select one defensible primary asset from a collected record."""
    if not isinstance(record, Mapping):
        return None
    candidates = extract_local_assets(record)
    candidates = [
        candidate
        for candidate in candidates
        if candidate["kind"] != "azure_named_resource"
        or candidate.get("resource_group")
        or candidate.get("resource_type")
    ]
    if not candidates:
        return None
    return sorted(
        candidates,
        key=lambda item: (
            ASSET_KIND_PRIORITY.get(item["kind"], 99),
            str(item["identifier"]).lower(),
        ),
    )[0]


def population_denominator(records: Iterable[Any]) -> Tuple[Dict[str, Any], set]:
    """Count unique primary assets when possible, otherwise count records."""
    records = list(records)
    assets_by_id = {}
    unidentified_records = 0
    for record in records:
        asset = primary_record_asset(record)
        if asset is None:
            unidentified_records += 1
            continue
        retain_asset(assets_by_id, asset)

    if records and unidentified_records == 0:
        return (
            {
                "value": len(assets_by_id),
                "unit": "assets",
                "basis": "unique_assets_in_primary_source",
            },
            set(assets_by_id),
        )
    return (
        {
            "value": len(records),
            "unit": "records",
            "basis": "records_in_primary_source",
        },
        set(assets_by_id),
    )


def affected_asset_ids(finding: Mapping[str, Any]) -> set:
    """Return affected asset identities, excluding synthetic assessment scopes."""
    return {
        asset.get("asset_id")
        for asset in finding.get("reporting", {}).get("assets", [])
        if asset.get("asset_id") and asset.get("kind") != "assessment_scope"
    }


def unavailable_coverage(status: str, limitations: Iterable[str]) -> Dict[str, Any]:
    """Build a complete unavailable or not-implemented coverage object."""
    return {
        "schema_version": COVERAGE_SCHEMA_VERSION,
        "status": status,
        "denominator": {
            "value": None,
            "unit": None,
            "basis": None,
            "source_files": [],
        },
        "affected": {
            "observations": 0,
            "assets": 0,
            "matched_denominator_assets": None,
        },
        "affected_percentage": None,
        "limitations": sorted(set(limitations)),
    }


def normalise_finding_coverage(
    finding: Dict[str, Any],
    catalog: Optional[Mapping[str, Any]] = None,
    ordered_source_files: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Attach a collected-population denominator to one finding."""
    status = finding.get("status")
    if status == "not_implemented":
        finding["coverage"] = unavailable_coverage(
            "not_implemented",
            ["The check is not implemented, so no assessment denominator exists"],
        )
        validate_finding_coverage(finding)
        return finding

    source_files = list(
        ordered_source_files
        if ordered_source_files is not None
        else finding.get("references", {}).get("source_files", [])
    )
    source_file, records = select_primary_source(source_files, catalog)
    denominator, population_asset_ids = population_denominator(records)
    affected_ids = affected_asset_ids(finding)
    matched_asset_ids = affected_ids.intersection(population_asset_ids)
    affected_observations = int(finding.get("evidence_count") or 0)
    limitations = []

    if status == "no_data_to_assess":
        coverage = unavailable_coverage(
            "unavailable",
            ["Required source data was unavailable, so coverage cannot be measured"],
        )
        if source_file is not None:
            coverage["denominator"].update(denominator)
            coverage["denominator"]["source_files"] = [Path(source_file).name]
        finding["coverage"] = coverage
        validate_finding_coverage(finding)
        return finding

    if source_file is None:
        if status == "found" and affected_observations:
            assessment_scopes = {
                asset.get("asset_id")
                for asset in finding.get("reporting", {}).get("assets", [])
                if asset.get("kind") == "assessment_scope"
            }
            denominator = {
                "value": max(1, len(assessment_scopes)),
                "unit": "assessment_scopes",
                "basis": "inferred_from_finding_observations",
            }
            limitations.append(
                "No primary source dataset was attributable; the denominator was inferred from finding scope"
            )
        else:
            finding["coverage"] = unavailable_coverage(
                "unavailable",
                ["No primary source dataset was attributable to this check"],
            )
            validate_finding_coverage(finding)
            return finding

    limitations.append(
        "The denominator is a collected-population proxy; check-specific eligibility filtering is not yet instrumented"
    )
    matched_count = (
        len(matched_asset_ids)
        if denominator["unit"] == "assets"
        else None
    )
    percentage = None
    if denominator["unit"] == "assets" and denominator["value"]:
        percentage = round((matched_count / denominator["value"]) * 100, 2)
        if affected_observations and matched_count == 0:
            percentage = None
            limitations.append(
                "Affected asset identities could not be matched to the primary-source denominator"
            )

    finding["coverage"] = {
        "schema_version": COVERAGE_SCHEMA_VERSION,
        "status": "proxy",
        "denominator": {
            **denominator,
            "source_files": [Path(source_file).name] if source_file else [],
        },
        "affected": {
            "observations": affected_observations,
            "assets": len(affected_ids),
            "matched_denominator_assets": matched_count,
        },
        "affected_percentage": percentage,
        "limitations": sorted(set(limitations)),
    }
    validate_finding_coverage(finding)
    return finding


def validate_finding_coverage(finding: Mapping[str, Any]) -> None:
    """Reject malformed or internally inconsistent coverage metadata."""
    coverage = finding.get("coverage") or {}
    if coverage.get("schema_version") != COVERAGE_SCHEMA_VERSION:
        raise ValueError("Unsupported finding coverage schema")
    if coverage.get("status") not in COVERAGE_STATUSES:
        raise ValueError("Invalid finding coverage status")
    denominator = coverage.get("denominator")
    affected = coverage.get("affected")
    if not isinstance(denominator, Mapping) or not isinstance(affected, Mapping):
        raise ValueError("Finding coverage denominator and affected counts must be objects")
    value = denominator.get("value")
    if value is not None and (
        isinstance(value, bool) or not isinstance(value, int) or value < 0
    ):
        raise ValueError("Finding coverage denominator must be a non-negative integer")
    if not isinstance(denominator.get("source_files"), list):
        raise ValueError("Finding coverage source files must be a list")
    for key in ("observations", "assets"):
        if (
            isinstance(affected.get(key), bool)
            or not isinstance(affected.get(key), int)
            or affected[key] < 0
        ):
            raise ValueError("Finding coverage affected counts must be non-negative integers")
    matched = affected.get("matched_denominator_assets")
    if matched is not None and (
        isinstance(matched, bool) or not isinstance(matched, int) or matched < 0
    ):
        raise ValueError("Finding coverage matched asset count is invalid")
    if matched is not None and value is not None and matched > value:
        raise ValueError("Finding coverage matched assets exceed the denominator")
    if affected.get("observations") != int(finding.get("evidence_count") or 0):
        raise ValueError("Finding coverage observations do not match evidence count")
    percentage = coverage.get("affected_percentage")
    if percentage is not None:
        if (
            isinstance(percentage, bool)
            or not isinstance(percentage, (int, float))
            or not 0 <= percentage <= 100
        ):
            raise ValueError("Finding coverage percentage must be between zero and 100")
        if denominator.get("unit") != "assets" or not value:
            raise ValueError("Finding coverage percentage requires an asset denominator")
    if coverage.get("status") == "proxy" and value is None:
        raise ValueError("Proxy finding coverage requires a denominator")
    if not isinstance(coverage.get("limitations"), list):
        raise ValueError("Finding coverage limitations must be a list")
