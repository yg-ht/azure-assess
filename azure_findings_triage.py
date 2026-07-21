# SPDX-License-Identifier: AGPL-3.0-or-later
"""Group, prioritise, deduplicate, and compare report-facing findings."""

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from azure_findings_reporting import normalise_identifier, stable_digest
from azure_findings_review import CONTEXTUAL_SEVERITY_LEVELS


TRIAGE_SCHEMA_VERSION = "1.0"
MAX_BASELINE_FILE_SIZE = 100 * 1024 * 1024
MAX_TRIAGE_TEXT_LENGTH = 10_000
TRIAGE_ID_RE = re.compile(r"^(group|obsgroup|dedup|findingfp)_[a-f0-9]{24}$")
SEVERITY_LEVELS = CONTEXTUAL_SEVERITY_LEVELS.union({"Unknown"})
DEDUPLICATION_STATUSES = {"not_applicable", "unique", "duplicates_present"}
RETEST_OUTCOMES = {
    "not_assessed",
    "same_run",
    "new",
    "persistent",
    "potentially_resolved",
    "unchanged_not_detected",
    "scope_changed",
    "inconclusive",
}
NON_DETECTED_STATUSES = {"not_found"}
INCOMPLETE_STATUSES = {"no_data_to_assess", "not_implemented"}
EXPOSURE_ATTRIBUTE_NAMES = {
    "access_actions",
    "destination_addresses",
    "destination_ports",
    "public_access_levels",
    "public_network_access",
    "source_addresses",
}
SEVERITY_NORMALISATION = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
    "info": "Informational",
    "unknown": "Unknown",
}


def validate_triage_text(value: Any, field_name: str) -> None:
    """Require bounded non-empty text in report-facing triage metadata."""
    if not isinstance(value, str) or not value or len(value) > MAX_TRIAGE_TEXT_LENGTH:
        raise ValueError(f"Finding triage {field_name} must be bounded non-empty text")


def canonical_severity(value: Any) -> str:
    """Normalise supported legacy severity casing without guessing new levels."""
    severity = SEVERITY_NORMALISATION.get(str(value or "Unknown").strip().casefold())
    if severity is None:
        raise ValueError(f"Unsupported finding severity: {value}")
    return severity


def report_grouping(finding: Mapping[str, Any]) -> Dict[str, Any]:
    """Build stable report and per-asset observation groups."""
    context = finding.get("context", {})
    family = context.get("family", {})
    engagement = context.get("engagement", {})
    scope = context.get("scope", {})
    tenant_ids = sorted(engagement.get("tenant_ids", []), key=str.casefold)
    subscription_ids = sorted(scope.get("subscription_ids", []), key=str.casefold)
    if not subscription_ids and engagement.get("selected_subscription_id"):
        subscription_ids = [engagement["selected_subscription_id"]]
    dimensions = {
        "family_id": family.get("id"),
        "service_id": family.get("service_id"),
        "tenant_ids": tenant_ids,
        "subscription_ids": subscription_ids,
    }

    observations_by_assets: Dict[Tuple[str, ...], List[str]] = {}
    for observation in finding.get("reporting", {}).get("observations", []):
        asset_ids = tuple(sorted(set(observation.get("asset_ids", []))))
        observations_by_assets.setdefault(asset_ids, []).append(
            observation["observation_id"]
        )
    observation_groups = []
    for asset_ids, observation_ids in sorted(observations_by_assets.items()):
        observation_ids = sorted(observation_ids)
        observation_groups.append(
            {
                "group_id": stable_digest(
                    "obsgroup",
                    [finding.get("finding_id"), list(asset_ids)],
                ),
                "asset_ids": list(asset_ids),
                "observation_ids": observation_ids,
                "observation_count": len(observation_ids),
            }
        )
    return {
        "report_group_id": stable_digest("group", dimensions),
        "dimensions": dimensions,
        "observation_groups": observation_groups,
    }


def severity_record(finding: Mapping[str, Any]) -> Dict[str, Any]:
    """Retain definition severity unless a reviewed analyst override exists."""
    default_severity = canonical_severity(
        finding.get("definition", {}).get("default_severity")
        or finding.get("severity")
        or "Unknown"
    )
    review = finding.get("review", {})
    analyst = review.get("analyst", {})
    override = analyst.get("contextual_severity")
    attributes = finding.get("context", {}).get("attributes", {})
    exposure_attributes = {
        key: list(attributes[key])
        for key in sorted(EXPOSURE_ATTRIBUTE_NAMES.intersection(attributes))
    }
    factors = {
        "family_id": finding.get("context", {}).get("family", {}).get("id"),
        "service_id": finding.get("context", {}).get("family", {}).get("service_id"),
        "scope_level": finding.get("context", {}).get("scope", {}).get("level"),
        "affected_asset_count": finding.get("context", {})
        .get("scope", {})
        .get("affected_asset_count"),
        "affected_percentage": finding.get("coverage", {}).get("affected_percentage"),
        "confidence": review.get("confidence", {}).get("level"),
        "disposition": review.get("disposition"),
        "exposure_attributes": exposure_attributes,
    }
    if isinstance(override, Mapping):
        return {
            "default": default_severity,
            "contextual": override["level"],
            "source": "analyst",
            "changed": override["level"] != default_severity,
            "rationale": [override["rationale"]],
            "analyst": {
                "reviewer": analyst.get("reviewer"),
                "reviewed_at": analyst.get("reviewed_at"),
            },
            "factors": factors,
        }
    return {
        "default": default_severity,
        "contextual": default_severity,
        "source": "definition",
        "changed": False,
        "rationale": [
            "No analyst contextual severity override was supplied; default severity was retained"
        ],
        "analyst": {
            "reviewer": None,
            "reviewed_at": None,
        },
        "factors": factors,
    }


def observation_deduplication(finding: Mapping[str, Any]) -> Dict[str, Any]:
    """Identify exact duplicate observations without dropping original evidence."""
    observations = finding.get("reporting", {}).get("observations", [])
    observations_by_key: Dict[str, List[str]] = {}
    for observation in observations:
        identity = {
            "asset_ids": sorted(set(observation.get("asset_ids", []))),
            "data": observation.get("data", {}),
            "source_files": sorted(set(observation.get("source_files", []))),
        }
        dedup_key = stable_digest("dedup", identity)
        observations_by_key.setdefault(dedup_key, []).append(
            observation["observation_id"]
        )

    duplicate_sets = []
    for dedup_key, observation_ids in sorted(observations_by_key.items()):
        observation_ids = sorted(observation_ids)
        if len(observation_ids) < 2:
            continue
        duplicate_sets.append(
            {
                "dedup_key": dedup_key,
                "canonical_observation_id": observation_ids[0],
                "duplicate_observation_ids": observation_ids[1:],
            }
        )
    duplicate_count = sum(
        len(item["duplicate_observation_ids"])
        for item in duplicate_sets
    )
    if not observations:
        status = "not_applicable"
    elif duplicate_count:
        status = "duplicates_present"
    else:
        status = "unique"
    return {
        "strategy": "exact_data_assets_and_sources",
        "status": status,
        "original_observation_count": len(observations),
        "unique_observation_count": len(observations) - duplicate_count,
        "duplicate_observation_count": duplicate_count,
        "duplicate_sets": duplicate_sets,
        "evidence_retained": True,
    }


def concrete_asset_keys(finding: Mapping[str, Any]) -> Dict[str, str]:
    """Return stable asset IDs keyed by normalised kind and identifier."""
    keys = {}
    for asset in finding.get("reporting", {}).get("assets", []):
        if asset.get("kind") == "assessment_scope":
            continue
        identity = f"{asset.get('kind')}|{normalise_identifier(asset.get('identifier'))}"
        if asset.get("asset_id"):
            keys[identity] = asset["asset_id"]
    return keys


def finding_fingerprint(finding: Mapping[str, Any]) -> Dict[str, Any]:
    """Build a cross-run identity independent of finding status and evidence values."""
    asset_keys = concrete_asset_keys(finding)
    context = finding.get("context", {})
    if asset_keys:
        scope_basis = {
            "kind": "concrete_assets",
            "identities": sorted(asset_keys),
        }
    else:
        engagement = context.get("engagement", {})
        scope = context.get("scope", {})
        scope_basis = {
            "kind": "assessment_scope",
            "tenant_ids": sorted(engagement.get("tenant_ids", [])),
            "subscription_ids": sorted(scope.get("subscription_ids", [])),
            "selected_subscription_id": engagement.get("selected_subscription_id"),
            "scope_level": scope.get("level"),
        }
    return {
        "algorithm": "sha256-v1",
        "value": stable_digest(
            "findingfp",
            {
                "finding_id": finding.get("finding_id"),
                "scope": scope_basis,
            },
        ),
        "basis": scope_basis["kind"],
    }


def assessment_scope(finding: Mapping[str, Any]) -> Optional[Dict[str, List[str]]]:
    """Return comparable tenant and selected-subscription assessment scope."""
    context = finding.get("context", {})
    engagement = context.get("engagement", {})
    tenant_ids = sorted(
        {str(item).casefold() for item in engagement.get("tenant_ids", []) if item}
    )
    selected_subscription_id = engagement.get("selected_subscription_id")
    if selected_subscription_id:
        subscription_ids = [str(selected_subscription_id).casefold()]
    else:
        subscription_ids = sorted(
            {
                str(item).casefold()
                for item in context.get("scope", {}).get("subscription_ids", [])
                if item
            }
        )
        if not subscription_ids:
            subscription_ids = sorted(
                {
                    str(item.get("subscription_id")).casefold()
                    for item in engagement.get("subscriptions", [])
                    if item.get("subscription_id")
                }
            )
    if not tenant_ids and not subscription_ids:
        return None
    return {
        "tenant_ids": tenant_ids,
        "subscription_ids": subscription_ids,
    }


def collection_supports_resolution(finding: Mapping[str, Any]) -> Tuple[bool, List[str]]:
    """Require successful, verified source collection before suggesting resolution."""
    provenance = finding.get("reporting", {}).get("provenance", {})
    collection_run = provenance.get("collection_run") or {}
    datasets = provenance.get("source_datasets", [])
    reasons = []
    if collection_run.get("status") != "success":
        reasons.append("Current collection run was not successful")
    coverage = finding.get("coverage", {})
    if coverage.get("status") != "proxy" or coverage.get("denominator", {}).get(
        "value"
    ) is None:
        reasons.append("Current assessment coverage was unavailable")
    if not datasets:
        reasons.append("No current source datasets were attributable")
    elif any(item.get("integrity_status") != "verified" for item in datasets):
        reasons.append("Current source datasets were not all hash-verified")
    collection_statuses = {
        status
        for item in datasets
        for status in item.get("collection_statuses", [])
    }
    if not collection_statuses:
        reasons.append("No current endpoint collection status was attributable")
    elif not collection_statuses.issubset({"success", "empty"}):
        reasons.append("Current endpoint collection was incomplete")
    return not reasons, reasons


def finding_run_id(finding: Mapping[str, Any]) -> Optional[str]:
    """Return the collection run identity attached to one finding."""
    value = (
        finding.get("context", {})
        .get("engagement", {})
        .get("collection", {})
        .get("run_id")
    )
    return str(value) if value else None


def default_retest_record(
    finding: Mapping[str, Any],
    baseline_requested: bool = False,
) -> Dict[str, Any]:
    """Build an explicit no-baseline retest state."""
    return {
        "comparison_status": "baseline_missing"
        if baseline_requested
        else "not_requested",
        "outcome": "not_assessed",
        "current_run_id": finding_run_id(finding),
        "baseline_run_id": None,
        "scope_match": None,
        "baseline_status": None,
        "current_status": finding.get("status"),
        "asset_changes": {
            "persisting_asset_ids": [],
            "new_asset_ids": [],
            "potentially_resolved_asset_ids": [],
        },
        "rationale": [
            "Finding definition was absent from the supplied baseline"
            if baseline_requested
            else "No baseline findings file was supplied"
        ],
    }


def compare_retest(
    finding: Mapping[str, Any],
    baseline: Mapping[str, Any],
) -> Dict[str, Any]:
    """Conservatively compare one current finding with its prior definition row."""
    if baseline.get("finding_id") != finding.get("finding_id"):
        raise ValueError("Baseline finding ID does not match current finding")
    if baseline.get("status") not in {
        "found",
        "not_found",
        "no_data_to_assess",
        "not_implemented",
    }:
        raise ValueError("Baseline finding status is invalid")
    current_run_id = finding_run_id(finding)
    baseline_run_id = finding_run_id(baseline)
    current_status = finding.get("status")
    baseline_status = baseline.get("status")
    current_scope = assessment_scope(finding)
    baseline_scope = assessment_scope(baseline)
    scope_match = (
        current_scope == baseline_scope
        if current_scope is not None and baseline_scope is not None
        else None
    )
    current_assets = concrete_asset_keys(finding)
    baseline_assets = concrete_asset_keys(baseline)
    current_keys = set(current_assets)
    baseline_keys = set(baseline_assets)
    rationale = []

    if current_run_id and baseline_run_id and current_run_id == baseline_run_id:
        outcome = "same_run"
        rationale.append("Current and baseline findings use the same collection run")
    elif scope_match is False:
        outcome = "scope_changed"
        rationale.append("Current and baseline engagement scopes differ")
    elif scope_match is None:
        outcome = "inconclusive"
        rationale.append("Current and baseline engagement scopes could not be compared")
    elif baseline_status == "found" and current_status == "found":
        outcome = "persistent"
        rationale.append("The finding remains present in a comparable assessment scope")
    elif baseline_status == "not_found" and current_status == "found":
        outcome = "new"
        rationale.append("The finding is present but was not detected in the baseline")
    elif baseline_status in INCOMPLETE_STATUSES and current_status == "found":
        outcome = "inconclusive"
        rationale.append("The baseline check status cannot establish prior non-detection")
    elif baseline_status == "found" and current_status in NON_DETECTED_STATUSES:
        adequate, limitations = collection_supports_resolution(finding)
        if adequate:
            outcome = "potentially_resolved"
            rationale.append(
                "The finding was not detected in a comparable, successfully verified collection"
            )
        else:
            outcome = "inconclusive"
            rationale.extend(limitations)
    elif (
        baseline_status in NON_DETECTED_STATUSES
        and current_status in NON_DETECTED_STATUSES
    ):
        outcome = "unchanged_not_detected"
        rationale.append("The finding was not detected in either comparable assessment")
    elif current_status in INCOMPLETE_STATUSES:
        outcome = "inconclusive"
        rationale.append("Current check status cannot support a retest conclusion")
    else:
        outcome = "inconclusive"
        rationale.append("The current and baseline statuses do not support a conclusion")

    persisting_asset_ids = []
    new_asset_ids = []
    potentially_resolved_asset_ids = []
    if outcome == "persistent":
        persisting_asset_ids = sorted(
            current_assets[key] for key in current_keys.intersection(baseline_keys)
        )
        new_asset_ids = sorted(
            current_assets[key] for key in current_keys - baseline_keys
        )
        adequate, _ = collection_supports_resolution(finding)
        if adequate:
            potentially_resolved_asset_ids = sorted(
                baseline_assets[key] for key in baseline_keys - current_keys
            )
    elif outcome == "new":
        new_asset_ids = sorted(current_assets.values())
    elif outcome == "potentially_resolved":
        potentially_resolved_asset_ids = sorted(baseline_assets.values())
    asset_changes = {
        "persisting_asset_ids": persisting_asset_ids,
        "new_asset_ids": new_asset_ids,
        "potentially_resolved_asset_ids": potentially_resolved_asset_ids,
    }

    return {
        "comparison_status": "compared",
        "outcome": outcome,
        "current_run_id": current_run_id,
        "baseline_run_id": baseline_run_id,
        "scope_match": scope_match,
        "baseline_status": baseline_status,
        "current_status": current_status,
        "asset_changes": asset_changes,
        "rationale": rationale,
    }


def load_baseline_findings(path: Path) -> Dict[str, Dict[str, Any]]:
    """Load a bounded prior flat findings output keyed by canonical finding ID."""
    baseline_path = Path(path)
    if baseline_path.stat().st_size > MAX_BASELINE_FILE_SIZE:
        raise ValueError(
            f"Baseline findings file exceeds {MAX_BASELINE_FILE_SIZE} bytes"
        )
    with baseline_path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, Mapping) or not isinstance(payload.get("rows"), list):
        raise ValueError("Baseline findings file must be a flat output object with rows")
    findings = {}
    for row in payload["rows"]:
        if not isinstance(row, Mapping):
            raise ValueError("Baseline finding rows must be objects")
        finding_id = row.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id:
            raise ValueError("Baseline finding rows require canonical finding IDs")
        if finding_id in findings:
            raise ValueError(f"Duplicate baseline finding ID: {finding_id}")
        if row.get("status") not in {
            "found",
            "not_found",
            "no_data_to_assess",
            "not_implemented",
        }:
            raise ValueError(f"Invalid baseline finding status: {finding_id}")
        findings[finding_id] = dict(row)
    return findings


def normalise_finding_triage(
    finding: Dict[str, Any],
    baseline: Optional[Mapping[str, Any]] = None,
    baseline_requested: bool = False,
) -> Dict[str, Any]:
    """Attach validated grouping, severity, deduplication, and retest metadata."""
    finding["triage"] = {
        "schema_version": TRIAGE_SCHEMA_VERSION,
        "grouping": report_grouping(finding),
        "severity": severity_record(finding),
        "deduplication": observation_deduplication(finding),
        "fingerprint": finding_fingerprint(finding),
        "retest": compare_retest(finding, baseline)
        if baseline is not None
        else default_retest_record(
            finding,
            baseline_requested=baseline_requested,
        ),
    }
    validate_finding_triage(finding)
    return finding


def apply_findings_triage(
    findings: Iterable[Dict[str, Any]],
    baseline_findings: Optional[Mapping[str, Mapping[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Apply triage metadata and reject stale baseline definition IDs."""
    findings = list(findings)
    finding_ids = [finding.get("finding_id") for finding in findings]
    if len(finding_ids) != len(set(finding_ids)):
        raise ValueError("Current findings contain duplicate canonical IDs")
    baseline_requested = baseline_findings is not None
    baseline_findings = dict(baseline_findings or {})
    unknown_ids = sorted(set(baseline_findings) - set(finding_ids))
    if unknown_ids:
        raise ValueError(
            "Baseline contains unknown finding IDs: " + ", ".join(unknown_ids)
        )
    for finding_id, baseline in baseline_findings.items():
        if not isinstance(baseline, Mapping):
            raise ValueError(f"Baseline finding must be an object: {finding_id}")
        if baseline.get("finding_id") != finding_id:
            raise ValueError(f"Baseline finding ID does not match its key: {finding_id}")
        if baseline.get("status") not in {
            "found",
            "not_found",
            "no_data_to_assess",
            "not_implemented",
        }:
            raise ValueError(f"Invalid baseline finding status: {finding_id}")
    for finding in findings:
        normalise_finding_triage(
            finding,
            baseline=baseline_findings.get(finding.get("finding_id")),
            baseline_requested=baseline_requested,
        )
    return findings


def validate_string_list(value: Any, field_name: str) -> None:
    """Require unique bounded strings in triage identity lists."""
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"Finding triage {field_name} must be a list of strings")
    if any(not item or len(item) > MAX_TRIAGE_TEXT_LENGTH for item in value):
        raise ValueError(f"Finding triage {field_name} contains invalid text")
    if len(value) != len(set(value)):
        raise ValueError(f"Finding triage {field_name} contains duplicates")


def validate_finding_triage(finding: Mapping[str, Any]) -> None:
    """Reject malformed or inconsistent report-facing triage metadata."""
    triage = finding.get("triage") or {}
    if triage.get("schema_version") != TRIAGE_SCHEMA_VERSION:
        raise ValueError("Unsupported finding triage schema")
    grouping = triage.get("grouping")
    severity = triage.get("severity")
    deduplication = triage.get("deduplication")
    fingerprint = triage.get("fingerprint")
    retest = triage.get("retest")
    if not all(
        isinstance(item, Mapping)
        for item in (grouping, severity, deduplication, fingerprint, retest)
    ):
        raise ValueError("Finding triage sections must be objects")

    if not TRIAGE_ID_RE.fullmatch(str(grouping.get("report_group_id") or "")):
        raise ValueError("Finding triage report group ID is invalid")
    observation_ids = {
        item.get("observation_id")
        for item in finding.get("reporting", {}).get("observations", [])
    }
    grouped_observation_ids = []
    for group in grouping.get("observation_groups", []):
        if not isinstance(group, Mapping):
            raise ValueError("Finding triage observation groups must be objects")
        if not TRIAGE_ID_RE.fullmatch(str(group.get("group_id") or "")):
            raise ValueError("Finding triage observation group ID is invalid")
        validate_string_list(group.get("asset_ids"), "observation group asset IDs")
        validate_string_list(
            group.get("observation_ids"),
            "observation group observation IDs",
        )
        if group.get("observation_count") != len(group["observation_ids"]):
            raise ValueError("Finding triage observation group count is inconsistent")
        grouped_observation_ids.extend(group["observation_ids"])
    if set(grouped_observation_ids) != observation_ids or len(
        grouped_observation_ids
    ) != len(observation_ids):
        raise ValueError("Finding triage observation groups do not partition observations")
    if grouping != report_grouping(finding):
        raise ValueError("Finding triage grouping conflicts with current finding context")

    if severity.get("default") not in SEVERITY_LEVELS:
        raise ValueError("Finding triage default severity is invalid")
    if severity.get("contextual") not in SEVERITY_LEVELS:
        raise ValueError("Finding triage contextual severity is invalid")
    if severity.get("source") not in {"definition", "analyst"}:
        raise ValueError("Finding triage severity source is invalid")
    if not isinstance(severity.get("changed"), bool):
        raise ValueError("Finding triage severity changed flag must be boolean")
    if severity.get("changed") != (
        severity.get("default") != severity.get("contextual")
    ):
        raise ValueError("Finding triage severity changed flag is inconsistent")
    validate_string_list(severity.get("rationale"), "severity rationale")
    if severity.get("source") == "analyst":
        analyst = severity.get("analyst") or {}
        if not isinstance(analyst, Mapping):
            raise ValueError("Finding triage severity analyst metadata must be an object")
        if not analyst.get("reviewer") or not analyst.get("reviewed_at"):
            raise ValueError("Analyst contextual severity requires review attribution")
    if severity != severity_record(finding):
        raise ValueError("Finding triage severity conflicts with review and context")

    observations = finding.get("reporting", {}).get("observations", [])
    original_count = deduplication.get("original_observation_count")
    unique_count = deduplication.get("unique_observation_count")
    duplicate_count = deduplication.get("duplicate_observation_count")
    if original_count != len(observations):
        raise ValueError("Finding triage deduplication count does not match observations")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in (original_count, unique_count, duplicate_count)
    ):
        raise ValueError("Finding triage deduplication counts are invalid")
    if unique_count + duplicate_count != original_count:
        raise ValueError("Finding triage deduplication counts are inconsistent")
    expected_status = (
        "not_applicable"
        if not observations
        else "duplicates_present"
        if duplicate_count
        else "unique"
    )
    if deduplication.get("status") != expected_status:
        raise ValueError("Finding triage deduplication status is inconsistent")
    if deduplication.get("evidence_retained") is not True:
        raise ValueError("Finding triage must retain original evidence")
    duplicate_ids = []
    for duplicate_set in deduplication.get("duplicate_sets", []):
        if not isinstance(duplicate_set, Mapping):
            raise ValueError("Finding triage duplicate sets must be objects")
        if not TRIAGE_ID_RE.fullmatch(str(duplicate_set.get("dedup_key") or "")):
            raise ValueError("Finding triage deduplication key is invalid")
        canonical_id = duplicate_set.get("canonical_observation_id")
        validate_string_list(
            duplicate_set.get("duplicate_observation_ids"),
            "duplicate observation IDs",
        )
        if canonical_id not in observation_ids:
            raise ValueError("Finding triage canonical duplicate observation is unknown")
        duplicate_ids.extend(duplicate_set["duplicate_observation_ids"])
    if len(duplicate_ids) != duplicate_count or not set(duplicate_ids).issubset(
        observation_ids
    ):
        raise ValueError("Finding triage duplicate observation references are inconsistent")
    if deduplication != observation_deduplication(finding):
        raise ValueError("Finding triage deduplication conflicts with observations")

    if fingerprint.get("algorithm") != "sha256-v1" or not TRIAGE_ID_RE.fullmatch(
        str(fingerprint.get("value") or "")
    ):
        raise ValueError("Finding triage fingerprint is invalid")
    if fingerprint.get("basis") not in {"concrete_assets", "assessment_scope"}:
        raise ValueError("Finding triage fingerprint basis is invalid")
    if fingerprint != finding_fingerprint(finding):
        raise ValueError("Finding triage fingerprint conflicts with current scope")

    if retest.get("comparison_status") not in {
        "not_requested",
        "baseline_missing",
        "compared",
    }:
        raise ValueError("Finding triage retest comparison status is invalid")
    if retest.get("outcome") not in RETEST_OUTCOMES:
        raise ValueError("Finding triage retest outcome is invalid")
    if retest.get("current_status") != finding.get("status"):
        raise ValueError("Finding triage retest current status is inconsistent")
    scope_match = retest.get("scope_match")
    if scope_match is not None and not isinstance(scope_match, bool):
        raise ValueError("Finding triage retest scope match is invalid")
    for key in ("current_run_id", "baseline_run_id"):
        value = retest.get(key)
        if value is not None and (
            not isinstance(value, str)
            or not value
            or len(value) > MAX_TRIAGE_TEXT_LENGTH
        ):
            raise ValueError(f"Finding triage retest {key} is invalid")
    comparison_status = retest.get("comparison_status")
    if comparison_status in {"not_requested", "baseline_missing"}:
        if (
            retest.get("outcome") != "not_assessed"
            or retest.get("baseline_status") is not None
            or retest.get("baseline_run_id") is not None
            or scope_match is not None
        ):
            raise ValueError("Finding triage unperformed retest metadata is inconsistent")
    elif retest.get("baseline_status") not in {
        "found",
        "not_found",
        "no_data_to_assess",
        "not_implemented",
    }:
        raise ValueError("Finding triage compared baseline status is invalid")
    elif retest.get("outcome") == "not_assessed":
        raise ValueError("Finding triage compared retest requires an outcome")
    validate_string_list(retest.get("rationale"), "retest rationale")
    asset_changes = retest.get("asset_changes")
    if not isinstance(asset_changes, Mapping):
        raise ValueError("Finding triage retest asset changes must be an object")
    for key in (
        "persisting_asset_ids",
        "new_asset_ids",
        "potentially_resolved_asset_ids",
    ):
        validate_string_list(asset_changes.get(key), f"retest {key}")
    changed_asset_ids = [
        asset_id
        for key in (
            "persisting_asset_ids",
            "new_asset_ids",
            "potentially_resolved_asset_ids",
        )
        for asset_id in asset_changes[key]
    ]
    if len(changed_asset_ids) != len(set(changed_asset_ids)):
        raise ValueError("Finding triage retest asset change sets overlap")
