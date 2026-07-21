# SPDX-License-Identifier: AGPL-3.0-or-later
"""Normalise finding evidence into report-facing assets and observations."""

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


REPORTING_SCHEMA_VERSION = "1.0"
ASSET_ID_RE = re.compile(r"^asset_[a-f0-9]{24}$")
OBSERVATION_ID_RE = re.compile(r"^obs_[a-f0-9]{24}$")
AZURE_IDENTIFIER_KEYS = {
    "id",
    "resourceId",
    "scope",
    "nsgId",
    "appGatewayId",
    "vmId",
    "target",
    "pe",
}
PRINCIPAL_IDENTIFIER_KEYS = {
    "principalId",
    "userId",
    "objectId",
    "userPrincipalName",
    "principalName",
}
PRINCIPAL_LIST_KEYS = {"principalIds", "userIds", "objectIds"}
NAMED_ASSET_KEYS = (
    "name",
    "ruleName",
    "serverName",
    "webApp",
    "nsgName",
    "subscriptionName",
)
SOURCE_HASH_CACHE: Dict[Tuple[str, int, int], str] = {}


def stable_digest(prefix: str, value: Any) -> str:
    """Return a deterministic short identity for JSON-compatible content."""
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    ).encode("utf-8")
    return f"{prefix}_{hashlib.sha256(encoded).hexdigest()[:24]}"


def sha256_file(path: Path) -> str:
    """Hash a source dataset without loading it into memory again."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cached_sha256_file(path: Path) -> str:
    """Hash a stable file once while guarding the cache with file metadata."""
    source_path = Path(path)
    stat = source_path.stat()
    cache_key = (str(source_path.resolve()), stat.st_mtime_ns, stat.st_size)
    if cache_key not in SOURCE_HASH_CACHE:
        SOURCE_HASH_CACHE[cache_key] = sha256_file(source_path)
    return SOURCE_HASH_CACHE[cache_key]


def normalise_identifier(value: Any) -> str:
    """Normalise case-insensitive Azure and Entra identifiers."""
    return str(value or "").strip().lower()


def azure_asset_kind(identifier: str) -> str:
    """Classify a resource path as a subscription, resource, or scope."""
    lowered = normalise_identifier(identifier).rstrip("/")
    parts = lowered.split("/")
    if len(parts) == 3 and parts[1] == "subscriptions":
        return "azure_subscription"
    if lowered.startswith("/subscriptions/") or lowered.startswith("/providers/"):
        return "azure_resource"
    return "azure_scope"


def asset_record(
    kind: str,
    identifier: Any,
    name: Any = None,
    resource_group: Any = None,
    resource_type: Any = None,
    subscription_id: Any = None,
    portal: Any = None,
) -> Dict[str, Any]:
    """Build one deterministic, compact asset record."""
    canonical_identifier = normalise_identifier(identifier)
    return {
        "asset_id": stable_digest("asset", [kind, canonical_identifier]),
        "kind": kind,
        "identifier": str(identifier),
        "name": str(name) if name not in (None, "") else None,
        "resource_group": (
            str(resource_group) if resource_group not in (None, "") else None
        ),
        "resource_type": (
            str(resource_type) if resource_type not in (None, "") else None
        ),
        "subscription_id": (
            str(subscription_id) if subscription_id not in (None, "") else None
        ),
        "portal": str(portal) if portal not in (None, "") else None,
    }


def retain_asset(assets_by_id: Dict[str, Dict[str, Any]], asset: Dict[str, Any]) -> None:
    """Retain one asset identity while filling metadata from richer occurrences."""
    existing = assets_by_id.get(asset["asset_id"])
    if existing is None:
        assets_by_id[asset["asset_id"]] = asset
        return
    for key, value in asset.items():
        if existing.get(key) in (None, "") and value not in (None, ""):
            existing[key] = value


def local_portal_link(record: Mapping[str, Any], identifier: str) -> Optional[str]:
    """Reuse a portal link already attached to the evidence where possible."""
    for reference in record.get("_references", []) or []:
        if reference.get("id") == identifier and reference.get("portal"):
            return str(reference["portal"])
    return None


def principal_display_name(record: Mapping[str, Any]) -> Any:
    """Select a compact display value from common resolved-principal shapes."""
    resolved = record.get("resolvedPrincipal")
    if isinstance(resolved, Mapping):
        resolved = (
            resolved.get("displayName")
            or resolved.get("name")
            or resolved.get("userPrincipalName")
        )
    return (
        record.get("displayName")
        or resolved
        or record.get("name")
        or record.get("userPrincipalName")
    )


def extract_local_assets(record: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Extract assets directly represented by one evidence mapping."""
    assets = []
    azure_identifiers = []
    principal_identifiers = []
    subscription_id = record.get("subscriptionId")

    for key in AZURE_IDENTIFIER_KEYS:
        value = record.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        lowered = normalise_identifier(value)
        if lowered.startswith(("/subscriptions/", "/providers/")):
            azure_identifiers.append(value)

    for identifier in sorted(set(azure_identifiers)):
        assets.append(
            asset_record(
                azure_asset_kind(identifier),
                identifier,
                name=record.get("name"),
                resource_group=record.get("resourceGroup"),
                resource_type=record.get("type"),
                subscription_id=subscription_id,
                portal=local_portal_link(record, identifier),
            )
        )

    if isinstance(subscription_id, str) and subscription_id.strip():
        subscription_identifier = subscription_id
        if not normalise_identifier(subscription_id).startswith("/subscriptions/"):
            subscription_identifier = f"/subscriptions/{subscription_id}"
        assets.append(
            asset_record(
                "azure_subscription",
                subscription_identifier,
                name=record.get("subscriptionName"),
                subscription_id=subscription_id,
            )
        )

    has_directory_object_id = bool(
        record.get("userPrincipalName") and record.get("id")
    )
    if has_directory_object_id:
        principal_identifiers.append(record["id"])
    for key in PRINCIPAL_IDENTIFIER_KEYS:
        if key == "userPrincipalName" and has_directory_object_id:
            continue
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            principal_identifiers.append(value)
    for key in PRINCIPAL_LIST_KEYS:
        values = record.get(key)
        if isinstance(values, list):
            principal_identifiers.extend(
                value
                for value in values
                if isinstance(value, str) and value.strip()
            )

    for value in sorted(set(principal_identifiers)):
        assets.append(
            asset_record(
                "entra_principal",
                value,
                name=principal_display_name(record),
            )
        )

    scope = record.get("scope")
    if (
        isinstance(scope, str)
        and scope.strip()
        and not normalise_identifier(scope).startswith(("/subscriptions/", "/providers/"))
    ):
        assets.append(
            asset_record(
                "assessment_scope",
                scope,
                name=scope,
            )
        )

    if not azure_identifiers and not principal_identifiers:
        for key in NAMED_ASSET_KEYS:
            value = record.get(key)
            if not isinstance(value, str) or not value.strip():
                continue
            identifier = "|".join(
                str(item or "")
                for item in (
                    record.get("type"),
                    record.get("resourceGroup"),
                    key,
                    value,
                )
            )
            assets.append(
                asset_record(
                    "azure_named_resource",
                    identifier,
                    name=value,
                    resource_group=record.get("resourceGroup"),
                    resource_type=record.get("type"),
                    subscription_id=subscription_id,
                )
            )
            break

    return assets


def walk_evidence_assets(value: Any) -> Iterable[Dict[str, Any]]:
    """Yield assets from nested evidence without retaining unrelated fields."""
    if isinstance(value, Mapping):
        yield from extract_local_assets(value)
        for key, child in value.items():
            if key == "_references":
                continue
            yield from walk_evidence_assets(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_evidence_assets(child)


def evidence_without_references(evidence: Mapping[str, Any]) -> Dict[str, Any]:
    """Return the legacy evidence payload without generated navigation links."""
    return {
        str(key): value
        for key, value in evidence.items()
        if key != "_references"
    }


def observation_summary(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> str:
    """Build a concise deterministic label without fabricating narrative."""
    for key in (
        "name",
        "ruleName",
        "serverName",
        "webApp",
        "nsgName",
        "userPrincipalName",
        "eventType",
        "setting",
        "id",
        "resourceId",
        "scope",
    ):
        value = evidence.get(key)
        if isinstance(value, str) and value:
            return f"{finding['title']}: {value}"
    return str(finding["title"])


def source_dataset_records(
    source_files: Iterable[str],
    manifest: Optional[Mapping[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Describe and, when possible, verify datasets used by a finding."""
    manifest_datasets = {
        item.get("filename"): item
        for item in (manifest or {}).get("datasets", [])
        if isinstance(item, Mapping) and item.get("filename")
    }
    endpoint_runs = [
        item
        for item in (manifest or {}).get("endpoint_runs", [])
        if isinstance(item, Mapping)
    ]
    records = []
    limitations = []
    for source_file in sorted(set(source_files)):
        source_path = Path(source_file)
        filename = source_path.name
        manifest_record = manifest_datasets.get(filename)
        record = {
            "filename": filename,
            "dataset_id": None,
            "record_count": None,
            "sha256": None,
            "size_bytes": None,
            "source_endpoint_id": None,
            "collection_statuses": [],
            "integrity_status": "manifest_unavailable" if manifest is None else "not_recorded",
        }
        if manifest_record:
            record.update(
                {
                    "dataset_id": manifest_record.get("dataset_id"),
                    "record_count": manifest_record.get("record_count"),
                    "sha256": manifest_record.get("sha256"),
                    "size_bytes": manifest_record.get("size_bytes"),
                    "source_endpoint_id": manifest_record.get("source_endpoint_id"),
                }
            )
            record["collection_statuses"] = sorted(
                {
                    endpoint_run.get("status")
                    for endpoint_run in endpoint_runs
                    if endpoint_run.get("status")
                    and (
                        filename in (endpoint_run.get("output_files") or [])
                        or (
                            manifest_record.get("source_endpoint_id")
                            and endpoint_run.get("endpoint_id")
                            == manifest_record.get("source_endpoint_id")
                        )
                    )
                }
            )
            if not source_path.is_file():
                record["integrity_status"] = "source_unavailable"
            else:
                try:
                    actual_digest = cached_sha256_file(source_path)
                except OSError:
                    record["integrity_status"] = "source_unavailable"
                else:
                    record["integrity_status"] = (
                        "verified"
                        if actual_digest == manifest_record.get("sha256")
                        else "mismatch"
                    )
        if record["integrity_status"] != "verified":
            limitations.append(
                f"Dataset provenance for {filename}: {record['integrity_status']}"
            )
        incomplete_statuses = set(record["collection_statuses"]).intersection(
            {"failed", "unauthorised", "not_attempted"}
        )
        if incomplete_statuses:
            limitations.append(
                f"Dataset collection for {filename}: "
                f"{', '.join(sorted(incomplete_statuses))}"
            )
        records.append(record)
    return records, limitations


def collection_manifest(catalog: Optional[Mapping[str, Any]]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Return the collection manifest payload and filename from a loaded catalog."""
    for base_name, item in (catalog or {}).items():
        if not str(base_name).startswith("azure-collection-manifest"):
            continue
        if not isinstance(item, Mapping) or not isinstance(item.get("data"), dict):
            continue
        manifest_path = item.get("path")
        return item["data"], Path(manifest_path).name if manifest_path else None
    return None, None


def collection_run_record(
    manifest: Optional[Mapping[str, Any]],
    manifest_filename: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Select non-secret run metadata required for report provenance."""
    if manifest is None:
        return None
    tool = manifest.get("tool") if isinstance(manifest.get("tool"), Mapping) else {}
    context = (
        manifest.get("context")
        if isinstance(manifest.get("context"), Mapping)
        else {}
    )
    return {
        "manifest_file": manifest_filename,
        "schema_version": manifest.get("schema_version"),
        "run_id": manifest.get("run_id"),
        "status": manifest.get("status"),
        "started_at": manifest.get("started_at"),
        "completed_at": manifest.get("completed_at"),
        "tenant_id": context.get("tenant_id"),
        "subscription_id": context.get("subscription_id"),
        "tool_git_commit": tool.get("git_commit"),
        "azure_cli_version": tool.get("azure_cli_version"),
        "limitations": list(manifest.get("limitations") or []),
    }


def normalise_finding_reporting(
    finding: Dict[str, Any],
    catalog: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Attach normalised assets, observations, and provenance to a finding."""
    manifest, manifest_filename = collection_manifest(catalog)
    source_files = finding.get("references", {}).get("source_files", [])
    datasets, limitations = source_dataset_records(source_files, manifest)
    if manifest is None:
        limitations.append("No collection-run manifest was available for provenance")
    else:
        if manifest.get("status") != "success":
            limitations.append(
                f"Collection run status was {manifest.get('status') or 'unknown'}"
            )
        limitations.extend(
            f"Collection run limitation: {item}"
            for item in manifest.get("limitations", [])
            if item
        )

    assets_by_id = {}
    observations = []
    observation_identity_counts = {}
    source_filenames = [item["filename"] for item in datasets]
    for raw_evidence in finding.get("evidence", []):
        evidence = (
            raw_evidence
            if isinstance(raw_evidence, Mapping)
            else {"value": raw_evidence}
        )
        evidence_data = evidence_without_references(evidence)
        observation_assets = {}
        for asset in walk_evidence_assets(evidence):
            retain_asset(observation_assets, asset)
            retain_asset(assets_by_id, asset)
        if not observation_assets:
            scope_asset = asset_record(
                "assessment_scope",
                finding["finding_id"],
                name=finding["definition"]["category"],
            )
            retain_asset(observation_assets, scope_asset)
            retain_asset(assets_by_id, scope_asset)

        observation_identity = {
            "finding_id": finding["finding_id"],
            "asset_ids": sorted(observation_assets),
            "evidence": evidence_data,
        }
        identity_key = stable_digest("obs", observation_identity)
        occurrence = observation_identity_counts.get(identity_key, 0)
        observation_identity_counts[identity_key] = occurrence + 1
        if occurrence:
            observation_identity["occurrence"] = occurrence
        observations.append(
            {
                "observation_id": stable_digest("obs", observation_identity),
                "summary": observation_summary(finding, evidence),
                "asset_ids": sorted(observation_assets),
                "data": evidence_data,
                "source_files": source_filenames,
                "reference_links": list(evidence.get("_references", [])),
            }
        )

    reporting = {
        "schema_version": REPORTING_SCHEMA_VERSION,
        "assets": sorted(
            assets_by_id.values(),
            key=lambda item: (item["kind"], normalise_identifier(item["identifier"])),
        ),
        "observations": sorted(
            observations,
            key=lambda item: item["observation_id"],
        ),
        "provenance": {
            "attribution_precision": "finding_level",
            "collection_run": collection_run_record(manifest, manifest_filename),
            "source_datasets": datasets,
            "limitations": sorted(set(limitations)),
        },
    }
    finding["reporting"] = reporting
    validate_finding_reporting(finding)
    return finding


def validate_finding_reporting(finding: Mapping[str, Any]) -> None:
    """Reject inconsistent report-facing normalisation data."""
    reporting = finding.get("reporting") or {}
    if reporting.get("schema_version") != REPORTING_SCHEMA_VERSION:
        raise ValueError("Unsupported finding reporting schema")
    assets = reporting.get("assets")
    observations = reporting.get("observations")
    if not isinstance(assets, list) or not isinstance(observations, list):
        raise ValueError("Finding reporting assets and observations must be lists")
    if any(not isinstance(item, Mapping) for item in assets):
        raise ValueError("Finding reporting assets must be objects")
    if any(not isinstance(item, Mapping) for item in observations):
        raise ValueError("Finding reporting observations must be objects")

    asset_ids = [item.get("asset_id") for item in assets]
    if len(asset_ids) != len(set(asset_ids)):
        raise ValueError("Finding reporting contains duplicate asset IDs")
    if any(not ASSET_ID_RE.fullmatch(str(asset_id or "")) for asset_id in asset_ids):
        raise ValueError("Finding reporting contains an invalid asset ID")
    if any(not item.get("kind") or not item.get("identifier") for item in assets):
        raise ValueError("Finding reporting contains an incomplete asset")

    observation_ids = [item.get("observation_id") for item in observations]
    if len(observation_ids) != len(set(observation_ids)):
        raise ValueError("Finding reporting contains duplicate observation IDs")
    if any(
        not OBSERVATION_ID_RE.fullmatch(str(observation_id or ""))
        for observation_id in observation_ids
    ):
        raise ValueError("Finding reporting contains an invalid observation ID")
    for observation in observations:
        unknown_assets = set(observation.get("asset_ids", [])) - set(asset_ids)
        if unknown_assets:
            raise ValueError("Finding observation references unknown assets")
        if not isinstance(observation.get("data"), Mapping):
            raise ValueError("Finding observation data must be an object")
        if not isinstance(observation.get("source_files"), list):
            raise ValueError("Finding observation source files must be a list")
        if not isinstance(observation.get("reference_links"), list):
            raise ValueError("Finding observation reference links must be a list")
    if len(observations) != int(finding.get("evidence_count") or 0):
        raise ValueError("Finding observation count does not match evidence count")

    provenance = reporting.get("provenance")
    if not isinstance(provenance, Mapping):
        raise ValueError("Finding reporting provenance must be an object")
    if provenance.get("attribution_precision") != "finding_level":
        raise ValueError("Unsupported finding provenance attribution precision")
    if not isinstance(provenance.get("source_datasets"), list):
        raise ValueError("Finding provenance source datasets must be a list")
    if not isinstance(provenance.get("limitations"), list):
        raise ValueError("Finding provenance limitations must be a list")
