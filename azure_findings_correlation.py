#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared, conservative joins for offline Azure finding correlations."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


DATASET_STATES = {
    "complete_data",
    "complete_empty",
    "partial",
    "failed",
    "missing",
    "manifest_unavailable",
}
CONCLUSION_SUPPORT = {
    "positive_and_negative",
    "positive_only",
    "inconclusive",
}
INCOMPLETE_ENDPOINT_STATUSES = {"failed", "unauthorised", "not_attempted", "skipped"}


def normalise_identifier(value: Any) -> str:
    """Return a case-insensitive identifier without inventing a value."""
    return str(value or "").strip().casefold()


def canonical_arm_id(value: Any) -> str:
    """Normalise an ARM identifier for joins while retaining ARM path semantics."""
    text = str(value or "").strip().replace("\\", "/")
    if not text:
        return ""
    parts = [part for part in text.split("/") if part]
    if not parts:
        return ""
    return "/" + "/".join(parts).casefold()


def canonical_object_id(value: Any) -> str:
    """Normalise a Microsoft Entra object identifier."""
    return normalise_identifier(value)


def canonical_role_definition_id(value: Any) -> str:
    """Return the stable role GUID/name component from any role definition ID."""
    canonical = canonical_arm_id(value)
    if canonical:
        return canonical.rsplit("/", 1)[-1]
    return normalise_identifier(value)


def arm_parent_scopes(value: Any, include_self: bool = True) -> List[str]:
    """Return recognised ARM ancestors from broadest scope to the resource itself."""
    resource_id = canonical_arm_id(value)
    if not resource_id:
        return []
    parts = resource_id.strip("/").split("/")
    scopes = []

    # Management-group scopes are independent of subscriptions.
    if len(parts) >= 4 and parts[:3] == ["providers", "microsoft.management", "managementgroups"]:
        scopes.append("/" + "/".join(parts[:4]))
    elif len(parts) >= 2 and parts[0] == "subscriptions":
        scopes.append("/" + "/".join(parts[:2]))
        if len(parts) >= 4 and parts[2] == "resourcegroups":
            scopes.append("/" + "/".join(parts[:4]))

    if include_self and resource_id not in scopes:
        scopes.append(resource_id)
    return list(dict.fromkeys(scopes))


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse Azure and manifest timestamps as timezone-aware UTC values."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def filename_timestamp(path: Any) -> Optional[datetime]:
    """Read a collection timestamp from the conventional filename suffix."""
    stem = Path(str(path or "")).stem
    if len(stem) < 15:
        return None
    candidate = stem[-15:]
    try:
        return datetime.strptime(candidate, "%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def collection_reference_time(
    manifest: Optional[Mapping[str, Any]],
    source_paths: Iterable[Any] = (),
) -> Tuple[datetime, str]:
    """Choose a reproducible assessment time and declare any fallback."""
    for field_name in ("completed_at", "started_at"):
        parsed = parse_timestamp((manifest or {}).get(field_name))
        if parsed is not None:
            return parsed, f"manifest.{field_name}"
    timestamps = [filename_timestamp(path) for path in source_paths]
    timestamps = [timestamp for timestamp in timestamps if timestamp is not None]
    if timestamps:
        return max(timestamps), "source_filename"
    return datetime.now(timezone.utc), "current_time_fallback"


def index_records(
    records: Iterable[Mapping[str, Any]],
    key_function: Callable[[Mapping[str, Any]], Any],
) -> Dict[str, List[Mapping[str, Any]]]:
    """Build a stable one-to-many index, ignoring records without a usable key."""
    index: Dict[str, List[Mapping[str, Any]]] = {}
    for record in records:
        key = normalise_identifier(key_function(record))
        if not key:
            continue
        index.setdefault(key, []).append(record)
    return index


@dataclass(frozen=True)
class DatasetSpec:
    """Bind one logical analyzer input to exact collection dataset identities."""

    logical_name: str
    aliases: Tuple[str, ...]
    endpoint_ids: Tuple[str, ...] = ()
    expand_value: bool = False


@dataclass
class AnalysisDataset:
    """Resolved records and completeness for one logical analyzer input."""

    logical_name: str
    records: List[Mapping[str, Any]] = field(default_factory=list)
    source_files: List[str] = field(default_factory=list)
    endpoint_ids: List[str] = field(default_factory=list)
    state: str = "missing"
    limitations: List[str] = field(default_factory=list)

    def supports_negative_conclusion(self) -> bool:
        return self.state in {"complete_data", "complete_empty"}


@dataclass
class CorrelationResult:
    """Evidence plus the degree of conclusion supported by its source inputs."""

    observations: List[Dict[str, Any]] = field(default_factory=list)
    eligible_assets: List[Dict[str, Any]] = field(default_factory=list)
    source_files: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    conclusion_support: str = "inconclusive"

    def __post_init__(self) -> None:
        if self.conclusion_support not in CONCLUSION_SUPPORT:
            raise ValueError(f"Unsupported conclusion support: {self.conclusion_support}")


def merge_correlation_results(results: Iterable[CorrelationResult]) -> CorrelationResult:
    """Merge service-specific results without overstating negative coverage."""
    results = list(results)
    supports = {item.conclusion_support for item in results}
    observations = [observation for item in results for observation in item.observations]
    if supports == {"positive_and_negative"}:
        support = "positive_and_negative"
    elif observations or "positive_only" in supports:
        support = "positive_only"
    else:
        support = "inconclusive"
    return CorrelationResult(
        observations=observations,
        eligible_assets=[asset for item in results for asset in item.eligible_assets],
        source_files=sorted({path for item in results for path in item.source_files}),
        limitations=list(
            dict.fromkeys(limitation for item in results for limitation in item.limitations)
        ),
        conclusion_support=support,
    )


def collection_manifest(catalog: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    """Return the loaded collection manifest, when present."""
    candidates = []
    for base_name, item in catalog.items():
        if not str(base_name).startswith("azure-collection-manifest"):
            continue
        if isinstance(item, Mapping) and isinstance(item.get("data"), Mapping):
            candidates.append(item["data"])
    if not candidates:
        return None
    return sorted(candidates, key=lambda item: str(item.get("completed_at") or ""))[-1]


def _catalog_matches(catalog: Mapping[str, Any], aliases: Sequence[str]) -> List[Mapping[str, Any]]:
    wanted = {normalise_identifier(alias) for alias in aliases}
    return [
        item
        for base_name, item in catalog.items()
        if normalise_identifier(base_name) in wanted and isinstance(item, Mapping)
    ]


def _records(payload: Any, expand_value: bool) -> List[Mapping[str, Any]]:
    if expand_value and isinstance(payload, Mapping) and isinstance(payload.get("value"), list):
        payload = payload.get("value")
    if isinstance(payload, Mapping):
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, Mapping)]
    return []


def resolve_analysis_dataset(
    catalog: Mapping[str, Any],
    spec: DatasetSpec,
    manifest: Optional[Mapping[str, Any]] = None,
) -> AnalysisDataset:
    """Resolve exact dataset aliases and conservatively classify completeness."""
    manifest = manifest if manifest is not None else collection_manifest(catalog)
    matches = _catalog_matches(catalog, spec.aliases)
    source_files = sorted(
        {str(item.get("path")) for item in matches if item.get("path")}
    )
    limitations = [
        f"Could not load {Path(str(item.get('path') or spec.logical_name)).name}: {item.get('error')}"
        for item in matches
        if item.get("error")
    ]
    records: List[Mapping[str, Any]] = []
    for item in matches:
        if item.get("error") is None:
            records.extend(_records(item.get("data"), spec.expand_value))

    endpoint_ids = list(dict.fromkeys(spec.endpoint_ids or spec.aliases))
    if manifest is None:
        if not matches:
            state = "missing"
        else:
            state = "manifest_unavailable"
            limitations.append(
                f"Collection completeness is unavailable for {spec.logical_name}"
            )
    else:
        endpoint_runs = [
            item
            for item in manifest.get("endpoint_runs", [])
            if isinstance(item, Mapping) and item.get("endpoint_id") in endpoint_ids
        ]
        statuses = {str(item.get("status")) for item in endpoint_runs if item.get("status")}
        incomplete = statuses.intersection(INCOMPLETE_ENDPOINT_STATUSES)
        successful = statuses.intersection({"success", "empty"})
        if incomplete and successful:
            state = "partial"
        elif incomplete:
            state = "failed"
        elif not endpoint_runs and matches:
            state = "partial"
            limitations.append(
                f"No collection endpoint status was attributable to {spec.logical_name}"
            )
        elif not matches and successful == {"empty"}:
            state = "complete_empty"
        elif not matches:
            state = "missing"
        elif limitations:
            state = "failed"
        elif records:
            state = "complete_data"
        else:
            state = "complete_empty"
        if incomplete:
            limitations.append(
                f"Collection for {spec.logical_name} was incomplete: "
                f"{', '.join(sorted(incomplete))}"
            )

    if state not in DATASET_STATES:
        raise ValueError(f"Unsupported dataset state: {state}")
    return AnalysisDataset(
        logical_name=spec.logical_name,
        records=records,
        source_files=source_files,
        endpoint_ids=endpoint_ids,
        state=state,
        limitations=list(dict.fromkeys(limitations)),
    )


class AnalysisInputs:
    """Resolve and cache logical datasets for one offline evaluation."""

    def __init__(self, catalog: Mapping[str, Any], specs: Iterable[DatasetSpec]) -> None:
        self.catalog = catalog
        self.manifest = collection_manifest(catalog)
        self.datasets = {
            spec.logical_name: resolve_analysis_dataset(catalog, spec, self.manifest)
            for spec in specs
        }

    def get(self, logical_name: str) -> AnalysisDataset:
        try:
            return self.datasets[logical_name]
        except KeyError as exc:
            raise KeyError(f"Unknown logical analysis dataset: {logical_name}") from exc

    def conclusion_support(self, required_names: Iterable[str]) -> str:
        required = [self.get(name) for name in required_names]
        if all(dataset.supports_negative_conclusion() for dataset in required):
            return "positive_and_negative"
        if any(dataset.records for dataset in required):
            return "positive_only"
        return "inconclusive"

    def limitations(self, logical_names: Iterable[str]) -> List[str]:
        """Describe incomplete inputs in report-ready language."""
        limitations = []
        for logical_name in logical_names:
            dataset = self.get(logical_name)
            limitations.extend(dataset.limitations)
            if not dataset.supports_negative_conclusion():
                limitations.append(
                    f"Dataset {logical_name} completeness was {dataset.state}"
                )
        return list(dict.fromkeys(limitations))
