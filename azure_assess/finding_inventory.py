#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Manifest-backed access to datasets used by offline finding evaluators."""

from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple


COMPLETE_STATUSES = {"success", "empty"}
POSITIVE_EVIDENCE_STATUSES = COMPLETE_STATUSES | {"incomplete"}


def payload(entry: Any) -> Any:
    """Accept both the CLI catalogue wrapper and direct unit-test payloads."""
    if (
        isinstance(entry, Mapping)
        and "data" in entry
        and ("path" in entry or "error" in entry)
    ):
        return entry.get("data")
    return entry


def source_filename(name: Any, entry: Any) -> str:
    if isinstance(entry, Mapping) and entry.get("path"):
        return Path(str(entry["path"])).name
    return Path(str(name)).name


def manifest(catalog: Mapping[str, Any]) -> Mapping[str, Any]:
    manifests = [
        payload(entry)
        for name, entry in catalog.items()
        if "manifest" in str(name).lower()
        and isinstance(payload(entry), Mapping)
    ]
    return manifests[-1] if manifests else {}


def manifest_statuses(catalog: Mapping[str, Any]) -> Dict[str, str]:
    grouped: Dict[str, list] = {}
    for run in manifest(catalog).get("endpoint_runs", []):
        if isinstance(run, Mapping) and run.get("endpoint_id"):
            grouped.setdefault(str(run["endpoint_id"]), []).append(
                str(run.get("status") or "unknown")
            )
    precedence = (
        "not_attempted", "failed", "unauthorised", "incomplete",
        "tenant_unavailable", "skipped", "not_applicable", "unknown",
        "success", "empty",
    )
    return {
        endpoint_id: next(
            (status for status in precedence if status in values), "unknown"
        )
        for endpoint_id, values in grouped.items()
    }

def current_filenames(catalog: Mapping[str, Any]) -> set:
    return {
        Path(str(item["filename"])).name
        for item in manifest(catalog).get("datasets", [])
        if isinstance(item, Mapping) and item.get("filename")
    }


def records(catalog: Mapping[str, Any], prefix: str) -> Tuple[list, list]:
    found, files = [], []
    current = current_filenames(catalog)
    for name, entry in catalog.items():
        catalogue_name = str(name)
        if catalogue_name != prefix and not catalogue_name.startswith(prefix + "_"):
            continue
        filename = source_filename(name, entry)
        if current and filename not in current:
            continue
        value = payload(entry)
        if value is None:
            continue
        files.append(str(entry.get("path")) if isinstance(entry, Mapping) and entry.get("path") else filename)
        values = value.get("value") if isinstance(value, Mapping) and isinstance(value.get("value"), list) else value
        if isinstance(values, list):
            found.extend(item for item in values if isinstance(item, Mapping))
        elif isinstance(values, Mapping):
            found.append(dict(values))
    return found, files


def inventory(
    catalog: Mapping[str, Any],
    endpoint_id: str,
    output_prefix: Optional[str] = None,
) -> dict:
    output = output_prefix or endpoint_id
    found, files = records(catalog, output)
    status = manifest_statuses(catalog).get(output)
    return {
        "endpoint_id": output,
        "records": found,
        "files": files,
        "status": status,
        "complete": bool(files) and status in COMPLETE_STATUSES,
        "positive_usable": bool(files) and status in POSITIVE_EVIDENCE_STATUSES,
    }
