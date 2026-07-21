#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Collection-run manifest models and persistence helpers."""

import hashlib
import json
import os
import platform
import re
import subprocess
import tempfile
import threading
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


MANIFEST_SCHEMA_VERSION = "2.0"
MANIFEST_FILENAME_PREFIX = "azure-collection-manifest"
MAX_ERROR_MESSAGE_CHARS = 1000
VALID_RUN_STATUSES = {"running", "success", "partial", "failed"}
VALID_ENDPOINT_STATUSES = {
    "success",
    "empty",
    "failed",
    "unauthorised",
    "skipped",
    "not_attempted",
}


def utc_timestamp() -> str:
    """Return a second-precision RFC 3339 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def truncate_error_text(value: Any) -> str:
    """Limit persisted endpoint error text without changing retained content."""
    text = str(value or "")
    if len(text) > MAX_ERROR_MESSAGE_CHARS:
        text = text[:MAX_ERROR_MESSAGE_CHARS] + "... [truncated]"
    return text


def result_item_count(data: Any) -> int:
    """Return a stable top-level record count for a collected JSON payload."""
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        return len(data.keys())
    return 0


def sha256_file(path: Path) -> str:
    """Hash a generated dataset without loading the complete file into memory."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def endpoint_id(command_template: str) -> str:
    """Build the same style of stable endpoint identifier used for datasets."""
    safe = [
        character if character.isalnum() or character in "._-" else "_"
        for character in str(command_template or "").lower().replace("{", "").replace("}", "")
    ]
    return "_".join(part for part in "".join(safe).split("_") if part) or "unknown"


def detect_git_commit(project_dir: Path) -> Optional[str]:
    """Return the checked-out Git commit when running from a repository."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(project_dir),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    commit = result.stdout.strip()
    return commit or None


def classify_execution_status(
    returncode: Optional[int],
    result_count: Optional[int],
    error_message: Optional[str] = None,
    diagnostic_text: Optional[str] = None,
) -> str:
    """Classify one command without persisting its diagnostic output."""
    combined_error = " ".join(
        str(item or "").lower()
        for item in (error_message, diagnostic_text)
    )
    if error_message or returncode not in (None, 0):
        permission_markers = (
            "authorizationfailed",
            "does not have authorization",
            "forbidden",
            "insufficient privileges",
            "permission",
            "unauthorized",
        )
        if any(marker in combined_error for marker in permission_markers):
            return "unauthorised"
        return "failed"
    if result_count == 0:
        return "empty"
    return "success"


def validate_manifest(payload: Mapping[str, Any]) -> None:
    """Reject incomplete or internally inconsistent manifest payloads."""
    required_keys = {
        "schema_version",
        "run_id",
        "status",
        "started_at",
        "completed_at",
        "tool",
        "context",
        "options",
        "endpoint_runs",
        "datasets",
        "errors",
        "limitations",
    }
    missing_keys = sorted(required_keys - set(payload.keys()))
    if missing_keys:
        raise ValueError(f"Collection manifest is missing required keys: {', '.join(missing_keys)}")
    if payload.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ValueError("Collection manifest schema version is not supported")
    if payload.get("status") not in VALID_RUN_STATUSES:
        raise ValueError(f"Invalid collection manifest status: {payload.get('status')}")
    if not isinstance(payload.get("endpoint_runs"), list):
        raise ValueError("Collection manifest endpoint_runs must be a list")
    if not isinstance(payload.get("datasets"), list):
        raise ValueError("Collection manifest datasets must be a list")
    for endpoint_run in payload["endpoint_runs"]:
        if endpoint_run.get("status") not in VALID_ENDPOINT_STATUSES:
            raise ValueError(
                f"Invalid endpoint execution status: {endpoint_run.get('status')}"
            )
    for dataset in payload["datasets"]:
        if not re.fullmatch(r"[a-f0-9]{64}", str(dataset.get("sha256") or "")):
            raise ValueError(
                f"Dataset has an invalid SHA-256 digest: {dataset.get('filename')}"
            )


class CollectionManifestRecorder:
    """Thread-safe accumulator for one azure-collect execution."""

    def __init__(
        self,
        run_id: str,
        output_dir: Path,
        context: Optional[Mapping[str, Any]] = None,
        options: Optional[Mapping[str, Any]] = None,
        project_dir: Optional[Path] = None,
    ) -> None:
        self.run_id = str(run_id)
        self.output_dir = Path(output_dir)
        # Keep caller-owned mappings isolated while preserving every supplied value.
        self.context = deepcopy(dict(context or {}))
        self.options = deepcopy(dict(options or {}))
        self.started_at = utc_timestamp()
        self.completed_at: Optional[str] = None
        self.status = "running"
        self.endpoint_runs: List[Dict[str, Any]] = []
        self.datasets: List[Dict[str, Any]] = []
        self.errors: List[Dict[str, Any]] = []
        self.limitations: List[str] = []
        self._planned_endpoints: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._observed_endpoints = set()
        self._lock = threading.Lock()

        repository_dir = Path(project_dir or Path(__file__).resolve().parent)
        self.tool = {
            "name": "azure-assess",
            "git_commit": detect_git_commit(repository_dir),
            "python_version": platform.python_version(),
            "azure_cli_version": None,
        }

    def register_endpoints(self, endpoints: Iterable[Mapping[str, Any]], category: str) -> None:
        """Record the endpoint set selected for this execution."""
        with self._lock:
            for endpoint in endpoints:
                name = str(endpoint.get("name") or "unknown")
                command_template = str(endpoint.get("cli_command") or "")
                self._planned_endpoints[(category, name)] = {
                    "endpoint_id": endpoint_id(endpoint.get("output_prefix") or command_template),
                    "endpoint_name": name,
                    "category": category,
                    "command_template": command_template,
                }

    def set_azure_cli_version(self, value: Any) -> None:
        """Attach the Azure CLI version string when available."""
        with self._lock:
            self.tool["azure_cli_version"] = str(value) if value else None

    def update_context(self, values: Mapping[str, Any]) -> None:
        """Update run context after authentication establishes the active account."""
        with self._lock:
            self.context.update(deepcopy(dict(values)))

    def record_execution(
        self,
        endpoint_name: str,
        category: str,
        command_template: str,
        started_at: str,
        duration_seconds: float,
        returncode: Optional[int],
        result_count: Optional[int],
        retry_count: int = 0,
        parameter_context: Optional[Mapping[str, Any]] = None,
        error_message: Optional[str] = None,
        diagnostic_text: Optional[str] = None,
        endpoint_identifier: Optional[str] = None,
    ) -> None:
        """Record one completed Azure CLI execution."""
        status = classify_execution_status(
            returncode,
            result_count,
            error_message=error_message,
            diagnostic_text=diagnostic_text,
        )
        record = {
            "endpoint_id": endpoint_id(endpoint_identifier or command_template),
            "endpoint_name": str(endpoint_name or "unknown"),
            "category": str(category or "collection"),
            "command_template": str(command_template),
            "parameter_context": deepcopy(dict(parameter_context or {})),
            "status": status,
            "started_at": started_at,
            "duration_ms": max(0, round(float(duration_seconds) * 1000)),
            "returncode": returncode,
            "result_count": result_count,
            "attempt_count": max(1, int(retry_count) + 1),
            "error": truncate_error_text(error_message) if error_message else None,
        }
        with self._lock:
            self.endpoint_runs.append(record)
            self._observed_endpoints.add((record["category"], record["endpoint_name"]))
            if status in {"failed", "unauthorised"}:
                self.errors.append(
                    {
                        "endpoint_name": record["endpoint_name"],
                        "category": record["category"],
                        "status": status,
                        "message": record["error"] or "Azure CLI command failed",
                    }
                )

    def record_skipped_endpoint(
        self,
        endpoint_name: str,
        category: str,
        command_template: str,
        reason: str,
        endpoint_identifier: Optional[str] = None,
    ) -> None:
        """Record a selected endpoint that could not be executed."""
        record = {
            "endpoint_id": endpoint_id(endpoint_identifier or command_template),
            "endpoint_name": str(endpoint_name or "unknown"),
            "category": str(category or "collection"),
            "command_template": str(command_template),
            "parameter_context": {},
            "status": "skipped",
            "started_at": None,
            "duration_ms": 0,
            "returncode": None,
            "result_count": None,
            "attempt_count": 0,
            "error": truncate_error_text(reason),
        }
        with self._lock:
            self.endpoint_runs.append(record)
            self._observed_endpoints.add((record["category"], record["endpoint_name"]))

    def record_dataset(
        self,
        path: Path,
        data: Any,
        append: bool = False,
        record_count: Optional[int] = None,
        source_endpoint_identifier: Optional[str] = None,
        source_endpoint_identifiers: Optional[Iterable[str]] = None,
    ) -> None:
        """Record the identity and integrity metadata for a generated JSON dataset."""
        dataset_path = Path(path)
        inferred_endpoint_id = self._source_endpoint_id(dataset_path)
        source_endpoint_ids = [
            endpoint_id(identifier)
            for identifier in (source_endpoint_identifiers or [])
            if identifier
        ]
        if source_endpoint_identifier:
            source_endpoint_ids.insert(0, endpoint_id(source_endpoint_identifier))
        source_endpoint_ids = list(dict.fromkeys(source_endpoint_ids))
        if not source_endpoint_ids:
            source_endpoint_ids = [inferred_endpoint_id]
        record = {
            "dataset_id": dataset_path.stem,
            "filename": dataset_path.name,
            "source_endpoint_id": source_endpoint_ids[0],
            "source_endpoint_ids": source_endpoint_ids,
            "record_count": result_item_count(data) if record_count is None else int(record_count),
            "sha256": sha256_file(dataset_path),
            "size_bytes": dataset_path.stat().st_size,
            "write_mode": "append" if append else "replace",
        }
        with self._lock:
            self.datasets.append(record)

    def _source_endpoint_id(self, dataset_path: Path) -> str:
        """Derive the producing endpoint prefix from a timestamped dataset filename."""
        stem = Path(dataset_path).stem
        run_suffix = f"_{self.run_id}"
        if stem.endswith(run_suffix):
            return stem[:-len(run_suffix)]
        return stem

    def add_limitation(self, message: str) -> None:
        """Record a non-fatal limitation once."""
        limitation = str(message)
        with self._lock:
            if limitation not in self.limitations:
                self.limitations.append(limitation)

    def finish(self, execution_successful: bool = True) -> Dict[str, Any]:
        """Finalise planned endpoints and derive the overall run status."""
        with self._lock:
            if self.completed_at is not None:
                return self._as_dict_locked()

            for key, planned in self._planned_endpoints.items():
                if key in self._observed_endpoints:
                    continue
                self.endpoint_runs.append(
                    {
                        **planned,
                        "parameter_context": {},
                        "status": "not_attempted",
                        "started_at": None,
                        "duration_ms": 0,
                        "returncode": None,
                        "result_count": None,
                        "attempt_count": 0,
                        "error": "Selected endpoint was not attempted",
                    }
                )

            statuses = {item["status"] for item in self.endpoint_runs}
            failures = statuses.intersection({"failed", "unauthorised", "not_attempted"})
            successes = statuses.intersection({"success", "empty"})
            if not execution_successful and not successes:
                self.status = "failed"
            elif failures or not execution_successful:
                self.status = "partial" if successes else "failed"
            else:
                self.status = "success"
            self.completed_at = utc_timestamp()
            return self._as_dict_locked()

    def to_dict(self) -> Dict[str, Any]:
        """Return a serialisable snapshot without finalising the run."""
        with self._lock:
            return self._as_dict_locked()

    def _as_dict_locked(self) -> Dict[str, Any]:
        datasets = sorted(self.datasets, key=lambda item: item["filename"])
        output_files_by_endpoint: Dict[str, List[str]] = {}
        for dataset in datasets:
            source_endpoint_ids = dataset.get("source_endpoint_ids") or [
                dataset["source_endpoint_id"]
            ]
            for source_endpoint_id in source_endpoint_ids:
                output_files_by_endpoint.setdefault(source_endpoint_id, []).append(
                    dataset["filename"]
                )
        endpoint_runs = sorted(
            (
                {
                    **item,
                    "output_files": output_files_by_endpoint.get(item["endpoint_id"], []),
                }
                for item in self.endpoint_runs
            ),
            key=lambda item: (
                item.get("category") or "",
                item.get("endpoint_name") or "",
                json.dumps(item.get("parameter_context") or {}, sort_keys=True),
                item.get("started_at") or "",
            ),
        )
        errors = sorted(
            self.errors,
            key=lambda item: (item.get("category") or "", item.get("endpoint_name") or ""),
        )
        return {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "run_id": self.run_id,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "tool": dict(self.tool),
            "context": self.context,
            "options": self.options,
            "endpoint_runs": endpoint_runs,
            "datasets": datasets,
            "errors": errors,
            "limitations": sorted(self.limitations),
        }

    def write(self, execution_successful: bool = True) -> Path:
        """Atomically persist the final manifest beneath the selected output directory."""
        payload = self.finish(execution_successful=execution_successful)
        validate_manifest(payload)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        destination = self.output_dir / f"{MANIFEST_FILENAME_PREFIX}_{self.run_id}.json"
        descriptor, temporary_name = tempfile.mkstemp(
            dir=str(self.output_dir),
            prefix=f".{destination.name}.",
            suffix=".tmp",
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, destination)
        finally:
            if temporary_path.exists():
                temporary_path.unlink()
        return destination
