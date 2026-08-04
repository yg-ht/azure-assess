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


MANIFEST_SCHEMA_VERSION = "2.5"
SUPPORTED_MANIFEST_SCHEMA_VERSIONS = {
    "2.0",
    "2.1",
    "2.2",
    "2.3",
    "2.4",
    MANIFEST_SCHEMA_VERSION,
}
VISIBILITY_MANIFEST_SCHEMA_VERSIONS = {"2.4", MANIFEST_SCHEMA_VERSION}
MANIFEST_FILENAME_PREFIX = "azure-collection-manifest"
MAX_ERROR_MESSAGE_CHARS = 1000
VALID_RUN_STATUSES = {"running", "success", "partial", "failed"}
VALID_ENDPOINT_STATUSES = {
    "success",
    "empty",
    "failed",
    "unauthorised",
    "tenant_unavailable",
    "not_applicable",
    "skipped",
    "not_attempted",
}
LEGACY_ENDPOINT_STATUSES = VALID_ENDPOINT_STATUSES - {
    "not_applicable",
    "tenant_unavailable",
}
VALID_SKIPPED_REASON_CODES = {
    "upstream_source_failed",
    "upstream_source_unauthorised",
    "upstream_source_tenant_unavailable",
    "upstream_source_not_attempted",
    "upstream_source_skipped",
    "upstream_source_returned_no_data",
    "upstream_source_not_applicable",
    "upstream_source_unavailable",
    "required_parameter_missing",
    "no_applicable_source_records",
    "no_usable_parameter_records",
    "parameter_template_mismatch",
    "skip_reason_unclassified",
}
VALID_NOT_ATTEMPTED_REASON_CODES = {
    "collection_interrupted",
    "collection_terminated_by_exception",
    "collector_outcome_not_recorded",
}
PRE_23_ENDPOINT_STATUSES = VALID_ENDPOINT_STATUSES - {"tenant_unavailable"}
PRE_23_SKIPPED_REASON_CODES = VALID_SKIPPED_REASON_CODES - {
    "upstream_source_tenant_unavailable"
}
VALID_VISIBILITY_STATUSES = {
    "access_verified",
    "scope_restricted",
    "visibility_unverified",
    "not_evaluated",
}
ENDPOINT_ACCESS_VERIFICATION_KEYS = {
    "status",
    "plane",
    "scope",
    "method",
    "reason_code",
    "required_permissions",
}
COLLECTION_ACCESS_VERIFICATION_KEYS = {"arm", "graph"}
ARM_ACCESS_VERIFICATION_KEYS = {
    "status",
    "scope",
    "method",
    "reason_code",
    "broad_read_granted",
    "role_assignment_count",
    "role_definition_count",
    "deny_assignment_count",
    "applicable_read_deny_count",
}
GRAPH_ACCESS_VERIFICATION_KEYS = {
    "status",
    "method",
    "reason_code",
    "token_type",
    "granted_permissions",
}
NOT_APPLICABLE_ERROR_MARKERS = (
    "network watcher is not enabled for region",
)
NOT_APPLICABLE_ERROR_CODES = {
    "resourcetypenotsupported",
}
TENANT_UNAVAILABLE_ERROR_CODES = {
    "authenticationrequestfromnonpremiumtenantorb2ctenant",
}
AZURE_ERROR_CODE_PATTERNS = (
    re.compile(
        r"(?im)^\s*(?:ERROR:\s*)?\((?P<code>[A-Za-z][A-Za-z0-9_.-]+)\)"
    ),
    re.compile(r"(?im)^\s*(?:error\s+)?code\s*:\s*(?P<code>[A-Za-z0-9_.-]+)"),
    re.compile(r'(?i)"code"\s*:\s*"(?P<code>[^"]+)"'),
)


def utc_timestamp() -> str:
    """Return a second-precision RFC 3339 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def truncate_error_text(value: Any) -> str:
    """Limit persisted endpoint error text without changing retained content."""
    text = str(value or "")
    if len(text) > MAX_ERROR_MESSAGE_CHARS:
        text = text[:MAX_ERROR_MESSAGE_CHARS] + "... [truncated]"
    return text


def _error_code_from_json(value: Any) -> Optional[str]:
    """Return the first explicit error code in a decoded Azure response."""
    if isinstance(value, Mapping):
        nested_error = value.get("error")
        if isinstance(nested_error, Mapping):
            code = nested_error.get("code")
            if code not in (None, ""):
                return str(code)
        code = value.get("code")
        if code not in (None, ""):
            return str(code)
        for child in value.values():
            code = _error_code_from_json(child)
            if code:
                return code
    elif isinstance(value, list):
        for child in value:
            code = _error_code_from_json(child)
            if code:
                return code
    return None


def extract_azure_error_code(value: Any) -> Optional[str]:
    """Extract an Azure-supplied error code without deriving one from permissions."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        decoded = json.loads(text)
    except (TypeError, ValueError):
        decoded = None
    code = _error_code_from_json(decoded)
    if code:
        return code
    for pattern in AZURE_ERROR_CODE_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group("code")
    return None


def is_not_applicable_error(value: Any) -> bool:
    """Return whether Azure explicitly reported a known inapplicable scope."""
    text = str(value or "").strip().lower()
    error_code = re.sub(
        r"[^a-z0-9]",
        "",
        str(extract_azure_error_code(value) or "").lower(),
    )
    return bool(text) and (
        error_code in NOT_APPLICABLE_ERROR_CODES
        or any(marker in text for marker in NOT_APPLICABLE_ERROR_MARKERS)
    )


def is_tenant_unavailable_error(value: Any) -> bool:
    """Return whether Azure reported a tenant licence or capability restriction."""
    error_code = extract_azure_error_code(value)
    normalised_error_code = re.sub(
        r"[^a-z0-9]", "", str(error_code or value or "").lower()
    )
    return normalised_error_code in TENANT_UNAVAILABLE_ERROR_CODES


def result_item_count(data: Any) -> int:
    """Return the number of semantic records in common Azure JSON payloads."""
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        if isinstance(data.get("value"), list):
            return len(data["value"])
        return 1 if data else 0
    return 0


def normalise_access_verification(value: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """Build a bounded, non-secret verification record for one endpoint."""
    if value is not None and not isinstance(value, Mapping):
        raise ValueError("Endpoint access verification must be an object")
    source = dict(value or {})
    unknown_keys = sorted(set(source) - ENDPOINT_ACCESS_VERIFICATION_KEYS)
    if unknown_keys:
        raise ValueError(
            "Endpoint access verification contains unsupported fields: "
            + ", ".join(unknown_keys)
        )
    status = str(source.get("status") or "not_evaluated")
    if status not in VALID_VISIBILITY_STATUSES:
        raise ValueError(f"Invalid endpoint visibility status: {status}")
    required_permissions = source.get("required_permissions") or []
    if not isinstance(required_permissions, (list, tuple, set)):
        raise ValueError("Endpoint required permissions must be a list")
    return {
        "status": status,
        "plane": str(source.get("plane") or "unknown"),
        "scope": str(source["scope"]) if source.get("scope") else None,
        "method": str(source.get("method") or "not_evaluated"),
        "reason_code": str(source.get("reason_code") or "not_evaluated"),
        "required_permissions": sorted(
            {str(item) for item in required_permissions if item}
        ),
    }


def normalise_collection_access_verification(
    value: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Build the bounded run-level access evidence persisted in schema 2.5."""
    if value is not None and not isinstance(value, Mapping):
        raise ValueError("Collection access verification must be an object")
    source = dict(value or {})
    unknown_keys = sorted(set(source) - COLLECTION_ACCESS_VERIFICATION_KEYS)
    if unknown_keys:
        raise ValueError(
            "Collection access verification contains unsupported fields: "
            + ", ".join(unknown_keys)
        )

    arm = source.get("arm") or {}
    graph = source.get("graph") or {}
    if not isinstance(arm, Mapping) or not isinstance(graph, Mapping):
        raise ValueError("Collection ARM and Graph access evidence must be objects")
    arm_unknown = sorted(set(arm) - ARM_ACCESS_VERIFICATION_KEYS)
    graph_unknown = sorted(set(graph) - GRAPH_ACCESS_VERIFICATION_KEYS)
    if arm_unknown or graph_unknown:
        fields = arm_unknown + graph_unknown
        raise ValueError(
            "Collection access verification contains unsupported evidence fields: "
            + ", ".join(fields)
        )

    arm_status = str(arm.get("status") or "not_evaluated")
    graph_status = str(graph.get("status") or "not_evaluated")
    if arm_status not in VALID_VISIBILITY_STATUSES:
        raise ValueError(f"Invalid ARM visibility status: {arm_status}")
    if graph_status not in VALID_VISIBILITY_STATUSES:
        raise ValueError(f"Invalid Graph visibility status: {graph_status}")
    token_type = str(graph.get("token_type") or "unknown")
    if token_type not in {"application", "delegated", "unknown"}:
        raise ValueError(f"Invalid Graph token type: {token_type}")
    granted_permissions = graph.get("granted_permissions") or []
    if not isinstance(granted_permissions, (list, tuple, set)):
        raise ValueError("Graph granted permissions must be a list")
    if "broad_read_granted" in arm and not isinstance(
        arm["broad_read_granted"], bool
    ):
        raise ValueError("ARM broad-read evidence must be a boolean")

    counts = {}
    for key in (
        "role_assignment_count",
        "role_definition_count",
        "deny_assignment_count",
        "applicable_read_deny_count",
    ):
        count = arm.get(key, 0)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError(f"Invalid ARM access evidence count: {key}")
        counts[key] = count

    return {
        "arm": {
            "status": arm_status,
            "scope": str(arm["scope"]) if arm.get("scope") else None,
            "method": str(arm.get("method") or "not_evaluated"),
            "reason_code": str(arm.get("reason_code") or "not_evaluated"),
            "broad_read_granted": arm.get("broad_read_granted", False),
            **counts,
        },
        "graph": {
            "status": graph_status,
            "method": str(graph.get("method") or "not_evaluated"),
            "reason_code": str(graph.get("reason_code") or "not_evaluated"),
            "token_type": token_type,
            "granted_permissions": sorted(
                {str(item) for item in granted_permissions if item}
            ),
        },
    }


def interpreted_visibility_status(
    manifest_schema_version: Any,
    verification: Optional[Mapping[str, Any]],
) -> str:
    """Interpret endpoint evidence conservatively across manifest revisions."""
    if not isinstance(verification, Mapping):
        return "visibility_unverified"
    status = str(verification.get("status") or "visibility_unverified")
    if status not in VALID_VISIBILITY_STATUSES:
        return "visibility_unverified"
    if (
        str(manifest_schema_version or "") == "2.4"
        and verification.get("method") == "arm_effective_permissions"
        and status in {"access_verified", "scope_restricted"}
    ):
        # Schema 2.4 used an undocumented subscription-level permissions call
        # and did not account for deny assignments, so it cannot prove access.
        return "visibility_unverified"
    return status


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
    error_code = extract_azure_error_code(diagnostic_text or error_message)
    normalised_error_code = re.sub(r"[^a-z0-9]", "", str(error_code or "").lower())
    permission_error_codes = (
        "authorizationfailed",
        "forbidden",
        "insufficientprivileges",
        "requestdenied",
        "unauthorized",
    )
    combined_error = " ".join(
        str(item or "").lower()
        for item in (error_message, diagnostic_text)
    )
    if error_message or returncode not in (None, 0):
        if (
            is_not_applicable_error(diagnostic_text)
            or is_not_applicable_error(error_message)
        ):
            return "not_applicable"
        if is_tenant_unavailable_error(diagnostic_text or error_message):
            return "tenant_unavailable"
        if any(code in normalised_error_code for code in permission_error_codes):
            return "unauthorised"
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
    schema_version = payload.get("schema_version")
    if schema_version not in SUPPORTED_MANIFEST_SCHEMA_VERSIONS:
        raise ValueError("Collection manifest schema version is not supported")
    if payload.get("status") not in VALID_RUN_STATUSES:
        raise ValueError(f"Invalid collection manifest status: {payload.get('status')}")
    if not isinstance(payload.get("endpoint_runs"), list):
        raise ValueError("Collection manifest endpoint_runs must be a list")
    if not isinstance(payload.get("datasets"), list):
        raise ValueError("Collection manifest datasets must be a list")
    if schema_version in VISIBILITY_MANIFEST_SCHEMA_VERSIONS and not isinstance(
        payload.get("access_verification"), Mapping
    ):
        raise ValueError("Collection manifest access_verification must be an object")
    if schema_version == MANIFEST_SCHEMA_VERSION:
        normalise_collection_access_verification(payload["access_verification"])
    if schema_version == "2.0":
        valid_endpoint_statuses = LEGACY_ENDPOINT_STATUSES
    elif schema_version in {"2.1", "2.2"}:
        valid_endpoint_statuses = PRE_23_ENDPOINT_STATUSES
    else:
        valid_endpoint_statuses = VALID_ENDPOINT_STATUSES
    for endpoint_run in payload["endpoint_runs"]:
        endpoint_status = endpoint_run.get("status")
        if endpoint_status not in valid_endpoint_statuses:
            raise ValueError(
                f"Invalid endpoint execution status: {endpoint_status}"
            )
        if (
            schema_version in {"2.2", "2.3", "2.4", MANIFEST_SCHEMA_VERSION}
            and endpoint_status == "skipped"
        ):
            valid_reason_codes = (
                PRE_23_SKIPPED_REASON_CODES
                if schema_version == "2.2"
                else VALID_SKIPPED_REASON_CODES
            )
            if endpoint_run.get("reason_code") not in valid_reason_codes:
                raise ValueError("Skipped endpoint is missing a valid reason code")
        if (
            schema_version in {"2.2", "2.3", "2.4", MANIFEST_SCHEMA_VERSION}
            and endpoint_status == "not_attempted"
        ):
            if endpoint_run.get("reason_code") not in VALID_NOT_ATTEMPTED_REASON_CODES:
                raise ValueError("Unattempted endpoint is missing a valid reason code")
        if schema_version in VISIBILITY_MANIFEST_SCHEMA_VERSIONS:
            verification = endpoint_run.get("access_verification")
            if not isinstance(verification, Mapping):
                raise ValueError("Endpoint execution is missing access verification")
            normalise_access_verification(verification)
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
        self.access_verification = normalise_collection_access_verification(None)
        self._planned_endpoints: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._observed_endpoints = set()
        self._lock = threading.Lock()

        repository_dir = Path(project_dir or Path(__file__).resolve().parents[1])
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

    def set_access_verification(self, values: Mapping[str, Any]) -> None:
        """Persist non-secret collection-scope authorisation evidence."""
        with self._lock:
            self.access_verification = normalise_collection_access_verification(
                values
            )

    def endpoint_statuses(self, endpoint_identifier: str) -> List[str]:
        """Return observed statuses for one stable endpoint identifier."""
        wanted = endpoint_id(endpoint_identifier)
        with self._lock:
            return sorted(
                {
                    str(record.get("status"))
                    for record in self.endpoint_runs
                    if record.get("endpoint_id") == wanted and record.get("status")
                }
            )

    def endpoint_outcomes(self, endpoint_identifier: str) -> List[Dict[str, Any]]:
        """Return complete observed outcomes for one stable endpoint identifier."""
        wanted = endpoint_id(endpoint_identifier)
        with self._lock:
            return deepcopy(
                [
                    record
                    for record in self.endpoint_runs
                    if record.get("endpoint_id") == wanted
                ]
            )

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
        access_verification: Optional[Mapping[str, Any]] = None,
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
            "error_code": extract_azure_error_code(diagnostic_text or error_message),
            "response_error": (
                truncate_error_text(diagnostic_text) if diagnostic_text else None
            ),
            "response_error_truncated": (
                len(str(diagnostic_text or "")) > MAX_ERROR_MESSAGE_CHARS
            ),
            "access_verification": normalise_access_verification(
                access_verification
            ),
        }
        with self._lock:
            self.endpoint_runs.append(record)
            self._observed_endpoints.add((record["category"], record["endpoint_name"]))
            if status in {"failed", "unauthorised", "tenant_unavailable"}:
                self.errors.append(
                    {
                        "endpoint_name": record["endpoint_name"],
                        "category": record["category"],
                        "status": status,
                        "error_code": record["error_code"],
                        "returncode": record["returncode"],
                        "message": (
                            record["response_error"]
                            or record["error"]
                            or "Azure CLI command failed"
                        ),
                    }
                )

    def record_skipped_endpoint(
        self,
        endpoint_name: str,
        category: str,
        command_template: str,
        reason: str,
        endpoint_identifier: Optional[str] = None,
        reason_code: str = "skip_reason_unclassified",
        reason_details: Optional[Mapping[str, Any]] = None,
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
            "reason_code": str(reason_code),
            "reason_details": deepcopy(dict(reason_details or {})),
            "access_verification": normalise_access_verification(None),
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

    def finish(
        self,
        execution_successful: bool = True,
        unattempted_reason_code: Optional[str] = None,
        unattempted_reason: Optional[str] = None,
        unattempted_reason_details: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Finalise planned endpoints and derive the overall run status."""
        with self._lock:
            if self.completed_at is not None:
                return self._as_dict_locked()

            fallback_reason_code = unattempted_reason_code or "collector_outcome_not_recorded"
            fallback_reason = unattempted_reason or (
                "Collector completed without recording an endpoint outcome"
            )
            fallback_reason_details = deepcopy(dict(unattempted_reason_details or {}))
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
                        "error": truncate_error_text(fallback_reason),
                        "reason_code": fallback_reason_code,
                        "reason_details": fallback_reason_details,
                        "access_verification": normalise_access_verification(None),
                    }
                )

            statuses = {item["status"] for item in self.endpoint_runs}
            failures = statuses.intersection(
                {"failed", "unauthorised", "tenant_unavailable", "not_attempted"}
            )
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
            "access_verification": deepcopy(self.access_verification),
            "endpoint_runs": endpoint_runs,
            "datasets": datasets,
            "errors": errors,
            "limitations": sorted(self.limitations),
        }

    def write(
        self,
        execution_successful: bool = True,
        unattempted_reason_code: Optional[str] = None,
        unattempted_reason: Optional[str] = None,
        unattempted_reason_details: Optional[Mapping[str, Any]] = None,
    ) -> Path:
        """Atomically persist the final manifest beneath the selected output directory."""
        payload = self.finish(
            execution_successful=execution_successful,
            unattempted_reason_code=unattempted_reason_code,
            unattempted_reason=unattempted_reason,
            unattempted_reason_details=unattempted_reason_details,
        )
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
