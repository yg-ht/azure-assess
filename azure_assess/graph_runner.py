#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Native, bounded-retry Microsoft Graph collection primitives."""

import json
import os
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from time import monotonic, sleep
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple


GRAPH_ROOT = "https://graph.microsoft.com"
TRANSIENT_STATUS = {429, 500, 502, 503, 504}
UNAUTHORISED_STATUS = {401, 403}
CAPABILITY_STATUS = {402, 404, 409, 422, 501}


class GraphError(RuntimeError):
    """A classified Graph request failure."""

    def __init__(self, message: str, *, status: Optional[int] = None, body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body

    @property
    def outcome(self) -> str:
        if self.status in UNAUTHORISED_STATUS:
            return "unauthorised"
        if self.status in CAPABILITY_STATUS:
            return "tenant_unavailable"
        return "failed"


@dataclass
class GraphResult:
    status: str
    count: int = 0
    pages: int = 0
    attempts: int = 0
    output_path: Optional[Path] = None
    contexts: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    error_status: Optional[int] = None
    incomplete: bool = False


def utc_interval(days: int, now: Optional[datetime] = None) -> Tuple[str, str]:
    """Return an exact UTC interval suitable for Graph filters."""
    if days < 1 or days > 365:
        raise ValueError("Graph lookback days must be between 1 and 365")
    end = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start = end - timedelta(days=days)
    render = lambda value: value.isoformat(timespec="seconds").replace("+00:00", "Z")
    return render(start), render(end)


def endpoint_url(endpoint: Mapping[str, Any], context: Mapping[str, Any]) -> str:
    path = str(endpoint["path"]).format(**context)
    if path.startswith("https://"):
        return path
    return f"{GRAPH_ROOT}/{endpoint['api']}{path}"


def resolved_body(endpoint: Mapping[str, Any], context: Mapping[str, Any]) -> Optional[Dict]:
    body = endpoint.get("body")
    if body is None:
        return None
    def resolve(value):
        if isinstance(value, str):
            return value.format(**context)
        if isinstance(value, list):
            return [resolve(item) for item in value]
        if isinstance(value, dict):
            return {key: resolve(item) for key, item in value.items()}
        return value
    return resolve(body)


def retry_delay(headers: Mapping[str, str], attempt: int, now: Optional[datetime] = None) -> float:
    value = headers.get("Retry-After") or headers.get("retry-after")
    if value:
        try:
            return max(0.0, float(value))
        except ValueError:
            try:
                target = parsedate_to_datetime(value)
                current = now or datetime.now(timezone.utc)
                return max(0.0, (target - current).total_seconds())
            except (TypeError, ValueError, OverflowError):
                pass
    return min(30.0, float(2 ** max(0, attempt - 1)))


class GraphTransport:
    """Small urllib transport using an already acquired app/delegated token."""

    def __init__(self, token: str, timeout: float = 60.0):
        self.token = token
        self.timeout = timeout

    def __call__(self, method: str, url: str, body: Optional[Mapping]) -> Tuple[int, Mapping[str, str], Any]:
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            url,
            data=payload,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
                decoded = json.loads(raw.decode("utf-8")) if raw else {}
                return response.status, dict(response.headers), decoded
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            raise GraphError(f"Microsoft Graph returned HTTP {exc.code}", status=exc.code, body=raw) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise GraphError(f"Microsoft Graph request failed: {exc}") from exc


class AtomicJsonArrayWriter:
    """Stream records to an atomic JSON dataset with no in-memory inventory."""

    def __init__(self, target: Path):
        self.target = Path(target)
        self.handle = None
        self.temp_path = None
        self.count = 0

    def __enter__(self):
        self.target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix=f".{self.target.name}.", suffix=".tmp", dir=str(self.target.parent))
        self.temp_path = Path(name)
        self.handle = os.fdopen(descriptor, "w", encoding="utf-8")
        self.handle.write("[\n")
        return self

    def write(self, record: Any) -> None:
        if self.count:
            self.handle.write(",\n")
        json.dump(record, self.handle, ensure_ascii=False, separators=(",", ":"))
        self.count += 1

    def __exit__(self, exc_type, exc, traceback):
        if self.handle:
            if exc_type is None:
                self.handle.write("\n]\n")
                self.handle.flush()
                os.fsync(self.handle.fileno())
            self.handle.close()
        if exc_type is None:
            os.replace(self.temp_path, self.target)
        elif self.temp_path:
            try:
                self.temp_path.unlink()
            except FileNotFoundError:
                pass


class GraphRunner:
    def __init__(
        self,
        transport: Callable[[str, str, Optional[Mapping]], Tuple[int, Mapping[str, str], Any]],
        *,
        max_attempts: int = 5,
        sleeper: Callable[[float], None] = sleep,
        poll_interval: float = 2.0,
        poll_timeout: float = 900.0,
    ):
        self.transport = transport
        self.max_attempts = max(1, max_attempts)
        self.sleeper = sleeper
        self.poll_interval = poll_interval
        self.poll_timeout = poll_timeout

    def request(self, method: str, url: str, body: Optional[Mapping] = None) -> Tuple[Any, int]:
        last_error = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                status, headers, payload = self.transport(method, url, body)
                if status >= 400:
                    raise GraphError(f"Microsoft Graph returned HTTP {status}", status=status, body=str(payload))
                if not isinstance(payload, (dict, list)):
                    raise GraphError("Microsoft Graph returned malformed JSON")
                return payload, attempt
            except GraphError as exc:
                last_error = exc
                if exc.status not in TRANSIENT_STATUS or attempt == self.max_attempts:
                    raise
                headers = getattr(exc, "headers", {})
                self.sleeper(retry_delay(headers, attempt))
        raise last_error

    @staticmethod
    def records(payload: Any) -> Tuple[List[Any], Optional[str]]:
        if isinstance(payload, list):
            return payload, None
        if not isinstance(payload, dict):
            raise GraphError("Microsoft Graph returned an unexpected response shape")
        if "value" in payload:
            if not isinstance(payload["value"], list):
                raise GraphError("Microsoft Graph value property was not an array")
            return payload["value"], payload.get("@odata.nextLink")
        return [payload] if payload else [], payload.get("@odata.nextLink")

    def collect(self, endpoint: Mapping[str, Any], target: Path, context: Mapping[str, Any]) -> GraphResult:
        started = monotonic()
        result = GraphResult(status="failed", output_path=Path(target))
        url = endpoint_url(endpoint, context)
        body = resolved_body(endpoint, context)
        try:
            if endpoint.get("mode") == "audit_query":
                return self._collect_audit(endpoint, target, context)
            with AtomicJsonArrayWriter(target) as writer:
                while url:
                    payload, attempts = self.request(endpoint["method"], url, body)
                    result.attempts += attempts
                    records, next_url = self.records(payload)
                    result.pages += 1
                    page_context = {"page": result.pages, "url": url, "record_count": len(records)}
                    result.contexts.append(page_context)
                    for record in records:
                        if isinstance(record, dict):
                            record = dict(record)
                            record["_collectionContext"] = {
                                "endpoint_id": endpoint["id"], "api": endpoint["api"],
                                "profile": endpoint["profile"], "page": result.pages,
                                "lookback_start": context.get("start"), "lookback_end": context.get("end"),
                                **({"parent_id": context["parent_id"]} if context.get("parent_id") else {}),
                            }
                        writer.write(record)
                    result.count = writer.count
                    url = next_url if endpoint.get("pagination", True) else None
                    body = None
            result.status = "success" if result.count else "empty"
        except GraphError as exc:
            result.status, result.error, result.error_status = exc.outcome, str(exc), exc.status
            result.incomplete = result.pages > 0
            if result.incomplete:
                result.status = "failed"
        result.contexts.append({"duration_ms": round((monotonic() - started) * 1000)})
        return result

    def _collect_audit(self, endpoint: Mapping[str, Any], target: Path, context: Mapping[str, Any]) -> GraphResult:
        create_url = endpoint_url(endpoint, context)
        payload, attempts = self.request("POST", create_url, resolved_body(endpoint, context))
        query_id = payload.get("id") if isinstance(payload, dict) else None
        if not query_id:
            raise GraphError("Audit query creation did not return an ID")
        status_url = f"{GRAPH_ROOT}/{endpoint['api']}/security/auditLog/queries/{query_id}"
        deadline = monotonic() + self.poll_timeout
        polls = 0
        while monotonic() < deadline:
            status_payload, used = self.request("GET", status_url)
            attempts += used
            polls += 1
            status = str(status_payload.get("status", "")).lower()
            if status == "succeeded":
                records_endpoint = dict(endpoint, method="GET", mode="collection", path=f"/security/auditLog/queries/{query_id}/records")
                collected = self.collect(records_endpoint, target, context)
                collected.attempts += attempts
                collected.contexts.insert(0, {"query_id": query_id, "poll_count": polls})
                return collected
            if status in {"failed", "cancelled"}:
                raise GraphError(f"Audit query finished with status {status}")
            self.sleeper(self.poll_interval)
        raise GraphError("Audit query polling timed out")

