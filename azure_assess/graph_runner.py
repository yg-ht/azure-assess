#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Native, bounded-retry Microsoft Graph collection primitives."""

import csv
import io
import json
import os
import tempfile
import urllib.error
import urllib.parse
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
CAPABILITY_STATUS = {402}
CAPABILITY_ERROR_CODES = {
    "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
    "AuthenticationRequestFromNonPremiumTenantOrB2CTenant",
    "LicenseRestriction",
    "NotLicensed",
    "TenantNotLicensed",
}
CAPABILITY_MESSAGE_MARKERS = (
    "doesn't have premium license",
    "does not have a premium license",
    "licence is required",
    "license is required",
    "tenant is not licensed",
    "tenant is not onboarded",
    "service is not available for this tenant",
)


class GraphError(RuntimeError):
    """A classified Graph request failure."""

    def __init__(self, message: str, *, status: Optional[int] = None, body: str = "", headers: Optional[Mapping[str, str]] = None):
        super().__init__(message)
        self.status = status
        self.body = body
        self.headers = dict(headers or {})
        self.attempts = 0

    @property
    def error_payload(self) -> Mapping[str, Any]:
        try:
            payload = json.loads(self.body or "{}")
        except (TypeError, ValueError):
            return {}
        return payload if isinstance(payload, Mapping) else {}

    @property
    def code(self) -> Optional[str]:
        error = self.error_payload.get("error")
        if isinstance(error, Mapping) and error.get("code"):
            return str(error["code"])
        if self.error_payload.get("code"):
            return str(self.error_payload["code"])
        return None

    @property
    def detail(self) -> str:
        error = self.error_payload.get("error")
        if isinstance(error, Mapping) and error.get("message"):
            return str(error["message"])
        if self.error_payload.get("message"):
            return str(self.error_payload["message"])
        return str(self)

    def outcome_for(self, api_channel: str = "v1.0") -> str:
        detail = self.detail.lower()
        if (
            self.code in CAPABILITY_ERROR_CODES
            or self.status in CAPABILITY_STATUS
            or any(marker in detail for marker in CAPABILITY_MESSAGE_MARKERS)
        ):
            return "tenant_unavailable"
        if self.status in UNAUTHORISED_STATUS:
            return "unauthorised"
        if api_channel == "beta" and self.status in {404, 501}:
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
    diagnostic: Optional[str] = None
    incomplete: bool = False


class SafeGraphRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Do not forward a Graph bearer token to a report download host."""

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        redirected = super().redirect_request(
            request, file_pointer, code, message, headers, new_url
        )
        if redirected is None:
            return None
        old_host = urllib.parse.urlsplit(request.full_url).hostname
        new_host = urllib.parse.urlsplit(new_url).hostname
        if old_host != new_host:
            redirected.remove_header("Authorization")
        return redirected


def utc_interval(days: int, now: Optional[datetime] = None) -> Tuple[str, str]:
    """Return an exact UTC interval suitable for Graph filters."""
    if days < 1 or days > 365:
        raise ValueError("Graph lookback days must be between 1 and 365")
    end = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start = end - timedelta(days=days)
    render = lambda value: value.isoformat(timespec="seconds").replace("+00:00", "Z")
    return render(start), render(end)


def endpoint_url(endpoint: Mapping[str, Any], context: Mapping[str, Any]) -> str:
    resolved_context = dict(context)
    if resolved_context.get("parent_id") is not None:
        resolved_context["parent_id"] = urllib.parse.quote(
            str(resolved_context["parent_id"]), safe=""
        )
    path = str(endpoint["path"]).format(**resolved_context)
    path = path.replace(" ", "%20")
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
        self.opener = urllib.request.build_opener(SafeGraphRedirectHandler())

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
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read()
                content_type = str(response.headers.get("Content-Type", "")).lower()
                try:
                    if "json" in content_type:
                        decoded = json.loads(raw.decode("utf-8")) if raw else {}
                    else:
                        decoded = raw.decode("utf-8-sig", errors="strict")
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise GraphError(
                        "Microsoft Graph returned a malformed response",
                        status=response.status,
                    ) from exc
                return response.status, dict(response.headers), decoded
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            raise GraphError(
                f"Microsoft Graph returned HTTP {exc.code}",
                status=exc.code,
                body=raw,
                headers=dict(exc.headers or {}),
            ) from exc
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
        progress: Optional[Callable[[str, Mapping[str, Any]], None]] = None,
    ):
        self.transport = transport
        self.max_attempts = max(1, max_attempts)
        self.sleeper = sleeper
        self.poll_interval = poll_interval
        self.poll_timeout = poll_timeout
        self.progress = progress

    def report_progress(self, event: str, **details: Any) -> None:
        """Emit non-sensitive progress without coupling collection to a console."""
        if self.progress is not None:
            self.progress(event, details)

    def request(
        self,
        method: str,
        url: str,
        body: Optional[Mapping] = None,
        progress_context: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[Any, int]:
        last_error = None
        progress_context = dict(progress_context or {})
        for attempt in range(1, self.max_attempts + 1):
            try:
                status, headers, payload = self.transport(method, url, body)
                if status >= 400:
                    raise GraphError(
                        f"Microsoft Graph returned HTTP {status}",
                        status=status,
                        body=(
                            json.dumps(payload, ensure_ascii=False)
                            if isinstance(payload, (dict, list)) else str(payload)
                        ),
                        headers=headers,
                    )
                if not isinstance(payload, (dict, list, str)):
                    raise GraphError("Microsoft Graph returned a malformed response")
                return payload, attempt
            except GraphError as exc:
                last_error = exc
                if exc.status not in TRANSIENT_STATUS or attempt == self.max_attempts:
                    exc.attempts = attempt
                    raise
                headers = getattr(exc, "headers", {})
                delay = retry_delay(headers, attempt)
                self.report_progress(
                    "retry_wait",
                    **progress_context,
                    attempt=attempt,
                    max_attempts=self.max_attempts,
                    status=exc.status,
                    delay_seconds=delay,
                )
                self.sleeper(delay)
        raise last_error

    @staticmethod
    def records(
        payload: Any,
        response_format: str = "json",
        records_field: Optional[str] = None,
    ) -> Tuple[Iterable[Any], Optional[str]]:
        if response_format == "csv":
            if not isinstance(payload, str):
                raise GraphError("Microsoft Graph report did not return CSV data")
            return csv.DictReader(io.StringIO(payload)), None
        if isinstance(payload, list):
            return payload, None
        if not isinstance(payload, dict):
            raise GraphError("Microsoft Graph returned an unexpected response shape")
        if records_field:
            values = payload.get(records_field)
            if not isinstance(values, list):
                raise GraphError(
                    f"Microsoft Graph {records_field} property was not an array"
                )
            return values, payload.get("@odata.nextLink")
        if "value" in payload:
            value = payload["value"]
            if isinstance(value, list):
                return value, payload.get("@odata.nextLink")
            if isinstance(value, dict):
                return [value], payload.get("@odata.nextLink")
            if value is None:
                return [], payload.get("@odata.nextLink")
            raise GraphError("Microsoft Graph value property was not an object or array")
        return [payload] if payload else [], payload.get("@odata.nextLink")

    def collect(self, endpoint: Mapping[str, Any], target: Path, context: Mapping[str, Any]) -> GraphResult:
        started = monotonic()
        result = GraphResult(status="failed", output_path=Path(target))
        url = endpoint_url(endpoint, context)
        body = resolved_body(endpoint, context)
        progress_context = {
            "endpoint_id": endpoint.get("id"),
            "endpoint_name": endpoint.get("name"),
        }
        try:
            if endpoint.get("mode") == "audit_query":
                return self._collect_audit(endpoint, target, context)
            with AtomicJsonArrayWriter(target) as writer:
                while url:
                    try:
                        payload, attempts = self.request(
                            endpoint["method"],
                            url,
                            body,
                            progress_context,
                        )
                    except GraphError as exc:
                        result.attempts += max(1, exc.attempts)
                        if not result.pages:
                            raise
                        result.status = "incomplete"
                        result.error = (
                            f"{exc.code}: {exc.detail}" if exc.code else exc.detail
                        )
                        result.error_status = exc.status
                        result.diagnostic = exc.body or str(exc)
                        result.incomplete = True
                        break
                    result.attempts += attempts
                    records, next_url = self.records(
                        payload,
                        endpoint.get("response_format", "json"),
                        endpoint.get("records_field"),
                    )
                    records = list(records)
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
                    self.report_progress(
                        "page_completed",
                        **progress_context,
                        page=result.pages,
                        page_records=len(records),
                        total_records=result.count,
                    )
                    url = next_url if endpoint.get("pagination", True) else None
                    body = None
            if not result.incomplete:
                result.status = "success" if result.count else "empty"
        except GraphError as exc:
            if not result.attempts:
                result.attempts = max(1, exc.attempts)
            result.status = exc.outcome_for(str(endpoint.get("api", "v1.0")))
            result.error = (
                f"{exc.code}: {exc.detail}" if exc.code else exc.detail
            )
            result.error_status = exc.status
            result.diagnostic = exc.body or str(exc)
            result.incomplete = result.pages > 0
            if result.incomplete:
                result.status = "incomplete"
        result.contexts.append({"duration_ms": round((monotonic() - started) * 1000)})
        return result

    def _collect_audit(self, endpoint: Mapping[str, Any], target: Path, context: Mapping[str, Any]) -> GraphResult:
        create_url = endpoint_url(endpoint, context)
        progress_context = {
            "endpoint_id": endpoint.get("id"),
            "endpoint_name": endpoint.get("name"),
        }
        payload, attempts = self.request(
            "POST",
            create_url,
            resolved_body(endpoint, context),
            progress_context,
        )
        query_id = payload.get("id") if isinstance(payload, dict) else None
        if not query_id:
            error = GraphError("Audit query creation did not return an ID")
            error.attempts = attempts
            raise error
        self.report_progress("audit_query_created", **progress_context)
        status_url = f"{GRAPH_ROOT}/{endpoint['api']}/security/auditLog/queries/{query_id}"
        deadline = monotonic() + self.poll_timeout
        polling_started = monotonic()
        polls = 0
        last_reported_status = None
        while monotonic() < deadline:
            status_payload, used = self.request(
                "GET", status_url, progress_context=progress_context
            )
            attempts += used
            polls += 1
            status = str(status_payload.get("status", "")).lower()
            if polls == 1 or polls % 15 == 0 or status != last_reported_status:
                self.report_progress(
                    "audit_poll",
                    **progress_context,
                    poll=polls,
                    status=status or "unknown",
                    elapsed_seconds=round(monotonic() - polling_started),
                )
                last_reported_status = status
            if status == "succeeded":
                records_endpoint = dict(endpoint, method="GET", mode="collection", path=f"/security/auditLog/queries/{query_id}/records")
                collected = self.collect(records_endpoint, target, context)
                collected.attempts += attempts
                collected.contexts.insert(0, {"query_id": query_id, "poll_count": polls})
                return collected
            if status in {"failed", "cancelled"}:
                error = GraphError(f"Audit query finished with status {status}")
                error.attempts = attempts
                raise error
            self.sleeper(self.poll_interval)
        error = GraphError("Audit query polling timed out")
        error.attempts = attempts
        raise error
