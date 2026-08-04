#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Orchestration between the Graph registry and Azure Assess manifests."""

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional

from .collection_manifest import utc_timestamp
from .graph_endpoints import GRAPH_ENDPOINTS
from .graph_runner import AtomicJsonArrayWriter, GraphRunner, GraphTransport, utc_interval


def graph_endpoint_definition(endpoint: Mapping[str, Any]) -> Dict[str, str]:
    return {
        "name": endpoint["name"],
        "cli_command": f"{endpoint['method']} https://graph.microsoft.com/{endpoint['api']}{endpoint['path']}",
        "output_prefix": endpoint["output"],
    }


def selected_graph_endpoints(keyword: Optional[str]) -> list:
    if not keyword:
        return list(GRAPH_ENDPOINTS)
    wanted = str(keyword).lower()
    return [
        endpoint for endpoint in GRAPH_ENDPOINTS
        if wanted in " ".join(str(endpoint.get(key, "")) for key in
                              ("id", "name", "profile", "permission", "path", "output")).lower()
    ]


def _iter_json_array(path: Path):
    """Yield array members incrementally from a runner-produced JSON file."""
    decoder = json.JSONDecoder()
    with Path(path).open(encoding="utf-8") as handle:
        buffer = ""
        eof = False
        started = False
        while True:
            if not eof and len(buffer) < 65536:
                chunk = handle.read(65536)
                if chunk:
                    buffer += chunk
                else:
                    eof = True
            buffer = buffer.lstrip()
            if not started:
                if not buffer:
                    if eof:
                        return
                    continue
                if buffer[0] != "[":
                    raise ValueError(f"Graph dataset {path.name} is not a JSON array")
                buffer = buffer[1:]
                started = True
            buffer = buffer.lstrip()
            if buffer.startswith("]"):
                return
            if buffer.startswith(","):
                buffer = buffer[1:].lstrip()
            try:
                value, used = decoder.raw_decode(buffer)
            except json.JSONDecodeError:
                if eof:
                    raise ValueError(f"Graph dataset {path.name} is truncated")
                continue
            yield value
            buffer = buffer[used:]


def _safe_unlink(path: Path) -> None:
    try:
        Path(path).unlink()
    except FileNotFoundError:
        pass


def acquire_graph_token(command_runner=subprocess.run) -> str:
    """Acquire an ephemeral token; callers must never log or persist it."""
    result = command_runner(
        ["az", "account", "get-access-token", "--resource", "https://graph.microsoft.com/", "--output", "json"],
        capture_output=True, text=True, check=False,
    )
    try:
        payload = json.loads(result.stdout or "{}")
    except ValueError as exc:
        raise RuntimeError("Azure CLI returned malformed Graph authentication data") from exc
    token = payload.get("accessToken")
    if result.returncode or not token:
        raise RuntimeError((result.stderr or "Could not acquire a Microsoft Graph access token").strip())
    return token


def collect_registered_graph(
    *, output_dir: Path, run_id: str, lookback_days: int, endpoint_filter: Optional[str],
    manifest, token: Optional[str] = None, runner: Optional[GraphRunner] = None,
) -> bool:
    """Collect selected endpoints and attach page/query/parent provenance."""
    endpoints = selected_graph_endpoints(endpoint_filter)
    manifest.register_endpoints(
        [graph_endpoint_definition(endpoint) for endpoint in endpoints], "microsoft_graph"
    )
    if not endpoints:
        return True
    start, end = utc_interval(lookback_days)
    try:
        graph_runner = runner or GraphRunner(GraphTransport(token or acquire_graph_token()))
    except RuntimeError as exc:
        for endpoint in endpoints:
            definition = graph_endpoint_definition(endpoint)
            manifest.record_execution(
                endpoint_name=endpoint["name"], category="microsoft_graph",
                command_template=definition["cli_command"], started_at=utc_timestamp(),
                duration_seconds=0, returncode=1, result_count=None,
                error_message=f"Graph authentication unavailable: {exc}",
                diagnostic_text='{"code":"Authorization_RequestDenied"}',
                endpoint_identifier=endpoint["output"],
            )
        return False

    parent_ids_by_endpoint: Dict[str, list] = {}
    successful = True
    for endpoint in endpoints:
        fan_out = endpoint.get("fan_out")
        contexts = [{"start": start, "end": end}]
        if fan_out:
            parents = parent_ids_by_endpoint.get(fan_out["parent"])
            if parents is None:
                manifest.record_skipped_endpoint(
                    endpoint["name"], "microsoft_graph", graph_endpoint_definition(endpoint)["cli_command"],
                    "The required parent endpoint was not selected or was unavailable",
                    endpoint_identifier=endpoint["output"], reason_code="upstream_source_unavailable",
                    reason_details={"parent_endpoint_id": fan_out["parent"]},
                )
                continue
            contexts = [
                {"start": start, "end": end, "parent_id": parent_id}
                for parent_id in parents if parent_id
            ]
            if not contexts:
                manifest.record_skipped_endpoint(
                    endpoint["name"], "microsoft_graph", graph_endpoint_definition(endpoint)["cli_command"],
                    "The parent inventory contained no applicable records",
                    endpoint_identifier=endpoint["output"], reason_code="upstream_source_returned_no_data",
                    reason_details={"parent_endpoint_id": fan_out["parent"]},
                )
                continue

        status = "empty"
        error = None
        attempts = pages = 0
        total_count = 0
        page_provenance = []
        output = Path(output_dir) / f"{endpoint['output']}_{run_id}.json"
        temporary_targets = []
        for parent_index, context in enumerate(contexts):
            target = Path(output_dir) / f"{endpoint['output']}_{parent_index}_{run_id}.json"
            result = graph_runner.collect(endpoint, target, context)
            attempts += result.attempts
            pages += result.pages
            page_provenance.extend(
                {"parent_index": parent_index, "parent_id": context.get("parent_id"), **item}
                for item in result.contexts
                if isinstance(item, dict)
            )
            if result.status not in {"success", "empty"}:
                status, error, successful = result.status, result.error, False
                break
            temporary_targets.append(target)
            total_count += result.count
            if result.status == "success":
                status = "success"
        if temporary_targets:
            with AtomicJsonArrayWriter(output) as writer:
                for target in temporary_targets:
                    for record in _iter_json_array(target):
                        writer.write(record)
                    _safe_unlink(target)
        elif status in {"failed", "unauthorised", "tenant_unavailable", "incomplete"}:
            _safe_unlink(output)
        if temporary_targets:
            manifest.record_dataset(
                output, None, record_count=total_count,
                source_endpoint_identifier=endpoint["output"],
            )
            if fan_out:
                parent_ids_by_endpoint[endpoint["id"]] = []
        if endpoint["id"] in {item.get("id") for item in endpoints} and endpoint.get("fan_out") is None and temporary_targets:
            # Retain only the identifier fields needed by downstream fan-out.
            for record in _iter_json_array(output):
                if isinstance(record, dict):
                    for child in endpoints:
                        child_fan_out = child.get("fan_out")
                        if child_fan_out and child_fan_out.get("parent") == endpoint["id"]:
                            value = record.get(child_fan_out.get("id"))
                            if value:
                                parent_ids_by_endpoint.setdefault(endpoint["id"], []).append(value)
        definition = graph_endpoint_definition(endpoint)
        manifest.record_execution(
            endpoint_name=endpoint["name"], category="microsoft_graph",
            command_template=definition["cli_command"],
            parameter_context={
                "endpoint_id": endpoint["id"], "profile": endpoint["profile"],
                "required_permission": endpoint["permission"], "api_channel": endpoint["api"],
                "licence_requirement": endpoint["licence"], "lookback_start": start,
                "lookback_end": end, "page_count": pages, "query_or_parent_count": len(contexts),
                "page_provenance": page_provenance,
                "incomplete": status == "incomplete",
            },
            started_at=utc_timestamp(), duration_seconds=0,
            returncode=0 if status in {"success", "empty"} else 1,
            result_count=total_count, retry_count=max(0, attempts - 1),
            error_message=error,
            diagnostic_text=(
                '{"code":"Authorization_RequestDenied"}' if status == "unauthorised"
                else '{"code":"AuthenticationRequestFromNonPremiumTenantOrB2CTenant"}'
                if status == "tenant_unavailable" else error
            ),
            endpoint_identifier=endpoint["output"],
            status_override=status if status == "incomplete" else None,
        )
        if endpoint["api"] == "beta":
            manifest.add_limitation(f"{endpoint['name']} uses the explicitly labelled Microsoft Graph beta API")
    return successful
