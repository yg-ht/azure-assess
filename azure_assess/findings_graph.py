#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Conservative Microsoft Graph workload observations.

The evaluator deliberately requires a manifest-backed Graph execution. A JSON
file alone is not evidence that the corresponding inventory was complete,
licensed and authorised.
"""

from typing import Any, Callable, Dict, Iterable, Mapping, Tuple

from .graph_endpoints import GRAPH_ENDPOINTS, HUNTING_QUERY_PACK


OUTPUT_BY_ID = {item["id"]: item["output"] for item in GRAPH_ENDPOINTS}


def _records(catalog: Mapping[str, Any], prefix: str) -> Tuple[list, list]:
    records, files = [], []
    for filename, payload in catalog.items():
        if not str(filename).startswith(prefix + "_"):
            continue
        files.append(str(filename))
        values = payload.get("value") if isinstance(payload, dict) else payload
        if isinstance(values, list):
            records.extend(item for item in values if isinstance(item, dict))
        elif isinstance(values, dict):
            records.append(values)
    return records, files


def _manifest_graph_statuses(catalog: Mapping[str, Any]) -> Dict[str, str]:
    statuses: Dict[str, str] = {}
    for filename, payload in catalog.items():
        if "manifest" not in str(filename) or not isinstance(payload, dict):
            continue
        for execution in payload.get("endpoint_runs", []):
            if execution.get("category") == "microsoft_graph" and execution.get("endpoint_id"):
                statuses[str(execution["endpoint_id"])] = str(execution.get("status") or "unknown")
    return statuses


def graph_collection_present(catalog: Mapping[str, Any]) -> bool:
    """Return whether the input contains a Graph run or Graph dataset."""
    if any(str(name).startswith("graph_") for name in catalog):
        return True
    return bool(_manifest_graph_statuses(catalog))


def _available(catalog: Mapping[str, Any], endpoint_id: str) -> Tuple[list, list, bool]:
    prefix = OUTPUT_BY_ID.get(endpoint_id, endpoint_id)
    records, files = _records(catalog, prefix)
    statuses = _manifest_graph_statuses(catalog)
    endpoint_status = statuses.get(prefix)
    complete = bool(files) and endpoint_status not in {
        "failed", "incomplete", "unauthorised", "tenant_unavailable",
        "not_applicable", "skipped", "not_attempted",
    }
    return records, files, complete


def _check(
    catalog: Mapping[str, Any], result: Callable, unsupported: Callable,
    title: str, severity: str, endpoint_ids: Iterable[str],
    predicate: Callable[[Mapping[str, Any]], bool], reason: str,
):
    endpoint_ids = list(endpoint_ids)
    available = [_available(catalog, endpoint_id) for endpoint_id in endpoint_ids]
    if not all(item[2] for item in available):
        finding = unsupported(title, severity, reason)
    else:
        observations = [record for records, _, _ in available for record in records if predicate(record)]
        finding = result(title, severity, f"{len(observations)} directly observed record(s) require review.", observations)
    finding["_required_endpoint_ids"] = endpoint_ids
    return finding, [filename for _, files, _ in available for filename in files]


def _state(record: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = record.get(key)
        if value is not None:
            return str(value).lower()
    return ""


def evaluate_graph_findings(catalog, result, unsupported):
    if not graph_collection_present(catalog):
        return [], {}

    findings, sources = [], {}
    checks = [
        ("Active Microsoft Entra risk detections", "High", ["risk_detections"], lambda r: _state(r, "riskState", "riskStatus") not in {"remediated", "dismissed", "resolved"}, "A complete, licensed risk-detection inventory is required."),
        ("Unresolved Microsoft Entra recommendations", "Medium", ["recommendations"], lambda r: _state(r, "status", "recommendationStatus") not in {"completed", "dismissed", "resolved"}, "A complete, licensed recommendation inventory is required."),
        ("Unhealthy on-premises directory synchronisation", "High", ["onprem_sync"], lambda r: _state(r, "state", "status", "healthStatus") in {"failed", "unhealthy", "error"} or r.get("features", {}).get("passwordSyncEnabled") is False, "A complete synchronisation inventory is required."),
        ("Weak or missing privileged authentication methods", "High", ["user_registration_details", "directory_role_assignments"], lambda r: _state(r, "isMfaRegistered", "isMfaCapable") in {"false", "0", "no"}, "Complete privileged-role and authentication-method inventories are required."),
        ("Unsafe entitlement-management assignments or policies", "High", ["entitlement_assignments", "entitlement_policies"], lambda r: _state(r, "status", "state") in {"pending", "inadequate", "permanent", "expired"} or r.get("assignmentScheduleInfo", {}).get("expiration", {}).get("type") == "noExpiration", "Complete entitlement inventories are required."),
        ("Permanent privileged directory assignments", "High", ["pim_directory_active"], lambda r: not r.get("assignmentScheduleInfo", {}).get("expiration") and not r.get("scheduleInfo", {}).get("expiration"), "Complete, licensed PIM active-assignment inventory is required."),
        ("Active privileged identity management alerts", "High", ["pim_alerts"], lambda r: _state(r, "status", "alertStatus") not in {"resolved", "dismissed", "closed"}, "A complete, licensed PIM alert inventory is required."),
        ("Unsafe Microsoft 365 sharing or tenant settings", "High", ["settings_sharepoint", "settings_apps_services", "settings_forms"], lambda r: _state(r, "sharingCapability", "externalSharing", "defaultSharingLinkType") in {"externalusersandguestsharing", "anyone", "anonymousaccess"}, "Complete licensed tenant-settings inventories are required."),
        ("Non-compliant or stale Intune managed devices", "High", ["managed_devices"], lambda r: _state(r, "complianceState", "deviceHealthAttestationState") in {"noncompliant", "error", "unknown", "stale"} or r.get("managementState") in {"retirePending", "wipePending"}, "A complete, licensed managed-device inventory is required."),
        ("Intune estate lacks compliance or enrolment controls", "High", ["managed_devices", "compliance_policies", "enrolment_restrictions"], lambda r: False, "Complete managed-device, compliance-policy and enrolment inventories are required."),
        ("Excessive Intune RBAC assignments", "High", ["intune_role_definitions", "intune_role_assignments"], lambda r: _state(r, "displayName", "roleName") in {"global administrator", "intune service administrator"}, "Complete licensed Intune RBAC inventories are required."),
        ("Managed encrypted devices lack BitLocker recovery-key metadata coverage", "Medium", ["managed_devices", "bitlocker_key_metadata"], lambda r: str(r.get("isEncrypted", "")).lower() == "true" and not r.get("deviceId"), "Complete managed-device and BitLocker metadata inventories are required; key material is never collected."),
        ("Global Secure Access forwarding or filtering controls are absent", "High", ["gsa_tenant_status", "gsa_forwarding_profiles", "gsa_forwarding_policies", "gsa_filtering_policies"], lambda r: _state(r, "status", "state", "enabled") in {"false", "disabled", "notconfigured"}, "Complete, applicable and licensed Global Secure Access inventories are required."),
        ("Unhealthy Defender for Identity sensors", "High", ["defender_identity_sensors", "defender_identity_health"], lambda r: _state(r, "healthStatus", "status") not in {"healthy", "active", "online"}, "Complete, licensed sensor and health inventories are required."),
        ("Unresolved significant Microsoft security incidents", "High", ["security_incidents"], lambda r: _state(r, "status") not in {"resolved", "redirected"} and _state(r, "severity", "classification") in {"high", "medium", "critical"}, "A complete, licensed incident inventory is required."),
    ]
    for title, severity, endpoint_ids, predicate, reason in checks:
        finding, files = _check(catalog, result, unsupported, title, severity, endpoint_ids, predicate, reason)
        findings.append(finding)
        sources[title] = files

    # Absence claims are only emitted when all applicable inventories succeeded.
    absence_specs = [
        ("Applicable Intune estate has no compliance policy", "High", ["managed_devices", "compliance_policies"], "A complete managed-device and compliance-policy inventory is required."),
        ("Applicable Intune estate has no enrolment restriction", "High", ["managed_devices", "enrolment_restrictions"], "A complete managed-device and enrolment inventory is required."),
        ("Applicable Global Secure Access tenant has no forwarding policy", "High", ["gsa_tenant_status", "gsa_forwarding_policies"], "A complete and licensed Global Secure Access inventory is required."),
    ]
    for title, severity, endpoint_ids, reason in absence_specs:
        available = [_available(catalog, endpoint_id) for endpoint_id in endpoint_ids]
        if not all(item[2] for item in available):
            finding = unsupported(title, severity, reason)
        else:
            evidence = [{"inventory_count": len(available[0][0])}] if available[0][0] and not available[1][0] else []
            finding = result(title, severity, "An applicable inventory was observed without the expected control.", evidence)
        finding["_required_endpoint_ids"] = endpoint_ids
        findings.append(finding)
        sources[title] = [filename for _, files, _ in available for filename in files]

    statuses = _manifest_graph_statuses(catalog)
    for query in HUNTING_QUERY_PACK["queries"]:
        endpoint_id = f"hunting_{query['id']}"
        prefix = OUTPUT_BY_ID[endpoint_id]
        records, files = _records(catalog, prefix)
        status = statuses.get(prefix)
        title = f"Defender hunting query: {query['title']}"
        if status in {"failed", "incomplete", "unauthorised", "tenant_unavailable", "skipped", "not_attempted"} or (status is None and not files):
            finding = unsupported(title, "High", "The relevant Defender hunting table or licence was unavailable; this query is inconclusive.")
        else:
            finding = result(title, "High", f"Built-in query pack {HUNTING_QUERY_PACK['version']} returned {len(records)} record(s).", records)
        finding["_required_endpoint_ids"] = [endpoint_id]
        findings.append(finding)
        sources[title] = files
    return findings, sources
