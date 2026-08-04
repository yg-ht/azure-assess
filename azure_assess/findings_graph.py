#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Conservative, manifest-backed Microsoft Graph workload findings."""

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from .graph_endpoints import GRAPH_ENDPOINTS, HUNTING_QUERY_PACK
from .graph_guidance import GUIDANCE_BY_ID, GUIDANCE_BY_TITLE


OUTPUT_BY_ID = {item["id"]: item["output"] for item in GRAPH_ENDPOINTS}
COMPLETE_STATUSES = {"success", "empty"}
POSITIVE_EVIDENCE_STATUSES = COMPLETE_STATUSES | {"incomplete"}


def _manifest(catalog: Mapping[str, Any]) -> Mapping[str, Any]:
    manifests = [
        payload for name, payload in catalog.items()
        if "manifest" in str(name) and isinstance(payload, dict)
    ]
    return manifests[-1] if manifests else {}


def _manifest_statuses(catalog: Mapping[str, Any]) -> Dict[str, str]:
    grouped: Dict[str, list] = {}
    for run in _manifest(catalog).get("endpoint_runs", []):
        if isinstance(run, dict) and run.get("endpoint_id"):
            grouped.setdefault(str(run["endpoint_id"]), []).append(
                str(run.get("status") or "unknown")
            )
    precedence = (
        "not_attempted", "failed", "unauthorised", "incomplete",
        "tenant_unavailable", "skipped", "not_applicable", "unknown",
        "success", "empty",
    )
    statuses = {}
    for endpoint_id, values in grouped.items():
        statuses[endpoint_id] = next(
            (status for status in precedence if status in values), "unknown"
        )
    return statuses


def _current_filenames(catalog: Mapping[str, Any]) -> set:
    return {
        str(item["filename"])
        for item in _manifest(catalog).get("datasets", [])
        if isinstance(item, dict) and item.get("filename")
    }


def _records(catalog: Mapping[str, Any], prefix: str) -> Tuple[list, list]:
    records, files = [], []
    current = _current_filenames(catalog)
    for filename, payload in catalog.items():
        name = str(filename)
        if not name.startswith(prefix + "_"):
            continue
        if current and name not in current:
            continue
        files.append(name)
        values = payload.get("value") if isinstance(payload, dict) else payload
        if isinstance(values, list):
            records.extend(item for item in values if isinstance(item, dict))
        elif isinstance(values, dict):
            records.append(values)
    return records, files


def graph_collection_present(catalog: Mapping[str, Any]) -> bool:
    if any(str(name).startswith("graph_") for name in catalog):
        return True
    return any(
        run.get("category") == "microsoft_graph"
        for run in _manifest(catalog).get("endpoint_runs", [])
        if isinstance(run, dict)
    )


def _inventory(catalog: Mapping[str, Any], endpoint_id: str, prefix: str = None) -> dict:
    output = prefix or OUTPUT_BY_ID.get(endpoint_id, endpoint_id)
    records, files = _records(catalog, output)
    status = _manifest_statuses(catalog).get(output)
    return {
        "endpoint_id": output,
        "records": records,
        "files": files,
        "status": status,
        "complete": bool(files) and status in COMPLETE_STATUSES,
        "positive_usable": bool(files) and status in POSITIVE_EVIDENCE_STATUSES,
    }


def _state(record: Mapping[str, Any], *paths: str) -> str:
    for path in paths:
        value: Any = record.get(path) if path in record else record
        if path not in record:
            for part in path.split("."):
                if not isinstance(value, Mapping):
                    value = None
                    break
                value = value.get(part)
        if value is not None:
            return str(value).strip().lower()
    return ""


def _truth(record: Mapping[str, Any], *paths: str) -> Optional[bool]:
    state = _state(record, *paths)
    if state in {"true", "1", "yes", "enabled"}:
        return True
    if state in {"false", "0", "no", "disabled"}:
        return False
    return None


def _parse_time(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _assessment_time(catalog: Mapping[str, Any]) -> datetime:
    manifest = _manifest(catalog)
    candidates = [
        (manifest.get("options") or {}).get("graph_lookback_end"),
        manifest.get("completed_at"),
        manifest.get("started_at"),
    ]
    return next((value for item in candidates if (value := _parse_time(item))),
                datetime.now(timezone.utc))


def _guidance(finding: dict, title: str) -> None:
    requirement = GUIDANCE_BY_TITLE.get(title)
    if requirement:
        finding["_guidance_requirement_ids"] = [requirement["id"]]


def _emit(result, unsupported, title: str, severity: str,
          inventories: Iterable[dict], observations: list, reason: str,
          absence: bool = False):
    inventories = list(inventories)
    positive_supported = observations and (
        all(item["complete"] for item in inventories)
        if absence else any(item["positive_usable"] for item in inventories)
    )
    if positive_supported:
        finding = result(title, severity, reason, observations)
    elif all(item["complete"] for item in inventories):
        finding = result(title, severity, reason, [])
    else:
        states = ", ".join(
            f"{item['endpoint_id']}={item['status'] or 'unrecorded'}"
            for item in inventories if not item["complete"]
        )
        finding = unsupported(
            title, severity,
            f"No complete set of required inventories was available ({states}).",
        )
    finding["_required_endpoint_ids"] = [item["endpoint_id"] for item in inventories]
    _guidance(finding, title)
    files = [name for item in inventories for name in item["files"]]
    return finding, files


def _no_expiration(record: Mapping[str, Any]) -> bool:
    values = (
        _state(record, "assignmentScheduleInfo.expiration.type"),
        _state(record, "scheduleInfo.expiration.type"),
        _state(record, "expiration.type"),
        _state(record, "properties.expiration.type"),
    )
    return any(value in {"noexpiration", "permanent"} for value in values)


def _wildcard_intune_role(record: Mapping[str, Any]) -> bool:
    if _truth(record, "isBuiltIn", "isBuiltInRoleDefinition") is not False:
        return False
    permissions = record.get("rolePermissions") or record.get("permissions") or []
    for permission in permissions if isinstance(permissions, list) else []:
        for action in permission.get("resourceActions", []) if isinstance(permission, dict) else []:
            allowed = action.get("allowedResourceActions", []) if isinstance(action, dict) else []
            if any("*" in str(value) for value in allowed):
                return True
    return False


def evaluate_graph_findings(catalog, result, unsupported):
    if not graph_collection_present(catalog):
        return [], {}

    findings, sources = [], {}

    def add(title, severity, inventories, observations, reason, absence=False):
        finding, files = _emit(
            result, unsupported, title, severity, inventories, observations,
            reason, absence=absence,
        )
        findings.append(finding)
        sources[title] = files

    risk = _inventory(catalog, "risk_detections")
    risk_states = set(GUIDANCE_BY_ID["identity_risk"]["parameters"]["active_states"])
    add("Active Microsoft Entra risk detections", "High", [risk], [
        record for record in risk["records"]
        if _state(record, "riskState", "riskStatus") in risk_states
    ], "Active at-risk or confirmed-compromised detections were directly observed.")

    recommendations = _inventory(catalog, "recommendations")
    resolved = set(GUIDANCE_BY_ID["directory_recommendations"]["parameters"]["resolved_states"])
    add("Unresolved Microsoft Entra recommendations", "Medium", [recommendations], [
        record for record in recommendations["records"]
        if (state := _state(record, "status", "recommendationStatus")) and state not in resolved
    ], "Recommendations with a non-resolved state were directly observed.")

    sync = _inventory(catalog, "onprem_sync")
    unhealthy = set(GUIDANCE_BY_ID["synchronisation_and_provisioning"]["parameters"]["unhealthy_states"])
    add("Unhealthy on-premises directory synchronisation", "High", [sync], [
        record for record in sync["records"]
        if _state(record, "state", "status", "healthStatus") in unhealthy
    ], "Synchronisation records explicitly reported an unhealthy state.")

    provisioning = _inventory(catalog, "provisioning_logs")
    add("Unhealthy Microsoft Entra provisioning activity", "High", [provisioning], [
        record for record in provisioning["records"]
        if _state(record, "statusInfo.status", "provisioningStatusInfo.status", "status") in unhealthy
        or _state(record, "statusInfo.errorCode", "provisioningStatusInfo.errorInformation.errorCode") not in {"", "0", "none"}
    ], "Provisioning records explicitly reported failure or an error code.")

    users = _inventory(catalog, "users")
    assignments = _inventory(catalog, "directory_role_assignments")
    registrations = _inventory(catalog, "user_registration_details")
    methods = _inventory(catalog, "user_authentication_methods")
    user_ids = {str(item.get("id")) for item in users["records"] if item.get("id")}
    privileged_ids = {
        str(item.get("principalId")) for item in assignments["records"]
        if item.get("principalId") and str(item.get("principalId")) in user_ids
    }
    registration_by_id = {
        str(item.get("id") or item.get("userId")): item
        for item in registrations["records"] if item.get("id") or item.get("userId")
    }
    methods_by_user: Dict[str, list] = {}
    for method in methods["records"]:
        parent = (method.get("_collectionContext") or {}).get("parent_id")
        if parent:
            methods_by_user.setdefault(str(parent), []).append(method)
    strong_types = set(GUIDANCE_BY_ID["authentication_methods"]["parameters"]["strong_method_types"])
    weak_privileged = []
    for principal_id in sorted(privileged_ids):
        registered = registration_by_id.get(principal_id)
        principal_methods = methods_by_user.get(principal_id, [])
        has_strong = any(
            _state(item, "@odata.type") in strong_types for item in principal_methods
        )
        if not has_strong:
            weak_privileged.append({
                "principalId": principal_id,
                "registration": registered,
                "authenticationMethods": principal_methods,
            })
    add("Weak or missing privileged authentication methods", "High",
        [users, assignments, registrations, methods], weak_privileged,
        "Privileged users without a collected phishing-resistant method were observed.",
        absence=True)

    entitlement_assignments = _inventory(catalog, "entitlement_assignments")
    entitlement_policies = _inventory(catalog, "entitlement_policies")
    unsafe_entitlement = [
        record for record in entitlement_assignments["records"] + entitlement_policies["records"]
        if _no_expiration(record)
    ]
    add("Unsafe entitlement-management assignments or policies", "High",
        [entitlement_assignments, entitlement_policies], unsafe_entitlement,
        "Entitlement records explicitly configured without expiration were observed.")

    pim_directory = _inventory(catalog, "pim_directory_active")
    add("Permanent privileged directory assignments", "High", [pim_directory],
        [record for record in pim_directory["records"] if _no_expiration(record)],
        "Active directory-role schedules explicitly configured without expiration were observed.")

    pim_group = _inventory(catalog, "pim_group_active")
    add("Permanent privileged group assignments", "High", [pim_group],
        [record for record in pim_group["records"] if _no_expiration(record)],
        "Active privileged-group schedules explicitly configured without expiration were observed.")

    pim_azure = _inventory(
        catalog, "arm_pim_azure_resource_assignment_schedules",
        prefix="arm_pim_azure_resource_assignment_schedules",
    )
    add("Permanent privileged Azure-resource assignments", "High", [pim_azure],
        [record for record in pim_azure["records"] if _no_expiration(record)],
        "Active Azure-resource schedules explicitly configured without expiration were observed.")

    alerts = _inventory(catalog, "pim_alerts")
    add("Active privileged identity management alerts", "High", [alerts], [
        record for record in alerts["records"]
        if _truth(record, "isActive") is True
        or (
            str(record.get("incidentCount") or "0").isdigit()
            and int(record.get("incidentCount") or 0) > 0
        )
    ], "Active PIM alerts or alerts with incidents were directly observed.")

    sharepoint = _inventory(catalog, "settings_sharepoint")
    apps_settings = _inventory(catalog, "settings_apps_services")
    forms_settings = _inventory(catalog, "settings_forms")
    unsafe_m365 = [
        record for record in sharepoint["records"]
        if _state(record, "sharingCapability") == "externaluserandguestsharing"
        or _state(record, "defaultSharingLinkType") in {"anonymousaccess", "anyone"}
    ]
    add("Unsafe Microsoft 365 sharing or tenant settings", "High",
        [sharepoint, apps_settings, forms_settings], unsafe_m365,
        "SharePoint settings explicitly enabled anonymous sharing or anonymous default links.")

    devices = _inventory(catalog, "managed_devices")
    stale_days = GUIDANCE_BY_ID["intune_compliance"]["parameters"]["stale_after_days"]
    assessed_at = _assessment_time(catalog)
    unsafe_devices = []
    for device in devices["records"]:
        sync_time = _parse_time(device.get("lastSyncDateTime"))
        stale = sync_time is not None and (assessed_at - sync_time).days > stale_days
        non_compliant = _state(device, "complianceState") in {
            "error", "inconflict", "noncompliant", "unknown"
        }
        pending = _state(device, "managementState") in {"retirepending", "wipepending"}
        if stale or non_compliant or pending:
            unsafe_devices.append(device)
    add("Non-compliant or stale Intune managed devices", "High", [devices], unsafe_devices,
        f"Devices were non-compliant, pending destructive management, or had not synchronised for more than {stale_days} days.")

    compliance = _inventory(catalog, "compliance_policies")
    enrolment = _inventory(catalog, "enrolment_restrictions")
    control_gaps = []
    if devices["records"] and not compliance["records"]:
        control_gaps.append({"control": "compliance_policy", "managedDeviceCount": len(devices["records"])})
    if devices["records"] and not enrolment["records"]:
        control_gaps.append({"control": "enrolment_restriction", "managedDeviceCount": len(devices["records"])})
    add("Intune estate lacks compliance or enrolment controls", "High",
        [devices, compliance, enrolment], control_gaps,
        "An applicable managed-device estate lacked one or more baseline control inventories.",
        absence=True)

    role_definitions = _inventory(catalog, "intune_role_definitions")
    role_assignments = _inventory(catalog, "intune_role_assignments")
    broad_definitions = {
        str(item.get("id")).rstrip("/").split("/")[-1]: item
        for item in role_definitions["records"]
        if item.get("id") and _wildcard_intune_role(item)
    }
    excessive_rbac = []
    for assignment in role_assignments["records"]:
        definition_id = str(assignment.get("roleDefinitionId") or "").rstrip("/").split("/")[-1]
        if definition_id in broad_definitions:
            excessive_rbac.append({
                "assignment": assignment,
                "roleDefinition": broad_definitions[definition_id],
            })
    add("Excessive Intune RBAC assignments", "High",
        [role_definitions, role_assignments], excessive_rbac,
        "Assignments to custom Intune roles containing wildcard resource actions were observed.")

    bitlocker = _inventory(catalog, "bitlocker_key_metadata")
    key_device_ids = {
        str(item.get("deviceId")).lower() for item in bitlocker["records"]
        if item.get("deviceId")
    }
    missing_keys = []
    for device in devices["records"]:
        device_id = device.get("azureADDeviceId") or device.get("deviceId")
        if _truth(device, "isEncrypted") is True and device_id and str(device_id).lower() not in key_device_ids:
            missing_keys.append(device)
    add("Managed encrypted devices lack BitLocker recovery-key metadata coverage", "Medium",
        [devices, bitlocker], missing_keys,
        "Encrypted managed devices had no matching BitLocker recovery-key metadata record; key material was not collected.",
        absence=True)

    gsa_status = _inventory(catalog, "gsa_tenant_status")
    gsa_profiles = _inventory(catalog, "gsa_forwarding_profiles")
    gsa_forwarding = _inventory(catalog, "gsa_forwarding_policies")
    gsa_filtering = _inventory(catalog, "gsa_filtering_policies")
    gsa_tls = _inventory(catalog, "gsa_tls_policies")
    gsa_assignments = _inventory(catalog, "gsa_policy_assignments")
    gsa_disabled = [
        record for inventory in (gsa_status, gsa_profiles, gsa_forwarding, gsa_filtering, gsa_tls)
        for record in inventory["records"]
        if _truth(record, "enabled", "isEnabled") is False
        or _state(record, "status", "state") in {"disabled", "notconfigured"}
    ]
    add("Global Secure Access forwarding or filtering controls are absent", "High",
        [gsa_status, gsa_profiles, gsa_forwarding, gsa_filtering, gsa_tls, gsa_assignments],
        gsa_disabled, "Applicable Global Secure Access controls were explicitly disabled or unconfigured.")

    tenant_enabled = any(
        _truth(record, "enabled", "isEnabled") is True
        or _state(record, "status", "state") in {"active", "enabled"}
        for record in gsa_status["records"]
    )
    for title, inventory, control in (
        ("Applicable Global Secure Access tenant has no forwarding policy", gsa_forwarding, "forwarding_policy"),
        ("Applicable Global Secure Access tenant has no filtering policy", gsa_filtering, "filtering_policy"),
        ("Applicable Global Secure Access tenant has no TLS inspection policy", gsa_tls, "tls_inspection_policy"),
        ("Applicable Global Secure Access tenant has no policy assignment", gsa_assignments, "policy_assignment"),
    ):
        evidence = [{"control": control}] if tenant_enabled and not inventory["records"] else []
        add(title, "High", [gsa_status, inventory], evidence,
            "An enabled Global Secure Access tenant lacked the applicable control inventory.",
            absence=True)

    for title, inventory, control in (
        ("Applicable Intune estate has no compliance policy", compliance, "compliance_policy"),
        ("Applicable Intune estate has no enrolment restriction", enrolment, "enrolment_restriction"),
    ):
        evidence = ([{"control": control, "managedDeviceCount": len(devices["records"])}]
                    if devices["records"] and not inventory["records"] else [])
        add(title, "High", [devices, inventory], evidence,
            "An applicable managed-device estate lacked the expected control inventory.",
            absence=True)

    sensors = _inventory(catalog, "defender_identity_sensors")
    health = _inventory(catalog, "defender_identity_health")
    unhealthy_sensors = [
        record for record in sensors["records"]
        if (state := _state(record, "healthStatus", "status"))
        and state not in {"healthy", "active", "online"}
    ] + [
        record for record in health["records"]
        if (state := _state(record, "status", "healthStatus"))
        and state not in {"resolved", "closed", "healthy"}
    ]
    add("Unhealthy Defender for Identity sensors", "High", [sensors, health],
        unhealthy_sensors, "Unhealthy sensors or unresolved health issues were directly observed.")

    incidents = _inventory(catalog, "security_incidents")
    significant = [
        record for record in incidents["records"]
        if _state(record, "status") not in {"resolved", "redirected"}
        and _state(record, "severity") in {"medium", "high", "critical"}
    ]
    add("Unresolved significant Microsoft security incidents", "High", [incidents],
        significant, "Unresolved medium, high or critical incidents were directly observed.")

    for query in HUNTING_QUERY_PACK["queries"]:
        endpoint_id = f"hunting_{query['id']}"
        inventory = _inventory(catalog, endpoint_id)
        title = f"Defender hunting query: {query['title']}"
        add(title, "High", [inventory], list(inventory["records"]),
            f"Built-in query pack {HUNTING_QUERY_PACK['version']} returned matching records.")

    return findings, sources
