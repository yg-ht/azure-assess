#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Conservative, manifest-backed Microsoft Graph workload findings."""

from datetime import datetime, timezone
import json
from typing import Any, Dict, Iterable, Mapping, Optional

from .finding_inventory import inventory, manifest
from .graph_endpoints import GRAPH_ENDPOINTS, HUNTING_QUERY_PACK
from .graph_guidance import GUIDANCE_BY_ID, GUIDANCE_BY_TITLE


OUTPUT_BY_ID = {item["id"]: item["output"] for item in GRAPH_ENDPOINTS}
def graph_collection_present(catalog: Mapping[str, Any]) -> bool:
    if any(str(name).startswith("graph_") for name in catalog):
        return True
    return any(
        run.get("category") == "microsoft_graph"
        for run in manifest(catalog).get("endpoint_runs", [])
        if isinstance(run, dict)
    )


def _inventory(catalog: Mapping[str, Any], endpoint_id: str, prefix: str = None) -> dict:
    output = prefix or OUTPUT_BY_ID.get(endpoint_id, endpoint_id)
    return inventory(catalog, output, output)


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
    collection_manifest = manifest(catalog)
    candidates = [
        (collection_manifest.get("options") or {}).get("graph_lookback_end"),
        collection_manifest.get("completed_at"),
        collection_manifest.get("started_at"),
    ]
    return next((value for item in candidates if (value := _parse_time(item))),
                datetime.now(timezone.utc))


def _guidance(finding: dict, title: str) -> None:
    requirement = GUIDANCE_BY_TITLE.get(title)
    if requirement:
        finding["_guidance_requirement_ids"] = [requirement["id"]]


def _emit(result, unsupported, title: str, severity: str,
          inventories: Iterable[dict], observations: list, reason: str,
          absence: bool = False, positive_supported: Optional[bool] = None,
          complete_supported: Optional[bool] = None):
    inventories = list(inventories)
    if positive_supported is None:
        positive_supported = bool(observations) and (
            all(item["complete"] for item in inventories)
            if absence else any(item["positive_usable"] for item in inventories)
        )
    if complete_supported is None:
        complete_supported = all(item["complete"] for item in inventories)
    if positive_supported:
        finding = result(title, severity, reason, observations)
    elif complete_supported:
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
        _state(record, "properties.scheduleInfo.expiration.type"),
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


def _audit_operation(record: Mapping[str, Any]) -> str:
    return _state(record, "operation", "activityDisplayName", "activity")


def _audit_data(record: Mapping[str, Any]) -> Mapping[str, Any]:
    value = record.get("auditData")
    if isinstance(value, Mapping):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return {}
        return parsed if isinstance(parsed, Mapping) else {}
    return {}


def _audit_has_parameter(record: Mapping[str, Any], names: set) -> bool:
    """Match an explicitly named audit parameter without interpreting its value."""
    details = _audit_data(record)
    parameters = details.get("Parameters") or details.get("parameters") or []
    if not isinstance(parameters, list):
        return False
    expected = {name.casefold() for name in names}
    return any(
        isinstance(parameter, Mapping)
        and str(parameter.get("Name") or parameter.get("name") or "").casefold()
        in expected
        for parameter in parameters
    )


def _explicitly_disabled_security_control(value: Any) -> bool:
    """Find a small allowlist of explicit disabled Intune security controls."""
    keys = {
        "antivirusenabled", "bitlockerenabled", "defenderrealtimescan",
        "encryptionenabled", "firewallenabled", "realtimeprotectionenabled",
    }
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).replace("_", "").lower() in keys and str(child).lower() in {
                "false", "0", "disabled",
            }:
                return True
            if _explicitly_disabled_security_control(child):
                return True
    elif isinstance(value, list):
        return any(_explicitly_disabled_security_control(item) for item in value)
    return False


def _settings_catalog_control_disabled(record: Mapping[str, Any]) -> bool:
    """Recognise explicit disabled values for a narrow set of core controls."""
    instances = []

    def visit(value: Any) -> None:
        if isinstance(value, Mapping):
            if value.get("settingDefinitionId"):
                instances.append(value)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(record)
    control_fragments = {
        "allowrealtimemonitoring",
        "enablefirewall",
        "requiredeviceencryption",
    }
    disabled_values = {"0", "disabled", "false"}
    for instance in instances:
        definition = "".join(
            character for character in str(instance.get("settingDefinitionId"))
            if character.isalnum()
        ).casefold()
        if not any(fragment in definition for fragment in control_fragments):
            continue
        for value_key in ("choiceSettingValue", "simpleSettingValue"):
            setting_value = instance.get(value_key) or {}
            raw_value = (
                setting_value.get("value")
                if isinstance(setting_value, Mapping) else None
            )
            normalised = str(
                raw_value if raw_value is not None else ""
            ).strip().casefold()
            if (
                normalised in disabled_values
                or normalised.rsplit("_", 1)[-1] in disabled_values
            ):
                return True
    return False


def evaluate_graph_findings(catalog, result, unsupported):
    if not graph_collection_present(catalog):
        return [], {}

    findings, sources = [], {}

    def add(
        title, severity, inventories, observations, reason, absence=False,
        positive_supported=None, complete_supported=None,
    ):
        finding, files = _emit(
            result, unsupported, title, severity, inventories, observations,
            reason, absence=absence, positive_supported=positive_supported,
            complete_supported=complete_supported,
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

    sign_ins = _inventory(catalog, "sign_ins")
    legacy_clients = {
        "authenticated smtp", "autodiscover", "exchange activesync",
        "exchange online powershell", "imap", "imap4", "mapi",
        "mapi over http", "other clients", "pop", "pop3", "smtp",
    }
    add("Successful Microsoft Entra legacy-authentication sign-ins", "High", [sign_ins], [
        record for record in sign_ins["records"]
        if _state(record, "clientAppUsed") in legacy_clients
        and _state(record, "status.errorCode", "errorCode") == "0"
    ], "Successful sign-ins using a legacy authentication client were directly observed.")

    directory_audits = _inventory(catalog, "directory_audits")
    sensitive_directory_operations = {
        "add app role assignment to service principal",
        "add eligible member to role",
        "add member to role",
        "add owner to application",
        "add owner to service principal",
        "add password credential",
        "add service principal credentials",
        "delete conditional access policy",
        "remove strong authentication",
        "update application – certificates and secrets management",
        "update conditional access policy",
    }
    add("Security-sensitive Microsoft Entra directory changes", "Medium", [directory_audits], [
        record for record in directory_audits["records"]
        if _audit_operation(record) in sensitive_directory_operations
    ], "Security-sensitive directory changes were directly observed in the assessment window.")

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

    exchange_audit = _inventory(catalog, "audit_exchange")
    delegation_operations = {"add-mailboxpermission", "add-recipientpermission"}
    inbox_forwarding_parameters = {
        "forwardasattachmentto", "forwardto", "redirectto",
    }
    mailbox_forwarding_parameters = {
        "delivertomailboxandforward", "forwardingaddress",
        "forwardingsmtpaddress",
    }
    add("Security-sensitive Exchange mailbox forwarding or delegation changes", "Medium",
        [exchange_audit], [
            record for record in exchange_audit["records"]
            if (
                (operation := _audit_operation(record).replace(" ", ""))
                in delegation_operations
                or operation in {"new-inboxrule", "set-inboxrule"}
                and _audit_has_parameter(record, inbox_forwarding_parameters)
                or operation == "set-mailbox"
                and _audit_has_parameter(record, mailbox_forwarding_parameters)
            )
        ], "Mailbox forwarding, inbox-rule or delegation changes were directly observed.")

    sharepoint_audit = _inventory(catalog, "audit_sharepoint")
    anonymous_operations = {
        "anonymouslinkcreated", "anonymouslinkupdated", "anonymouslinkused",
    }
    external_sharing = []
    for record in sharepoint_audit["records"]:
        operation = _audit_operation(record).replace(" ", "")
        details = _audit_data(record)
        target_type = _state(details, "TargetUserOrGroupType", "targetUserOrGroupType")
        if operation in anonymous_operations or target_type in {"guest", "external"}:
            external_sharing.append(record)
    add("Anonymous or external SharePoint sharing activity", "High",
        [sharepoint_audit], external_sharing,
        "Anonymous-link or explicitly external sharing activity was directly observed.")

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

    device_configurations = _inventory(catalog, "device_configurations")
    settings_catalog = _inventory(catalog, "settings_catalog")
    settings_catalog_settings = _inventory(catalog, "settings_catalog_settings")
    weakened_legacy_policies = [
        record for record in device_configurations["records"]
        if _explicitly_disabled_security_control(record)
    ]
    weakened_catalogue_settings = [
        record for record in settings_catalog_settings["records"]
        if _settings_catalog_control_disabled(record)
    ]
    weakened_policies = weakened_legacy_policies + weakened_catalogue_settings
    settings_inventories = [device_configurations, settings_catalog]
    if settings_catalog["records"]:
        settings_inventories.append(settings_catalog_settings)
    weakened_positive_supported = bool(weakened_policies) and (
        (
            bool(weakened_legacy_policies)
            and device_configurations["positive_usable"]
        )
        or (
            bool(weakened_catalogue_settings)
            and settings_catalog_settings["positive_usable"]
        )
    )
    weakened_complete_supported = (
        device_configurations["complete"]
        and settings_catalog["complete"]
        and (
            not settings_catalog["records"]
            or settings_catalog_settings["complete"]
        )
    )
    add("Intune policy explicitly disables a core endpoint security control", "High",
        settings_inventories,
        weakened_policies,
        "An Intune policy explicitly disabled firewall, antivirus, real-time protection or encryption.",
        positive_supported=weakened_positive_supported,
        complete_supported=weakened_complete_supported)

    security_connectors = _inventory(catalog, "security_connectors")
    connector_enable_fields = (
        "androidEnabled", "iosEnabled", "windowsEnabled",
        "androidMobileApplicationManagementEnabled",
        "iosMobileApplicationManagementEnabled",
    )
    unhealthy_connectors = [
        record for record in security_connectors["records"]
        if _truth(record, "enabled", "isEnabled") is False
        or _state(
            record, "partnerState", "status", "connectionStatus", "healthStatus"
        ) in {
            "disabled", "error", "failed", "notsetup",
            "unavailable", "unhealthy", "unresponsive",
        }
        or (
            (enable_states := [
                _truth(record, field) for field in connector_enable_fields
                if _state(record, field)
            ])
            and all(state is False for state in enable_states)
        )
    ]
    add("Intune security-service connectors are disabled or unhealthy", "High",
        [security_connectors], unhealthy_connectors,
        "Disabled or unhealthy Intune security-service connectors were directly observed.")

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

    gsa_branches = _inventory(catalog, "gsa_branches")
    gsa_connectors = _inventory(catalog, "gsa_connectors")
    unhealthy_gsa_connectivity = [
        record
        for item in (gsa_branches, gsa_connectors)
        for record in item["records"]
        if _truth(record, "enabled", "isEnabled") is False
        or _state(
            record, "connectivityState", "status", "state", "healthStatus"
        ) in {
            "degraded", "disabled", "error", "failed", "inactive", "offline", "unhealthy",
        }
    ]
    add("Global Secure Access branches or connectors are unhealthy", "High",
        [gsa_branches, gsa_connectors], unhealthy_gsa_connectivity,
        "Disabled, offline, failed or unhealthy connectivity components were directly observed.")

    enabled_unassociated_profiles = []
    for record in gsa_profiles["records"]:
        enabled = (
            _truth(record, "enabled", "isEnabled") is True
            or _state(record, "state", "status") == "enabled"
        )
        associations = record.get("associations")
        if enabled and isinstance(associations, list) and not associations:
            enabled_unassociated_profiles.append(record)
    add("Enabled Global Secure Access forwarding profiles have no associations", "Medium",
        [gsa_profiles], enabled_unassociated_profiles,
        "Enabled forwarding profiles with an explicitly empty association collection were observed.")

    pim_directory_requests = _inventory(catalog, "pim_directory_requests")
    pim_group_requests = _inventory(catalog, "pim_group_requests")
    pim_azure_requests = _inventory(
        catalog, "arm_pim_azure_resource_assignment_requests",
        prefix="arm_pim_azure_resource_assignment_requests",
    )
    permanent_requests = [
        record
        for item in (pim_directory_requests, pim_group_requests, pim_azure_requests)
        for record in item["records"]
        if _no_expiration(record)
        and _state(record, "status", "properties.status") not in {
            "cancelled", "denied", "failed", "revoked",
        }
    ]
    add("Privileged activation or assignment requests seek permanent access", "High",
        [pim_directory_requests, pim_group_requests, pim_azure_requests],
        permanent_requests,
        "Non-rejected privileged requests explicitly seeking no-expiration access were observed.")

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
