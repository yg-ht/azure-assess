#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Additional conservative findings over existing Azure collection datasets."""

from typing import Any, Iterable, Mapping, Optional

from .finding_inventory import inventory


def _value(record: Mapping[str, Any], *paths: str) -> Any:
    for path in paths:
        value: Any = record
        for part in path.split("."):
            if not isinstance(value, Mapping) or part not in value:
                value = None
                break
            value = value[part]
        if value is not None:
            return value
    return None


def _state(record: Mapping[str, Any], *paths: str) -> str:
    value = _value(record, *paths)
    return "" if value is None else str(value).strip().lower()


def _truth(record: Mapping[str, Any], *paths: str) -> Optional[bool]:
    state = _state(record, *paths)
    if state in {"true", "1", "yes", "enabled"}:
        return True
    if state in {"false", "0", "no", "disabled"}:
        return False
    return None


def _emit(result, unsupported, title: str, severity: str,
          inventories: Iterable[dict], observations: list, reason: str,
          correlated: bool = False, positive_supported: Optional[bool] = None):
    inventories = list(inventories)
    if positive_supported is None:
        positive_supported = bool(observations) and (
            all(item["complete"] for item in inventories)
            if correlated else any(item["positive_usable"] for item in inventories)
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
    finding["_required_endpoint_ids"] = [
        item["endpoint_id"] for item in inventories
    ]
    return finding, [name for item in inventories for name in item["files"]]


def _explicit_actions(record: Mapping[str, Any]) -> Optional[list]:
    actions = _value(record, "actions.actionGroups", "actionGroups", "actions")
    if isinstance(actions, list):
        return actions
    if isinstance(actions, Mapping):
        groups = actions.get("actionGroups")
        if isinstance(groups, list):
            return groups
    return None


def _role_id(record: Mapping[str, Any], *paths: str) -> str:
    value = _value(record, *paths)
    return str(value or "").strip().rstrip("/").split("/")[-1].lower()


def _has_wildcard_permissions(record: Mapping[str, Any]) -> bool:
    permissions = record.get("permissions") or []
    for permission in permissions if isinstance(permissions, list) else []:
        if not isinstance(permission, Mapping):
            continue
        for key in ("actions", "dataActions"):
            values = permission.get(key) or []
            if not isinstance(values, list):
                continue
            if any(
                str(value).strip() == "*" or str(value).rstrip().endswith("/*")
                for value in values
            ):
                return True
    return False


def _apim_weak_tls(record: Mapping[str, Any]) -> bool:
    properties = record.get("customProperties") or {}
    if not isinstance(properties, Mapping):
        return False
    for key, value in properties.items():
        lowered = str(key).lower()
        if any(protocol in lowered for protocol in ("tls10", "tls1.0", "tls11", "tls1.1")):
            if str(value).strip().lower() in {"true", "1", "enabled"}:
                return True
    return False


def evaluate_collection_surface_findings(catalog, result, unsupported):
    findings, sources = [], {}

    def inv(output):
        return inventory(catalog, output, output)

    def add(
        title, severity, inventories, observations, reason, correlated=False,
        positive_supported=None,
    ):
        finding, files = _emit(
            result, unsupported, title, severity, inventories, observations,
            reason, correlated=correlated,
            positive_supported=positive_supported,
        )
        findings.append(finding)
        sources[title] = files

    alerts = inv("az_security_alert_list")
    add("Unresolved significant Defender for Cloud alerts", "High", [alerts], [
        record for record in alerts["records"]
        if _state(record, "severity", "properties.severity") in {
            "high", "medium", "critical",
        }
        and _state(record, "status", "state", "properties.status", "properties.state") in {
            "active", "inprogress", "new",
        }
    ], "Unresolved medium, high or critical Defender for Cloud alerts were directly observed.")

    activity = inv("az_monitor_activity-log_list")
    sensitive_operations = {
        "microsoft.authorization/roleassignments/delete",
        "microsoft.authorization/roleassignments/write",
        "microsoft.authorization/policyassignments/delete",
        "microsoft.insights/diagnosticsettings/delete",
        "microsoft.keyvault/vaults/accesspolicies/write",
        "microsoft.network/networksecuritygroups/securityrules/delete",
        "microsoft.network/networksecuritygroups/securityrules/write",
        "microsoft.resources/subscriptions/resourcegroups/delete",
        "microsoft.security/securitysolutions/delete",
    }
    add("Security-sensitive Azure control-plane changes", "Medium", [activity], [
        record for record in activity["records"]
        if _state(record, "operationName.value", "operationName") in sensitive_operations
        and _state(record, "status.value", "status") in {
            "accepted", "started", "succeeded", "success",
        }
    ], "Successful security-sensitive Azure control-plane changes were directly observed.")

    gateways = inv("az_network_application-gateway_list")
    gateway_details = inv(
        "az_network_application-gateway_show_--name_name_--resource-group_resourcegroup"
    )
    waf_config = inv(
        "az_network_application-gateway_waf-config_show_--gateway-name_name_--resource-group_resourcegroup"
    )
    waf_policies = inv("az_network_application-gateway_waf-policy_list")
    weak_inline_waf = [
        record for record in waf_config["records"]
        if _truth(
            record, "enabled", "policySettings.enabled", "policySettings.state"
        ) is False
        or _state(record, "firewallMode", "policySettings.mode") == "detection"
        or bool(_value(record, "managedRules.exclusions"))
    ]
    policy_by_id = {
        str(record.get("id") or "").rstrip("/").casefold(): record
        for record in waf_policies["records"]
        if record.get("id")
    }
    referenced_policy_ids = {
        str(_value(gateway, "firewallPolicy.id") or "").rstrip("/").casefold()
        for gateway in gateways["records"]
        if _value(gateway, "firewallPolicy.id")
    }
    weak_policy_ids = {
        policy_id for policy_id, record in policy_by_id.items()
        if _truth(record, "policySettings.enabled", "policySettings.state") is False
        or _state(record, "policySettings.mode") == "detection"
        or bool(_value(record, "managedRules.exclusions"))
    }
    attached_weak_policies = [
        {
            "gateway": gateway,
            "policy": policy_by_id[policy_id],
        }
        for gateway in gateways["records"]
        if (policy_id := str(
            _value(gateway, "firewallPolicy.id") or ""
        ).rstrip("/").casefold()) in weak_policy_ids
    ]
    attached_weak_waf = weak_inline_waf + attached_weak_policies
    attached_supported = bool(attached_weak_waf) and (
        (bool(weak_inline_waf) and waf_config["positive_usable"])
        or (
            bool(attached_weak_policies)
            and gateways["complete"]
            and waf_policies["complete"]
        )
    )
    add("Application Gateway WAF is disabled or not enforcing full prevention", "High",
        [waf_config, waf_policies, gateways], attached_weak_waf,
        "An attached WAF was disabled, configured for Detection mode, or had explicit managed-rule exclusions.",
        positive_supported=attached_supported)

    unattached_weak_policies = [
        record for policy_id, record in policy_by_id.items()
        if policy_id in weak_policy_ids and policy_id not in referenced_policy_ids
    ]
    add("Unattached Application Gateway WAF policies are not enforcing full prevention", "Medium",
        [waf_policies, gateways], unattached_weak_policies,
        "An unattached WAF policy was disabled, configured for Detection mode, or had explicit managed-rule exclusions.",
        correlated=True)
    plaintext_listeners = []
    for gateway in gateways["records"] + gateway_details["records"]:
        listeners = gateway.get("httpListeners") or []
        rules = gateway.get("requestRoutingRules") or []
        for listener in listeners if isinstance(listeners, list) else []:
            if not isinstance(listener, Mapping) or _state(listener, "protocol") != "http":
                continue
            listener_id = str(listener.get("id") or "").rstrip("/").casefold()
            matching_rules = [
                rule for rule in rules if isinstance(rule, Mapping)
                and listener_id
                and str(_value(rule, "httpListener.id") or "").rstrip("/").casefold()
                == listener_id
            ] if isinstance(rules, list) else []
            non_redirect_rules = [
                rule for rule in matching_rules
                if _value(rule, "redirectConfiguration") is None
            ]
            if non_redirect_rules:
                plaintext_listeners.append({
                    "gatewayId": gateway.get("id"),
                    "gatewayName": gateway.get("name"),
                    "listener": listener,
                    "routingRules": non_redirect_rules,
                })
    add("Application Gateway exposes plaintext HTTP listeners", "High",
        [gateways, gateway_details], plaintext_listeners,
        "Application Gateway listeners explicitly configured for HTTP were observed.")

    appconfig = inv("az_appconfig_list")
    add("Azure App Configuration permits public network access", "Medium", [appconfig], [
        record for record in appconfig["records"]
        if _state(record, "publicNetworkAccess", "properties.publicNetworkAccess") == "enabled"
    ], "App Configuration stores explicitly permitting public network access were observed.")
    add("Azure App Configuration permits local access-key authentication", "High", [appconfig], [
        record for record in appconfig["records"]
        if _truth(record, "disableLocalAuth", "properties.disableLocalAuth") is False
    ], "App Configuration stores explicitly retaining local access-key authentication were observed.")

    log_analytics = inv("az_monitor_log-analytics_workspace_list")
    add("Log Analytics workspaces permit public query or ingestion", "Medium", [log_analytics], [
        record for record in log_analytics["records"]
        if _state(
            record,
            "publicNetworkAccessForIngestion",
            "properties.publicNetworkAccessForIngestion",
        ) == "enabled"
        or _state(
            record,
            "publicNetworkAccessForQuery",
            "properties.publicNetworkAccessForQuery",
        ) == "enabled"
    ], "Log Analytics public query or ingestion was explicitly enabled.")

    app_insights_details = inv(
        "az_monitor_app-insights_component_show_--app_name_--resource-group_resourcegroup"
    )
    add("Application Insights permits public query or ingestion", "Medium",
        [app_insights_details], [
            record for record in app_insights_details["records"]
            if _state(
                record,
                "publicNetworkAccessForIngestion",
                "properties.publicNetworkAccessForIngestion",
            ) == "enabled"
            or _state(
                record,
                "publicNetworkAccessForQuery",
                "properties.publicNetworkAccessForQuery",
            ) == "enabled"
        ], "Application Insights public query or ingestion was explicitly enabled.")

    vms = inv("az_vm_show_--name_name_--resource-group_resourcegroup")
    weak_trusted_launch = [
        record for record in vms["records"]
        if _state(record, "securityProfile.securityType") in {
            "confidentialvm", "trustedlaunch",
        }
        and (
            _truth(record, "securityProfile.uefiSettings.secureBootEnabled") is False
            or _truth(record, "securityProfile.uefiSettings.vTpmEnabled") is False
        )
    ]
    add("Trusted Launch virtual machines disable Secure Boot or vTPM", "Medium",
        [vms], weak_trusted_launch,
        "Trusted Launch-capable security profiles explicitly disabled Secure Boot or vTPM.")

    disks = inv("az_disk_list_--resource-group_name")
    snapshots = inv("az_snapshot_list")
    exposed_exports = [
        record for record in disks["records"] + snapshots["records"]
        if _state(record, "publicNetworkAccess", "properties.publicNetworkAccess") == "enabled"
        and _state(record, "networkAccessPolicy", "properties.networkAccessPolicy") == "allowall"
    ]
    add("Managed disks or snapshots permit unrestricted network export", "High",
        [disks, snapshots], exposed_exports,
        "Disk or snapshot network export access was explicitly enabled for all networks.")

    metric_alerts = inv("az_monitor_metrics_alert_list")
    activity_alerts = inv("az_monitor_activity-log_alert_list")
    scheduled_queries = inv("az_monitor_scheduled-query_list")
    alerts_without_actions = []
    for item in metric_alerts["records"] + activity_alerts["records"] + scheduled_queries["records"]:
        actions = _explicit_actions(item)
        if _truth(item, "enabled", "properties.enabled") is True and actions == []:
            alerts_without_actions.append(item)
    add("Azure Monitor alert rules have no effective action group", "Medium",
        [metric_alerts, activity_alerts, scheduled_queries], alerts_without_actions,
        "Enabled alert rules with an explicitly empty action-group collection were observed.")

    apim = inv("az_apim_show_--name_name_--resource-group_resourcegroup")
    add("API Management permits deprecated TLS protocols", "High", [apim], [
        record for record in apim["records"] if _apim_weak_tls(record)
    ], "API Management custom properties explicitly enabled TLS 1.0 or TLS 1.1.")
    add("API Management services lack a managed identity", "Medium", [apim], [
        record for record in apim["records"]
        if ("identity" in record and record.get("identity") in (None, {}))
        or _state(record, "identity.type") == "none"
    ], "API Management services without a configured managed identity were observed.",
        correlated=True)

    messaging = [
        inv("az_eventhubs_namespace_list"), inv("az_iot_hub_list"),
        inv("az_relay_namespace_list"), inv("az_servicebus_namespace_list"),
        inv("az_signalr_list"),
    ]
    messaging_records = [record for item in messaging for record in item["records"]]
    add("Azure messaging services permit local authentication", "High", messaging, [
        record for record in messaging_records
        if _truth(record, "disableLocalAuth", "properties.disableLocalAuth") is False
    ], "Messaging services explicitly retaining local/key authentication were observed.")
    add("Azure messaging services permit unrestricted public network access", "Medium", messaging, [
        record for record in messaging_records
        if _state(record, "publicNetworkAccess", "properties.publicNetworkAccess") == "enabled"
        and _state(
            record,
            "defaultAction",
            "networkRuleSet.defaultAction",
            "networkRuleSets.defaultAction",
            "properties.defaultAction",
            "properties.networkRuleSet.defaultAction",
            "properties.networkRuleSets.defaultAction",
        ) == "allow"
    ], "Messaging services explicitly permitting public network access were observed.")
    add("Azure messaging services permit deprecated TLS versions", "High", messaging, [
        record for record in messaging_records
        if _state(record, "minimumTlsVersion", "properties.minimumTlsVersion") in {
            "1.0", "1.1", "tls1_0", "tls1_1",
        }
    ], "Messaging services explicitly permitting TLS versions below 1.2 were observed.")

    role_definitions = inv("az_role_definition_custom_list")
    role_assignments = inv("az_role_assignment_list")
    broad_roles = {
        _role_id(record, "id", "name"): record
        for record in role_definitions["records"]
        if _role_id(record, "id", "name") and _has_wildcard_permissions(record)
    }
    wildcard_assignments = []
    for assignment in role_assignments["records"]:
        role_id = _role_id(assignment, "roleDefinitionId")
        if role_id in broad_roles:
            wildcard_assignments.append({
                "assignment": assignment,
                "roleDefinition": broad_roles[role_id],
            })
    add("Assigned custom Azure roles contain wildcard permissions", "High",
        [role_definitions, role_assignments], wildcard_assignments,
        "Assignments to custom roles containing wildcard actions or data actions were observed.",
        correlated=True)

    return findings, sources
