# SPDX-License-Identifier: AGPL-3.0-or-later
from datetime import datetime, timezone

from azure_findings_shared import (
    ADMIN_PORTAL_APPLICATION_IDS,
    APPROVED_VM_IMAGE_PUBLISHERS,
    GLOBAL_ADMIN_ROLE_TEMPLATE_ID,
    MANAGEMENT_API_APPLICATION_IDS,
    RISKY_ADMIN_ROLE_NAMES,
    VM_ACCESS_ROLE_NAMES,
    alert_policy_disabled_alerts,
    alert_policy_has_email_notifications,
    app_setting_value,
    app_stack_value,
    assessment_matches,
    assessment_resource_id,
    assessment_status,
    alert_text,
    build_user_registration_lookup,
    build_parameter_map,
    collection_key,
    collection_parameters,
    compact_dict,
    conditional_access_requires_mfa,
    conditional_access_targets_admins,
    conditional_access_targets_application,
    first_matching_group_setting,
    first_value,
    flatten_permission_actions,
    group_setting_value,
    identity_principal_id,
    is_any_source,
    map_by_name,
    normalize_location,
    normalize_text,
    parameter_value,
    parameterised_record_keys,
    parse_iso_datetime,
    ports_match,
    record_key,
    registration_has_mfa,
    resource_brief,
    result,
    role_assignment_name,
    rule_port_values,
    setting_is_enabled,
    truthy,
    version_is_older,
)

def find_public_blob_access(storage_accounts):
    evidence = []
    for account in storage_accounts:
        if truthy(first_value(account, "allowBlobPublicAccess", ("properties", "allowBlobPublicAccess"))):
            item = resource_brief(account)
            item["allowBlobPublicAccess"] = first_value(
                account, "allowBlobPublicAccess", ("properties", "allowBlobPublicAccess")
            )
            evidence.append(item)
    return result(
        "Azure blob container permits public access",
        "High",
        "Uses the storage account-level blob public access control collected by azure-collect.",
        evidence,
    )

def find_custom_subscription_owner_roles(role_definitions, role_assignments):
    risky_roles = {}
    for role in role_definitions:
        role_type = str(role.get("roleType") or role.get("type") or "").lower()
        is_custom = role_type == "customrole" or truthy(role.get("isCustom"))
        if not is_custom:
            continue

        assignable_scopes = role.get("assignableScopes") or []
        subscription_scopes = [scope for scope in assignable_scopes if str(scope).lower().startswith("/subscriptions/")]
        if not subscription_scopes:
            continue

        actions = flatten_permission_actions(role)
        lowered_actions = {action.lower() for action in actions}
        owner_like = (
            "*" in lowered_actions
            or "microsoft.authorization/*" in lowered_actions
            or "microsoft.authorization/roleassignments/write" in lowered_actions
            or "microsoft.authorization/locks/*" in lowered_actions
            or "owner" in str(role.get("roleName") or role.get("name") or "").lower()
        )
        if owner_like:
            risky_roles[str(role.get("id")).lower()] = {
                "id": role.get("id"),
                "name": role.get("roleName") or role.get("name"),
                "assignableScopes": subscription_scopes,
                "actions": actions,
                "assignments": [],
            }

    for assignment in role_assignments:
        role_id = str(assignment.get("roleDefinitionId") or "").lower()
        if role_id in risky_roles and str(assignment.get("scope") or "").lower().startswith("/subscriptions/"):
            risky_roles[role_id]["assignments"].append(
                {
                    "scope": assignment.get("scope"),
                    "principalId": assignment.get("principalId"),
                    "principalType": assignment.get("principalType"),
                    "resolvedPrincipal": assignment.get("resolvedPrincipal"),
                }
            )

    return result(
        "Custom Azure subscription owner roles permitted",
        "Medium",
        "Flags custom role definitions assignable at subscription scope that appear owner-like based on wildcard or authorization actions.",
        list(risky_roles.values()),
    )

def find_unencrypted_transfer(storage_accounts):
    evidence = []
    for account in storage_accounts:
        https_only = first_value(
            account,
            "supportsHttpsTrafficOnly",
            ("properties", "supportsHttpsTrafficOnly"),
            ("enableHttpsTrafficOnly",),
        )
        if https_only is False:
            item = resource_brief(account)
            item["supportsHttpsTrafficOnly"] = https_only
            evidence.append(item)
    return result(
        "Azure Storage accounts do not enforce encrypted data transfer",
        "Medium",
        "Checks the storage account HTTPS-only setting.",
        evidence,
    )

def find_storage_deprecated_tls(storage_accounts):
    evidence = []
    secure_versions = {"tls1_2", "tls1_3"}
    for account in storage_accounts:
        tls_version = first_value(account, "minimumTlsVersion", ("properties", "minimumTlsVersion"))
        if tls_version is None or str(tls_version).lower() not in secure_versions:
            item = resource_brief(account)
            item["minimumTlsVersion"] = tls_version
            evidence.append(item)
    return result(
        "Azure Storage Accounts permitting deprecated TLS versions",
        "Medium",
        "Flags storage accounts whose minimum TLS version is missing or below TLS1_2.",
        evidence,
    )

def find_storage_default_network_access(storage_accounts):
    evidence = []
    for account in storage_accounts:
        public_network = str(first_value(account, "publicNetworkAccess", ("properties", "publicNetworkAccess")) or "")
        default_action = str(
            first_value(account, ("networkAcls", "defaultAction"), ("properties", "networkAcls", "defaultAction")) or ""
        )
        if public_network.lower() == "enabled" or default_action.lower() == "allow":
            item = resource_brief(account)
            item["publicNetworkAccess"] = public_network
            item["defaultAction"] = default_action
            evidence.append(item)
    return result(
        "Storage accounts with default network access permitted",
        "Medium",
        "Flags storage accounts with public network access enabled or network ACL default action set to Allow.",
        evidence,
    )

def find_key_vault_unrestricted_access(key_vaults, network_rules):
    evidence = []
    rules_map = map_by_name(network_rules)

    for vault in key_vaults:
        name = str(vault.get("name") or "").lower()
        rule = rules_map.get(str(vault.get("id") or "").lower()) or rules_map.get(name) or {}
        public_network = str(
            first_value(vault, "publicNetworkAccess", ("properties", "publicNetworkAccess")) or "Enabled"
        )
        default_action = str(first_value(rule, "defaultAction", ("properties", "defaultAction")) or "Allow")
        ip_rules = first_value(rule, "ipRules", ("properties", "ipRules")) or []
        vnet_rules = first_value(rule, "virtualNetworkRules", ("properties", "virtualNetworkRules")) or []

        unrestricted = public_network.lower() != "disabled" and (
            default_action.lower() == "allow" or (not ip_rules and not vnet_rules)
        )
        if unrestricted:
            item = resource_brief(vault)
            item["publicNetworkAccess"] = public_network
            item["defaultAction"] = default_action
            item["ipRuleCount"] = len(ip_rules)
            item["virtualNetworkRuleCount"] = len(vnet_rules)
            evidence.append(item)

    return result(
        "Access to Azure Key Vault not restricted to trusted source addresses",
        "Low",
        "Uses vault network-rule data to flag broadly reachable vaults.",
        evidence,
    )

def find_monitor_alert_notification_gaps(metric_alerts):
    evidence = []
    for alert in metric_alerts:
        severity = str(alert.get("severity") or "")
        actions = alert.get("actions") or []
        if severity in {"0", "1", "Sev0", "Sev1"} and not actions:
            item = resource_brief(alert)
            item["severity"] = severity
            item["enabled"] = alert.get("enabled")
            evidence.append(item)
    return result(
        "Azure Monitor Alerts not configured to notify high severity events",
        "Low",
        "Checks high-severity metric alerts that have no action groups attached.",
        evidence,
    )

def find_storage_without_private_endpoints(storage_accounts):
    evidence = []
    for account in storage_accounts:
        connections = first_value(
            account,
            "privateEndpointConnections",
            ("properties", "privateEndpointConnections"),
        ) or []
        if not connections:
            evidence.append(resource_brief(account))
    return result(
        "Storage Accounts not using private IP endpoints",
        "Low",
        "Uses the storage account private endpoint connection list embedded in the account payload.",
        evidence,
    )

def find_defender_not_enabled(defender_settings):
    evidence = []
    for setting in defender_settings:
        pricing = str(setting.get("pricingTier") or setting.get("tier") or "")
        if pricing.lower() != "standard":
            evidence.append(
                {
                    "name": setting.get("name"),
                    "id": setting.get("id"),
                    "pricingTier": pricing,
                    "subPlan": setting.get("subPlan"),
                }
            )
    return result(
        "Microsoft Defender for Cloud is not enabled",
        "Low",
        "Flags Defender pricing plans that are not set to Standard.",
        evidence,
    )

def find_key_vault_rbac_disabled(key_vaults):
    evidence = []
    for vault in key_vaults:
        rbac = first_value(vault, "enableRbacAuthorization", ("properties", "enableRbacAuthorization"))
        if rbac is False:
            item = resource_brief(vault)
            item["enableRbacAuthorization"] = rbac
            evidence.append(item)
    return result(
        "Role-Based Access Control (RBAC) not enabled for Azure Key Vault",
        "Low",
        "Checks the key vault RBAC authorization mode.",
        evidence,
    )

def find_network_watcher_gaps(locations, resources, network_watchers):
    watcher_locations = {normalize_location(w.get("location")) for w in network_watchers if normalize_location(w.get("location"))}
    used_locations = {
        normalize_location(resource.get("location"))
        for resource in resources
        if normalize_location(resource.get("location"))
    }
    if not used_locations:
        used_locations = {normalize_location(item.get("name")) for item in locations if normalize_location(item.get("name"))}

    evidence = []
    for location in sorted(used_locations):
        if location not in watcher_locations:
            evidence.append({"location": location})

    return result(
        "Azure Network Watcher not enabled for all subscription locations",
        "Low",
        "Compares enabled Network Watchers against regions actually used by collected resources, falling back to subscription locations.",
        evidence,
    )

def find_key_vault_not_recoverable(key_vaults):
    evidence = []
    for vault in key_vaults:
        soft_delete = first_value(vault, "enableSoftDelete", ("properties", "enableSoftDelete"))
        purge_protection = first_value(vault, "enablePurgeProtection", ("properties", "enablePurgeProtection"))
        if soft_delete is False or purge_protection is False:
            item = resource_brief(vault)
            item["enableSoftDelete"] = soft_delete
            item["enablePurgeProtection"] = purge_protection
            evidence.append(item)
    return result(
        "Azure Key Vault not recoverable",
        "Low",
        "Flags vaults with soft delete or purge protection disabled.",
        evidence,
    )

def find_resource_lock_admin_role_gap(role_definitions, role_assignments):
    role_map = {}
    for role in role_definitions:
        actions = {action.lower() for action in flatten_permission_actions(role)}
        if "microsoft.authorization/locks/*" in actions or "microsoft.authorization/*" in actions or "*" in actions:
            role_map[str(role.get("id") or "").lower()] = role

    evidence = []
    for assignment in role_assignments:
        role = role_map.get(str(assignment.get("roleDefinitionId") or "").lower())
        if not role:
            continue
        evidence.append(
            {
                "scope": assignment.get("scope"),
                "principalId": assignment.get("principalId"),
                "principalType": assignment.get("principalType"),
                "resolvedPrincipal": assignment.get("resolvedPrincipal"),
                "roleDefinitionId": role.get("id"),
                "roleDefinitionName": role.get("roleName") or role.get("name"),
            }
        )

    return result(
        "Users with Permission to Administer Resource Locks Assigned",
        "Low",
        "Flags role assignments where the resolved role definition grants Microsoft.Authorization/locks permissions.",
        evidence,
    )

def find_app_service_deprecated_http(web_app_configs):
    evidence = []
    for config in web_app_configs:
        if config.get("http20Enabled") is False:
            item = resource_brief(config)
            item["http20Enabled"] = config.get("http20Enabled")
            item["minTlsVersion"] = config.get("minTlsVersion")
            evidence.append(item)
    return result(
        "Azure App Services using deprecated HTTP Version",
        "Low",
        "Flags App Service configurations with HTTP/2 disabled.",
        evidence,
    )

def find_storage_microsoft_managed_keys(storage_accounts):
    evidence = []
    for account in storage_accounts:
        key_source = first_value(account, ("encryption", "keySource"), ("properties", "encryption", "keySource"))
        if str(key_source).lower() == "microsoft.storage":
            item = resource_brief(account)
            item["keySource"] = key_source
            evidence.append(item)
    return result(
        "Data at rest in Azure storage accounts use Microsoft managed encryption keys",
        "Low",
        "Flags storage accounts using Microsoft-managed keys instead of customer-managed keys.",
        evidence,
    )

def find_storage_no_infra_encryption(storage_accounts):
    evidence = []
    for account in storage_accounts:
        infra_encryption = first_value(
            account,
            ("encryption", "requireInfrastructureEncryption"),
            ("properties", "encryption", "requireInfrastructureEncryption"),
        )
        if infra_encryption is False:
            item = resource_brief(account)
            item["requireInfrastructureEncryption"] = infra_encryption
            evidence.append(item)
    return result(
        "Azure Storage Accounts without infrastructure encryption enabled",
        "Low",
        "Checks the infrastructure encryption setting on storage accounts.",
        evidence,
    )

def find_postgres_azure_services_access(postgres_firewall_rules):
    evidence = []
    for rule in postgres_firewall_rules:
        start_ip = normalize_text(rule.get("startIpAddress"))
        end_ip = normalize_text(rule.get("endIpAddress"))
        if start_ip == "0.0.0.0" and end_ip == "0.0.0.0":
            params = collection_parameters(rule)
            evidence.append(
                {
                    "serverName": params.get("name"),
                    "resourceGroup": params.get("resourceGroup"),
                    "ruleName": rule.get("name"),
                    "startIpAddress": rule.get("startIpAddress"),
                    "endIpAddress": rule.get("endIpAddress"),
                }
            )
    return result(
        "Access permitted to PostgreSQL server from Azure services",
        "Medium",
        "Flags PostgreSQL flexible server firewall rules using the 0.0.0.0 to 0.0.0.0 Azure-services shortcut.",
        evidence,
    )

def find_storage_soft_delete_disabled(blob_service_properties):
    evidence = []
    for blob_props in blob_service_properties:
        delete_retention = first_value(
            blob_props,
            ("deleteRetentionPolicy", "enabled"),
            ("properties", "deleteRetentionPolicy", "enabled"),
        )
        container_retention = first_value(
            blob_props,
            ("containerDeleteRetentionPolicy", "enabled"),
            ("properties", "containerDeleteRetentionPolicy", "enabled"),
        )
        if delete_retention is False or container_retention is False:
            params = collection_parameters(blob_props)
            evidence.append(
                {
                    "storageAccount": params.get("name"),
                    "resourceGroup": params.get("resourceGroup"),
                    "blobSoftDeleteEnabled": delete_retention,
                    "containerSoftDeleteEnabled": container_retention,
                }
            )
    return result(
        "Azure Storage Containers without Soft Delete protection",
        "Low",
        "Uses blob service properties to flag disabled blob or container soft delete.",
        evidence,
    )

def find_activity_log_alert_gaps(activity_log_alerts):
    expected = {
        "role_assignment_changes": {
            "patterns": ["microsoft.authorization/roleassignments/write", "microsoft.authorization/roleassignments/delete"],
            "description": "role assignment create/delete events",
        },
        "nsg_rule_changes": {
            "patterns": ["microsoft.network/networksecuritygroups/securityrules/write", "microsoft.network/networksecuritygroups/securityrules/delete"],
            "description": "NSG rule create/delete events",
        },
        "route_changes": {
            "patterns": ["microsoft.network/routetables/routes/write", "microsoft.network/routetables/routes/delete"],
            "description": "route table route create/delete events",
        },
        "public_ip_changes": {
            "patterns": ["microsoft.network/publicipaddresses/write", "microsoft.network/publicipaddresses/delete"],
            "description": "public IP create/delete events",
        },
        "policy_assignment_changes": {
            "patterns": ["microsoft.authorization/policyassignments/write", "microsoft.authorization/policyassignments/delete"],
            "description": "policy assignment create/delete events",
        },
        "sql_firewall_rule_changes": {
            "patterns": [
                "microsoft.sql/servers/firewallrules/write",
                "microsoft.sql/servers/firewallrules/delete",
            ],
            "description": "SQL server firewall rule create/delete events",
        },
        "storage_key_access": {
            "patterns": ["microsoft.storage/storageaccounts/listkeys/action", "microsoft.storage/storageaccounts/regeneratekey/action"],
            "description": "storage key listing/regeneration events",
        },
    }

    coverage = {}
    for alert in activity_log_alerts:
        text = alert_text(alert)
        for key, definition in expected.items():
            if any(pattern in text for pattern in definition["patterns"]):
                coverage[key] = True

    evidence = []
    for key, definition in expected.items():
        if not coverage.get(key):
            evidence.append({"eventType": key, "description": definition["description"]})

    return result(
        "Azure Activity Log Alerts missing for key event types",
        "Low",
        "Checks collected activity log alert rules for coverage of high-value control-plane events.",
        evidence,
    )

def find_security_contact_phone_missing(security_contacts):
    evidence = []
    for contact in security_contacts:
        phone = first_value(contact, "phone", ("properties", "phone"))
        if not normalize_text(phone):
            evidence.append(
                {
                    "name": contact.get("name"),
                    "id": contact.get("id"),
                    "email": first_value(contact, "email", ("properties", "email")),
                    "phone": phone,
                }
            )
    return result(
        "Security contact phone number is not set in Azure tenant",
        "Low",
        "Flags Microsoft Defender for Cloud security contacts with no phone number.",
        evidence,
    )

def find_appservice_http_logs_disabled(web_app_logs):
    evidence = []
    for log_config in web_app_logs:
        http_logs_enabled = first_value(
            log_config,
            ("httpLogs", "fileSystem", "enabled"),
            ("properties", "httpLogs", "fileSystem", "enabled"),
        )
        if http_logs_enabled is False:
            params = collection_parameters(log_config)
            evidence.append(
                {
                    "webApp": params.get("name"),
                    "resourceGroup": params.get("resourceGroup"),
                    "httpLogsFileSystemEnabled": http_logs_enabled,
                }
            )
    return result(
        "Azure AppService HTTP logs not enabled enabled",
        "Low",
        "Uses App Service log configuration to flag disabled HTTP filesystem logging.",
        evidence,
    )

def find_diagnostic_category_gaps(diagnostic_settings, diagnostic_categories):
    settings_by_resource = {}
    for setting in diagnostic_settings:
        params = collection_parameters(setting)
        resource_id = params.get("id")
        if not resource_id:
            resource_id = first_value(setting, ("properties", "scope"), ("properties", "resourceId"))
        if not resource_id:
            continue
        settings_by_resource.setdefault(resource_id.lower(), []).append(setting)

    categories_by_resource = {}
    for category in diagnostic_categories:
        params = collection_parameters(category)
        resource_id = params.get("id")
        if not resource_id:
            continue
        categories_by_resource.setdefault(resource_id.lower(), []).append(category)

    evidence = []
    for resource_id, categories in categories_by_resource.items():
        available_logs = {category.get("name") for category in categories if normalize_text(category.get("categoryType")) == "logs"}
        available_metrics = {category.get("name") for category in categories if normalize_text(category.get("categoryType")) == "metrics"}
        settings = settings_by_resource.get(resource_id, [])

        enabled_logs = set()
        enabled_metrics = set()
        for setting in settings:
            for log in setting.get("logs", []) or []:
                if log.get("enabled") is True and log.get("category"):
                    enabled_logs.add(log.get("category"))
            for metric in setting.get("metrics", []) or []:
                if metric.get("enabled") is True and metric.get("category"):
                    enabled_metrics.add(metric.get("category"))

        if (available_logs and not enabled_logs) or (available_metrics and not enabled_metrics):
            evidence.append(
                {
                    "resourceId": resource_id,
                    "availableLogCategories": sorted(available_logs),
                    "enabledLogCategories": sorted(enabled_logs),
                    "availableMetricCategories": sorted(available_metrics),
                    "enabledMetricCategories": sorted(enabled_metrics),
                }
            )

    return result(
        "Ensure Diagnostic Setting captures appropriate categories",
        "Low",
        "Compares available diagnostic categories with enabled categories on the collected diagnostic settings.",
        evidence,
    )

def find_subscription_activity_logs_without_diagnostics(subscriptions, subscription_diagnostic_settings):
    settings_by_subscription = {}
    for setting in subscription_diagnostic_settings:
        subscription_id = collection_parameters(setting).get("id")
        if subscription_id:
            settings_by_subscription.setdefault(subscription_id.lower(), []).append(setting)

    evidence = []
    for subscription in subscriptions:
        subscription_id = normalize_text(subscription.get("id"))
        if not subscription_id:
            continue
        if not settings_by_subscription.get(subscription_id):
            evidence.append({"id": subscription.get("id"), "name": subscription.get("name")})

    return result(
        "Azure Subscription-level activity logs without a 'Diagnostic Setting' exist",
        "Low",
        "Checks whether each collected subscription has at least one subscription-scoped diagnostic setting.",
        evidence,
    )

def find_acr_admin_user_enabled(container_registries):
    evidence = []
    for registry in container_registries:
        if first_value(registry, "adminUserEnabled", ("properties", "adminUserEnabled")) is True:
            evidence.append(compact_dict(registry, adminUserEnabled=True))
    return result(
        "Azure Container Registry admin user enabled",
        "Low",
        "Flags Azure Container Registries with the admin user enabled.",
        evidence,
    )

def find_aks_rbac_disabled(aks_clusters):
    evidence = []
    for cluster in aks_clusters:
        if first_value(cluster, "enableRBAC", ("properties", "enableRBAC")) is False:
            evidence.append(compact_dict(cluster, enableRBAC=False))
    return result(
        "AKS clusters without RBAC enabled",
        "Low",
        "Flags AKS clusters where Kubernetes RBAC is disabled.",
        evidence,
    )

def find_aks_local_accounts_enabled(aks_clusters):
    evidence = []
    for cluster in aks_clusters:
        disabled_local_accounts = first_value(cluster, "disableLocalAccounts", ("properties", "disableLocalAccounts"))
        if disabled_local_accounts is False or disabled_local_accounts is None:
            evidence.append(compact_dict(cluster, disableLocalAccounts=disabled_local_accounts))
    return result(
        "AKS clusters with local accounts enabled",
        "Low",
        "Flags AKS clusters where local accounts are enabled or the control is unset.",
        evidence,
    )

def find_aks_no_authorized_ip_ranges(aks_clusters):
    evidence = []
    for cluster in aks_clusters:
        ip_ranges = first_value(
            cluster,
            ("apiServerAccessProfile", "authorizedIPRanges"),
            ("properties", "apiServerAccessProfile", "authorizedIPRanges"),
        ) or []
        if len(ip_ranges) == 0:
            evidence.append(compact_dict(cluster, authorizedIPRanges=[]))
    return result(
        "AKS clusters without authorized API server IP ranges",
        "Low",
        "Flags AKS clusters with no API server authorized IP ranges configured.",
        evidence,
    )

def find_aks_not_private(aks_clusters):
    evidence = []
    for cluster in aks_clusters:
        private_cluster = first_value(
            cluster,
            ("apiServerAccessProfile", "enablePrivateCluster"),
            ("properties", "apiServerAccessProfile", "enablePrivateCluster"),
        )
        if private_cluster is False:
            evidence.append(compact_dict(cluster, enablePrivateCluster=False))
    return result(
        "AKS clusters not using a private control plane",
        "Low",
        "Flags AKS clusters where private cluster mode is disabled.",
        evidence,
    )

def find_nsg_open_admin_ports(nsgs):
    admin_ports = {"22", "3389", "5985", "5986"}
    evidence = []
    for nsg in nsgs:
        for rule in first_value(nsg, ("securityRules",), ("properties", "securityRules")) or []:
            if normalize_text(rule.get("direction")) != "inbound" or normalize_text(rule.get("access")) != "allow":
                continue
            if not is_any_source(rule):
                continue
            ports = rule_port_values(rule)
            if ports_match(ports, admin_ports):
                evidence.append(
                    {
                        "nsgId": nsg.get("id"),
                        "nsgName": nsg.get("name"),
                        "ruleName": rule.get("name"),
                        "priority": rule.get("priority"),
                        "ports": ports,
                    }
                )
    return result(
        "Network security groups expose administrative ports to the Internet",
        "Medium",
        "Flags NSG inbound allow rules from any source to common administrative ports.",
        evidence,
    )

def find_nsg_open_data_ports(nsgs):
    data_ports = {"1433", "3306", "5432", "6379", "9200", "27017", "5601", "8080", "8443", "2375", "2376", "10250"}
    evidence = []
    for nsg in nsgs:
        for rule in first_value(nsg, ("securityRules",), ("properties", "securityRules")) or []:
            if normalize_text(rule.get("direction")) != "inbound" or normalize_text(rule.get("access")) != "allow":
                continue
            if not is_any_source(rule):
                continue
            ports = rule_port_values(rule)
            if ports_match(ports, data_ports):
                evidence.append(
                    {
                        "nsgId": nsg.get("id"),
                        "nsgName": nsg.get("name"),
                        "ruleName": rule.get("name"),
                        "priority": rule.get("priority"),
                        "ports": ports,
                    }
                )
    return result(
        "Network security groups expose common data ports to the Internet",
        "Medium",
        "Flags NSG inbound allow rules from any source to common database and management data ports.",
        evidence,
    )

def find_appservice_https_disabled(web_apps):
    evidence = []
    for app in web_apps:
        https_only = first_value(app, "httpsOnly", ("properties", "httpsOnly"))
        if https_only is False:
            evidence.append(compact_dict(app, httpsOnly=False))
    return result(
        "Azure App Services do not enforce HTTPS",
        "Medium",
        "Flags App Services where HTTPS-only mode is disabled.",
        evidence,
    )

def find_appservice_ftps_not_strict(web_apps):
    evidence = []
    for app in web_apps:
        ftps_state = first_value(app, "ftpsState", ("properties", "ftpsState"))
        if normalize_text(ftps_state) != "ftpsonly":
            evidence.append(compact_dict(app, ftpsState=ftps_state))
    return result(
        "Azure App Services do not enforce FTPS-only",
        "Low",
        "Flags App Services whose FTPS state is not set to FtpsOnly.",
        evidence,
    )

def find_appservice_remote_debugging_enabled(web_apps):
    evidence = []
    for app in web_apps:
        remote_debugging = first_value(app, "remoteDebuggingEnabled", ("properties", "remoteDebuggingEnabled"))
        if remote_debugging is True:
            evidence.append(compact_dict(app, remoteDebuggingEnabled=True))
    return result(
        "Azure App Services have remote debugging enabled",
        "Low",
        "Flags App Services with remote debugging enabled.",
        evidence,
    )

def find_appservice_permissive_cors(web_apps):
    evidence = []
    for app in web_apps:
        allowed_origins = first_value(
            app,
            ("cors", "allowedOrigins"),
            ("properties", "cors", "allowedOrigins"),
            ("siteConfig", "cors", "allowedOrigins"),
            ("properties", "siteConfig", "cors", "allowedOrigins"),
        ) or []
        if "*" in allowed_origins:
            evidence.append(compact_dict(app, allowedOrigins=allowed_origins))
    return result(
        "Azure App Services allow wildcard CORS origins",
        "Low",
        "Flags App Services whose CORS allowed origins contain '*'.",
        evidence,
    )

def find_appservice_access_restrictions_missing(web_app_access_restrictions):
    evidence = []
    for restriction in web_app_access_restrictions:
        ip_rules = first_value(restriction, "ipSecurityRestrictions", ("properties", "ipSecurityRestrictions")) or []
        if len(ip_rules) == 0:
            params = collection_parameters(restriction)
            evidence.append(
                {
                    "webApp": params.get("name"),
                    "resourceGroup": params.get("resourceGroup"),
                    "ipSecurityRestrictions": [],
                }
            )
    return result(
        "Azure App Services have no access restrictions configured",
        "Low",
        "Flags App Services with no main-site IP security restrictions.",
        evidence,
    )

def find_appservice_scm_restrictions_missing(web_app_access_restrictions):
    evidence = []
    for restriction in web_app_access_restrictions:
        scm_rules = first_value(restriction, "scmIpSecurityRestrictions", ("properties", "scmIpSecurityRestrictions")) or []
        if len(scm_rules) == 0:
            params = collection_parameters(restriction)
            evidence.append(
                {
                    "webApp": params.get("name"),
                    "resourceGroup": params.get("resourceGroup"),
                    "scmIpSecurityRestrictions": [],
                }
            )
    return result(
        "Azure App Services have unrestricted SCM endpoints",
        "Low",
        "Flags App Services with no SCM IP security restrictions.",
        evidence,
    )

def find_appservice_client_cert_disabled(web_apps):
    evidence = []
    for app in web_apps:
        enabled = first_value(app, "clientCertEnabled", ("properties", "clientCertEnabled"))
        if enabled is False:
            evidence.append(compact_dict(app, clientCertEnabled=False))
    return result(
        "Azure App Services do not require client certificates",
        "Low",
        "Flags App Services where client certificate enforcement is disabled.",
        evidence,
    )

def find_appservice_tls_below_12(web_app_configs):
    evidence = []
    secure_versions = {"1.2", "1.3", "tls1_2", "tls1_3"}
    for config in web_app_configs:
        tls_version = normalize_text(first_value(config, "minTlsVersion", ("properties", "minTlsVersion")))
        if tls_version not in secure_versions:
            item = resource_brief(config)
            item["minTlsVersion"] = first_value(config, "minTlsVersion", ("properties", "minTlsVersion"))
            evidence.append(item)
    return result(
        "Azure App Services permit TLS versions below 1.2",
        "Low",
        "Flags App Service configurations whose minimum TLS version is missing or below 1.2.",
        evidence,
    )

def find_appservice_ftp_not_disabled(web_apps):
    evidence = []
    for app in web_apps:
        ftps_state = normalize_text(first_value(app, "ftpsState", ("properties", "ftpsState")))
        if ftps_state != "disabled":
            evidence.append(compact_dict(app, ftpsState=first_value(app, "ftpsState", ("properties", "ftpsState"))))
    return result(
        "Azure App Services do not disable FTP deployment",
        "Low",
        "Flags App Services whose FTP/FTPS deployment state is not Disabled.",
        evidence,
    )

def find_appservice_missing_identity(web_apps):
    evidence = []
    for app in web_apps:
        identity_type = normalize_text(first_value(app, ("identity", "type"), "identity.type"))
        principal_id = first_value(app, ("identity", "principalId"))
        if not identity_type or identity_type == "none" or not principal_id:
            evidence.append(
                compact_dict(
                    app,
                    identityType=first_value(app, ("identity", "type"), "identity.type"),
                    principalId=principal_id,
                )
            )
    return result(
        "Azure App Services are not registered with a managed identity",
        "Low",
        "Flags App Services without a system-assigned or user-assigned managed identity.",
        evidence,
    )

def find_functionapp_missing_app_insights(function_apps, function_app_appsettings):
    settings_by_app = {}
    for setting in function_app_appsettings:
        key = collection_key(setting)
        if key and key != "::":
            settings_by_app.setdefault(key, []).append(setting)

    evidence = []
    for app in function_apps:
        key = record_key(app)
        settings = settings_by_app.get(key, [])
        names = {normalize_text(item.get("name")) for item in settings}
        if not names.intersection({"applicationinsights_connection_string", "appinsights_instrumentationkey"}):
            evidence.append(resource_brief(app))
    return result(
        "Function Apps are missing Application Insights configuration",
        "Low",
        "Checks Function App application settings for Application Insights connection details.",
        evidence,
    )

def find_functionapp_ftp_not_disabled(function_apps):
    evidence = []
    for app in function_apps:
        ftps_state = normalize_text(first_value(app, "ftpsState", ("properties", "ftpsState")))
        if ftps_state != "disabled":
            evidence.append(compact_dict(app, ftpsState=first_value(app, "ftpsState", ("properties", "ftpsState"))))
    return result(
        "Function Apps do not disable FTP deployment",
        "Low",
        "Flags Function Apps whose FTP/FTPS deployment state is not Disabled.",
        evidence,
    )

def find_functionapp_missing_identity(function_apps, function_app_identities):
    identities = parameterised_record_keys(function_app_identities)
    evidence = []
    for app in function_apps:
        key = record_key(app)
        identity_type = normalize_text(first_value(app, ("identity", "type")))
        if key not in identities and (not identity_type or identity_type == "none"):
            evidence.append(resource_brief(app))
    return result(
        "Function Apps do not have a managed identity configured",
        "Low",
        "Checks Function Apps for an attached managed identity.",
        evidence,
    )

def find_functionapp_publicly_accessible(function_apps, function_app_access_restrictions):
    restriction_keys = parameterised_record_keys(function_app_access_restrictions)
    evidence = []
    for app in function_apps:
        key = record_key(app)
        public_network_access = normalize_text(first_value(app, "publicNetworkAccess", ("properties", "publicNetworkAccess")))
        if public_network_access == "disabled":
            continue
        if key not in restriction_keys:
            evidence.append(compact_dict(app, publicNetworkAccess=first_value(app, "publicNetworkAccess", ("properties", "publicNetworkAccess"))))
            continue
        matching = [item for item in function_app_access_restrictions if collection_key(item) == key]
        allowed = False
        for restriction in matching:
            ip_rules = first_value(restriction, "ipSecurityRestrictions", ("properties", "ipSecurityRestrictions")) or []
            if len(ip_rules) == 0:
                allowed = True
                break
        if allowed:
            evidence.append(compact_dict(app, publicNetworkAccess=first_value(app, "publicNetworkAccess", ("properties", "publicNetworkAccess"))))
    return result(
        "Function Apps are publicly reachable",
        "Low",
        "Flags Function Apps that do not disable public access and have no IP access restrictions collected.",
        evidence,
    )

def find_functionapp_missing_vnet_integration(function_apps, function_app_vnet_integrations):
    integrated = parameterised_record_keys(function_app_vnet_integrations)
    evidence = []
    for app in function_apps:
        if record_key(app) not in integrated:
            evidence.append(resource_brief(app))
    return result(
        "Function Apps are not integrated with a virtual network",
        "Low",
        "Compares the Function App inventory with apps that returned at least one VNet integration.",
        evidence,
    )

def find_acr_public_network_enabled(container_registries):
    evidence = []
    for registry in container_registries:
        public_network = normalize_text(first_value(registry, "publicNetworkAccess", ("properties", "publicNetworkAccess")))
        if public_network in {"", "enabled"}:
            evidence.append(compact_dict(registry, publicNetworkAccess=first_value(registry, "publicNetworkAccess", ("properties", "publicNetworkAccess"))))
    return result(
        "Azure Container Registries allow public network access",
        "Low",
        "Flags Azure Container Registries whose public network access setting is enabled or unset.",
        evidence,
    )

def find_cosmosdb_unrestricted_network(cosmosdb_accounts):
    evidence = []
    for account in cosmosdb_accounts:
        public_network = normalize_text(first_value(account, "publicNetworkAccess", ("properties", "publicNetworkAccess")))
        vnet_filter = first_value(account, "isVirtualNetworkFilterEnabled", ("properties", "isVirtualNetworkFilterEnabled"))
        ip_rules = first_value(account, "ipRules", ("properties", "ipRules")) or []
        if public_network != "disabled" and not truthy(vnet_filter) and len(ip_rules) == 0:
            evidence.append(
                compact_dict(
                    account,
                    publicNetworkAccess=first_value(account, "publicNetworkAccess", ("properties", "publicNetworkAccess")),
                    isVirtualNetworkFilterEnabled=vnet_filter,
                    ipRuleCount=len(ip_rules),
                )
            )
    return result(
        "Cosmos DB accounts do not restrict network access",
        "Low",
        "Flags Cosmos DB accounts that leave public access enabled without VNet filtering or IP rules.",
        evidence,
    )

def find_cosmosdb_without_private_endpoints(cosmosdb_accounts):
    evidence = []
    for account in cosmosdb_accounts:
        connections = first_value(account, "privateEndpointConnections", ("properties", "privateEndpointConnections")) or []
        if len(connections) == 0:
            evidence.append(resource_brief(account))
    return result(
        "Cosmos DB accounts do not use private endpoints",
        "Low",
        "Uses the private endpoint connection list embedded in the Cosmos DB account payload.",
        evidence,
    )

def find_eventgrid_topics_public_network_enabled(eventgrid_topics):
    evidence = []
    for topic in eventgrid_topics:
        public_network = normalize_text(first_value(topic, "publicNetworkAccess", ("properties", "publicNetworkAccess")))
        if public_network in {"", "enabled"}:
            evidence.append(compact_dict(topic, publicNetworkAccess=first_value(topic, "publicNetworkAccess", ("properties", "publicNetworkAccess"))))
    return result(
        "Event Grid Topics allow public network access",
        "Low",
        "Flags Event Grid Topics whose public network access setting is enabled or unset.",
        evidence,
    )

def find_iot_dps_public_network_enabled(iot_dps_instances):
    evidence = []
    for dps in iot_dps_instances:
        public_network = normalize_text(first_value(dps, "publicNetworkAccess", ("properties", "publicNetworkAccess")))
        if public_network in {"", "enabled"}:
            evidence.append(compact_dict(dps, publicNetworkAccess=first_value(dps, "publicNetworkAccess", ("properties", "publicNetworkAccess"))))
    return result(
        "IoT Device Provisioning Services allow public network access",
        "Low",
        "Flags IoT DPS instances whose public network access setting is enabled or unset.",
        evidence,
    )

def find_key_vault_without_private_endpoints(key_vaults, key_vault_private_endpoints):
    connected = parameterised_record_keys(key_vault_private_endpoints)
    evidence = []
    for vault in key_vaults:
        if record_key(vault) not in connected:
            evidence.append(resource_brief(vault))
    return result(
        "Azure Key Vaults do not use private endpoints",
        "Low",
        "Compares the Key Vault inventory with the explicit private endpoint connection dataset.",
        evidence,
    )

def find_key_vault_logging_disabled(key_vaults, diagnostic_settings):
    settings_with_logs = set()
    for setting in diagnostic_settings:
        params = collection_parameters(setting)
        resource_id = params.get("id") or first_value(setting, ("properties", "scope"), ("properties", "resourceId"))
        if not resource_id:
            continue
        logs = setting.get("logs", []) or []
        if any(log.get("enabled") is True for log in logs):
            settings_with_logs.add(normalize_text(resource_id))

    evidence = []
    for vault in key_vaults:
        if normalize_text(vault.get("id")) not in settings_with_logs:
            evidence.append(resource_brief(vault))
    return result(
        "Azure Key Vaults do not have diagnostic logging enabled",
        "Low",
        "Checks whether each Key Vault has at least one enabled diagnostic log category.",
        evidence,
    )

def find_aks_azure_policy_disabled(aks_clusters):
    evidence = []
    for cluster in aks_clusters:
        enabled = first_value(cluster, ("addonProfiles", "azurepolicy", "enabled"), ("properties", "addonProfiles", "azurepolicy", "enabled"))
        if enabled is not True:
            evidence.append(compact_dict(cluster, azurePolicyEnabled=enabled))
    return result(
        "AKS clusters do not have Azure Policy enabled",
        "Low",
        "Flags AKS clusters where the Azure Policy add-on is disabled or unset.",
        evidence,
    )

def find_aks_network_policy_disabled(aks_clusters):
    evidence = []
    for cluster in aks_clusters:
        network_policy = normalize_text(first_value(cluster, "networkPolicy", ("networkProfile", "networkPolicy"), ("properties", "networkProfile", "networkPolicy")))
        if not network_policy or network_policy == "none":
            evidence.append(compact_dict(cluster, networkPolicy=first_value(cluster, "networkPolicy", ("networkProfile", "networkPolicy"), ("properties", "networkProfile", "networkPolicy"))))
    return result(
        "AKS clusters do not have a network policy configured",
        "Low",
        "Flags AKS clusters where the network policy is missing or set to None.",
        evidence,
    )

def find_aks_public_nodes_enabled(aks_clusters):
    evidence = []
    for cluster in aks_clusters:
        node_pools = first_value(cluster, "agentPoolProfiles", ("properties", "agentPoolProfiles")) or []
        if any(pool.get("enableNodePublicIP") is True for pool in node_pools if isinstance(pool, dict)):
            evidence.append(compact_dict(cluster, publicNodePools=True))
    return result(
        "AKS clusters use public node IPs",
        "Low",
        "Flags AKS clusters whose node pools enable public node IP addresses.",
        evidence,
    )

def find_monitor_service_health_alert_missing(activity_log_alerts):
    service_health_alerts = []
    for alert in activity_log_alerts:
        text = alert_text(alert)
        if "servicehealth" in text or "service health" in text:
            service_health_alerts.append(alert)
    evidence = []
    if not service_health_alerts:
        evidence.append({"eventType": "service_health", "description": "service health events"})
    return result(
        "Azure Activity Log Alerts missing for service health events",
        "Low",
        "Checks whether any collected activity log alert appears to target Azure Service Health events.",
        evidence,
    )

def find_mysql_audit_logging_disabled(mysql_servers, mysql_parameters):
    parameter_map = build_parameter_map(mysql_parameters)
    evidence = []
    for server in mysql_servers:
        value = normalize_text(parameter_value(parameter_map, server, "audit_log_enabled"))
        if value not in {"on", "enabled", "true", "yes"}:
            evidence.append(compact_dict(server, auditLogEnabled=parameter_value(parameter_map, server, "audit_log_enabled")))
    return result(
        "MySQL flexible servers do not have audit logging enabled",
        "Low",
        "Uses the MySQL flexible server parameter dataset to check audit_log_enabled.",
        evidence,
    )

def find_mysql_geo_backup_disabled(mysql_servers):
    evidence = []
    for server in mysql_servers:
        value = normalize_text(first_value(server, ("backup", "geoRedundantBackup"), ("properties", "backup", "geoRedundantBackup")))
        if value not in {"enabled", "enable", "on"}:
            evidence.append(compact_dict(server, geoRedundantBackup=first_value(server, ("backup", "geoRedundantBackup"), ("properties", "backup", "geoRedundantBackup"))))
    return result(
        "MySQL flexible servers do not enable geo-redundant backup",
        "Low",
        "Checks the geo-redundant backup setting in the MySQL flexible server payload.",
        evidence,
    )

def find_mysql_tls_below_12(mysql_servers, mysql_parameters):
    parameter_map = build_parameter_map(mysql_parameters)
    secure_versions = {"tlsv1.2", "tls 1.2", "tls1_2", "1.2", "tlsv1.3", "1.3"}
    evidence = []
    for server in mysql_servers:
        value = normalize_text(parameter_value(parameter_map, server, "tls_version", "tls_version_enforced", "minimal_tls_version"))
        if value not in secure_versions:
            evidence.append(compact_dict(server, tlsVersion=parameter_value(parameter_map, server, "tls_version", "tls_version_enforced", "minimal_tls_version")))
    return result(
        "MySQL flexible servers permit TLS versions below 1.2",
        "Low",
        "Uses the MySQL flexible server parameter dataset to check TLS enforcement settings.",
        evidence,
    )

def find_mysql_ssl_disabled(mysql_servers, mysql_parameters):
    parameter_map = build_parameter_map(mysql_parameters)
    evidence = []
    for server in mysql_servers:
        value = normalize_text(parameter_value(parameter_map, server, "require_secure_transport"))
        if value not in {"on", "enabled", "true", "yes"}:
            evidence.append(compact_dict(server, requireSecureTransport=parameter_value(parameter_map, server, "require_secure_transport")))
    return result(
        "MySQL flexible servers do not enforce SSL connections",
        "Low",
        "Uses the MySQL flexible server parameter dataset to check require_secure_transport.",
        evidence,
    )

def find_postgres_ssl_disabled(postgres_servers, postgres_parameters):
    parameter_map = build_parameter_map(postgres_parameters)
    evidence = []
    for server in postgres_servers:
        value = normalize_text(parameter_value(parameter_map, server, "require_secure_transport"))
        if value not in {"on", "enabled", "true", "yes"}:
            evidence.append(compact_dict(server, requireSecureTransport=parameter_value(parameter_map, server, "require_secure_transport")))
    return result(
        "PostgreSQL flexible servers do not enforce SSL connections",
        "Low",
        "Uses the PostgreSQL flexible server parameter dataset to check require_secure_transport.",
        evidence,
    )

def find_postgres_geo_backup_disabled(postgres_servers):
    evidence = []
    for server in postgres_servers:
        value = normalize_text(first_value(server, ("backup", "geoRedundantBackup"), ("properties", "backup", "geoRedundantBackup")))
        if value not in {"enabled", "enable", "on"}:
            evidence.append(compact_dict(server, geoRedundantBackup=first_value(server, ("backup", "geoRedundantBackup"), ("properties", "backup", "geoRedundantBackup"))))
    return result(
        "PostgreSQL flexible servers do not enable geo-redundant backup",
        "Low",
        "Checks the geo-redundant backup setting in the PostgreSQL flexible server payload.",
        evidence,
    )

def find_postgres_parameter_disabled(postgres_servers, postgres_parameters, parameter_name, title, description, evidence_field):
    parameter_map = build_parameter_map(postgres_parameters)
    evidence = []
    for server in postgres_servers:
        value = normalize_text(parameter_value(parameter_map, server, parameter_name))
        if value not in {"on", "enabled", "true", "yes"}:
            evidence.append(compact_dict(server, **{evidence_field: parameter_value(parameter_map, server, parameter_name)}))
    return result(title, "Low", description, evidence)

def find_postgres_private_dns_missing(postgres_servers):
    evidence = []
    for server in postgres_servers:
        dns_zone = first_value(server, ("network", "privateDnsZoneArmResourceId"), ("properties", "network", "privateDnsZoneArmResourceId"))
        if not dns_zone:
            evidence.append(compact_dict(server, privateDnsZoneArmResourceId=dns_zone))
    return result(
        "PostgreSQL flexible servers do not have a private DNS zone configured",
        "Low",
        "Checks the PostgreSQL flexible server network configuration for a private DNS zone resource ID.",
        evidence,
    )

def find_postgres_private_network_disabled(postgres_servers):
    evidence = []
    for server in postgres_servers:
        public_network = normalize_text(first_value(server, ("network", "publicNetworkAccess"), ("properties", "network", "publicNetworkAccess")))
        delegated_subnet = first_value(server, ("network", "delegatedSubnetResourceId"), ("properties", "network", "delegatedSubnetResourceId"))
        if public_network != "disabled" or not delegated_subnet:
            evidence.append(
                compact_dict(
                    server,
                    publicNetworkAccess=first_value(server, ("network", "publicNetworkAccess"), ("properties", "network", "publicNetworkAccess")),
                    delegatedSubnetResourceId=delegated_subnet,
                )
            )
    return result(
        "PostgreSQL flexible servers do not use private network access",
        "Low",
        "Flags PostgreSQL flexible servers that still expose public network access or lack a delegated subnet.",
        evidence,
    )

def find_redis_rdb_backup_disabled(redis_caches):
    evidence = []
    for cache in redis_caches:
        enabled = normalize_text(
            first_value(
                cache,
                ("redisConfiguration", "rdb-backup-enabled"),
                ("properties", "redisConfiguration", "rdb-backup-enabled"),
            )
        )
        if enabled not in {"true", "yes", "enabled", "1"}:
            evidence.append(compact_dict(cache, rdbBackupEnabled=first_value(cache, ("redisConfiguration", "rdb-backup-enabled"), ("properties", "redisConfiguration", "rdb-backup-enabled"))))
    return result(
        "Redis caches do not have RDB backup enabled",
        "Low",
        "Checks the Redis cache configuration for rdb-backup-enabled.",
        evidence,
    )

def find_storage_shared_key_access_enabled(storage_accounts):
    evidence = []
    for account in storage_accounts:
        allow_shared_key = first_value(account, "allowSharedKeyAccess", ("properties", "allowSharedKeyAccess"))
        if allow_shared_key is not False:
            evidence.append(compact_dict(account, allowSharedKeyAccess=allow_shared_key))
    return result(
        "Storage accounts permit shared key access",
        "Low",
        "Flags storage accounts where allowSharedKeyAccess is enabled or unset.",
        evidence,
    )

def find_storage_blob_versioning_disabled(blob_service_properties):
    evidence = []
    for blob_props in blob_service_properties:
        versioning_enabled = first_value(blob_props, "isVersioningEnabled", ("properties", "isVersioningEnabled"))
        if versioning_enabled is not True:
            params = collection_parameters(blob_props)
            evidence.append(
                {
                    "storageAccount": params.get("name"),
                    "resourceGroup": params.get("resourceGroup"),
                    "isVersioningEnabled": versioning_enabled,
                }
            )
    return result(
        "Storage accounts do not have blob versioning enabled",
        "Low",
        "Uses blob service properties to check whether blob versioning is enabled.",
        evidence,
    )

def find_storage_cross_tenant_replication_enabled(storage_accounts):
    evidence = []
    for account in storage_accounts:
        value = first_value(account, "allowCrossTenantReplication", ("properties", "allowCrossTenantReplication"))
        if value is not False:
            evidence.append(compact_dict(account, allowCrossTenantReplication=value))
    return result(
        "Storage accounts allow cross-tenant replication",
        "Low",
        "Flags storage accounts where cross-tenant replication is enabled or unset.",
        evidence,
    )

def find_storage_entra_auth_not_default(storage_accounts):
    evidence = []
    for account in storage_accounts:
        value = first_value(account, "defaultToOAuthAuthentication", ("properties", "defaultToOAuthAuthentication"))
        if value is not True:
            evidence.append(compact_dict(account, defaultToOAuthAuthentication=value))
    return result(
        "Storage accounts do not default to Microsoft Entra authorization",
        "Low",
        "Checks the defaultToOAuthAuthentication setting on storage accounts.",
        evidence,
    )

def find_storage_azure_services_bypass_disabled(storage_accounts):
    evidence = []
    for account in storage_accounts:
        bypass = first_value(account, ("networkAcls", "bypass"), ("properties", "networkAcls", "bypass"))
        bypass_values = {normalize_text(item) for item in (bypass if isinstance(bypass, list) else str(bypass).split(","))}
        if "azureservices" not in bypass_values:
            evidence.append(compact_dict(account, bypass=bypass))
    return result(
        "Storage accounts do not trust Azure services network bypass",
        "Low",
        "Checks the storage account network ACL bypass list for AzureServices.",
        evidence,
    )

def find_storage_geo_replication_disabled(storage_accounts):
    geo_skus = {"standard_grs", "standard_ragrs", "standard_gzrs", "standard_ragzrs", "premium_grs"}
    evidence = []
    for account in storage_accounts:
        sku_name = normalize_text(first_value(account, ("sku", "name"), "skuName"))
        if sku_name not in geo_skus:
            evidence.append(compact_dict(account, skuName=first_value(account, ("sku", "name"), "skuName")))
    return result(
        "Storage accounts do not use geo-redundant replication",
        "Low",
        "Checks the storage account SKU for a geo-redundant replication tier.",
        evidence,
    )

def find_synapse_exfiltration_protection_disabled(synapse_workspaces):
    evidence = []
    for workspace in synapse_workspaces:
        enabled = first_value(workspace, "dataExfiltrationProtection", ("properties", "dataExfiltrationProtection"))
        if normalize_text(enabled) not in {"true", "enabled", "yes"}:
            evidence.append(compact_dict(workspace, dataExfiltrationProtection=enabled))
    return result(
        "Synapse workspaces do not enable data exfiltration protection",
        "Low",
        "Checks the Synapse workspace data exfiltration protection setting.",
        evidence,
    )

def find_synapse_managed_vnet_disabled(synapse_workspaces):
    evidence = []
    for workspace in synapse_workspaces:
        managed_vnet = first_value(workspace, "managedVirtualNetwork", ("properties", "managedVirtualNetwork"))
        if not managed_vnet or normalize_text(managed_vnet) in {"none", ""}:
            evidence.append(compact_dict(workspace, managedVirtualNetwork=managed_vnet))
    return result(
        "Synapse workspaces do not use a managed virtual network",
        "Low",
        "Checks the Synapse workspace managedVirtualNetwork setting.",
        evidence,
    )

def find_bastion_host_absent(bastion_hosts, subscriptions):
    evidence = []
    if len(bastion_hosts) == 0:
        if subscriptions:
            for subscription in subscriptions:
                evidence.append({"subscriptionId": subscription.get("id"), "subscriptionName": subscription.get("name")})
        else:
            evidence.append({"scope": "subscription"})
    return result(
        "Azure Bastion hosts are not deployed",
        "Low",
        "Reports the collected subscription scope when no Bastion host resources were found.",
        evidence,
    )

def find_flow_logs_not_captured(flow_logs):
    evidence = []
    for log in flow_logs:
        enabled = first_value(log, "enabled", ("properties", "enabled"))
        storage_id = first_value(log, "storageId", ("properties", "storageId"))
        if enabled is not True or not storage_id:
            evidence.append(
                {
                    "name": log.get("name"),
                    "id": log.get("id"),
                    "location": log.get("location"),
                    "enabled": enabled,
                    "storageId": storage_id,
                }
            )
    return result(
        "Network Watcher flow logs are not captured to storage",
        "Low",
        "Checks flow log resources for an enabled state and a configured storage account destination.",
        evidence,
    )

def find_flow_logs_retention_short(flow_logs):
    evidence = []
    for log in flow_logs:
        days = first_value(log, ("retentionPolicy", "days"), ("properties", "retentionPolicy", "days"))
        enabled = first_value(log, ("retentionPolicy", "enabled"), ("properties", "retentionPolicy", "enabled"))
        if enabled is not True or not isinstance(days, int) or days <= 90:
            evidence.append(
                {
                    "name": log.get("name"),
                    "id": log.get("id"),
                    "location": log.get("location"),
                    "retentionEnabled": enabled,
                    "retentionDays": days,
                }
            )
    return result(
        "Network Watcher flow logs do not retain data for more than 90 days",
        "Low",
        "Checks flow log retention policy settings.",
        evidence,
    )

def find_vm_linux_password_auth_enabled(vm_details):
    evidence = []
    for vm in vm_details:
        linux_config = first_value(vm, ("osProfile", "linuxConfiguration"), ("properties", "osProfile", "linuxConfiguration")) or {}
        if not isinstance(linux_config, dict):
            continue
        disabled_password_auth = linux_config.get("disablePasswordAuthentication")
        if disabled_password_auth is not True:
            evidence.append(compact_dict(vm, disablePasswordAuthentication=disabled_password_auth))
    return result(
        "Linux virtual machines allow password-based SSH authentication",
        "Low",
        "Checks VM OS profile settings for disablePasswordAuthentication.",
        evidence,
    )

def find_vmss_without_load_balancer(vm_scale_sets):
    evidence = []
    for vmss in vm_scale_sets:
        nic_configs = first_value(
            vmss,
            ("virtualMachineProfile", "networkProfile", "networkInterfaceConfigurations"),
            ("properties", "virtualMachineProfile", "networkProfile", "networkInterfaceConfigurations"),
        ) or []
        pools = []
        for nic in nic_configs:
            for ip_config in nic.get("ipConfigurations", []) or []:
                pools.extend(ip_config.get("loadBalancerBackendAddressPools", []) or [])
        if len(pools) == 0:
            evidence.append(resource_brief(vmss))
    return result(
        "Virtual machine scale sets are not associated with a load balancer",
        "Low",
        "Checks VM scale set NIC configuration for load balancer backend pool references.",
        evidence,
    )

def find_appservice_auth_not_configured(web_app_auth_settings):
    evidence = []
    for auth in web_app_auth_settings:
        enabled = first_value(auth, "enabled", ("properties", "enabled"))
        if enabled is not True:
            params = collection_parameters(auth)
            evidence.append({"webApp": params.get("name"), "resourceGroup": params.get("resourceGroup"), "enabled": enabled})
    return result(
        "Azure App Services do not have authentication configured",
        "Low",
        "Uses Web App auth settings to flag apps where built-in authentication is disabled or unset.",
        evidence,
    )

def find_webapp_missing_app_insights(web_apps, web_app_appsettings):
    settings_by_app = {}
    for setting in web_app_appsettings:
        key = collection_key(setting)
        if key and key != "::":
            settings_by_app.setdefault(key, []).append(setting)

    evidence = []
    for app in web_apps:
        names = {normalize_text(item.get("name")) for item in settings_by_app.get(record_key(app), [])}
        if not names.intersection({"applicationinsights_connection_string", "appinsights_instrumentationkey"}):
            evidence.append(resource_brief(app))
    return result(
        "Azure App Services are missing Application Insights configuration",
        "Low",
        "Checks Web App application settings for Application Insights connection details.",
        evidence,
    )

def find_functionapp_missing_access_keys(function_apps, function_app_keys):
    keys_by_app = {}
    for item in function_app_keys:
        key = collection_key(item)
        if key and key != "::":
            keys_by_app[key] = item

    evidence = []
    for app in function_apps:
        payload = keys_by_app.get(record_key(app))
        function_keys = first_value(payload or {}, "functionKeys", ("functionKeys",))
        master_key = first_value(payload or {}, "masterKey", ("masterKey",))
        system_keys = first_value(payload or {}, "systemKeys", ("systemKeys",))
        if not function_keys and not master_key and not system_keys:
            evidence.append(resource_brief(app))
    return result(
        "Function Apps do not have access keys configured",
        "Low",
        "Checks Function App host keys output for master, function, or system keys.",
        evidence,
    )

def find_cognitive_services_local_auth_enabled(accounts):
    evidence = []
    for account in accounts:
        disable_local_auth = first_value(account, "disableLocalAuth", ("properties", "disableLocalAuth"))
        if disable_local_auth is not True:
            evidence.append(compact_dict(account, disableLocalAuth=disable_local_auth))
    return result(
        "Cognitive Services accounts permit local authentication",
        "Low",
        "Checks Cognitive Services accounts for the disableLocalAuth setting.",
        evidence,
    )

def find_acr_without_private_link(container_registries, private_endpoint_connections):
    connected = parameterised_record_keys(private_endpoint_connections)
    evidence = []
    for registry in container_registries:
        if record_key(registry) not in connected:
            evidence.append(resource_brief(registry))
    return result(
        "Azure Container Registries do not use private link",
        "Low",
        "Compares the registry inventory with collected private endpoint connection records.",
        evidence,
    )

def find_cosmosdb_without_aad_rbac(cosmosdb_accounts, role_assignments):
    assignments_by_account = {}
    for item in role_assignments:
        key = collection_key(item)
        if key and key != "::":
            assignments_by_account.setdefault(key, []).append(item)

    evidence = []
    for account in cosmosdb_accounts:
        disable_local_auth = first_value(account, "disableLocalAuth", ("properties", "disableLocalAuth"))
        if disable_local_auth is True and assignments_by_account.get(record_key(account)):
            continue
        evidence.append(
            compact_dict(
                account,
                disableLocalAuth=disable_local_auth,
                sqlRoleAssignmentCount=len(assignments_by_account.get(record_key(account), [])),
            )
        )
    return result(
        "Cosmos DB accounts do not use Microsoft Entra ID and RBAC",
        "Low",
        "Flags Cosmos DB accounts that do not both disable local auth and expose SQL RBAC role assignments.",
        evidence,
    )

def find_databricks_without_cmk(workspaces):
    evidence = []
    for workspace in workspaces:
        cmk = first_value(
            workspace,
            ("parameters", "prepareEncryption", "value"),
            ("properties", "parameters", "prepareEncryption", "value"),
            ("parameters", "encryption", "value"),
            ("properties", "parameters", "encryption", "value"),
        )
        if cmk is not True:
            evidence.append(compact_dict(workspace, cmkPrepared=cmk))
    return result(
        "Databricks workspaces do not enable customer-managed key encryption",
        "Low",
        "Checks Databricks workspace detail parameters for CMK-related settings.",
        evidence,
    )

def find_databricks_without_vnet_injection(workspaces):
    evidence = []
    for workspace in workspaces:
        vnet_id = first_value(
            workspace,
            ("parameters", "customVirtualNetworkId", "value"),
            ("properties", "parameters", "customVirtualNetworkId", "value"),
        )
        if not vnet_id:
            evidence.append(compact_dict(workspace, customVirtualNetworkId=vnet_id))
    return result(
        "Databricks workspaces do not use VNet injection",
        "Low",
        "Checks Databricks workspace detail parameters for a custom virtual network ID.",
        evidence,
    )

def find_defender_auto_provisioning_disabled(settings):
    evidence = []
    for setting in settings:
        state = normalize_text(first_value(setting, "autoProvision", ("properties", "autoProvision")))
        if state not in {"on", "enabled"}:
            evidence.append({"name": setting.get("name"), "id": setting.get("id"), "autoProvision": first_value(setting, "autoProvision", ("properties", "autoProvision"))})
    return result(
        "Defender auto provisioning for Log Analytics agents is not enabled",
        "Low",
        "Checks Defender auto-provisioning settings for an enabled state.",
        evidence,
    )

def find_security_contacts_not_notifying_owners(security_contacts):
    evidence = []
    for contact in security_contacts:
        enabled = first_value(
            contact,
            ("alertNotifications", "state"),
            ("properties", "alertNotifications", "state"),
            ("notificationsByRole", "state"),
            ("properties", "notificationsByRole", "state"),
        )
        if normalize_text(enabled) not in {"on", "enabled"}:
            evidence.append({"name": contact.get("name"), "id": contact.get("id"), "notificationsByRole": enabled})
    return result(
        "Microsoft Defender security contacts do not notify subscription owners",
        "Low",
        "Checks Defender security contact notification settings for owner-role notifications.",
        evidence,
    )

def find_entra_security_defaults_disabled(policy_records):
    evidence = []
    for policy in policy_records:
        enabled = first_value(policy, "isEnabled", ("isEnabled",))
        if enabled is not True:
            evidence.append({"id": policy.get("id"), "displayName": policy.get("displayName"), "isEnabled": enabled})
    return result(
        "Microsoft Entra security defaults are not enabled",
        "Low",
        "Checks the Graph security defaults enforcement policy.",
        evidence,
    )

def find_entra_named_locations_missing(named_locations):
    evidence = []
    if len(named_locations) == 0:
        evidence.append({"scope": "tenant"})
    return result(
        "Microsoft Entra trusted named locations are not configured",
        "Low",
        "Checks whether any Graph named location records were returned.",
        evidence,
    )

def find_entra_users_can_create_apps(auth_policy_records):
    evidence = []
    for policy in auth_policy_records:
        allowed = first_value(policy, ("defaultUserRolePermissions", "allowedToCreateApps"))
        if allowed is not False:
            evidence.append({"id": policy.get("id"), "allowedToCreateApps": allowed})
    return result(
        "Microsoft Entra default users can create applications",
        "Low",
        "Checks the authorization policy default user permissions for app creation.",
        evidence,
    )

def find_entra_users_can_create_tenants(auth_policy_records):
    evidence = []
    for policy in auth_policy_records:
        allowed = first_value(policy, ("defaultUserRolePermissions", "allowedToCreateTenants"))
        if allowed is not False:
            evidence.append({"id": policy.get("id"), "allowedToCreateTenants": allowed})
    return result(
        "Microsoft Entra default users can create tenants",
        "Low",
        "Checks the authorization policy default user permissions for tenant creation.",
        evidence,
    )

def find_entra_guest_invites_not_admin_only(auth_policy_records):
    evidence = []
    for policy in auth_policy_records:
        value = normalize_text(first_value(policy, "allowInvitesFrom", ("allowInvitesFrom",)))
        if value not in {"adminsandguestinviters", "admins"}:
            evidence.append({"id": policy.get("id"), "allowInvitesFrom": first_value(policy, "allowInvitesFrom", ("allowInvitesFrom",))})
    return result(
        "Microsoft Entra guest invites are not restricted to admins",
        "Low",
        "Checks the authorization policy allowInvitesFrom setting.",
        evidence,
    )

def find_entra_guest_access_not_restricted(auth_policy_records):
    evidence = []
    for policy in auth_policy_records:
        value = normalize_text(first_value(policy, "guestUserRoleId", ("guestUserRoleId",)))
        if not value:
            evidence.append({"id": policy.get("id"), "guestUserRoleId": value})
    return result(
        "Microsoft Entra guest user access restrictions are not configured",
        "Low",
        "Checks the authorization policy for a guest user role restriction.",
        evidence,
    )

def find_eventgrid_domains_public_network_enabled(domains):
    evidence = []
    for domain in domains:
        public_network = normalize_text(first_value(domain, "publicNetworkAccess", ("properties", "publicNetworkAccess")))
        if public_network in {"", "enabled"}:
            evidence.append(compact_dict(domain, publicNetworkAccess=first_value(domain, "publicNetworkAccess", ("properties", "publicNetworkAccess"))))
    return result(
        "Event Grid Domains allow public network access",
        "Low",
        "Flags Event Grid Domains whose public network access setting is enabled or unset.",
        evidence,
    )

def find_ml_workspace_public_network_enabled(workspaces):
    evidence = []
    for workspace in workspaces:
        public_network = normalize_text(first_value(workspace, "publicNetworkAccess", ("properties", "publicNetworkAccess")))
        if public_network in {"", "enabled"}:
            evidence.append(compact_dict(workspace, publicNetworkAccess=first_value(workspace, "publicNetworkAccess", ("properties", "publicNetworkAccess"))))
    return result(
        "Machine Learning workspaces allow public network access",
        "Low",
        "Flags ML workspaces whose public network access setting is enabled or unset.",
        evidence,
    )

def find_ml_workspace_without_vnet(workspaces):
    evidence = []
    for workspace in workspaces:
        pe = first_value(workspace, "privateEndpointConnections", ("properties", "privateEndpointConnections")) or []
        if len(pe) == 0:
            evidence.append(resource_brief(workspace))
    return result(
        "Machine Learning workspaces do not use virtual network integration",
        "Low",
        "Uses ML workspace private endpoint connections as the current network isolation signal.",
        evidence,
    )

def find_activity_log_alert_security_solution_gaps(activity_log_alerts):
    patterns = [
        "microsoft.security/securitysolutions/write",
        "microsoft.security/securitysolutions/delete",
    ]
    text_hit = any(any(pattern in alert_text(alert) for pattern in patterns) for alert in activity_log_alerts)
    evidence = [] if text_hit else [{"eventType": "security_solution_changes", "description": "security solution create/delete events"}]
    return result(
        "Azure Activity Log Alerts missing for security solution changes",
        "Low",
        "Checks collected activity log alert rules for security solution create/delete coverage.",
        evidence,
    )

def find_monitor_storage_targets_not_cmk(subscriptions, subscription_diagnostic_settings, storage_accounts):
    accounts = {normalize_text(account.get("id")): account for account in storage_accounts}
    evidence = []
    for setting in subscription_diagnostic_settings:
        storage_id = normalize_text(first_value(setting, "storageAccountId", ("properties", "storageAccountId")))
        if not storage_id:
            continue
        account = accounts.get(storage_id)
        if not account:
            continue
        key_source = normalize_text(first_value(account, ("encryption", "keySource"), ("properties", "encryption", "keySource")))
        if key_source == "microsoft.storage":
            evidence.append({"subscriptionId": collection_parameters(setting).get("id"), "storageAccountId": account.get("id"), "keySource": key_source})
    return result(
        "Subscription activity logs are stored in accounts without customer-managed keys",
        "Low",
        "Cross-references subscription diagnostic settings with storage account encryption key source.",
        evidence,
    )

def find_monitor_storage_targets_not_private(subscription_diagnostic_settings, storage_accounts):
    accounts = {normalize_text(account.get("id")): account for account in storage_accounts}
    evidence = []
    for setting in subscription_diagnostic_settings:
        storage_id = normalize_text(first_value(setting, "storageAccountId", ("properties", "storageAccountId")))
        if not storage_id:
            continue
        account = accounts.get(storage_id)
        if not account:
            continue
        connections = first_value(account, "privateEndpointConnections", ("properties", "privateEndpointConnections")) or []
        if len(connections) == 0:
            evidence.append({"subscriptionId": collection_parameters(setting).get("id"), "storageAccountId": account.get("id")})
    return result(
        "Subscription activity logs are stored in accounts without private endpoints",
        "Low",
        "Cross-references subscription diagnostic settings with storage account private endpoint usage.",
        evidence,
    )

def find_search_public_network_enabled(search_services):
    evidence = []
    for service in search_services:
        public_network = normalize_text(first_value(service, "publicNetworkAccess", ("properties", "publicNetworkAccess")))
        if public_network in {"", "enabled"}:
            evidence.append(compact_dict(service, publicNetworkAccess=first_value(service, "publicNetworkAccess", ("properties", "publicNetworkAccess"))))
    return result(
        "Azure AI Search services allow public network access",
        "Low",
        "Flags Search services whose public network access setting is enabled or unset.",
        evidence,
    )

def find_search_without_shared_private_links(search_services, shared_private_links):
    linked = parameterised_record_keys(shared_private_links)
    evidence = []
    for service in search_services:
        if record_key(service) not in linked:
            evidence.append(resource_brief(service))
    return result(
        "Azure AI Search services do not use shared private links",
        "Low",
        "Compares Search services with the shared private link resource dataset.",
        evidence,
    )

def find_signalr_public_network_enabled(signalr_services):
    evidence = []
    for service in signalr_services:
        public_network = normalize_text(first_value(service, "publicNetworkAccess", ("properties", "publicNetworkAccess")))
        if public_network in {"", "enabled"}:
            evidence.append(compact_dict(service, publicNetworkAccess=first_value(service, "publicNetworkAccess", ("properties", "publicNetworkAccess"))))
    return result(
        "SignalR services allow public network access",
        "Low",
        "Flags SignalR services whose public network access setting is enabled or unset.",
        evidence,
    )

def find_sqlserver_atp_disabled(threat_policies):
    evidence = []
    for policy in threat_policies:
        state = normalize_text(first_value(policy, "state", ("properties", "state")))
        if state not in {"enabled", "on"}:
            params = collection_parameters(policy)
            evidence.append({"server": params.get("name"), "resourceGroup": params.get("resourceGroup"), "state": first_value(policy, "state", ("properties", "state"))})
    return result(
        "SQL servers do not have Advanced Threat Protection enabled",
        "Low",
        "Checks SQL server threat policy state.",
        evidence,
    )

def find_sqlserver_auditing_disabled(audit_policies):
    evidence = []
    for policy in audit_policies:
        state = normalize_text(first_value(policy, "state", ("properties", "state")))
        if state not in {"enabled", "on"}:
            params = collection_parameters(policy)
            evidence.append({"server": params.get("name"), "resourceGroup": params.get("resourceGroup"), "state": first_value(policy, "state", ("properties", "state"))})
    return result(
        "SQL servers do not have auditing enabled",
        "Low",
        "Checks SQL server auditing policy state.",
        evidence,
    )

def find_sqlserver_audit_retention_short(audit_policies):
    evidence = []
    for policy in audit_policies:
        days = first_value(policy, "retentionDays", ("properties", "retentionDays"))
        if not isinstance(days, int) or days < 90:
            params = collection_parameters(policy)
            evidence.append({"server": params.get("name"), "resourceGroup": params.get("resourceGroup"), "retentionDays": days})
    return result(
        "SQL servers do not retain audit logs for at least 90 days",
        "Low",
        "Checks SQL server auditing policy retention days.",
        evidence,
    )

def find_sqlserver_no_aad_admin(ad_admins, sql_servers):
    admin_keys = parameterised_record_keys(ad_admins)
    evidence = []
    for server in sql_servers:
        if record_key(server) not in admin_keys:
            evidence.append(resource_brief(server))
    return result(
        "SQL servers do not have an Azure AD administrator configured",
        "Low",
        "Compares SQL server inventory with collected Azure AD admin records.",
        evidence,
    )

def find_sqlserver_tde_not_cmk(tde_keys):
    evidence = []
    for key in tde_keys:
        server_key_type = normalize_text(first_value(key, "serverKeyType", ("properties", "serverKeyType")))
        if server_key_type != "azurekeyvault":
            params = collection_parameters(key)
            evidence.append({"server": params.get("name"), "resourceGroup": params.get("resourceGroup"), "serverKeyType": first_value(key, "serverKeyType", ("properties", "serverKeyType"))})
    return result(
        "SQL servers do not encrypt TDE with customer-managed keys",
        "Low",
        "Checks SQL server TDE protector settings for Azure Key Vault usage.",
        evidence,
    )

def find_sql_database_tde_disabled(database_tde):
    evidence = []
    for item in database_tde:
        state = normalize_text(first_value(item, "state", ("properties", "state")))
        if state not in {"enabled", "on"}:
            params = collection_parameters(item)
            evidence.append({"database": params.get("name"), "server": params.get("serverName"), "resourceGroup": params.get("resourceGroup"), "state": first_value(item, "state", ("properties", "state"))})
    return result(
        "SQL databases do not have Transparent Data Encryption enabled",
        "Low",
        "Checks SQL database TDE state.",
        evidence,
    )

def find_sqlserver_unrestricted_inbound_access(sql_firewall_rules):
    evidence = []
    for rule in sql_firewall_rules:
        start_ip = normalize_text(rule.get("startIpAddress"))
        end_ip = normalize_text(rule.get("endIpAddress"))
        if start_ip == "0.0.0.0" and end_ip == "0.0.0.0":
            continue
        if start_ip == "0.0.0.0" and end_ip == "255.255.255.255":
            params = collection_parameters(rule)
            evidence.append({"server": params.get("name"), "resourceGroup": params.get("resourceGroup"), "ruleName": rule.get("name"), "startIpAddress": rule.get("startIpAddress"), "endIpAddress": rule.get("endIpAddress")})
    return result(
        "SQL servers permit unrestricted inbound access",
        "Low",
        "Flags SQL server firewall rules that allow the full IPv4 address space.",
        evidence,
    )

def find_sqlserver_va_disabled(vuln_assessments):
    evidence = []
    for item in vuln_assessments:
        recurring = first_value(item, ("recurringScans", "isEnabled"), ("properties", "recurringScans", "isEnabled"))
        storage = first_value(item, "storageContainerPath", ("properties", "storageContainerPath"))
        params = collection_parameters(item)
        if recurring is not True or not storage:
            evidence.append({"server": params.get("name"), "resourceGroup": params.get("resourceGroup"), "recurringScansEnabled": recurring, "storageContainerPath": storage})
    return result(
        "SQL servers do not have vulnerability assessment configured",
        "Low",
        "Checks SQL server vulnerability assessment settings for recurring scans and report storage.",
        evidence,
    )

def find_storage_file_soft_delete_disabled(file_service_properties):
    evidence = []
    for props in file_service_properties:
        retention = first_value(props, ("shareDeleteRetentionPolicy", "enabled"), ("properties", "shareDeleteRetentionPolicy", "enabled"))
        if retention is not True:
            params = collection_parameters(props)
            evidence.append({"storageAccount": params.get("name"), "resourceGroup": params.get("resourceGroup"), "shareDeleteRetentionPolicyEnabled": retention})
    return result(
        "Storage accounts do not enable file share soft delete",
        "Low",
        "Checks file service properties for share delete retention policy.",
        evidence,
    )

def find_storage_keys_not_rotated(storage_accounts, storage_keys):
    keys_by_account = {}
    for item in storage_keys:
        key = collection_key(item)
        if key and key != "::":
            keys_by_account.setdefault(key, []).append(item)
    evidence = []
    for account in storage_accounts:
        stale = []
        for key in keys_by_account.get(record_key(account), []):
            created_at = parse_iso_datetime(key.get("creationTime"))
            if not created_at:
                stale.append({"keyName": key.get("keyName"), "creationTime": key.get("creationTime"), "ageDays": None})
                continue
            age_days = (datetime.now(timezone.utc) - created_at.astimezone(timezone.utc)).days
            if age_days > 90:
                stale.append({"keyName": key.get("keyName"), "creationTime": key.get("creationTime"), "ageDays": age_days})
        if stale:
            evidence.append(compact_dict(account, keys=stale))
    return result(
        "Storage Account Access Keys Not Rotated",
        "Low",
        "Flags storage account access keys older than 90 days using the collected creationTime value.",
        evidence,
    )

def find_vm_backup_disabled(vm_details, backup_items):
    protected_ids = set()
    for item in backup_items:
        source_id = normalize_text(
            first_value(item, ("properties", "sourceResourceId"), ("sourceResourceId",), ("properties", "virtualMachineId"))
        )
        if source_id:
            protected_ids.add(source_id)
    evidence = []
    for vm in vm_details:
        if normalize_text(vm.get("id")) not in protected_ids:
            evidence.append(resource_brief(vm))
    return result(
        "Virtual machines are not protected by backup",
        "Low",
        "Compares VM inventory with backup item source resource IDs.",
        evidence,
    )

def find_vm_jit_disabled(vm_details, jit_policies):
    protected_ids = set()
    for policy in jit_policies:
        for vm in first_value(policy, "virtualMachines", ("properties", "virtualMachines")) or []:
            resource_id = normalize_text(first_value(vm, "id", ("id",)))
            if resource_id:
                protected_ids.add(resource_id)
    evidence = []
    for vm in vm_details:
        if normalize_text(vm.get("id")) not in protected_ids:
            evidence.append(resource_brief(vm))
    return result(
        "Virtual machines do not have JIT access enabled",
        "Low",
        "Compares VM inventory with Defender JIT policy protected virtual machines.",
        evidence,
    )

def find_vm_attached_disks_not_cmk(vm_details, managed_disks):
    disks_by_id = {normalize_text(disk.get("id")): disk for disk in managed_disks}
    evidence = []
    for vm in vm_details:
        os_disk = first_value(vm, ("storageProfile", "osDisk"), ("properties", "storageProfile", "osDisk")) or {}
        os_disk_ref = os_disk.get("managedDisk", {}).get("id")
        if os_disk_ref:
            disk = disks_by_id.get(normalize_text(os_disk_ref))
            if disk:
                key_source = normalize_text(first_value(disk, ("encryption", "type"), ("properties", "encryption", "type")))
                if "customer" not in key_source:
                    evidence.append(
                        {
                            "vmId": vm.get("id"),
                            "vmName": vm.get("name"),
                            "diskId": disk.get("id"),
                            "diskName": disk.get("name"),
                            "diskRole": "os",
                            "encryptionType": first_value(disk, ("encryption", "type"), ("properties", "encryption", "type")),
                        }
                    )
        for disk_ref in first_value(vm, ("storageProfile", "dataDisks"), ("properties", "storageProfile", "dataDisks")) or []:
            disk = disks_by_id.get(normalize_text(disk_ref.get("managedDisk", {}).get("id")))
            if not disk:
                continue
            key_source = normalize_text(first_value(disk, ("encryption", "type"), ("properties", "encryption", "type")))
            if "customer" not in key_source:
                evidence.append({"vmId": vm.get("id"), "vmName": vm.get("name"), "diskId": disk.get("id"), "diskName": disk.get("name"), "diskRole": "data", "encryptionType": first_value(disk, ("encryption", "type"), ("properties", "encryption", "type"))})
    return result(
        "VM OS and Data Disks Not Encrypted with Customer Managed Keys",
        "Low",
        "Checks OS and attached managed disks for a customer-managed encryption type.",
        evidence,
    )

def find_unattached_disks_not_cmk(managed_disks):
    evidence = []
    for disk in managed_disks:
        managed_by = first_value(disk, "managedBy", ("properties", "managedBy"))
        if managed_by:
            continue
        key_source = normalize_text(first_value(disk, ("encryption", "type"), ("properties", "encryption", "type")))
        if "customer" not in key_source:
            evidence.append(compact_dict(disk, managedBy=managed_by, encryptionType=first_value(disk, ("encryption", "type"), ("properties", "encryption", "type"))))
    return result(
        "Unattached managed disks are not encrypted with customer-managed keys",
        "Low",
        "Checks unattached managed disks for a customer-managed encryption type.",
        evidence,
    )

def find_guest_users_present(ad_users, registration_details):
    registrations = {}
    for item in registration_details:
        registrations[normalize_text(item.get("userPrincipalName"))] = item

    evidence = []
    for user in ad_users:
        if normalize_text(user.get("userType")) != "guest":
            continue
        upn = normalize_text(user.get("userPrincipalName"))
        registration = registrations.get(upn, {})
        is_mfa_capable = first_value(registration, "isMfaCapable", ("isMfaCapable",))
        if registration and is_mfa_capable is True:
            continue
        evidence.append(
            {
                "id": user.get("id"),
                "name": user.get("displayName"),
                "userPrincipalName": user.get("userPrincipalName"),
                "userType": user.get("userType"),
                "accountEnabled": user.get("accountEnabled"),
                "isMfaCapable": is_mfa_capable,
            }
        )
    return result(
        "Unauthenticated Guest Users Present in Azure AD",
        "Medium",
        "Flags guest users lacking positive MFA capability evidence in the collected Microsoft Graph registration details.",
        evidence,
    )

def find_appservice_outdated_runtime(web_app_configs, stack_name, minimum_version, title):
    evidence = []
    for config in web_app_configs:
        version_value = app_stack_value(config, stack_name)
        if not version_value:
            continue
        if version_is_older(version_value, minimum_version):
            evidence.append(compact_dict(config, stack=stack_name, runtimeVersion=version_value))
    return result(
        title,
        "Low",
        f"Flags App Services whose detected {stack_name} runtime is older than the built-in minimum baseline {minimum_version[0]}.{minimum_version[1]}.",
        evidence,
    )

def find_appservice_outdated_programming_language(web_app_configs):
    checks = [
        ("dotnet", (8, 0)),
        ("java", (17, 0)),
        ("php", (8, 1)),
        ("python", (3, 10)),
    ]
    evidence = []
    for config in web_app_configs:
        for stack_name, minimum in checks:
            version_value = app_stack_value(config, stack_name)
            if version_value and version_is_older(version_value, minimum):
                evidence.append(compact_dict(config, stack=stack_name, runtimeVersion=version_value))
                break
    return result(
        "App Service Running Outdated Programming Language Version",
        "Low",
        "Flags App Services whose detected language runtime is older than the built-in minimum baselines used by azure-findings.",
        evidence,
    )

def find_keyvault_public_network_enabled(key_vaults):
    evidence = []
    for vault in key_vaults:
        public_network = normalize_text(first_value(vault, "publicNetworkAccess", ("properties", "publicNetworkAccess")))
        if public_network in {"", "enabled"}:
            evidence.append(compact_dict(vault, publicNetworkAccess=first_value(vault, "publicNetworkAccess", ("properties", "publicNetworkAccess"))))
    return result(
        "Key Vault Allows Public Network Access",
        "Low",
        "Flags Key Vaults whose public network access setting is enabled or unset.",
        evidence,
    )

def find_keyvault_recovery_protection_disabled(key_vaults):
    evidence = []
    for vault in key_vaults:
        enabled = first_value(vault, "enablePurgeProtection", ("properties", "enablePurgeProtection"))
        if enabled is not True:
            evidence.append(compact_dict(vault, enablePurgeProtection=enabled))
    return result(
        "Key Vault Recovery Protection Not Enabled",
        "Low",
        "Flags Key Vaults without purge protection enabled.",
        evidence,
    )

def find_resource_diagnostic_settings_missing(resources, diagnostic_settings):
    configured = set()
    for setting in diagnostic_settings:
        resource_id = normalize_text(collection_parameters(setting).get("id"))
        if resource_id:
            configured.add(resource_id)

    evidence = []
    for resource in resources:
        resource_id = normalize_text(resource.get("id"))
        if resource_id and resource_id not in configured:
            evidence.append(resource_brief(resource))
    return result(
        "Diagnostic Settings Not Configured",
        "Low",
        "Flags collected Azure resources for which azure-collect found no resource-scoped diagnostic setting.",
        evidence,
    )

def find_activity_log_profile_incomplete(log_profiles):
    evidence = []
    required_categories = {"write", "delete", "action"}
    for profile in log_profiles:
        categories = {normalize_text(item) for item in first_value(profile, "categories", ("properties", "categories")) or []}
        locations = {normalize_text(item) for item in first_value(profile, "locations", ("properties", "locations")) or []}
        if not required_categories.issubset(categories) or "global" not in locations:
            evidence.append(
                {
                    "id": profile.get("id"),
                    "name": profile.get("name"),
                    "categories": sorted(categories),
                    "locations": sorted(locations),
                }
            )
    if not log_profiles:
        evidence.append({"scope": "subscription", "reason": "no_log_profiles_collected"})
    return result(
        "Activity Log Profile Does Not Capture All Events",
        "Low",
        "Checks Azure Monitor log profiles for write, delete, action categories and the global location.",
        evidence,
    )

def find_nsg_open_all_ports(nsgs):
    evidence = []
    for nsg in nsgs:
        for rule in first_value(nsg, ("securityRules",), ("properties", "securityRules")) or []:
            if normalize_text(rule.get("direction")) != "inbound" or normalize_text(rule.get("access")) != "allow":
                continue
            if not is_any_source(rule):
                continue
            ports = rule_port_values(rule)
            if "*" in ports:
                evidence.append({"nsgId": nsg.get("id"), "nsgName": nsg.get("name"), "ruleName": rule.get("name"), "priority": rule.get("priority"), "ports": ports})
    return result(
        "NSG Inbound Rule Allows Internet Access to All Ports",
        "High",
        "Flags NSG inbound allow rules from any source that expose all destination ports.",
        evidence,
    )

def find_nsg_open_mssql(nsgs):
    evidence = []
    for nsg in nsgs:
        for rule in first_value(nsg, ("securityRules",), ("properties", "securityRules")) or []:
            if normalize_text(rule.get("direction")) != "inbound" or normalize_text(rule.get("access")) != "allow":
                continue
            if not is_any_source(rule):
                continue
            ports = rule_port_values(rule)
            if ports_match(ports, {"1433"}):
                evidence.append({"nsgId": nsg.get("id"), "nsgName": nsg.get("name"), "ruleName": rule.get("name"), "priority": rule.get("priority"), "ports": ports})
    return result(
        "NSG Inbound Rule Allows Internet Access to MSSQL Service",
        "Medium",
        "Flags NSG inbound allow rules from any source to TCP port 1433.",
        evidence,
    )

def find_nsg_open_udp(nsgs):
    evidence = []
    for nsg in nsgs:
        for rule in first_value(nsg, ("securityRules",), ("properties", "securityRules")) or []:
            if normalize_text(rule.get("direction")) != "inbound" or normalize_text(rule.get("access")) != "allow":
                continue
            if not is_any_source(rule):
                continue
            protocol = normalize_text(rule.get("protocol"))
            if protocol not in {"udp", "*", "any"}:
                continue
            evidence.append({"nsgId": nsg.get("id"), "nsgName": nsg.get("name"), "ruleName": rule.get("name"), "priority": rule.get("priority"), "ports": rule_port_values(rule), "protocol": rule.get("protocol")})
    return result(
        "NSG Inbound Rule Allows Internet Access to UDP Services",
        "Medium",
        "Flags NSG inbound allow rules from any source that permit UDP traffic.",
        evidence,
    )

def find_nsg_open_exposed_services(nsgs):
    evidence = []
    exposed_ports = {"1433", "3306", "5432", "6379", "9200", "27017", "5601", "8080", "8443", "2375", "2376", "10250"}
    for nsg in nsgs:
        for rule in first_value(nsg, ("securityRules",), ("properties", "securityRules")) or []:
            if normalize_text(rule.get("direction")) != "inbound" or normalize_text(rule.get("access")) != "allow":
                continue
            if not is_any_source(rule):
                continue
            ports = rule_port_values(rule)
            if ports_match(ports, exposed_ports):
                evidence.append({"nsgId": nsg.get("id"), "nsgName": nsg.get("name"), "ruleName": rule.get("name"), "priority": rule.get("priority"), "ports": ports})
    return result(
        "NSG Inbound Rule Allows Internet Access to Exposed Services",
        "Medium",
        "Flags NSG inbound allow rules from any source to common exposed service ports.",
        evidence,
    )

def find_postgres_firewall_any_ip(postgres_firewall_rules):
    evidence = []
    for rule in postgres_firewall_rules:
        start_ip = normalize_text(rule.get("startIpAddress"))
        end_ip = normalize_text(rule.get("endIpAddress"))
        if start_ip == "0.0.0.0" and end_ip == "255.255.255.255":
            params = collection_parameters(rule)
            evidence.append({"serverName": params.get("name"), "resourceGroup": params.get("resourceGroup"), "ruleName": rule.get("name"), "startIpAddress": rule.get("startIpAddress"), "endIpAddress": rule.get("endIpAddress")})
    return result(
        "PostgreSQL Server Firewall Allows Access from Any IP",
        "High",
        "Flags PostgreSQL flexible server firewall rules that allow the full IPv4 address space.",
        evidence,
    )

def find_security_contacts_missing(security_contacts):
    evidence = [] if security_contacts else [{"scope": "subscription"}]
    return result(
        "Security Contacts Not Configured",
        "Low",
        "Checks whether any Microsoft Defender for Cloud security contact records were collected.",
        evidence,
    )

def find_security_contact_email_missing(security_contacts):
    evidence = []
    for contact in security_contacts:
        email = first_value(contact, "email", ("properties", "email"))
        if not normalize_text(email):
            evidence.append({"name": contact.get("name"), "id": contact.get("id"), "email": email})
    return result(
        "Security Contact Email Address Not Configured",
        "Low",
        "Flags Microsoft Defender for Cloud security contacts with no email address configured.",
        evidence,
    )

def find_security_contact_alert_notifications_disabled(security_contacts):
    evidence = []
    for contact in security_contacts:
        state = first_value(contact, ("alertNotifications", "state"), ("properties", "alertNotifications", "state"))
        if normalize_text(state) not in {"on", "enabled"}:
            evidence.append({"name": contact.get("name"), "id": contact.get("id"), "alertNotifications": state})
    return result(
        "Security Contact Email Notifications Not Enabled",
        "Low",
        "Flags security contacts where alert notification email delivery is disabled.",
        evidence,
    )

def find_security_contact_admin_notifications_disabled(security_contacts):
    evidence = []
    for contact in security_contacts:
        state = first_value(contact, ("notificationsByRole", "state"), ("properties", "notificationsByRole", "state"))
        if normalize_text(state) not in {"on", "enabled"}:
            evidence.append({"name": contact.get("name"), "id": contact.get("id"), "notificationsByRole": state})
    return result(
        "Security Contact Admin Email Notifications Not Enabled",
        "Low",
        "Flags security contacts where admin and subscription-owner notification by role is disabled.",
        evidence,
    )

def find_defender_setting_disabled(defender_general_settings, expected_name, title):
    evidence = []
    matched = False
    for setting in defender_general_settings:
        name = normalize_text(setting.get("name"))
        if expected_name not in name:
            continue
        matched = True
        enabled = normalize_text(first_value(setting, "enabled", ("properties", "enabled"), "value", ("properties", "value")))
        if enabled not in {"true", "on", "enabled"}:
            evidence.append({"name": setting.get("name"), "id": setting.get("id"), "enabled": first_value(setting, "enabled", ("properties", "enabled"), "value", ("properties", "value"))})
    if not matched:
        evidence.append({"setting": expected_name, "status": "missing"})
    return result(
        title,
        "Low",
        "Checks Defender general settings for the requested integration state.",
        evidence,
    )

def find_assessment_failures(assessments, title, reason, all_keywords=(), any_keywords=(), resource_type_fragment=None):
    evidence = []
    for assessment in assessments:
        if assessment_status(assessment) not in {"unhealthy", "failed"}:
            continue
        if not assessment_matches(assessment, all_keywords=all_keywords, any_keywords=any_keywords):
            continue
        resource_id = assessment_resource_id(assessment)
        if resource_type_fragment and resource_type_fragment not in normalize_text(resource_id):
            continue
        evidence.append(
            {
                "id": assessment.get("id"),
                "name": first_value(assessment, "displayName", ("metadata", "displayName"), ("properties", "displayName")),
                "resourceId": resource_id,
                "status": first_value(assessment, ("status", "code"), ("properties", "status", "code")),
            }
        )
    return result(title, "Low", reason, evidence)

def find_functionapp_identity_with_admin_privileges(function_apps, function_app_identities, role_assignments):
    apps_by_principal = {}
    identity_by_key = {collection_key(item): item for item in function_app_identities}
    for app in function_apps:
        identity = identity_by_key.get(record_key(app))
        principal_id = identity_principal_id(identity or app)
        if principal_id:
            apps_by_principal.setdefault(principal_id, []).append(app)

    evidence = []
    for assignment in role_assignments:
        principal_id = normalize_text(assignment.get("principalId"))
        if principal_id not in apps_by_principal:
            continue
        role_name = role_assignment_name(assignment)
        if role_name not in RISKY_ADMIN_ROLE_NAMES:
            continue
        for app in apps_by_principal[principal_id]:
            evidence.append(
                compact_dict(
                    app,
                    principalId=assignment.get("principalId"),
                    scope=assignment.get("scope"),
                    roleDefinitionName=assignment.get("roleDefinitionName"),
                )
            )
    return result(
        "Function Apps have managed identities with administrative privileges",
        "Medium",
        "Flags Function App managed identities assigned broad Azure RBAC roles such as Owner, Contributor, or User Access Administrator.",
        evidence,
    )

def find_functionapp_outdated_runtime(function_app_configs, function_app_appsettings):
    appsettings_by_key = {}
    for item in function_app_appsettings:
        key = collection_key(item)
        if key and key != "::":
            appsettings_by_key.setdefault(key, []).append(item)

    evidence = []
    for config in function_app_configs:
        extension_version = first_value(
            config,
            "functionsExtensionVersion",
            ("properties", "functionsExtensionVersion"),
        ) or app_setting_value(appsettings_by_key.get(collection_key(config), []), "FUNCTIONS_EXTENSION_VERSION")
        lowered = normalize_text(extension_version)
        if lowered in {"", "~4", "4"}:
            continue
        evidence.append(compact_dict(config, functionsExtensionVersion=extension_version))
    return result(
        "Function Apps are not using the latest Functions runtime major version",
        "Low",
        "Checks Function App configuration and app settings for FUNCTIONS_EXTENSION_VERSION values older than v4.",
        evidence,
    )

def find_app_service_environment_missing(ase_details):
    evidence = []
    if not ase_details:
        evidence.append({"scope": "subscription", "reason": "no_app_service_environment_collected"})
    return result(
        "App Service Environment vNet injection not deployed",
        "Low",
        "Flags the tenant when azure-collect found no App Service Environment resources to provide isolated App Service network injection.",
        evidence,
    )

def find_defender_auto_provisioning_vulnerability_assessment_disabled(settings):
    evidence = []
    matched = False
    for setting in settings:
        name = normalize_text(setting.get("name"))
        if "vulnerability" not in name and "qualys" not in name:
            continue
        matched = True
        auto_provision = normalize_text(first_value(setting, "autoProvision", ("properties", "autoProvision"), "autoProvisioningState", ("properties", "autoProvisioningState")))
        if auto_provision not in {"on", "enabled", "true"}:
            evidence.append({"name": setting.get("name"), "id": setting.get("id"), "autoProvision": first_value(setting, "autoProvision", ("properties", "autoProvision"), "autoProvisioningState", ("properties", "autoProvisioningState"))})
    if not matched:
        evidence.append({"setting": "vulnerability_assessments", "status": "missing"})
    return result(
        "Defender auto provisioning for vulnerability assessments is not enabled on machines",
        "Low",
        "Checks Defender auto-provisioning settings for vulnerability assessment onboarding related entries.",
        evidence,
    )

def find_entra_conditional_access_mfa_for_admin_portals(policies):
    evidence = []
    matched = False
    for policy in policies:
        state = normalize_text(policy.get("state"))
        if state == "disabled":
            continue
        if not conditional_access_targets_application(policy, ADMIN_PORTAL_APPLICATION_IDS):
            continue
        if not conditional_access_targets_admins(policy):
            continue
        matched = True
        if conditional_access_requires_mfa(policy):
            continue
        evidence.append({"id": policy.get("id"), "name": policy.get("displayName"), "state": policy.get("state")})
    if not matched:
        evidence.append({"scope": "tenant", "target": "Microsoft Admin Portals"})
    return result(
        "Conditional Access does not require MFA for admin portals",
        "Medium",
        "Checks Graph Conditional Access policies for an enabled policy that targets Microsoft Admin Portals for admin users and requires MFA.",
        evidence,
    )

def find_entra_conditional_access_mfa_for_management_api(policies):
    evidence = []
    matched = False
    for policy in policies:
        state = normalize_text(policy.get("state"))
        if state == "disabled":
            continue
        if not conditional_access_targets_application(policy, MANAGEMENT_API_APPLICATION_IDS):
            continue
        matched = True
        if conditional_access_requires_mfa(policy):
            continue
        evidence.append({"id": policy.get("id"), "name": policy.get("displayName"), "state": policy.get("state")})
    if not matched:
        evidence.append({"scope": "tenant", "target": "Azure Management API"})
    return result(
        "Conditional Access does not require MFA for the Azure management API",
        "Medium",
        "Checks Graph Conditional Access policies for an enabled policy that targets the Azure management API and requires MFA.",
        evidence,
    )

def find_entra_global_admin_over_assignment(directory_roles, directory_role_assignments):
    global_role_ids = set()
    for role in directory_roles:
        if normalize_text(role.get("roleTemplateId")) == GLOBAL_ADMIN_ROLE_TEMPLATE_ID or normalize_text(role.get("displayName")) in {"global administrator", "company administrator"}:
            global_role_ids.add(normalize_text(role.get("id")))

    principals = sorted(
        {
            assignment.get("principalId")
            for assignment in directory_role_assignments
            if normalize_text(assignment.get("roleDefinitionId")) in global_role_ids and assignment.get("principalId")
        }
    )
    evidence = []
    if len(principals) >= 5:
        evidence.append({"role": "Global Administrator", "count": len(principals), "principalIds": principals})
    return result(
        "Global Administrator role is assigned to five or more users",
        "Medium",
        "Counts distinct principals assigned to the Microsoft Entra Global Administrator role.",
        evidence,
    )

def find_entra_users_without_mfa(ad_users, registration_details, directory_roles, directory_role_assignments, privileged):
    lookup = build_user_registration_lookup(ad_users, registration_details)
    privileged_principals = {
        normalize_text(item.get("principalId"))
        for item in directory_role_assignments
        if normalize_text(item.get("roleDefinitionId")) in {
            normalize_text(role.get("id"))
            for role in directory_roles
            if ("admin" in normalize_text(role.get("displayName")) or "privileged" in normalize_text(role.get("displayName")))
        }
    }
    evidence = []
    for user in ad_users:
        user_id = normalize_text(user.get("id"))
        if normalize_text(user.get("userType")) == "guest":
            continue
        is_privileged = user_id in privileged_principals
        if privileged != is_privileged:
            continue
        if registration_has_mfa(lookup.get(user_id)):
            continue
        evidence.append(
            {
                "id": user.get("id"),
                "name": user.get("displayName"),
                "userPrincipalName": user.get("userPrincipalName"),
                "privileged": is_privileged,
            }
        )
    title = "Privileged Microsoft Entra users do not have MFA" if privileged else "Non-privileged Microsoft Entra users do not have MFA"
    reason = "Checks Microsoft Graph user registration details for MFA evidence after splitting users by directory-role privilege."
    return result(title, "Medium", reason, evidence)

def find_entra_user_consent_policy(auth_policy_records, require_verified_apps):
    policy = auth_policy_records[0] if auth_policy_records else {}
    grant_policies = [
        normalize_text(item)
        for item in first_value(
            policy,
            "permissionGrantPolicyIdsAssignedToDefaultUserRole",
            ("permissionGrantPolicyIdsAssignedToDefaultUserRole",),
            ("defaultUserRolePermissions", "permissionGrantPoliciesAssigned"),
        )
        or []
    ]
    evidence = []
    if require_verified_apps:
        if not any("verified" in item or "low" in item for item in grant_policies):
            evidence.append({"scope": "tenant", "permissionGrantPolicies": grant_policies})
        title = "User consent for verified applications is not enforced"
    else:
        if any("legacy" in item or "managepermissiongrantsforself" in item for item in grant_policies):
            evidence.append({"scope": "tenant", "permissionGrantPolicies": grant_policies})
        title = "User consent for applications is not sufficiently restricted"
    return result(
        title,
        "Low",
        "Checks Microsoft Entra authorization policy permission-grant policy assignments for the default user role.",
        evidence,
    )

def find_entra_vm_access_users_without_mfa(ad_users, registration_details, role_assignments):
    lookup = build_user_registration_lookup(ad_users, registration_details)
    users_by_id = {normalize_text(user.get("id")): user for user in ad_users}
    evidence = []
    seen = set()
    for assignment in role_assignments:
        principal_id = normalize_text(assignment.get("principalId"))
        if normalize_text(assignment.get("principalType")) != "user" or principal_id not in users_by_id:
            continue
        scope = normalize_text(assignment.get("scope"))
        role_name = role_assignment_name(assignment)
        if "/providers/microsoft.compute/virtualmachines/" not in scope and role_name not in VM_ACCESS_ROLE_NAMES and "virtual machine" not in role_name:
            continue
        if registration_has_mfa(lookup.get(principal_id)):
            continue
        if principal_id in seen:
            continue
        seen.add(principal_id)
        user = users_by_id[principal_id]
        evidence.append({"id": user.get("id"), "name": user.get("displayName"), "userPrincipalName": user.get("userPrincipalName"), "scope": assignment.get("scope"), "roleDefinitionName": assignment.get("roleDefinitionName")})
    return result(
        "Users with VM access do not have MFA",
        "Medium",
        "Checks users assigned VM-scoped or VM-related Azure RBAC roles for MFA evidence in Microsoft Graph registration details.",
        evidence,
    )

def find_entra_m365_group_creation_enabled(group_settings):
    setting = first_matching_group_setting(group_settings, "group.unified")
    value = group_setting_value(setting or {}, "EnableGroupCreation")
    evidence = []
    if normalize_text(value) != "false":
        evidence.append({"scope": "tenant", "EnableGroupCreation": value})
    return result(
        "Users can create Microsoft 365 groups",
        "Low",
        "Checks the Microsoft Graph Group.Unified setting for EnableGroupCreation.",
        evidence,
    )

def find_hdinsight_kafka_manual_auth_enabled(hdinsight_clusters):
    evidence = []
    for cluster in hdinsight_clusters:
        if normalize_text(cluster.get("kind")) != "kafka":
            continue
        security_profile = first_value(cluster, "securityProfile", ("properties", "securityProfile")) or {}
        if security_profile:
            continue
        evidence.append(compact_dict(cluster, kind=cluster.get("kind")))
    return result(
        "HDInsight Kafka clusters do not disable manual authentication",
        "Low",
        "Uses the presence of a securityProfile on Kafka clusters as a proxy for disabling manual cluster authentication.",
        evidence,
    )

def find_user_access_admin_assigned_to_users(role_assignments):
    evidence = []
    for assignment in role_assignments:
        if role_assignment_name(assignment) != "user access administrator":
            continue
        if normalize_text(assignment.get("principalType")) != "user":
            continue
        evidence.append(
            {
                "scope": assignment.get("scope"),
                "principalId": assignment.get("principalId"),
                "resolvedPrincipal": assignment.get("resolvedPrincipal"),
                "roleDefinitionName": assignment.get("roleDefinitionName"),
            }
        )
    return result(
        "User Access Administrator role is assigned directly to users",
        "Medium",
        "Flags direct user assignments to the User Access Administrator Azure RBAC role.",
        evidence,
    )

def find_keyvault_expiry_missing(vaults, items, title, kind, require_rbac=None):
    vaults_by_name = {normalize_text(vault.get("name")): vault for vault in vaults}
    evidence = []
    for item in items:
        vault_name = normalize_text(collection_parameters(item).get("name"))
        vault = vaults_by_name.get(vault_name)
        if not vault:
            continue
        if require_rbac is not None and truthy(first_value(vault, "enableRbacAuthorization", ("properties", "enableRbacAuthorization"))) is not require_rbac:
            continue
        attributes = item.get("attributes") or {}
        expires = first_value(item, ("attributes", "exp"), ("attributes", "expires"), "expires")
        if parse_iso_datetime(expires):
            continue
        evidence.append(
            {
                "vaultName": vault.get("name"),
                "name": item.get("name") or item.get("kid") or item.get("id"),
                "kind": kind,
                "expires": expires,
                "id": item.get("kid") or item.get("id"),
                "enabled": attributes.get("enabled"),
            }
        )
    return result(title, "Low", "Checks collected Key Vault item metadata for an explicit expiration value.", evidence)

def find_keyvault_key_rotation_disabled(vaults, keys, rotation_policies):
    vaults_by_name = {normalize_text(vault.get("name")): vault for vault in vaults}
    policies_by_key = {}
    for item in rotation_policies:
        policy_id = normalize_text(first_value(item, "id", ("properties", "id")))
        if policy_id:
            policies_by_key[policy_id] = item
    evidence = []
    for key in keys:
        vault_name = normalize_text(collection_parameters(key).get("name"))
        if vault_name not in vaults_by_name:
            continue
        key_id = normalize_text(key.get("kid") or key.get("id"))
        policy = policies_by_key.get(key_id)
        lifetime_actions = first_value(policy or {}, "lifetimeActions", ("lifetimeActions",), ("properties", "lifetimeActions")) or []
        if lifetime_actions:
            continue
        evidence.append({"vaultName": vaults_by_name[vault_name].get("name"), "name": key.get("name"), "id": key.get("kid") or key.get("id"), "rotationPolicyPresent": bool(policy)})
    return result(
        "Key Vault keys do not have rotation enabled",
        "Low",
        "Checks collected Key Vault key rotation policies for at least one configured lifetime action.",
        evidence,
    )

def find_mysql_audit_log_connection_disabled(mysql_servers, mysql_parameters):
    params_by_server = {}
    for item in mysql_parameters:
        params_by_server.setdefault(collection_key(item), {})[normalize_text(item.get("name"))] = item.get("value")
    evidence = []
    for server in mysql_servers:
        params = params_by_server.get(record_key(server), {})
        events = normalize_text(params.get("audit_log_events"))
        enabled = normalize_text(params.get("audit_log_enabled"))
        if enabled in {"on", "enabled", "true"} and "connection" in events:
            continue
        evidence.append(compact_dict(server, auditLogEnabled=params.get("audit_log_enabled"), auditLogEvents=params.get("audit_log_events")))
    return result(
        "MySQL flexible servers do not audit connection events",
        "Low",
        "Checks MySQL flexible server parameters for audit_log_enabled and audit_log_events containing CONNECTION.",
        evidence,
    )

def find_server_data_encryption_gap(servers, title):
    evidence = []
    for server in servers:
        encryption_type = normalize_text(first_value(server, ("dataEncryption", "type"), ("properties", "dataEncryption", "type")))
        if encryption_type and "keyvault" in encryption_type:
            continue
        evidence.append(compact_dict(server, dataEncryptionType=first_value(server, ("dataEncryption", "type"), ("properties", "dataEncryption", "type"))))
    return result(title, "Low", "Uses the collected dataEncryption.type field as a proxy for customer-managed infrastructure double encryption.", evidence)

def find_server_private_access_disabled(servers, title):
    evidence = []
    for server in servers:
        public_network = normalize_text(first_value(server, "publicNetworkAccess", ("network", "publicNetworkAccess"), ("properties", "publicNetworkAccess"), ("properties", "network", "publicNetworkAccess")))
        delegated_subnet = first_value(server, "delegatedSubnetResourceId", ("network", "delegatedSubnetResourceId"), ("properties", "delegatedSubnetResourceId"), ("properties", "network", "delegatedSubnetResourceId"))
        private_dns = first_value(server, "privateDnsZoneArmResourceId", ("network", "privateDnsZoneArmResourceId"), ("properties", "privateDnsZoneArmResourceId"), ("properties", "network", "privateDnsZoneArmResourceId"))
        if public_network == "disabled" or delegated_subnet or private_dns:
            continue
        evidence.append(compact_dict(server, publicNetworkAccess=first_value(server, "publicNetworkAccess", ("network", "publicNetworkAccess"), ("properties", "publicNetworkAccess"), ("properties", "network", "publicNetworkAccess"))))
    return result(title, "Low", "Checks server network settings for disabled public access or private network integration fields.", evidence)

def find_defender_pricing_gap(defender_settings, resource_name_keywords, title, description):
    evidence = []
    matched = False
    for setting in defender_settings:
        name = normalize_text(setting.get("name") or first_value(setting, ("properties", "resourceType")))
        if not any(keyword in name for keyword in resource_name_keywords):
            continue
        matched = True
        if setting_is_enabled(setting):
            continue
        evidence.append({"name": setting.get("name"), "pricingTier": first_value(setting, "pricingTier", ("properties", "pricingTier"), "tier", ("properties", "tier")), "subPlan": first_value(setting, "subPlan", ("properties", "subPlan"))})
    if not matched:
        evidence.append({"setting": ",".join(resource_name_keywords), "status": "missing"})
    return result(title, "Low", description, evidence)

def find_nsg_open_http(nsgs):
    evidence = []
    for nsg in nsgs:
        for rule in first_value(nsg, ("securityRules",), ("properties", "securityRules")) or []:
            if normalize_text(rule.get("direction")) != "inbound" or normalize_text(rule.get("access")) != "allow":
                continue
            if not is_any_source(rule):
                continue
            ports = rule_port_values(rule)
            if ports_match(ports, {"80"}):
                evidence.append({"nsgId": nsg.get("id"), "nsgName": nsg.get("name"), "ruleName": rule.get("name"), "priority": rule.get("priority"), "ports": ports})
    return result(
        "HTTP is exposed to the internet through NSG rules",
        "Medium",
        "Flags NSG inbound allow rules from any source to TCP port 80.",
        evidence,
    )

def find_public_ip_exposure(public_ip_addresses):
    evidence = []
    for item in public_ip_addresses:
        if normalize_text(item.get("publicIPAddressVersion")) not in {"ipv4", "ipv6", ""}:
            continue
        ip_address = item.get("ipAddress") or first_value(item, ("properties", "ipAddress"))
        if not ip_address:
            continue
        evidence.append(compact_dict(item, ipAddress=ip_address, publicIPAllocationMethod=first_value(item, "publicIPAllocationMethod", ("properties", "publicIPAllocationMethod"))))
    return result(
        "Public IP addresses are exposed to internet indexing services",
        "Medium",
        "Flags collected Azure public IP resources with an assigned address as internet-reachable assets that may be discoverable by Shodan-like services.",
        evidence,
    )

def find_servicebus_public_access(namespaces, child_items, title, child_label):
    namespace_by_key = {record_key(item): item for item in namespaces}
    evidence = []
    for item in child_items:
        namespace = namespace_by_key.get(collection_key(item))
        public_network = normalize_text(first_value(namespace or {}, "publicNetworkAccess", ("properties", "publicNetworkAccess")))
        if namespace and public_network == "disabled":
            continue
        evidence.append(
            {
                "namespace": collection_parameters(item).get("name"),
                "resourceGroup": collection_parameters(item).get("resourceGroup"),
                child_label: item.get("name"),
                "publicNetworkAccess": first_value(namespace or {}, "publicNetworkAccess", ("properties", "publicNetworkAccess")),
                "id": first_value(namespace or {}, "id"),
            }
        )
    return result(title, "Low", "Uses the parent Service Bus namespace publicNetworkAccess setting as the effective network exposure control for its child entities.", evidence)

def find_sql_server_tls_below_recommendation(sql_servers):
    evidence = []
    for server in sql_servers:
        tls_version = normalize_text(first_value(server, "minimalTlsVersion", ("properties", "minimalTlsVersion")))
        if tls_version in {"1.2", "1.3"}:
            continue
        evidence.append(compact_dict(server, minimalTlsVersion=first_value(server, "minimalTlsVersion", ("properties", "minimalTlsVersion"))))
    return result(
        "SQL servers use a minimal TLS version below the recommended baseline",
        "Low",
        "Checks SQL server minimalTlsVersion for a baseline of TLS 1.2 or newer.",
        evidence,
    )

def find_storage_child_public_access(storage_accounts, child_items, title, child_label):
    accounts_by_name = {normalize_text(account.get("name")): account for account in storage_accounts}
    evidence = []
    for item in child_items:
        account = accounts_by_name.get(normalize_text(collection_parameters(item).get("name")))
        public_network = normalize_text(first_value(account or {}, "publicNetworkAccess", ("properties", "publicNetworkAccess")))
        default_action = normalize_text(first_value(account or {}, ("networkRuleSet", "defaultAction"), ("properties", "networkRuleSet", "defaultAction"), ("networkAcls", "defaultAction"), ("properties", "networkAcls", "defaultAction")))
        if account and public_network == "disabled":
            continue
        if account and default_action == "deny":
            continue
        evidence.append({"storageAccount": collection_parameters(item).get("name"), "name": item.get("name"), "resourceGroup": collection_parameters(item).get("resourceGroup"), child_label: item.get("name"), "publicNetworkAccess": first_value(account or {}, "publicNetworkAccess", ("properties", "publicNetworkAccess"))})
    return result(title, "Low", "Uses the parent storage account network-access configuration as the effective public-access control for the collected child resource type.", evidence)

def find_storage_smb_secure_channel_encryption(file_service_properties):
    evidence = []
    for props in file_service_properties:
        channel_encryption = normalize_text(first_value(props, ("protocolSettings", "smb", "channelEncryption"), ("smb", "channelEncryption")))
        if "aes-128-gcm" in channel_encryption or "aes-256-gcm" in channel_encryption:
            continue
        params = collection_parameters(props)
        evidence.append({"storageAccount": params.get("name"), "resourceGroup": params.get("resourceGroup"), "channelEncryption": first_value(props, ("protocolSettings", "smb", "channelEncryption"), ("smb", "channelEncryption"))})
    return result(
        "Storage accounts do not use secure SMB channel encryption algorithms",
        "Low",
        "Checks storage file service SMB protocol settings for modern AES-GCM channel encryption values.",
        evidence,
    )

def find_storage_smb_protocol_not_latest(file_service_properties):
    evidence = []
    for props in file_service_properties:
        versions = normalize_text(first_value(props, ("protocolSettings", "smb", "versions"), ("smb", "versions")))
        if "3.1.1" in versions:
            continue
        params = collection_parameters(props)
        evidence.append({"storageAccount": params.get("name"), "resourceGroup": params.get("resourceGroup"), "versions": first_value(props, ("protocolSettings", "smb", "versions"), ("smb", "versions"))})
    return result(
        "Storage accounts do not use the latest SMB protocol version",
        "Low",
        "Checks storage file service SMB protocol settings for SMB 3.1.1 support.",
        evidence,
    )

def find_vm_unapproved_images(vm_details):
    evidence = []
    for vm in vm_details:
        image_reference = first_value(vm, ("storageProfile", "imageReference"), ("properties", "storageProfile", "imageReference")) or {}
        publisher = normalize_text(image_reference.get("publisher"))
        if publisher in APPROVED_VM_IMAGE_PUBLISHERS:
            continue
        evidence.append({"vmId": vm.get("id"), "vmName": vm.get("name"), "publisher": image_reference.get("publisher"), "offer": image_reference.get("offer"), "sku": image_reference.get("sku"), "version": image_reference.get("version"), "imageId": image_reference.get("id")})
    return result(
        "Virtual machines are not using approved base images",
        "Low",
        "Flags VMs whose marketplace image publisher falls outside the built-in approved publisher allow-list used by azure-findings.",
        evidence,
    )

def find_vm_backup_retention_too_short(backup_items, backup_policies, minimum_days=7):
    policies = {}
    for policy in backup_policies:
        params = collection_parameters(policy)
        daily_count = first_value(
            policy,
            ("retentionPolicy", "dailySchedule", "retentionDuration", "count"),
            ("properties", "retentionPolicy", "dailySchedule", "retentionDuration", "count"),
        )
        if daily_count is None:
            sub_policies = first_value(policy, "subProtectionPolicy", ("properties", "subProtectionPolicy")) or []
            for sub_policy in sub_policies:
                daily_count = first_value(
                    sub_policy,
                    ("retentionPolicy", "dailySchedule", "retentionDuration", "count"),
                    ("policy", "retentionPolicy", "dailySchedule", "retentionDuration", "count"),
                )
                if daily_count is not None:
                    break
        policies[(normalize_text(params.get("name")), normalize_text(params.get("resourceGroup")), normalize_text(policy.get("name")))] = daily_count

    evidence = []
    for item in backup_items:
        params = collection_parameters(item)
        policy_name = normalize_text(first_value(item, ("properties", "policyInfo", "name"), "policyName", ("properties", "policyName")))
        key = (normalize_text(params.get("name")), normalize_text(params.get("resourceGroup")), policy_name)
        retention_days = policies.get(key)
        if isinstance(retention_days, int) and retention_days >= minimum_days:
            continue
        evidence.append({"vaultName": params.get("name"), "resourceGroup": params.get("resourceGroup"), "backupItem": item.get("name"), "policyName": policy_name, "dailyRetentionDays": retention_days})
    return result(
        "Virtual machine backup policies do not retain daily restore points long enough",
        "Low",
        f"Checks backup policy daily retention counts for a minimum of {minimum_days} days.",
        evidence,
    )

def find_sql_policy_disabled(policies, title):
    evidence = []
    for policy in policies:
        state = normalize_text(first_value(policy, "state", ("properties", "state")))
        if state not in {"enabled", "on"}:
            params = collection_parameters(policy)
            evidence.append({"database": params.get("name"), "server": params.get("serverName"), "resourceGroup": params.get("resourceGroup"), "state": first_value(policy, "state", ("properties", "state"))})
    return result(title, "Low", "Checks SQL database/server policy state.", evidence)

def find_sql_policy_retention_short(policies, title):
    evidence = []
    for policy in policies:
        days = first_value(policy, "retentionDays", ("properties", "retentionDays"))
        if not isinstance(days, int) or days < 90:
            params = collection_parameters(policy)
            evidence.append({"database": params.get("name"), "server": params.get("serverName"), "resourceGroup": params.get("resourceGroup"), "retentionDays": days})
    return result(title, "Low", "Checks SQL policy retentionDays for a 90-day minimum.", evidence)

def find_sql_policy_alerts_disabled(policies, title):
    evidence = []
    for policy in policies:
        disabled_alerts = alert_policy_disabled_alerts(policy)
        if disabled_alerts:
            params = collection_parameters(policy)
            evidence.append({"database": params.get("name"), "server": params.get("serverName"), "resourceGroup": params.get("resourceGroup"), "disabledAlerts": disabled_alerts})
    return result(title, "Low", "Flags SQL threat-detection policies with disabled alert types.", evidence)

def find_sql_policy_email_alerts_disabled(policies, title):
    evidence = []
    for policy in policies:
        if alert_policy_has_email_notifications(policy):
            continue
        params = collection_parameters(policy)
        evidence.append({"database": params.get("name"), "server": params.get("serverName"), "resourceGroup": params.get("resourceGroup"), "emailAccountAdmins": first_value(policy, "emailAccountAdmins", ("properties", "emailAccountAdmins")), "emailAddresses": first_value(policy, "emailAddresses", ("properties", "emailAddresses"))})
    return result(title, "Low", "Flags SQL threat-detection policies with no email alert recipients configured.", evidence)

def find_sqlserver_va_admin_notifications_disabled(vuln_assessments):
    evidence = []
    for item in vuln_assessments:
        admins_enabled = first_value(item, ("recurringScans", "emailSubscriptionAdmins"), ("properties", "recurringScans", "emailSubscriptionAdmins"))
        if admins_enabled is not True:
            params = collection_parameters(item)
            evidence.append({"server": params.get("name"), "resourceGroup": params.get("resourceGroup"), "emailSubscriptionAdmins": admins_enabled})
    return result(
        "SQL Server Vulnerability Assessment Email Notifications to Admins and Owners Not Enabled",
        "Low",
        "Flags SQL Server vulnerability assessments without recurring scan email notifications to admins and owners.",
        evidence,
    )

def find_sqlserver_va_recipients_missing(vuln_assessments):
    evidence = []
    for item in vuln_assessments:
        recipients = first_value(item, ("recurringScans", "emails"), ("properties", "recurringScans", "emails"))
        has_recipients = isinstance(recipients, list) and recipients or isinstance(recipients, str) and recipients.strip()
        if has_recipients:
            continue
        params = collection_parameters(item)
        evidence.append({"server": params.get("name"), "resourceGroup": params.get("resourceGroup"), "emails": recipients})
    return result(
        "SQL Server Vulnerability Assessment Scan Report Recipients Not Configured",
        "Low",
        "Flags SQL Server vulnerability assessments without recurring scan email recipients.",
        evidence,
    )

def find_storage_azure_services_bypass_enabled(storage_accounts):
    evidence = []
    for account in storage_accounts:
        bypass = normalize_text(first_value(account, ("networkAcls", "bypass"), ("properties", "networkAcls", "bypass")))
        if "azureservices" in bypass:
            evidence.append(compact_dict(account, bypass=first_value(account, ("networkAcls", "bypass"), ("properties", "networkAcls", "bypass"))))
    return result(
        "Storage Account Permits Trusted Microsoft Services Bypass",
        "Low",
        "Flags storage accounts whose network ACL bypass includes AzureServices.",
        evidence,
    )

def find_vm_disk_encryption_not_enabled(managed_disks):
    evidence = []
    for disk in managed_disks:
        encryption_type = normalize_text(first_value(disk, ("encryption", "type"), ("properties", "encryption", "type")))
        if not encryption_type:
            evidence.append(compact_dict(disk, encryptionType=first_value(disk, ("encryption", "type"), ("properties", "encryption", "type"))))
    return result(
        "VM Disk Encryption Not Enabled",
        "Low",
        "Flags managed disks with no explicit encryption type recorded in the collected disk payload.",
        evidence,
    )

def find_vm_not_using_managed_disks(vm_details):
    evidence = []
    for vm in vm_details:
        os_disk = first_value(vm, ("storageProfile", "osDisk"), ("properties", "storageProfile", "osDisk")) or {}
        os_managed = os_disk.get("managedDisk", {}).get("id")
        data_disks = first_value(vm, ("storageProfile", "dataDisks"), ("properties", "storageProfile", "dataDisks")) or []
        if not os_managed or any(not disk.get("managedDisk", {}).get("id") for disk in data_disks):
            evidence.append({"vmId": vm.get("id"), "vmName": vm.get("name"), "osManagedDiskId": os_managed, "dataDiskCount": len(data_disks)})
    return result(
        "VM Not Using Managed Disks",
        "Low",
        "Flags virtual machines whose OS disk or any data disk does not use a managed disk reference.",
        evidence,
    )

def find_unapproved_vm_extensions(vm_extensions):
    evidence = []
    for item in vm_extensions:
        publisher = normalize_text(item.get("publisher"))
        if publisher.startswith("microsoft.") or publisher == "microsoft.azure.extensions":
            continue
        params = collection_parameters(item)
        evidence.append({"vmName": params.get("name"), "resourceGroup": params.get("resourceGroup"), "extensionName": item.get("name"), "publisher": item.get("publisher"), "type": item.get("type")})
    return result(
        "Unapproved VM Extensions Installed",
        "Low",
        "Flags installed VM extensions from non-Microsoft publishers as potentially unapproved.",
        evidence,
    )
