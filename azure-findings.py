#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Search previously collected Azure JSON data for evidence supporting known findings.

import argparse
import json
import re
from pathlib import Path
from urllib.parse import quote


TIMESTAMP_SUFFIX_RE = re.compile(r"_\d{8}-\d{6}$")


def parse_arguments():
    parser = argparse.ArgumentParser(description="Search collected Azure JSON for known-bad findings")
    parser.add_argument(
        "-i",
        "--input-dir",
        type=str,
        default="azure-collect",
        help="Directory containing JSON produced by azure-collect.py",
    )
    parser.add_argument(
        "-o",
        "--output-file",
        type=str,
        default=None,
        help="Path to save the findings as JSON (defaults to <input-dir>/azure-findings.json)",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Do not save JSON output; only print a summary",
    )
    parser.add_argument(
        "--flat-output-file",
        type=str,
        default=None,
        help="Path to save a flat list of findings for easier viewing in azure-present (defaults to <input-dir>/azure-findings-flat.json)",
    )
    return parser.parse_args()


def resolve_output_path(input_dir, output_file, default_filename):
    if output_file:
        return Path(output_file)
    return Path(input_dir) / default_filename


def strip_timestamp(path):
    return TIMESTAMP_SUFFIX_RE.sub("", path.stem.lower())


def load_catalog(input_dir):
    base = Path(input_dir)
    if not base.exists():
        raise FileNotFoundError(f"Input directory not found: {base}")

    files_by_base = {}
    for path in sorted(base.glob("*.json")):
        files_by_base[strip_timestamp(path)] = path

    catalog = {}
    for base_name, path in files_by_base.items():
        try:
            with open(path, encoding="utf-8") as handle:
                payload = json.load(handle)
        except Exception as exc:
            catalog[base_name] = {"path": str(path), "data": None, "error": str(exc)}
            continue
        catalog[base_name] = {"path": str(path), "data": payload, "error": None}
    return catalog


def as_list(payload):
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    return [payload]


def dataset_records(catalog, *fragments):
    fragments = [fragment.lower() for fragment in fragments]
    matched = []
    for base_name, item in catalog.items():
        if all(fragment in base_name for fragment in fragments):
            matched.extend(as_list(item["data"]))
    return matched


def dataset_present(catalog, *fragments):
    fragments = [fragment.lower() for fragment in fragments]
    return any(all(fragment in base_name for fragment in fragments) for base_name in catalog)


def dataset_paths(catalog, *fragments):
    fragments = [fragment.lower() for fragment in fragments]
    paths = []
    for base_name, item in catalog.items():
        if all(fragment in base_name for fragment in fragments):
            paths.append(item["path"])
    return sorted(set(paths))


def get_path(obj, *keys, default=None):
    current = obj
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
    return current


def first_value(obj, *paths):
    for path in paths:
        if not isinstance(path, tuple):
            path = (path,)
        value = get_path(obj, *path, default=None)
        if value is not None:
            return value
    return None


def truthy(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "enabled", "yes"}
    return bool(value)


def normalize_location(value):
    if not value:
        return None
    return str(value).strip().lower().replace(" ", "")


def normalize_text(value):
    if value is None:
        return ""
    return str(value).strip().lower()


def resource_brief(resource):
    return {
        "id": resource.get("id"),
        "name": resource.get("name"),
        "resourceGroup": resource.get("resourceGroup"),
        "location": resource.get("location"),
        "type": resource.get("type"),
    }


def collection_parameters(record):
    return get_path(record, "_collectionContext", "parameters", default={}) or {}


def flatten_permission_actions(role_definition):
    actions = []
    for permission in role_definition.get("permissions", []):
        if not isinstance(permission, dict):
            continue
        actions.extend(permission.get("actions", []) or [])
        actions.extend(permission.get("dataActions", []) or [])
    return [str(action) for action in actions]


def compact_dict(resource, **extra):
    item = resource_brief(resource)
    item.update(extra)
    return item


def resource_portal_link(resource_id):
    if not resource_id:
        return None
    return f"https://portal.azure.com/#view/HubsExtension/ResourceMenuBlade/~/overview/resourceId/{quote(str(resource_id), safe='')}"


def subscription_portal_link(subscription_id):
    if not subscription_id:
        return None
    value = str(subscription_id)
    if value.lower().startswith("/subscriptions/"):
        value = value.split("/", 3)[2]
    return f"https://portal.azure.com/#view/Microsoft_Azure_Billing/SubscriptionsBlade/subscriptionId/{quote(value, safe='')}"


def extract_reference_ids(evidence):
    ids = []
    for key in (
        "id",
        "resourceId",
        "scope",
        "nsgId",
        "appGatewayId",
        "vmId",
        "subscriptionId",
        "target",
        "pe",
    ):
        value = evidence.get(key)
        if isinstance(value, str) and value:
            ids.append(value)
    return sorted(set(ids))


def build_evidence_references(evidence):
    references = []
    seen = set()
    for ref_id in extract_reference_ids(evidence):
        if ref_id in seen:
            continue
        seen.add(ref_id)
        link = resource_portal_link(ref_id) if ref_id.lower().startswith("/subscriptions/") else None
        references.append({"type": "azure_resource", "id": ref_id, "portal": link})

    subscription_id = evidence.get("subscriptionId")
    if isinstance(subscription_id, str) and subscription_id:
        key = f"subscription:{subscription_id}"
        if key not in seen:
            seen.add(key)
            references.append(
                {"type": "azure_subscription", "id": subscription_id, "portal": subscription_portal_link(subscription_id)}
            )
    return references


def evidence_query_term(evidence):
    for key in (
        "id",
        "resourceId",
        "scope",
        "name",
        "ruleName",
        "serverName",
        "webApp",
        "nsgName",
        "subscriptionId",
    ):
        value = evidence.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def build_present_links(source_files, evidence, finding_title):
    query = evidence_query_term(evidence) or finding_title
    links = []
    seen = set()
    for source_file in source_files:
        filename = Path(source_file).name
        href = f"/query/{quote(filename, safe='')}?query={quote(str(query), safe='')}"
        if href in seen:
            continue
        seen.add(href)
        links.append({"type": "azure_present", "file": filename, "query": query, "href": href})
    return links


def attach_references(finding, source_files):
    references = {"source_files": sorted(set(source_files)), "evidence_links": []}
    for evidence in finding["evidence"]:
        item_refs = build_evidence_references(evidence)
        item_refs.extend(build_present_links(source_files, evidence, finding["title"]))
        evidence["_references"] = item_refs
        references["evidence_links"].extend(item_refs)

    deduped_links = []
    seen = set()
    for item in references["evidence_links"]:
        key = (item.get("type"), item.get("id"), item.get("portal"))
        if key in seen:
            continue
        seen.add(key)
        deduped_links.append(item)
    references["evidence_links"] = deduped_links
    finding["references"] = references
    return finding


def flat_rows(findings):
    rows = []
    for finding in findings:
        row = {
            "title": finding["title"],
            "severity": finding["severity"],
            "status": finding["status"],
            "reason": finding["reason"],
            "evidence_count": finding["evidence_count"],
            "source_files": finding.get("references", {}).get("source_files", []),
            "reference_links": [item.get("portal") for item in finding.get("references", {}).get("evidence_links", []) if item.get("portal")],
            "evidence": finding["evidence"] if finding["evidence"] else [],
        }
        rows.append(row)
    return rows


def unsupported(title, severity, reason):
    return {
        "title": title,
        "severity": severity,
        "status": "not_evaluated",
        "reason": reason,
        "evidence_count": 0,
        "evidence": [],
    }


def result(title, severity, reason, evidence):
    return {
        "title": title,
        "severity": severity,
        "status": "found" if evidence else "not_found",
        "reason": reason,
        "evidence_count": len(evidence),
        "evidence": evidence,
    }


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
        "High > partially resolved > medium",
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


def map_by_name(records):
    mapped = {}
    for record in records:
        for key in ("id", "name"):
            value = record.get(key)
            if value:
                mapped[str(value).lower()] = record
    return mapped


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


def find_resource_lock_admin_role_gap(role_definitions):
    evidence = []
    for role in role_definitions:
        actions = {action.lower() for action in flatten_permission_actions(role)}
        if "microsoft.authorization/locks/*" in actions or "microsoft.authorization/*" in actions or "*" in actions:
            evidence.append(
                {
                    "id": role.get("id"),
                    "name": role.get("roleName") or role.get("name"),
                    "roleType": role.get("roleType"),
                }
            )
    return {
        "title": "Azure subscription does not have a role for administration of resource locks",
        "severity": "Low",
        "status": "not_found" if evidence else "supported",
        "reason": "Looks for any role definition that appears able to manage resource locks.",
        "evidence_count": len(evidence),
        "evidence": evidence,
    }


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


def alert_text(record):
    return " ".join(
        normalize_text(value)
        for value in (
            record.get("name"),
            record.get("description"),
            json.dumps(record.get("condition", {}), sort_keys=True),
            json.dumps(record.get("actions", []), sort_keys=True),
            json.dumps(record, sort_keys=True),
        )
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


def is_any_source(rule):
    values = []
    for field in ("sourceAddressPrefix", "sourceAddressPrefixes"):
        value = rule.get(field)
        if isinstance(value, list):
            values.extend(value)
        elif value is not None:
            values.append(value)
    lowered = {normalize_text(value) for value in values}
    return bool(lowered.intersection({"*", "0.0.0.0/0", "internet"}))


def rule_port_values(rule):
    values = []
    for field in ("destinationPortRange", "destinationPortRanges"):
        value = rule.get(field)
        if isinstance(value, list):
            values.extend(value)
        elif value is not None:
            values.append(value)
    return [str(value) for value in values]


def ports_match(port_values, exact_ports):
    for port_value in port_values:
        if port_value == "*":
            return True
        if port_value in exact_ports:
            return True
    return False


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


def evaluate_findings(catalog):
    storage_accounts = dataset_records(catalog, "az_storage_account_list")
    storage_blob_service_properties = dataset_records(catalog, "az_storage_account_blob-service-properties_show")
    role_definitions = dataset_records(catalog, "az_role_definition_list")
    role_assignments = dataset_records(catalog, "role_enriched") or dataset_records(catalog, "az_role_assignment_list")
    postgres_servers = dataset_records(catalog, "az_postgres_flexible-server_list")
    postgres_firewall_rules = dataset_records(catalog, "az_postgres_flexible-server_firewall-rule_list")
    key_vaults = dataset_records(catalog, "az_keyvault_list")
    key_vault_network_rules = dataset_records(catalog, "az_keyvault_network-rule_list")
    metric_alerts = dataset_records(catalog, "az_monitor_metrics_alert_list")
    defender_settings = dataset_records(catalog, "az_security_pricing_list")
    security_contacts = dataset_records(catalog, "az_security_contact_list")
    locations = dataset_records(catalog, "az_account_list-locations")
    resources = dataset_records(catalog, "az_resource_list")
    network_watchers = dataset_records(catalog, "az_network_watcher_list")
    subscriptions = dataset_records(catalog, "az_account_list")
    subscription_diagnostic_settings = dataset_records(catalog, "az_monitor_diagnostic-settings_subscription_list")
    diagnostic_settings = dataset_records(catalog, "az_monitor_diagnostic-settings_list")
    diagnostic_categories = dataset_records(catalog, "az_monitor_diagnostic-settings_categories_list")
    activity_log_alerts = dataset_records(catalog, "az_monitor_activity-log_alert_list")
    web_app_configs = dataset_records(catalog, "az_webapp_config_show")
    web_app_access_restrictions = dataset_records(catalog, "az_webapp_config_access-restriction_show")
    web_app_logs = dataset_records(catalog, "az_webapp_log_show")
    web_apps = dataset_records(catalog, "az_webapp_list")
    aks_clusters = dataset_records(catalog, "az_aks_list")
    container_registries = dataset_records(catalog, "az_acr_list")
    nsgs = dataset_records(catalog, "az_network_nsg_list")
    source_map = {
        "storage_accounts": dataset_paths(catalog, "az_storage_account_list"),
        "storage_blob_service_properties": dataset_paths(catalog, "az_storage_account_blob-service-properties_show"),
        "role_definitions": dataset_paths(catalog, "az_role_definition_list"),
        "role_assignments": dataset_paths(catalog, "role_enriched") or dataset_paths(catalog, "az_role_assignment_list"),
        "postgres_firewall_rules": dataset_paths(catalog, "az_postgres_flexible-server_firewall-rule_list"),
        "key_vaults": dataset_paths(catalog, "az_keyvault_list"),
        "key_vault_network_rules": dataset_paths(catalog, "az_keyvault_network-rule_list"),
        "metric_alerts": dataset_paths(catalog, "az_monitor_metrics_alert_list"),
        "defender_settings": dataset_paths(catalog, "az_security_pricing_list"),
        "security_contacts": dataset_paths(catalog, "az_security_contact_list"),
        "locations": dataset_paths(catalog, "az_account_list-locations"),
        "resources": dataset_paths(catalog, "az_resource_list"),
        "network_watchers": dataset_paths(catalog, "az_network_watcher_list"),
        "subscriptions": dataset_paths(catalog, "az_account_list"),
        "subscription_diagnostic_settings": dataset_paths(catalog, "az_monitor_diagnostic-settings_subscription_list"),
        "diagnostic_settings": dataset_paths(catalog, "az_monitor_diagnostic-settings_list"),
        "diagnostic_categories": dataset_paths(catalog, "az_monitor_diagnostic-settings_categories_list"),
        "activity_log_alerts": dataset_paths(catalog, "az_monitor_activity-log_alert_list"),
        "web_app_configs": dataset_paths(catalog, "az_webapp_config_show"),
        "web_app_access_restrictions": dataset_paths(catalog, "az_webapp_config_access-restriction_show"),
        "web_app_logs": dataset_paths(catalog, "az_webapp_log_show"),
        "web_apps": dataset_paths(catalog, "az_webapp_list"),
        "aks_clusters": dataset_paths(catalog, "az_aks_list"),
        "container_registries": dataset_paths(catalog, "az_acr_list"),
        "nsgs": dataset_paths(catalog, "az_network_nsg_list"),
    }

    findings = []

    findings.append(
        find_public_blob_access(storage_accounts)
        if storage_accounts
        else unsupported(
            "Azure blob container permits public access",
            "High > partially resolved > medium",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_custom_subscription_owner_roles(role_definitions, role_assignments)
        if role_definitions and role_assignments
        else unsupported(
            "Custom Azure subscription owner roles permitted",
            "Medium",
            "Role definitions and enriched role assignments are required.",
        )
    )
    findings.append(
        unsupported(
            "Stale Azure access keys present",
            "Medium",
            "azure-collect does not currently gather storage keys, account keys, or key last-used metadata.",
        )
    )
    findings.append(
        find_unencrypted_transfer(storage_accounts)
        if storage_accounts
        else unsupported(
            "Azure Storage accounts do not enforce encrypted data transfer",
            "Medium",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        unsupported(
            "Azure policy permits users to create security groups",
            "Medium",
            "The current collector does not gather the policy/rule data needed to safely infer user group creation capability.",
        )
    )
    findings.append(
        find_storage_deprecated_tls(storage_accounts)
        if storage_accounts
        else unsupported(
            "Azure Storage Accounts permitting deprecated TLS versions",
            "Medium",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_storage_default_network_access(storage_accounts)
        if storage_accounts
        else unsupported(
            "Storage accounts with default network access permitted",
            "Medium",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_postgres_azure_services_access(postgres_firewall_rules)
        if postgres_firewall_rules
        else unsupported(
            "Access permitted to PostgreSQL server from Azure services",
            "Medium",
            "No PostgreSQL firewall rule dataset was found.",
        )
    )
    findings.append(
        find_key_vault_unrestricted_access(key_vaults, key_vault_network_rules)
        if key_vaults and dataset_present(catalog, "az_keyvault_network-rule_list")
        else unsupported(
            "Access to Azure Key Vault not restricted to trusted source addresses",
            "Low",
            "Key Vault list and network-rule datasets are required.",
        )
    )
    findings.append(
        find_monitor_alert_notification_gaps(metric_alerts)
        if metric_alerts
        else unsupported(
            "Azure Monitor Alerts not configured to notify high severity events",
            "Low",
            "No metric alert dataset was found.",
        )
    )
    findings.append(
        find_storage_without_private_endpoints(storage_accounts)
        if storage_accounts
        else unsupported(
            "Storage Accounts not using private IP endpoints",
            "Low",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        unsupported(
            "PostgreSQL server without connection throttling",
            "Low",
            "azure-collect does not gather PostgreSQL configuration parameters for connection throttling.",
        )
    )
    findings.append(
        find_storage_soft_delete_disabled(storage_blob_service_properties)
        if storage_blob_service_properties
        else unsupported(
            "Azure Storage Containers without Soft Delete protection",
            "Low",
            "No storage blob service properties dataset was found.",
        )
    )
    findings.append(
        find_activity_log_alert_gaps(activity_log_alerts)
        if activity_log_alerts
        else unsupported(
            "Azure Activity Log Alerts missing for key event types",
            "Low",
            "No activity log alert dataset was found.",
        )
    )
    findings.append(
        find_defender_not_enabled(defender_settings)
        if defender_settings
        else unsupported(
            "Microsoft Defender for Cloud is not enabled",
            "Low",
            "No Defender pricing dataset was found.",
        )
    )
    findings.append(
        find_key_vault_rbac_disabled(key_vaults)
        if key_vaults
        else unsupported(
            "Role-Based Access Control (RBAC) not enabled for Azure Key Vault",
            "Low",
            "No Key Vault dataset was found.",
        )
    )
    findings.append(
        unsupported(
            "MySQL server without audit logging enabled",
            "Low",
            "azure-collect does not currently gather MySQL server datasets.",
        )
    )
    findings.append(
        unsupported(
            "PostgreSQL server with short log retention period",
            "Low",
            "azure-collect does not gather PostgreSQL log retention settings.",
        )
    )
    findings.append(
        find_security_contact_phone_missing(security_contacts)
        if security_contacts
        else unsupported(
            "Security contact phone number is not set in Azure tenant",
            "Low",
            "No security contact dataset was found.",
        )
    )
    findings.append(
        find_appservice_http_logs_disabled(web_app_logs)
        if web_app_logs
        else unsupported(
            "Azure AppService HTTP logs not enabled enabled",
            "Low",
            "No App Service log configuration dataset was found.",
        )
    )
    findings.append(
        find_network_watcher_gaps(locations, resources, network_watchers)
        if network_watchers and (resources or locations)
        else unsupported(
            "Azure Network Watcher not enabled for all subscription locations",
            "Low",
            "Network watcher data plus either resource or location data is required.",
        )
    )
    findings.append(
        find_key_vault_not_recoverable(key_vaults)
        if key_vaults
        else unsupported(
            "Azure Key Vault not recoverable",
            "Low",
            "No Key Vault dataset was found.",
        )
    )
    findings.append(
        find_diagnostic_category_gaps(diagnostic_settings, diagnostic_categories)
        if diagnostic_settings and diagnostic_categories
        else unsupported(
            "Ensure Diagnostic Setting captures appropriate categories",
            "Low",
            "Diagnostic settings and diagnostic category datasets are required.",
        )
    )
    findings.append(
        find_resource_lock_admin_role_gap(role_definitions)
        if role_definitions
        else unsupported(
            "Azure subscription does not have a role for administration of resource locks",
            "Low",
            "No role definition dataset was found.",
        )
    )
    findings.append(
        find_app_service_deprecated_http(web_app_configs)
        if web_app_configs
        else unsupported(
            "Azure App Services using deprecated HTTP Version",
            "Low",
            "No Web App configuration dataset was found.",
        )
    )
    findings.append(
        find_storage_microsoft_managed_keys(storage_accounts)
        if storage_accounts
        else unsupported(
            "Data at rest in Azure storage accounts use Microsoft managed encryption keys",
            "Low",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_subscription_activity_logs_without_diagnostics(subscriptions, subscription_diagnostic_settings)
        if subscriptions
        else unsupported(
            "Azure Subscription-level activity logs without a 'Diagnostic Setting' exist",
            "Low",
            "No subscription dataset was found.",
        )
    )
    findings.append(
        find_storage_no_infra_encryption(storage_accounts)
        if storage_accounts
        else unsupported(
            "Azure Storage Accounts without infrastructure encryption enabled",
            "Low",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_acr_admin_user_enabled(container_registries)
        if container_registries
        else unsupported(
            "Azure Container Registry admin user enabled",
            "Low",
            "No container registry dataset was found.",
        )
    )
    findings.append(
        find_aks_rbac_disabled(aks_clusters)
        if aks_clusters
        else unsupported(
            "AKS clusters without RBAC enabled",
            "Low",
            "No AKS dataset was found.",
        )
    )
    findings.append(
        find_aks_local_accounts_enabled(aks_clusters)
        if aks_clusters
        else unsupported(
            "AKS clusters with local accounts enabled",
            "Low",
            "No AKS dataset was found.",
        )
    )
    findings.append(
        find_aks_no_authorized_ip_ranges(aks_clusters)
        if aks_clusters
        else unsupported(
            "AKS clusters without authorized API server IP ranges",
            "Low",
            "No AKS dataset was found.",
        )
    )
    findings.append(
        find_aks_not_private(aks_clusters)
        if aks_clusters
        else unsupported(
            "AKS clusters not using a private control plane",
            "Low",
            "No AKS dataset was found.",
        )
    )
    findings.append(
        find_nsg_open_admin_ports(nsgs)
        if nsgs
        else unsupported(
            "Network security groups expose administrative ports to the Internet",
            "Medium",
            "No NSG dataset was found.",
        )
    )
    findings.append(
        find_nsg_open_data_ports(nsgs)
        if nsgs
        else unsupported(
            "Network security groups expose common data ports to the Internet",
            "Medium",
            "No NSG dataset was found.",
        )
    )
    findings.append(
        find_appservice_https_disabled(web_apps)
        if web_apps
        else unsupported(
            "Azure App Services do not enforce HTTPS",
            "Medium",
            "No Web App dataset was found.",
        )
    )
    findings.append(
        find_appservice_ftps_not_strict(web_apps)
        if web_apps
        else unsupported(
            "Azure App Services do not enforce FTPS-only",
            "Low",
            "No Web App dataset was found.",
        )
    )
    findings.append(
        find_appservice_remote_debugging_enabled(web_apps)
        if web_apps
        else unsupported(
            "Azure App Services have remote debugging enabled",
            "Low",
            "No Web App dataset was found.",
        )
    )
    findings.append(
        find_appservice_permissive_cors(web_apps)
        if web_apps
        else unsupported(
            "Azure App Services allow wildcard CORS origins",
            "Low",
            "No Web App dataset was found.",
        )
    )
    findings.append(
        find_appservice_access_restrictions_missing(web_app_access_restrictions)
        if web_app_access_restrictions
        else unsupported(
            "Azure App Services have no access restrictions configured",
            "Low",
            "No Web App access restriction dataset was found.",
        )
    )
    findings.append(
        find_appservice_scm_restrictions_missing(web_app_access_restrictions)
        if web_app_access_restrictions
        else unsupported(
            "Azure App Services have unrestricted SCM endpoints",
            "Low",
            "No Web App access restriction dataset was found.",
        )
    )

    if postgres_servers and not postgres_firewall_rules:
        for finding in findings:
            if finding["title"] in {
                "Access permitted to PostgreSQL server from Azure services",
                "PostgreSQL server without connection throttling",
                "PostgreSQL server with short log retention period",
            }:
                finding["reason"] += " PostgreSQL servers were collected, but the required supporting sub-resource data was not."

    reference_sources = {
        "Azure blob container permits public access": source_map["storage_accounts"],
        "Custom Azure subscription owner roles permitted": source_map["role_definitions"] + source_map["role_assignments"],
        "Stale Azure access keys present": dataset_paths(catalog, "az_storage_account_keys_list"),
        "Azure Storage accounts do not enforce encrypted data transfer": source_map["storage_accounts"],
        "Azure policy permits users to create security groups": dataset_paths(catalog, "az_policy_assignment_show") + dataset_paths(catalog, "az_policy_definition_show"),
        "Azure Storage Accounts permitting deprecated TLS versions": source_map["storage_accounts"],
        "Storage accounts with default network access permitted": source_map["storage_accounts"],
        "Access permitted to PostgreSQL server from Azure services": source_map["postgres_firewall_rules"],
        "Access to Azure Key Vault not restricted to trusted source addresses": source_map["key_vaults"] + source_map["key_vault_network_rules"],
        "Azure Monitor Alerts not configured to notify high severity events": source_map["metric_alerts"],
        "Storage Accounts not using private IP endpoints": source_map["storage_accounts"],
        "PostgreSQL server without connection throttling": dataset_paths(catalog, "az_postgres_flexible-server_parameter_list"),
        "Azure Storage Containers without Soft Delete protection": source_map["storage_blob_service_properties"],
        "Azure Activity Log Alerts missing for key event types": source_map["activity_log_alerts"],
        "Microsoft Defender for Cloud is not enabled": source_map["defender_settings"],
        "Role-Based Access Control (RBAC) not enabled for Azure Key Vault": source_map["key_vaults"],
        "MySQL server without audit logging enabled": dataset_paths(catalog, "az_mysql_flexible-server_parameter_list"),
        "PostgreSQL server with short log retention period": dataset_paths(catalog, "az_postgres_flexible-server_parameter_list"),
        "Security contact phone number is not set in Azure tenant": source_map["security_contacts"],
        "Azure AppService HTTP logs not enabled enabled": source_map["web_app_logs"],
        "Azure Network Watcher not enabled for all subscription locations": source_map["network_watchers"] + source_map["resources"] + source_map["locations"],
        "Azure Key Vault not recoverable": source_map["key_vaults"],
        "Ensure Diagnostic Setting captures appropriate categories": source_map["diagnostic_settings"] + source_map["diagnostic_categories"],
        "Azure subscription does not have a role for administration of resource locks": source_map["role_definitions"],
        "Azure App Services using deprecated HTTP Version": source_map["web_app_configs"],
        "Data at rest in Azure storage accounts use Microsoft managed encryption keys": source_map["storage_accounts"],
        "Azure Subscription-level activity logs without a 'Diagnostic Setting' exist": source_map["subscriptions"] + source_map["subscription_diagnostic_settings"],
        "Azure Storage Accounts without infrastructure encryption enabled": source_map["storage_accounts"],
        "Azure Container Registry admin user enabled": source_map["container_registries"],
        "AKS clusters without RBAC enabled": source_map["aks_clusters"],
        "AKS clusters with local accounts enabled": source_map["aks_clusters"],
        "AKS clusters without authorized API server IP ranges": source_map["aks_clusters"],
        "AKS clusters not using a private control plane": source_map["aks_clusters"],
        "Network security groups expose administrative ports to the Internet": source_map["nsgs"],
        "Network security groups expose common data ports to the Internet": source_map["nsgs"],
        "Azure App Services do not enforce HTTPS": source_map["web_apps"],
        "Azure App Services do not enforce FTPS-only": source_map["web_apps"],
        "Azure App Services have remote debugging enabled": source_map["web_apps"],
        "Azure App Services allow wildcard CORS origins": source_map["web_apps"],
        "Azure App Services have no access restrictions configured": source_map["web_app_access_restrictions"],
        "Azure App Services have unrestricted SCM endpoints": source_map["web_app_access_restrictions"],
    }

    for finding in findings:
        attach_references(finding, reference_sources.get(finding["title"], []))

    return findings


def print_summary(findings):
    print("Known-bad finding search results")
    print("=" * 31)
    for finding in findings:
        print(
            f"[{finding['status']}] {finding['title']} | severity={finding['severity']} | evidence={finding['evidence_count']}"
        )


def main():
    args = parse_arguments()
    catalog = load_catalog(args.input_dir)
    findings = evaluate_findings(catalog)
    output = {
        "input_dir": str(Path(args.input_dir)),
        "files_loaded": sorted(catalog.keys()),
        "findings": findings,
    }
    flat_output = {
        "input_dir": str(Path(args.input_dir)),
        "files_loaded": sorted(catalog.keys()),
        "rows": flat_rows(findings),
    }

    print_summary(findings)

    if not args.no_save:
        output_path = resolve_output_path(args.input_dir, args.output_file, "azure-findings.json")
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(output, handle, indent=2)
        flat_output_path = resolve_output_path(args.input_dir, args.flat_output_file, "azure-findings-flat.json")
        with open(flat_output_path, "w", encoding="utf-8") as handle:
            json.dump(flat_output, handle, indent=2)
        print(f"\nSaved findings JSON to: {output_path}")
        print(f"Saved flat findings JSON to: {flat_output_path}")


if __name__ == "__main__":
    main()
