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

REQUESTED_HEADLINES = [
    "aisearch_service_not_publicly_accessible",
    "aks_cluster_rbac_enabled",
    "aks_clusters_created_with_private_nodes",
    "aks_clusters_public_access_disabled",
    "aks_network_policy_enabled",
    "apim_threat_detection_llm_jacking",
    "app_client_certificates_on",
    "app_ensure_auth_is_set_up",
    "app_ensure_http_is_redirected_to_https",
    "app_ensure_java_version_is_latest",
    "app_ensure_php_version_is_latest",
    "app_ensure_python_version_is_latest",
    "app_ensure_using_http20",
    "app_ftp_deployment_disabled",
    "app_function_access_keys_configured",
    "app_function_application_insights_enabled",
    "app_function_ftps_deployment_disabled",
    "app_function_identity_is_configured",
    "app_function_identity_without_admin_privileges",
    "app_function_latest_runtime_version",
    "app_function_not_publicly_accessible",
    "app_function_vnet_integration_enabled",
    "app_http_logs_enabled",
    "app_minimum_tls_version_12",
    "app_register_with_identity",
    "app_service_environment_injection_deployed",
    "appinsights_ensure_is_configured",
    "cognitive_services_local_auth_disabled",
    "containerregistry_admin_user_disabled",
    "containerregistry_not_publicly_accessible",
    "containerregistry_uses_private_link",
    "cosmosdb_account_firewall_use_selected_networks",
    "cosmosdb_account_use_aad_and_rbac",
    "cosmosdb_account_use_private_endpoints",
    "databricks_workspace_cmk_encryption_enabled",
    "databricks_workspace_vnet_injection_enabled",
    "defender_additional_email_configured_with_a_security_contact",
    "defender_assessments_vm_endpoint_protection_installed",
    "defender_auto_provisioning_log_analytics_agent_vms_on",
    "defender_auto_provisioning_vulnerabilty_assessments_machines_on",
    "defender_container_images_resolved_vulnerabilities",
    "defender_container_images_scan_enabled",
    "defender_ensure_defender_for_app_services_is_on",
    "defender_ensure_defender_for_arm_is_on",
    "defender_ensure_defender_for_azure_sql_databases_is_on",
    "defender_ensure_defender_for_containers_is_on",
    "defender_ensure_defender_for_cosmosdb_is_on",
    "defender_ensure_defender_for_databases_is_on",
    "defender_ensure_defender_for_dns_is_on",
    "defender_ensure_defender_for_keyvault_is_on",
    "defender_ensure_defender_for_os_relational_databases_is_on",
    "defender_ensure_defender_for_server_is_on",
    "defender_ensure_defender_for_sql_servers_is_on",
    "defender_ensure_defender_for_storage_is_on",
    "defender_ensure_iot_hub_defender_is_on",
    "defender_ensure_mcas_is_enabled",
    "defender_ensure_notify_alerts_severity_is_high",
    "defender_ensure_notify_emails_to_owners",
    "defender_ensure_system_updates_are_applied",
    "defender_ensure_wdatp_is_enabled",
    "entra_conditional_access_policy_require_mfa_for_admin_portals",
    "entra_conditional_access_policy_require_mfa_for_management_api",
    "entra_global_admin_in_less_than_five_users",
    "entra_non_privileged_user_has_mfa",
    "entra_policy_default_users_cannot_create_security_groups",
    "entra_policy_ensure_default_user_cannot_create_apps",
    "entra_policy_ensure_default_user_cannot_create_tenants",
    "entra_policy_guest_invite_only_for_admin_roles",
    "entra_policy_guest_users_access_restrictions",
    "entra_policy_restricts_user_consent_for_apps",
    "entra_policy_user_consent_for_verified_apps",
    "entra_privileged_user_has_mfa",
    "entra_security_defaults_enabled",
    "entra_trusted_named_locations_exists",
    "entra_user_with_vm_access_has_mfa",
    "entra_users_cannot_create_microsoft_365_groups",
    "eventgrid_domain_public_network_access_disabled",
    "eventgrid_topic_public_network_access_disabled",
    "hdinsight_kafka_cluster_manual_auth_disabled",
    "iam_custom_role_has_permissions_to_administer_resource_locks",
    "iam_role_user_access_admin_restricted",
    "iam_subscription_roles_owner_custom_not_created",
    "iot_dps_public_network_access_disabled",
    "keyvault_access_only_through_private_endpoints",
    "keyvault_key_expiration_set_in_non_rbac",
    "keyvault_key_rotation_enabled",
    "keyvault_logging_enabled",
    "keyvault_non_rbac_secret_expiration_set",
    "keyvault_private_endpoints",
    "keyvault_purge_protection_enabled",
    "keyvault_rbac_enabled",
    "keyvault_rbac_key_expiration_set",
    "keyvault_rbac_secret_expiration_set",
    "keyvault_recoverable",
    "keyvault_recoverable_secrets_should_be_enabled",
    "keyvault_secret_expiration_set",
    "keyvault_soft_delete_enabled",
    "kubernetes_cluster_azure_policy_enabled",
    "machine_learning_workspace_public_access_disabled",
    "machine_learning_workspace_vnet_configured",
    "monitor_alert_create_policy_assignment",
    "monitor_alert_create_update_nsg",
    "monitor_alert_create_update_public_ip_address_rule",
    "monitor_alert_create_update_security_solution",
    "monitor_alert_create_update_sqlserver_fr",
    "monitor_alert_delete_nsg",
    "monitor_alert_delete_policy_assignment",
    "monitor_alert_delete_public_ip_address_rule",
    "monitor_alert_delete_security_solution",
    "monitor_alert_delete_sqlserver_fr",
    "monitor_alert_service_health_exists",
    "monitor_diagnostic_setting_with_appropriate_categories",
    "monitor_diagnostic_settings_exists",
    "monitor_storage_account_with_activity_logs_cmk_encrypted",
    "monitor_storage_account_with_activity_logs_is_private",
    "mysql_flexible_server_audit_log_connection_activated",
    "mysql_flexible_server_audit_log_enabled",
    "mysql_flexible_server_geo_redundant_backup_enabled",
    "mysql_flexible_server_infra_double_encryption_enabled",
    "mysql_flexible_server_minimum_tls_version_12",
    "mysql_flexible_server_private_access_enabled",
    "mysql_flexible_server_ssl_connection_enabled",
    "mysql_flexible_server_threat_detection_enabled",
    "network_bastion_host_exists",
    "network_flow_log_captured_sent",
    "network_flow_log_more_than_90_days",
    "network_http_internet_access_restricted",
    "network_public_ip_shodan",
    "network_rdp_internet_access_restricted",
    "network_ssh_internet_access_restricted",
    "network_udp_internet_access_restricted",
    "network_watcher_enabled",
    "postgresql_flexible_server_allow_access_services_disabled",
    "postgresql_flexible_server_enforce_ssl_enabled",
    "postgresql_flexible_server_geo_redundant_backup_enabled",
    "postgresql_flexible_server_infra_double_encryption_enabled",
    "postgresql_flexible_server_log_checkpoints_on",
    "postgresql_flexible_server_log_connections_on",
    "postgresql_flexible_server_log_disconnections_on",
    "postgresql_flexible_server_log_retention_days_greater_3",
    "postgresql_flexible_server_private_dns_zone_configured",
    "postgresql_flexible_server_private_network_access_enabled",
    "postgresql_flexible_server_threat_detection_enabled",
    "redis_cache_rdb_backup_enabled",
    "search_service_public_network_access_disabled",
    "search_service_shared_private_links_enabled",
    "servicebus_queue_public_network_access_disabled",
    "servicebus_topic_public_network_access_disabled",
    "signalr_public_network_access_disabled",
    "sqlserver_atp_enabled",
    "sqlserver_auditing_enabled",
    "sqlserver_auditing_retention_90_days",
    "sqlserver_azuread_administrator_enabled",
    "sqlserver_microsoft_defender_enabled",
    "sqlserver_recommended_minimal_tls_version",
    "sqlserver_tde_encrypted_with_cmk",
    "sqlserver_tde_encryption_enabled",
    "sqlserver_unrestricted_inbound_access",
    "sqlserver_va_emails_notifications_admins_enabled",
    "sqlserver_va_periodic_recurring_scans_enabled",
    "sqlserver_va_scan_reports_configured",
    "sqlserver_vulnerability_assessment_enabled",
    "storage_account_key_access_disabled",
    "storage_blob_public_access_level_is_disabled",
    "storage_blob_versioning_is_enabled",
    "storage_container_public_access_disabled",
    "storage_cross_tenant_replication_disabled",
    "storage_default_network_access_rule_denied",
    "storage_default_network_access_rule_is_denied",
    "storage_default_to_entra_authorization_enabled",
    "storage_ensure_azure_services_are_trusted_to_access_is_enabled",
    "storage_ensure_encryption_with_customer_managed_keys",
    "storage_ensure_file_shares_soft_delete_is_enabled",
    "storage_ensure_minimum_tls_version_12",
    "storage_ensure_private_endpoints_in_storage_accounts",
    "storage_ensure_soft_delete_is_enabled",
    "storage_geo_redundant_enabled",
    "storage_infrastructure_encryption_is_enabled",
    "storage_key_rotation_90_days",
    "storage_queue_public_access_disabled",
    "storage_secure_transfer_required_is_enabled",
    "storage_share_public_access_disabled",
    "storage_smb_channel_encryption_with_secure_algorithm",
    "storage_smb_protocol_version_is_latest",
    "storage_table_public_access_disabled",
    "synapse_workspace_data_exfiltration_protection_enabled",
    "synapse_workspace_managed_virtual_network_enabled",
    "vm_backup_enabled",
    "vm_ensure_attached_disks_encrypted_with_cmk",
    "vm_ensure_unattached_disks_encrypted_with_cmk",
    "vm_ensure_using_approved_images",
    "vm_jit_access_enabled",
    "vm_linux_enforce_ssh_authentication",
    "vm_scaleset_associated_with_load_balancer",
    "vm_sufficient_daily_backup_retention_period",
]

EXISTING_FINDING_HEADLINES = {
    "Azure blob container permits public access": [
        "storage_blob_public_access_level_is_disabled",
        "storage_container_public_access_disabled",
    ],
    "Custom Azure subscription owner roles permitted": [
        "iam_subscription_roles_owner_custom_not_created",
    ],
    "Azure Storage accounts do not enforce encrypted data transfer": [
        "storage_secure_transfer_required_is_enabled",
    ],
    "Azure policy permits users to create security groups": [
        "entra_policy_default_users_cannot_create_security_groups",
    ],
    "Azure Storage Accounts permitting deprecated TLS versions": [
        "storage_ensure_minimum_tls_version_12",
    ],
    "Storage accounts with default network access permitted": [
        "storage_default_network_access_rule_denied",
        "storage_default_network_access_rule_is_denied",
    ],
    "Access permitted to PostgreSQL server from Azure services": [
        "postgresql_flexible_server_allow_access_services_disabled",
    ],
    "Azure Monitor Alerts not configured to notify high severity events": [
        "defender_ensure_notify_alerts_severity_is_high",
    ],
    "Storage Accounts not using private IP endpoints": [
        "storage_ensure_private_endpoints_in_storage_accounts",
    ],
    "Azure Storage Containers without Soft Delete protection": [
        "storage_ensure_soft_delete_is_enabled",
    ],
    "Azure Activity Log Alerts missing for key event types": [
        "monitor_alert_create_policy_assignment",
        "monitor_alert_delete_policy_assignment",
        "monitor_alert_create_update_nsg",
        "monitor_alert_delete_nsg",
        "monitor_alert_create_update_public_ip_address_rule",
        "monitor_alert_delete_public_ip_address_rule",
        "monitor_alert_create_update_sqlserver_fr",
        "monitor_alert_delete_sqlserver_fr",
    ],
    "Microsoft Defender for Cloud is not enabled": [
        "defender_ensure_defender_for_app_services_is_on",
        "defender_ensure_defender_for_arm_is_on",
        "defender_ensure_defender_for_azure_sql_databases_is_on",
        "defender_ensure_defender_for_containers_is_on",
        "defender_ensure_defender_for_cosmosdb_is_on",
        "defender_ensure_defender_for_databases_is_on",
        "defender_ensure_defender_for_dns_is_on",
        "defender_ensure_defender_for_keyvault_is_on",
        "defender_ensure_defender_for_os_relational_databases_is_on",
        "defender_ensure_defender_for_server_is_on",
        "defender_ensure_defender_for_sql_servers_is_on",
        "defender_ensure_defender_for_storage_is_on",
        "defender_ensure_iot_hub_defender_is_on",
    ],
    "Role-Based Access Control (RBAC) not enabled for Azure Key Vault": [
        "keyvault_rbac_enabled",
    ],
    "MySQL server without audit logging enabled": [
        "mysql_flexible_server_audit_log_enabled",
    ],
    "PostgreSQL server with short log retention period": [
        "postgresql_flexible_server_log_retention_days_greater_3",
    ],
    "Security contact phone number is not set in Azure tenant": [
        "defender_additional_email_configured_with_a_security_contact",
    ],
    "Azure AppService HTTP logs not enabled enabled": [
        "app_http_logs_enabled",
    ],
    "Azure Network Watcher not enabled for all subscription locations": [
        "network_watcher_enabled",
    ],
    "Azure Key Vault not recoverable": [
        "keyvault_purge_protection_enabled",
        "keyvault_recoverable",
        "keyvault_recoverable_secrets_should_be_enabled",
        "keyvault_soft_delete_enabled",
    ],
    "Ensure Diagnostic Setting captures appropriate categories": [
        "monitor_diagnostic_setting_with_appropriate_categories",
    ],
    "Azure subscription does not have a role for administration of resource locks": [
        "iam_custom_role_has_permissions_to_administer_resource_locks",
    ],
    "Azure App Services using deprecated HTTP Version": [
        "app_ensure_using_http20",
    ],
    "Data at rest in Azure storage accounts use Microsoft managed encryption keys": [
        "storage_ensure_encryption_with_customer_managed_keys",
    ],
    "Azure Subscription-level activity logs without a 'Diagnostic Setting' exist": [
        "monitor_diagnostic_settings_exists",
    ],
    "Azure Storage Accounts without infrastructure encryption enabled": [
        "storage_infrastructure_encryption_is_enabled",
    ],
    "Azure Container Registry admin user enabled": [
        "containerregistry_admin_user_disabled",
    ],
    "AKS clusters without RBAC enabled": [
        "aks_cluster_rbac_enabled",
    ],
    "AKS clusters not using a private control plane": [
        "aks_clusters_public_access_disabled",
    ],
    "Network security groups expose administrative ports to the Internet": [
        "network_rdp_internet_access_restricted",
        "network_ssh_internet_access_restricted",
    ],
    "Azure App Services do not enforce HTTPS": [
        "app_ensure_http_is_redirected_to_https",
    ],
    "Azure App Services do not require client certificates": [
        "app_client_certificates_on",
    ],
    "Azure App Services permit TLS versions below 1.2": [
        "app_minimum_tls_version_12",
    ],
    "Azure App Services do not disable FTP deployment": [
        "app_ftp_deployment_disabled",
    ],
    "Azure App Services are not registered with a managed identity": [
        "app_register_with_identity",
    ],
    "Function Apps are missing Application Insights configuration": [
        "app_function_application_insights_enabled",
    ],
    "Function Apps do not disable FTP deployment": [
        "app_function_ftps_deployment_disabled",
    ],
    "Function Apps do not have a managed identity configured": [
        "app_function_identity_is_configured",
    ],
    "Function Apps are publicly reachable": [
        "app_function_not_publicly_accessible",
    ],
    "Function Apps are not integrated with a virtual network": [
        "app_function_vnet_integration_enabled",
    ],
    "Azure Container Registries allow public network access": [
        "containerregistry_not_publicly_accessible",
    ],
    "Cosmos DB accounts do not restrict network access": [
        "cosmosdb_account_firewall_use_selected_networks",
    ],
    "Cosmos DB accounts do not use private endpoints": [
        "cosmosdb_account_use_private_endpoints",
    ],
    "Event Grid Topics allow public network access": [
        "eventgrid_topic_public_network_access_disabled",
    ],
    "IoT Device Provisioning Services allow public network access": [
        "iot_dps_public_network_access_disabled",
    ],
    "Azure Key Vaults do not use private endpoints": [
        "keyvault_access_only_through_private_endpoints",
        "keyvault_private_endpoints",
    ],
    "Azure Key Vaults do not have diagnostic logging enabled": [
        "keyvault_logging_enabled",
    ],
    "AKS clusters do not have Azure Policy enabled": [
        "kubernetes_cluster_azure_policy_enabled",
    ],
    "AKS clusters do not have a network policy configured": [
        "aks_network_policy_enabled",
    ],
    "AKS clusters use public node IPs": [
        "aks_clusters_created_with_private_nodes",
    ],
    "Azure Activity Log Alerts missing for service health events": [
        "monitor_alert_service_health_exists",
    ],
    "MySQL flexible servers do not have audit logging enabled": [
        "mysql_flexible_server_audit_log_enabled",
    ],
    "MySQL flexible servers do not enable geo-redundant backup": [
        "mysql_flexible_server_geo_redundant_backup_enabled",
    ],
    "MySQL flexible servers permit TLS versions below 1.2": [
        "mysql_flexible_server_minimum_tls_version_12",
    ],
    "MySQL flexible servers do not enforce SSL connections": [
        "mysql_flexible_server_ssl_connection_enabled",
    ],
    "PostgreSQL flexible servers do not enforce SSL connections": [
        "postgresql_flexible_server_enforce_ssl_enabled",
    ],
    "PostgreSQL flexible servers do not enable geo-redundant backup": [
        "postgresql_flexible_server_geo_redundant_backup_enabled",
    ],
    "PostgreSQL flexible servers do not log checkpoints": [
        "postgresql_flexible_server_log_checkpoints_on",
    ],
    "PostgreSQL flexible servers do not log connections": [
        "postgresql_flexible_server_log_connections_on",
    ],
    "PostgreSQL flexible servers do not log disconnections": [
        "postgresql_flexible_server_log_disconnections_on",
    ],
    "PostgreSQL flexible servers do not have a private DNS zone configured": [
        "postgresql_flexible_server_private_dns_zone_configured",
    ],
    "PostgreSQL flexible servers do not use private network access": [
        "postgresql_flexible_server_private_network_access_enabled",
    ],
    "Redis caches do not have RDB backup enabled": [
        "redis_cache_rdb_backup_enabled",
    ],
    "Storage accounts permit shared key access": [
        "storage_account_key_access_disabled",
    ],
    "Storage accounts do not have blob versioning enabled": [
        "storage_blob_versioning_is_enabled",
    ],
    "Storage accounts allow cross-tenant replication": [
        "storage_cross_tenant_replication_disabled",
    ],
    "Storage accounts do not default to Microsoft Entra authorization": [
        "storage_default_to_entra_authorization_enabled",
    ],
    "Storage accounts do not trust Azure services network bypass": [
        "storage_ensure_azure_services_are_trusted_to_access_is_enabled",
    ],
    "Storage accounts do not use geo-redundant replication": [
        "storage_geo_redundant_enabled",
    ],
    "Synapse workspaces do not enable data exfiltration protection": [
        "synapse_workspace_data_exfiltration_protection_enabled",
    ],
    "Synapse workspaces do not use a managed virtual network": [
        "synapse_workspace_managed_virtual_network_enabled",
    ],
    "Azure Bastion hosts are not deployed": [
        "network_bastion_host_exists",
    ],
    "Network Watcher flow logs are not captured to storage": [
        "network_flow_log_captured_sent",
    ],
    "Network Watcher flow logs do not retain data for more than 90 days": [
        "network_flow_log_more_than_90_days",
    ],
    "Linux virtual machines allow password-based SSH authentication": [
        "vm_linux_enforce_ssh_authentication",
    ],
    "Virtual machine scale sets are not associated with a load balancer": [
        "vm_scaleset_associated_with_load_balancer",
    ],
}


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


def resource_key(name=None, resource_group=None, identifier=None):
    if identifier:
        return normalize_text(identifier)
    return f"{normalize_text(resource_group)}::{normalize_text(name)}"


def record_key(record):
    return resource_key(
        name=record.get("name"),
        resource_group=record.get("resourceGroup"),
        identifier=record.get("id"),
    )


def collection_key(record):
    params = collection_parameters(record)
    return resource_key(
        name=params.get("name"),
        resource_group=params.get("resourceGroup"),
        identifier=params.get("id"),
    )


def parameterised_record_keys(records):
    keys = set()
    for record in records:
        key = collection_key(record)
        if key and key != "::":
            keys.add(key)
    return keys


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
        key = (
            item.get("type"),
            item.get("id"),
            item.get("portal"),
            item.get("href"),
        )
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
            "headline_ids": finding.get("headline_ids", []),
            "severity": finding["severity"],
            "status": finding["status"],
            "reason": finding["reason"],
            "count": finding["evidence_count"],
            "evidence": finding["evidence"] if finding["evidence"] else [],
            "viewer_links": [item.get("href") for item in finding.get("references", {}).get("evidence_links", []) if item.get("href")],
            "source_file": finding.get("references", {}).get("source_files", []),
            "azure_portal_links": [item.get("portal") for item in finding.get("references", {}).get("evidence_links", []) if item.get("portal")],
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
        "status": "confirmed" if evidence else "not_found",
        "reason": reason,
        "evidence_count": len(evidence),
        "evidence": evidence,
    }


def annotate_requested_headlines(findings):
    covered = set()
    for finding in findings:
        headline_ids = EXISTING_FINDING_HEADLINES.get(finding["title"], [])
        finding["headline_ids"] = headline_ids
        covered.update(headline_ids)

    for headline in REQUESTED_HEADLINES:
        if headline in covered:
            continue
        findings.append(
            {
                **unsupported(
                    headline,
                    "Unknown",
                    "azure-findings does not currently implement this requested headline with the datasets collected today.",
                ),
                "headline_ids": [headline],
            }
        )

    return findings


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
        "status": "confirmed" if evidence else "not_found",
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


def build_parameter_map(parameter_records):
    result_map = {}
    for record in parameter_records:
        key = collection_key(record)
        if not key or key == "::":
            continue
        result_map.setdefault(key, {})[normalize_text(record.get("name"))] = record
    return result_map


def parameter_value(parameter_map, resource, *parameter_names):
    entries = parameter_map.get(record_key(resource), {})
    for name in parameter_names:
        record = entries.get(normalize_text(name))
        if record is not None:
            return record.get("value")
    return None


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


def evaluate_findings(catalog):
    storage_accounts = dataset_records(catalog, "az_storage_account_list")
    storage_blob_service_properties = dataset_records(catalog, "az_storage_account_blob-service-properties_show")
    role_definitions = dataset_records(catalog, "az_role_definition_list")
    role_assignments = dataset_records(catalog, "role_enriched") or dataset_records(catalog, "az_role_assignment_list")
    postgres_servers = dataset_records(catalog, "az_postgres_flexible-server_list")
    postgres_firewall_rules = dataset_records(catalog, "az_postgres_flexible-server_firewall-rule_list")
    postgres_parameters = dataset_records(catalog, "az_postgres_flexible-server_parameter_list")
    mysql_servers = dataset_records(catalog, "az_mysql_flexible-server_list")
    mysql_parameters = dataset_records(catalog, "az_mysql_flexible-server_parameter_list")
    key_vaults = dataset_records(catalog, "az_keyvault_list")
    key_vault_network_rules = dataset_records(catalog, "az_keyvault_network-rule_list")
    key_vault_private_endpoint_connections = dataset_records(catalog, "az_keyvault_show", "privateendpointconnections")
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
    web_app_appsettings = dataset_records(catalog, "az_webapp_config_appsettings_list")
    function_apps = dataset_records(catalog, "az_functionapp_list")
    function_app_configs = dataset_records(catalog, "az_functionapp_config_show")
    function_app_appsettings = dataset_records(catalog, "az_functionapp_config_appsettings_list")
    function_app_access_restrictions = dataset_records(catalog, "az_functionapp_config_access-restriction_show")
    function_app_identities = dataset_records(catalog, "az_functionapp_identity_show")
    function_app_vnet_integrations = dataset_records(catalog, "az_functionapp_vnet-integration_list")
    aks_clusters = dataset_records(catalog, "az_aks_list")
    container_registries = dataset_records(catalog, "az_acr_list")
    cosmosdb_accounts = dataset_records(catalog, "az_cosmosdb_list")
    eventgrid_topics = dataset_records(catalog, "az_eventgrid_topic_list")
    iot_dps_instances = dataset_records(catalog, "az_iot_dps_list")
    redis_caches = dataset_records(catalog, "az_redis_list")
    synapse_workspaces = dataset_records(catalog, "az_synapse_workspace_list")
    bastion_hosts = dataset_records(catalog, "az_network_bastion_list")
    flow_logs = dataset_records(catalog, "az_network_watcher_flow-log_list")
    vm_details = dataset_records(catalog, "az_vm_show")
    vm_scale_sets = dataset_records(catalog, "az_vmss_list")
    nsgs = dataset_records(catalog, "az_network_nsg_list")
    source_map = {
        "storage_accounts": dataset_paths(catalog, "az_storage_account_list"),
        "storage_blob_service_properties": dataset_paths(catalog, "az_storage_account_blob-service-properties_show"),
        "role_definitions": dataset_paths(catalog, "az_role_definition_list"),
        "role_assignments": dataset_paths(catalog, "role_enriched") or dataset_paths(catalog, "az_role_assignment_list"),
        "postgres_parameters": dataset_paths(catalog, "az_postgres_flexible-server_parameter_list"),
        "postgres_firewall_rules": dataset_paths(catalog, "az_postgres_flexible-server_firewall-rule_list"),
        "mysql_servers": dataset_paths(catalog, "az_mysql_flexible-server_list"),
        "mysql_parameters": dataset_paths(catalog, "az_mysql_flexible-server_parameter_list"),
        "key_vaults": dataset_paths(catalog, "az_keyvault_list"),
        "key_vault_network_rules": dataset_paths(catalog, "az_keyvault_network-rule_list"),
        "key_vault_private_endpoint_connections": dataset_paths(catalog, "az_keyvault_show", "privateendpointconnections"),
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
        "web_app_appsettings": dataset_paths(catalog, "az_webapp_config_appsettings_list"),
        "function_apps": dataset_paths(catalog, "az_functionapp_list"),
        "function_app_configs": dataset_paths(catalog, "az_functionapp_config_show"),
        "function_app_appsettings": dataset_paths(catalog, "az_functionapp_config_appsettings_list"),
        "function_app_access_restrictions": dataset_paths(catalog, "az_functionapp_config_access-restriction_show"),
        "function_app_identities": dataset_paths(catalog, "az_functionapp_identity_show"),
        "function_app_vnet_integrations": dataset_paths(catalog, "az_functionapp_vnet-integration_list"),
        "aks_clusters": dataset_paths(catalog, "az_aks_list"),
        "container_registries": dataset_paths(catalog, "az_acr_list"),
        "cosmosdb_accounts": dataset_paths(catalog, "az_cosmosdb_list"),
        "eventgrid_topics": dataset_paths(catalog, "az_eventgrid_topic_list"),
        "iot_dps_instances": dataset_paths(catalog, "az_iot_dps_list"),
        "redis_caches": dataset_paths(catalog, "az_redis_list"),
        "synapse_workspaces": dataset_paths(catalog, "az_synapse_workspace_list"),
        "bastion_hosts": dataset_paths(catalog, "az_network_bastion_list"),
        "flow_logs": dataset_paths(catalog, "az_network_watcher_flow-log_list"),
        "vm_details": dataset_paths(catalog, "az_vm_show"),
        "vm_scale_sets": dataset_paths(catalog, "az_vmss_list"),
        "nsgs": dataset_paths(catalog, "az_network_nsg_list"),
    }

    findings = []

    findings.append(
        find_public_blob_access(storage_accounts)
        if storage_accounts
        else unsupported(
            "Azure blob container permits public access",
            "High",
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
    findings.append(
        find_appservice_client_cert_disabled(web_apps)
        if web_apps
        else unsupported(
            "Azure App Services do not require client certificates",
            "Low",
            "No Web App dataset was found.",
        )
    )
    findings.append(
        find_appservice_tls_below_12(web_app_configs)
        if web_app_configs
        else unsupported(
            "Azure App Services permit TLS versions below 1.2",
            "Low",
            "No Web App configuration dataset was found.",
        )
    )
    findings.append(
        find_appservice_ftp_not_disabled(web_apps)
        if web_apps
        else unsupported(
            "Azure App Services do not disable FTP deployment",
            "Low",
            "No Web App dataset was found.",
        )
    )
    findings.append(
        find_appservice_missing_identity(web_apps)
        if web_apps
        else unsupported(
            "Azure App Services are not registered with a managed identity",
            "Low",
            "No Web App dataset was found.",
        )
    )
    findings.append(
        find_functionapp_missing_app_insights(function_apps, function_app_appsettings)
        if function_apps and dataset_present(catalog, "az_functionapp_config_appsettings_list")
        else unsupported(
            "Function Apps are missing Application Insights configuration",
            "Low",
            "Function App and app settings datasets are required.",
        )
    )
    findings.append(
        find_functionapp_ftp_not_disabled(function_apps)
        if function_apps
        else unsupported(
            "Function Apps do not disable FTP deployment",
            "Low",
            "No Function App dataset was found.",
        )
    )
    findings.append(
        find_functionapp_missing_identity(function_apps, function_app_identities)
        if function_apps and dataset_present(catalog, "az_functionapp_identity_show")
        else unsupported(
            "Function Apps do not have a managed identity configured",
            "Low",
            "Function App and identity datasets are required.",
        )
    )
    findings.append(
        find_functionapp_publicly_accessible(function_apps, function_app_access_restrictions)
        if function_apps and dataset_present(catalog, "az_functionapp_config_access-restriction_show")
        else unsupported(
            "Function Apps are publicly reachable",
            "Low",
            "Function App and access restriction datasets are required.",
        )
    )
    findings.append(
        find_functionapp_missing_vnet_integration(function_apps, function_app_vnet_integrations)
        if function_apps and dataset_present(catalog, "az_functionapp_vnet-integration_list")
        else unsupported(
            "Function Apps are not integrated with a virtual network",
            "Low",
            "Function App and VNet integration datasets are required.",
        )
    )
    findings.append(
        find_acr_public_network_enabled(container_registries)
        if container_registries
        else unsupported(
            "Azure Container Registries allow public network access",
            "Low",
            "No container registry dataset was found.",
        )
    )
    findings.append(
        find_cosmosdb_unrestricted_network(cosmosdb_accounts)
        if cosmosdb_accounts
        else unsupported(
            "Cosmos DB accounts do not restrict network access",
            "Low",
            "No Cosmos DB dataset was found.",
        )
    )
    findings.append(
        find_cosmosdb_without_private_endpoints(cosmosdb_accounts)
        if cosmosdb_accounts
        else unsupported(
            "Cosmos DB accounts do not use private endpoints",
            "Low",
            "No Cosmos DB dataset was found.",
        )
    )
    findings.append(
        find_eventgrid_topics_public_network_enabled(eventgrid_topics)
        if eventgrid_topics
        else unsupported(
            "Event Grid Topics allow public network access",
            "Low",
            "No Event Grid Topic dataset was found.",
        )
    )
    findings.append(
        find_iot_dps_public_network_enabled(iot_dps_instances)
        if iot_dps_instances
        else unsupported(
            "IoT Device Provisioning Services allow public network access",
            "Low",
            "No IoT DPS dataset was found.",
        )
    )
    findings.append(
        find_key_vault_without_private_endpoints(key_vaults, key_vault_private_endpoint_connections)
        if key_vaults and dataset_present(catalog, "az_keyvault_show", "privateendpointconnections")
        else unsupported(
            "Azure Key Vaults do not use private endpoints",
            "Low",
            "Key Vault list and private endpoint connection datasets are required.",
        )
    )
    findings.append(
        find_key_vault_logging_disabled(key_vaults, diagnostic_settings)
        if key_vaults and diagnostic_settings
        else unsupported(
            "Azure Key Vaults do not have diagnostic logging enabled",
            "Low",
            "Key Vault and diagnostic setting datasets are required.",
        )
    )
    findings.append(
        find_aks_azure_policy_disabled(aks_clusters)
        if aks_clusters
        else unsupported(
            "AKS clusters do not have Azure Policy enabled",
            "Low",
            "No AKS dataset was found.",
        )
    )
    findings.append(
        find_aks_network_policy_disabled(aks_clusters)
        if aks_clusters
        else unsupported(
            "AKS clusters do not have a network policy configured",
            "Low",
            "No AKS dataset was found.",
        )
    )
    findings.append(
        find_aks_public_nodes_enabled(aks_clusters)
        if aks_clusters
        else unsupported(
            "AKS clusters use public node IPs",
            "Low",
            "No AKS dataset was found.",
        )
    )
    findings.append(
        find_monitor_service_health_alert_missing(activity_log_alerts)
        if activity_log_alerts
        else unsupported(
            "Azure Activity Log Alerts missing for service health events",
            "Low",
            "No activity log alert dataset was found.",
        )
    )
    findings.append(
        find_mysql_audit_logging_disabled(mysql_servers, mysql_parameters)
        if mysql_servers and mysql_parameters
        else unsupported(
            "MySQL flexible servers do not have audit logging enabled",
            "Low",
            "MySQL server and parameter datasets are required.",
        )
    )
    findings.append(
        find_mysql_geo_backup_disabled(mysql_servers)
        if mysql_servers
        else unsupported(
            "MySQL flexible servers do not enable geo-redundant backup",
            "Low",
            "No MySQL server dataset was found.",
        )
    )
    findings.append(
        find_mysql_tls_below_12(mysql_servers, mysql_parameters)
        if mysql_servers and mysql_parameters
        else unsupported(
            "MySQL flexible servers permit TLS versions below 1.2",
            "Low",
            "MySQL server and parameter datasets are required.",
        )
    )
    findings.append(
        find_mysql_ssl_disabled(mysql_servers, mysql_parameters)
        if mysql_servers and mysql_parameters
        else unsupported(
            "MySQL flexible servers do not enforce SSL connections",
            "Low",
            "MySQL server and parameter datasets are required.",
        )
    )
    findings.append(
        find_postgres_ssl_disabled(postgres_servers, postgres_parameters)
        if postgres_servers and postgres_parameters
        else unsupported(
            "PostgreSQL flexible servers do not enforce SSL connections",
            "Low",
            "PostgreSQL server and parameter datasets are required.",
        )
    )
    findings.append(
        find_postgres_geo_backup_disabled(postgres_servers)
        if postgres_servers
        else unsupported(
            "PostgreSQL flexible servers do not enable geo-redundant backup",
            "Low",
            "No PostgreSQL server dataset was found.",
        )
    )
    findings.append(
        find_postgres_parameter_disabled(
            postgres_servers,
            postgres_parameters,
            "log_checkpoints",
            "PostgreSQL flexible servers do not log checkpoints",
            "Uses the PostgreSQL flexible server parameter dataset to check log_checkpoints.",
            "logCheckpoints",
        )
        if postgres_servers and postgres_parameters
        else unsupported(
            "PostgreSQL flexible servers do not log checkpoints",
            "Low",
            "PostgreSQL server and parameter datasets are required.",
        )
    )
    findings.append(
        find_postgres_parameter_disabled(
            postgres_servers,
            postgres_parameters,
            "log_connections",
            "PostgreSQL flexible servers do not log connections",
            "Uses the PostgreSQL flexible server parameter dataset to check log_connections.",
            "logConnections",
        )
        if postgres_servers and postgres_parameters
        else unsupported(
            "PostgreSQL flexible servers do not log connections",
            "Low",
            "PostgreSQL server and parameter datasets are required.",
        )
    )
    findings.append(
        find_postgres_parameter_disabled(
            postgres_servers,
            postgres_parameters,
            "log_disconnections",
            "PostgreSQL flexible servers do not log disconnections",
            "Uses the PostgreSQL flexible server parameter dataset to check log_disconnections.",
            "logDisconnections",
        )
        if postgres_servers and postgres_parameters
        else unsupported(
            "PostgreSQL flexible servers do not log disconnections",
            "Low",
            "PostgreSQL server and parameter datasets are required.",
        )
    )
    findings.append(
        find_postgres_private_dns_missing(postgres_servers)
        if postgres_servers
        else unsupported(
            "PostgreSQL flexible servers do not have a private DNS zone configured",
            "Low",
            "No PostgreSQL server dataset was found.",
        )
    )
    findings.append(
        find_postgres_private_network_disabled(postgres_servers)
        if postgres_servers
        else unsupported(
            "PostgreSQL flexible servers do not use private network access",
            "Low",
            "No PostgreSQL server dataset was found.",
        )
    )
    findings.append(
        find_redis_rdb_backup_disabled(redis_caches)
        if redis_caches
        else unsupported(
            "Redis caches do not have RDB backup enabled",
            "Low",
            "No Redis cache dataset was found.",
        )
    )
    findings.append(
        find_storage_shared_key_access_enabled(storage_accounts)
        if storage_accounts
        else unsupported(
            "Storage accounts permit shared key access",
            "Low",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_storage_blob_versioning_disabled(storage_blob_service_properties)
        if storage_blob_service_properties
        else unsupported(
            "Storage accounts do not have blob versioning enabled",
            "Low",
            "No storage blob service properties dataset was found.",
        )
    )
    findings.append(
        find_storage_cross_tenant_replication_enabled(storage_accounts)
        if storage_accounts
        else unsupported(
            "Storage accounts allow cross-tenant replication",
            "Low",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_storage_entra_auth_not_default(storage_accounts)
        if storage_accounts
        else unsupported(
            "Storage accounts do not default to Microsoft Entra authorization",
            "Low",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_storage_azure_services_bypass_disabled(storage_accounts)
        if storage_accounts
        else unsupported(
            "Storage accounts do not trust Azure services network bypass",
            "Low",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_storage_geo_replication_disabled(storage_accounts)
        if storage_accounts
        else unsupported(
            "Storage accounts do not use geo-redundant replication",
            "Low",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_synapse_exfiltration_protection_disabled(synapse_workspaces)
        if synapse_workspaces
        else unsupported(
            "Synapse workspaces do not enable data exfiltration protection",
            "Low",
            "No Synapse workspace dataset was found.",
        )
    )
    findings.append(
        find_synapse_managed_vnet_disabled(synapse_workspaces)
        if synapse_workspaces
        else unsupported(
            "Synapse workspaces do not use a managed virtual network",
            "Low",
            "No Synapse workspace dataset was found.",
        )
    )
    findings.append(
        find_bastion_host_absent(bastion_hosts, subscriptions)
        if dataset_present(catalog, "az_network_bastion_list")
        else unsupported(
            "Azure Bastion hosts are not deployed",
            "Low",
            "No Bastion host dataset was found.",
        )
    )
    findings.append(
        find_flow_logs_not_captured(flow_logs)
        if flow_logs
        else unsupported(
            "Network Watcher flow logs are not captured to storage",
            "Low",
            "No flow log dataset was found.",
        )
    )
    findings.append(
        find_flow_logs_retention_short(flow_logs)
        if flow_logs
        else unsupported(
            "Network Watcher flow logs do not retain data for more than 90 days",
            "Low",
            "No flow log dataset was found.",
        )
    )
    findings.append(
        find_vm_linux_password_auth_enabled(vm_details)
        if vm_details
        else unsupported(
            "Linux virtual machines allow password-based SSH authentication",
            "Low",
            "No VM detail dataset was found.",
        )
    )
    findings.append(
        find_vmss_without_load_balancer(vm_scale_sets)
        if vm_scale_sets
        else unsupported(
            "Virtual machine scale sets are not associated with a load balancer",
            "Low",
            "No VM scale set dataset was found.",
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
        "Azure App Services do not require client certificates": source_map["web_apps"],
        "Azure App Services permit TLS versions below 1.2": source_map["web_app_configs"],
        "Azure App Services do not disable FTP deployment": source_map["web_apps"],
        "Azure App Services are not registered with a managed identity": source_map["web_apps"],
        "Function Apps are missing Application Insights configuration": source_map["function_apps"] + source_map["function_app_appsettings"],
        "Function Apps do not disable FTP deployment": source_map["function_apps"],
        "Function Apps do not have a managed identity configured": source_map["function_apps"] + source_map["function_app_identities"],
        "Function Apps are publicly reachable": source_map["function_apps"] + source_map["function_app_access_restrictions"],
        "Function Apps are not integrated with a virtual network": source_map["function_apps"] + source_map["function_app_vnet_integrations"],
        "Azure Container Registries allow public network access": source_map["container_registries"],
        "Cosmos DB accounts do not restrict network access": source_map["cosmosdb_accounts"],
        "Cosmos DB accounts do not use private endpoints": source_map["cosmosdb_accounts"],
        "Event Grid Topics allow public network access": source_map["eventgrid_topics"],
        "IoT Device Provisioning Services allow public network access": source_map["iot_dps_instances"],
        "Azure Key Vaults do not use private endpoints": source_map["key_vaults"] + source_map["key_vault_private_endpoint_connections"],
        "Azure Key Vaults do not have diagnostic logging enabled": source_map["key_vaults"] + source_map["diagnostic_settings"],
        "AKS clusters do not have Azure Policy enabled": source_map["aks_clusters"],
        "AKS clusters do not have a network policy configured": source_map["aks_clusters"],
        "AKS clusters use public node IPs": source_map["aks_clusters"],
        "Azure Activity Log Alerts missing for service health events": source_map["activity_log_alerts"],
        "MySQL flexible servers do not have audit logging enabled": source_map["mysql_servers"] + source_map["mysql_parameters"],
        "MySQL flexible servers do not enable geo-redundant backup": source_map["mysql_servers"],
        "MySQL flexible servers permit TLS versions below 1.2": source_map["mysql_servers"] + source_map["mysql_parameters"],
        "MySQL flexible servers do not enforce SSL connections": source_map["mysql_servers"] + source_map["mysql_parameters"],
        "PostgreSQL flexible servers do not enforce SSL connections": source_map["postgres_parameters"] + dataset_paths(catalog, "az_postgres_flexible-server_list"),
        "PostgreSQL flexible servers do not enable geo-redundant backup": dataset_paths(catalog, "az_postgres_flexible-server_list"),
        "PostgreSQL flexible servers do not log checkpoints": source_map["postgres_parameters"] + dataset_paths(catalog, "az_postgres_flexible-server_list"),
        "PostgreSQL flexible servers do not log connections": source_map["postgres_parameters"] + dataset_paths(catalog, "az_postgres_flexible-server_list"),
        "PostgreSQL flexible servers do not log disconnections": source_map["postgres_parameters"] + dataset_paths(catalog, "az_postgres_flexible-server_list"),
        "PostgreSQL flexible servers do not have a private DNS zone configured": dataset_paths(catalog, "az_postgres_flexible-server_list"),
        "PostgreSQL flexible servers do not use private network access": dataset_paths(catalog, "az_postgres_flexible-server_list"),
        "Redis caches do not have RDB backup enabled": source_map["redis_caches"],
        "Storage accounts permit shared key access": source_map["storage_accounts"],
        "Storage accounts do not have blob versioning enabled": source_map["storage_blob_service_properties"],
        "Storage accounts allow cross-tenant replication": source_map["storage_accounts"],
        "Storage accounts do not default to Microsoft Entra authorization": source_map["storage_accounts"],
        "Storage accounts do not trust Azure services network bypass": source_map["storage_accounts"],
        "Storage accounts do not use geo-redundant replication": source_map["storage_accounts"],
        "Synapse workspaces do not enable data exfiltration protection": source_map["synapse_workspaces"],
        "Synapse workspaces do not use a managed virtual network": source_map["synapse_workspaces"],
        "Azure Bastion hosts are not deployed": source_map["bastion_hosts"] + source_map["subscriptions"],
        "Network Watcher flow logs are not captured to storage": source_map["flow_logs"],
        "Network Watcher flow logs do not retain data for more than 90 days": source_map["flow_logs"],
        "Linux virtual machines allow password-based SSH authentication": source_map["vm_details"],
        "Virtual machine scale sets are not associated with a load balancer": source_map["vm_scale_sets"],
    }

    findings = annotate_requested_headlines(findings)

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
