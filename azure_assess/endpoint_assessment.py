#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Declare how collected endpoint evidence participates in assessment."""

from collections import Counter
from typing import Any, Mapping


AUTOMATED = "automated"
SUPPORTING = "supporting"
MANUAL = "manual"
ASSESSMENT_ROLES = {AUTOMATED, SUPPORTING, MANUAL}


# These inventories supply parameters, scope or enrichment to an automated
# check, but do not independently establish a pass or failure.
SUPPORTING_ONLY_ENDPOINTS = {
    "az_apim_list",
    "az_appservice_ase_list",
    "az_backup_vault_list",
    "az_databricks_workspace_list",
    "az_group_list",
    "az_hdinsight_list",
    "az_ml_workspace_list",
    "az_monitor_app-insights_component_show",
    "az_search_service_list",
    "az_vm_list",
    "graph_identity_baseline_recommendation_impacted_resources",
}


# Each endpoint below returns useful assessment context, but the current
# evidence does not have a tenant-independent Microsoft-guidance-based state
# that can be conservatively labelled pass or fail. An analyst must decide how
# it applies to the assessed tenant or workload.
MANUAL_ASSESSMENT_ENDPOINTS = {
    # Azure base inventory.
    "az_account_management-group_list_--no-register",
    "az_afd_profile_list",
    "az_appservice_plan_list",
    "az_aro_list",
    "az_batch_account_list",
    "az_billing_account_list",
    "az_cdn_profile_list",
    "az_consumption_usage_list",
    "az_container_list",
    "az_datafactory_list",
    "az_logicapp_list",
    "az_managedapp_list",
    "az_maps_account_list",
    "az_monitor_account_list",
    "az_monitor_action-group_list",
    "az_monitor_app-insights_web-test_list",
    "az_monitor_data-collection_endpoint_list",
    "az_monitor_data-collection_rule_list",
    "az_monitor_log-analytics_cluster_list",
    "az_monitor_log-analytics_solution_list",
    "az_network_dns_zone_list",
    "az_network_express-route_list",
    "az_network_nat_gateway_list",
    "az_network_private-dns_zone_list",
    "az_network_private-endpoint_list",
    "az_policy_definition_list_--filter_policytype_eq_custom",
    "az_policy_metadata_list",
    "az_policy_set-definition_list",
    "az_purview_account_list",
    "az_security_workspace-setting_list",
    "az_ts_list",
    "az_vm_host_group_list",
    "az_vm_list-ip-addresses",

    # Azure parameterised inventory.
    "arm_pim_azure_resource_assignment_instances",
    "arm_pim_azure_resource_eligibility_instances",
    "arm_pim_azure_resource_eligibility_requests",
    "arm_pim_azure_resource_eligibility_schedules",
    "az_appconfig_feature_list_--name_name_--all",
    "az_appconfig_kv_list_--name_name_--all",
    "az_appconfig_revision_list_--name_name_--all",
    "az_appconfig_snapshot_list_--name_name_--all",
    "az_appservice_ase_list-addresses_--name_name",
    "az_appservice_ase_list-plans_--name_name",
    "az_appservice_plan_show_--name_name_--resource-group_resourcegroup",
    "az_appservice_vnet-integration_list_--resource-group_resourcegroup_--plan_name",
    "az_cognitiveservices_account_show_--name_name_--resource-group_resourcegroup",
    "az_cosmosdb_sql_role_definition_list_--account-name_name_--resource-group_resourcegroup",
    "az_deployment_group_list_--resource-group_name",
    "az_disk_show_--name_name_--resource-group_resourcegroup",
    "az_eventgrid_domain_show_--name_name_--resource-group_resourcegroup",
    "az_functionapp_cors_show_--name_name_--resource-group_resourcegroup",
    "az_functionapp_deployment_slot_list_--name_name_--resource-group_resourcegroup",
    "az_keyvault_private-link-resource_list_--vault-name_name_--resource-group_resourcegroup",
    "az_keyvault_show_--name_name_--resource-group_resourcegroup",
    "az_monitor_metrics_list-namespaces_--resource_id",
    "az_network_application-gateway_http-settings_list_--gateway-name_name_--resource-group_resourcegroup",
    "az_network_application-gateway_rewrite-rule_set_list_--gateway-name_name_--resource-group_resourcegroup",
    "az_network_application-gateway_rule_list_--gateway-name_name_--resource-group_resourcegroup",
    "az_network_application-gateway_ssl-cert_list_--gateway-name_name_--resource-group_resourcegroup",
    "az_network_application-gateway_ssl-profile_list_--gateway-name_name_--resource-group_resourcegroup",
    "az_network_application-gateway_url-path-map_list_--gateway-name_name_--resource-group_resourcegroup",
    "az_network_list-service-tags_--location_name",
    "az_network_nat_gateway_show_--name_name_--resource-group_resourcegroup",
    "az_network_nic_show-effective-route-table_--ids_id",
    "az_network_nsg_rule_list_--nsg-name_name_--resource-group_resourcegroup",
    "az_network_nsg_show_--name_name_--resource-group_resourcegroup",
    "az_network_private-endpoint_dns-zone-group_list_--endpoint-name_name_--resource-group_resourcegroup",
    "az_network_private-endpoint_ip-config_list_--endpoint-name_name_--resource-group_resourcegroup",
    "az_network_private-endpoint_show_--name_name_--resource-group_resourcegroup",
    "az_network_route-table_list_--resource-group_name",
    "az_network_vnet_list",
    "az_network_vnet_subnet_list_--resource-group_resourcegroup_--vnet-name_name",
    "az_policy_definition_show_--name_name",
    "az_policy_set-definition_show_--name_name",
    "az_resource_show_--ids_id_--api-version_2024-11-01_--include-response-body_true",
    "az_rest_--method_get_--url_id_api-version_2025-11-01",
    "az_sql_db_list_--server_name_--resource-group_resourcegroup",
    "az_storage_blob_list_--account-name_storage_account_name_--container-name_container_name",
    "az_storage_container_list_--account-name_name_--auth-mode_login_--query_.container_name_name_storage_account_name_name_metadata_metadata_properties_properties",
    "az_storage_cors_list_--services_q_--account-name_name_--auth-mode_login",
    "az_vm_nic_list_--resource-group_resourcegroup_--vm-name_name",
    "az_vm_nic_show_--resource-group_resourcegroup_--vm-name_vm_name_--nic_id",
    "az_vm_secret_list_--resource-group_resourcegroup_--name_name",
    "az_webapp_vnet-integration_list_--name_name_--resource-group_resourcegroup",

    # Microsoft Graph inventory and activity context.
    "graph_endpoint_intune_autopilot_profiles",
    "graph_endpoint_intune_detected_apps",
    "graph_endpoint_intune_device_categories",
    "graph_endpoint_intune_intune_scope_tags",
    "graph_endpoint_intune_notification_templates",
    "graph_endpoint_intune_terms_conditions",
    "graph_identity_baseline_administrative_units",
    "graph_identity_baseline_connected_organisations",
    "graph_identity_baseline_credential_usage_report",
    "graph_identity_baseline_domains",
    "graph_identity_baseline_entitlement_catalogs",
    "graph_identity_baseline_entitlement_packages",
    "graph_identity_baseline_identity_providers",
    "graph_identity_baseline_organisation",
    "graph_identity_baseline_report_settings",
    "graph_m365_audit_activity_exchange",
    "graph_m365_audit_activity_m365_web",
    "graph_m365_audit_activity_onedrive",
    "graph_m365_audit_activity_teams",
    "graph_m365_audit_audit_general",
    "graph_m365_audit_audit_onedrive",
    "graph_p_i_m_pim_alert_configurations",
    "graph_p_i_m_pim_directory_eligibility_instances",
    "graph_p_i_m_pim_directory_eligibility_requests",
    "graph_p_i_m_pim_directory_eligible",
    "graph_p_i_m_pim_directory_schedule_instances",
    "graph_p_i_m_pim_group_eligibility_instances",
    "graph_p_i_m_pim_group_eligibility_requests",
    "graph_p_i_m_pim_group_eligible",
    "graph_p_i_m_pim_group_schedule_instances",
}


def endpoint_assessment_role(endpoint_id: Any) -> str:
    """Return the declared assessment relationship for a stable endpoint ID."""
    identifier = str(endpoint_id or "").casefold()
    if identifier in SUPPORTING_ONLY_ENDPOINTS:
        return SUPPORTING
    if identifier in MANUAL_ASSESSMENT_ENDPOINTS:
        return MANUAL
    return AUTOMATED


def manual_assessment_reason(endpoint_run: Mapping[str, Any]) -> str:
    """Explain why an endpoint outcome requires tenant-aware analyst review."""
    category = str(endpoint_run.get("category") or "collection")
    return (
        f"The {category} evidence has no current conservative, tenant-independent "
        "automated pass/fail rule. Review the collected records in the context of "
        "the tenant's architecture, threat model and approved configuration."
    )


def manual_endpoint_groups(collection_manifest: Mapping[str, Any]) -> list:
    """Group context-only executions without retaining parameter values."""
    groups = {}
    for endpoint_run in collection_manifest.get("endpoint_runs", []):
        if not isinstance(endpoint_run, Mapping):
            continue
        endpoint_id = str(endpoint_run.get("endpoint_id") or "").casefold()
        if endpoint_assessment_role(endpoint_id) != MANUAL:
            continue
        group = groups.setdefault(
            endpoint_id,
            {
                "endpoint_id": endpoint_id,
                "endpoint_name": str(
                    endpoint_run.get("endpoint_name") or endpoint_id
                ),
                "categories": set(),
                "statuses": Counter(),
                "execution_count": 0,
                "record_count": 0,
                "source_files": set(),
                "usable_evidence": False,
                "reason": manual_assessment_reason(endpoint_run),
            },
        )
        category = str(endpoint_run.get("category") or "collection")
        status = str(endpoint_run.get("status") or "unknown")
        result_count = endpoint_run.get("result_count")
        output_files = {
            filename
            for filename in endpoint_run.get("output_files", [])
            if isinstance(filename, str) and filename
        }
        group["categories"].add(category)
        group["statuses"][status] += 1
        group["execution_count"] += 1
        if isinstance(result_count, int) and result_count > 0:
            group["record_count"] += result_count
            if status in {"success", "incomplete"} and output_files:
                group["usable_evidence"] = True
        group["source_files"].update(output_files)

    return [
        {
            **group,
            "categories": sorted(group["categories"]),
            "statuses": dict(sorted(group["statuses"].items())),
            "source_files": sorted(group["source_files"]),
        }
        for _endpoint_id, group in sorted(groups.items())
    ]
