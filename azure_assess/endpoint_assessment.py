#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Declare how collected endpoint evidence participates in assessment."""

from collections import Counter
from typing import Any, Mapping


AUTOMATED = "automated"
SUPPORTING = "supporting"
MANUAL = "manual"
CONTEXT = "context"
ASSESSMENT_ROLES = {AUTOMATED, SUPPORTING, MANUAL, CONTEXT}


# These inventories supply parameters, scope or enrichment to an automated
# check, but do not independently establish a pass or failure.
SUPPORTING_ONLY_ENDPOINTS = {
    "arm_afd_endpoints",
    "arm_afd_origin_groups",
    "arm_afd_origins",
    "arm_afd_routes",
    "arm_cdn_endpoints",
    "az_apim_list",
    "az_appservice_ase_list",
    "az_appservice_ase_list-addresses_--name_name",
    "az_backup_vault_list",
    "az_databricks_workspace_list",
    "az_group_list",
    "az_hdinsight_list",
    "az_ml_workspace_list",
    "az_monitor_app-insights_component_show",
    "az_search_service_list",
    "az_container_list",
    "az_containerapp_list",
    "az_network_dns_record-set_list_--zone-name_name_--resource-group_resourcegroup",
    "az_network_dns_zone_list",
    "az_network_bastion_list",
    "az_network_firewall_list",
    "az_network_firewall_policy_list",
    "az_network_firewall_policy_rule-collection-group_list_--policy-name_name_--resource-group_resourcegroup",
    "az_network_nat_gateway_list",
    "az_network_nat_gateway_show_--name_name_--resource-group_resourcegroup",
    "az_network_public-ip_prefix_list",
    "az_network_traffic-manager_profile_list",
    "az_network_traffic-manager_profile_show_--name_name_--resource-group_resourcegroup",
    "az_network_vnet-gateway_list",
    "az_network_vpn-connection_list_--resource-group_name",
    "az_relay_namespace_list",
    "az_signalr_list",
    "az_vm_list",
    "az_vm_list-ip-addresses",
    "az_vmss_list-instance-public-ips_--name_name_--resource-group_resourcegroup",
    "az_functionapp_deployment_slot_list_--name_name_--resource-group_resourcegroup",
    "az_webapp_deployment_slot_list_--name_name_--resource-group_resourcegroup",
    "az_network_nic_show-effective-route-table_--ids_id",
    "graph_identity_baseline_recommendation_impacted_resources",
    "graph_p_i_m_pim_directory_schedule_instances",
}


# Manual reviews are deliberately curated. Each definition must identify a
# concrete decision that the returned records support, and why tenant-specific
# knowledge prevents a safe automated pass/fail conclusion.
MANUAL_ASSESSMENT_DEFINITIONS = {
    "az_monitor_data-collection_endpoint_list": {
        "question": "Are the data collection endpoint network boundaries appropriate for the monitoring architecture?",
        "applicability": "One or more Azure Monitor data collection endpoints are configured.",
        "evidence_fields": ["name", "location", "networkAcls", "privateLinkScopedResources"],
        "rationale": "Public or private connectivity is only meaningful when compared with the tenant's agent locations, private-link design and availability requirements.",
        "outcomes": ["approved architecture", "network exposure requires remediation", "further evidence required"],
    },
    "az_monitor_data-collection_rule_list": {
        "question": "Do data collection rules send the intended telemetry to approved destinations?",
        "applicability": "One or more Azure Monitor data collection rules are configured.",
        "evidence_fields": ["name", "dataFlows", "dataSources", "destinations", "streamDeclarations"],
        "rationale": "Required telemetry and destinations depend on the workloads, incident-response plan and data residency requirements.",
        "outcomes": ["coverage and destinations approved", "monitoring gap or unapproved destination", "further evidence required"],
    },
    "az_monitor_log-analytics_cluster_list": {
        "question": "Are dedicated Log Analytics cluster settings appropriate for the tenant's security and retention design?",
        "applicability": "One or more dedicated Log Analytics clusters are configured.",
        "evidence_fields": ["name", "keyVaultProperties", "isDoubleEncryptionEnabled", "billingType", "sku"],
        "rationale": "Encryption-key, capacity and billing choices require tenant-specific regulatory and operational context.",
        "outcomes": ["cluster design approved", "cluster control requires remediation", "further evidence required"],
    },
    "az_policy_definition_list_--filter_policytype_eq_custom": {
        "question": "Do custom Azure Policy definitions implement approved controls without unsafe exclusions or effects?",
        "applicability": "One or more custom Azure Policy definitions exist.",
        "evidence_fields": ["name", "displayName", "description", "mode", "parameters", "policyRule"],
        "rationale": "Correctness depends on the organisation's intended control, exemptions and deployment model.",
        "outcomes": ["definition approved", "definition weakens or misimplements a control", "further evidence required"],
    },
    "az_network_application-gateway_rewrite-rule_set_list_--gateway-name_name_--resource-group_resourcegroup": {
        "question": "Are Application Gateway rewrite rules authorised and safe for the applications they front?",
        "applicability": "One or more Application Gateway rewrite rule sets exist.",
        "evidence_fields": ["name", "rewriteRules"],
        "rationale": "Header and URL transformations can remove security controls or change routing, but intended behaviour is application-specific.",
        "outcomes": ["rewrite behaviour approved", "rewrite behaviour creates a security concern", "further evidence required"],
    },
    "az_storage_cors_list_--services_q_--account-name_name_--auth-mode_login": {
        "question": "Do Queue service CORS origins, methods and headers match the approved client applications?",
        "applicability": "One or more Queue service CORS rules are configured.",
        "evidence_fields": ["allowedOrigins", "allowedMethods", "allowedHeaders", "exposedHeaders", "maxAgeInSeconds"],
        "rationale": "The safe allow-list depends on the tenant's legitimate browser clients; CORS is not an authorisation mechanism.",
        "outcomes": ["CORS rule approved", "CORS rule is broader than required", "further evidence required"],
    },
    "graph_endpoint_intune_autopilot_profiles": {
        "question": "Do Windows Autopilot deployment modes and user account types match the approved device-build model?",
        "applicability": "One or more Windows Autopilot deployment profiles exist.",
        "evidence_fields": ["displayName", "deviceType", "deviceNameTemplate", "outOfBoxExperienceSettings"],
        "rationale": "Administrator versus standard-user and deployment-mode choices depend on device ownership, support and recovery controls.",
        "outcomes": ["profile approved", "profile grants inappropriate deployment privileges", "further evidence required"],
    },
    "graph_endpoint_intune_detected_apps": {
        "question": "Are detected applications approved, supported and within the organisation's software-risk tolerance?",
        "applicability": "Intune reports one or more detected applications.",
        "evidence_fields": ["displayName", "version", "platform", "publisher", "deviceCount"],
        "rationale": "Approval, support lifecycle and vulnerability exposure require an organisational software baseline and current vulnerability intelligence.",
        "outcomes": ["software approved", "unsupported or prohibited software identified", "further evidence required"],
    },
    "graph_identity_baseline_connected_organisations": {
        "question": "Are entitlement-management connected organisations current, approved trust relationships?",
        "applicability": "One or more connected organisations are configured.",
        "evidence_fields": ["displayName", "description", "state", "identitySources", "externalSponsors", "internalSponsors"],
        "rationale": "The Graph record cannot establish whether an external organisation remains an authorised business partner.",
        "outcomes": ["relationship approved", "stale or unauthorised relationship", "further evidence required"],
    },
    "graph_identity_baseline_domains": {
        "question": "Are tenant domains and their authentication arrangements authorised and controlled?",
        "applicability": "One or more Microsoft Entra domains are configured.",
        "evidence_fields": ["id", "authenticationType", "isDefault", "isInitial", "isVerified", "supportedServices"],
        "rationale": "Expected domains and federation arrangements depend on business ownership and the tenant's identity architecture.",
        "outcomes": ["domain approved", "unexpected or unsafe domain arrangement", "further evidence required"],
    },
    "graph_identity_baseline_entitlement_catalogs": {
        "question": "Do entitlement-management catalogue visibility, state and purpose match the approved governance design?",
        "applicability": "One or more entitlement-management catalogues exist.",
        "evidence_fields": ["displayName", "description", "catalogType", "state", "isExternallyVisible"],
        "rationale": "External visibility and catalogue purpose must be compared with business ownership and delegation requirements.",
        "outcomes": ["catalogue design approved", "catalogue visibility or lifecycle concern", "further evidence required"],
    },
    "graph_identity_baseline_entitlement_packages": {
        "question": "Do access-package purpose, catalogue placement and visibility match the approved access model?",
        "applicability": "One or more entitlement-management access packages exist.",
        "evidence_fields": ["displayName", "description", "isHidden", "catalog"],
        "rationale": "Package purpose and visibility depend on business roles, resource ownership and separation-of-duties requirements.",
        "outcomes": ["package metadata approved", "package purpose or visibility concern", "further evidence required"],
    },
    "graph_identity_baseline_identity_providers": {
        "question": "Are all configured external identity providers approved and required?",
        "applicability": "One or more external identity providers are configured.",
        "evidence_fields": ["@odata.type", "displayName", "clientId"],
        "rationale": "Graph can show configured providers but cannot determine whether the associated external trust is still authorised.",
        "outcomes": ["provider approved", "unexpected or obsolete provider", "further evidence required"],
    },
}

MANUAL_ASSESSMENT_ENDPOINTS = set(MANUAL_ASSESSMENT_DEFINITIONS)


# Inventories below remain available in the data viewer and collection-health
# accounting, but do not create a finding or an analyst task merely because no
# automated rule currently consumes them.
CONTEXT_ONLY_ENDPOINTS = {
    "arm_pim_azure_resource_assignment_instances",
    "arm_pim_azure_resource_eligibility_instances",
    "az_account_management-group_list_--no-register",
    "az_afd_profile_list",
    "az_appconfig_feature_list_--name_name_--all",
    "az_appconfig_kv_list_--name_name_--all",
    "az_appconfig_revision_list_--name_name_--all",
    "az_appconfig_snapshot_list_--name_name_--all",
    "az_appservice_ase_list-plans_--name_name",
    "az_appservice_plan_list",
    "az_appservice_plan_show_--name_name_--resource-group_resourcegroup",
    "az_appservice_vnet-integration_list_--resource-group_resourcegroup_--plan_name",
    "az_aro_list",
    "az_billing_account_list",
    "az_cdn_profile_list",
    "az_cognitiveservices_account_show_--name_name_--resource-group_resourcegroup",
    "az_cosmosdb_sql_role_definition_list_--account-name_name_--resource-group_resourcegroup",
    "az_consumption_usage_list",
    "az_deployment_group_list_--resource-group_name",
    "az_disk_show_--name_name_--resource-group_resourcegroup",
    "az_eventgrid_domain_show_--name_name_--resource-group_resourcegroup",
    "az_keyvault_private-link-resource_list_--vault-name_name_--resource-group_resourcegroup",
    "az_keyvault_show_--name_name_--resource-group_resourcegroup",
    "az_logicapp_list",
    "az_managedapp_list",
    "az_maps_account_list",
    "az_monitor_account_list",
    "az_monitor_action-group_list",
    "az_monitor_app-insights_web-test_list",
    "az_monitor_log-analytics_solution_list",
    "az_monitor_metrics_list-namespaces_--resource_id",
    "az_network_application-gateway_http-settings_list_--gateway-name_name_--resource-group_resourcegroup",
    "az_network_application-gateway_rule_list_--gateway-name_name_--resource-group_resourcegroup",
    "az_network_application-gateway_ssl-cert_list_--gateway-name_name_--resource-group_resourcegroup",
    "az_network_application-gateway_ssl-profile_list_--gateway-name_name_--resource-group_resourcegroup",
    "az_network_application-gateway_url-path-map_list_--gateway-name_name_--resource-group_resourcegroup",
    "az_network_express-route_list",
    "az_network_list-service-tags_--location_name",
    "az_network_nsg_rule_list_--nsg-name_name_--resource-group_resourcegroup",
    "az_network_nsg_show_--name_name_--resource-group_resourcegroup",
    "az_network_private-dns_zone_list",
    "az_network_private-endpoint_dns-zone-group_list_--endpoint-name_name_--resource-group_resourcegroup",
    "az_network_private-endpoint_ip-config_list_--endpoint-name_name_--resource-group_resourcegroup",
    "az_network_private-endpoint_list",
    "az_network_private-endpoint_show_--name_name_--resource-group_resourcegroup",
    "az_network_route-table_list_--resource-group_name",
    "az_network_vnet_list",
    "az_network_vnet_subnet_list_--resource-group_resourcegroup_--vnet-name_name",
    "az_policy_definition_show_--name_name",
    "az_policy_metadata_list",
    "az_policy_set-definition_list",
    "az_policy_set-definition_show_--name_name",
    "az_purview_account_list",
    "az_resource_show_--ids_id_--api-version_2024-11-01_--include-response-body_true",
    "az_rest_--method_get_--url_id_api-version_2025-11-01",
    "az_security_workspace-setting_list",
    "az_sql_db_list_--server_name_--resource-group_resourcegroup",
    "az_storage_blob_list_--account-name_storage_account_name_--container-name_container_name",
    "az_storage_container_list_--account-name_name_--auth-mode_login_--query_.container_name_name_storage_account_name_name_metadata_metadata_properties_properties",
    "az_ts_list",
    "az_vm_host_group_list",
    "az_vm_nic_list_--resource-group_resourcegroup_--vm-name_name",
    "az_vm_nic_show_--resource-group_resourcegroup_--vm-name_vm_name_--nic_id",
    "az_vm_secret_list_--resource-group_resourcegroup_--name_name",
    "az_webapp_vnet-integration_list_--name_name_--resource-group_resourcegroup",
    "graph_endpoint_intune_device_categories",
    "graph_endpoint_intune_intune_scope_tags",
    "graph_endpoint_intune_notification_templates",
    "graph_endpoint_intune_terms_conditions",
    "graph_identity_baseline_administrative_units",
    "graph_identity_baseline_credential_usage_report",
    "graph_identity_baseline_organisation",
    "graph_identity_baseline_report_settings",
    "graph_m365_audit_activity_exchange",
    "graph_m365_audit_activity_m365_web",
    "graph_m365_audit_activity_onedrive",
    "graph_m365_audit_activity_teams",
    "graph_m365_audit_audit_general",
    "graph_m365_audit_audit_onedrive",
    "graph_p_i_m_pim_directory_eligibility_instances",
    "graph_p_i_m_pim_group_eligibility_instances",
    "graph_p_i_m_pim_group_schedule_instances",
}


RETIRED_CATCH_ALL_MANUAL_ENDPOINTS = (
    CONTEXT_ONLY_ENDPOINTS
    | {
        "arm_pim_azure_resource_eligibility_requests",
        "arm_pim_azure_resource_eligibility_schedules",
        "az_batch_account_list",
        "az_datafactory_list",
        "az_functionapp_cors_show_--name_name_--resource-group_resourcegroup",
        "az_network_nic_show-effective-route-table_--ids_id",
        "graph_p_i_m_pim_alert_configurations",
        "graph_p_i_m_pim_directory_eligibility_requests",
        "graph_p_i_m_pim_directory_eligible",
        "graph_p_i_m_pim_directory_schedule_instances",
        "graph_p_i_m_pim_group_eligibility_requests",
        "graph_p_i_m_pim_group_eligible",
    }
)


def validate_manual_assessment_definitions() -> None:
    """Reject vague or malformed manual review declarations at import time."""
    required = {
        "question",
        "applicability",
        "evidence_fields",
        "rationale",
        "outcomes",
    }
    for endpoint_id, definition in MANUAL_ASSESSMENT_DEFINITIONS.items():
        if set(definition) != required:
            raise ValueError(
                f"Manual assessment definition {endpoint_id} has invalid fields"
            )
        for field in ("question", "applicability", "rationale"):
            if not isinstance(definition[field], str) or not definition[field].strip():
                raise ValueError(
                    f"Manual assessment definition {endpoint_id} has no {field}"
                )
        for field in ("evidence_fields", "outcomes"):
            values = definition[field]
            if (
                not isinstance(values, list)
                or not values
                or not all(isinstance(value, str) and value.strip() for value in values)
            ):
                raise ValueError(
                    f"Manual assessment definition {endpoint_id} has invalid {field}"
                )
        if len(definition["outcomes"]) < 2:
            raise ValueError(
                f"Manual assessment definition {endpoint_id} has no decision outcomes"
            )


validate_manual_assessment_definitions()


def endpoint_assessment_role(endpoint_id: Any) -> str:
    """Return the declared assessment relationship for a stable endpoint ID."""
    identifier = str(endpoint_id or "").casefold()
    if identifier in SUPPORTING_ONLY_ENDPOINTS:
        return SUPPORTING
    if identifier in MANUAL_ASSESSMENT_ENDPOINTS:
        return MANUAL
    if identifier in CONTEXT_ONLY_ENDPOINTS:
        return CONTEXT
    return AUTOMATED


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
                "review_definition": MANUAL_ASSESSMENT_DEFINITIONS[endpoint_id],
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
