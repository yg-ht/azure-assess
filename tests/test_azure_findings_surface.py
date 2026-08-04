#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later

import unittest

from azure_assess.findings_surface import evaluate_collection_surface_findings


def result(title, severity, reason, evidence):
    return {
        "title": title, "severity": severity,
        "status": "finding" if evidence else "not_found",
        "reason": reason, "evidence": evidence,
    }


def unsupported(title, severity, reason):
    return {
        "title": title, "severity": severity, "status": "no_data_to_assess",
        "reason": reason, "evidence": [],
    }


def catalogue(datasets, **statuses):
    values = dict(datasets)
    values["azure-collection-manifest.json"] = {
        "schema_version": "2.5",
        "endpoint_runs": [
            {"endpoint_id": endpoint, "status": status, "category": "base"}
            for endpoint, status in statuses.items()
        ],
    }
    return values


class CollectionSurfaceFindingTests(unittest.TestCase):
    def test_threat_and_activity_observations_are_reported(self):
        data = catalogue({
            "az_security_alert_list_20260804.json": [{
                "id": "alert", "severity": "High", "status": "Active",
            }],
            "az_monitor_activity-log_list_20260804.json": [{
                "id": "change",
                "operationName": {
                    "value": "Microsoft.Authorization/roleAssignments/write",
                },
                "status": {"value": "Succeeded"},
            }],
        }, az_security_alert_list="success", **{
            "az_monitor_activity-log_list": "success",
        })
        findings, _ = evaluate_collection_surface_findings(
            data, result, unsupported
        )
        by_title = {item["title"]: item for item in findings}
        self.assertEqual(
            "finding",
            by_title["Unresolved significant Defender for Cloud alerts"]["status"],
        )
        self.assertEqual(
            "finding",
            by_title["Security-sensitive Azure control-plane changes"]["status"],
        )

    def test_waf_and_plaintext_listener_findings(self):
        waf_output = (
            "az_network_application-gateway_waf-config_show_--gateway-name_name_"
            "--resource-group_resourcegroup"
        )
        data = catalogue({
            f"{waf_output}_20260804.json": [{
                "id": "waf", "enabled": True, "firewallMode": "Detection",
            }],
            "az_network_application-gateway_list_20260804.json": [{
                "id": "gateway", "name": "gateway",
                "httpListeners": [{"id": "listener", "protocol": "Http"}],
                "requestRoutingRules": [{
                    "id": "rule", "httpListener": {"id": "listener"},
                    "backendAddressPool": {"id": "backend"},
                }],
            }],
        }, **{
            waf_output: "success",
            "az_network_application-gateway_list": "success",
        })
        findings, _ = evaluate_collection_surface_findings(
            data, result, unsupported
        )
        by_title = {item["title"]: item for item in findings}
        self.assertEqual(
            "finding",
            by_title[
                "Application Gateway WAF is disabled or not enforcing full prevention"
            ]["status"],
        )
        self.assertEqual(
            "finding",
            by_title["Application Gateway exposes plaintext HTTP listeners"]["status"],
        )

    def test_platform_security_settings_are_reported(self):
        vm_output = "az_vm_show_--name_name_--resource-group_resourcegroup"
        disk_output = "az_disk_list_--resource-group_name"
        data = catalogue({
            "az_appconfig_list_20260804.json": [{
                "id": "store", "publicNetworkAccess": "Enabled",
                "disableLocalAuth": False,
            }],
            "az_monitor_log-analytics_workspace_list_20260804.json": [{
                "id": "workspace", "publicNetworkAccessForQuery": "Enabled",
            }],
            f"{vm_output}_20260804.json": [{
                "id": "vm", "securityProfile": {
                    "securityType": "TrustedLaunch",
                    "uefiSettings": {
                        "secureBootEnabled": False, "vTpmEnabled": True,
                    },
                },
            }],
            f"{disk_output}_20260804.json": [{
                "id": "disk", "publicNetworkAccess": "Enabled",
                "networkAccessPolicy": "AllowAll",
            }],
            "az_snapshot_list_20260804.json": [],
        }, **{
            "az_appconfig_list": "success",
            "az_monitor_log-analytics_workspace_list": "success",
            vm_output: "success", disk_output: "success",
            "az_snapshot_list": "empty",
        })
        findings, _ = evaluate_collection_surface_findings(
            data, result, unsupported
        )
        by_title = {item["title"]: item for item in findings}
        for title in (
            "Azure App Configuration permits public network access",
            "Azure App Configuration permits local access-key authentication",
            "Log Analytics workspaces permit public query or ingestion",
            "Trusted Launch virtual machines disable Secure Boot or vTPM",
            "Managed disks or snapshots permit unrestricted network export",
        ):
            self.assertEqual("finding", by_title[title]["status"])

    def test_service_and_custom_role_findings(self):
        apim_output = "az_apim_show_--name_name_--resource-group_resourcegroup"
        data = catalogue({
            f"{apim_output}_20260804.json": [{
                "id": "apim", "identity": {"type": "None"},
                "customProperties": {
                    "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10": "True",
                },
            }],
            "az_eventhubs_namespace_list_20260804.json": [{
                "id": "hub", "disableLocalAuth": False,
                "publicNetworkAccess": "Enabled", "minimumTlsVersion": "1.1",
                "networkRuleSet": {"defaultAction": "Allow"},
            }],
            "az_role_definition_custom_list_20260804.json": [{
                "id": "/providers/Microsoft.Authorization/roleDefinitions/role",
                "permissions": [{"actions": ["*"]}],
            }],
            "az_role_assignment_list_20260804.json": [{
                "id": "assignment",
                "roleDefinitionId": (
                    "/providers/Microsoft.Authorization/roleDefinitions/role"
                ),
            }],
        }, **{
            apim_output: "success", "az_eventhubs_namespace_list": "success",
            "az_role_definition_custom_list": "success",
            "az_role_assignment_list": "success",
        })
        findings, _ = evaluate_collection_surface_findings(
            data, result, unsupported
        )
        by_title = {item["title"]: item for item in findings}
        for title in (
            "API Management permits deprecated TLS protocols",
            "API Management services lack a managed identity",
            "Azure messaging services permit local authentication",
            "Azure messaging services permit unrestricted public network access",
            "Azure messaging services permit deprecated TLS versions",
            "Assigned custom Azure roles contain wildcard permissions",
        ):
            self.assertEqual("finding", by_title[title]["status"])

    def test_redirect_only_gateway_listener_and_deny_default_namespace_are_safe(self):
        gateway_details = (
            "az_network_application-gateway_show_--name_name_"
            "--resource-group_resourcegroup"
        )
        data = catalogue({
            "az_network_application-gateway_list_20260804.json": [{
                "id": "gateway",
                "httpListeners": [{"id": "listener", "protocol": "Http"}],
                "requestRoutingRules": [{
                    "id": "redirect-rule",
                    "httpListener": {"id": "listener"},
                    "redirectConfiguration": {"id": "https-redirect"},
                }],
            }],
            f"{gateway_details}_20260804.json": [],
            "az_eventhubs_namespace_list_20260804.json": [{
                "id": "hub",
                "publicNetworkAccess": "Enabled",
                "networkRuleSet": {"defaultAction": "Deny"},
            }],
            "az_iot_hub_list_20260804.json": [],
            "az_relay_namespace_list_20260804.json": [],
            "az_servicebus_namespace_list_20260804.json": [],
            "az_signalr_list_20260804.json": [],
        }, **{
            "az_network_application-gateway_list": "success",
            gateway_details: "empty",
            "az_eventhubs_namespace_list": "success",
            "az_iot_hub_list": "empty",
            "az_relay_namespace_list": "empty",
            "az_servicebus_namespace_list": "empty",
            "az_signalr_list": "empty",
        })
        findings, _ = evaluate_collection_surface_findings(
            data, result, unsupported
        )
        by_title = {item["title"]: item for item in findings}
        self.assertEqual(
            "not_found",
            by_title["Application Gateway exposes plaintext HTTP listeners"]["status"],
        )
        self.assertEqual(
            "not_found",
            by_title[
                "Azure messaging services permit unrestricted public network access"
            ]["status"],
        )

    def test_attached_and_unattached_weak_waf_policies_are_distinct(self):
        inline_output = (
            "az_network_application-gateway_waf-config_show_--gateway-name_name_"
            "--resource-group_resourcegroup"
        )
        attached_id = (
            "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/"
            "ApplicationGatewayWebApplicationFirewallPolicies/attached"
        )
        unattached_id = attached_id.rsplit("/", 1)[0] + "/unattached"
        data = catalogue({
            f"{inline_output}_20260804.json": [],
            "az_network_application-gateway_waf-policy_list_20260804.json": [
                {
                    "id": attached_id,
                    "policySettings": {"state": "Enabled", "mode": "Detection"},
                },
                {
                    "id": unattached_id,
                    "policySettings": {"state": "Disabled", "mode": "Prevention"},
                },
            ],
            "az_network_application-gateway_list_20260804.json": [{
                "id": "gateway", "firewallPolicy": {"id": attached_id},
            }],
        }, **{
            inline_output: "failed",
            "az_network_application-gateway_waf-policy_list": "success",
            "az_network_application-gateway_list": "success",
        })
        findings, _ = evaluate_collection_surface_findings(
            data, result, unsupported
        )
        by_title = {item["title"]: item for item in findings}
        attached = by_title[
            "Application Gateway WAF is disabled or not enforcing full prevention"
        ]
        unattached = by_title[
            "Unattached Application Gateway WAF policies are not enforcing full prevention"
        ]
        self.assertEqual("finding", attached["status"])
        self.assertEqual("High", attached["severity"])
        self.assertEqual(attached_id, attached["evidence"][0]["policy"]["id"])
        self.assertEqual("finding", unattached["status"])
        self.assertEqual("Medium", unattached["severity"])
        self.assertEqual(unattached_id, unattached["evidence"][0]["id"])

    def test_publicly_disabled_disk_is_not_reported_when_policy_is_allow_all(self):
        disk_output = "az_disk_list_--resource-group_name"
        data = catalogue({
            f"{disk_output}_20260804.json": [{
                "id": "disk", "publicNetworkAccess": "Disabled",
                "networkAccessPolicy": "AllowAll",
            }],
            "az_snapshot_list_20260804.json": [],
        }, **{disk_output: "success", "az_snapshot_list": "empty"})
        findings, _ = evaluate_collection_surface_findings(
            data, result, unsupported
        )
        finding = next(
            item for item in findings
            if item["title"] == (
                "Managed disks or snapshots permit unrestricted network export"
            )
        )
        self.assertEqual("not_found", finding["status"])

    def test_monitor_network_and_action_group_findings(self):
        insights_output = (
            "az_monitor_app-insights_component_show_--app_name_"
            "--resource-group_resourcegroup"
        )
        data = catalogue({
            f"{insights_output}_20260804.json": [{
                "id": "insights", "publicNetworkAccessForIngestion": "Enabled",
            }],
            "az_monitor_metrics_alert_list_20260804.json": [{
                "id": "metric-alert", "enabled": True, "actions": [],
            }],
            "az_monitor_activity-log_alert_list_20260804.json": [],
            "az_monitor_scheduled-query_list_20260804.json": [],
        }, **{
            insights_output: "success",
            "az_monitor_metrics_alert_list": "success",
            "az_monitor_activity-log_alert_list": "empty",
            "az_monitor_scheduled-query_list": "empty",
        })
        findings, _ = evaluate_collection_surface_findings(
            data, result, unsupported
        )
        by_title = {item["title"]: item for item in findings}
        self.assertEqual(
            "finding",
            by_title["Application Insights permits public query or ingestion"]["status"],
        )
        self.assertEqual(
            "finding",
            by_title["Azure Monitor alert rules have no effective action group"]["status"],
        )

    def test_partial_or_missing_inputs_do_not_create_clean_conclusions(self):
        data = catalogue(
            {"az_security_alert_list_20260804.json": []},
            az_security_alert_list="incomplete",
        )
        findings, _ = evaluate_collection_surface_findings(
            data, result, unsupported
        )
        finding = next(
            item for item in findings
            if item["title"] == "Unresolved significant Defender for Cloud alerts"
        )
        self.assertEqual("no_data_to_assess", finding["status"])


if __name__ == "__main__":
    unittest.main()
