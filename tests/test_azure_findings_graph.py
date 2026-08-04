#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later

import unittest

from azure_assess.findings_graph import evaluate_graph_findings


def result(title, severity, reason, evidence):
    return {"title": title, "severity": severity, "status": "finding" if evidence else "not_found", "reason": reason, "evidence": evidence}


def unsupported(title, severity, reason):
    return {"title": title, "severity": severity, "status": "no_data_to_assess", "reason": reason, "evidence": []}


def graph_manifest(*outputs):
    return {"schema_version": "2.5", "endpoint_runs": [
        {"category": "microsoft_graph", "endpoint_id": output, "status": "success"}
        for output in outputs
    ]}


def status_manifest(**statuses):
    return {"schema_version": "2.5", "endpoint_runs": [
        {"category": "microsoft_graph", "endpoint_id": output, "status": status}
        for output, status in statuses.items()
    ]}


class GraphFindingTests(unittest.TestCase):
    def test_positive_risk_and_passing_inventory(self):
        catalog = {
            "graph_identity_baseline_risk_detections_20260804.json": [
                {"id": "active", "riskState": "atRisk"},
                {"id": "closed", "riskState": "remediated"},
            ],
            "graph_identity_baseline_recommendations_20260804.json": [],
            "azure-collection-manifest.json": graph_manifest("graph_identity_baseline_risk_detections", "graph_identity_baseline_recommendations"),
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        by_title = {item["title"]: item for item in findings}
        self.assertEqual("finding", by_title["Active Microsoft Entra risk detections"]["status"])
        self.assertEqual(1, len(by_title["Active Microsoft Entra risk detections"]["evidence"]))
        self.assertEqual("not_found", by_title["Unresolved Microsoft Entra recommendations"]["status"])

    def test_missing_input_is_never_treated_as_proven_absence(self):
        findings, _ = evaluate_graph_findings({}, result, unsupported)
        self.assertEqual([], findings)

    def test_intune_absence_requires_both_complete_inventories(self):
        incomplete, _ = evaluate_graph_findings(
            {"graph_endpoint_intune_managed_devices_20260804.json": [{"id": "d"}], "azure-collection-manifest.json": graph_manifest("graph_endpoint_intune_managed_devices")}, result, unsupported
        )
        complete, _ = evaluate_graph_findings(
            {
                "graph_endpoint_intune_managed_devices_20260804.json": [{"id": "d"}],
                "graph_endpoint_intune_compliance_policies_20260804.json": [],
                "azure-collection-manifest.json": graph_manifest("graph_endpoint_intune_managed_devices", "graph_endpoint_intune_compliance_policies"),
            }, result, unsupported
        )
        title = "Applicable Intune estate has no compliance policy"
        self.assertEqual("no_data_to_assess", next(item for item in incomplete if item["title"] == title)["status"])
        self.assertEqual("finding", next(item for item in complete if item["title"] == title)["status"])

    def test_positive_hunting_result_is_local_to_affected_query(self):
        catalog = {
            "graph_defender_hunting_hunting_identity_recon_20260804.json": [{"DeviceName": "one"}],
            "graph_defender_hunting_hunting_remote_logon_20260804.json": [],
        }
        findings, sources = evaluate_graph_findings(catalog, result, unsupported)
        hunting = [item for item in findings if item["title"] == "Defender hunting query: Identity reconnaissance"]
        self.assertEqual(1, len(hunting))
        self.assertEqual(["graph_defender_hunting_hunting_identity_recon_20260804.json"], sources[hunting[0]["title"]])

    def test_only_active_pim_alerts_are_findings(self):
        catalog = {
            "graph_p_i_m_pim_alerts_20260804.json": [
                {"id": "active", "isActive": True, "incidentCount": 1},
                {"id": "inactive", "isActive": False, "incidentCount": 0},
            ],
            "azure-collection-manifest.json": graph_manifest("graph_p_i_m_pim_alerts"),
        }

        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        finding = next(
            item for item in findings
            if item["title"] == "Active privileged identity management alerts"
        )
        self.assertEqual("finding", finding["status"])
        self.assertEqual(["active"], [item["id"] for item in finding["evidence"]])

    def test_file_without_manifest_cannot_prove_a_pass(self):
        catalog = {
            "graph_identity_baseline_recommendations_20260804.json": [],
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        finding = next(
            item for item in findings
            if item["title"] == "Unresolved Microsoft Entra recommendations"
        )
        self.assertEqual("no_data_to_assess", finding["status"])

    def test_partial_inventory_supports_observed_risk_but_not_clean_result(self):
        catalog = {
            "graph_identity_baseline_risk_detections_20260804.json": [
                {"id": "risk", "riskState": "atRisk"},
            ],
            "graph_identity_baseline_recommendations_20260804.json": [],
            "azure-collection-manifest.json": status_manifest(
                graph_identity_baseline_risk_detections="incomplete",
                graph_identity_baseline_recommendations="incomplete",
            ),
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        by_title = {item["title"]: item for item in findings}
        self.assertEqual(
            "finding", by_title["Active Microsoft Entra risk detections"]["status"]
        )
        self.assertEqual(
            "no_data_to_assess",
            by_title["Unresolved Microsoft Entra recommendations"]["status"],
        )

    def test_repeated_endpoint_statuses_are_aggregated_conservatively(self):
        catalog = {
            "graph_identity_baseline_recommendations_20260804.json": [],
            "azure-collection-manifest.json": {
                "schema_version": "2.5",
                "endpoint_runs": [
                    {
                        "category": "microsoft_graph",
                        "endpoint_id": "graph_identity_baseline_recommendations",
                        "status": "success",
                    },
                    {
                        "category": "microsoft_graph",
                        "endpoint_id": "graph_identity_baseline_recommendations",
                        "status": "failed",
                    },
                ],
            },
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        finding = next(
            item for item in findings
            if item["title"] == "Unresolved Microsoft Entra recommendations"
        )
        self.assertEqual("no_data_to_assess", finding["status"])

    def test_mixed_endpoint_status_retains_directly_observed_evidence(self):
        catalog = {
            "graph_identity_baseline_risk_detections_20260804.json": [{
                "id": "observed", "riskState": "atRisk",
            }],
            "azure-collection-manifest.json": {
                "schema_version": "2.5",
                "endpoint_runs": [
                    {
                        "category": "microsoft_graph",
                        "endpoint_id": "graph_identity_baseline_risk_detections",
                        "status": "success",
                    },
                    {
                        "category": "microsoft_graph",
                        "endpoint_id": "graph_identity_baseline_risk_detections",
                        "status": "failed",
                    },
                ],
            },
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        finding = next(
            item for item in findings
            if item["title"] == "Active Microsoft Entra risk detections"
        )
        self.assertEqual("finding", finding["status"])
        self.assertEqual("observed", finding["evidence"][0]["id"])

    def test_failed_provisioning_activity_is_reported(self):
        catalog = {
            "graph_identity_baseline_provisioning_logs_20260804.json": [
                {"id": "failed", "statusInfo": {"status": "failure"}},
                {"id": "ok", "statusInfo": {"status": "success"}},
            ],
            "azure-collection-manifest.json": graph_manifest(
                "graph_identity_baseline_provisioning_logs"
            ),
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        finding = next(
            item for item in findings
            if item["title"] == "Unhealthy Microsoft Entra provisioning activity"
        )
        self.assertEqual(["failed"], [item["id"] for item in finding["evidence"]])

    def test_privileged_authentication_is_correlated_by_user_id(self):
        catalog = {
            "graph_identity_baseline_users_20260804.json": [
                {"id": "weak-user"}, {"id": "strong-user"},
            ],
            "graph_identity_baseline_directory_role_assignments_20260804.json": [
                {"principalId": "weak-user"}, {"principalId": "strong-user"},
            ],
            "graph_identity_baseline_user_registration_details_20260804.json": [
                {"id": "weak-user", "isMfaRegistered": True},
                {"id": "strong-user", "isMfaRegistered": True},
            ],
            "graph_identity_baseline_user_authentication_methods_20260804.json": [
                {
                    "id": "phone",
                    "@odata.type": "#microsoft.graph.phoneAuthenticationMethod",
                    "_collectionContext": {"parent_id": "weak-user"},
                },
                {
                    "id": "fido",
                    "@odata.type": "#microsoft.graph.fido2AuthenticationMethod",
                    "_collectionContext": {"parent_id": "strong-user"},
                },
            ],
            "azure-collection-manifest.json": graph_manifest(
                "graph_identity_baseline_users",
                "graph_identity_baseline_directory_role_assignments",
                "graph_identity_baseline_user_registration_details",
                "graph_identity_baseline_user_authentication_methods",
            ),
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        finding = next(
            item for item in findings
            if item["title"] == "Weak or missing privileged authentication methods"
        )
        self.assertEqual(
            ["weak-user"], [item["principalId"] for item in finding["evidence"]]
        )

    def test_permanent_group_and_azure_resource_assignments_are_reported(self):
        catalog = {
            "graph_p_i_m_pim_group_active_20260804.json": [
                {"id": "group", "scheduleInfo": {"expiration": {"type": "noExpiration"}}},
            ],
            "arm_pim_azure_resource_assignment_schedules_20260804.json": {
                "value": [{"id": "azure", "properties": {"expiration": {"type": "NoExpiration"}}}]
            },
            "azure-collection-manifest.json": status_manifest(
                graph_p_i_m_pim_group_active="success",
                arm_pim_azure_resource_assignment_schedules="success",
            ),
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        by_title = {item["title"]: item for item in findings}
        self.assertEqual(
            "finding", by_title["Permanent privileged group assignments"]["status"]
        )
        self.assertEqual(
            "finding",
            by_title["Permanent privileged Azure-resource assignments"]["status"],
        )

    def test_bitlocker_coverage_correlates_device_identifiers(self):
        catalog = {
            "graph_endpoint_intune_managed_devices_20260804.json": [
                {"id": "one", "azureADDeviceId": "device-one", "isEncrypted": True},
                {"id": "two", "azureADDeviceId": "device-two", "isEncrypted": True},
            ],
            "graph_endpoint_intune_bitlocker_key_metadata_20260804.json": [
                {"id": "key", "deviceId": "device-two"},
            ],
            "azure-collection-manifest.json": graph_manifest(
                "graph_endpoint_intune_managed_devices",
                "graph_endpoint_intune_bitlocker_key_metadata",
            ),
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        finding = next(
            item for item in findings
            if item["title"] == "Managed encrypted devices lack BitLocker recovery-key metadata coverage"
        )
        self.assertEqual(["one"], [item["id"] for item in finding["evidence"]])

    def test_intune_rbac_correlates_assignment_to_wildcard_custom_role(self):
        catalog = {
            "graph_endpoint_intune_intune_role_definitions_20260804.json": [{
                "id": "role-one",
                "isBuiltIn": False,
                "rolePermissions": [{"resourceActions": [{
                    "allowedResourceActions": ["Microsoft.Intune/*"],
                }]}],
            }],
            "graph_endpoint_intune_intune_role_assignments_20260804.json": [{
                "id": "assignment", "roleDefinitionId": "/roleDefinitions/role-one",
            }],
            "azure-collection-manifest.json": graph_manifest(
                "graph_endpoint_intune_intune_role_definitions",
                "graph_endpoint_intune_intune_role_assignments",
            ),
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        finding = next(
            item for item in findings
            if item["title"] == "Excessive Intune RBAC assignments"
        )
        self.assertEqual("assignment", finding["evidence"][0]["assignment"]["id"])

    def test_gsa_absence_requires_enabled_tenant_and_complete_control_inventory(self):
        catalog = {
            "graph_global_secure_access_gsa_tenant_status_20260804.json": [
                {"id": "tenant", "enabled": True},
            ],
            "graph_global_secure_access_gsa_filtering_policies_20260804.json": [],
            "azure-collection-manifest.json": graph_manifest(
                "graph_global_secure_access_gsa_tenant_status",
                "graph_global_secure_access_gsa_filtering_policies",
            ),
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        finding = next(
            item for item in findings
            if item["title"] == "Applicable Global Secure Access tenant has no filtering policy"
        )
        self.assertEqual("finding", finding["status"])

    def test_gsa_unlicensed_inventory_cannot_create_an_absence_finding(self):
        catalog = {
            "graph_global_secure_access_gsa_tenant_status_20260804.json": [],
            "graph_global_secure_access_gsa_filtering_policies_20260804.json": [],
            "azure-collection-manifest.json": status_manifest(
                graph_global_secure_access_gsa_tenant_status="tenant_unavailable",
                graph_global_secure_access_gsa_filtering_policies="tenant_unavailable",
            ),
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        finding = next(
            item for item in findings
            if item["title"] == "Applicable Global Secure Access tenant has no filtering policy"
        )
        self.assertEqual("no_data_to_assess", finding["status"])

    def test_stale_device_uses_manifest_assessment_time(self):
        catalog = {
            "graph_endpoint_intune_managed_devices_20260804.json": [{
                "id": "stale", "complianceState": "compliant",
                "lastSyncDateTime": "2026-06-01T00:00:00Z",
            }],
            "azure-collection-manifest.json": {
                **graph_manifest("graph_endpoint_intune_managed_devices"),
                "options": {"graph_lookback_end": "2026-08-04T00:00:00Z"},
            },
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        finding = next(
            item for item in findings
            if item["title"] == "Non-compliant or stale Intune managed devices"
        )
        self.assertEqual(["stale"], [item["id"] for item in finding["evidence"]])

    def test_anonymous_sharepoint_setting_is_reported(self):
        catalog = {
            "graph_m365_audit_settings_sharepoint_20260804.json": [{
                "id": "tenant", "defaultSharingLinkType": "anonymousAccess",
            }],
            "graph_m365_audit_settings_apps_services_20260804.json": [{}],
            "graph_m365_audit_settings_forms_20260804.json": [{}],
            "azure-collection-manifest.json": graph_manifest(
                "graph_m365_audit_settings_sharepoint",
                "graph_m365_audit_settings_apps_services",
                "graph_m365_audit_settings_forms",
            ),
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        finding = next(
            item for item in findings
            if item["title"] == "Unsafe Microsoft 365 sharing or tenant settings"
        )
        self.assertEqual("finding", finding["status"])
        self.assertEqual("tenant", finding["evidence"][0]["id"])

    def test_defender_health_and_significant_incidents_are_reported(self):
        catalog = {
            "graph_defender_hunting_defender_identity_sensors_20260804.json": [{
                "id": "sensor", "healthStatus": "unhealthy",
            }],
            "graph_defender_hunting_defender_identity_health_20260804.json": [],
            "graph_defender_hunting_security_incidents_20260804.json": [{
                "id": "incident", "severity": "high", "status": "active",
            }],
            "azure-collection-manifest.json": graph_manifest(
                "graph_defender_hunting_defender_identity_sensors",
                "graph_defender_hunting_defender_identity_health",
                "graph_defender_hunting_security_incidents",
            ),
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        by_title = {item["title"]: item for item in findings}
        self.assertEqual(
            "finding", by_title["Unhealthy Defender for Identity sensors"]["status"]
        )
        self.assertEqual(
            "finding",
            by_title["Unresolved significant Microsoft security incidents"]["status"],
        )

    def test_security_sensitive_identity_and_m365_activity_is_reported(self):
        catalog = {
            "graph_identity_baseline_sign_ins_20260804.json": [{
                "id": "legacy", "clientAppUsed": "IMAP",
                "status": {"errorCode": 0},
            }],
            "graph_identity_baseline_directory_audits_20260804.json": [{
                "id": "role-change", "activityDisplayName": "Add member to role",
            }],
            "graph_m365_audit_audit_exchange_20260804.json": [{
                "id": "inbox", "operation": "New-InboxRule",
                "auditData": (
                    '{"Parameters":[{"Name":"ForwardTo",'
                    '"Value":"external@example.invalid"}]}'
                ),
            }],
            "graph_m365_audit_audit_sharepoint_20260804.json": [{
                "id": "share", "operation": "AnonymousLinkCreated",
            }],
            "azure-collection-manifest.json": graph_manifest(
                "graph_identity_baseline_sign_ins",
                "graph_identity_baseline_directory_audits",
                "graph_m365_audit_audit_exchange",
                "graph_m365_audit_audit_sharepoint",
            ),
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        by_title = {item["title"]: item for item in findings}
        for title in (
            "Successful Microsoft Entra legacy-authentication sign-ins",
            "Security-sensitive Microsoft Entra directory changes",
            "Security-sensitive Exchange mailbox forwarding or delegation changes",
            "Anonymous or external SharePoint sharing activity",
        ):
            self.assertEqual("finding", by_title[title]["status"])

    def test_non_forwarding_exchange_changes_are_not_reported(self):
        catalog = {
            "graph_m365_audit_audit_exchange_20260804.json": [{
                "id": "ordinary-change",
                "operation": "Set-Mailbox",
                "auditData": (
                    '{"Parameters":[{"Name":"DisplayName","Value":"Example"}]}'
                ),
            }],
            "azure-collection-manifest.json": graph_manifest(
                "graph_m365_audit_audit_exchange"
            ),
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        finding = next(
            item for item in findings
            if item["title"] == (
                "Security-sensitive Exchange mailbox forwarding or delegation changes"
            )
        )
        self.assertEqual("not_found", finding["status"])

    def test_intune_and_gsa_direct_security_states_are_reported(self):
        catalog = {
            "graph_endpoint_intune_device_configurations_20260804.json": [{
                "id": "policy", "firewallEnabled": False,
            }],
            "graph_endpoint_intune_settings_catalog_20260804.json": [],
            "graph_endpoint_intune_security_connectors_20260804.json": [{
                "id": "connector", "partnerState": "unresponsive",
            }],
            "graph_global_secure_access_gsa_branches_20260804.json": [{
                "id": "branch", "connectivityState": "error",
            }],
            "graph_global_secure_access_gsa_connectors_20260804.json": [],
            "graph_global_secure_access_gsa_forwarding_profiles_20260804.json": [{
                "id": "profile", "state": "enabled", "associations": [],
            }],
            "azure-collection-manifest.json": graph_manifest(
                "graph_endpoint_intune_device_configurations",
                "graph_endpoint_intune_settings_catalog",
                "graph_endpoint_intune_security_connectors",
                "graph_global_secure_access_gsa_branches",
                "graph_global_secure_access_gsa_connectors",
                "graph_global_secure_access_gsa_forwarding_profiles",
            ),
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        by_title = {item["title"]: item for item in findings}
        for title in (
            "Intune policy explicitly disables a core endpoint security control",
            "Intune security-service connectors are disabled or unhealthy",
            "Global Secure Access branches or connectors are unhealthy",
            "Enabled Global Secure Access forwarding profiles have no associations",
        ):
            self.assertEqual("finding", by_title[title]["status"])

    def test_settings_catalog_setting_is_assessed_from_fan_out_records(self):
        catalog = {
            "graph_endpoint_intune_device_configurations_20260804.json": [],
            "graph_endpoint_intune_settings_catalog_20260804.json": [{
                "id": "policy",
            }],
            "graph_endpoint_intune_settings_catalog_settings_20260804.json": [{
                "id": "setting",
                "settingInstance": {
                    "settingDefinitionId": (
                        "device_vendor_msft_policy_config_defender_"
                        "allowrealtimemonitoring"
                    ),
                    "choiceSettingValue": {
                        "value": (
                            "device_vendor_msft_policy_config_defender_"
                            "allowrealtimemonitoring_0"
                        ),
                    },
                },
                "_collectionContext": {"parent_id": "policy"},
            }],
            "azure-collection-manifest.json": graph_manifest(
                "graph_endpoint_intune_device_configurations",
                "graph_endpoint_intune_settings_catalog",
                "graph_endpoint_intune_settings_catalog_settings",
            ),
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        finding = next(
            item for item in findings
            if item["title"] == (
                "Intune policy explicitly disables a core endpoint security control"
            )
        )
        self.assertEqual("finding", finding["status"])
        self.assertEqual("setting", finding["evidence"][0]["id"])

    def test_settings_catalog_boolean_value_identifies_disabled_encryption(self):
        catalog = {
            "graph_endpoint_intune_device_configurations_20260804.json": [],
            "graph_endpoint_intune_settings_catalog_20260804.json": [{
                "id": "policy",
            }],
            "graph_endpoint_intune_settings_catalog_settings_20260804.json": [{
                "id": "setting",
                "settingInstance": {
                    "settingDefinitionId": (
                        "device_vendor_msft_policy_config_security_"
                        "requiredeviceencryption"
                    ),
                    "simpleSettingValue": {"value": False},
                },
                "_collectionContext": {"parent_id": "policy"},
            }],
            "azure-collection-manifest.json": graph_manifest(
                "graph_endpoint_intune_device_configurations",
                "graph_endpoint_intune_settings_catalog",
                "graph_endpoint_intune_settings_catalog_settings",
            ),
        }

        findings, _ = evaluate_graph_findings(catalog, result, unsupported)

        finding = next(
            item for item in findings
            if item["title"] == (
                "Intune policy explicitly disables a core endpoint security control"
            )
        )
        self.assertEqual("finding", finding["status"])
        self.assertEqual("setting", finding["evidence"][0]["id"])

    def test_permanent_privileged_request_is_reported(self):
        catalog = {
            "graph_p_i_m_pim_directory_requests_20260804.json": [{
                "id": "request", "status": "Provisioned",
                "scheduleInfo": {"expiration": {"type": "noExpiration"}},
            }],
            "azure-collection-manifest.json": graph_manifest(
                "graph_p_i_m_pim_directory_requests"
            ),
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        finding = next(
            item for item in findings
            if item["title"] == (
                "Privileged activation or assignment requests seek permanent access"
            )
        )
        self.assertEqual("finding", finding["status"])
        self.assertEqual("request", finding["evidence"][0]["id"])


if __name__ == "__main__":
    unittest.main()
