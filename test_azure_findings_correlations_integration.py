import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("azure-findings.py")
SPEC = importlib.util.spec_from_file_location("azure_findings_correlations", MODULE_PATH)
azure_findings = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(azure_findings)


SUBSCRIPTION = "/subscriptions/sub-one"
GROUP = f"{SUBSCRIPTION}/resourceGroups/rg-one"
STORAGE = f"{GROUP}/providers/Microsoft.Storage/storageAccounts/account-one"
PUBLIC_IP = f"{GROUP}/providers/Microsoft.Network/publicIPAddresses/ip-one"
NIC = f"{GROUP}/providers/Microsoft.Network/networkInterfaces/nic-one"
NSG = f"{GROUP}/providers/Microsoft.Network/networkSecurityGroups/nsg-one"


class OfflineCorrelationIntegrationTests(unittest.TestCase):
    def catalog(self):
        catalog = {}

        def add(name, data):
            catalog[name] = {
                "path": f"/data/{name}_20260721-120000.json",
                "data": data,
                "error": None,
            }

        add(
            "az_resource_list",
            [{"id": STORAGE, "name": "account-one", "type": "Microsoft.Storage/storageAccounts"}],
        )
        add("az_lock_list", [])
        add(
            "az_policy_state_list_--all",
            [
                {
                    "resourceId": STORAGE,
                    "policyAssignmentId": f"{SUBSCRIPTION}/providers/Microsoft.Authorization/policyAssignments/one",
                    "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/one",
                    "complianceState": "NonCompliant",
                    "timestamp": "2026-07-21T11:00:00Z",
                }
            ],
        )
        add(
            "az_advisor_recommendation_list",
            [
                {
                    "recommendationTypeId": "advisor-one",
                    "category": "Security",
                    "impact": "High",
                    "resourceMetadata": {"resourceId": STORAGE},
                    "shortDescription": {"problem": "Restrict network access"},
                }
            ],
        )
        add(
            "az_storage_account_list",
            [{"id": STORAGE, "name": "account-one", "publicNetworkAccess": "Enabled"}],
        )
        add(
            "az_network_private-endpoint-connection_list_--resource-group_resourcegroup_--resource-name_name_--type_microsoft.storage_storageaccounts",
            [
                {
                    "id": f"{STORAGE}/privateEndpointConnections/connection-one",
                    "privateEndpoint": {
                        "id": f"{GROUP}/providers/Microsoft.Network/privateEndpoints/pe-one"
                    },
                    "privateLinkServiceConnectionState": {"status": "Approved"},
                    "groupIds": ["blob"],
                    "provisioningState": "Succeeded",
                }
            ],
        )
        add(
            "az_network_public-ip_list",
            [{"id": PUBLIC_IP, "ipAddress": "198.51.100.10"}],
        )
        add(
            "az_network_nic_list",
            [
                {
                    "id": NIC,
                    "networkSecurityGroup": {"id": NSG},
                    "ipConfigurations": [
                        {"id": f"{NIC}/ipConfigurations/primary", "publicIPAddress": {"id": PUBLIC_IP}}
                    ],
                }
            ],
        )
        add(
            "az_network_nsg_list",
            [
                {
                    "id": NSG,
                    "securityRules": [
                        {
                            "name": "allow-ssh",
                            "priority": 100,
                            "direction": "Inbound",
                            "access": "Allow",
                            "protocol": "Tcp",
                            "sourceAddressPrefix": "Internet",
                            "destinationPortRange": "22",
                        }
                    ],
                }
            ],
        )
        endpoint_runs = [
            {"endpoint_id": name, "status": "success"}
            for name in catalog
        ]
        catalog["azure-collection-manifest"] = {
            "path": "/data/azure-collection-manifest_20260721-120000.json",
            "data": {
                "run_id": "20260721-120000",
                "status": "success",
                "started_at": "2026-07-21T11:00:00Z",
                "completed_at": "2026-07-21T12:00:00Z",
                "context": {"subscription_id": "sub-one", "tenant_id": "tenant-one"},
                "tool": {},
                "endpoint_runs": endpoint_runs,
                "datasets": [],
                "limitations": [],
            },
            "error": None,
        }
        return catalog

    def test_new_correlations_flow_through_the_complete_evaluator(self):
        findings = azure_findings.evaluate_findings(self.catalog())
        by_id = {finding["finding_id"]: finding for finding in findings}

        expected_found = {
            "resource_lock_critical_resource_delete_protection_missing",
            "policy_current_resource_non_compliance",
            "advisor_active_security_recommendation",
            "network_private_endpoint_public_exposure_remains",
            "network_external_attack_path_identified",
        }
        self.assertEqual(
            {finding_id for finding_id in expected_found if by_id[finding_id]["status"] == "found"},
            expected_found,
        )
        self.assertTrue(
            all(
                by_id[finding_id]["coverage"]["denominator"]["basis"]
                == "check_specific_eligible_assets"
                for finding_id in expected_found
            )
        )
        self.assertTrue(
            all(by_id[finding_id]["reporting"]["observations"] for finding_id in expected_found)
        )
        self.assertEqual(
            by_id["entra_non_human_identity_privileged_broad_scope_role"]["status"],
            "no_data_to_assess",
        )
        self.assertEqual(
            by_id["policy_required_security_assignment_missing"]["status"],
            "no_data_to_assess",
        )
        self.assertEqual(
            by_id["policy_evaluation_failure"]["status"],
            "no_data_to_assess",
        )

    def test_failed_lock_collection_does_not_create_absence_findings(self):
        catalog = self.catalog()
        for endpoint in catalog["azure-collection-manifest"]["data"]["endpoint_runs"]:
            if endpoint["endpoint_id"] == "az_lock_list":
                endpoint["status"] = "failed"
        findings = azure_findings.evaluate_findings(catalog)
        by_id = {finding["finding_id"]: finding for finding in findings}
        lock_finding = by_id[
            "resource_lock_critical_resource_delete_protection_missing"
        ]
        self.assertEqual(lock_finding["status"], "no_data_to_assess")
        self.assertEqual(lock_finding["evidence"], [])
        self.assertTrue(
            any("locks" in item for item in lock_finding["coverage"]["limitations"])
        )

    def test_failed_policy_assignment_collection_does_not_create_a_gap(self):
        catalog = self.catalog()
        catalog["az_policy_assignment_list"] = {
            "path": "/data/az_policy_assignment_list_20260721-120000.json",
            "data": [],
            "error": None,
        }
        catalog["azure-collection-manifest"]["data"]["endpoint_runs"].append(
            {"endpoint_id": "az_policy_assignment_list", "status": "failed"}
        )
        findings = azure_findings.evaluate_findings(catalog)
        by_id = {finding["finding_id"]: finding for finding in findings}
        assignment_finding = by_id["policy_required_security_assignment_missing"]
        self.assertEqual(assignment_finding["status"], "no_data_to_assess")
        self.assertEqual(assignment_finding["evidence"], [])


if __name__ == "__main__":
    unittest.main()
