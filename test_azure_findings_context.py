import importlib.util
import unittest
from pathlib import Path

from azure_findings_context import (
    CONTEXT_SCHEMA_VERSION,
    MAX_OBSERVATION_DEPTH,
    azure_path_parts,
    normalise_finding_context,
    validate_finding_context,
)
from azure_findings_definitions import finding_definition
from azure_findings_reporting import normalise_finding_reporting


FINDINGS_MODULE_PATH = Path(__file__).with_name("azure-findings.py")
FINDINGS_SPEC = importlib.util.spec_from_file_location(
    "azure_findings_context_tests",
    FINDINGS_MODULE_PATH,
)
azure_findings = importlib.util.module_from_spec(FINDINGS_SPEC)
FINDINGS_SPEC.loader.exec_module(azure_findings)


def context_finding(title, evidence, severity="Medium"):
    definition = finding_definition(title, severity)
    return {
        "finding_id": definition["finding_id"],
        "definition": definition,
        "title": title,
        "severity": severity,
        "status": "found" if evidence else "not_found",
        "reason": "Example reason.",
        "evidence_count": len(evidence),
        "evidence": evidence,
        "references": {"source_files": [], "evidence_links": []},
    }


def engagement_catalog():
    return {
        "azure-collection-manifest": {
            "path": "/tmp/azure-collection-manifest_run-one.json",
            "error": None,
            "data": {
                "schema_version": "1.0",
                "run_id": "run-one",
                "status": "success",
                "started_at": "2026-07-21T10:00:00Z",
                "completed_at": "2026-07-21T10:10:00Z",
                "context": {
                    "tenant_id": "tenant-one",
                    "subscription_id": "sub-one",
                },
                "tool": {},
                "limitations": [],
                "datasets": [],
                "endpoint_runs": [],
            },
        },
        "az_account_list": {
            "path": "/tmp/az_account_list_run-one.json",
            "error": None,
            "data": [
                {
                    "id": "sub-one",
                    "name": "Production subscription",
                    "tenantId": "tenant-one",
                    "state": "Enabled",
                    "isDefault": True,
                }
            ],
        },
    }


class AzurePathContextTests(unittest.TestCase):
    def test_nested_resource_id_extracts_scope_and_resource_type(self):
        identifier = (
            "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
            "Microsoft.Web/sites/app-one/slots/staging"
        )

        parts = azure_path_parts(identifier)

        self.assertEqual(parts["subscription_id"], "sub-one")
        self.assertEqual(parts["resource_group"], "rg-one")
        self.assertEqual(parts["resource_type"], "Microsoft.Web/sites/slots")

    def test_non_resource_identifier_has_no_azure_scope_parts(self):
        self.assertEqual(
            azure_path_parts("principal-one"),
            {
                "subscription_id": None,
                "resource_group": None,
                "resource_type": None,
            },
        )

    def test_extension_resource_uses_its_final_provider_type(self):
        identifier = (
            "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
            "Microsoft.Compute/virtualMachines/vm-one/providers/"
            "Microsoft.Insights/diagnosticSettings/default"
        )

        parts = azure_path_parts(identifier)

        self.assertEqual(
            parts["resource_type"],
            "Microsoft.Insights/diagnosticSettings",
        )


class FindingContextNormalisationTests(unittest.TestCase):
    def test_storage_context_combines_engagement_asset_and_family_fields(self):
        resource_id = (
            "/subscriptions/sub-one/resourceGroups/rg-storage/providers/"
            "Microsoft.Storage/storageAccounts/account-one"
        )
        finding = context_finding(
            "Azure blob container permits public access",
            [
                {
                    "id": resource_id,
                    "name": "account-one",
                    "resourceGroup": "rg-storage",
                    "type": "Microsoft.Storage/storageAccounts",
                    "location": "uksouth",
                    "publicAccess": "Blob",
                    "minimumTlsVersion": "TLS1_0",
                    "secretKey": "must-not-enter-context",
                }
            ],
            severity="High",
        )
        catalog = engagement_catalog()
        normalise_finding_reporting(finding, catalog=catalog)

        normalise_finding_context(finding, catalog=catalog)

        context = finding["context"]
        self.assertEqual(context["schema_version"], CONTEXT_SCHEMA_VERSION)
        self.assertEqual(context["family"]["id"], "storage_security")
        self.assertEqual(context["family"]["service_id"], "storage")
        self.assertEqual(context["scope"]["level"], "resource")
        self.assertEqual(context["scope"]["subscription_ids"], ["sub-one"])
        self.assertEqual(context["scope"]["resource_groups"], ["rg-storage"])
        self.assertEqual(
            context["scope"]["resource_types"],
            ["Microsoft.Storage/storageAccounts"],
        )
        self.assertEqual(context["scope"]["locations"], ["uksouth"])
        self.assertEqual(context["attributes"]["public_access_levels"], ["Blob"])
        self.assertEqual(context["attributes"]["minimum_tls_versions"], ["TLS1_0"])
        self.assertNotIn("secret", str(context).casefold())

        engagement = context["engagement"]
        self.assertEqual(engagement["tenant_ids"], ["tenant-one"])
        self.assertEqual(engagement["selected_subscription_id"], "sub-one")
        self.assertEqual(engagement["subscriptions"][0]["name"], "Production subscription")
        self.assertEqual(engagement["collection"]["run_id"], "run-one")
        self.assertTrue(engagement["sources"]["collection_manifest"])
        self.assertTrue(engagement["sources"]["subscription_inventory"])

    def test_entra_context_uses_tenant_scope_and_identity_fields(self):
        finding = context_finding(
            "Privileged Microsoft Entra users do not have MFA",
            [
                {
                    "id": "principal-one",
                    "displayName": "Example Administrator",
                    "userPrincipalName": "admin@example.test",
                    "userType": "Member",
                    "authenticationRequirement": "singleFactorAuthentication",
                }
            ],
            severity="High",
        )
        normalise_finding_reporting(finding)

        normalise_finding_context(finding)

        context = finding["context"]
        self.assertEqual(context["family"]["control_plane"], "microsoft_graph")
        self.assertEqual(context["family"]["service_id"], "entra_id")
        self.assertEqual(context["scope"]["level"], "tenant")
        self.assertEqual(context["attributes"]["principal_types"], ["Member"])
        self.assertEqual(
            context["attributes"]["principal_names"],
            ["admin@example.test"],
        )

    def test_parent_subscription_asset_does_not_make_resource_scope_mixed(self):
        finding = context_finding(
            "Azure blob container permits public access",
            [
                {
                    "id": (
                        "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
                        "Microsoft.Storage/storageAccounts/account-one"
                    ),
                    "subscriptionId": "sub-one",
                    "name": "account-one",
                }
            ],
        )
        normalise_finding_reporting(finding)

        normalise_finding_context(finding)

        self.assertEqual(finding["context"]["scope"]["level"], "resource")

    def test_longest_service_prefix_distinguishes_machine_learning(self):
        finding = context_finding(
            "Machine Learning workspaces allow public network access",
            [],
        )
        normalise_finding_reporting(finding)

        normalise_finding_context(finding)

        self.assertEqual(finding["context"]["family"]["service_id"], "machine_learning")

    def test_deep_observation_context_is_bounded_and_declares_limitation(self):
        nested = {"publicNetworkAccess": "Enabled"}
        for index in range(MAX_OBSERVATION_DEPTH + 2):
            nested = {f"level{index}": nested}
        finding = context_finding(
            "Machine Learning workspaces allow public network access",
            [nested],
        )
        normalise_finding_reporting(finding)

        normalise_finding_context(finding)

        self.assertIn(
            "Observation traversal was bounded while deriving finding context",
            finding["context"]["limitations"],
        )

    def test_missing_engagement_sources_are_explicit_limitations(self):
        finding = context_finding("Azure blob container permits public access", [])
        normalise_finding_reporting(finding)

        normalise_finding_context(finding)

        limitations = finding["context"]["limitations"]
        self.assertTrue(any("No collection manifest" in item for item in limitations))
        self.assertTrue(any("No tenant identity" in item for item in limitations))
        self.assertTrue(any("No subscription identity" in item for item in limitations))

    def test_empty_subscription_inventory_is_available_but_retains_selected_scope(self):
        finding = context_finding("Azure blob container permits public access", [])
        catalog = engagement_catalog()
        catalog["az_account_list"]["data"] = []
        normalise_finding_reporting(finding, catalog=catalog)

        normalise_finding_context(finding, catalog=catalog)

        engagement = finding["context"]["engagement"]
        self.assertTrue(engagement["sources"]["subscription_inventory"])
        self.assertEqual(
            [item["subscription_id"] for item in engagement["subscriptions"]],
            ["sub-one"],
        )

    def test_existing_collection_run_proves_manifest_source_without_catalog(self):
        finding = context_finding("Azure blob container permits public access", [])
        normalise_finding_reporting(finding, catalog=engagement_catalog())

        normalise_finding_context(finding)

        context = finding["context"]
        self.assertTrue(context["engagement"]["sources"]["collection_manifest"])
        self.assertFalse(context["engagement"]["sources"]["subscription_inventory"])
        self.assertFalse(any("No collection manifest" in item for item in context["limitations"]))


class FindingContextValidationTests(unittest.TestCase):
    def test_validation_rejects_duplicate_scope_values(self):
        finding = context_finding("Azure blob container permits public access", [])
        normalise_finding_reporting(finding)
        normalise_finding_context(finding)
        finding["context"]["scope"]["locations"] = ["UKSouth", "uksouth"]

        with self.assertRaisesRegex(ValueError, "contains duplicates"):
            validate_finding_context(finding)

    def test_validation_rejects_affected_asset_count_mismatch(self):
        finding = context_finding(
            "Azure blob container permits public access",
            [{"name": "account-one", "resourceGroup": "rg-one"}],
        )
        normalise_finding_reporting(finding)
        normalise_finding_context(finding)
        finding["context"]["scope"]["affected_asset_count"] += 1

        with self.assertRaisesRegex(ValueError, "does not match reporting assets"):
            validate_finding_context(finding)

    def test_validation_rejects_unapproved_family_attribute(self):
        finding = context_finding("Azure blob container permits public access", [])
        normalise_finding_reporting(finding)
        normalise_finding_context(finding)
        finding["context"]["attributes"]["secret_values"] = ["not-allowed"]

        with self.assertRaisesRegex(ValueError, "unsupported family attribute"):
            validate_finding_context(finding)

    def test_validation_requires_selected_subscription_in_inventory(self):
        finding = context_finding("Azure blob container permits public access", [])
        normalise_finding_reporting(finding)
        normalise_finding_context(finding)
        finding["context"]["engagement"]["selected_subscription_id"] = "sub-missing"

        with self.assertRaisesRegex(ValueError, "absent from subscriptions"):
            validate_finding_context(finding)

    def test_validation_rejects_family_metadata_that_conflicts_with_definition(self):
        finding = context_finding("Azure blob container permits public access", [])
        normalise_finding_reporting(finding)
        normalise_finding_context(finding)
        finding["context"]["family"]["service_id"] = "virtual_machines"

        with self.assertRaisesRegex(ValueError, "conflicts with its definition"):
            validate_finding_context(finding)


class FindingContextIntegrationTests(unittest.TestCase):
    def test_flat_and_sarif_outputs_include_the_same_context(self):
        finding = context_finding(
            "Azure blob container permits public access",
            [{"name": "account-one", "resourceGroup": "rg-one"}],
        )

        row = azure_findings.flat_rows([finding])[0]
        sarif = azure_findings.sarif_output("/tmp/input", {}, [finding])
        result = sarif["runs"][0]["results"][0]

        self.assertEqual(row["context"]["family"]["service_id"], "storage")
        self.assertEqual(result["properties"]["context"], row["context"])

    def test_every_evaluated_definition_has_specific_family_context(self):
        findings = azure_findings.evaluate_findings({})

        self.assertGreater(len(findings), 200)
        self.assertTrue(all("context" in finding for finding in findings))
        self.assertFalse(
            [
                finding["finding_id"]
                for finding in findings
                if finding["context"]["family"]["service_id"] == "azure"
            ]
        )


if __name__ == "__main__":
    unittest.main()
