import unittest
from datetime import datetime, timezone

from azure_findings_correlation import (
    AnalysisInputs,
    CorrelationResult,
    DatasetSpec,
    arm_parent_scopes,
    canonical_arm_id,
    canonical_role_definition_id,
    collection_reference_time,
    index_records,
    merge_correlation_results,
    resolve_analysis_dataset,
)


class IdentifierTests(unittest.TestCase):
    def test_arm_ids_are_case_and_separator_insensitive(self):
        self.assertEqual(
            canonical_arm_id(" /SUBSCRIPTIONS/Sub-One//resourceGroups/RG-One/ "),
            "/subscriptions/sub-one/resourcegroups/rg-one",
        )

    def test_arm_parent_scopes_include_subscription_group_and_resource(self):
        resource_id = (
            "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
            "Microsoft.KeyVault/vaults/vault-one"
        )
        self.assertEqual(
            arm_parent_scopes(resource_id),
            [
                "/subscriptions/sub-one",
                "/subscriptions/sub-one/resourcegroups/rg-one",
                canonical_arm_id(resource_id),
            ],
        )

    def test_role_definition_ids_reduce_to_the_stable_guid(self):
        self.assertEqual(
            canonical_role_definition_id(
                "/subscriptions/sub-one/providers/Microsoft.Authorization/"
                "roleDefinitions/Role-Guid"
            ),
            "role-guid",
        )

    def test_index_records_preserves_duplicate_keys(self):
        records = [{"id": "ONE", "value": 1}, {"id": "one", "value": 2}]
        index = index_records(records, lambda item: item["id"])
        self.assertEqual([item["value"] for item in index["one"]], [1, 2])


class DatasetResolutionTests(unittest.TestCase):
    def manifest(self, status="success", endpoint_id="az_network_public-ip_list"):
        return {
            "completed_at": "2026-07-21T12:00:00Z",
            "endpoint_runs": [
                {"endpoint_id": endpoint_id, "status": status}
            ],
        }

    def catalog(self, payload, error=None):
        return {
            "az_network_public-ip_list": {
                "path": "/data/az_network_public-ip_list_20260721-120000.json",
                "data": payload,
                "error": error,
            },
            "azure-collection-manifest": {
                "path": "/data/azure-collection-manifest_20260721-120000.json",
                "data": self.manifest(),
                "error": None,
            },
        }

    def spec(self):
        return DatasetSpec(
            "public_ips",
            ("az_network_public-ip_list",),
            ("az_network_public-ip_list",),
        )

    def test_complete_dataset_supports_negative_conclusions(self):
        dataset = resolve_analysis_dataset(self.catalog([]), self.spec())
        self.assertEqual(dataset.state, "complete_empty")
        self.assertTrue(dataset.supports_negative_conclusion())

    def test_failed_endpoint_does_not_support_negative_conclusions(self):
        catalog = self.catalog([])
        catalog["azure-collection-manifest"]["data"] = self.manifest("failed")
        dataset = resolve_analysis_dataset(catalog, self.spec())
        self.assertEqual(dataset.state, "failed")
        self.assertFalse(dataset.supports_negative_conclusion())

    def test_records_from_partial_collection_support_positive_evidence_only(self):
        catalog = self.catalog([{"id": "public-ip-one"}])
        catalog["azure-collection-manifest"]["data"]["endpoint_runs"] = [
            {"endpoint_id": "az_network_public-ip-list", "status": "success"},
            {"endpoint_id": "az_network_public-ip-list-second", "status": "failed"},
        ]
        spec = DatasetSpec(
            "public_ips",
            ("az_network_public-ip-list", "az_network_public-ip-list-second"),
            ("az_network_public-ip-list", "az_network_public-ip-list-second"),
        )
        catalog["az_network_public-ip-list"] = catalog.pop(
            "az_network_public-ip_list"
        )
        inputs = AnalysisInputs(catalog, [spec])
        self.assertEqual(inputs.get("public_ips").state, "partial")
        self.assertEqual(inputs.conclusion_support(["public_ips"]), "positive_only")

    def test_alias_matching_is_exact_not_substring_based(self):
        catalog = self.catalog([{"id": "wanted"}])
        catalog["az_network_public-ip-list-extra"] = {
            "path": "/data/extra.json",
            "data": [{"id": "unexpected"}],
            "error": None,
        }
        dataset = resolve_analysis_dataset(catalog, self.spec())
        self.assertEqual([item["id"] for item in dataset.records], ["wanted"])

    def test_manifest_time_is_used_for_reproducible_age_checks(self):
        reference, source = collection_reference_time(self.manifest())
        self.assertEqual(reference, datetime(2026, 7, 21, 12, tzinfo=timezone.utc))
        self.assertEqual(source, "manifest.completed_at")

    def test_correlation_result_rejects_unknown_support(self):
        with self.assertRaisesRegex(ValueError, "Unsupported conclusion support"):
            CorrelationResult(conclusion_support="guessed")

    def test_merged_results_preserve_positive_evidence_but_not_false_negative_support(self):
        merged = merge_correlation_results(
            [
                CorrelationResult(
                    observations=[{"id": "one"}],
                    conclusion_support="positive_and_negative",
                ),
                CorrelationResult(conclusion_support="inconclusive"),
            ]
        )
        self.assertEqual(merged.observations, [{"id": "one"}])
        self.assertEqual(merged.conclusion_support, "positive_only")


if __name__ == "__main__":
    unittest.main()
