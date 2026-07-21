import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from azure_findings_definitions import finding_definition
from azure_findings_reporting import (
    REPORTING_SCHEMA_VERSION,
    normalise_finding_reporting,
    sha256_file,
    validate_finding_reporting,
)


FINDINGS_MODULE_PATH = Path(__file__).with_name("azure-findings.py")
FINDINGS_SPEC = importlib.util.spec_from_file_location(
    "azure_findings_reporting_tests",
    FINDINGS_MODULE_PATH,
)
azure_findings = importlib.util.module_from_spec(FINDINGS_SPEC)
FINDINGS_SPEC.loader.exec_module(azure_findings)


def example_finding(evidence, source_files=None):
    title = "Azure blob container permits public access"
    definition = finding_definition(title, "High")
    finding = {
        "finding_id": definition["finding_id"],
        "definition": definition,
        "title": title,
        "severity": "High",
        "status": "found" if evidence else "not_found",
        "reason": "Public access is enabled.",
        "evidence_count": len(evidence),
        "evidence": evidence,
        "references": {
            "source_files": list(source_files or []),
            "evidence_links": [],
        },
    }
    return finding


class FindingAssetAndObservationTests(unittest.TestCase):
    def test_nested_evidence_produces_resource_and_principal_assets(self):
        resource_id = (
            "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
            "Microsoft.Storage/storageAccounts/account-one"
        )
        evidence = {
            "id": resource_id,
            "name": "account-one",
            "resourceGroup": "rg-one",
            "type": "Microsoft.Storage/storageAccounts",
            "assignments": [
                {
                    "principalId": "principal-one",
                    "resolvedPrincipal": "Security Team",
                }
            ],
        }
        finding = example_finding([evidence])
        azure_findings.attach_references(finding, [])

        normalise_finding_reporting(finding)

        reporting = finding["reporting"]
        assets_by_kind = {asset["kind"]: asset for asset in reporting["assets"]}
        self.assertEqual(reporting["schema_version"], REPORTING_SCHEMA_VERSION)
        self.assertEqual(assets_by_kind["azure_resource"]["identifier"], resource_id)
        self.assertEqual(
            assets_by_kind["entra_principal"]["identifier"],
            "principal-one",
        )
        observation = reporting["observations"][0]
        self.assertEqual(set(observation["asset_ids"]), {
            assets_by_kind["azure_resource"]["asset_id"],
            assets_by_kind["entra_principal"]["asset_id"],
        })
        self.assertNotIn("_references", observation["data"])
        self.assertIn("_references", finding["evidence"][0])

    def test_observation_identity_is_independent_of_mapping_key_order(self):
        first = example_finding(
            [{"name": "account-one", "resourceGroup": "rg-one", "enabled": True}]
        )
        second = example_finding(
            [{"enabled": True, "resourceGroup": "rg-one", "name": "account-one"}]
        )

        normalise_finding_reporting(first)
        normalise_finding_reporting(second)

        self.assertEqual(
            first["reporting"]["observations"][0]["observation_id"],
            second["reporting"]["observations"][0]["observation_id"],
        )
        self.assertEqual(
            first["reporting"]["assets"][0]["asset_id"],
            second["reporting"]["assets"][0]["asset_id"],
        )

    def test_non_resource_evidence_uses_an_assessment_scope_asset(self):
        finding = example_finding(
            [{"eventType": "service_health", "description": "service health events"}]
        )

        normalise_finding_reporting(finding)

        asset = finding["reporting"]["assets"][0]
        self.assertEqual(asset["kind"], "assessment_scope")
        self.assertEqual(
            finding["reporting"]["observations"][0]["asset_ids"],
            [asset["asset_id"]],
        )

    def test_entra_user_prefers_object_id_over_user_principal_name(self):
        finding = example_finding(
            [
                {
                    "id": "user-object-one",
                    "name": "Example User",
                    "userPrincipalName": "user@example.test",
                }
            ]
        )

        normalise_finding_reporting(finding)

        self.assertEqual(len(finding["reporting"]["assets"]), 1)
        asset = finding["reporting"]["assets"][0]
        self.assertEqual(asset["kind"], "entra_principal")
        self.assertEqual(asset["identifier"], "user-object-one")
        self.assertEqual(asset["name"], "Example User")

    def test_non_mapping_legacy_evidence_remains_representable(self):
        finding = example_finding(["legacy evidence"])

        normalise_finding_reporting(finding)

        self.assertEqual(
            finding["reporting"]["observations"][0]["data"],
            {"value": "legacy evidence"},
        )

    def test_duplicate_evidence_items_receive_distinct_observation_ids(self):
        evidence = {"name": "account-one", "enabled": True}
        finding = example_finding([copy.deepcopy(evidence), copy.deepcopy(evidence)])

        normalise_finding_reporting(finding)

        observation_ids = [
            item["observation_id"]
            for item in finding["reporting"]["observations"]
        ]
        self.assertEqual(len(observation_ids), 2)
        self.assertEqual(len(set(observation_ids)), 2)

    def test_validation_rejects_unknown_observation_assets(self):
        finding = example_finding([{"name": "account-one"}])
        normalise_finding_reporting(finding)
        finding["reporting"]["observations"][0]["asset_ids"] = [
            "asset_000000000000000000000000"
        ]

        with self.assertRaisesRegex(ValueError, "unknown assets"):
            validate_finding_reporting(finding)


class FindingProvenanceTests(unittest.TestCase):
    def manifest_catalog(self, dataset_path, digest):
        return {
            "azure-collection-manifest": {
                "path": str(dataset_path.parent / "azure-collection-manifest_run-one.json"),
                "error": None,
                "data": {
                    "schema_version": "1.0",
                    "run_id": "run-one",
                    "status": "success",
                    "started_at": "2026-07-21T10:00:00Z",
                    "completed_at": "2026-07-21T10:05:00Z",
                    "context": {
                        "tenant_id": "tenant-one",
                        "subscription_id": "sub-one",
                        "client_secret": "do-not-copy",
                    },
                    "tool": {
                        "git_commit": "abc123",
                        "azure_cli_version": "2.75.0",
                        "access_token": "do-not-copy-either",
                    },
                    "limitations": [],
                    "endpoint_runs": [
                        {
                            "endpoint_id": "az_storage_account_list",
                            "status": "success",
                            "output_files": [dataset_path.name],
                        }
                    ],
                    "datasets": [
                        {
                            "dataset_id": dataset_path.stem,
                            "filename": dataset_path.name,
                            "record_count": 1,
                            "sha256": digest,
                            "size_bytes": dataset_path.stat().st_size,
                            "source_endpoint_id": "az_storage_account_list",
                        }
                    ],
                },
            }
        }

    def test_manifest_dataset_hash_and_collection_run_are_linked(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dataset_path = Path(tmpdir) / "az_storage_account_list_run-one.json"
            dataset_path.write_text(
                json.dumps([{"name": "account-one"}]),
                encoding="utf-8",
            )
            catalog = self.manifest_catalog(dataset_path, sha256_file(dataset_path))
            finding = example_finding(
                [{"name": "account-one"}],
                source_files=[str(dataset_path)],
            )

            normalise_finding_reporting(finding, catalog=catalog)

        provenance = finding["reporting"]["provenance"]
        self.assertEqual(
            provenance["source_datasets"][0]["integrity_status"],
            "verified",
        )
        self.assertEqual(provenance["collection_run"]["run_id"], "run-one")
        self.assertEqual(provenance["collection_run"]["tenant_id"], "tenant-one")
        self.assertEqual(
            provenance["source_datasets"][0]["collection_statuses"],
            ["success"],
        )
        self.assertEqual(provenance["limitations"], [])
        self.assertNotIn("do-not-copy", json.dumps(provenance))

    def test_manifest_hash_mismatch_is_an_explicit_limitation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dataset_path = Path(tmpdir) / "az_storage_account_list_run-two.json"
            dataset_path.write_text("[]", encoding="utf-8")
            catalog = self.manifest_catalog(dataset_path, "0" * 64)
            finding = example_finding(
                [{"name": "account-one"}],
                source_files=[str(dataset_path)],
            )

            normalise_finding_reporting(finding, catalog=catalog)

        provenance = finding["reporting"]["provenance"]
        self.assertEqual(
            provenance["source_datasets"][0]["integrity_status"],
            "mismatch",
        )
        self.assertIn("mismatch", provenance["limitations"][0])

    def test_partial_collection_run_is_an_explicit_limitation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dataset_path = Path(tmpdir) / "az_storage_account_list_run-three.json"
            dataset_path.write_text("[]", encoding="utf-8")
            catalog = self.manifest_catalog(dataset_path, sha256_file(dataset_path))
            catalog["azure-collection-manifest"]["data"]["status"] = "partial"
            finding = example_finding(
                [{"name": "account-one"}],
                source_files=[str(dataset_path)],
            )

            normalise_finding_reporting(finding, catalog=catalog)

        self.assertIn(
            "Collection run status was partial",
            finding["reporting"]["provenance"]["limitations"],
        )

    def test_catalog_enriches_reporting_created_by_a_legacy_helper(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dataset_path = Path(tmpdir) / "az_storage_account_list_run-four.json"
            dataset_path.write_text("[]", encoding="utf-8")
            catalog = self.manifest_catalog(dataset_path, sha256_file(dataset_path))
            finding = example_finding(
                [{"name": "account-one"}],
                source_files=[str(dataset_path)],
            )
            normalise_finding_reporting(finding)

            azure_findings.ensure_finding_reporting(finding, catalog=catalog)

        provenance = finding["reporting"]["provenance"]
        self.assertEqual(provenance["collection_run"]["run_id"], "run-one")
        self.assertEqual(
            provenance["source_datasets"][0]["integrity_status"],
            "verified",
        )

    def test_evaluation_pipeline_links_loaded_dataset_to_loaded_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            dataset_path = data_dir / "az_storage_account_list_20260721-100000.json"
            dataset_path.write_text(
                json.dumps(
                    [
                        {
                            "id": (
                                "/subscriptions/sub-one/resourceGroups/rg-one/"
                                "providers/Microsoft.Storage/storageAccounts/account-one"
                            ),
                            "name": "account-one",
                            "resourceGroup": "rg-one",
                            "type": "Microsoft.Storage/storageAccounts",
                            "allowBlobPublicAccess": True,
                        }
                    ]
                ),
                encoding="utf-8",
            )
            manifest_data = self.manifest_catalog(
                dataset_path,
                sha256_file(dataset_path),
            )["azure-collection-manifest"]["data"]
            manifest_path = data_dir / "azure-collection-manifest_20260721-100000.json"
            manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

            catalog = azure_findings.load_catalog(data_dir)
            findings = azure_findings.evaluate_findings(catalog)

        finding = next(
            item
            for item in findings
            if item["title"] == "Azure blob container permits public access"
        )
        self.assertEqual(finding["status"], "found")
        self.assertEqual(
            finding["reporting"]["provenance"]["collection_run"]["run_id"],
            "run-one",
        )
        self.assertEqual(
            finding["reporting"]["provenance"]["source_datasets"][0][
                "integrity_status"
            ],
            "verified",
        )
        self.assertEqual(finding["coverage"]["denominator"]["value"], 1)
        self.assertEqual(finding["coverage"]["affected_percentage"], 100.0)

    def test_older_collection_without_manifest_remains_supported(self):
        finding = example_finding(
            [{"name": "account-one"}],
            source_files=["az_storage_account_list_legacy.json"],
        )

        normalise_finding_reporting(finding)

        provenance = finding["reporting"]["provenance"]
        self.assertIsNone(provenance["collection_run"])
        self.assertEqual(
            provenance["source_datasets"][0]["integrity_status"],
            "manifest_unavailable",
        )
        self.assertTrue(
            any("No collection-run manifest" in item for item in provenance["limitations"])
        )


class FindingReportingOutputTests(unittest.TestCase):
    def test_flat_and_sarif_outputs_preserve_legacy_evidence_and_add_reporting(self):
        finding = example_finding([{"name": "account-one"}])
        original_evidence = copy.deepcopy(finding["evidence"])

        row = azure_findings.flat_rows([finding])[0]
        sarif = azure_findings.sarif_output("/tmp/input", {}, [finding])
        result = sarif["runs"][0]["results"][0]

        self.assertEqual(row["evidence"], original_evidence)
        self.assertEqual(row["reporting"]["schema_version"], REPORTING_SCHEMA_VERSION)
        self.assertEqual(
            result["properties"]["reporting"]["observations"],
            row["reporting"]["observations"],
        )


if __name__ == "__main__":
    unittest.main()
