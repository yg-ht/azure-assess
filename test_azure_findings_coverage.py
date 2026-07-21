import importlib.util
import unittest
from pathlib import Path

from azure_findings_coverage import (
    COVERAGE_SCHEMA_VERSION,
    normalise_finding_coverage,
    validate_finding_coverage,
)
from azure_findings_definitions import finding_definition
from azure_findings_reporting import normalise_finding_reporting


FINDINGS_MODULE_PATH = Path(__file__).with_name("azure-findings.py")
FINDINGS_SPEC = importlib.util.spec_from_file_location(
    "azure_findings_coverage_tests",
    FINDINGS_MODULE_PATH,
)
azure_findings = importlib.util.module_from_spec(FINDINGS_SPEC)
FINDINGS_SPEC.loader.exec_module(azure_findings)


def resource(resource_id, name):
    return {
        "id": resource_id,
        "name": name,
        "resourceGroup": "rg-one",
        "type": "Microsoft.Storage/storageAccounts",
    }


def coverage_finding(evidence, status=None, source_file="az_storage_account_list.json"):
    title = "Azure blob container permits public access"
    definition = finding_definition(title, "High")
    finding = {
        "finding_id": definition["finding_id"],
        "definition": definition,
        "title": title,
        "severity": "High",
        "status": status or ("found" if evidence else "not_found"),
        "reason": "Public access is enabled.",
        "evidence_count": len(evidence),
        "evidence": evidence,
        "references": {
            "source_files": [source_file] if source_file else [],
            "evidence_links": [],
        },
    }
    normalise_finding_reporting(finding)
    return finding


def source_catalog(source_file, records):
    return {
        "primary-source": {
            "path": source_file,
            "data": records,
            "error": None,
        }
    }


class FindingCoverageDenominatorTests(unittest.TestCase):
    def test_correlation_supplied_population_uses_check_specific_denominator(self):
        first = resource(
            "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
            "Microsoft.Storage/storageAccounts/account-one",
            "account-one",
        )
        second = resource(
            "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
            "Microsoft.Storage/storageAccounts/account-two",
            "account-two",
        )
        finding = coverage_finding([first])
        finding["_coverage_eligible_assets"] = [first, second]

        normalise_finding_coverage(finding)

        coverage = finding["coverage"]
        self.assertEqual(coverage["denominator"]["basis"], "check_specific_eligible_assets")
        self.assertEqual(coverage["denominator"]["value"], 2)
        self.assertEqual(coverage["affected_percentage"], 50.0)

    def test_unique_primary_assets_form_the_denominator(self):
        first = resource(
            "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
            "Microsoft.Storage/storageAccounts/account-one",
            "account-one",
        )
        second = resource(
            "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
            "Microsoft.Storage/storageAccounts/account-two",
            "account-two",
        )
        source_file = "az_storage_account_list.json"
        finding = coverage_finding([first], source_file=source_file)

        normalise_finding_coverage(
            finding,
            catalog=source_catalog(source_file, [first, second]),
            ordered_source_files=[source_file],
        )

        coverage = finding["coverage"]
        self.assertEqual(coverage["schema_version"], COVERAGE_SCHEMA_VERSION)
        self.assertEqual(coverage["status"], "proxy")
        self.assertEqual(coverage["denominator"]["value"], 2)
        self.assertEqual(coverage["denominator"]["unit"], "assets")
        self.assertEqual(coverage["affected"]["matched_denominator_assets"], 1)
        self.assertEqual(coverage["affected_percentage"], 50.0)

    def test_duplicate_primary_asset_records_are_counted_once(self):
        account = resource(
            "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
            "Microsoft.Storage/storageAccounts/account-one",
            "account-one",
        )
        source_file = "az_storage_account_list.json"
        finding = coverage_finding([account], source_file=source_file)

        normalise_finding_coverage(
            finding,
            catalog=source_catalog(source_file, [account, dict(account)]),
            ordered_source_files=[source_file],
        )

        self.assertEqual(finding["coverage"]["denominator"]["value"], 1)
        self.assertEqual(finding["coverage"]["affected_percentage"], 100.0)

    def test_unidentifiable_population_uses_a_record_denominator(self):
        source_file = "az_setting_list.json"
        finding = coverage_finding(
            [{"setting": "audit", "enabled": False}],
            source_file=source_file,
        )

        normalise_finding_coverage(
            finding,
            catalog=source_catalog(
                source_file,
                [
                    {"setting": "audit", "enabled": False},
                    {"setting": "logging", "enabled": True},
                ],
            ),
            ordered_source_files=[source_file],
        )

        coverage = finding["coverage"]
        self.assertEqual(coverage["denominator"]["value"], 2)
        self.assertEqual(coverage["denominator"]["unit"], "records")
        self.assertIsNone(coverage["affected"]["matched_denominator_assets"])
        self.assertIsNone(coverage["affected_percentage"])

    def test_unmatched_found_asset_does_not_produce_a_zero_percent_claim(self):
        source_asset = resource(
            "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
            "Microsoft.Storage/storageAccounts/account-one",
            "account-one",
        )
        different_asset = resource(
            "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
            "Microsoft.Storage/storageAccounts/account-two",
            "account-two",
        )
        source_file = "az_storage_account_list.json"
        finding = coverage_finding([different_asset], source_file=source_file)

        normalise_finding_coverage(
            finding,
            catalog=source_catalog(source_file, [source_asset]),
            ordered_source_files=[source_file],
        )

        coverage = finding["coverage"]
        self.assertIsNone(coverage["affected_percentage"])
        self.assertTrue(
            any("could not be matched" in item for item in coverage["limitations"])
        )

    def test_not_found_population_has_a_zero_percent_proxy(self):
        account = resource(
            "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
            "Microsoft.Storage/storageAccounts/account-one",
            "account-one",
        )
        source_file = "az_storage_account_list.json"
        finding = coverage_finding([], status="not_found", source_file=source_file)

        normalise_finding_coverage(
            finding,
            catalog=source_catalog(source_file, [account]),
            ordered_source_files=[source_file],
        )

        self.assertEqual(finding["coverage"]["affected_percentage"], 0.0)


class FindingCoverageAvailabilityTests(unittest.TestCase):
    def test_no_data_status_does_not_claim_assessment_coverage(self):
        source_file = "az_storage_account_list.json"
        finding = coverage_finding(
            [],
            status="no_data_to_assess",
            source_file=source_file,
        )

        normalise_finding_coverage(
            finding,
            catalog=source_catalog(source_file, []),
            ordered_source_files=[source_file],
        )

        self.assertEqual(finding["coverage"]["status"], "unavailable")
        self.assertIsNone(finding["coverage"]["affected_percentage"])

    def test_not_implemented_check_has_no_denominator(self):
        finding = coverage_finding([], status="not_implemented", source_file=None)

        normalise_finding_coverage(finding)

        self.assertEqual(finding["coverage"]["status"], "not_implemented")
        self.assertIsNone(finding["coverage"]["denominator"]["value"])

    def test_found_scope_without_source_uses_an_explicit_inferred_proxy(self):
        finding = coverage_finding(
            [{"eventType": "service_health"}],
            source_file=None,
        )

        normalise_finding_coverage(finding)

        coverage = finding["coverage"]
        self.assertEqual(coverage["status"], "proxy")
        self.assertEqual(coverage["denominator"]["value"], 1)
        self.assertEqual(coverage["denominator"]["unit"], "assessment_scopes")
        self.assertIsNone(coverage["affected_percentage"])

    def test_invalid_percentage_is_rejected(self):
        finding = coverage_finding(
            [{"eventType": "service_health"}],
            source_file=None,
        )
        normalise_finding_coverage(finding)
        finding["coverage"]["affected_percentage"] = 101

        with self.assertRaisesRegex(ValueError, "between zero and 100"):
            validate_finding_coverage(finding)


class FindingCoverageOutputTests(unittest.TestCase):
    def test_flat_and_sarif_outputs_include_coverage_without_removing_evidence(self):
        finding = coverage_finding(
            [{"eventType": "service_health"}],
            source_file=None,
        )

        row = azure_findings.flat_rows([finding])[0]
        sarif = azure_findings.sarif_output("/tmp/input", {}, [finding])
        result = sarif["runs"][0]["results"][0]

        self.assertEqual(row["evidence"], finding["evidence"])
        self.assertEqual(row["coverage"]["schema_version"], COVERAGE_SCHEMA_VERSION)
        self.assertEqual(result["properties"]["coverage"], row["coverage"])


if __name__ == "__main__":
    unittest.main()
