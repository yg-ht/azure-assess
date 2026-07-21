import importlib.util
import unittest
from pathlib import Path

from azure_findings_definitions import (
    EXISTING_FINDING_HEADLINES,
    FINDING_DEFINITION_SCHEMA_VERSION,
    FINDING_DEFINITION_VERSION,
    FINDING_ID_OVERRIDES,
    canonical_finding_id,
    finding_definition,
    validate_finding_definitions,
)


FINDINGS_MODULE_PATH = Path(__file__).with_name("azure-findings.py")
FINDINGS_SPEC = importlib.util.spec_from_file_location(
    "azure_findings_definition_tests",
    FINDINGS_MODULE_PATH,
)
azure_findings = importlib.util.module_from_spec(FINDINGS_SPEC)
FINDINGS_SPEC.loader.exec_module(azure_findings)


class FindingDefinitionIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = azure_findings.evaluate_findings({})
        cls.by_title = {finding["title"]: finding for finding in cls.findings}

    def test_every_current_finding_has_a_unique_canonical_id(self):
        finding_ids = [finding["finding_id"] for finding in self.findings]

        self.assertEqual(len(finding_ids), 215)
        self.assertEqual(len(finding_ids), len(set(finding_ids)))
        self.assertTrue(all(finding_id == finding_id.lower() for finding_id in finding_ids))

    def test_every_current_finding_id_is_pinned(self):
        unpinned_titles = [
            finding["title"]
            for finding in self.findings
            if finding["title"] not in EXISTING_FINDING_HEADLINES
            and finding["title"] not in FINDING_ID_OVERRIDES
        ]

        self.assertEqual(unpinned_titles, [])

    def test_legacy_check_ids_are_retained_as_aliases(self):
        finding = self.by_title["Azure blob container permits public access"]

        self.assertEqual(
            finding["finding_id"],
            "storage_blob_public_access_level_is_disabled",
        )
        self.assertEqual(
            finding["definition"]["check_ids"],
            [
                "storage_blob_public_access_level_is_disabled",
                "storage_container_public_access_disabled",
            ],
        )

    def test_shared_legacy_aliases_no_longer_collide(self):
        resource_finding = self.by_title["Diagnostic Settings Not Configured"]
        subscription_finding = self.by_title[
            "Azure Subscription-level activity logs without a 'Diagnostic Setting' exist"
        ]

        self.assertNotEqual(
            resource_finding["finding_id"],
            subscription_finding["finding_id"],
        )
        self.assertEqual(
            resource_finding["definition"]["check_ids"],
            ["monitor_diagnostic_settings_exists"],
        )
        self.assertEqual(
            subscription_finding["definition"]["check_ids"],
            ["monitor_diagnostic_settings_exists"],
        )

    def test_unmapped_title_has_an_explicit_pinned_id(self):
        self.assertEqual(
            canonical_finding_id("Unauthenticated Guest Users Present in Azure AD"),
            "entra_unauthenticated_guest_users_present",
        )

    def test_definition_exposes_report_metadata_contract(self):
        definition = finding_definition("Example Azure finding", "Medium")

        self.assertEqual(
            definition["schema_version"],
            FINDING_DEFINITION_SCHEMA_VERSION,
        )
        self.assertEqual(definition["definition_version"], FINDING_DEFINITION_VERSION)
        self.assertEqual(definition["report_title"], "Example Azure finding")
        self.assertEqual(definition["default_severity"], "Medium")
        self.assertEqual(definition["category"], "Azure configuration")
        self.assertEqual(definition["report"]["narrative_status"], "not_authored")
        self.assertIsNone(definition["report"]["impact"])
        self.assertEqual(definition["report"]["references"], [])

    def test_duplicate_canonical_ids_are_rejected(self):
        definition = finding_definition(
            "Azure blob container permits public access",
            "High",
        )
        findings = [
            {
                "title": "First",
                "finding_id": definition["finding_id"],
                "definition": definition,
            },
            {
                "title": "Second",
                "finding_id": definition["finding_id"],
                "definition": definition,
            },
        ]

        with self.assertRaisesRegex(ValueError, "Duplicate canonical finding ID"):
            validate_finding_definitions(findings)

    def test_incomplete_report_contract_is_rejected(self):
        definition = finding_definition("Example Azure finding", "Medium")
        del definition["report"]["impact"]
        findings = [
            {
                "title": "Example Azure finding",
                "finding_id": definition["finding_id"],
                "definition": definition,
            }
        ]

        with self.assertRaisesRegex(ValueError, "report contract is incomplete"):
            validate_finding_definitions(findings)


class FindingDefinitionOutputTests(unittest.TestCase):
    def setUp(self):
        self.finding = {
            "title": "Azure blob container permits public access",
            "severity": "High",
            "status": "found",
            "reason": "Public blob access is enabled.",
            "evidence_count": 1,
            "evidence": [{"id": "resource-one"}],
            "references": {"source_files": [], "evidence_links": []},
        }

    def test_flat_output_adds_canonical_id_and_definition_to_legacy_finding(self):
        row = azure_findings.flat_rows([self.finding])[0]

        self.assertEqual(
            row["finding_id"],
            "storage_blob_public_access_level_is_disabled",
        )
        self.assertEqual(row["definition"]["category"], "Storage security")

    def test_sarif_uses_canonical_id_and_preserves_legacy_ids(self):
        output = azure_findings.sarif_output("/tmp/input", {}, [self.finding])
        run = output["runs"][0]
        rule = run["tool"]["driver"]["rules"][0]
        result = run["results"][0]

        self.assertEqual(rule["id"], self.finding["finding_id"])
        self.assertEqual(result["ruleId"], self.finding["finding_id"])
        self.assertEqual(
            rule["properties"]["headline_ids"],
            self.finding["definition"]["check_ids"],
        )
        self.assertEqual(
            rule["properties"]["definition"]["schema_version"],
            FINDING_DEFINITION_SCHEMA_VERSION,
        )
        self.assertEqual(
            result["properties"]["definition"]["schema_version"],
            FINDING_DEFINITION_SCHEMA_VERSION,
        )


if __name__ == "__main__":
    unittest.main()
