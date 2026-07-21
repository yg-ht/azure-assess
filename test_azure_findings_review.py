import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from azure_findings_definitions import finding_definition
from azure_findings_review import (
    REVIEW_SCHEMA_VERSION,
    apply_review_override,
    apply_review_overrides,
    automated_confidence,
    load_review_overrides,
    validate_finding_review,
)


FINDINGS_MODULE_PATH = Path(__file__).with_name("azure-findings.py")
FINDINGS_SPEC = importlib.util.spec_from_file_location(
    "azure_findings_review_tests",
    FINDINGS_MODULE_PATH,
)
azure_findings = importlib.util.module_from_spec(FINDINGS_SPEC)
FINDINGS_SPEC.loader.exec_module(azure_findings)


def review_finding(status="found", integrity_status=None, run_status=None):
    title = "Azure blob container permits public access"
    definition = finding_definition(title, "High")
    evidence = [{"name": "account-one"}] if status == "found" else []
    source_datasets = []
    if integrity_status is not None:
        source_datasets.append(
            {
                "filename": "az_storage_account_list.json",
                "integrity_status": integrity_status,
                "collection_statuses": ["success"],
            }
        )
    return {
        "finding_id": definition["finding_id"],
        "definition": definition,
        "title": title,
        "severity": "High",
        "status": status,
        "reason": "Public access is enabled.",
        "evidence_count": len(evidence),
        "evidence": evidence,
        "reporting": {
            "schema_version": "1.0",
            "assets": [],
            "observations": [
                {
                    "observation_id": "obs_000000000000000000000000",
                    "asset_ids": [],
                    "data": evidence[0],
                    "source_files": [],
                    "reference_links": [],
                }
            ]
            if evidence
            else [],
            "provenance": {
                "attribution_precision": "finding_level",
                "collection_run": {"status": run_status} if run_status else None,
                "source_datasets": source_datasets,
                "limitations": [],
            },
        },
    }


def confirmed_override(finding_id):
    return {
        "finding_id": finding_id,
        "disposition": "confirmed",
        "confidence": {
            "level": "high",
            "rationale": "Evidence was manually verified in the Azure portal.",
        },
        "reviewer": "A. Tester",
        "reviewed_at": "2026-07-21T12:00:00Z",
        "notes": "Confirmed during analyst review.",
    }


class FindingReviewDefaultTests(unittest.TestCase):
    def test_found_finding_defaults_to_included_unreviewed_candidate(self):
        finding = review_finding()

        apply_review_override(finding)

        review = finding["review"]
        self.assertEqual(review["schema_version"], REVIEW_SCHEMA_VERSION)
        self.assertEqual(review["review_state"], "unreviewed")
        self.assertEqual(review["disposition"], "candidate")
        self.assertTrue(review["report_ready"]["include"])
        self.assertEqual(
            review["report_ready"]["basis"],
            "candidate_included_by_default",
        )

    def test_not_found_finding_requires_no_review_and_is_not_included(self):
        finding = review_finding(status="not_found")

        apply_review_override(finding)

        review = finding["review"]
        self.assertEqual(review["review_state"], "not_required")
        self.assertEqual(review["disposition"], "not_detected")
        self.assertEqual(review["confidence"]["level"], "not_assessed")
        self.assertFalse(review["report_ready"]["include"])

    def test_successful_verified_provenance_has_high_automated_confidence(self):
        finding = review_finding(
            integrity_status="verified",
            run_status="success",
        )

        confidence = automated_confidence(finding)

        self.assertEqual(confidence["level"], "high")
        self.assertEqual(confidence["source"], "automated")

    def test_missing_manifest_has_medium_automated_confidence(self):
        confidence = automated_confidence(review_finding())

        self.assertEqual(confidence["level"], "medium")
        self.assertTrue(any("No collection-run manifest" in item for item in confidence["rationale"]))

    def test_verified_dataset_without_endpoint_status_has_medium_confidence(self):
        finding = review_finding(
            integrity_status="verified",
            run_status="success",
        )
        finding["reporting"]["provenance"]["source_datasets"][0][
            "collection_statuses"
        ] = []

        confidence = automated_confidence(finding)

        self.assertEqual(confidence["level"], "medium")
        self.assertTrue(any("No collection endpoint status" in item for item in confidence["rationale"]))

    def test_integrity_mismatch_has_low_automated_confidence(self):
        finding = review_finding(
            integrity_status="mismatch",
            run_status="success",
        )

        confidence = automated_confidence(finding)

        self.assertEqual(confidence["level"], "low")
        self.assertTrue(any("mismatch" in item for item in confidence["rationale"]))


class FindingReviewOverrideTests(unittest.TestCase):
    def test_confirmed_override_records_analyst_decision_and_confidence(self):
        finding = review_finding()
        override = confirmed_override(finding["finding_id"])

        apply_review_override(finding, override)

        review = finding["review"]
        self.assertEqual(review["review_state"], "reviewed")
        self.assertEqual(review["disposition"], "confirmed")
        self.assertEqual(review["confidence"]["source"], "analyst")
        self.assertEqual(review["confidence"]["level"], "high")
        self.assertEqual(review["analyst"]["reviewer"], "A. Tester")
        self.assertTrue(review["report_ready"]["include"])

    def test_false_positive_override_excludes_finding_from_report_ready_output(self):
        finding = review_finding()
        override = {
            "finding_id": finding["finding_id"],
            "disposition": "false_positive",
            "reviewer": "A. Tester",
            "reviewed_at": "2026-07-21T12:00:00Z",
            "notes": "Compensating control verified.",
        }

        apply_review_override(finding, override)

        self.assertFalse(finding["review"]["report_ready"]["include"])
        self.assertEqual(
            finding["review"]["report_ready"]["basis"],
            "disposition_false_positive",
        )

    def test_unknown_override_ids_are_rejected(self):
        finding = review_finding()

        with self.assertRaisesRegex(ValueError, "unknown finding IDs"):
            apply_review_overrides(
                [finding],
                {
                    "unknown_finding": {
                        "finding_id": "unknown_finding",
                        "disposition": "confirmed",
                    }
                },
            )

    def test_invalid_review_timestamp_is_rejected(self):
        finding = review_finding()
        override = confirmed_override(finding["finding_id"])
        override["reviewed_at"] = "not-a-date"

        with self.assertRaisesRegex(ValueError, "ISO-8601 timestamp"):
            apply_review_override(finding, override)

    def test_review_timestamp_requires_a_timezone(self):
        finding = review_finding()
        override = confirmed_override(finding["finding_id"])
        override["reviewed_at"] = "2026-07-21T12:00:00"

        with self.assertRaisesRegex(ValueError, "include a timezone"):
            apply_review_override(finding, override)

    def test_review_override_requires_a_reviewer(self):
        finding = review_finding()
        override = confirmed_override(finding["finding_id"])
        override["reviewer"] = None

        with self.assertRaisesRegex(ValueError, "reviewer is required"):
            apply_review_override(finding, override)

    def test_review_validation_detects_conflicting_inclusion(self):
        finding = review_finding()
        apply_review_override(finding)
        finding["review"]["report_ready"]["include"] = False

        with self.assertRaisesRegex(ValueError, "conflicts with disposition"):
            validate_finding_review(finding)

    def test_review_validation_rejects_non_string_confidence_rationale(self):
        finding = review_finding()
        apply_review_override(finding)
        finding["review"]["confidence"]["rationale"] = [{"detail": "invalid"}]

        with self.assertRaisesRegex(ValueError, "rationale items must be strings"):
            validate_finding_review(finding)

    def test_review_validation_detects_conflicting_inclusion_basis(self):
        finding = review_finding()
        apply_review_override(finding)
        finding["review"]["report_ready"]["basis"] = "disposition_false_positive"

        with self.assertRaisesRegex(ValueError, "basis conflicts with disposition"):
            validate_finding_review(finding)


class FindingReviewFileTests(unittest.TestCase):
    def test_versioned_review_file_loads_by_canonical_id(self):
        finding = review_finding()
        payload = {
            "schema_version": REVIEW_SCHEMA_VERSION,
            "reviews": [confirmed_override(finding["finding_id"])],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            review_path = Path(tmpdir) / "reviews.json"
            review_path.write_text(json.dumps(payload), encoding="utf-8")

            overrides = load_review_overrides(review_path)

        self.assertEqual(list(overrides), [finding["finding_id"]])
        self.assertEqual(overrides[finding["finding_id"]]["disposition"], "confirmed")

    def test_duplicate_review_file_entries_are_rejected(self):
        finding = review_finding()
        review = confirmed_override(finding["finding_id"])
        payload = {
            "schema_version": REVIEW_SCHEMA_VERSION,
            "reviews": [review, dict(review)],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            review_path = Path(tmpdir) / "reviews.json"
            review_path.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "Duplicate review override"):
                load_review_overrides(review_path)

    def test_relative_review_path_resolves_below_input_directory(self):
        resolved = azure_findings.resolve_review_path(
            Path("/tmp/assessment"),
            "reviews/analyst.json",
        )

        self.assertEqual(
            resolved,
            Path("/tmp/assessment/reviews/analyst.json"),
        )


class FindingReviewOutputTests(unittest.TestCase):
    def test_flat_and_sarif_outputs_include_candidates_by_default(self):
        finding = review_finding()

        row = azure_findings.flat_rows([finding])[0]
        sarif = azure_findings.sarif_output("/tmp/input", {}, [finding])
        result = sarif["runs"][0]["results"][0]

        self.assertEqual(row["review"]["disposition"], "candidate")
        self.assertTrue(row["review"]["report_ready"]["include"])
        self.assertEqual(result["properties"]["review"], row["review"])

    def test_evaluation_applies_override_by_canonical_finding_id(self):
        finding_id = "storage_blob_public_access_level_is_disabled"
        source_path = "/tmp/az_storage_account_list.json"
        catalog = {
            "az_storage_account_list": {
                "path": source_path,
                "error": None,
                "data": [
                    {
                        "id": (
                            "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
                            "Microsoft.Storage/storageAccounts/account-one"
                        ),
                        "name": "account-one",
                        "resourceGroup": "rg-one",
                        "type": "Microsoft.Storage/storageAccounts",
                        "allowBlobPublicAccess": True,
                    }
                ],
            }
        }
        override = confirmed_override(finding_id)

        findings = azure_findings.evaluate_findings(
            catalog,
            review_overrides={finding_id: override},
        )

        finding = next(item for item in findings if item["finding_id"] == finding_id)
        self.assertEqual(finding["status"], "found")
        self.assertEqual(finding["review"]["disposition"], "confirmed")
        self.assertEqual(finding["review"]["review_state"], "reviewed")


if __name__ == "__main__":
    unittest.main()
