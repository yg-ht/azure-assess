import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from azure_findings_context import normalise_finding_context
from azure_findings_coverage import normalise_finding_coverage
from azure_findings_definitions import finding_definition
from azure_findings_reporting import normalise_finding_reporting
from azure_findings_review import apply_review_override
from azure_findings_triage import (
    TRIAGE_SCHEMA_VERSION,
    apply_findings_triage,
    load_baseline_findings,
    normalise_finding_triage,
    validate_finding_triage,
)


FINDINGS_MODULE_PATH = Path(__file__).with_name("azure-findings.py")
FINDINGS_SPEC = importlib.util.spec_from_file_location(
    "azure_findings_triage_tests",
    FINDINGS_MODULE_PATH,
)
azure_findings = importlib.util.module_from_spec(FINDINGS_SPEC)
FINDINGS_SPEC.loader.exec_module(azure_findings)


RESOURCE_ID = (
    "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
    "Microsoft.Storage/storageAccounts/account-one"
)


def triage_finding(
    status="found",
    evidence=None,
    run_id="run-current",
    subscription_id="sub-one",
    verified=True,
):
    if evidence is None:
        evidence = (
            [
                {
                    "id": RESOURCE_ID,
                    "name": "account-one",
                    "resourceGroup": "rg-one",
                    "type": "Microsoft.Storage/storageAccounts",
                    "publicAccess": "Blob",
                }
            ]
            if status == "found"
            else []
        )
    title = "Azure blob container permits public access"
    definition = finding_definition(title, "High")
    finding = {
        "finding_id": definition["finding_id"],
        "definition": definition,
        "title": title,
        "severity": "High",
        "status": status,
        "reason": "Public access is enabled.",
        "evidence_count": len(evidence),
        "evidence": evidence,
        "references": {
            "source_files": ["/tmp/az_storage_account_list.json"],
            "evidence_links": [],
        },
    }
    normalise_finding_reporting(finding)
    finding["reporting"]["provenance"] = {
        "attribution_precision": "finding_level",
        "collection_run": {
            "run_id": run_id,
            "status": "success" if verified else "partial",
            "tenant_id": "tenant-one",
            "subscription_id": subscription_id,
        },
        "source_datasets": [
            {
                "filename": "az_storage_account_list.json",
                "integrity_status": "verified" if verified else "not_recorded",
                "collection_statuses": ["success"] if verified else ["failed"],
            }
        ],
        "limitations": [],
    }
    normalise_finding_context(finding)
    normalise_finding_coverage(
        finding,
        catalog={
            "az_storage_account_list": {
                "path": "/tmp/az_storage_account_list.json",
                "error": None,
                "data": evidence,
            }
        },
    )
    apply_review_override(finding)
    return finding


def review_override(finding_id, severity=None):
    override = {
        "finding_id": finding_id,
        "disposition": "confirmed",
        "reviewer": "A. Tester",
        "reviewed_at": "2026-07-21T12:00:00Z",
        "notes": "Reviewed.",
    }
    if severity:
        override["contextual_severity"] = {
            "level": severity,
            "rationale": "Internet exposure affects production customer data.",
        }
    return override


class FindingGroupingAndDeduplicationTests(unittest.TestCase):
    def test_observations_are_grouped_by_assets_and_exact_duplicates_are_retained(self):
        evidence = {
            "id": RESOURCE_ID,
            "name": "account-one",
            "resourceGroup": "rg-one",
            "type": "Microsoft.Storage/storageAccounts",
            "publicAccess": "Blob",
        }
        finding = triage_finding(evidence=[dict(evidence), dict(evidence)])

        normalise_finding_triage(finding)

        triage = finding["triage"]
        self.assertEqual(triage["schema_version"], TRIAGE_SCHEMA_VERSION)
        groups = triage["grouping"]["observation_groups"]
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["observation_count"], 2)
        deduplication = triage["deduplication"]
        self.assertEqual(deduplication["status"], "duplicates_present")
        self.assertEqual(deduplication["original_observation_count"], 2)
        self.assertEqual(deduplication["unique_observation_count"], 1)
        self.assertEqual(deduplication["duplicate_observation_count"], 1)
        self.assertTrue(deduplication["evidence_retained"])
        self.assertEqual(len(finding["reporting"]["observations"]), 2)

    def test_report_group_is_shared_by_same_service_and_engagement_scope(self):
        first = triage_finding()
        second = triage_finding(evidence=[])

        normalise_finding_triage(first)
        normalise_finding_triage(second)

        self.assertEqual(
            first["triage"]["grouping"]["report_group_id"],
            second["triage"]["grouping"]["report_group_id"],
        )

    def test_fingerprint_is_stable_for_equivalent_asset_identity(self):
        first = triage_finding(run_id="run-one")
        second = triage_finding(run_id="run-two")

        normalise_finding_triage(first)
        normalise_finding_triage(second)

        self.assertEqual(
            first["triage"]["fingerprint"]["value"],
            second["triage"]["fingerprint"]["value"],
        )


class ContextualSeverityTests(unittest.TestCase):
    def test_definition_severity_is_retained_without_analyst_override(self):
        finding = triage_finding()

        normalise_finding_triage(finding)

        severity = finding["triage"]["severity"]
        self.assertEqual(severity["default"], "High")
        self.assertEqual(severity["contextual"], "High")
        self.assertEqual(severity["source"], "definition")
        self.assertFalse(severity["changed"])
        self.assertEqual(
            severity["factors"]["exposure_attributes"]["public_access_levels"],
            ["Blob"],
        )

    def test_reviewed_contextual_severity_is_attributed_to_analyst(self):
        finding = triage_finding()
        apply_review_override(
            finding,
            review_override(finding["finding_id"], severity="Critical"),
        )

        normalise_finding_triage(finding)

        severity = finding["triage"]["severity"]
        self.assertEqual(severity["contextual"], "Critical")
        self.assertEqual(severity["source"], "analyst")
        self.assertTrue(severity["changed"])
        self.assertEqual(severity["analyst"]["reviewer"], "A. Tester")

    def test_legacy_lower_case_definition_severity_is_normalised(self):
        finding = triage_finding()
        finding["definition"]["default_severity"] = "high"

        normalise_finding_triage(finding)

        self.assertEqual(finding["triage"]["severity"]["default"], "High")


class FindingRetestTests(unittest.TestCase):
    def test_no_baseline_is_explicitly_not_assessed(self):
        finding = triage_finding()

        normalise_finding_triage(finding)

        retest = finding["triage"]["retest"]
        self.assertEqual(retest["comparison_status"], "not_requested")
        self.assertEqual(retest["outcome"], "not_assessed")

    def test_comparable_positive_finding_is_persistent(self):
        baseline = triage_finding(run_id="run-baseline")
        current = triage_finding(run_id="run-current")

        normalise_finding_triage(current, baseline=baseline)

        retest = current["triage"]["retest"]
        self.assertEqual(retest["outcome"], "persistent")
        self.assertTrue(retest["scope_match"])
        self.assertEqual(len(retest["asset_changes"]["persisting_asset_ids"]), 1)

    def test_persistent_finding_tracks_asset_level_changes(self):
        second_resource_id = RESOURCE_ID.replace("account-one", "account-two")
        baseline = triage_finding(
            run_id="run-baseline",
            evidence=[
                {"id": RESOURCE_ID, "name": "account-one"},
                {"id": second_resource_id, "name": "account-two"},
            ],
        )
        current = triage_finding(
            run_id="run-current",
            evidence=[{"id": RESOURCE_ID, "name": "account-one"}],
        )

        normalise_finding_triage(current, baseline=baseline)

        retest = current["triage"]["retest"]
        self.assertEqual(retest["outcome"], "persistent")
        self.assertEqual(len(retest["asset_changes"]["persisting_asset_ids"]), 1)
        self.assertEqual(
            len(retest["asset_changes"]["potentially_resolved_asset_ids"]),
            1,
        )

    def test_verified_non_detection_is_only_potentially_resolved(self):
        baseline = triage_finding(run_id="run-baseline")
        current = triage_finding(
            status="not_found",
            run_id="run-current",
            verified=True,
        )

        normalise_finding_triage(current, baseline=baseline)

        retest = current["triage"]["retest"]
        self.assertEqual(retest["outcome"], "potentially_resolved")
        self.assertTrue(retest["scope_match"])
        self.assertEqual(
            retest["asset_changes"]["potentially_resolved_asset_ids"],
            [baseline["reporting"]["assets"][0]["asset_id"]],
        )

    def test_incomplete_non_detection_is_inconclusive(self):
        baseline = triage_finding(run_id="run-baseline")
        current = triage_finding(
            status="not_found",
            run_id="run-current",
            verified=False,
        )

        normalise_finding_triage(current, baseline=baseline)

        self.assertEqual(current["triage"]["retest"]["outcome"], "inconclusive")

    def test_non_detection_without_coverage_is_inconclusive(self):
        baseline = triage_finding(run_id="run-baseline")
        current = triage_finding(
            status="not_found",
            run_id="run-current",
            verified=True,
        )
        current["coverage"]["status"] = "unavailable"
        current["coverage"]["denominator"]["value"] = None

        normalise_finding_triage(current, baseline=baseline)

        retest = current["triage"]["retest"]
        self.assertEqual(retest["outcome"], "inconclusive")
        self.assertTrue(any("coverage" in item for item in retest["rationale"]))

    def test_changed_engagement_scope_does_not_claim_resolution(self):
        baseline = triage_finding(
            run_id="run-baseline",
            subscription_id="sub-one",
        )
        current = triage_finding(
            status="not_found",
            run_id="run-current",
            subscription_id="sub-two",
        )

        normalise_finding_triage(current, baseline=baseline)

        self.assertEqual(current["triage"]["retest"]["outcome"], "scope_changed")
        self.assertFalse(current["triage"]["retest"]["scope_match"])
        self.assertEqual(
            current["triage"]["retest"]["asset_changes"],
            {
                "persisting_asset_ids": [],
                "new_asset_ids": [],
                "potentially_resolved_asset_ids": [],
            },
        )

    def test_same_collection_run_is_not_treated_as_a_retest(self):
        baseline = triage_finding(run_id="run-one")
        current = triage_finding(run_id="run-one")

        normalise_finding_triage(current, baseline=baseline)

        self.assertEqual(current["triage"]["retest"]["outcome"], "same_run")

    def test_new_positive_finding_is_identified(self):
        baseline = triage_finding(status="not_found", run_id="run-baseline")
        current = triage_finding(run_id="run-current")

        normalise_finding_triage(current, baseline=baseline)

        self.assertEqual(current["triage"]["retest"]["outcome"], "new")

    def test_direct_comparison_requires_matching_finding_ids(self):
        baseline = triage_finding(run_id="run-baseline")
        baseline["finding_id"] = "different_finding"
        current = triage_finding(run_id="run-current")

        with self.assertRaisesRegex(ValueError, "does not match current"):
            normalise_finding_triage(current, baseline=baseline)


class BaselineFileTests(unittest.TestCase):
    def test_flat_baseline_file_loads_by_canonical_finding_id(self):
        finding = triage_finding()
        payload = {"rows": [azure_findings.flat_rows([finding])[0]]}
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "baseline.json"
            path.write_text(json.dumps(payload), encoding="utf-8")

            baseline = load_baseline_findings(path)

        self.assertEqual(list(baseline), [finding["finding_id"]])

    def test_duplicate_baseline_ids_are_rejected(self):
        finding = triage_finding()
        row = azure_findings.flat_rows([finding])[0]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "baseline.json"
            path.write_text(json.dumps({"rows": [row, dict(row)]}), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "Duplicate baseline finding ID"):
                load_baseline_findings(path)

    def test_unknown_baseline_ids_are_rejected_during_application(self):
        finding = triage_finding()
        baseline = triage_finding()
        baseline["finding_id"] = "unknown_finding"

        with self.assertRaisesRegex(ValueError, "unknown finding IDs"):
            apply_findings_triage(
                [finding],
                baseline_findings={"unknown_finding": baseline},
            )

    def test_missing_definition_in_supplied_baseline_is_not_called_new(self):
        finding = triage_finding()

        apply_findings_triage([finding], baseline_findings={})

        retest = finding["triage"]["retest"]
        self.assertEqual(retest["comparison_status"], "baseline_missing")
        self.assertEqual(retest["outcome"], "not_assessed")
        self.assertIn("absent", retest["rationale"][0])

    def test_baseline_mapping_key_must_match_row_finding_id(self):
        finding = triage_finding()
        baseline = triage_finding()
        baseline["finding_id"] = "different_finding"

        with self.assertRaisesRegex(ValueError, "does not match its key"):
            apply_findings_triage(
                [finding],
                baseline_findings={finding["finding_id"]: baseline},
            )

    def test_relative_baseline_path_resolves_below_input_directory(self):
        path = azure_findings.resolve_baseline_path(
            Path("/tmp/current"),
            "previous/azure-findings-flat.json",
        )

        self.assertEqual(
            path,
            Path("/tmp/current/previous/azure-findings-flat.json"),
        )


class FindingTriageValidationTests(unittest.TestCase):
    def test_validation_rejects_observation_group_partition_mismatch(self):
        finding = triage_finding()
        normalise_finding_triage(finding)
        finding["triage"]["grouping"]["observation_groups"] = []

        with self.assertRaisesRegex(ValueError, "do not partition observations"):
            validate_finding_triage(finding)

    def test_validation_rejects_inconsistent_deduplication_count(self):
        finding = triage_finding()
        normalise_finding_triage(finding)
        finding["triage"]["deduplication"]["duplicate_observation_count"] = 1

        with self.assertRaisesRegex(ValueError, "counts are inconsistent"):
            validate_finding_triage(finding)


class FindingTriageIntegrationTests(unittest.TestCase):
    def test_flat_and_sarif_outputs_include_the_same_triage_metadata(self):
        finding = triage_finding()

        row = azure_findings.flat_rows([finding])[0]
        sarif = azure_findings.sarif_output("/tmp/input", {}, [finding])
        result = sarif["runs"][0]["results"][0]

        self.assertEqual(row["triage"]["severity"]["contextual"], "High")
        self.assertEqual(result["properties"]["triage"], row["triage"])

    def test_evaluation_adds_triage_to_every_finding(self):
        findings = azure_findings.evaluate_findings({})

        self.assertGreater(len(findings), 200)
        self.assertTrue(all("triage" in finding for finding in findings))

    def test_evaluation_accepts_prior_flat_rows_as_a_complete_baseline(self):
        baseline_findings = azure_findings.evaluate_findings({})
        baseline_rows = {
            row["finding_id"]: row
            for row in azure_findings.flat_rows(baseline_findings)
        }

        current_findings = azure_findings.evaluate_findings(
            {},
            baseline_findings=baseline_rows,
        )

        self.assertTrue(
            all(
                finding["triage"]["retest"]["comparison_status"] == "compared"
                for finding in current_findings
            )
        )


if __name__ == "__main__":
    unittest.main()
