import importlib.util
import json
import unittest
from pathlib import Path

from azure_findings_context import normalise_finding_context
from azure_findings_coverage import normalise_finding_coverage
from azure_findings_definitions import finding_definition
from azure_findings_report import (
    REDACTION_MARKER,
    REPORT_READY_SCHEMA_VERSION,
    build_report_ready_output,
    redact_report_value,
    validate_report_ready_output,
)
from azure_findings_reporting import normalise_finding_reporting
from azure_findings_review import apply_review_override
from azure_findings_triage import normalise_finding_triage


STORAGE_TITLE = "Azure blob container permits public access"
IDENTITY_TITLE = "Privileged Microsoft Entra users do not have MFA"
RESOURCE_ID = (
    "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
    "Microsoft.Storage/storageAccounts/account-one"
)
FINDINGS_MODULE_PATH = Path(__file__).with_name("azure-findings.py")
FINDINGS_SPEC = importlib.util.spec_from_file_location(
    "azure_findings_report_tests",
    FINDINGS_MODULE_PATH,
)
azure_findings = importlib.util.module_from_spec(FINDINGS_SPEC)
FINDINGS_SPEC.loader.exec_module(azure_findings)


def report_test_finding(
    title=STORAGE_TITLE,
    evidence=None,
    status="found",
    duplicate=False,
):
    if evidence is None:
        evidence = [
            {
                "id": RESOURCE_ID,
                "name": "account-one",
                "resourceGroup": "rg-one",
                "type": "Microsoft.Storage/storageAccounts",
                "location": "uksouth",
                "publicAccess": "Blob",
            }
        ]
    if status != "found":
        evidence = []
    if duplicate:
        evidence = [dict(evidence[0]), dict(evidence[0])]
    definition = finding_definition(title, "High")
    finding = {
        "finding_id": definition["finding_id"],
        "definition": definition,
        "title": title,
        "severity": "High",
        "status": status,
        "reason": "Example evaluation reason.",
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
            "run_id": "run-current",
            "status": "success",
            "tenant_id": "tenant-one",
            "subscription_id": "sub-one",
        },
        "source_datasets": [
            {
                "filename": "az_storage_account_list.json",
                "integrity_status": "verified",
                "collection_statuses": ["success"],
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
    normalise_finding_triage(finding)
    return finding


def analyst_override(finding_id, disposition="confirmed"):
    return {
        "finding_id": finding_id,
        "disposition": disposition,
        "confidence": {
            "level": "high",
            "rationale": "The evidence was manually verified.",
        },
        "contextual_severity": {
            "level": "High",
            "rationale": "The default severity remains appropriate for this scope.",
        },
        "reviewer": "A. Tester",
        "reviewed_at": "2026-07-21T12:00:00Z",
        "notes": "Reviewed for report publication.",
    }


def apply_authored_review(finding):
    finding["definition"]["report"] = {
        "description": "The storage account permits public blob access.",
        "impact": "Unauthenticated users may retrieve exposed blob data.",
        "recommendation": "Disable public blob access and review existing containers.",
        "references": ["https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent"],
        "narrative_status": "authored",
    }
    apply_review_override(finding, analyst_override(finding["finding_id"]))
    normalise_finding_triage(finding)


class ReportRedactionTests(unittest.TestCase):
    def test_sensitive_names_values_and_signed_urls_are_redacted(self):
        payload = {
            "clientSecret": "secret-value",
            "secretName": "metadata-is-safe",
            "disablePasswordAuthentication": False,
            "genericJwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
            "connection": "Server=test;AccountKey=secret-value",
            "signedUrl": "https://example.test/blob?sv=1&sig=secret-value",
            "nested": {"functionKeys": {"default": "secret-value"}},
        }

        redacted, paths = redact_report_value(payload)

        self.assertEqual(redacted["clientSecret"], REDACTION_MARKER)
        self.assertEqual(redacted["secretName"], "metadata-is-safe")
        self.assertFalse(redacted["disablePasswordAuthentication"])
        self.assertEqual(redacted["genericJwt"], REDACTION_MARKER)
        self.assertEqual(redacted["connection"], REDACTION_MARKER)
        self.assertEqual(redacted["signedUrl"], REDACTION_MARKER)
        self.assertEqual(redacted["nested"]["functionKeys"], REDACTION_MARKER)
        self.assertIn("clientSecret", paths)

    def test_redaction_is_idempotent(self):
        first, first_paths = redact_report_value({"password": "secret-value"})
        second, second_paths = redact_report_value(first)

        self.assertEqual(first, second)
        self.assertEqual(first_paths, ["password"])
        self.assertEqual(second_paths, [])


class ReportSelectionTests(unittest.TestCase):
    def test_unreviewed_candidate_is_selected_by_default(self):
        candidate = report_test_finding()

        output = build_report_ready_output(
            "/tmp/assessment",
            [candidate],
            generated_at="2026-07-21T12:00:00Z",
        )

        self.assertEqual(output["schema_version"], REPORT_READY_SCHEMA_VERSION)
        self.assertTrue(output["selection_policy"]["include_candidates_by_default"])
        self.assertEqual(output["summary"]["findings_selected"], 1)
        self.assertEqual(output["summary"]["candidates_selected"], 1)
        record = output["findings"][0]
        self.assertEqual(record["workflow"]["disposition"], "candidate")
        self.assertTrue(record["workflow"]["selection"]["include"])
        self.assertIn(
            "analyst_review_required",
            record["workflow"]["publication"]["blockers"],
        )
        self.assertFalse(
            record["workflow"]["publication"]["ready_for_publication"]
        )

    def test_false_positive_is_excluded_with_audit_record(self):
        candidate = report_test_finding()
        false_positive = report_test_finding(
            title=IDENTITY_TITLE,
            evidence=[
                {
                    "id": "principal-one",
                    "userPrincipalName": "admin@example.test",
                }
            ],
        )
        apply_review_override(
            false_positive,
            analyst_override(false_positive["finding_id"], "false_positive"),
        )
        normalise_finding_triage(false_positive)

        output = build_report_ready_output(
            "/tmp/assessment",
            [candidate, false_positive],
            generated_at="2026-07-21T12:00:00Z",
        )

        self.assertEqual(
            [record["finding_id"] for record in output["findings"]],
            [candidate["finding_id"]],
        )
        self.assertEqual(output["excluded_findings"][0]["finding_id"], false_positive["finding_id"])
        self.assertEqual(output["excluded_findings"][0]["disposition"], "false_positive")

    def test_reviewed_authored_finding_can_be_publication_ready(self):
        finding = report_test_finding()
        apply_authored_review(finding)

        output = build_report_ready_output(
            "/tmp/assessment",
            [finding],
            generated_at="2026-07-21T12:00:00Z",
        )

        publication = output["findings"][0]["workflow"]["publication"]
        self.assertTrue(publication["ready_for_publication"])
        self.assertEqual(publication["blockers"], [])
        self.assertEqual(output["summary"]["ready_for_publication"], 1)


class ReportEvidenceTests(unittest.TestCase):
    def test_exact_duplicates_emit_one_canonical_observation_with_accounting(self):
        finding = report_test_finding(duplicate=True)

        output = build_report_ready_output(
            "/tmp/assessment",
            [finding],
            generated_at="2026-07-21T12:00:00Z",
        )

        evidence = output["findings"][0]["evidence"]
        self.assertEqual(evidence["original_observation_count"], 2)
        self.assertEqual(evidence["emitted_observation_count"], 1)
        self.assertEqual(evidence["duplicate_observation_count"], 1)
        self.assertEqual(len(evidence["duplicate_sets"]), 1)
        self.assertEqual(len(evidence["observations"]), 1)

    def test_sensitive_observation_values_are_redacted_and_recorded(self):
        finding = report_test_finding(
            evidence=[
                {
                    "id": RESOURCE_ID,
                    "name": "account-one",
                    "connectionString": "AccountKey=secret-value",
                    "secretName": "report-safe-name",
                }
            ]
        )

        output = build_report_ready_output(
            "/tmp/assessment",
            [finding],
            generated_at="2026-07-21T12:00:00Z",
        )

        observation = output["findings"][0]["evidence"]["observations"][0]
        self.assertEqual(observation["data"]["connectionString"], REDACTION_MARKER)
        self.assertEqual(observation["data"]["secretName"], "report-safe-name")
        self.assertIn("data.connectionString", observation["redactions"])
        self.assertNotIn("secret-value", json.dumps(output))

    def test_analyst_text_with_connection_secret_is_redacted_from_export(self):
        finding = report_test_finding()
        override = analyst_override(finding["finding_id"])
        override["notes"] = "Captured AccountKey=secret-value during validation."
        apply_review_override(finding, override)
        normalise_finding_triage(finding)

        output = build_report_ready_output(
            "/tmp/assessment",
            [finding],
            generated_at="2026-07-21T12:00:00Z",
        )

        record = output["findings"][0]
        self.assertEqual(record["workflow"]["analyst"]["notes"], REDACTION_MARKER)
        self.assertIn("workflow.analyst.notes", record["redactions"])
        self.assertIn(
            "report_content_redacted",
            record["workflow"]["publication"]["warnings"],
        )
        self.assertNotIn("secret-value", json.dumps(output))

    def test_redacted_required_narrative_blocks_publication(self):
        finding = report_test_finding()
        apply_authored_review(finding)
        finding["definition"]["report"]["impact"] = (
            "Validation captured AccountKey=secret-value in the exposed response."
        )

        output = build_report_ready_output(
            "/tmp/assessment",
            [finding],
            generated_at="2026-07-21T12:00:00Z",
        )

        record = output["findings"][0]
        publication = record["workflow"]["publication"]
        self.assertEqual(record["report"]["impact"], REDACTION_MARKER)
        self.assertFalse(publication["ready_for_publication"])
        self.assertIn("required_report_narrative_redacted", publication["blockers"])

    def test_output_is_json_serialisable_and_omits_legacy_raw_evidence(self):
        finding = report_test_finding()

        output = build_report_ready_output(
            "/tmp/assessment",
            [finding],
            generated_at="2026-07-21T12:00:00Z",
        )

        encoded = json.dumps(output)
        self.assertIn('"report_ready_findings"', encoded)
        self.assertNotIn('"evidence_count"', encoded)
        self.assertNotIn('"references": {"source_files"', encoded)


class ReportValidationTests(unittest.TestCase):
    def test_report_groups_partition_selected_findings(self):
        finding = report_test_finding()
        output = build_report_ready_output(
            "/tmp/assessment",
            [finding],
            generated_at="2026-07-21T12:00:00Z",
        )

        self.assertEqual(
            output["report_groups"][0]["finding_ids"],
            [finding["finding_id"]],
        )

    def test_validation_rejects_candidate_exclusion(self):
        finding = report_test_finding()
        output = build_report_ready_output(
            "/tmp/assessment",
            [finding],
            generated_at="2026-07-21T12:00:00Z",
        )
        output["findings"] = []
        output["report_groups"] = []
        output["excluded_findings"] = [
            {
                "finding_id": finding["finding_id"],
                "disposition": "candidate",
            }
        ]
        output["summary"]["findings_selected"] = 0
        output["summary"]["findings_excluded"] = 1
        output["summary"]["candidates_selected"] = 0
        output["summary"]["ready_for_publication"] = 0
        output["summary"]["requiring_work"] = 0
        output["summary"]["selected_by_contextual_severity"] = {}
        output["summary"]["selected_by_disposition"] = {}
        output["summary"]["selected_by_family"] = {}
        output["summary"]["excluded_by_disposition"] = {"candidate": 1}

        with self.assertRaisesRegex(ValueError, "selection conflicts"):
            validate_report_ready_output(output, source_findings=[finding])

    def test_validation_rejects_unredacted_sensitive_observation(self):
        finding = report_test_finding()
        output = build_report_ready_output(
            "/tmp/assessment",
            [finding],
            generated_at="2026-07-21T12:00:00Z",
        )
        observation = output["findings"][0]["evidence"]["observations"][0]
        observation["data"]["password"] = "secret-value"

        with self.assertRaisesRegex(ValueError, "unredacted sensitive data"):
            validate_report_ready_output(output)


class ReportPipelineIntegrationTests(unittest.TestCase):
    def test_evaluated_candidates_flow_into_report_ready_output(self):
        catalog = {
            "az_storage_account_list": {
                "path": "/tmp/az_storage_account_list.json",
                "error": None,
                "data": [
                    {
                        "id": RESOURCE_ID,
                        "name": "account-one",
                        "resourceGroup": "rg-one",
                        "type": "Microsoft.Storage/storageAccounts",
                        "allowBlobPublicAccess": True,
                    }
                ],
            }
        }

        findings = azure_findings.evaluate_findings(catalog)
        output = build_report_ready_output(
            "/tmp/assessment",
            findings,
            generated_at="2026-07-21T12:00:00Z",
        )

        selected_ids = {record["finding_id"] for record in output["findings"]}
        self.assertIn("storage_blob_public_access_level_is_disabled", selected_ids)
        self.assertGreater(output["summary"]["candidates_selected"], 0)
        self.assertNotIn(
            "candidate",
            {
                record["disposition"]
                for record in output["excluded_findings"]
            },
        )


if __name__ == "__main__":
    unittest.main()
