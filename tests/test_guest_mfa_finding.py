import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "azure-findings.py"
SPEC = importlib.util.spec_from_file_location("azure_findings_guest_mfa", MODULE_PATH)
azure_findings = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(azure_findings)


TITLE = "Active guest users without reported MFA capability"
USERS_ENDPOINT = "graph_identity_baseline_users"
REGISTRATIONS_ENDPOINT = "graph_identity_baseline_user_registration_details"


class GuestMfaFindingIntegrationTests(unittest.TestCase):
    def test_enabled_guest_without_reported_capability_is_found(self):
        finding = azure_findings.find_guest_users_present(
            [{
                "id": "guest-one",
                "userPrincipalName": "guest@example.com",
                "userType": "Guest",
                "accountEnabled": True,
            }],
            [{
                "id": "guest-one",
                "userPrincipalName": "different@example.com",
                "isMfaCapable": False,
            }],
        )

        self.assertEqual(finding["status"], "found")
        self.assertEqual(finding["title"], TITLE)
        self.assertEqual(finding["evidence"][0]["evidenceBasis"], "isMfaCapable_false")
        self.assertTrue(finding["evidence"][0]["registrationRecordFound"])

    def test_object_id_match_takes_precedence_over_changed_upn(self):
        finding = azure_findings.find_guest_users_present(
            [{
                "id": "guest-one",
                "userPrincipalName": "current@example.com",
                "userType": "Guest",
                "accountEnabled": True,
            }],
            [{
                "id": "guest-one",
                "userPrincipalName": "old@example.com",
                "isMfaCapable": True,
            }],
        )

        self.assertEqual(finding["status"], "not_found")

    def test_disabled_or_unknown_account_state_is_not_assessed(self):
        for account_enabled in (False, None):
            with self.subTest(account_enabled=account_enabled):
                finding = azure_findings.find_guest_users_present(
                    [{
                        "id": "guest-one",
                        "userPrincipalName": "guest@example.com",
                        "userType": "Guest",
                        "accountEnabled": account_enabled,
                    }],
                    [{"id": "guest-one", "isMfaCapable": False}],
                )

                self.assertEqual(finding["status"], "not_found")

    def test_missing_registration_is_only_evidence_when_inventory_is_complete(self):
        guest = [{
            "id": "guest-one",
            "userPrincipalName": "guest@example.com",
            "userType": "Guest",
            "accountEnabled": True,
        }]

        complete = azure_findings.find_guest_users_present(
            guest,
            [],
            registration_inventory_complete=True,
        )
        partial = azure_findings.find_guest_users_present(
            guest,
            [],
            registration_inventory_complete=False,
        )

        self.assertEqual(complete["status"], "found")
        self.assertEqual(
            complete["evidence"][0]["evidenceBasis"],
            "no_matching_registration_record",
        )
        self.assertEqual(partial["status"], "not_found")

    @staticmethod
    def catalog(registration_status, registrations=None, include_registration_file=True):
        users = [{
            "id": "guest-one",
            "displayName": "Guest One",
            "userPrincipalName": "guest@example.com",
            "userType": "Guest",
            "accountEnabled": True,
        }]
        catalog = {
            "graph_identity_baseline_users": {
                "path": "/data/graph_identity_baseline_users_20260805-120000.json",
                "data": users,
                "error": None,
            },
            "azure-collection-manifest_20260805-120000": {
                "path": "/data/azure-collection-manifest_20260805-120000.json",
                "data": {
                    "schema_version": "2.5",
                    "run_id": "guest-mfa-run",
                    "status": "success",
                    "endpoint_runs": [
                        {
                            "endpoint_id": USERS_ENDPOINT,
                            "category": "microsoft_graph",
                            "status": "success",
                            "result_count": 1,
                        },
                        {
                            "endpoint_id": REGISTRATIONS_ENDPOINT,
                            "category": "microsoft_graph",
                            "status": registration_status,
                            "result_count": len(registrations or []),
                        },
                    ],
                },
                "error": None,
            },
        }
        if include_registration_file:
            catalog["graph_identity_baseline_user_registration_details"] = {
                "path": (
                    "/data/graph_identity_baseline_user_registration_details_"
                    "20260805-120000.json"
                ),
                "data": registrations or [],
                "error": None,
            }
        return catalog

    @staticmethod
    def finding(catalog):
        return next(
            finding
            for finding in azure_findings.evaluate_findings(catalog)
            if finding["title"] == TITLE
        )

    def test_unavailable_registration_report_produces_no_data(self):
        finding = self.finding(self.catalog(
            "unauthorised",
            include_registration_file=False,
        ))

        self.assertEqual(finding["status"], "no_data_to_assess")
        self.assertEqual(finding["evidence_count"], 0)
        self.assertEqual(
            finding["reporting"]["provenance"]["insufficient_data"]["cause"],
            "unauthorised_source",
        )

    def test_partial_report_only_raises_explicit_negative_observations(self):
        missing_match = self.finding(self.catalog(
            "incomplete",
            registrations=[{
                "id": "another-user",
                "isMfaCapable": True,
            }],
        ))
        explicit_negative = self.finding(self.catalog(
            "incomplete",
            registrations=[{
                "id": "guest-one",
                "isMfaCapable": False,
            }],
        ))

        self.assertEqual(missing_match["status"], "no_data_to_assess")
        self.assertEqual(explicit_negative["status"], "found")
        self.assertEqual(
            explicit_negative["finding_id"],
            "entra_unauthenticated_guest_users_present",
        )

    def test_complete_empty_report_supports_missing_registration_observation(self):
        finding = self.finding(self.catalog(
            "empty",
            registrations=[],
            include_registration_file=False,
        ))

        self.assertEqual(finding["status"], "found")
        self.assertEqual(
            finding["evidence"][0]["evidenceBasis"],
            "no_matching_registration_record",
        )


if __name__ == "__main__":
    unittest.main()
