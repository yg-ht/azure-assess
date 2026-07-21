import unittest
from datetime import datetime, timezone

from azure_findings_identity import (
    analyse_application_credentials,
    analyse_privileged_non_human_identities,
    scope_level,
)


class IdentityPrivilegeTests(unittest.TestCase):
    def test_scope_levels_distinguish_broad_and_narrow_assignments(self):
        self.assertEqual(scope_level("/subscriptions/sub-one"), "subscription")
        self.assertEqual(
            scope_level("/subscriptions/sub-one/resourceGroups/rg-one"),
            "resource_group",
        )

    def test_privileged_service_principal_assignment_is_reported(self):
        non_human, groups = analyse_privileged_non_human_identities(
            applications=[{"id": "app-object", "appId": "app-one"}],
            service_principals=[
                {
                    "id": "principal-one",
                    "appId": "app-one",
                    "displayName": "Automation",
                    "servicePrincipalType": "Application",
                }
            ],
            managed_identities=[],
            groups=[],
            role_assignments=[
                {
                    "principalId": "principal-one",
                    "roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/owner",
                    "roleDefinitionName": "Owner",
                    "scope": "/subscriptions/sub-one",
                }
            ],
            role_definitions=[],
            conclusion_support="positive_and_negative",
        )
        self.assertEqual(non_human.observations[0]["identityKind"], "service_principal")
        self.assertEqual(groups.observations, [])

    def test_custom_wildcard_role_is_privileged(self):
        non_human, _ = analyse_privileged_non_human_identities(
            applications=[],
            service_principals=[{"id": "principal-one", "servicePrincipalType": "Application"}],
            managed_identities=[],
            groups=[],
            role_assignments=[
                {
                    "principalId": "principal-one",
                    "roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/custom-one",
                    "scope": "/subscriptions/sub-one",
                }
            ],
            role_definitions=[
                {"id": "/providers/Microsoft.Authorization/roleDefinitions/custom-one", "permissions": [{"actions": ["*"]}]}
            ],
            conclusion_support="positive_and_negative",
        )
        self.assertEqual(non_human.observations[0]["privilegedActions"], ["*"])

    def test_enriched_assignment_permissions_are_used_without_definition_record(self):
        non_human, _ = analyse_privileged_non_human_identities(
            applications=[],
            service_principals=[{"id": "principal-one"}],
            managed_identities=[],
            groups=[],
            role_assignments=[
                {
                    "principalId": "principal-one",
                    "roleDefinitionId": "custom-one",
                    "scope": "/subscriptions/sub-one",
                    "permissions": [
                        {"actions": ["Microsoft.Authorization/roleAssignments/*"]}
                    ],
                }
            ],
            role_definitions=[],
            conclusion_support="positive_and_negative",
        )
        self.assertEqual(
            non_human.observations[0]["privilegedActions"],
            ["microsoft.authorization/roleassignments/*"],
        )

    def test_service_specific_mutation_role_is_privileged_at_broad_scope(self):
        non_human, _ = analyse_privileged_non_human_identities(
            applications=[],
            service_principals=[{"id": "principal-one"}],
            managed_identities=[],
            groups=[],
            role_assignments=[
                {
                    "principalId": "principal-one",
                    "roleDefinitionId": "custom-one",
                    "scope": "/subscriptions/sub-one",
                }
            ],
            role_definitions=[
                {
                    "id": "custom-one",
                    "permissions": [
                        {"dataActions": ["Microsoft.KeyVault/vaults/secrets/write"]}
                    ],
                }
            ],
            conclusion_support="positive_and_negative",
        )
        self.assertEqual(
            non_human.observations[0]["privilegedActions"],
            ["microsoft.keyvault/vaults/secrets/write"],
        )

    def test_group_assignment_declares_membership_limitation(self):
        _, groups = analyse_privileged_non_human_identities(
            applications=[],
            service_principals=[],
            managed_identities=[],
            groups=[{"id": "group-one", "displayName": "Operators"}],
            role_assignments=[
                {
                    "principalId": "group-one",
                    "roleDefinitionName": "Contributor",
                    "scope": "/subscriptions/sub-one",
                }
            ],
            role_definitions=[],
            conclusion_support="positive_and_negative",
        )
        self.assertEqual(groups.observations[0]["identityKind"], "group")
        self.assertTrue(any("membership" in item for item in groups.limitations))


class CredentialExpiryTests(unittest.TestCase):
    REFERENCE = datetime(2026, 7, 21, 12, tzinfo=timezone.utc)

    def application(self, end):
        return {
            "id": "application-one",
            "appId": "app-one",
            "displayName": "Automation",
            "passwordCredentials": [
                {"keyId": "credential-one", "displayName": "deployment", "endDateTime": end}
            ],
        }

    def analyse(self, end):
        return analyse_application_credentials(
            [self.application(end)],
            [],
            self.REFERENCE,
            "manifest.completed_at",
            "positive_and_negative",
        )

    def test_expired_and_boundary_credentials_are_reported(self):
        self.assertEqual(
            self.analyse("2026-07-20T12:00:00Z").observations[0]["expiryStatus"],
            "expired",
        )
        self.assertEqual(
            self.analyse("2026-07-20T12:00:00Z").observations[0]["daysUntilExpiry"],
            -1.0,
        )
        self.assertEqual(
            self.analyse("2026-08-20T12:00:00Z").observations[0]["expiryStatus"],
            "expires_within_30_days",
        )

    def test_healthy_long_lived_credential_is_not_reported(self):
        self.assertEqual(self.analyse("2027-07-21T12:00:00Z").observations, [])

    def test_evidence_does_not_copy_credential_secret_values(self):
        application = self.application("2026-07-20T12:00:00Z")
        application["passwordCredentials"][0]["secretText"] = "do-not-copy"
        result = analyse_application_credentials(
            [application], [], self.REFERENCE, "manifest.completed_at", "positive_and_negative"
        )
        self.assertNotIn("do-not-copy", str(result.observations))


if __name__ == "__main__":
    unittest.main()
