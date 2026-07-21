import unittest

from azure_findings_governance import (
    analyse_advisor_defender,
    analyse_critical_resource_locks,
    analyse_expected_policy_assignments,
    analyse_policy_states,
)


SUBSCRIPTION = "/subscriptions/sub-one"
GROUP = f"{SUBSCRIPTION}/resourceGroups/rg-one"
VAULT = f"{GROUP}/providers/Microsoft.KeyVault/vaults/vault-one"


class ResourceLockTests(unittest.TestCase):
    def resource(self, resource_id=VAULT, resource_type="Microsoft.KeyVault/vaults"):
        return {"id": resource_id, "name": "vault-one", "type": resource_type}

    def lock(self, scope, level="CanNotDelete"):
        return {
            "id": f"{scope}/providers/Microsoft.Authorization/locks/protection",
            "level": level,
        }

    def test_resource_group_lock_protects_child_resource(self):
        result = analyse_critical_resource_locks(
            [self.resource()], [self.lock(GROUP)], "positive_and_negative"
        )
        self.assertEqual(result.observations, [])
        self.assertEqual(len(result.eligible_assets), 1)

    def test_sibling_lock_does_not_protect_resource(self):
        sibling = VAULT.replace("vault-one", "vault-two")
        result = analyse_critical_resource_locks(
            [self.resource()], [self.lock(sibling)], "positive_and_negative"
        )
        self.assertEqual(result.observations[0]["id"], VAULT)

    def test_readonly_lock_satisfies_delete_protection(self):
        result = analyse_critical_resource_locks(
            [self.resource()], [self.lock(VAULT, "ReadOnly")], "positive_and_negative"
        )
        self.assertEqual(result.observations, [])

    def test_non_profiled_resource_is_not_called_critical(self):
        result = analyse_critical_resource_locks(
            [self.resource(resource_type="Microsoft.Network/networkInterfaces")],
            [],
            "positive_and_negative",
        )
        self.assertEqual(result.eligible_assets, [])
        self.assertEqual(result.observations, [])

    def test_partial_lock_inventory_does_not_support_an_absence_finding(self):
        result = analyse_critical_resource_locks(
            [self.resource()], [], "positive_only"
        )
        self.assertEqual(result.observations, [])
        self.assertEqual(len(result.eligible_assets), 1)


class PolicyAssignmentTests(unittest.TestCase):
    DEFINITION_ID = "1f3afdf9-d0c9-4c3d-847f-89da613e70a8"

    def assignment(self, enforcement_mode="Default"):
        return {
            "id": f"{SUBSCRIPTION}/providers/Microsoft.Authorization/policyAssignments/security",
            "policyDefinitionId": (
                "/providers/Microsoft.Authorization/policySetDefinitions/"
                f"{self.DEFINITION_ID}"
            ),
            "enforcementMode": enforcement_mode,
        }

    def test_enforced_expected_assignment_satisfies_profile(self):
        result = analyse_expected_policy_assignments(
            [self.assignment()], ["sub-one"], "positive_and_negative"
        )
        self.assertEqual(result.observations, [])

    def test_missing_expected_assignment_is_reported(self):
        result = analyse_expected_policy_assignments(
            [], ["sub-one"], "positive_and_negative"
        )
        self.assertEqual(result.observations[0]["requirementId"], "microsoft_cloud_security_benchmark")

    def test_unknown_subscription_scope_is_inconclusive(self):
        result = analyse_expected_policy_assignments(
            [], [], "positive_and_negative"
        )
        self.assertEqual(result.observations, [])
        self.assertEqual(result.conclusion_support, "inconclusive")
        self.assertIn("No selected subscription ID", result.limitations[0])

    def test_do_not_enforce_does_not_satisfy_profile(self):
        result = analyse_expected_policy_assignments(
            [self.assignment("DoNotEnforce")],
            ["sub-one"],
            "positive_and_negative",
        )
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(
            result.observations[0]["nonEnforcedAssignmentIds"],
            [self.assignment()["id"]],
        )

    def test_partial_assignment_inventory_does_not_support_a_missing_finding(self):
        result = analyse_expected_policy_assignments(
            [], ["sub-one"], "inconclusive"
        )
        self.assertEqual(result.observations, [])
        self.assertEqual(len(result.eligible_assets), 1)

    def test_returned_management_group_assignment_satisfies_subscription(self):
        assignment = self.assignment()
        assignment["id"] = (
            "/providers/Microsoft.Management/managementGroups/group-one/providers/"
            "Microsoft.Authorization/policyAssignments/security"
        )
        result = analyse_expected_policy_assignments(
            [assignment], ["sub-one"], "positive_and_negative"
        )
        self.assertEqual(result.observations, [])

    def test_management_group_assignment_excluding_subscription_does_not_satisfy(self):
        assignment = self.assignment()
        assignment["id"] = (
            "/providers/Microsoft.Management/managementGroups/group-one/providers/"
            "Microsoft.Authorization/policyAssignments/security"
        )
        assignment["notScopes"] = [SUBSCRIPTION]
        result = analyse_expected_policy_assignments(
            [assignment], ["sub-one"], "positive_and_negative"
        )
        self.assertEqual(len(result.observations), 1)


class PolicyStateTests(unittest.TestCase):
    def state(self, compliance, timestamp, **extra):
        return {
            "resourceId": f"{GROUP}/providers/Microsoft.Storage/storageAccounts/account-one",
            "policyAssignmentId": f"{SUBSCRIPTION}/providers/Microsoft.Authorization/policyAssignments/one",
            "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/definition-one",
            "complianceState": compliance,
            "timestamp": timestamp,
            **extra,
        }

    def test_latest_state_wins(self):
        non_compliant, errors = analyse_policy_states(
            [
                self.state("NonCompliant", "2026-07-20T12:00:00Z"),
                self.state("Compliant", "2026-07-21T12:00:00Z"),
            ],
            "positive_and_negative",
        )
        self.assertEqual(non_compliant.observations, [])
        self.assertEqual(errors.observations, [])

    def test_current_non_compliance_is_reported(self):
        non_compliant, _ = analyse_policy_states(
            [self.state("NonCompliant", "2026-07-21T12:00:00Z")],
            "positive_and_negative",
        )
        self.assertEqual(non_compliant.observations[0]["complianceState"], "NonCompliant")

    def test_exempt_state_is_not_reported(self):
        non_compliant, _ = analyse_policy_states(
            [self.state("Exempt", "2026-07-21T12:00:00Z")],
            "positive_and_negative",
        )
        self.assertEqual(non_compliant.observations, [])

    def test_explicit_error_is_separate_from_non_compliance(self):
        non_compliant, errors = analyse_policy_states(
            [
                self.state(
                    "NonCompliant",
                    "2026-07-21T12:00:00Z",
                    errorCode="EvaluationTimeout",
                )
            ],
            "positive_and_negative",
        )
        self.assertEqual(non_compliant.observations, [])
        self.assertEqual(errors.observations[0]["evaluationError"], "EvaluationTimeout")

    def test_policy_event_can_supply_explicit_evaluation_error(self):
        _, errors = analyse_policy_states(
            [],
            "positive_and_negative",
            events=[self.state("Unknown", "2026-07-21T12:00:00Z", error="AliasNotFound")],
        )
        self.assertEqual(errors.observations[0]["evaluationError"], "AliasNotFound")

    def test_policy_error_support_can_include_event_completeness(self):
        non_compliant, errors = analyse_policy_states(
            [],
            "positive_and_negative",
            error_conclusion_support="inconclusive",
        )
        self.assertEqual(non_compliant.conclusion_support, "positive_and_negative")
        self.assertEqual(errors.conclusion_support, "inconclusive")


class AdvisorDefenderTests(unittest.TestCase):
    RESOURCE_ID = f"{GROUP}/providers/Microsoft.Compute/virtualMachines/vm-one"

    def advisor(self, title="Endpoint protection should be installed", category="Security"):
        return {
            "recommendationTypeId": "advisor-one",
            "category": category,
            "impact": "High",
            "resourceMetadata": {"resourceId": self.RESOURCE_ID},
            "shortDescription": {"problem": title, "solution": "Install protection"},
        }

    def defender(self, title="Endpoint protection should be installed", status="Unhealthy"):
        return {
            "name": "assessment-one",
            "properties": {
                "displayName": title,
                "status": {"code": status},
                "resourceDetails": {"id": self.RESOURCE_ID},
            },
        }

    def test_exact_resource_and_title_are_correlated(self):
        result = analyse_advisor_defender(
            [self.advisor()], [self.defender()], "positive_and_negative"
        )
        self.assertEqual(
            result.observations[0]["correlationMethod"],
            "exact_resource_and_title",
        )
        self.assertEqual(result.observations[0]["defenderStatus"], "unhealthy")

    def test_same_title_on_another_resource_is_not_correlated(self):
        defender = self.defender()
        defender["properties"]["resourceDetails"]["id"] = self.RESOURCE_ID.replace(
            "vm-one", "vm-two"
        )
        result = analyse_advisor_defender(
            [self.advisor()], [defender], "positive_and_negative"
        )
        self.assertEqual(result.observations[0]["correlationMethod"], "unmatched")

    def test_exact_control_identifier_takes_precedence_over_title(self):
        defender = self.defender("A different title")
        defender["name"] = "advisor-one"
        result = analyse_advisor_defender(
            [self.advisor()], [defender], "positive_and_negative"
        )
        self.assertEqual(
            result.observations[0]["correlationMethod"],
            "exact_resource_and_control_id",
        )

    def test_suppressed_and_non_security_recommendations_are_excluded(self):
        suppressed = self.advisor()
        suppressed["suppressionIds"] = ["suppression-one"]
        result = analyse_advisor_defender(
            [suppressed, self.advisor(category="Cost")],
            [],
            "positive_and_negative",
        )
        self.assertEqual(result.observations, [])

    def test_weak_text_similarity_does_not_suppress_unmatched_recommendation(self):
        result = analyse_advisor_defender(
            [self.advisor("Install endpoint protection")],
            [self.defender("Encrypt virtual machine disks")],
            "positive_and_negative",
        )
        self.assertEqual(result.observations[0]["correlationMethod"], "unmatched")


if __name__ == "__main__":
    unittest.main()
