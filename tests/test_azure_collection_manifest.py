import importlib.util
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from azure_assess.collection_manifest import (
    CollectionManifestRecorder,
    classify_execution_status,
    extract_azure_error_code,
    interpreted_visibility_status,
    result_item_count,
    sha256_file,
    truncate_error_text,
    validate_manifest,
)


COLLECT_MODULE_PATH = Path(__file__).resolve().parents[1] / "azure-collect.py"
COLLECT_SPEC = importlib.util.spec_from_file_location(
    "azure_collect_manifest_integration",
    COLLECT_MODULE_PATH,
)
azure_collect = importlib.util.module_from_spec(COLLECT_SPEC)
COLLECT_SPEC.loader.exec_module(azure_collect)


class CollectionManifestContentTests(unittest.TestCase):
    def test_manifest_preserves_all_context_and_diagnostic_content(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            command = "az login --password 'words with spaces' --tenant tenant-one"
            context = {
                "tenant_id": "tenant-one",
                "client_secret": "do-not-remove",
                "nested": {"accessToken": "token-value"},
            }
            recorder = CollectionManifestRecorder(
                "run-content",
                Path(tmpdir),
                context=context,
                options={"authorization": "Bearer token-value"},
                project_dir=Path(tmpdir),
            )
            recorder.record_execution(
                "Authentication",
                "setup",
                command,
                "2026-07-21T12:00:00Z",
                0.1,
                1,
                None,
                parameter_context={"password": "words with spaces"},
                error_message="Password: words with spaces; Authorization: Bearer token-value",
            )
            recorder.add_limitation("ClientSecret=do-not-remove")

            manifest = recorder.finish()

        self.assertEqual(manifest["context"], context)
        self.assertEqual(manifest["options"]["authorization"], "Bearer token-value")
        execution = manifest["endpoint_runs"][0]
        self.assertEqual(execution["command_template"], command)
        self.assertEqual(execution["parameter_context"]["password"], "words with spaces")
        self.assertEqual(
            execution["error"],
            "Password: words with spaces; Authorization: Bearer token-value",
        )
        self.assertEqual(manifest["limitations"], ["ClientSecret=do-not-remove"])

    def test_only_error_text_over_one_thousand_characters_is_truncated(self):
        exact = "s" * 1000
        oversized = "s" * 1001

        self.assertEqual(truncate_error_text(exact), exact)
        self.assertEqual(
            truncate_error_text(oversized),
            exact + "... [truncated]",
        )

    def test_permission_failures_are_classified_without_persisting_output(self):
        status = classify_execution_status(
            1,
            None,
            error_message="Command failed",
            diagnostic_text="AuthorizationFailed: principal does not have authorization",
        )

        self.assertEqual(status, "unauthorised")

        coded_status = classify_execution_status(
            1,
            None,
            diagnostic_text="(Authorization_RequestDenied) Access was rejected.",
        )

        self.assertEqual(coded_status, "unauthorised")

    def test_explicitly_unavailable_service_scope_is_not_applicable(self):
        status = classify_execution_status(
            1,
            None,
            error_message="Azure CLI request failed with return code 1",
            diagnostic_text=(
                "ERROR: network watcher is not enabled for region spaincentral."
            ),
        )

        self.assertEqual(status, "not_applicable")

        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = CollectionManifestRecorder(
                "run-not-applicable",
                Path(tmpdir),
                project_dir=Path(tmpdir),
            )
            recorder.record_execution(
                "Flow Logs (by location)",
                "parameterised",
                "az network watcher flow-log list --location {location}",
                "2026-08-03T12:00:00Z",
                0.1,
                1,
                None,
                parameter_context={"location": "spaincentral"},
                error_message="Azure CLI request failed with return code 1",
                diagnostic_text=(
                    "ERROR: network watcher is not enabled for region spaincentral."
                ),
            )
            manifest = recorder.finish()

        self.assertEqual(manifest["schema_version"], "2.5")
        self.assertEqual(manifest["status"], "success")
        self.assertEqual(manifest["endpoint_runs"][0]["status"], "not_applicable")
        self.assertEqual(manifest["errors"], [])

    def test_unsupported_diagnostic_resource_type_is_not_applicable(self):
        status = classify_execution_status(
            1,
            None,
            error_message="Azure CLI request failed with return code 1",
            diagnostic_text=(
                "ERROR: (ResourceTypeNotSupported) The resource type "
                "'microsoft.compute/snapshots' does not support diagnostic settings."
            ),
        )

        self.assertEqual(status, "not_applicable")

    def test_non_premium_tenant_response_is_not_classified_as_unauthorised(self):
        diagnostic = json.dumps(
            {
                "error": {
                    "code": "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
                    "message": "Tenant does not have a premium licence",
                }
            }
        )

        status = classify_execution_status(
            1,
            None,
            error_message="Azure CLI request failed with return code 1",
            diagnostic_text=diagnostic,
        )

        self.assertEqual(status, "tenant_unavailable")

    def test_azure_error_codes_are_extracted_from_direct_response_formats(self):
        self.assertEqual(
            extract_azure_error_code(
                '{"error":{"code":"AuthorizationFailed","message":"denied"}}'
            ),
            "AuthorizationFailed",
        )
        self.assertEqual(
            extract_azure_error_code(
                "ERROR: (Forbidden) The client cannot perform this request."
            ),
            "Forbidden",
        )
        self.assertIsNone(extract_azure_error_code("request failed without a code"))

    def test_direct_response_truncation_is_explicit_in_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = CollectionManifestRecorder(
                "run-truncated-response",
                Path(tmpdir),
                project_dir=Path(tmpdir),
            )
            diagnostic = "x" * 1001

            recorder.record_execution(
                "Resources",
                "base",
                "az resource list",
                "2026-08-03T12:00:00Z",
                0.1,
                1,
                None,
                error_message="Azure CLI request failed with return code 1",
                diagnostic_text=diagnostic,
            )
            manifest = recorder.finish()

        execution = manifest["endpoint_runs"][0]
        self.assertTrue(execution["response_error_truncated"])
        self.assertEqual(
            execution["response_error"],
            ("x" * 1000) + "... [truncated]",
        )


class CollectionManifestRecorderTests(unittest.TestCase):
    def test_schema_2_4_arm_proof_is_interpreted_conservatively(self):
        self.assertEqual(
            interpreted_visibility_status(
                "2.4",
                {
                    "status": "access_verified",
                    "method": "arm_effective_permissions",
                },
            ),
            "visibility_unverified",
        )
        self.assertEqual(
            interpreted_visibility_status(
                "2.4",
                {
                    "status": "access_verified",
                    "method": "graph_access_token_claims",
                },
            ),
            "access_verified",
        )

    def test_result_count_uses_semantic_collection_records(self):
        self.assertEqual(result_item_count({"@odata.context": "metadata", "value": []}), 0)
        self.assertEqual(
            result_item_count(
                {"@odata.context": "metadata", "value": [{"id": "one"}]}
            ),
            1,
        )
        self.assertEqual(result_item_count({"id": "singleton"}), 1)

    def test_manifest_records_endpoint_and_run_access_verification(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = CollectionManifestRecorder(
                "run-visibility",
                Path(tmpdir),
                project_dir=Path(tmpdir),
            )
            recorder.set_access_verification(
                {
                    "arm": {
                        "status": "access_verified",
                        "scope": "/subscriptions/sub-one",
                    },
                    "graph": {"status": "visibility_unverified"},
                }
            )
            recorder.record_execution(
                "Resources",
                "base",
                "az resource list",
                "2026-08-03T12:00:00Z",
                0.1,
                0,
                0,
                access_verification={
                    "status": "access_verified",
                    "plane": "azure_resource_manager",
                    "scope": "/subscriptions/sub-one",
                    "method": "arm_role_and_deny_assignments",
                    "reason_code": "subscription_wide_arm_read_verified",
                    "required_permissions": ["*/read"],
                },
            )

            manifest = recorder.finish()
            validate_manifest(manifest)

        self.assertEqual(manifest["schema_version"], "2.5")
        self.assertEqual(
            manifest["access_verification"]["arm"]["status"],
            "access_verified",
        )
        self.assertEqual(
            manifest["endpoint_runs"][0]["access_verification"]["status"],
            "access_verified",
        )

    def test_manifest_rejects_unbounded_access_evidence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = CollectionManifestRecorder(
                "run-bounded-evidence",
                Path(tmpdir),
                project_dir=Path(tmpdir),
            )
            recorder.record_execution(
                "Resources",
                "base",
                "az resource list",
                "2026-08-03T12:00:00Z",
                0.1,
                0,
                0,
            )
            manifest = recorder.finish()

        manifest["access_verification"]["graph"]["accessToken"] = "never-store"
        with self.assertRaisesRegex(ValueError, "unsupported evidence fields"):
            validate_manifest(manifest)

    def test_manifest_rejects_malformed_required_permissions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = CollectionManifestRecorder(
                "run-malformed-evidence",
                Path(tmpdir),
                project_dir=Path(tmpdir),
            )
            with self.assertRaisesRegex(ValueError, "must be a list"):
                recorder.record_execution(
                    "Resources",
                    "base",
                    "az resource list",
                    "2026-08-03T12:00:00Z",
                    0.1,
                    0,
                    0,
                    access_verification={
                        "status": "access_verified",
                        "required_permissions": "*/read",
                    },
                )

    def test_successful_run_records_execution_and_dataset_integrity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            dataset_path = output_dir / "az_resource_list_run-one.json"
            dataset = [{"id": "one"}, {"id": "two"}]
            dataset_path.write_text(json.dumps(dataset), encoding="utf-8")
            expected_hash = sha256_file(dataset_path)
            recorder = CollectionManifestRecorder(
                "run-one",
                output_dir,
                context={"tenant_id": "tenant-one"},
                project_dir=output_dir,
            )
            recorder.register_endpoints(
                [{"name": "Resources", "cli_command": "az resource list"}],
                "base",
            )

            recorder.record_execution(
                endpoint_name="Resources",
                category="base",
                command_template="az resource list",
                started_at="2026-07-21T12:00:00Z",
                duration_seconds=1.25,
                returncode=0,
                result_count=2,
            )
            recorder.record_dataset(dataset_path, dataset)
            manifest_path = recorder.write()
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(manifest["status"], "success")
        self.assertEqual(manifest["endpoint_runs"][0]["status"], "success")
        self.assertEqual(manifest["endpoint_runs"][0]["duration_ms"], 1250)
        self.assertEqual(manifest["datasets"][0]["record_count"], 2)
        self.assertEqual(manifest["datasets"][0]["sha256"], expected_hash)
        self.assertEqual(
            manifest["endpoint_runs"][0]["output_files"],
            ["az_resource_list_run-one.json"],
        )

    def test_mixed_success_and_failure_produces_partial_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = CollectionManifestRecorder("run-two", Path(tmpdir), project_dir=Path(tmpdir))
            recorder.record_execution(
                "Resources", "base", "az resource list", "2026-07-21T12:00:00Z", 0.1, 0, 1
            )
            recorder.record_execution(
                "Users",
                "base",
                "az ad user list",
                "2026-07-21T12:00:01Z",
                0.2,
                1,
                None,
                error_message="Command failed",
            )

            manifest = recorder.finish()

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual({item["status"] for item in manifest["endpoint_runs"]}, {"success", "failed"})
        self.assertEqual(len(manifest["errors"]), 1)

    def test_selected_but_unobserved_endpoint_is_not_attempted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = CollectionManifestRecorder("run-three", Path(tmpdir), project_dir=Path(tmpdir))
            recorder.register_endpoints(
                [{"name": "Resources", "cli_command": "az resource list"}],
                "base",
            )

            manifest = recorder.finish(
                execution_successful=False,
                unattempted_reason_code="collection_interrupted",
                unattempted_reason="Collection was interrupted by the operator",
                unattempted_reason_details={"termination_type": "KeyboardInterrupt"},
            )

        self.assertEqual(manifest["status"], "failed")
        self.assertEqual(manifest["endpoint_runs"][0]["status"], "not_attempted")
        self.assertEqual(
            manifest["endpoint_runs"][0]["reason_code"],
            "collection_interrupted",
        )
        self.assertEqual(
            manifest["endpoint_runs"][0]["reason_details"]["termination_type"],
            "KeyboardInterrupt",
        )

    def test_completed_collection_without_endpoint_outcome_is_flagged_as_defect(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = CollectionManifestRecorder(
                "run-instrumentation-gap",
                Path(tmpdir),
                project_dir=Path(tmpdir),
            )
            recorder.register_endpoints(
                [{"name": "Resources", "cli_command": "az resource list"}],
                "base",
            )

            manifest = recorder.finish()

        endpoint_run = manifest["endpoint_runs"][0]
        self.assertEqual(endpoint_run["status"], "not_attempted")
        self.assertEqual(endpoint_run["reason_code"], "collector_outcome_not_recorded")
        self.assertIn("without recording", endpoint_run["error"])

    def test_skipped_endpoint_does_not_make_otherwise_successful_run_partial(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = CollectionManifestRecorder("run-four", Path(tmpdir), project_dir=Path(tmpdir))
            recorder.record_skipped_endpoint(
                "Storage Keys",
                "parameterised",
                "az storage account keys list --account-name {name}",
                "No storage accounts were collected",
                reason_code="upstream_source_returned_no_data",
                reason_details={"source": "az_storage_account_list"},
            )

            manifest = recorder.finish()

        self.assertEqual(manifest["status"], "success")
        self.assertEqual(manifest["endpoint_runs"][0]["status"], "skipped")
        self.assertEqual(
            manifest["endpoint_runs"][0]["reason_code"],
            "upstream_source_returned_no_data",
        )

    def test_manifest_write_replaces_existing_file_and_leaves_no_temporary_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            recorder = CollectionManifestRecorder("run-five", output_dir, project_dir=output_dir)
            manifest_path = output_dir / "azure-collection-manifest_run-five.json"
            manifest_path.write_text("obsolete", encoding="utf-8")

            written_path = recorder.write()

            self.assertEqual(written_path, manifest_path)
            self.assertEqual(json.loads(manifest_path.read_text(encoding="utf-8"))["run_id"], "run-five")
            self.assertEqual(list(output_dir.glob("*.tmp")), [])

    def test_manifest_validation_rejects_invalid_endpoint_status(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = CollectionManifestRecorder("run-six", Path(tmpdir), project_dir=Path(tmpdir))
            manifest = recorder.finish()
            manifest["endpoint_runs"] = [{"status": "unexpected"}]

            with self.assertRaisesRegex(ValueError, "Invalid endpoint execution status"):
                validate_manifest(manifest)

    def test_manifest_validation_keeps_schema_2_0_readable_without_new_status(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = CollectionManifestRecorder(
                "run-legacy",
                Path(tmpdir),
                project_dir=Path(tmpdir),
            )
            manifest = recorder.finish()

        manifest["schema_version"] = "2.0"
        validate_manifest(manifest)

        manifest["endpoint_runs"] = [{"status": "not_applicable"}]
        with self.assertRaisesRegex(ValueError, "Invalid endpoint execution status"):
            validate_manifest(manifest)

    def test_manifest_validation_keeps_schema_2_1_omissions_readable_without_reasons(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = CollectionManifestRecorder(
                "run-legacy-omission",
                Path(tmpdir),
                project_dir=Path(tmpdir),
            )
            manifest = recorder.finish()

        manifest["schema_version"] = "2.1"
        manifest["endpoint_runs"] = [{"status": "skipped"}]
        validate_manifest(manifest)

        manifest["schema_version"] = "2.2"
        with self.assertRaisesRegex(ValueError, "valid reason code"):
            validate_manifest(manifest)

    def test_manifest_validation_keeps_schema_2_3_readable_without_access_evidence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = CollectionManifestRecorder(
                "run-pre-visibility",
                Path(tmpdir),
                project_dir=Path(tmpdir),
            )
            recorder.record_execution(
                "Resources",
                "base",
                "az resource list",
                "2026-08-03T12:00:00Z",
                0.1,
                0,
                0,
            )
            manifest = recorder.finish()

        manifest["schema_version"] = "2.3"
        manifest.pop("access_verification")
        manifest["endpoint_runs"][0].pop("access_verification")

        validate_manifest(manifest)

    def test_manifest_validation_keeps_schema_2_4_access_evidence_readable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = CollectionManifestRecorder(
                "run-pre-rbac-evidence",
                Path(tmpdir),
                project_dir=Path(tmpdir),
            )
            recorder.record_execution(
                "Resources",
                "base",
                "az resource list",
                "2026-08-03T12:00:00Z",
                0.1,
                0,
                0,
            )
            manifest = recorder.finish()

        manifest["schema_version"] = "2.4"
        manifest["access_verification"]["arm"] = {
            "status": "access_verified",
            "method": "arm_effective_permissions",
            "reason_code": "subscription_wide_arm_read_verified",
            "broad_read_granted": True,
            "permission_block_count": 1,
        }

        validate_manifest(manifest)

    def test_concurrent_execution_records_are_not_lost(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = CollectionManifestRecorder("run-concurrent", Path(tmpdir), project_dir=Path(tmpdir))

            def record_execution(index):
                recorder.record_execution(
                    endpoint_name="Resource Details",
                    category="parameterised",
                    command_template="az resource show --ids {id}",
                    parameter_context={"id": f"resource-{index}"},
                    started_at="2026-07-21T12:00:00Z",
                    duration_seconds=0.01,
                    returncode=0,
                    result_count=1,
                )

            with ThreadPoolExecutor(max_workers=8) as executor:
                list(executor.map(record_execution, range(50)))

            manifest = recorder.finish()

        self.assertEqual(len(manifest["endpoint_runs"]), 50)
        self.assertEqual({item["status"] for item in manifest["endpoint_runs"]}, {"success"})


class CollectionManifestIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.original_manifest = azure_collect.COLLECTION_MANIFEST
        self.original_access_verification = azure_collect.ACCESS_VERIFICATION
        self.original_auth_config = azure_collect.AUTH_CONFIG
        self.original_output_dir = getattr(azure_collect, "OUTPUT_DIR", None)
        self.original_start_timestamp = getattr(azure_collect, "START_TIMESTAMP", None)

    def tearDown(self):
        azure_collect.COLLECTION_MANIFEST = self.original_manifest
        azure_collect.ACCESS_VERIFICATION = self.original_access_verification
        azure_collect.AUTH_CONFIG = self.original_auth_config
        if self.original_output_dir is None:
            if hasattr(azure_collect, "OUTPUT_DIR"):
                del azure_collect.OUTPUT_DIR
        else:
            azure_collect.OUTPUT_DIR = self.original_output_dir
        if self.original_start_timestamp is None:
            if hasattr(azure_collect, "START_TIMESTAMP"):
                del azure_collect.START_TIMESTAMP
        else:
            azure_collect.START_TIMESTAMP = self.original_start_timestamp

    def test_timed_azure_cli_execution_records_parameter_context(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = CollectionManifestRecorder("run-seven", Path(tmpdir), project_dir=Path(tmpdir))
            azure_collect.COLLECTION_MANIFEST = recorder
            result = {
                "returncode": 0,
                "success": True,
                "stdout": "[]",
                "json": [{"name": "rule-one"}],
                "_retry_count": 1,
            }

            with mock.patch.object(azure_collect, "run_az_cli", return_value=result):
                azure_collect.timed_run_az_cli(
                    "az network nsg rule list --nsg-name nsg-one",
                    endpoint_name="NSG Rules",
                    category="parameterised",
                    command_template="az network nsg rule list --nsg-name {name}",
                    parameter_context={"name": "nsg-one", "client_secret": "never-store"},
                )

            manifest = recorder.finish()

        execution = manifest["endpoint_runs"][0]
        self.assertEqual(execution["status"], "success")
        self.assertEqual(execution["parameter_context"]["name"], "nsg-one")
        self.assertEqual(execution["parameter_context"]["client_secret"], "never-store")
        self.assertIn("{name}", execution["command_template"])
        self.assertNotIn("nsg-one", execution["command_template"])
        self.assertEqual(execution["attempt_count"], 2)

    def test_automatic_access_verification_uses_arm_permissions_and_graph_roles(self):
        azure_collect.AUTH_CONFIG = {
            "tenant_id": "tenant-one",
            "subscription_id": "sub-one",
        }
        azure_collect.SUBSCRIPTION_ROLE_ASSIGNMENTS_CACHE.pop("sub-one", None)
        responses = [
            ({"accessToken": "header.payload.signature"}, None),
            ({"value": []}, None),
            (
                [{
                    "principalId": "principal-one",
                    "roleDefinitionId": "/subscriptions/sub-one/providers/Microsoft.Authorization/roleDefinitions/reader-role",
                }],
                None,
            ),
            ([{
                "permissions": [{
                    "actions": ["*/read"],
                    "notActions": [],
                    "dataActions": [],
                    "notDataActions": [],
                }]
            }], None),
            ([], None),
        ]

        with mock.patch.object(
            azure_collect,
            "run_json_command",
            side_effect=responses,
        ):
            with mock.patch.object(
                azure_collect,
                "decode_jwt_payload",
                return_value={
                    "idtyp": "app",
                    "oid": "principal-one",
                    "roles": ["Policy.Read.All", "Directory.Read.All"],
                },
            ):
                verification = azure_collect.collect_automatic_access_verification()

        self.assertEqual(verification["arm"]["status"], "access_verified")
        self.assertTrue(verification["arm"]["broad_read_granted"])
        self.assertEqual(verification["graph"]["token_type"], "application")
        self.assertNotIn("accessToken", json.dumps(verification))
        self.assertEqual(
            azure_collect.endpoint_access_verification(
                "Graph Security Defaults Policy",
                "az rest --method get --url https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy",
            )["status"],
            "access_verified",
        )
        self.assertEqual(
            azure_collect.endpoint_access_verification(
                "Storage Accounts",
                "az storage account list",
            )["status"],
            "access_verified",
        )
        self.assertEqual(
            azure_collect.endpoint_access_verification(
                "Storage Account Keys",
                "az storage account keys list --account-name {name}",
            )["status"],
            "visibility_unverified",
        )

    def test_arm_read_deny_prevents_access_verification(self):
        azure_collect.AUTH_CONFIG = {"subscription_id": "sub-denied"}
        azure_collect.SUBSCRIPTION_ROLE_ASSIGNMENTS_CACHE.pop("sub-denied", None)
        responses = [
            ({"value": []}, None),
            ([{
                "principalId": "principal-one",
                "roleDefinitionId": "/subscriptions/sub-denied/providers/Microsoft.Authorization/roleDefinitions/reader-role",
            }], None),
            ([{"permissions": [{"actions": ["*/read"], "notActions": []}]}], None),
            ([{
                "permissions": [{"actions": ["Microsoft.Storage/*"], "notActions": []}],
                "principals": [{
                    "id": "00000000-0000-0000-0000-000000000000",
                    "type": "SystemDefined",
                }],
                "excludePrincipals": [],
            }], None),
        ]

        with mock.patch.object(
            azure_collect,
            "run_json_command",
            side_effect=responses,
        ):
            verification = azure_collect.collect_arm_access_verification(
                "principal-one"
            )

        self.assertEqual(verification["status"], "visibility_unverified")
        self.assertEqual(
            verification["reason_code"],
            "applicable_read_deny_assignment_present",
        )
        self.assertEqual(verification["applicable_read_deny_count"], 1)

    def test_deny_query_failure_prevents_access_verification(self):
        azure_collect.AUTH_CONFIG = {"subscription_id": "sub-deny-query"}
        azure_collect.SUBSCRIPTION_ROLE_ASSIGNMENTS_CACHE.pop(
            "sub-deny-query", None
        )
        responses = [
            ({"value": []}, None),
            ([{
                "principalId": "principal-one",
                "roleDefinitionId": "/subscriptions/sub-deny-query/providers/Microsoft.Authorization/roleDefinitions/reader-role",
            }], None),
            ([{"permissions": [{"actions": ["*/read"], "notActions": []}]}], None),
            (None, "Forbidden"),
        ]

        with mock.patch.object(
            azure_collect,
            "run_json_command",
            side_effect=responses,
        ):
            verification = azure_collect.collect_arm_access_verification(
                "principal-one"
            )

        self.assertEqual(verification["status"], "visibility_unverified")
        self.assertEqual(
            verification["reason_code"],
            "deny_assignment_query_failed",
        )

    def test_non_read_deny_does_not_hide_verified_read_access(self):
        self.assertFalse(
            azure_collect.deny_permission_may_block_reads(
                {
                    "actions": [
                        "Microsoft.Authorization/roleAssignments/write",
                        "*/delete",
                    ],
                    "notActions": [],
                }
            )
        )

    def test_broad_role_with_namespace_read_exclusion_is_not_unrestricted(self):
        self.assertFalse(
            azure_collect.block_grants_unrestricted_arm_reads(
                {
                    "actions": ["*"],
                    "notActions": ["Microsoft.Storage/*"],
                }
            )
        )
        self.assertTrue(
            azure_collect.block_grants_unrestricted_arm_reads(
                {
                    "actions": ["*"],
                    "notActions": ["Microsoft.Authorization/*/write"],
                }
            )
        )

    def test_unverified_subscription_access_does_not_claim_scope_restriction(self):
        azure_collect.ACCESS_VERIFICATION = {
            "arm": {
                "status": "visibility_unverified",
                "scope": "/subscriptions/sub-one",
            },
            "graph": {"status": "visibility_unverified"},
        }

        verification = azure_collect.endpoint_access_verification(
            "Management Groups",
            "az account management-group list",
        )

        self.assertEqual(verification["status"], "visibility_unverified")
        self.assertEqual(
            verification["reason_code"],
            "endpoint_and_subscription_scope_access_unverified",
        )

    def test_documented_higher_graph_permission_can_verify_endpoint_access(self):
        azure_collect.AUTH_CONFIG = {"tenant_id": "tenant-one"}
        azure_collect.ACCESS_VERIFICATION = {
            "arm": {"status": "visibility_unverified"},
            "graph": {
                "status": "visibility_unverified",
                "token_type": "application",
                "granted_permissions": ["GroupSettings.Read.All"],
            },
        }

        verification = azure_collect.endpoint_access_verification(
            "Graph Group Settings",
            "az rest --method get --url https://graph.microsoft.com/v1.0/groupSettings",
        )

        self.assertEqual(verification["status"], "access_verified")

    def test_delegated_graph_claims_do_not_prove_tenant_wide_visibility(self):
        azure_collect.AUTH_CONFIG = {
            "tenant_id": "tenant-one",
            "subscription_id": "sub-one",
        }
        azure_collect.ACCESS_VERIFICATION = {
            "arm": {"status": "visibility_unverified"},
            "graph": {
                "status": "visibility_unverified",
                "token_type": "delegated",
                "granted_permissions": ["Policy.Read.All"],
            },
        }

        verification = azure_collect.endpoint_access_verification(
            "Graph Security Defaults Policy",
            "az rest --method get --url https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy",
        )

        self.assertEqual(verification["status"], "visibility_unverified")
        self.assertEqual(
            verification["reason_code"],
            "delegated_graph_access_requires_user_privileges",
        )

    def test_failed_azure_cli_execution_preserves_diagnostic_output(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = CollectionManifestRecorder(
                "run-failed-command",
                Path(tmpdir),
                project_dir=Path(tmpdir),
            )
            azure_collect.COLLECTION_MANIFEST = recorder
            result = {
                "returncode": 1,
                "success": False,
                "stdout": "(AuthorizationFailed) Principal cannot read this resource.",
                "json": {},
                "collection_error": "Command failed",
            }

            with mock.patch.object(azure_collect, "run_az_cli", return_value=result):
                azure_collect.timed_run_az_cli(
                    "az resource list",
                    endpoint_name="Resources",
                    category="base",
                )

            manifest = recorder.finish()

        self.assertEqual(
            manifest["endpoint_runs"][0]["error"],
            "Command failed",
        )
        execution = manifest["endpoint_runs"][0]
        self.assertEqual(execution["error_code"], "AuthorizationFailed")
        self.assertEqual(
            execution["response_error"],
            "(AuthorizationFailed) Principal cannot read this resource.",
        )
        self.assertFalse(execution["response_error_truncated"])
        self.assertEqual(manifest["errors"][0]["error_code"], "AuthorizationFailed")
        self.assertEqual(manifest["errors"][0]["returncode"], 1)

    def test_managed_role_cache_records_version_dataset_and_output_link(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            cache_path = output_dir / "managed-roles.json"
            recorder = CollectionManifestRecorder(
                "run-cache",
                output_dir,
                project_dir=output_dir,
            )
            azure_collect.COLLECTION_MANIFEST = recorder
            roles = [
                {
                    "id": "/subscriptions/sub-one/providers/Microsoft.Authorization/roleDefinitions/role-one",
                    "name": "Reader",
                    "roleType": "BuiltInRole",
                }
            ]

            with mock.patch.object(
                azure_collect,
                "run_json_command",
                side_effect=[(roles, None), ({"azure-cli": "2.75.0"}, None)],
            ):
                azure_collect.collect_managed_role_definitions_cache(cache_path)

            manifest = recorder.finish()

        self.assertEqual(manifest["tool"]["azure_cli_version"], "2.75.0")
        self.assertEqual(manifest["datasets"][0]["record_count"], 1)
        self.assertEqual(
            manifest["endpoint_runs"][0]["output_files"],
            ["managed-roles.json"],
        )

    def test_post_processing_failure_preserves_exception_details(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = CollectionManifestRecorder(
                "run-processing-failure",
                Path(tmpdir),
                project_dir=Path(tmpdir),
            )
            azure_collect.COLLECTION_MANIFEST = recorder
            azure_collect.START_TIMESTAMP = "run-processing-failure"
            endpoint = {
                "name": "Resources",
                "cli_command": "az resource list",
            }

            with mock.patch.object(
                azure_collect,
                "timed_run_az_cli",
                return_value={"returncode": 0, "json": [{"id": "one"}]},
            ):
                with mock.patch.object(
                    azure_collect,
                    "save_json",
                    side_effect=RuntimeError("sensitive implementation detail"),
                ):
                    azure_collect.collect_endpoint(endpoint)

            manifest = recorder.finish()

        self.assertEqual(manifest["status"], "failed")
        self.assertEqual(manifest["endpoint_runs"][0]["status"], "failed")
        self.assertEqual(
            manifest["endpoint_runs"][0]["error"],
            "Collected data could not be post-processed: sensitive implementation detail",
        )
        self.assertIn("sensitive implementation detail", json.dumps(manifest))

    def test_save_json_registers_generated_dataset(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            recorder = CollectionManifestRecorder("run-eight", output_dir, project_dir=output_dir)
            azure_collect.COLLECTION_MANIFEST = recorder
            azure_collect.OUTPUT_DIR = output_dir

            saved_path = azure_collect.save_json(
                [{"id": "resource-one"}],
                "az_resource_list_run-eight.json",
            )
            manifest = recorder.finish()

        self.assertEqual(saved_path.name, "az_resource_list_run-eight.json")
        self.assertEqual(manifest["datasets"][0]["filename"], saved_path.name)
        self.assertEqual(manifest["datasets"][0]["record_count"], 1)

    def test_derived_dataset_is_linked_to_each_input_endpoint(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            dataset_path = output_dir / "role_enriched_run-lineage.json"
            dataset = [{"id": "assignment-one"}]
            dataset_path.write_text(json.dumps(dataset), encoding="utf-8")
            recorder = CollectionManifestRecorder(
                "run-lineage",
                output_dir,
                project_dir=output_dir,
            )
            for endpoint_id_value, endpoint_name in (
                ("az_role_assignment_list", "Role Assignments"),
                ("az_role_definition_custom_list", "Custom Role Definitions"),
            ):
                recorder.record_execution(
                    endpoint_name,
                    "base",
                    endpoint_id_value,
                    "2026-07-21T12:00:00Z",
                    0.1,
                    0,
                    1,
                    endpoint_identifier=endpoint_id_value,
                )
            recorder.record_dataset(
                dataset_path,
                dataset,
                source_endpoint_identifiers=[
                    "az_role_assignment_list",
                    "az_role_definition_custom_list",
                ],
            )

            manifest = recorder.finish()

        self.assertEqual(
            manifest["datasets"][0]["source_endpoint_ids"],
            ["az_role_assignment_list", "az_role_definition_custom_list"],
        )
        self.assertTrue(
            all(
                dataset_path.name in endpoint["output_files"]
                for endpoint in manifest["endpoint_runs"]
            )
        )

    def test_context_can_be_updated_after_authentication(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = CollectionManifestRecorder(
                "run-context",
                Path(tmpdir),
                context={"tenant_id": None, "subscription_id": None},
                project_dir=Path(tmpdir),
            )

            recorder.update_context(
                {"tenant_id": "tenant-active", "subscription_id": "sub-active"}
            )

            manifest = recorder.finish()

        self.assertEqual(manifest["context"]["tenant_id"], "tenant-active")
        self.assertEqual(manifest["context"]["subscription_id"], "sub-active")


if __name__ == "__main__":
    unittest.main()
