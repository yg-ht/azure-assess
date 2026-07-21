import importlib.util
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from azure_collection_manifest import (
    CollectionManifestRecorder,
    classify_execution_status,
    redact_value,
    sha256_file,
    validate_manifest,
)


COLLECT_MODULE_PATH = Path(__file__).with_name("azure-collect.py")
COLLECT_SPEC = importlib.util.spec_from_file_location(
    "azure_collect_manifest_integration",
    COLLECT_MODULE_PATH,
)
azure_collect = importlib.util.module_from_spec(COLLECT_SPEC)
COLLECT_SPEC.loader.exec_module(azure_collect)


class CollectionManifestSecurityTests(unittest.TestCase):
    def test_recursive_redaction_removes_credentials_and_inline_secrets(self):
        value = {
            "tenant_id": "tenant-one",
            "client_secret": "do-not-store",
            "nested": {
                "accessToken": "token-value",
                "message": "az login --password plaintext --tenant tenant-one",
            },
        }

        redacted = redact_value(value)

        self.assertEqual(redacted["tenant_id"], "tenant-one")
        self.assertEqual(redacted["client_secret"], "[REDACTED]")
        self.assertEqual(redacted["nested"]["accessToken"], "[REDACTED]")
        self.assertNotIn("plaintext", redacted["nested"]["message"])

    def test_recursive_redaction_removes_quoted_passwords(self):
        redacted = redact_value("az login --password 'words with spaces' --tenant tenant-one")

        self.assertNotIn("words with spaces", redacted)
        self.assertIn("--password [REDACTED]", redacted)

    def test_permission_failures_are_classified_without_persisting_output(self):
        status = classify_execution_status(
            1,
            None,
            error_message="Command failed",
            diagnostic_text="AuthorizationFailed: principal does not have authorization",
        )

        self.assertEqual(status, "unauthorised")


class CollectionManifestRecorderTests(unittest.TestCase):
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

            manifest = recorder.finish(execution_successful=False)

        self.assertEqual(manifest["status"], "failed")
        self.assertEqual(manifest["endpoint_runs"][0]["status"], "not_attempted")

    def test_skipped_endpoint_does_not_make_otherwise_successful_run_partial(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = CollectionManifestRecorder("run-four", Path(tmpdir), project_dir=Path(tmpdir))
            recorder.record_skipped_endpoint(
                "Storage Keys",
                "parameterised",
                "az storage account keys list --account-name {name}",
                "No storage accounts were collected",
            )

            manifest = recorder.finish()

        self.assertEqual(manifest["status"], "success")
        self.assertEqual(manifest["endpoint_runs"][0]["status"], "skipped")

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
        self.original_output_dir = getattr(azure_collect, "OUTPUT_DIR", None)
        self.original_start_timestamp = getattr(azure_collect, "START_TIMESTAMP", None)

    def tearDown(self):
        azure_collect.COLLECTION_MANIFEST = self.original_manifest
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
        self.assertEqual(execution["parameter_context"]["client_secret"], "[REDACTED]")
        self.assertIn("{name}", execution["command_template"])
        self.assertNotIn("nsg-one", execution["command_template"])
        self.assertEqual(execution["attempt_count"], 2)

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

    def test_post_processing_failure_is_recorded_without_exception_details(self):
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
            "Collected data could not be post-processed",
        )
        self.assertNotIn("sensitive implementation detail", json.dumps(manifest))

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
