import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("azure-collect.py")
SPEC = importlib.util.spec_from_file_location("azure_collect", MODULE_PATH)
azure_collect = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(azure_collect)

FINDINGS_MODULE_PATH = Path(__file__).with_name("azure-findings.py")
FINDINGS_SPEC = importlib.util.spec_from_file_location("azure_findings", FINDINGS_MODULE_PATH)
azure_findings = importlib.util.module_from_spec(FINDINGS_SPEC)
FINDINGS_SPEC.loader.exec_module(azure_findings)


class FakeAzProcess:
    def __init__(self, returncode, output):
        self.returncode = returncode
        self.stdout = FakeStdout(output)

    def poll(self):
        return self.returncode

    def wait(self):
        return self.returncode


class FakeStdout:
    def __init__(self, output):
        self.lines = iter(output.splitlines(keepends=True))

    def readline(self):
        return next(self.lines, "")


class DefenderAssessmentsEndpointTests(unittest.TestCase):
    def test_defender_assessments_use_arm_rest_endpoint(self):
        endpoint = next(
            endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
            if endpoint["name"] == "Defender Assessments"
        )

        self.assertIn("az rest --method get", endpoint["cli_command"])
        self.assertIn("/subscriptions/{id}/providers/", endpoint["cli_command"])
        self.assertIn("Microsoft.Security/assessments?api-version=2020-01-01", endpoint["cli_command"])
        self.assertNotIn("az security assessment list", endpoint["cli_command"])
        self.assertEqual(endpoint["required_params"], {"id": "az_account_list"})
        self.assertTrue(endpoint["extract_value"])

    def test_defender_assessments_extracts_value_and_uses_safe_filename(self):
        endpoint = {
            "name": "Defender Assessments",
            "cli_command": "az rest --method get --url \"/subscriptions/{id}/providers/Microsoft.Security/assessments?api-version=2020-01-01\"",
            "needs_pagination": False,
            "extract_value": True,
        }
        commands_run = []
        saved_payloads = []

        def fake_run_az_cli(cmd):
            commands_run.append(cmd)
            if cmd.startswith("az config set "):
                return {"json": {}, "success": True, "stdout": "{}"}
            return {"json": {"value": [{"name": "assessment"}]}, "success": True, "stdout": "{}"}

        def fake_save_json(data, filename, append=False):
            saved_payloads.append((data, filename, append))

        azure_collect.START_TIMESTAMP = "20260402-000000"
        azure_collect.DEBUG = False

        with mock.patch.object(azure_collect, "run_az_cli", side_effect=fake_run_az_cli):
            with mock.patch.object(azure_collect, "save_json", side_effect=fake_save_json):
                azure_collect.collect_data([endpoint])

        self.assertIn(endpoint["cli_command"], commands_run)
        self.assertEqual(saved_payloads[0][0], [{"name": "assessment"}])
        self.assertNotIn("/", saved_payloads[0][1])
        self.assertIn("microsoft.security_assessments", saved_payloads[0][1])


class DefenderAssessmentFindingsDatasetTests(unittest.TestCase):
    def test_defender_assessment_records_include_rest_dataset_prefix(self):
        assessment = {"name": "assessment"}
        catalog = {
            "az_rest_--method_get_--url_subscriptions_id_providers_microsoft.security_assessments_api-version_2020-01-01_20260402-000000.json": {
                "data": [assessment],
                "path": Path("defender-assessments.json"),
            }
        }

        self.assertEqual(
            azure_findings.dataset_records_any(
                catalog,
                ("az_security_assessment_list",),
                ("microsoft.security", "assessments"),
            ),
            [assessment],
        )
        self.assertEqual(
            azure_findings.dataset_paths_any(
                catalog,
                ("az_security_assessment_list",),
                ("microsoft.security", "assessments"),
            ),
            [Path("defender-assessments.json")],
        )


class ApplicationInsightsEndpointTests(unittest.TestCase):
    def test_application_insights_collection_uses_supported_component_show_command(self):
        endpoint = next(
            endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS
            if endpoint["name"] == "Application Insights"
        )

        self.assertEqual(endpoint["cli_command"], "az monitor app-insights component show")

    def test_application_insights_details_uses_collection_dataset_source(self):
        endpoint = next(
            endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
            if endpoint["name"] == "Application Insights Details"
        )

        self.assertEqual(
            endpoint["required_params"],
            {
                "name": "az_monitor_app-insights_component_show",
                "resourceGroup": "az_monitor_app-insights_component_show",
            },
        )


class KubernetesEnvironmentsEndpointTests(unittest.TestCase):
    def test_kubernetes_environments_collection_uses_generic_resource_endpoint(self):
        endpoint = next(
            endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS
            if endpoint["name"] == "Kubernetes Environments"
        )

        self.assertEqual(
            endpoint["cli_command"],
            "az resource list --resource-type Microsoft.Web/kubeEnvironments",
        )
        self.assertNotIn("az appservice kube list", endpoint["cli_command"])

    def test_kubernetes_environment_details_uses_collected_resource_id(self):
        endpoint = next(
            endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
            if endpoint["name"] == "Kubernetes Environment Details"
        )

        self.assertEqual(
            endpoint["cli_command"],
            "az resource show --ids {id} --api-version 2024-11-01 --include-response-body true",
        )
        self.assertEqual(
            endpoint["required_params"],
            {"id": "az_resource_list_--resource-type_microsoft.web_kubeenvironments"},
        )


class AppConfigurationEndpointTests(unittest.TestCase):
    def test_app_configuration_revision_collection_uses_supported_command_group(self):
        endpoint = next(
            endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
            if endpoint["name"] == "App Configuration KeyValue Revisions"
        )

        self.assertEqual(
            endpoint["cli_command"],
            "az appconfig revision list --name {name} --all",
        )

    def test_app_configuration_revision_collection_does_not_use_legacy_kv_subcommand(self):
        commands = [
            endpoint["cli_command"]
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
        ]

        self.assertNotIn("az appconfig kv revision list --name {name} --all", commands)


class PerformanceOptionTests(unittest.TestCase):
    def test_max_workers_defaults_to_four(self):
        with mock.patch.object(azure_collect.sys, "argv", ["azure-collect.py"]):
            args = azure_collect.parse_arguments()

        self.assertEqual(args.max_workers, 4)

    def test_bounded_worker_count_allows_serial_opt_out(self):
        self.assertEqual(azure_collect.bounded_worker_count(1), 1)
        self.assertEqual(azure_collect.bounded_worker_count(0), 1)
        self.assertEqual(azure_collect.bounded_worker_count("8"), 8)

    def test_run_tasks_preserves_result_order_with_workers(self):
        results = azure_collect.run_tasks(
            [
                lambda: "first",
                lambda: "second",
                lambda: "third",
            ],
            worker_count=2,
        )

        self.assertEqual(results, ["first", "second", "third"])


class DependencyEndpointTests(unittest.TestCase):
    def test_virtual_networks_are_collected_as_base_source(self):
        base_endpoint = next(
            endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS
            if endpoint["name"] == "Virtual Networks"
        )
        self.assertEqual(base_endpoint["cli_command"], "az network vnet list")

        param_names = {
            endpoint["name"]
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
        }
        self.assertNotIn("Virtual Networks", param_names)

    def test_managed_disks_use_resource_group_name_parameter(self):
        endpoint = next(
            endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
            if endpoint["name"] == "Managed Disks"
        )

        self.assertEqual(endpoint["cli_command"], "az disk list --resource-group \"{name}\"")
        self.assertEqual(endpoint["required_params"], {"name": "az_group_list"})

    def test_function_and_web_auth_settings_have_distinct_output_prefixes(self):
        function_endpoint = next(
            endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
            if endpoint["name"] == "Function App Auth Settings"
        )
        web_endpoint = next(
            endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
            if endpoint["name"] == "Web App Auth Settings"
        )

        self.assertNotEqual(
            azure_collect.endpoint_output_prefix(function_endpoint),
            azure_collect.endpoint_output_prefix(web_endpoint),
        )

    def test_role_definition_custom_output_does_not_match_merged_prefix(self):
        endpoint = next(
            endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS
            if endpoint["name"] == "Role Definitions"
        )

        self.assertEqual(endpoint["cli_command"], "az role definition list --custom-role-only true")
        self.assertEqual(azure_collect.endpoint_output_prefix(endpoint), "az_role_definition_custom_list")
        self.assertNotIn("az_role_definition_list", azure_collect.endpoint_output_prefix(endpoint))

    def test_exact_source_prefix_does_not_match_more_specific_resource_list(self):
        azure_collect.START_TIMESTAMP = "20260402-000000"

        self.assertTrue(
            azure_collect.source_filename_matches(
                "az_resource_list_20260402-000000.json",
                "az_resource_list",
            )
        )
        self.assertFalse(
            azure_collect.source_filename_matches(
                "az_resource_list_--resource-type_microsoft.web_kubeenvironments_20260402-000000.json",
                "az_resource_list",
            )
        )

    def test_abbreviated_source_prefix_matches_command_with_arguments(self):
        azure_collect.START_TIMESTAMP = "20260402-000000"

        self.assertTrue(
            azure_collect.source_filename_matches(
                "az_storage_container_list_--account-name_name_--auth-mode_login_20260402-000000.json",
                "az_storage_container_list",
            )
        )


class ManagedRoleDefinitionCacheTests(unittest.TestCase):
    def test_builtin_role_cache_rejects_custom_roles(self):
        with self.assertRaises(ValueError):
            azure_collect.validate_builtin_role_definitions(
                [{"name": "custom-role", "roleType": "CustomRole"}]
            )

    def test_builtin_role_cache_accepts_builtin_roles(self):
        azure_collect.validate_builtin_role_definitions(
            [{"name": "reader", "roleType": "BuiltInRole"}]
        )

    def test_collect_managed_role_definitions_cache_writes_validated_payload(self):
        commands = []
        written = {}

        def fake_run_json_command(command):
            commands.append(command)
            if command.startswith("az version"):
                return {"azure-cli": "test"}, None
            return [{"name": "reader", "roleType": "BuiltInRole"}], None

        def fake_write(role_definitions, path=None, az_version=None):
            written["role_definitions"] = role_definitions
            written["path"] = path
            written["az_version"] = az_version

        with mock.patch.object(azure_collect, "run_json_command", side_effect=fake_run_json_command):
            with mock.patch.object(azure_collect, "write_managed_role_definitions_cache", side_effect=fake_write):
                azure_collect.collect_managed_role_definitions_cache("cache.json")

        self.assertEqual(
            commands[0],
            "az role definition list --query \"[?roleType=='BuiltInRole']\" --output json",
        )
        self.assertEqual(written["role_definitions"], [{"name": "reader", "roleType": "BuiltInRole"}])
        self.assertEqual(written["path"], "cache.json")

    def test_merge_role_definitions_combines_cached_builtin_and_live_custom_roles(self):
        saved_payloads = []

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            custom_role_file = output_dir / "az_role_definition_custom_list_20260402-000000.json"
            custom_role_file.write_text(
                json.dumps([{"name": "custom", "roleType": "CustomRole"}]),
                encoding="utf-8",
            )

            azure_collect.OUTPUT_DIR = output_dir
            azure_collect.START_TIMESTAMP = "20260402-000000"
            azure_collect.SOURCE_RECORD_CACHE.clear()
            azure_collect.SOURCE_FILE_INDEX_CACHE.clear()

            def fake_save_json(data, filename, append=False):
                saved_payloads.append((data, filename, append))

            with mock.patch.object(
                azure_collect,
                "load_managed_role_definitions_cache",
                return_value=[{"name": "reader", "roleType": "BuiltInRole"}],
            ):
                with mock.patch.object(azure_collect, "save_json", side_effect=fake_save_json):
                    merged = azure_collect.merge_role_definition_dataset("cache.json")

        self.assertEqual(
            merged,
            [
                {"name": "reader", "roleType": "BuiltInRole"},
                {"name": "custom", "roleType": "CustomRole"},
            ],
        )
        self.assertEqual(saved_payloads[0][1], "az_role_definition_list_20260402-000000.json")


class RbacReuseTests(unittest.TestCase):
    def test_subscription_role_assignments_are_cached(self):
        azure_collect.SUBSCRIPTION_ROLE_ASSIGNMENTS_CACHE.clear()
        calls = []

        def fake_run_json_command(command):
            calls.append(command)
            return [{"roleDefinitionName": "Reader", "principalId": "principal"}], None

        with mock.patch.object(azure_collect, "run_json_command", side_effect=fake_run_json_command):
            first, first_error = azure_collect.get_subscription_role_assignments("sub-1")
            second, second_error = azure_collect.get_subscription_role_assignments("sub-1")

        self.assertIsNone(first_error)
        self.assertIsNone(second_error)
        self.assertEqual(first, second)
        self.assertEqual(len(calls), 1)


class CollectDataWithParamsTests(unittest.TestCase):
    def setUp(self):
        azure_collect.START_TIMESTAMP = "20260402-000000"
        azure_collect.DEBUG = False
        azure_collect.SOURCE_RECORD_CACHE.clear()
        azure_collect.SOURCE_FILE_INDEX_CACHE.clear()

    def test_parameterised_follow_on_queries_use_collection_context_for_multiple_records(self):
        endpoint = {
            "name": "VM NIC details",
            "cli_command": "az vm nic show --resource-group {resourceGroup} --vm-name {vm_name} --nic {id}",
            "required_params": {
                "resourceGroup": "az_vm_nic_list",
                "vm_name": "az_vm_nic_list",
                "id": "az_vm_nic_list",
            },
        }

        source_records = [
            {
                "id": "nic-1",
                "_collectionContext": {
                    "endpoint": "VM NIC IDs",
                    "parameters": {"resourceGroup": "rg-one", "vm_name": "vm-one"},
                },
            },
            {
                "id": "nic-2",
                "_collectionContext": {
                    "endpoint": "VM NIC IDs",
                    "parameters": {"resourceGroup": "rg-two", "vm_name": "vm-two"},
                },
            },
        ]

        commands_run = []
        saved_payloads = []

        def fake_run_az_cli(cmd):
            commands_run.append(cmd)
            return {"json": {"command": cmd}, "success": True, "stdout": '{"command": "ok"}'}

        def fake_save_json(data, filename, append=False):
            saved_payloads.append((data, filename, append))

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            source_file = output_dir / "az_vm_nic_list_20260402-000000.json"
            source_file.write_text(json.dumps(source_records), encoding="utf-8")

            azure_collect.OUTPUT_DIR = output_dir

            with mock.patch.object(azure_collect, "run_az_cli", side_effect=fake_run_az_cli):
                with mock.patch.object(azure_collect, "save_json", side_effect=fake_save_json):
                    azure_collect.collect_data_with_params([endpoint])

        self.assertEqual(
            commands_run,
            [
                "az vm nic show --resource-group rg-one --vm-name vm-one --nic nic-1",
                "az vm nic show --resource-group rg-two --vm-name vm-two --nic nic-2",
            ],
        )
        self.assertEqual(len(saved_payloads), 1)
        self.assertEqual(len(saved_payloads[0][0]), 2)

    def test_managed_disks_resolve_resource_group_from_group_name(self):
        endpoint = next(
            endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
            if endpoint["name"] == "Managed Disks"
        )
        commands_run = []
        saved_payloads = []

        def fake_run_az_cli(cmd):
            commands_run.append(cmd)
            return {"json": [{"name": "disk-one"}], "success": True, "stdout": "[]"}

        def fake_save_json(data, filename, append=False):
            saved_payloads.append((data, filename, append))

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            source_file = output_dir / "az_group_list_20260402-000000.json"
            source_file.write_text(json.dumps([{"name": "rg(test)"}]), encoding="utf-8")

            azure_collect.OUTPUT_DIR = output_dir

            with mock.patch.object(azure_collect, "run_az_cli", side_effect=fake_run_az_cli):
                with mock.patch.object(azure_collect, "save_json", side_effect=fake_save_json):
                    azure_collect.collect_data_with_params([endpoint])

        self.assertEqual(commands_run, ["az disk list --resource-group \"rg(test)\""])
        self.assertEqual(len(saved_payloads), 1)
        self.assertEqual(saved_payloads[0][0][0]["name"], "disk-one")

    def test_defender_assessments_resolve_subscription_from_account_id(self):
        endpoint = next(
            endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
            if endpoint["name"] == "Defender Assessments"
        )
        commands_run = []
        saved_payloads = []

        def fake_run_az_cli(cmd):
            commands_run.append(cmd)
            return {
                "json": {"value": [{"name": "assessment-one"}]},
                "success": True,
                "stdout": "{}",
            }

        def fake_save_json(data, filename, append=False):
            saved_payloads.append((data, filename, append))

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            source_file = output_dir / "az_account_list_20260402-000000.json"
            source_file.write_text(json.dumps([{"id": "sub-one"}]), encoding="utf-8")

            azure_collect.OUTPUT_DIR = output_dir

            with mock.patch.object(azure_collect, "run_az_cli", side_effect=fake_run_az_cli):
                with mock.patch.object(azure_collect, "save_json", side_effect=fake_save_json):
                    azure_collect.collect_data_with_params([endpoint])

        self.assertEqual(
            commands_run,
            [
                "az rest --method get --url "
                "\"/subscriptions/sub-one/providers/Microsoft.Security/assessments?api-version=2020-01-01\"",
            ],
        )
        self.assertEqual(len(saved_payloads), 1)
        self.assertEqual(saved_payloads[0][0][0]["name"], "assessment-one")


class PermissionBaselineTests(unittest.TestCase):
    def test_directory_role_names_include_direct_and_group_assignments(self):
        assignments = [
            {
                "principalId": "principal-1",
                "roleDefinition": {"displayName": "Global Reader"},
            },
            {
                "principalId": "group-1",
                "roleDefinition": {"displayName": "Security Reader"},
            },
            {
                "principalId": "other-principal",
                "roleDefinition": {"displayName": "Global Administrator"},
            },
            {
                "principalId": "group-2",
                "roleDefinition": {},
            },
        ]
        graph_urls = []

        def fake_graph_collection_values(url):
            graph_urls.append(url)
            return assignments, None

        with mock.patch.object(azure_collect, "graph_collection_values", side_effect=fake_graph_collection_values):
            role_names, errors = azure_collect.get_directory_role_names_for_principal_ids(
                {"principal-1", "group-1"},
            )

        self.assertEqual(role_names, {"Global Reader", "Security Reader"})
        self.assertEqual(errors, [])
        self.assertEqual(len(graph_urls), 1)
        self.assertIn("roleManagement/directory/roleAssignments", graph_urls[0])
        self.assertNotIn("%24filter", graph_urls[0])

    def test_directory_role_names_returns_graph_errors(self):
        with mock.patch.object(
            azure_collect,
            "graph_collection_values",
            return_value=([], "graph failed"),
        ):
            role_names, errors = azure_collect.get_directory_role_names_for_principal_ids(
                {"principal-1"},
            )

        self.assertEqual(role_names, set())
        self.assertEqual(errors, ["graph failed"])

    def test_subscription_role_names_include_direct_and_group_assignments(self):
        assignments = [
            {"principalId": "principal-1", "roleDefinitionName": "Reader"},
            {"principalId": "group-1", "roleDefinitionName": "Security Reader"},
            {"principalId": "other-principal", "roleDefinitionName": "Owner"},
            {"principalId": "group-2"},
        ]

        with mock.patch.object(
            azure_collect,
            "get_subscription_role_assignments",
            return_value=(assignments, None),
        ):
            role_names, errors = azure_collect.get_subscription_role_names_for_principal_ids(
                "subscription-1",
                {"principal-1", "group-1"},
            )

        self.assertEqual(role_names, {"Reader", "Security Reader"})
        self.assertEqual(errors, [])

    def test_subscription_role_names_returns_assignment_errors(self):
        with mock.patch.object(
            azure_collect,
            "get_subscription_role_assignments",
            return_value=(None, "assignment failed"),
        ):
            role_names, errors = azure_collect.get_subscription_role_names_for_principal_ids(
                "subscription-1",
                {"principal-1"},
            )

        self.assertEqual(role_names, set())
        self.assertEqual(errors, ["assignment failed"])


class AzureCliExtensionInstallTests(unittest.TestCase):
    def setUp(self):
        azure_collect.DEBUG = False
        azure_collect.AZURE_CLI_EXTENSION_CACHE.clear()

    @staticmethod
    def completed_process(returncode=0, stdout="", stderr=""):
        return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)

    def test_missing_iot_extension_is_installed_and_command_is_retried(self):
        missing_extension_output = (
            "az iot: 'iot' is not in the 'az' command group. See 'az --help'.\n"
            "If the command is from an extension, please make sure the corresponding "
            "extension is installed.\n"
        )
        popen_results = [
            FakeAzProcess(2, missing_extension_output),
            FakeAzProcess(0, '[{"name": "hub-one"}]\n'),
        ]
        az_commands = []

        def fake_run_az_command(cmd, capture_output=False):
            az_commands.append(cmd)
            if cmd.startswith("az extension show "):
                return self.completed_process(returncode=1, stderr="Extension not found")
            if cmd.startswith("az extension add "):
                return self.completed_process(returncode=0)
            return self.completed_process(returncode=0)

        with mock.patch.object(azure_collect.subprocess, "Popen", side_effect=popen_results) as popen_mock:
            with mock.patch.object(azure_collect, "run_az_command", side_effect=fake_run_az_command):
                result = azure_collect.run_az_cli("az iot hub list")

        self.assertTrue(result["success"])
        self.assertEqual(result["json"], [{"name": "hub-one"}])
        self.assertEqual(
            [call.args[0] for call in popen_mock.call_args_list],
            ["az iot hub list --output json", "az iot hub list --output json"],
        )
        self.assertIn("az extension show --name azure-iot --output json", az_commands)
        self.assertIn("az extension add --name azure-iot --yes", az_commands)

    def test_missing_extension_name_can_be_read_from_cli_output(self):
        output = "The command requires the extension azure-devops. Install it with az extension add --name azure-devops."

        self.assertEqual(
            azure_collect.resolve_missing_extension_name("az devops project list", output),
            "azure-devops",
        )

    def test_missing_nested_command_group_uses_known_extension_mapping(self):
        output = "az monitor: 'app-insights' is not in the 'monitor' command group. See 'az monitor --help'."

        self.assertEqual(
            azure_collect.resolve_missing_extension_name("az monitor app-insights component show", output),
            "application-insights",
        )

    def test_mapped_extension_is_not_installed_for_non_extension_errors(self):
        output = "ERROR: the following arguments are required: --name"

        self.assertIsNone(
            azure_collect.resolve_missing_extension_name("az iot hub show", output)
        )


if __name__ == "__main__":
    unittest.main()
