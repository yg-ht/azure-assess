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
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS
            if endpoint["name"] == "Defender Assessments"
        )

        self.assertIn("az rest --method get", endpoint["cli_command"])
        self.assertIn("Microsoft.Security/assessments?api-version=2020-01-01", endpoint["cli_command"])
        self.assertNotIn("az security assessment list", endpoint["cli_command"])
        self.assertTrue(endpoint["extract_value"])

    def test_defender_assessments_extracts_value_and_uses_safe_filename(self):
        endpoint = {
            "name": "Defender Assessments",
            "cli_command": "az rest --method get --url \"/subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01\"",
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
            "az_rest_--method_get_--url_subscriptions_subscriptionid_providers_microsoft.security_assessments_api-version_2020-01-01_20260402-000000.json": {
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


class CollectDataWithParamsTests(unittest.TestCase):
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
            source_file = output_dir / "az_vm_nic_list_fixture.json"
            source_file.write_text(json.dumps(source_records), encoding="utf-8")

            azure_collect.OUTPUT_DIR = output_dir
            azure_collect.START_TIMESTAMP = "20260402-000000"
            azure_collect.DEBUG = False

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
