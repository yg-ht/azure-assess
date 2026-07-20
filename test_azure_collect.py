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

PRESENT_MODULE_PATH = Path(__file__).with_name("azure-present.py")
PRESENT_SPEC = importlib.util.spec_from_file_location("azure_present", PRESENT_MODULE_PATH)
azure_present = importlib.util.module_from_spec(PRESENT_SPEC)
PRESENT_SPEC.loader.exec_module(azure_present)


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


class SqlServerVulnerabilityAssessmentEndpointTests(unittest.TestCase):
    def test_sql_server_vulnerability_assessment_uses_arm_rest_endpoint(self):
        endpoint = next(
            endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
            if endpoint["name"] == "SQL Server Vulnerability Assessment"
        )

        self.assertIn("az rest --method get", endpoint["cli_command"])
        self.assertIn("{id}/vulnerabilityAssessments/default?api-version=2023-08-01", endpoint["cli_command"])
        self.assertNotIn("az sql server vuln-assessment show", endpoint["cli_command"])
        self.assertEqual(endpoint["required_params"], {"id": "az_sql_server_list"})
        self.assertEqual(
            azure_collect.endpoint_output_prefix(endpoint),
            "az_sql_server_vuln-assessment_show",
        )


class DefenderAssessmentFindingsDatasetTests(unittest.TestCase):
    def test_resource_portal_link_uses_resource_route(self):
        resource_id = (
            "/subscriptions/sub-one/resourceGroups/rg-one/"
            "providers/Microsoft.Storage/storageAccounts/storage-one"
        )
        link = azure_findings.resource_portal_link(resource_id)

        self.assertEqual(
            link,
            "https://portal.azure.com/#resource/subscriptions/sub-one/resourceGroups/rg-one/"
            "providers/Microsoft.Storage/storageAccounts/storage-one/overview",
        )
        self.assertNotIn("ResourceMenuBlade", link)

    def test_default_findings_input_dir_is_script_relative(self):
        expected = FINDINGS_MODULE_PATH.parent / "azure-collect"

        self.assertEqual(azure_findings.resolve_input_dir(None), expected)

    def test_relative_findings_input_dir_is_script_relative(self):
        self.assertEqual(
            azure_findings.resolve_input_dir("relative-data"),
            FINDINGS_MODULE_PATH.parent / "relative-data",
        )

    def test_absolute_findings_input_dir_is_preserved(self):
        absolute_path = Path("/tmp/relative-data")

        self.assertEqual(
            azure_findings.resolve_input_dir(str(absolute_path)),
            absolute_path,
        )

    def test_default_findings_output_paths_follow_resolved_input_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir) / "collected"

            self.assertEqual(
                azure_findings.resolve_output_path(input_dir, None, "azure-findings-flat.json"),
                input_dir / "azure-findings-flat.json",
            )

    def test_relative_findings_output_paths_follow_resolved_input_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir) / "collected"

            self.assertEqual(
                azure_findings.resolve_output_path(input_dir, "custom-flat.json", "azure-findings-flat.json"),
                input_dir / "custom-flat.json",
            )

    def test_absolute_findings_output_paths_are_preserved(self):
        absolute_path = Path("/tmp/custom-flat.json")

        self.assertEqual(
            azure_findings.resolve_output_path(Path("collected"), str(absolute_path), "azure-findings-flat.json"),
            absolute_path,
        )

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


class AzurePresentDatasetIndexTests(unittest.TestCase):
    def test_linkify_rendered_urls_labels_azure_portal_links_by_resource(self):
        html = (
            "https://portal.azure.com/#resource/subscriptions/sub-one/resourceGroups/rg-one/"
            "providers/Microsoft.Storage/storageAccounts/storage-one/overview"
        )

        linked_html = azure_present.linkify_rendered_urls(html)

        self.assertIn(">storageAccounts/storage-one</a>", linked_html)
        self.assertNotIn(">https://portal.azure.com", linked_html)
        self.assertIn('href="https://portal.azure.com/#resource/subscriptions/sub-one', linked_html)

    def test_linkify_rendered_urls_labels_viewer_links_by_dataset_and_query(self):
        html = (
            "/query/az_resource_list_20260705-000000.json?"
            "query=%2Fsubscriptions%2Fsub-one%2FresourceGroups%2Frg-one%2Fproviders"
            "%2FMicrosoft.Storage%2FstorageAccounts%2Fstorage-one"
        )

        linked_html = azure_present.linkify_rendered_urls(html)

        self.assertIn(">Az Resource List: storageAccounts/storage-one</a>", linked_html)
        self.assertNotIn(">/query/", linked_html)
        self.assertIn('href="/query/az_resource_list_20260705-000000.json?', linked_html)

    def test_findings_link_cell_with_ten_links_remains_expanded(self):
        links = [
            f"/query/file-{index}.json?query=resource-{index}"
            for index in range(10)
        ]
        html = azure_present.generate_html_table([{"viewer_links": links}])

        collapsed_html = azure_present.collapse_findings_link_cells(html)

        self.assertEqual(collapsed_html, html)
        self.assertNotIn("<details", collapsed_html)

    def test_findings_link_cell_with_eleven_links_is_collapsed(self):
        links = [
            f"/query/file-{index}.json?query=resource-{index}"
            for index in range(11)
        ]
        html = azure_present.generate_html_table([{"viewer_links": links}])

        collapsed_html = azure_present.collapse_findings_link_cells(html)

        self.assertIn('<details class="findings-links-disclosure">', collapsed_html)
        self.assertIn("<summary>11 links</summary>", collapsed_html)
        disclosure_html = collapsed_html.split('<details class="findings-links-disclosure">', 1)[1]
        disclosure_html = disclosure_html.split("</details>", 1)[0]
        self.assertEqual(disclosure_html.count("<a "), 11)

    def test_findings_link_cell_does_not_collapse_unrelated_links(self):
        links = "".join(
            f'<li><a href="https://example.com/{index}">Link {index}</a></li>'
            for index in range(11)
        )
        html = f"<table><tbody><tr><td><ul>{links}</ul></td></tr></tbody></table>"

        collapsed_html = azure_present.collapse_findings_link_cells(html)

        self.assertEqual(collapsed_html, html)

    def test_findings_route_renders_long_link_list_as_collapsed(self):
        links = [
            f"/query/file-{index}.json?query=resource-{index}"
            for index in range(11)
        ]
        finding_rows = {
            "rows": [
                {
                    "title": "Example finding",
                    "severity": "medium",
                    "status": "found",
                    "reason": "Regression test",
                    "count": 11,
                    "evidence": [],
                    "viewer_links": links,
                    "source_file": [],
                    "azure_portal_links": [],
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            findings_path = data_dir / azure_present.FINDINGS_FLAT_FILENAME
            findings_path.write_text(json.dumps(finding_rows), encoding="utf-8")

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                client = azure_present.app.test_client()
                response = client.get("/findings?status=all")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'<details class="findings-links-disclosure">', response.data)
        self.assertIn(b"<summary>11 links</summary>", response.data)

    def test_dataset_groups_default_does_not_load_record_counts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            latest_path = data_dir / "az_resource_list_20260402-000000.json"
            latest_path.write_text(json.dumps([{"name": "one"}, {"name": "two"}]), encoding="utf-8")

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                with mock.patch.object(azure_present, "load_json_file") as loader:
                    groups = azure_present.dataset_groups()

            self.assertEqual(len(groups), 1)
            self.assertEqual(groups[0]["filename"], latest_path.name)
            self.assertEqual(groups[0]["record_count"], "Loading...")
            loader.assert_not_called()

    def test_dataset_groups_only_loads_latest_file_for_record_counts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            old_path = data_dir / "az_resource_list_20260401-000000.json"
            latest_path = data_dir / "az_resource_list_20260402-000000.json"
            old_path.write_text(json.dumps([{"name": "old"}]), encoding="utf-8")
            latest_path.write_text(json.dumps([{"name": "one"}, {"name": "two"}]), encoding="utf-8")

            loaded_paths = []
            original_loader = azure_present.load_json_file

            def tracking_loader(path):
                loaded_paths.append(Path(path).name)
                return original_loader(path)

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                with mock.patch.object(azure_present, "load_json_file", side_effect=tracking_loader):
                    groups = azure_present.dataset_groups(load_record_counts=True)

            self.assertEqual(len(groups), 1)
            self.assertEqual(groups[0]["filename"], latest_path.name)
            self.assertEqual(groups[0]["record_count"], 2)
            self.assertEqual(loaded_paths, [latest_path.name])

    def test_dataset_counts_endpoint_returns_counts_for_valid_dataset_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            dataset_path = data_dir / "az_resource_list_20260402-000000.json"
            dataset_path.write_text(json.dumps([{"name": "one"}, {"name": "two"}]), encoding="utf-8")

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                client = azure_present.app.test_client()
                response = client.get(f"/dataset-counts?filename={dataset_path.name}")

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json(), {"counts": {dataset_path.name: 2}, "errors": {}})

    def test_dataset_counts_endpoint_rejects_unknown_and_unsafe_filenames(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            dataset_path = data_dir / "az_resource_list_20260402-000000.json"
            dataset_path.write_text(json.dumps([{"name": "one"}]), encoding="utf-8")

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                client = azure_present.app.test_client()
                response = client.get(
                    "/dataset-counts",
                    query_string=[
                        ("filename", dataset_path.name),
                        ("filename", "../secrets.json"),
                        ("filename", "azure-findings-flat.json"),
                    ],
                )

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["counts"], {dataset_path.name: 1})
            self.assertEqual(
                response.get_json()["errors"],
                {
                    "../secrets.json": "Unknown dataset file",
                    "azure-findings-flat.json": "Unknown dataset file",
                },
            )

    def test_datasets_route_renders_async_record_count_placeholders(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            dataset_path = data_dir / "az_resource_list_20260402-000000.json"
            dataset_path.write_text(json.dumps([{"name": "one"}]), encoding="utf-8")

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                with mock.patch.object(azure_present, "load_json_file") as loader:
                    client = azure_present.app.test_client()
                    response = client.get("/datasets")

            body = response.get_data(as_text=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn(f'data-record-count-filename="{dataset_path.name}"', body)
            self.assertIn("Loading...", body)
            loader.assert_not_called()

    def test_dashboard_renders_async_object_count_placeholder(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            dataset_path = data_dir / "az_resource_list_20260402-000000.json"
            dataset_path.write_text(json.dumps([{"name": "one"}]), encoding="utf-8")

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                with mock.patch.object(azure_present, "load_json_file") as loader:
                    client = azure_present.app.test_client()
                    response = client.get("/")

            body = response.get_data(as_text=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn(f'data-summary-count-filenames="{dataset_path.name}"', body)
            self.assertIn("Objects In Subscription", body)
            self.assertIn("Loading...", body)
            loader.assert_not_called()

    def test_dataset_group_lookup_does_not_load_json_payloads(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            latest_path = data_dir / "az_resource_list_20260402-000000.json"
            latest_path.write_text("{malformed json", encoding="utf-8")

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                with mock.patch.object(azure_present, "load_json_file") as loader:
                    group = azure_present.dataset_group_by_filename(latest_path.name)

            self.assertIsNotNone(group)
            self.assertEqual(group["filename"], latest_path.name)
            loader.assert_not_called()

    def test_findings_route_reports_missing_flat_file_for_selected_input_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                client = azure_present.app.test_client()
                response = client.get("/findings")

            body = response.get_data(as_text=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn("Findings data has not been generated", body)
            self.assertIn(str(data_dir / "azure-findings-flat.json"), body)
            self.assertIn(f"python azure-findings.py -i {data_dir}", body)


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
    def test_virtual_networks_are_collected_per_resource_group(self):
        base_names = {
            endpoint["name"]
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS
        }
        self.assertNotIn("Virtual Networks", base_names)

        endpoint = next(
            endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
            if endpoint["name"] == "Virtual Networks"
        )

        self.assertEqual(endpoint["cli_command"], "az network vnet list --resource-group \"{name}\"")
        self.assertEqual(endpoint["required_params"], {"name": "az_group_list"})
        self.assertEqual(azure_collect.endpoint_output_prefix(endpoint), "az_network_vnet_list")

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

    def test_builtin_role_cache_rejects_subscription_scoped_values(self):
        with self.assertRaises(ValueError):
            azure_collect.validate_builtin_role_definitions(
                [
                    {
                        "id": "/subscriptions/sub-one/providers/Microsoft.Authorization/roleDefinitions/role-guid",
                        "name": "role-guid",
                        "roleType": "BuiltInRole",
                    }
                ]
            )

    def test_builtin_role_cache_normalises_subscription_scoped_ids(self):
        role = {
            "id": "/subscriptions/sub-one/providers/Microsoft.Authorization/roleDefinitions/role-guid",
            "name": "role-guid",
            "roleType": "BuiltInRole",
        }

        self.assertEqual(
            azure_collect.normalize_builtin_role_definition(role)["id"],
            "/providers/Microsoft.Authorization/roleDefinitions/role-guid",
        )

    def test_builtin_role_cache_load_normalises_legacy_subscription_scoped_ids(self):
        payload = {
            "schemaVersion": 1,
            "roleDefinitions": [
                {
                    "id": "/subscriptions/sub-one/providers/Microsoft.Authorization/roleDefinitions/reader-guid",
                    "name": "reader-guid",
                    "roleType": "BuiltInRole",
                }
            ],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "cache.json"
            cache_path.write_text(json.dumps(payload), encoding="utf-8")

            roles = azure_collect.load_managed_role_definitions_cache(cache_path)

        self.assertEqual(
            roles[0]["id"],
            "/providers/Microsoft.Authorization/roleDefinitions/reader-guid",
        )

    def test_builtin_role_cache_load_accepts_subscription_neutral_schema_v2(self):
        payload = {
            "schemaVersion": 2,
            "roleDefinitionIdFormat": "/providers/Microsoft.Authorization/roleDefinitions/{roleGuid}",
            "subscriptionIdentifiers": "removed",
            "roleDefinitions": [
                {
                    "id": "/providers/Microsoft.Authorization/roleDefinitions/reader-guid",
                    "name": "reader-guid",
                    "roleType": "BuiltInRole",
                }
            ],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "cache.json"
            cache_path.write_text(json.dumps(payload), encoding="utf-8")

            roles = azure_collect.load_managed_role_definitions_cache(cache_path)

        self.assertEqual(
            roles[0]["id"],
            "/providers/Microsoft.Authorization/roleDefinitions/reader-guid",
        )

    def test_builtin_role_cache_write_sanitises_subscription_scoped_ids(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "cache.json"

            azure_collect.write_managed_role_definitions_cache(
                [
                    {
                        "id": "/subscriptions/sub-one/providers/Microsoft.Authorization/roleDefinitions/reader-guid",
                        "name": "reader-guid",
                        "roleType": "BuiltInRole",
                    }
                ],
                path=cache_path,
                az_version={"azure-cli": "test"},
            )

            payload = json.loads(cache_path.read_text(encoding="utf-8"))

        self.assertEqual(payload["schemaVersion"], 2)
        self.assertEqual(
            payload["roleDefinitionIdFormat"],
            "/providers/Microsoft.Authorization/roleDefinitions/{roleGuid}",
        )
        self.assertEqual(payload["subscriptionIdentifiers"], "removed")
        self.assertEqual(
            payload["roleDefinitions"][0]["id"],
            "/providers/Microsoft.Authorization/roleDefinitions/reader-guid",
        )

    def test_collect_managed_role_definitions_cache_writes_validated_payload(self):
        commands = []
        written = {}

        def fake_run_json_command(command):
            commands.append(command)
            if command.startswith("az version"):
                return {"azure-cli": "test"}, None
            return [
                {
                    "id": "/subscriptions/sub-one/providers/Microsoft.Authorization/roleDefinitions/reader-guid",
                    "name": "reader-guid",
                    "roleType": "BuiltInRole",
                }
            ], None

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
        self.assertEqual(
            written["role_definitions"],
            [
                {
                    "id": "/providers/Microsoft.Authorization/roleDefinitions/reader-guid",
                    "name": "reader-guid",
                    "roleType": "BuiltInRole",
                }
            ],
        )
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

    def test_role_assignment_enrichment_matches_subscription_neutral_builtin_role_ids(self):
        role_assignments = [
            {
                "principalId": "principal-one",
                "roleDefinitionId": "/subscriptions/sub-one/providers/Microsoft.Authorization/roleDefinitions/reader-guid",
            }
        ]
        role_definitions = [
            {
                "id": "/providers/Microsoft.Authorization/roleDefinitions/reader-guid",
                "name": "reader-guid",
                "roleName": "Reader",
                "permissions": [{"actions": ["Microsoft.Resources/subscriptions/read"]}],
            }
        ]

        with mock.patch.object(azure_collect, "resolve_principal", return_value={"name": "User One"}):
            enriched = azure_collect.resolve_role_assignments(role_assignments, role_definitions)

        self.assertEqual(enriched[0]["roleDefinitionName"], "Reader")
        self.assertEqual(enriched[0]["permissionSet"], role_definitions[0]["permissions"])

    def test_lock_admin_finding_matches_subscription_neutral_builtin_role_ids(self):
        role_definitions = [
            {
                "id": "/providers/Microsoft.Authorization/roleDefinitions/lock-admin-guid",
                "roleName": "Lock Administrator",
                "permissions": [{"actions": ["Microsoft.Authorization/locks/*"]}],
            }
        ]
        role_assignments = [
            {
                "scope": "/subscriptions/sub-one",
                "principalId": "principal-one",
                "roleDefinitionId": "/subscriptions/sub-one/providers/Microsoft.Authorization/roleDefinitions/lock-admin-guid",
            }
        ]

        finding = azure_findings.find_resource_lock_admin_role_gap(role_definitions, role_assignments)

        self.assertEqual(finding["status"], "found")
        self.assertEqual(finding["evidence"][0]["roleDefinitionName"], "Lock Administrator")


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

    def test_apim_details_only_uses_apim_service_source_records(self):
        endpoint = next(
            endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
            if endpoint["name"] == "API Management Service Details"
        )
        commands_run = []
        saved_payloads = []

        def fake_run_az_cli(cmd):
            commands_run.append(cmd)
            return {"json": {"command": cmd}, "success": True, "stdout": "{}"}

        def fake_save_json(data, filename, append=False):
            saved_payloads.append((data, filename, append))

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            source_file = output_dir / "az_apim_list_20260402-000000.json"
            source_file.write_text(
                json.dumps(
                    [
                        {
                            "name": "wrong-name",
                            "resourceGroup": "wrong-rg",
                            "type": "Microsoft.Web/sites",
                        },
                        {
                            "name": "apim-one",
                            "resourceGroup": "apim-rg",
                            "type": "Microsoft.ApiManagement/service",
                        },
                    ]
                ),
                encoding="utf-8",
            )

            azure_collect.OUTPUT_DIR = output_dir

            with mock.patch.object(azure_collect, "run_az_cli", side_effect=fake_run_az_cli):
                with mock.patch.object(azure_collect, "save_json", side_effect=fake_save_json):
                    azure_collect.collect_data_with_params([endpoint])

        self.assertEqual(
            commands_run,
            ["az apim show --name apim-one --resource-group apim-rg"],
        )
        self.assertEqual(len(saved_payloads), 1)

    def test_app_service_environment_details_can_resolve_name_from_resource_id(self):
        endpoint = next(
            endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
            if endpoint["name"] == "App Service Environment Details"
        )
        commands_run = []
        saved_payloads = []

        def fake_run_az_cli(cmd):
            commands_run.append(cmd)
            return {"json": {"command": cmd}, "success": True, "stdout": "{}"}

        def fake_save_json(data, filename, append=False):
            saved_payloads.append((data, filename, append))

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            source_file = output_dir / "az_appservice_ase_list_20260402-000000.json"
            source_file.write_text(
                json.dumps(
                    [
                        {
                            "id": (
                                "/subscriptions/sub-one/resourceGroups/ase-rg/providers/"
                                "Microsoft.Web/hostingEnvironments/ase-one"
                            ),
                            "type": "Microsoft.Web/hostingEnvironments",
                        }
                    ]
                ),
                encoding="utf-8",
            )

            azure_collect.OUTPUT_DIR = output_dir

            with mock.patch.object(azure_collect, "run_az_cli", side_effect=fake_run_az_cli):
                with mock.patch.object(azure_collect, "save_json", side_effect=fake_save_json):
                    azure_collect.collect_data_with_params([endpoint])

        self.assertEqual(commands_run, ["az appservice ase show --name ase-one"])
        self.assertEqual(len(saved_payloads), 1)

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
        azure_collect.COLLECTION_ERRORS.clear()

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

    def test_advisory_extension_install_text_is_not_treated_as_requirement(self):
        output = (
            "WARNING: The 'cdn' and 'afd' command groups have moved to the 'cdn' CLI extension. "
            "Install the latest version with: az extension add --name cdn.\n"
            "ERROR: 'vuln-assessment' is misspelled or not recognized by the system."
        )

        self.assertIsNone(
            azure_collect.resolve_missing_extension_name(
                "az sql server vuln-assessment show --server sql-one --resource-group rg-one",
                output,
            )
        )


class AzureCliCollectionErrorTests(unittest.TestCase):
    def setUp(self):
        azure_collect.DEBUG = False
        azure_collect.COLLECTION_ERRORS.clear()
        azure_collect.START_TIMESTAMP = "20260402-000000"

    def tearDown(self):
        azure_collect.COLLECTION_ERRORS.clear()

    def test_malformed_cli_command_records_error_without_system_exit(self):
        output = "ERROR: 'vuln-assessment' is misspelled or not recognized by the system."

        with mock.patch.object(
            azure_collect.subprocess,
            "Popen",
            return_value=FakeAzProcess(2, output),
        ):
            result = azure_collect.run_az_cli(
                "az sql server vuln-assessment show",
                endpoint_name="SQL Server Vulnerability Assessment",
                category="parameterised",
            )

        self.assertFalse(result["success"])
        self.assertEqual(result["returncode"], 2)
        self.assertEqual(len(azure_collect.COLLECTION_ERRORS), 1)
        self.assertEqual(
            azure_collect.COLLECTION_ERRORS[0]["message"],
            "Unrecognised or malformed CLI command",
        )
        self.assertEqual(
            azure_collect.COLLECTION_ERRORS[0]["endpoint"],
            "SQL Server Vulnerability Assessment",
        )

    def test_base_collection_continues_and_accumulates_multiple_command_errors(self):
        endpoints = [
            {"name": "Broken One", "cli_command": "az broken one"},
            {"name": "Broken Two", "cli_command": "az broken two"},
        ]

        def fake_run_az_cli(cmd, endpoint_name=None, category=None):
            if cmd.startswith("az config set "):
                return {"success": True, "returncode": 0, "stdout": "{}", "json": {}}

            endpoint_name = endpoint_name or getattr(azure_collect.AZURE_CLI_CONTEXT, "endpoint_name", None)
            category = category or getattr(azure_collect.AZURE_CLI_CONTEXT, "category", "collection")
            result = {
                "success": False,
                "returncode": 2,
                "stdout": f"ERROR: {cmd} failed",
                "json": None,
            }
            azure_collect.record_collection_error(
                cmd,
                "Unrecognised or malformed CLI command",
                result,
                endpoint_name=endpoint_name,
                category=category,
            )
            return result

        with mock.patch.object(azure_collect, "run_az_cli", side_effect=fake_run_az_cli):
            with mock.patch.object(azure_collect, "save_json") as save_mock:
                azure_collect.collect_data(endpoints, max_workers=1)

        self.assertEqual(len(azure_collect.COLLECTION_ERRORS), 2)
        self.assertEqual(
            [error["endpoint"] for error in azure_collect.COLLECTION_ERRORS],
            ["Broken One", "Broken Two"],
        )
        save_mock.assert_not_called()

    def test_collection_error_summary_prints_all_errors(self):
        azure_collect.record_collection_error(
            "az broken one",
            "first failure",
            {"returncode": 2, "stdout": "first details"},
            endpoint_name="Broken One",
            category="base",
        )
        azure_collect.record_collection_error(
            "az broken two",
            "second failure",
            {"returncode": 3, "stdout": "second details"},
            endpoint_name="Broken Two",
            category="parameterised",
        )

        with mock.patch("builtins.print") as print_mock:
            azure_collect.print_collection_error_summary()

        printed = "\n".join(str(call.args[0]) for call in print_mock.call_args_list if call.args)
        self.assertIn("2 command error(s)", printed)
        self.assertIn("Broken One", printed)
        self.assertIn("Broken Two", printed)
        self.assertIn("second failure", printed)


if __name__ == "__main__":
    unittest.main()
