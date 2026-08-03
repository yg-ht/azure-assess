import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "azure-collect.py"
SPEC = importlib.util.spec_from_file_location("azure_collect", MODULE_PATH)
azure_collect = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(azure_collect)

FINDINGS_MODULE_PATH = Path(__file__).resolve().parents[1] / "azure-findings.py"
FINDINGS_SPEC = importlib.util.spec_from_file_location("azure_findings", FINDINGS_MODULE_PATH)
azure_findings = importlib.util.module_from_spec(FINDINGS_SPEC)
FINDINGS_SPEC.loader.exec_module(azure_findings)

PRESENT_MODULE_PATH = Path(__file__).resolve().parents[1] / "azure-present.py"
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


class AuthenticationContextTests(unittest.TestCase):
    def test_validation_captures_the_active_account_when_scope_was_not_supplied(self):
        account_result = mock.Mock(
            returncode=0,
            stdout=json.dumps({"id": "sub-active", "tenantId": "tenant-active"}),
        )
        azure_collect.AUTH_CONFIG = {
            "auth_method": "existing",
            "tenant_id": None,
            "subscription_id": None,
        }

        with mock.patch.object(azure_collect, "run_az_command", return_value=account_result):
            with mock.patch.object(azure_collect, "validate_access_token", return_value=True):
                self.assertTrue(azure_collect.validate_auth_session())

        self.assertEqual(azure_collect.AUTH_CONFIG["tenant_id"], "tenant-active")
        self.assertEqual(azure_collect.AUTH_CONFIG["subscription_id"], "sub-active")


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
                azure_findings.resolve_output_path(
                    input_dir,
                    None,
                    azure_findings.DEFAULT_SARIF_OUTPUT_FILENAME,
                ),
                input_dir / "azure-findings-SARIF.json",
            )

    def test_sarif_output_filename_identifies_its_format(self):
        self.assertIn("SARIF", azure_findings.DEFAULT_SARIF_OUTPUT_FILENAME)

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

        self.assertIn(">Resources: storageAccounts/storage-one</a>", linked_html)
        self.assertNotIn(">Az Resource List", linked_html)
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

    def test_findings_rows_prioritise_actionable_columns_and_add_entities(self):
        row = {
            "finding_id": "example_finding",
            "definition": {},
            "reporting": {
                "assets": [
                    {"name": "account-one", "identifier": "/accounts/one"},
                    {"name": "account-one", "identifier": "/accounts/one"},
                    {"name": None, "identifier": "/accounts/two"},
                ]
            },
            "title": "Example finding",
            "severity": "medium",
            "status": "found",
            "reason": "Regression test",
            "count": 2,
            "evidence": [{"name": "account-one"}],
            "viewer_links": ["/query/one.json", "/query/one.json"],
        }

        prepared = azure_present.prepare_findings_rows([row])[0]

        self.assertEqual(
            list(prepared)[:8],
            [
                "title",
                "severity",
                "status",
                "reason",
                "count",
                "evidence",
                "viewer_links",
                "affected_entities",
            ],
        )
        self.assertEqual(prepared["viewer_links"], ["/query/one.json"])
        self.assertEqual(
            prepared["affected_entities"],
            ["account-one", "/accounts/two"],
        )
        self.assertIn("definition", prepared)
        self.assertEqual(list(prepared)[-1], "finding_id")

    def test_affected_entities_remain_complete_for_expandable_display(self):
        entities = [f"account-{index}" for index in range(10)]
        prepared = azure_present.prepare_findings_rows([
            {"affected_entities": entities}
        ])

        html = azure_present.generate_html_table(prepared)

        self.assertEqual(
            prepared[0]["affected_entities"],
            entities,
        )
        self.assertNotIn("<details", html)
        self.assertEqual(html.count("<li>"), len(entities))

    def test_findings_header_tooltips_explain_metadata_columns(self):
        row = {
            "definition": {},
            "reporting": {},
            "context": {},
            "coverage": {},
            "review": {},
            "triage": {},
            "affected_entities": [],
        }
        html = azure_present.generate_html_table([row])

        annotated = azure_present.add_findings_header_tooltips(html)

        for name, tooltip in azure_present.FINDINGS_HEADER_TOOLTIPS.items():
            self.assertIn(
                f'aria-sort="none" title="{tooltip}">'
                f'{azure_present.title_case_column_heading(name)}</th>',
                annotated,
            )
        self.assertIn(
            f'data-initial-visible-count="{azure_present.AFFECTED_ENTITIES_DISPLAY_LIMIT}">'
            "Affected Entities</th>",
            annotated,
        )

    def test_findings_data_headers_are_sortable_but_json_action_source_is_not(self):
        html = azure_present.generate_html_table([
            {"title": "Example", "count": 1}
        ])

        annotated = azure_present.add_findings_header_tooltips(html)

        self.assertIn("<th>json_string</th>", annotated)
        self.assertIn(
            '<th class="table-sortable" tabindex="0" role="button" '
            'aria-sort="none">Title</th>',
            annotated,
        )
        self.assertIn(
            '<th class="table-sortable" tabindex="0" role="button" '
            'aria-sort="none">Count</th>',
            annotated,
        )
        self.assertNotIn('aria-sort="none">json_string</th>', annotated)

    def test_dataset_headers_are_title_cased_without_changing_nested_keys(self):
        html = azure_present.generate_html_table([
            {
                "resourceGroup": "rg-one",
                "subscription_id": "sub-one",
                "details": {"finding_id": "nested-id"},
            }
        ])

        prepared = azure_present.prepare_top_level_headers(html)

        self.assertIn("<th>Resource Group</th>", prepared)
        self.assertIn("<th>Subscription ID</th>", prepared)
        self.assertIn("<th>Details</th>", prepared)
        self.assertIn("<th>finding_id</th>", prepared)

    def test_duplicate_links_are_removed_before_collapse_threshold_is_applied(self):
        unique_links = [
            f"/query/file-{index}.json?query=resource-{index}"
            for index in range(10)
        ]
        prepared = azure_present.prepare_findings_rows([
            {"viewer_links": unique_links + [unique_links[0]]}
        ])
        html = azure_present.generate_html_table(prepared)

        collapsed_html = azure_present.collapse_findings_link_cells(html)

        self.assertEqual(prepared[0]["viewer_links"], unique_links)
        self.assertNotIn("<details", collapsed_html)
        self.assertEqual(collapsed_html.count("<li>"), 10)

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

    def test_findings_route_hides_unprepared_table_behind_loading_status(self):
        finding_rows = {
            "rows": [
                {
                    "title": "Example finding",
                    "severity": "medium",
                    "status": "found",
                    "reason": "Regression test",
                    "count": 1,
                    "evidence": [{"name": "account-one"}],
                    "viewer_links": [],
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

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('id="data-table-loading"', body)
        self.assertIn('role="status"', body)
        self.assertIn("Preparing data view…", body)
        self.assertIn('id="table-content" class="table-content-pending"', body)
        self.assertIn("content.classList.remove('table-content-pending')", body)
        self.assertIn("loading.hidden = true", body)
        self.assertIn('id="decreaseTableFont"', body)
        self.assertIn('id="increaseTableFont"', body)
        self.assertIn("white-space: nowrap", body)
        self.assertIn("Show ${hiddenItems.length} more", body)
        self.assertIn("'Show fewer'", body)
        self.assertIn('data-initial-visible-count="8"', body)
        self.assertIn("font-size: var(--table-font-size, 0.8rem)", body)
        self.assertIn('class="data-filter-controls-row"', body)
        self.assertIn('class="data-filter-actions-row"', body)
        controls_row = body.split('class="data-filter-controls-row"', 1)[1]
        controls_row = controls_row.split('class="data-filter-actions-row"', 1)[0]
        self.assertIn('id="findingsStatusSelect" name="status"', controls_row)
        self.assertIn('id="query"', controls_row)
        self.assertNotIn('id="findingsStatusInput"', body)
        actions_row = body.split('class="data-filter-actions-row"', 1)[1]
        actions_row = actions_row.split("</form>", 1)[0]
        self.assertIn(">Search</button>", actions_row)
        self.assertIn(">Reset Search</a>", actions_row)
        self.assertIn('aria-label="Table font size"', actions_row)

    def test_dataset_query_route_uses_the_same_loading_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            dataset_path = data_dir / "az_resource_list_20260402-000000.json"
            dataset_path.write_text(json.dumps([{"name": "account-one"}]), encoding="utf-8")

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                client = azure_present.app.test_client()
                response = client.get(f"/query/{dataset_path.name}")

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('id="data-table-loading"', body)
        self.assertIn('progress-bar-animated', body)
        self.assertIn('id="table-content" class="table-content-pending"', body)
        self.assertIn('id="decreaseTableFont"', body)
        self.assertIn('id="increaseTableFont"', body)
        self.assertIn(
            '<th class="table-sortable" tabindex="0" role="button" '
            'aria-sort="none">Name</th>',
            body,
        )
        self.assertIn('class="data-filter-controls-row"', body)
        self.assertIn('class="data-filter-actions-row"', body)
        self.assertNotIn('id="findingsStatusSelect"', body)

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
                        ("filename", "azure-findings-SARIF.json"),
                        ("filename", "azure-findings.json"),
                    ],
                )

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["counts"], {dataset_path.name: 1})
            self.assertEqual(
                response.get_json()["errors"],
                {
                    "../secrets.json": "Unknown dataset file",
                    "azure-findings-flat.json": "Unknown dataset file",
                    "azure-findings-SARIF.json": "Unknown dataset file",
                    "azure-findings.json": "Unknown dataset file",
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

    def test_dashboard_colours_follow_light_and_dark_themes(self):
        findings_rows = {
            "rows": [
                {"status": "found"},
                {"status": "not_found"},
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            findings_path = data_dir / azure_present.FINDINGS_FLAT_FILENAME
            findings_path.write_text(json.dumps(findings_rows), encoding="utf-8")

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                client = azure_present.app.test_client()
                response = client.get("/")

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("--dashboard-muted-text: #5c636a", body)
        self.assertIn("--dashboard-muted-text: #b8c0c8", body)
        self.assertIn("--dashboard-card-border: #6c757d", body)
        self.assertIn("--dashboard-card-border: #69737d", body)
        self.assertIn("dashboard-summary-card", body)
        self.assertIn("dashboard-muted", body)
        self.assertNotIn("text-secondary", body)
        self.assertIn(
            "window.dispatchEvent(new Event('azure-theme-change'))",
            body,
        )
        self.assertIn(
            "window.addEventListener('azure-theme-change', drawPieChart)",
            body,
        )

    def test_dashboard_surfaces_direct_azure_request_failures(self):
        findings_rows = {
            "rows": [
                {"status": "no_data_to_assess"},
                {"status": "no_data_to_assess"},
                {"status": "no_data_to_assess"},
                {"status": "found"},
            ]
        }
        manifest = {
            "endpoint_runs": [
                {
                    "endpoint_name": "Storage Account Keys",
                    "category": "parameterised",
                    "status": "unauthorised",
                    "returncode": 1,
                    "parameter_context": {"name": "account-one"},
                    "error": "(AuthorizationFailed) Principal cannot list storage account keys.",
                },
                {
                    "endpoint_name": "Legacy Failed Endpoint",
                    "category": "base",
                    "status": "failed",
                    "returncode": 2,
                    "parameter_context": {},
                    "error": "Legacy manifest error message",
                },
                {
                    "endpoint_name": "Unattempted Endpoint",
                    "category": "base",
                    "status": "not_attempted",
                    "returncode": None,
                },
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            findings_path = data_dir / azure_present.FINDINGS_FLAT_FILENAME
            findings_path.write_text(json.dumps(findings_rows), encoding="utf-8")
            manifest_path = data_dir / "azure-collection-manifest_20260803-120000.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                summary = azure_present.findings_summary()
                requests = azure_present.collection_request_summary()
                cards = azure_present.build_dashboard_summary_cards(
                    [],
                    summary,
                    requests,
                )
                client = azure_present.app.test_client()
                response = client.get("/")

        self.assertEqual(summary["no_data_to_assess"], 3)
        self.assertNotIn("permission_blocked", summary)
        self.assertEqual(requests["failed"], 1)
        self.assertEqual(requests["unauthorised"], 1)
        failed_card = next(
            card for card in cards if card["label"] == "Failed Azure Requests"
        )
        unauthorised_card = next(
            card for card in cards if card["label"] == "Unauthorised Azure Requests"
        )
        self.assertEqual(failed_card["value"], 1)
        self.assertEqual(unauthorised_card["value"], 1)
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('"label": "Permission Blocked"', body)
        self.assertIn('"label": "No Data To Assess", "value": 3', body)
        self.assertIn('"label": "Failed Azure Requests", "value": 1', body)
        self.assertIn('"label": "Unauthorised Azure Requests", "value": 1', body)
        self.assertIn("Unsuccessful Azure Requests", body)
        self.assertIn('<details class="dashboard-request-details">', body)
        self.assertNotIn('<details class="dashboard-request-details" open>', body)
        self.assertIn("dashboard-request-table", body)
        self.assertIn("--bs-table-color: var(--text-color)", body)
        self.assertEqual(body.count('class="dashboard-sort-button"'), 7)
        self.assertEqual(body.count('class="dashboard-column-filter"'), 7)
        self.assertIn("function applyFilters()", body)
        self.assertIn("leftValue.localeCompare", body)
        self.assertIn("Storage Account Keys", body)
        self.assertIn("AuthorizationFailed", body)
        self.assertIn("Principal cannot list storage account keys.", body)
        self.assertIn("Legacy manifest error message", body)
        self.assertNotIn("Unattempted Endpoint", body)

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

    def test_every_collector_output_prefix_has_its_declared_friendly_name(self):
        endpoints = (
            azure_collect.AZURE_CLI_ENDPOINTS
            + azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
        )

        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint["name"]):
                prefix = azure_collect.endpoint_output_prefix(endpoint)
                self.assertEqual(
                    azure_present.DATASET_NAME_MAP.get(prefix),
                    endpoint["name"],
                )

    def test_recent_sanitised_and_explicit_output_prefixes_have_friendly_names(self):
        expected_names = {
            "az_resource_list_--resource-type_microsoft.web_kubeenvironments":
                "Kubernetes Environments",
            "az_rest_--method_get_--url_https_graph.microsoft.com_v1.0_directoryroles":
                "Graph Directory Roles",
            "az_functionapp_auth_show": "Function App Auth Settings",
            "az_search_service_list": "Search Services",
            "az_sql_server_threat-policy_show": "SQL Server Threat Policy",
            "az_rest_--method_get_--url_subscriptions_id_providers_microsoft.security_assessments_api-version_2020-01-01":
                "Defender Assessments",
        }

        for prefix, expected_name in expected_names.items():
            with self.subTest(prefix=prefix):
                self.assertEqual(
                    azure_present.display_name_for_dataset(
                        f"{prefix}_20260727-120000.json"
                    ),
                    expected_name,
                )

    def test_legacy_output_prefix_keeps_its_friendly_name(self):
        legacy_prefix = azure_present.collect_filename_prefix(
            "az rest --method get --url https://graph.microsoft.com/v1.0/directoryRoles"
        )

        self.assertEqual(
            azure_present.DATASET_NAME_MAP[legacy_prefix],
            "Graph Directory Roles",
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

            def fake_save_json(
                data,
                filename,
                append=False,
                source_endpoint_identifiers=None,
            ):
                saved_payloads.append(
                    (data, filename, append, source_endpoint_identifiers)
                )

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
        self.assertEqual(
            saved_payloads[0][3],
            ["az_role_definition_custom_list"],
        )

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

    def test_service_tags_use_one_physical_region_and_ignore_logical_locations(self):
        endpoint = next(
            endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
            if endpoint["name"] == "Azure Network Resources"
        )
        commands_run = []
        saved_payloads = []

        def fake_run_az_cli(cmd):
            commands_run.append(cmd)
            return {
                "json": {"values": [{"name": "AzureCloud"}]},
                "success": True,
                "stdout": "{}",
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            source_file = output_dir / "az_account_list-locations_20260402-000000.json"
            source_file.write_text(
                json.dumps(
                    [
                        {
                            "name": "asia",
                            "type": "Region",
                            "metadata": {"regionType": "Logical"},
                        },
                        {
                            "name": "uksouth",
                            "type": "Region",
                            "metadata": {"regionType": "Physical"},
                        },
                        {
                            "name": "ukwest",
                            "type": "Region",
                            "metadata": {"regionType": "Physical"},
                        },
                        {
                            "name": "edge-one",
                            "type": "EdgeZone",
                            "metadata": {"regionType": "Physical"},
                        },
                    ]
                ),
                encoding="utf-8",
            )
            azure_collect.OUTPUT_DIR = output_dir

            with mock.patch.object(azure_collect, "run_az_cli", side_effect=fake_run_az_cli):
                with mock.patch.object(
                    azure_collect,
                    "save_json",
                    side_effect=lambda data, filename, append=False: saved_payloads.append(
                        (data, filename)
                    ),
                ):
                    azure_collect.collect_data_with_params([endpoint])

        self.assertEqual(
            commands_run,
            ["az network list-service-tags --location uksouth"],
        )
        self.assertEqual(len(saved_payloads), 1)

    def test_customer_collection_does_not_request_provider_cross_connections(self):
        endpoint_names = {endpoint["name"] for endpoint in azure_collect.AZURE_CLI_ENDPOINTS}
        endpoint_commands = {endpoint["cli_command"] for endpoint in azure_collect.AZURE_CLI_ENDPOINTS}

        self.assertNotIn("Peering Services", endpoint_names)
        self.assertNotIn("az network cross-connection list", endpoint_commands)

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
        self.assertEqual(result["_retry_count"], 1)
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

    def test_nonzero_azure_request_records_direct_failure_and_continues(self):
        output = "(AuthorizationFailed) Principal cannot read this resource."

        with mock.patch.object(
            azure_collect.subprocess,
            "Popen",
            return_value=FakeAzProcess(1, output),
        ):
            result = azure_collect.run_az_cli(
                "az resource list",
                endpoint_name="Resources",
                category="base",
            )

        self.assertFalse(result["success"])
        self.assertEqual(result["returncode"], 1)
        self.assertEqual(len(azure_collect.COLLECTION_ERRORS), 1)
        self.assertEqual(
            azure_collect.COLLECTION_ERRORS[0]["message"],
            "Azure CLI request failed with return code 1",
        )
        self.assertEqual(
            azure_collect.COLLECTION_ERRORS[0]["process_output"],
            output,
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
