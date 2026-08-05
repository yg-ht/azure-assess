import importlib.util
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
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


class AzureCliCommandSafetyTests(unittest.TestCase):
    def test_parameter_values_remain_single_arguments_without_shell_interpretation(self):
        resource_name = "alert (production); touch should-not-exist"
        command = azure_collect.format_parameterised_cli_command(
            "az monitor metrics list-namespaces --resource {id}",
            {"id": resource_name},
        )

        self.assertEqual(
            command,
            ["az", "monitor", "metrics", "list-namespaces", "--resource", resource_name],
        )

        completed = mock.Mock(returncode=0)
        with mock.patch.object(
            azure_collect.subprocess,
            "run",
            return_value=completed,
        ) as subprocess_run:
            result = azure_collect.run_az_command(command, capture_output=True)

        self.assertIs(result, completed)
        subprocess_run.assert_called_once_with(
            command,
            capture_output=True,
            text=True,
        )
        self.assertNotIn("shell", subprocess_run.call_args.kwargs)

    def test_parameter_substitution_preserves_embedded_query_placeholders(self):
        account_name = "storage account (production)"
        command = azure_collect.format_parameterised_cli_command(
            "az storage container list --account-name {name} --query "
            "'[].{{container_name:name, storage_account_name:`{name}`}}'",
            {"name": account_name},
        )

        self.assertEqual(command[5], account_name)
        self.assertEqual(
            command[7],
            "[].{container_name:name, storage_account_name:`storage account (production)`}",
        )

    def test_empty_or_nul_arguments_are_rejected(self):
        with self.assertRaises(ValueError):
            azure_collect.command_argv(["az", ""])
        with self.assertRaises(ValueError):
            azure_collect.command_argv(["az", "bad\x00argument"])

    def test_streaming_azure_cli_process_does_not_request_a_shell(self):
        with mock.patch.object(
            azure_collect.subprocess,
            "Popen",
            return_value=FakeAzProcess(0, "[]"),
        ) as popen:
            result = azure_collect.run_az_cli_process(["az", "account", "list"])

        self.assertTrue(result["success"])
        self.assertEqual(popen.call_args.args[0], ["az", "account", "list"])
        self.assertNotIn("shell", popen.call_args.kwargs)

    def test_json_command_timeout_is_reported_without_aborting_collection(self):
        with mock.patch.object(
            azure_collect,
            "run_az_command",
            side_effect=azure_collect.subprocess.TimeoutExpired("az version", 3),
        ):
            payload, error = azure_collect.run_json_command(
                "az version --output json",
                timeout=3,
            )

        self.assertIsNone(payload)
        self.assertEqual("Command timed out after 3 seconds", error)

    def test_graph_console_progress_uses_friendly_non_sensitive_context(self):
        output = io.StringIO()
        with redirect_stdout(output):
            azure_collect.print_graph_progress(
                "endpoint_started",
                {
                    "index": 4,
                    "total": 88,
                    "endpoint_name": "Graph Security Incidents",
                    "profile": "DefenderHunting",
                    "api": "v1.0",
                    "parent_count": 1,
                    "endpoint_id": "technical-id-not-for-console",
                },
            )
            azure_collect.print_graph_progress(
                "audit_poll",
                {
                    "endpoint_name": "Unified Audit",
                    "status": "running",
                    "elapsed_seconds": 30,
                    "poll": 15,
                    "query_id": "query-id-not-for-console",
                },
            )
            azure_collect.print_graph_progress(
                "consolidation_started",
                {
                    "endpoint_name": "Graph Group Assignments",
                    "part_count": 120,
                    "total_records": 45000,
                },
            )
            azure_collect.print_graph_progress(
                "fanout_index_started",
                {
                    "endpoint_name": "Graph Groups",
                    "child_count": 4,
                    "total_records": 20000,
                    "parent_id": "parent-id-not-for-console",
                },
            )

        rendered = output.getvalue()
        self.assertIn("Graph [4/88]: Graph Security Incidents", rendered)
        self.assertIn("audit query running after 30s", rendered)
        self.assertIn("consolidating 120 streamed parts", rendered)
        self.assertIn("preparing parent IDs for 4 dependent endpoint(s)", rendered)
        self.assertNotIn("technical-id-not-for-console", rendered)
        self.assertNotIn("query-id-not-for-console", rendered)
        self.assertNotIn("parent-id-not-for-console", rendered)


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
            with mock.patch.object(
                azure_collect, "validate_access_token", return_value=True
            ) as validate_token:
                self.assertTrue(azure_collect.validate_auth_session())

        self.assertEqual(azure_collect.AUTH_CONFIG["tenant_id"], "tenant-active")
        self.assertEqual(azure_collect.AUTH_CONFIG["subscription_id"], "sub-active")
        self.assertEqual(
            [call.args[0] for call in validate_token.call_args_list],
            ["https://management.azure.com/"],
        )

    def test_existing_mode_ignores_configured_service_principal_credentials(self):
        azure_collect.AUTH_CONFIG = {
            "auth_method": "existing",
            "tenant_id": None,
            "subscription_id": None,
            "client_id": "stale-client",
            "client_secret": "stale-secret",
            "client_certificate": "/not/read/certificate.pem",
            "client_certificate_password": "stale-password",
        }
        with mock.patch.object(azure_collect, "validate_auth_session", return_value=True):
            with mock.patch.object(azure_collect, "set_az_account_context"):
                with mock.patch.object(azure_collect, "ensure_required_permission_baseline"):
                    with mock.patch.object(azure_collect, "run_az_command") as run_command:
                        azure_collect.ensure_az_login()
        run_command.assert_not_called()


class ServicePrincipalAuthenticationTests(unittest.TestCase):
    def auth_config(self, **overrides):
        config = {
            "auth_method": "service-principal",
            "tenant_id": "tenant-one",
            "subscription_id": None,
            "client_id": "client-one",
            "client_secret": None,
            "client_certificate": None,
            "client_certificate_password": None,
        }
        config.update(overrides)
        return config

    def test_client_secret_and_certificate_commands_are_distinct(self):
        secret = azure_collect.service_principal_login_command(
            self.auth_config(client_secret="secret-value")
        )
        certificate = azure_collect.service_principal_login_command(
            self.auth_config(client_certificate="collector.pem")
        )
        self.assertEqual(secret[-2:], ["--password", "secret-value"])
        self.assertEqual(certificate[-2:], ["--certificate", "collector.pem"])
        self.assertNotIn("--certificate", secret)
        self.assertNotIn("--password", certificate)

    def test_conflicting_service_principal_credentials_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "either a client secret or a certificate"):
            azure_collect.service_principal_login_command(
                self.auth_config(
                    client_secret="secret-value",
                    client_certificate="collector.pem",
                )
            )

    def test_certificate_auth_uses_current_azure_cli_argument(self):
        with tempfile.TemporaryDirectory() as directory:
            certificate = Path(directory) / "collector.pem"
            certificate.write_text(
                "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"
                "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n",
                encoding="utf-8",
            )
            completed = mock.Mock(returncode=0)
            with mock.patch.object(
                azure_collect, "run_az_command", return_value=completed
            ) as run_command:
                with mock.patch.object(azure_collect, "set_az_account_context"):
                    azure_collect.authenticate_with_selected_method(
                        self.auth_config(client_certificate=str(certificate))
                    )
        command = run_command.call_args.args[0]
        self.assertEqual(command[-2:], ["--certificate", str(certificate)])
        self.assertNotIn("--certificate-password", command)

    def test_encrypted_certificate_is_prepared_with_protected_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            certificate = Path(directory) / "collector.pem"
            certificate.write_text(
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\nkey\n"
                "-----END ENCRYPTED PRIVATE KEY-----\n"
                "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n",
                encoding="utf-8",
            )
            openssl_result = mock.Mock(
                returncode=0,
                stdout="-----BEGIN PRIVATE KEY-----\nunlocked\n-----END PRIVATE KEY-----\n",
            )
            with mock.patch.object(
                azure_collect.subprocess, "run", return_value=openssl_result
            ) as openssl:
                with azure_collect.prepared_client_certificate(
                    certificate, "passphrase"
                ) as prepared:
                    prepared = Path(prepared)
                    self.assertTrue(prepared.exists())
                    self.assertEqual(0o600, prepared.stat().st_mode & 0o777)
                    content = prepared.read_text(encoding="utf-8")
                    self.assertIn("BEGIN PRIVATE KEY", content)
                    self.assertIn("BEGIN CERTIFICATE", content)
                self.assertFalse(prepared.exists())
        self.assertEqual("passphrase\n", openssl.call_args.kwargs["input"])
        self.assertNotIn("passphrase", openssl.call_args.args[0])

    def test_pkcs12_certificate_is_rejected_before_login(self):
        with tempfile.TemporaryDirectory() as directory:
            certificate = Path(directory) / "collector.pfx"
            certificate.write_bytes(b"not-a-supported-certificate")
            with self.assertRaisesRegex(ValueError, "combined PEM"):
                with azure_collect.prepared_client_certificate(certificate):
                    pass

    def test_encrypted_temporary_certificate_is_removed_when_login_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            certificate = Path(directory) / "collector.pem"
            certificate.write_text(
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\nkey\n"
                "-----END ENCRYPTED PRIVATE KEY-----\n"
                "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n",
                encoding="utf-8",
            )
            openssl_result = mock.Mock(
                returncode=0,
                stdout="-----BEGIN PRIVATE KEY-----\nunlocked\n-----END PRIVATE KEY-----\n",
            )
            prepared_paths = []
            def failed_login(command, capture_output=False):
                self.assertEqual("--certificate", command[-2])
                prepared_paths.append(Path(command[-1]))
                self.assertTrue(prepared_paths[-1].exists())
                return mock.Mock(returncode=1)
            with mock.patch.object(
                azure_collect.subprocess, "run", return_value=openssl_result
            ):
                with mock.patch.object(
                    azure_collect, "run_az_command", side_effect=failed_login
                ):
                    with self.assertRaises(SystemExit):
                        azure_collect.authenticate_with_selected_method(
                            self.auth_config(
                                client_certificate=str(certificate),
                                client_certificate_password="passphrase",
                            )
                        )
        self.assertEqual(1, len(prepared_paths))
        self.assertFalse(prepared_paths[0].exists())


class SplitGraphAuthenticationTests(unittest.TestCase):
    def test_graph_certificate_login_uses_isolated_temporary_cli_state(self):
        with tempfile.TemporaryDirectory() as directory:
            certificate = Path(directory) / "collector.pem"
            certificate.write_text(
                "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"
                "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n",
                encoding="utf-8",
            )
            calls = []

            def runner(command, **kwargs):
                config_dir = Path(kwargs["env"]["AZURE_CONFIG_DIR"])
                self.assertTrue(config_dir.is_dir())
                self.assertNotEqual(
                    kwargs["env"].get("AZURE_CONFIG_DIR"),
                    os.environ.get("AZURE_CONFIG_DIR"),
                )
                calls.append((command, config_dir))
                if command[1] == "login":
                    return mock.Mock(returncode=0, stdout="", stderr="")
                return mock.Mock(
                    returncode=0,
                    stdout=json.dumps({"accessToken": "graph-token"}),
                    stderr="",
                )

            token = azure_collect.acquire_isolated_graph_token(
                {
                    "graph_client_id": "graph-client",
                    "graph_tenant_id": "tenant-one",
                    "graph_client_certificate": str(certificate),
                    "graph_client_certificate_password": None,
                },
                command_runner=runner,
            )

        self.assertEqual("graph-token", token)
        self.assertEqual(2, len(calls))
        self.assertIn("--allow-no-subscriptions", calls[0][0])
        self.assertEqual("https://graph.microsoft.com/", calls[1][0][4])
        self.assertFalse(calls[0][1].exists())

    def test_partial_graph_certificate_configuration_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "graph-client-certificate"):
            azure_collect.acquire_isolated_graph_token(
                {
                    "graph_client_id": "graph-client",
                    "graph_tenant_id": "tenant-one",
                }
            )


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


class CorrectedAzureEndpointTests(unittest.TestCase):
    def test_retired_services_are_not_requested(self):
        endpoint_names = {
            endpoint["name"]
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS
            + azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
        }

        self.assertNotIn("Data Lake Store Accounts", endpoint_names)
        self.assertNotIn("Media Services", endpoint_names)
        self.assertEqual(
            azure_present.DATASET_NAME_MAP["az_ams_account_list"],
            "Media Services",
        )
        self.assertEqual(
            azure_present.DATASET_NAME_MAP["az_dls_account_list"],
            "Data Lake Store Accounts",
        )

    def test_private_endpoint_connections_use_resource_ids(self):
        corrected_endpoint_names = {
            "Storage Private Endpoint Connections",
            "App Service Private Endpoint Connections",
            "App Configuration Private Endpoint Connections",
            "Key Vault Private Endpoint Connections (explicit)",
            "Application Gateway Private Endpoint Connections",
            "Container Registry Private Endpoint Connections",
        }
        endpoints = [
            endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
            if endpoint["name"] in corrected_endpoint_names
        ]

        self.assertEqual(len(endpoints), 6)
        for endpoint in endpoints:
            self.assertEqual(
                endpoint["cli_command"],
                "az network private-endpoint-connection list --id {id}",
            )
            self.assertEqual(list(endpoint["required_params"]), ["id"])
            self.assertIn("--resource-name_name", endpoint["output_prefix"])

    def test_storage_queue_cors_uses_the_arm_service_properties_endpoint(self):
        endpoint = next(
            item
            for item in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
            if item["name"] == "Storage Queue CORS Rules"
        )

        self.assertEqual(endpoint["required_params"], {"id": "az_storage_account_list"})
        self.assertIn("/queueServices/default?api-version=2025-06-01", endpoint["cli_command"])
        self.assertIn("--query properties.cors.corsRules", endpoint["cli_command"])
        self.assertEqual(
            endpoint["output_prefix"],
            "az_storage_cors_list_--services_q_--account-name_name_--auth-mode_login",
        )

    def test_application_gateway_collectors_only_request_supported_details(self):
        endpoints = {
            endpoint["name"]: endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
        }

        self.assertNotIn("Application Gateway SSL Policy", endpoints)
        self.assertEqual(
            azure_present.DATASET_NAME_MAP[
                "az_network_application-gateway_ssl-policy_show_--gateway-name_name_--resource-group_resourcegroup"
            ],
            "Application Gateway SSL Policy",
        )
        self.assertEqual(
            endpoints["Application Gateway WAF Config"]["required_source_values"],
            {"az_network_application-gateway_list": {"sku.tier": {"WAF", "WAF_v2"}}},
        )
        self.assertEqual(
            endpoints["Application Gateway WAF Config"]["required_source_non_null"],
            {"az_network_application-gateway_list": {"webApplicationFirewallConfiguration"}},
        )

    def test_policy_backed_application_gateway_skips_inline_waf_collection(self):
        endpoint = next(
            item for item in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
            if item["name"] == "Application Gateway WAF Config"
        )
        records = [
            {
                "name": "inline",
                "sku": {"tier": "WAF_v2"},
                "webApplicationFirewallConfiguration": {"enabled": True},
            },
            {
                "name": "policy-backed",
                "sku": {"tier": "WAF_v2"},
                "webApplicationFirewallConfiguration": None,
                "firewallPolicy": {
                    "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/policy"
                },
            },
        ]

        self.assertEqual(
            ["inline"],
            [
                item["name"]
                for item in azure_collect.filter_source_records_for_endpoint(
                    endpoint, "az_network_application-gateway_list", records
                )
            ],
        )

    def test_management_groups_collection_never_registers_the_provider(self):
        endpoint = next(
            item for item in azure_collect.AZURE_CLI_ENDPOINTS
            if item["name"] == "Management Groups"
        )

        self.assertEqual(
            "az account management-group list --no-register",
            endpoint["cli_command"],
        )

    def test_azure_resource_pim_uses_arm_schedule_apis(self):
        endpoints = [
            item for item in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
            if item["name"].startswith("PIM Azure Resource")
        ]

        self.assertEqual(6, len(endpoints))
        for endpoint in endpoints:
            self.assertIn("management.azure.com/subscriptions/{id}", endpoint["cli_command"])
            self.assertIn("providers/Microsoft.Authorization/role", endpoint["cli_command"])
            self.assertNotIn("graph.microsoft.com", endpoint["cli_command"])
            self.assertEqual({"id": "az_account_list"}, endpoint["required_params"])
            self.assertTrue(endpoint["extract_value"])
            self.assertTrue(endpoint["follow_next_link"])

    def test_graph_collection_is_not_duplicated_through_azure_cli(self):
        commands = [item["cli_command"] for item in azure_collect.AZURE_CLI_ENDPOINTS]

        self.assertFalse(any(command.startswith("az ad ") for command in commands))
        self.assertFalse(any("graph.microsoft.com" in command for command in commands))

    def test_arm_pim_pagination_retains_all_pages_and_duplicates(self):
        endpoint = {
            "name": "PIM test",
            "cli_command": "az rest --method get --url https://management.azure.com/{id}",
            "output_prefix": "arm_pim_test",
            "follow_next_link": True,
            "extract_value": True,
        }
        results = [
            {"returncode": 0, "json": {"value": [{"id": "same"}], "nextLink": "https://next"}},
            {"returncode": 0, "json": {"value": [{"id": "same"}]}},
        ]
        with mock.patch.object(
            azure_collect, "timed_run_az_cli", side_effect=results
        ) as timed:
            records = azure_collect.collect_parameter_set(endpoint, {"id": "sub"})

        self.assertEqual(["same", "same"], [item["id"] for item in records])
        self.assertEqual(
            ["az", "rest", "--method", "get", "--url", "https://next"],
            timed.call_args_list[1].args[0],
        )

    def test_arm_pim_partial_page_retains_completed_records(self):
        endpoint = {
            "name": "PIM test",
            "cli_command": "az rest --method get --url https://management.azure.com/{id}",
            "output_prefix": "arm_pim_test",
            "follow_next_link": True,
            "extract_value": True,
        }
        results = [
            {"returncode": 0, "json": {"value": [{"id": "complete"}], "nextLink": "https://next"}},
            {"returncode": 1, "json": {}, "stdout": "later page failed"},
        ]
        with mock.patch.object(
            azure_collect, "timed_run_az_cli", side_effect=results
        ):
            records = azure_collect.collect_parameter_set(endpoint, {"id": "sub"})

        self.assertEqual(["complete"], [item["id"] for item in records])

    def test_diagnostic_settings_follow_successful_category_discovery(self):
        endpoints = azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
        categories_index = next(
            index
            for index, endpoint in enumerate(endpoints)
            if endpoint["name"] == "Diagnostic Settings Categories"
        )
        settings_index = next(
            index
            for index, endpoint in enumerate(endpoints)
            if endpoint["name"] == "Diagnostic Settings"
        )
        settings = endpoints[settings_index]

        self.assertLess(categories_index, settings_index)
        self.assertEqual(
            settings["required_params"],
            {"id": "az_monitor_diagnostic-settings_categories_list"},
        )
        self.assertEqual(settings["prefer_collection_context_params"], {"id"})
        self.assertTrue(settings["preserve_empty_result"])


class DiagnosticSettingsFindingTests(unittest.TestCase):
    def test_only_successfully_assessed_resources_are_evaluated(self):
        configured_id = "/subscriptions/sub/resourceGroups/rg/providers/type/configured"
        missing_id = "/subscriptions/sub/resourceGroups/rg/providers/type/missing"
        unsupported_id = "/subscriptions/sub/resourceGroups/rg/providers/type/unsupported"
        resources = [
            {"id": configured_id, "name": "configured"},
            {"id": missing_id, "name": "missing"},
            {"id": missing_id, "name": "duplicate inventory record"},
            {"id": unsupported_id, "name": "unsupported"},
        ]
        diagnostic_settings = [
            {
                "id": f"{configured_id}/providers/microsoft.insights/diagnosticSettings/main",
                "_collectionContext": {"parameters": {"id": configured_id}},
            },
            {
                "_collectionResult": {"status": "empty"},
                "_collectionContext": {"parameters": {"id": missing_id}},
            },
        ]

        finding = azure_findings.find_resource_diagnostic_settings_missing(
            resources,
            diagnostic_settings,
        )

        self.assertEqual(finding["status"], "found")
        self.assertEqual([item["id"] for item in finding["evidence"]], [missing_id])
        self.assertEqual(
            {item["id"] for item in finding["_coverage_eligible_assets"]},
            {configured_id, missing_id},
        )

    def test_no_successful_resource_assessments_are_reported_as_insufficient_data(self):
        finding = azure_findings.find_resource_diagnostic_settings_missing(
            [{"id": "/subscriptions/sub/providers/type/name", "name": "name"}],
            [],
        )

        self.assertEqual(finding["status"], "no_data_to_assess")
        self.assertEqual(finding["evidence"], [])
        self.assertEqual(finding["_coverage_eligible_assets"], [])


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
    def test_sankey_keeps_endpoint_check_and_relationship_denominators_distinct(self):
        rows = [
            {
                "status": "found",
                "definition": {"category": "Identity"},
                "reporting": {"provenance": {"required_endpoints": [
                    {"endpoint_id": "endpoint-a", "category": "base"},
                ]}},
            },
            {
                "status": "not_found",
                "definition": {"category": "Identity"},
                "reporting": {"provenance": {"required_endpoints": [
                    {"endpoint_id": "endpoint-a", "category": "base"},
                    {"endpoint_id": "endpoint-b", "category": "microsoft_graph"},
                ]}},
            },
        ]
        manifest = {
            "schema_version": "2.5",
            "endpoint_runs": [
                {
                    "endpoint_id": "endpoint-a",
                    "category": "parameterised",
                    "status": "success",
                    "parameter_context": {"name": "one"},
                },
                {
                    "endpoint_id": "endpoint-a",
                    "category": "parameterised",
                    "status": "success",
                    "parameter_context": {"name": "two"},
                },
                {
                    "endpoint_id": "endpoint-b",
                    "category": "microsoft_graph",
                    "status": "success",
                },
                {
                    "endpoint_id": "endpoint-c",
                    "category": "base",
                    "status": "empty",
                    "access_verification": {"status": "access_verified"},
                },
            ],
        }
        finding_file = mock.Mock()
        finding_file.exists.return_value = True
        with (
            mock.patch.object(
                azure_present,
                "findings_flat_path",
                return_value=finding_file,
            ),
            mock.patch.object(
                azure_present,
                "load_json_file",
                return_value={"rows": rows},
            ),
        ):
            summary = azure_present.findings_summary(manifest)

        self.assertEqual(summary["executed"], 2)
        self.assertEqual(summary["sankey_relationship_count"], 5)
        self.assertEqual(
            summary["sankey_node_counts"][
                (0, "Base Endpoints", "endpoint executions")
            ],
            3,
        )
        self.assertEqual(
            summary["sankey_node_counts"][
                (0, "Microsoft Graph Endpoints", "endpoint executions")
            ],
            1,
        )
        self.assertEqual(
            summary["sankey_node_counts"][
                (2, "Identity Finding Checks", "finding checks")
            ],
            2,
        )
        self.assertEqual(
            summary["sankey_paths"][(
                (
                    "Base Endpoints",
                    "Returned Data",
                    "Identity Finding Checks",
                    "Assessed",
                    "Failed",
                ),
                azure_present.FINDING_RESULT_OPTIONS["Failed"],
            )],
            2,
        )
        self.assertIn(
            (
                (
                    "Base Endpoints",
                    "No Data — Access Verified",
                    "No Linked Finding Check",
                ),
                "#adb5bd",
            ),
            summary["sankey_paths"],
        )

    def test_finding_charts_consolidate_all_insufficient_data_causes(self):
        causes = [
            "missing_or_unattributed_source",
            "source_visibility_unverified",
            "empty_source",
            "scope_restricted_source",
            "tenant_capability_unavailable",
            "failed_request",
            "collection_incomplete",
            "unauthorised_source",
            "skipped_prerequisite",
        ]
        rows = [
            {
                "status": "no_data_to_assess",
                "reporting": {"provenance": {
                    "insufficient_data": {"cause": cause},
                    "required_endpoints": [{
                        "endpoint_id": "test_endpoint",
                        "category": "microsoft_graph" if index % 2 else "base",
                    }],
                }},
            }
            for index, cause in enumerate(causes)
        ]
        rows.extend([{"status": "found"}, {"status": "not_found"}])
        finding_file = mock.Mock()
        finding_file.exists.return_value = True

        with (
            mock.patch.object(
                azure_present,
                "findings_flat_path",
                return_value=finding_file,
            ),
            mock.patch.object(
                azure_present,
                "load_json_file",
                return_value={"rows": rows},
            ),
        ):
            summary = azure_present.findings_summary()

        chart_counts = {
            label: count
            for (_outcome, label, _color), count
            in summary["chart_segments"].items()
        }
        self.assertEqual(
            chart_counts,
            {
                "Findings Raised": 1,
                "Checks Passed": 1,
                "Missing Source": 2,
                "Empty Upstream Source": 1,
                "Scope Restricted": 1,
                "Unlicensed": 1,
                "Failed": 2,
                "Unauthorised": 1,
                "Missing Prerequisite": 1,
            },
        )
        self.assertEqual(sum(chart_counts.values()), summary["executed"])
        self.assertTrue(all(len(path) == 5 for path, _color in summary["sankey_paths"]))
        self.assertEqual(
            {path[0] for path, _color in summary["sankey_paths"]},
            {"Base Endpoints", "Microsoft Graph Endpoints", "Unattributed Endpoint"},
        )
        self.assertEqual(
            {path[-1] for path, _color in summary["sankey_paths"]},
            {"Passed", "Failed", "Nothing to Assess", "Could Not Assess"},
        )
        self.assertEqual(summary["sankey_relationship_count"], summary["executed"])

    def test_declared_graph_check_without_an_execution_is_not_unattributed(self):
        rows = [
            {
                "status": "no_data_to_assess",
                "reporting": {
                    "provenance": {
                        "endpoint_source_type": "Graph",
                        "required_endpoints": [],
                        "insufficient_data": {
                            "cause": "missing_or_unattributed_source",
                        },
                    },
                },
            }
        ]
        finding_file = mock.Mock()
        finding_file.exists.return_value = True

        with (
            mock.patch.object(
                azure_present,
                "findings_flat_path",
                return_value=finding_file,
            ),
            mock.patch.object(
                azure_present,
                "load_json_file",
                return_value={"rows": rows},
            ),
        ):
            summary = azure_present.findings_summary(manifest={"endpoint_runs": []})

        paths = {path for path, _color in summary["sankey_paths"]}
        self.assertEqual(
            paths,
            {
                (
                    "Microsoft Graph Endpoints",
                    "Endpoint Not Recorded",
                    "Finding Checks",
                    "No Data to Assess",
                    "Could Not Assess",
                )
            },
        )
        self.assertNotIn(
            "Unattributed Endpoint",
            {node for path in paths for node in path},
        )

    def test_review_and_validated_export_files_are_not_data_viewer_datasets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            dataset = data_dir / "az_resource_list_20260804-120000.json"
            dataset.write_text("[]", encoding="utf-8")
            (data_dir / "azure-collection-manifest_20260804-120000.json").write_text(
                "{}", encoding="utf-8"
            )
            for filename in (
                azure_present.FINDINGS_REVIEW_FILENAME,
                azure_present.VALIDATED_FINDINGS_SARIF_FILENAME,
            ):
                (data_dir / filename).write_text("{}", encoding="utf-8")

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                files = azure_present.standard_data_files()

        self.assertEqual(files, [dataset])

    def test_singleton_graph_object_is_rendered_as_one_horizontal_row(self):
        graph_policy = {
            "@odata.context": (
                "https://graph.microsoft.com/v1.0/"
                "$metadata#policies/authorizationPolicy/$entity"
            ),
            "id": "authorizationPolicy",
        }

        with mock.patch("builtins.print") as printer:
            html = azure_present.generate_html_table(graph_policy)

        self.assertIn("<th>json_string</th>", html)
        self.assertIn("<th>@odata.context</th>", html)
        self.assertIn("<th>id</th>", html)
        self.assertNotIn("<th>data</th>", html)
        self.assertIn("authorizationPolicy", html)
        hidden_json_cell = html.split("<tbody><tr><td>", 1)[1].split("</td>", 1)[0]
        self.assertNotIn("<a ", hidden_json_cell)
        self.assertIn('<a href="https://graph.microsoft.com/', html)
        self.assertNotIn("Error displaying data", html)
        self.assertEqual(azure_present.record_count_for_data(graph_policy), 1)
        printer.assert_not_called()

    def test_view_json_payload_round_trips_urls_unicode_and_nested_values(self):
        record = {
            "url": "https://graph.microsoft.com/v1.0/policies/authorizationPolicy",
            "displayName": "Sécurité",
            "settings": {"enabled": True, "names": ["one", "two"]},
        }

        encoded = azure_present.encode_json_action_payload(record)
        decoded = json.loads(azure_present.unquote(encoded))

        self.assertEqual(decoded, record)
        self.assertNotIn("https://", encoded)
        self.assertNotIn('"', encoded)

    def test_empty_and_scalar_json_shapes_render_without_errors(self):
        empty_html = azure_present.generate_html_table([])
        scalar_html = azure_present.generate_html_table("enabled")

        self.assertIn("No records were returned", empty_html)
        self.assertNotIn("Error displaying data", empty_html)
        self.assertIn("<th>value</th>", scalar_html)
        self.assertIn("enabled", scalar_html)
        self.assertNotIn("Error displaying data", scalar_html)
        self.assertEqual(azure_present.record_count_for_data({}), 0)
        self.assertEqual(azure_present.record_count_for_data("enabled"), 1)
        self.assertEqual(azure_present.record_count_for_data(None), 0)

    def test_flat_json_list_is_rendered_with_index_and_value_columns(self):
        html = azure_present.generate_html_table(["one", "two"])

        self.assertIn("<th>index</th>", html)
        self.assertIn("<th>value</th>", html)
        self.assertIn("one", html)
        self.assertIn("two", html)

    def test_graph_collection_envelope_renders_and_counts_individual_records(self):
        graph_users = {
            "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users",
            "value": [
                {"id": "user-one", "displayName": "Alpha"},
                {"id": "user-two", "displayName": "Beta"},
            ],
        }

        html = azure_present.generate_html_table(graph_users)

        self.assertEqual(azure_present.record_count_for_data(graph_users), 2)
        self.assertIn("<th>id</th>", html)
        self.assertIn("<th>displayName</th>", html)
        self.assertNotIn("<th>value</th>", html)
        self.assertNotIn("<th>@odata.context</th>", html)
        self.assertIn("Alpha", html)
        self.assertIn("Beta", html)

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

    def test_findings_metadata_columns_are_concise_purpose_led_summaries(self):
        row = {
            "finding_id": "storage_example",
            "title": "Storage example",
            "severity": "Medium",
            "status": "found",
            "definition": {
                "schema_version": "1.0",
                "report_title": "Storage example",
                "default_severity": "Medium",
                "category": "Storage security",
                "check_ids": ["storage_example_alias"],
                "report": {
                    "narrative_status": "authored",
                    "description": "Explains the check.",
                    "impact": "Explains why it matters.",
                    "recommendation": "Explains what to do.",
                },
            },
            "reporting": {
                "schema_version": "1.2",
                "assets": [{"name": "storage-one"}],
                "observations": [{"data": {"public": True}}],
                "provenance": {
                    "source_datasets": [{"filename": "storage.json"}],
                    "required_endpoints": [{"name": "Storage Accounts"}],
                    "collection_run": {"status": "success"},
                    "limitations": ["Example limitation"],
                },
            },
            "context": {
                "schema_version": "1.0",
                "family": {
                    "service_label": "Azure Storage",
                    "control_plane": "azure_resource_manager",
                },
                "engagement": {
                    "tenant_ids": ["tenant-one"],
                    "selected_subscription_id": "sub-one",
                    "subscriptions": [
                        {"subscription_id": "sub-one", "name": "Production"}
                    ],
                },
                "scope": {"level": "resource", "affected_asset_count": 1},
                "limitations": [],
            },
            "coverage": {
                "schema_version": "1.0",
                "status": "proxy",
                "denominator": {"value": 4, "unit": "assets"},
                "affected": {"assets": 1},
                "affected_percentage": 25.0,
                "limitations": ["Proxy denominator"],
            },
            "review": {
                "schema_version": "1.0",
                "review_state": "unreviewed",
                "disposition": "candidate",
                "confidence": {
                    "level": "high",
                    "rationale": ["Verified source data", "Complete collection"],
                },
                "analyst": {"reviewer": None},
                "report_ready": {"include": True},
            },
            "triage": {
                "schema_version": "1.0",
                "grouping": {"observation_groups": [{"group_id": "opaque"}]},
                "severity": {"contextual": "High", "changed": True},
                "deduplication": {
                    "status": "duplicates_present",
                    "duplicate_observation_count": 2,
                },
                "fingerprint": {"value": "findingfp_opaque"},
                "retest": {"outcome": "persistent"},
            },
        }

        prepared = azure_present.prepare_findings_rows([row])[0]

        self.assertEqual(prepared["definition"]["Category"], "Storage Security")
        self.assertEqual(prepared["definition"]["Narrative"], "Authored")
        self.assertEqual(prepared["reporting"]["Assets"], 1)
        self.assertEqual(prepared["reporting"]["Source Datasets"], 1)
        self.assertEqual(prepared["context"]["Azure Service"], "Azure Storage")
        self.assertEqual(prepared["context"]["Selected Subscription"], "Production")
        self.assertEqual(prepared["coverage"]["Eligible Population"], "4 assets")
        self.assertEqual(prepared["coverage"]["Affected Percentage"], "25.0%")
        self.assertEqual(prepared["review"]["Report Inclusion"], "Yes")
        self.assertEqual(
            prepared["review"]["Confidence Basis"],
            "Verified source data (+1 more)",
        )
        self.assertEqual(prepared["triage"]["Observation Groups"], 1)
        self.assertEqual(prepared["triage"]["Duplicate Observations"], 2)
        displayed_metadata = json.dumps(
            {name: prepared[name] for name in azure_present.FINDINGS_METADATA_COLUMNS}
        )
        for internal_value in (
            "schema_version",
            "report_title",
            "default_severity",
            "findingfp_opaque",
            '"data": {"public": true}',
        ):
            self.assertNotIn(internal_value, displayed_metadata)

    def test_findings_view_json_retains_original_unsummarised_row(self):
        row = {
            "finding_id": "example_finding",
            "definition": {"schema_version": "1.0", "report_title": "Original"},
            "reporting": {"assets": [{"name": "account-one"}]},
            "viewer_links": ["/query/source.json", "/query/source.json"],
        }

        prepared = azure_present.prepare_findings_rows([row])[0]
        html = azure_present.generate_html_table([prepared])
        hidden_json_cell = html.split("<tbody><tr><td>", 1)[1].split("</td>", 1)[0]

        self.assertEqual(
            prepared[azure_present.VIEW_JSON_SOURCE_ROW_KEY],
            row,
        )
        self.assertEqual(
            json.loads(azure_present.unquote(hidden_json_cell)),
            row,
        )
        self.assertNotIn(
            f"<th>{azure_present.VIEW_JSON_SOURCE_ROW_KEY}</th>",
            html,
        )

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
                    "finding_id": "example_finding_with_links",
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
                    "finding_id": "example_loading_finding",
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
        self.assertIn('id="findingsReviewer"', actions_row)
        self.assertIn('id="exportValidatedSarif"', actions_row)
        self.assertIn("Validated finding:", body)
        self.assertIn("/findings/review", body)

    def test_findings_review_requires_csrf_and_persists_confirmation(self):
        finding_rows = {
            "rows": [
                {
                    "finding_id": "example_finding",
                    "title": "Example finding",
                    "severity": "High",
                    "status": "found",
                    "reason": "Regression test",
                    "count": 1,
                    "evidence": [{"name": "account-one"}],
                    "reporting": {"assets": [], "observations": []},
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            (data_dir / azure_present.FINDINGS_FLAT_FILENAME).write_text(
                json.dumps(finding_rows), encoding="utf-8"
            )
            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                client = azure_present.app.test_client()
                rejected = client.post(
                    "/findings/review",
                    json={
                        "finding_id": "example_finding",
                        "confirmed": True,
                        "reviewer": "A. Tester",
                    },
                )
                response = client.post(
                    "/findings/review",
                    headers={
                        "X-Azure-Assess-CSRF": azure_present.FINDINGS_REVIEW_CSRF_TOKEN
                    },
                    json={
                        "finding_id": "example_finding",
                        "confirmed": True,
                        "reviewer": "A. Tester",
                    },
                )
                saved = json.loads(
                    (data_dir / azure_present.FINDINGS_REVIEW_FILENAME).read_text(
                        encoding="utf-8"
                    )
                )

        self.assertEqual(rejected.status_code, 403)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["confirmed"])
        self.assertEqual(response.get_json()["validated_findings"], 1)
        self.assertEqual(saved["schema_version"], "1.0")
        self.assertEqual(saved["reviews"][0]["finding_id"], "example_finding")
        self.assertEqual(saved["reviews"][0]["disposition"], "confirmed")
        self.assertEqual(saved["reviews"][0]["reviewer"], "A. Tester")
        self.assertTrue(saved["reviews"][0]["reviewed_at"].endswith("Z"))

    def test_findings_review_rejects_non_findings_and_unknown_ids(self):
        finding_rows = {
            "rows": [
                {
                    "finding_id": "clear_check",
                    "title": "Clear check",
                    "severity": "Low",
                    "status": "not_found",
                    "reason": "Nothing was found",
                    "count": 0,
                    "evidence": [],
                }
            ]
        }
        headers = {
            "X-Azure-Assess-CSRF": azure_present.FINDINGS_REVIEW_CSRF_TOKEN
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            (data_dir / azure_present.FINDINGS_FLAT_FILENAME).write_text(
                json.dumps(finding_rows), encoding="utf-8"
            )
            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                client = azure_present.app.test_client()
                clear_response = client.post(
                    "/findings/review",
                    headers=headers,
                    json={
                        "finding_id": "clear_check",
                        "confirmed": True,
                        "reviewer": "A. Tester",
                    },
                )
                unknown_response = client.post(
                    "/findings/review",
                    headers=headers,
                    json={
                        "finding_id": "unknown_check",
                        "confirmed": True,
                        "reviewer": "A. Tester",
                    },
                )

        self.assertEqual(clear_response.status_code, 409)
        self.assertEqual(unknown_response.status_code, 404)

    def test_validated_sarif_export_contains_only_confirmed_results(self):
        finding_rows = {
            "rows": [
                {
                    "finding_id": finding_id,
                    "title": title,
                    "severity": "High",
                    "status": "found",
                    "reason": "Regression test",
                    "count": 1,
                    "evidence": [{"name": finding_id}],
                    "reporting": {"assets": [], "observations": []},
                }
                for finding_id, title in (
                    ("confirmed_finding", "Confirmed finding"),
                    ("candidate_finding", "Candidate finding"),
                )
            ]
        }
        source_sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "azure-findings",
                            "rules": [
                                {"id": "confirmed_finding"},
                                {"id": "candidate_finding"},
                            ],
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "properties": {"found_findings": 2},
                        }
                    ],
                    "results": [
                        {
                            "ruleId": finding_id,
                            "properties": {
                                "finding_id": finding_id,
                                "review": {"disposition": "candidate"},
                            },
                        }
                        for finding_id in ("confirmed_finding", "candidate_finding")
                    ],
                }
            ],
        }
        confirmed_review = {
            "finding_id": "confirmed_finding",
            "disposition": "confirmed",
            "reviewer": "A. Tester",
            "reviewed_at": "2026-08-04T12:00:00Z",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            (data_dir / azure_present.FINDINGS_FLAT_FILENAME).write_text(
                json.dumps(finding_rows), encoding="utf-8"
            )
            (data_dir / azure_present.FINDINGS_SARIF_FILENAME).write_text(
                json.dumps(source_sarif), encoding="utf-8"
            )
            azure_present.save_review_overrides(
                data_dir / azure_present.FINDINGS_REVIEW_FILENAME,
                {"confirmed_finding": confirmed_review},
            )
            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                response = azure_present.app.test_client().get(
                    "/findings/export-validated-sarif"
                )

        exported = response.get_json()
        run = exported["runs"][0]
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/sarif+json")
        self.assertIn(
            azure_present.VALIDATED_FINDINGS_SARIF_FILENAME,
            response.headers["Content-Disposition"],
        )
        self.assertEqual([result["ruleId"] for result in run["results"]], ["confirmed_finding"])
        self.assertEqual([rule["id"] for rule in run["tool"]["driver"]["rules"]], ["confirmed_finding"])
        self.assertEqual(
            run["results"][0]["properties"]["review"]["disposition"],
            "confirmed",
        )
        self.assertEqual(exported["properties"]["validated_findings"], 1)
        self.assertEqual(run["invocations"][0]["properties"]["found_findings"], 1)
        self.assertEqual(
            run["invocations"][0]["properties"]["source_found_findings"],
            2,
        )

    def test_validated_sarif_rejects_conflicting_result_identifiers(self):
        source_sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "different_finding",
                            "properties": {"finding_id": "confirmed_finding"},
                        }
                    ]
                }
            ],
        }
        confirmed = {
            "finding_id": "confirmed_finding",
            "status": "found",
            "review": {"disposition": "confirmed"},
        }

        with self.assertRaisesRegex(ValueError, "conflicting finding_id"):
            azure_present.build_validated_sarif(source_sarif, [confirmed])

    def test_checkbox_override_preserves_existing_analyst_metadata(self):
        row = {
            "finding_id": "confirmed_finding",
            "review": {
                "confidence": {
                    "level": "high",
                    "source": "analyst",
                    "rationale": ["Portal evidence was checked."],
                },
                "analyst": {
                    "notes": "Retain this note.",
                    "contextual_severity": {
                        "level": "Critical",
                        "rationale": "Production exposure.",
                    },
                },
            },
        }

        override = azure_present.review_override_from_effective_review(
            row,
            "Second Analyst",
            False,
        )

        self.assertEqual(override["disposition"], "candidate")
        self.assertEqual(override["reviewer"], "Second Analyst")
        self.assertEqual(override["notes"], "Retain this note.")
        self.assertEqual(override["confidence"]["level"], "high")
        self.assertEqual(
            override["contextual_severity"]["rationale"],
            "Production exposure.",
        )

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

    def test_dataset_query_route_renders_singleton_graph_object_as_table(self):
        graph_policy = {
            "@odata.context": (
                "https://graph.microsoft.com/v1.0/"
                "$metadata#policies/authorizationPolicy/$entity"
            ),
            "id": "authorizationPolicy",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            dataset_path = data_dir / (
                "az_rest_--url_graph_authorization_policy_20260803-212113.json"
            )
            dataset_path.write_text(json.dumps(graph_policy), encoding="utf-8")

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                response = azure_present.app.test_client().get(
                    f"/query/{dataset_path.name}"
                )

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            '<th class="table-sortable" tabindex="0" role="button" '
            'aria-sort="none">@odata.context</th>',
            body,
        )
        self.assertIn(
            '<th class="table-sortable" tabindex="0" role="button" '
            'aria-sort="none">ID</th>',
            body,
        )
        self.assertNotIn("Working with something which is neither", body)
        self.assertNotIn("Error displaying data", body)
        self.assertIn(
            "decodeURIComponent(jsonCell.textContent.trim())",
            body,
        )

    def test_dataset_query_filters_records_inside_graph_collection_envelope(self):
        graph_users = {
            "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users",
            "value": [
                {"id": "user-one", "displayName": "Alpha"},
                {"id": "user-two", "displayName": "Beta"},
            ],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            dataset_path = data_dir / "graph_users_20260803-212113.json"
            dataset_path.write_text(json.dumps(graph_users), encoding="utf-8")

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                response = azure_present.app.test_client().get(
                    f"/query/{dataset_path.name}?query=beta"
                )

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Beta", body)
        self.assertNotIn("Alpha", body)
        self.assertNotIn("<th>value</th>", body)

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

    def test_graph_datasets_keep_friendly_names_and_show_collection_metadata(self):
        filename = "graph_identity_baseline_applications_20260805-120000.json"
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            (data_dir / filename).write_text(
                json.dumps([{"id": "app-one"}]), encoding="utf-8"
            )

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                groups = azure_present.dataset_groups(load_record_counts=True)
                response = azure_present.app.test_client().get("/datasets")

        self.assertEqual(groups[0]["name"], "Graph Applications")
        self.assertEqual(groups[0]["source"], "Microsoft Graph")
        self.assertEqual(groups[0]["workload"], "Identity Baseline")
        self.assertEqual(groups[0]["api_channel"], "v1.0")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Collection Source", body)
        self.assertIn("Workload", body)
        self.assertIn("Graph Applications", body)
        self.assertIn("Microsoft Graph", body)
        self.assertIn("Identity Baseline", body)
        self.assertNotIn(">graph_identity_baseline_applications<", body)

    def test_dashboard_summarises_graph_records_from_manifest_provenance(self):
        graph_filename = (
            "graph_identity_baseline_applications_20260805-120000.json"
        )
        manifest = {
            "schema_version": "2.5",
            "run_id": "20260805-120000",
            "status": "partial",
            "endpoint_runs": [
                {
                    "endpoint_id": "graph_identity_baseline_applications",
                    "endpoint_name": "Graph Applications",
                    "category": "microsoft_graph",
                    "status": "success",
                    "result_count": 2,
                    "output_files": [graph_filename],
                    "parameter_context": {
                        "profile": "IdentityBaseline",
                        "api_channel": "v1.0",
                    },
                },
                {
                    "endpoint_id": "graph_identity_baseline_domains",
                    "endpoint_name": "Graph Domains",
                    "category": "microsoft_graph",
                    "status": "empty",
                    "result_count": 0,
                    "output_files": [],
                },
                {
                    "endpoint_id": "graph_identity_baseline_security_defaults",
                    "endpoint_name": "Graph Security Defaults Policy",
                    "category": "microsoft_graph",
                    "status": "unauthorised",
                    "result_count": None,
                    "output_files": [],
                    "error": "Required Graph permission was unavailable",
                },
            ],
            "datasets": [
                {
                    "filename": graph_filename,
                    "source_endpoint_id": (
                        "graph_identity_baseline_applications"
                    ),
                    "source_endpoint_ids": [
                        "graph_identity_baseline_applications"
                    ],
                    "record_count": 2,
                    "size_bytes": 42,
                    "sha256": "a" * 64,
                }
            ],
            "errors": [],
            "limitations": [],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            (data_dir / graph_filename).write_text(
                json.dumps([{"id": "one"}, {"id": "two"}]),
                encoding="utf-8",
            )
            (data_dir / "azure-collection-manifest_20260805-120000.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                summary = azure_present.graph_collection_summary()
                response = azure_present.app.test_client().get("/")

        self.assertEqual(summary["selected_endpoints"], 3)
        self.assertEqual(summary["endpoints_with_data"], 1)
        self.assertEqual(summary["records_written"], 2)
        self.assertEqual(summary["dataset_files"], 1)
        self.assertEqual(summary["outcome"], "Partial — data retained")
        self.assertEqual(
            summary["status_counts"],
            {"empty": 1, "success": 1, "unauthorised": 1},
        )
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Microsoft Graph Collection", body)
        self.assertIn("Graph Endpoints With Data", body)
        self.assertIn("Graph Records Written", body)
        self.assertIn("Graph Endpoint Results", body)
        self.assertIn("Graph Applications", body)
        self.assertIn("Graph Security Defaults Policy", body)
        self.assertIn("Required Graph permission was unavailable", body)
        self.assertIn("Collection Request Health", body)
        self.assertNotIn("Azure Request Health", body)

    def test_dashboard_makes_missing_graph_manifest_evidence_explicit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                summary = azure_present.graph_collection_summary()
                response = azure_present.app.test_client().get("/")

        self.assertEqual(summary["outcome"], "Manifest unavailable")
        self.assertEqual(summary["selected_endpoints"], 0)
        self.assertEqual(summary["records_written"], 0)
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Microsoft Graph Collection", body)
        self.assertIn("Manifest unavailable", body)
        self.assertIn(
            "Microsoft Graph collection cannot be verified", body
        )

    def test_graph_summary_distinguishes_complete_empty_collection(self):
        manifest = {
            "endpoint_runs": [
                {
                    "endpoint_id": "graph_identity_baseline_domains",
                    "endpoint_name": "Graph Domains",
                    "category": "microsoft_graph",
                    "status": "empty",
                    "result_count": 0,
                    "output_files": [],
                }
            ],
            "datasets": [],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch.object(
                azure_present, "DATA_DIR", Path(tmpdir)
            ):
                summary = azure_present.graph_collection_summary(manifest)

        self.assertEqual(summary["selected_endpoints"], 1)
        self.assertEqual(summary["endpoints_with_data"], 0)
        self.assertEqual(summary["records_written"], 0)
        self.assertEqual(
            summary["outcome"], "Complete — no records returned"
        )

    def test_manifest_routes_expose_versioned_summary_and_raw_json_safely(self):
        dataset_filename = "graph_identity_baseline_domains_20260805-120000.json"
        newest_manifest = {
            "schema_version": "2.5",
            "run_id": "new-run",
            "status": "success",
            "started_at": "2026-08-05T12:00:00Z",
            "completed_at": "2026-08-05T12:01:00Z",
            "context": {"tenant_id": "tenant-one"},
            "options": {"graph_lookback_days": 30},
            "access_verification": {
                "graph": {"status": "access_verified"}
            },
            "endpoint_runs": [
                {
                    "endpoint_name": "Graph Domains",
                    "category": "microsoft_graph",
                    "status": "success",
                    "result_count": 1,
                    "output_files": [dataset_filename],
                }
            ],
            "datasets": [
                {
                    "filename": dataset_filename,
                    "record_count": 1,
                    "size_bytes": 20,
                    "sha256": "b" * 64,
                }
            ],
            "limitations": [
                "Example beta limitation",
                "<script>alert(1)</script>",
            ],
            "errors": [],
        }
        older_manifest = {
            **newest_manifest,
            "run_id": "old-run",
            "status": "partial",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            (data_dir / dataset_filename).write_text(
                json.dumps([{"id": "domain-one"}]), encoding="utf-8"
            )
            newest_filename = "azure-collection-manifest_20260805-120000.json"
            older_filename = "azure-collection-manifest_20260804-120000.json"
            (data_dir / newest_filename).write_text(
                json.dumps(newest_manifest), encoding="utf-8"
            )
            (data_dir / older_filename).write_text(
                json.dumps(older_manifest), encoding="utf-8"
            )

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                client = azure_present.app.test_client()
                summary_response = client.get("/manifest")
                old_response = client.get(
                    f"/manifest?filename={older_filename}"
                )
                raw_response = client.get(
                    f"/manifest/raw?filename={newest_filename}"
                )
                unsafe_response = client.get(
                    "/manifest/raw?filename=../outside.json"
                )

        summary_body = summary_response.get_data(as_text=True)
        self.assertEqual(summary_response.status_code, 200)
        self.assertIn("Collection Manifest", summary_body)
        self.assertIn("new-run", summary_body)
        self.assertIn("Graph Domains", summary_body)
        self.assertIn("View Raw Manifest JSON", summary_body)
        self.assertIn("Example beta limitation", summary_body)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", summary_body)
        self.assertNotIn("<script>alert(1)</script>", summary_body)
        self.assertIn("can contain tenant identifiers", summary_body)
        self.assertIn(newest_filename, summary_body)
        self.assertIn(older_filename, summary_body)
        self.assertEqual(summary_response.headers["Cache-Control"], "no-store")
        self.assertEqual(
            summary_response.headers["X-Content-Type-Options"], "nosniff"
        )
        self.assertEqual(old_response.status_code, 200)
        self.assertIn("old-run", old_response.get_data(as_text=True))
        self.assertEqual(raw_response.status_code, 200)
        self.assertEqual(raw_response.get_json()["run_id"], "new-run")
        self.assertEqual(raw_response.headers["Cache-Control"], "no-store")
        self.assertEqual(raw_response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(unsafe_response.status_code, 404)

    def test_manifest_route_does_not_follow_manifest_symlinks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data_dir = root / "data"
            data_dir.mkdir()
            outside = root / "outside.json"
            outside.write_text(
                json.dumps({"run_id": "outside"}), encoding="utf-8"
            )
            link = data_dir / "azure-collection-manifest_20260805-120000.json"
            link.symlink_to(outside)

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                response = azure_present.app.test_client().get("/manifest/raw")

        self.assertEqual(response.status_code, 404)

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
            self.assertIn("Azure Resources Discovered", body)
            self.assertIn("Loading...", body)
            loader.assert_not_called()

    def test_dashboard_does_not_treat_other_dataset_rows_as_azure_resources(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            dataset_path = data_dir / "az_group_list_20260402-000000.json"
            dataset_path.write_text(json.dumps([{"name": "one"}]), encoding="utf-8")

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                client = azure_present.app.test_client()
                response = client.get("/")

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Azure Resources Discovered", body)
        self.assertIn("The Azure resource inventory was not collected", body)
        self.assertNotIn(
            f'data-summary-count-filenames="{dataset_path.name}"',
            body,
        )

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
                {
                    "status": "no_data_to_assess",
                    "reporting": {"provenance": {
                        "insufficient_data": {"cause": "unauthorised_source"},
                        "required_endpoints": [{
                            "endpoint_id": "graph_identity_baseline_report_settings",
                            "category": "microsoft_graph",
                        }],
                    }},
                },
                {
                    "status": "no_data_to_assess",
                    "reporting": {"provenance": {
                        "insufficient_data": {"cause": "empty_source"},
                        "required_endpoints": [{
                            "endpoint_id": "az_resource_list",
                            "category": "base",
                        }],
                    }},
                },
                {"status": "no_data_to_assess"},
                {"status": "found"},
                {
                    "status": "not_found",
                    "reporting": {"provenance": {
                        "required_endpoints": [{
                            "endpoint_id": "az_network_nic_effective_nsg",
                            "category": "parameterised",
                        }],
                    }},
                },
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
                    "error": "Selected endpoint was not attempted",
                },
                {
                    "endpoint_name": "Skipped Endpoint",
                    "category": "parameterised",
                    "status": "skipped",
                    "returncode": None,
                    "reason_code": "upstream_source_returned_no_data",
                    "reason_details": {
                        "source": "az_storage_account_list",
                        "collection_statuses": ["empty"],
                    },
                    "error": "Missing required parameters: name",
                },
                {
                    "endpoint_id": "az_network_nic_effective_nsg",
                    "endpoint_name": "Successful Endpoint",
                    "category": "base",
                    "status": "success",
                    "returncode": 0,
                    "result_count": 2,
                },
                {
                    "endpoint_name": "Partially Collected Graph Endpoint",
                    "category": "microsoft_graph",
                    "status": "incomplete",
                    "returncode": 1,
                    "result_count": 1,
                    "error": "A later Graph page failed after data was retained",
                },
                {
                    "endpoint_id": "graph_identity_baseline_report_settings",
                    "endpoint_name": "Graph Report Settings",
                    "category": "microsoft_graph",
                    "status": "unauthorised",
                    "returncode": 1,
                    "result_count": None,
                    "error_code": "Authorization_RequestDenied",
                    "response_error": "The access token lacks required Microsoft Graph permissions: ReportSettings.Read.All",
                },
                {
                    "endpoint_name": "Empty Endpoint — Visibility Unverified",
                    "category": "base",
                    "status": "empty",
                    "returncode": 0,
                    "result_count": 0,
                },
                {
                    "endpoint_id": "az_resource_list",
                    "endpoint_name": "Empty Endpoint — Access Verified",
                    "category": "base",
                    "status": "empty",
                    "returncode": 0,
                    "result_count": 0,
                    "access_verification": {"status": "access_verified"},
                },
                {
                    "endpoint_name": "Empty Endpoint — Scope Restricted",
                    "category": "base",
                    "status": "empty",
                    "returncode": 0,
                    "result_count": 0,
                    "access_verification": {"status": "scope_restricted"},
                },
                {
                    "endpoint_name": "Azure CLI config",
                    "category": "setup",
                    "status": "empty",
                    "returncode": 0,
                    "result_count": 0,
                },
                {
                    "endpoint_name": "Flow Logs (legacy manifest)",
                    "category": "parameterised",
                    "status": "failed",
                    "returncode": 1,
                    "parameter_context": {"name": "spaincentral"},
                    "error": "Azure CLI request failed with return code 1",
                    "response_error": (
                        "ERROR: network watcher is not enabled for region "
                        "spaincentral."
                    ),
                },
                {
                    "endpoint_name": "Unavailable Service",
                    "category": "parameterised",
                    "status": "not_applicable",
                    "returncode": 1,
                    "parameter_context": {"location": "region-one"},
                    "response_error": "Service is explicitly unavailable for this scope.",
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
        self.assertEqual(summary["insufficient_data_causes"]["unauthorised_source"], 1)
        self.assertEqual(summary["insufficient_data_causes"]["empty_source"], 1)
        self.assertEqual(
            summary["insufficient_data_causes"]["missing_or_unattributed_source"],
            1,
        )
        self.assertNotIn("permission_blocked", summary)
        self.assertEqual(requests["attempted"], 10)
        self.assertEqual(requests["endpoint_count"], 12)
        self.assertEqual(requests["success"], 1)
        self.assertEqual(requests["empty"], 3)
        self.assertEqual(requests["empty_access_verified"], 1)
        self.assertEqual(requests["empty_scope_restricted"], 1)
        self.assertEqual(requests["empty_visibility_unverified"], 1)
        self.assertEqual(requests["failed"], 1)
        self.assertEqual(requests["incomplete"], 1)
        self.assertEqual(requests["unauthorised"], 2)
        self.assertEqual(requests["not_applicable"], 2)
        self.assertEqual(requests["unattempted"], 2)
        self.assertEqual(requests["skipped"], 1)
        self.assertEqual(requests["not_attempted"], 1)
        self.assertEqual(len(requests["base_endpoint_results"]), 10)
        self.assertEqual(len(requests["graph_endpoint_results"]), 2)
        self.assertEqual(len(requests["successes"]), 4)
        self.assertEqual(len(requests["failures"]), 4)
        self.assertEqual(sum(requests["outcome_counts"].values()), 12)
        self.assertEqual(summary["sankey_relationship_count"], 5)
        sankey_node_counts = {
            (stage, name, unit): count
            for (stage, name, unit), count
            in summary["sankey_node_counts"].items()
        }
        self.assertEqual(
            sankey_node_counts[(0, "Base Endpoints", "endpoint executions")],
            10,
        )
        self.assertEqual(
            sankey_node_counts[
                (0, "Microsoft Graph Endpoints", "endpoint executions")
            ],
            2,
        )
        self.assertEqual(
            sankey_node_counts[(4, "Nothing to Assess", "finding checks")],
            1,
        )
        self.assertEqual(
            sankey_node_counts[(4, "Could Not Assess", "finding checks")],
            2,
        )
        graph_outcomes = next(
            row
            for row in requests["category_outcome_rows"]
            if row["category"] == "Microsoft Graph"
        )
        self.assertEqual(graph_outcomes["total"], 2)
        self.assertEqual(
            {item["key"]: item["count"] for item in graph_outcomes["outcomes"]},
            {"incomplete": 1, "unauthorised": 1},
        )
        self.assertEqual(len(requests["omission_groups"]), 2)
        self.assertEqual(
            {group["reason_label"] for group in requests["omission_groups"]},
            {
                "Upstream source returned no records",
                "Reason unavailable in legacy manifest",
            },
        )
        failed_card = next(
            card
            for card in cards["requests"]["attempts"]
            if card["label"] == "Failed"
        )
        unauthorised_card = next(
            card
            for card in cards["requests"]["attempts"]
            if card["label"] == "Unauthorised"
        )
        request_attempts_card = next(
            card
            for card in cards["requests"]["attempts"]
            if card["label"] == "Total Attempts"
        )
        not_applicable_card = next(
            card
            for card in cards["requests"]["attempts"]
            if card["label"] == "Not Applicable"
        )
        self.assertEqual(failed_card["value"], 1)
        self.assertEqual(unauthorised_card["value"], 2)
        self.assertEqual(request_attempts_card["value"], 10)
        self.assertEqual(not_applicable_card["value"], 2)
        self.assertEqual(
            cards["requests"]["unrecorded"][0],
            {
                "label": "Total Without Recorded Outcome",
                "value": 1,
                "detail": "Planned endpoint definitions with no request or deliberate skip outcome",
            },
        )
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('"label": "Permission Blocked"', body)
        self.assertIn("Collection Snapshot", body)
        self.assertIn("Finding Outcomes", body)
        self.assertIn("Collection Request Health", body)
        self.assertIn("Request Attempt Outcomes", body)
        self.assertIn("Skipped Endpoint Definitions", body)
        self.assertIn("Unrecorded Endpoint Definitions", body)
        self.assertIn("the cards below add up to Total Attempts", body)
        self.assertIn("the cause cards below add up to Total Skipped", body)
        self.assertIn("They are an accounting gap", body)
        self.assertIn("Returned No Data — Access Verified", body)
        self.assertIn("Returned No Data — Scope Restricted", body)
        self.assertIn("Returned No Data — Visibility Unverified", body)
        self.assertIn("Incomplete", body)
        self.assertIn("Checks Without Sufficient Data", body)
        self.assertNotIn("Rows in azure-findings-flat.json", body)
        self.assertNotIn("Status: not_found", body)
        self.assertIn('"label": "Unauthorised", "value": 1', body)
        self.assertIn('"label": "Empty Upstream Source", "value": 1', body)
        self.assertIn('"label": "Missing Source", "value": 1', body)
        self.assertIn('"label": "Checks Passed", "value": 1', body)
        self.assertNotIn('"label": "Insufficient Data \\u2014', body)
        self.assertIn("Finding Outcome Distribution", body)
        self.assertIn("Endpoint-to-Finding Flow", body)
        self.assertNotIn("Collection Endpoint Outcome Distribution", body)
        self.assertIn("Endpoint Outcomes by Collection Type", body)
        self.assertIn("shows 12 endpoint executions (5 Finding checks)", body)
        self.assertIn("findingsPieChart", body)
        self.assertIn("findingsSankeyChart", body)
        self.assertNotIn("requestsPieChart", body)
        self.assertNotIn("requestsSankeyChart", body)
        self.assertEqual(body.count("renderDashboardPie('findingsPieChart'"), 1)
        self.assertEqual(body.count("'findingsSankeyChart',"), 1)
        self.assertEqual(body.count('aria-label="Pie chart of consolidated finding outcomes across all endpoint types"'), 1)
        self.assertEqual(body.count('aria-label="Relationship-weighted Sankey chart from endpoint type and status through finding checks to finding results"'), 1)
        finding_chart_call = body.split(
            "renderDashboardPie('findingsPieChart'",
            1,
        )[1].split(");", 1)[0]
        self.assertIn('"label": "Findings Raised", "value": 1', finding_chart_call)
        self.assertIn('"label": "Unauthorised", "value": 1', finding_chart_call)
        self.assertIn('"label": "Checks Passed", "value": 1', finding_chart_call)
        self.assertEqual(
            sum(item["value"] for item in json.loads(
                finding_chart_call.split(", ", 2)[2]
            )),
            summary["executed"],
        )
        sankey_chart_call = body.split(
            "'findingsSankeyChart',",
            1,
        )[1].split(");", 1)[0]
        self.assertIn(
            '"nodes": ["Microsoft Graph Endpoints", "Unauthorised", '
            '"Finding Checks", "No Data to Assess", "Could Not Assess"], "value": 1',
            sankey_chart_call,
        )
        self.assertIn(
            '"nodes": ["Base Endpoints", "Returned Data", "Finding Checks", '
            '"Assessed", "Passed"], "value": 1',
            sankey_chart_call,
        )
        self.assertIn(
            '"nodes": ["Base Endpoints", "No Data \\u2014 Access Verified", '
            '"Finding Checks", "No Data to Assess", "Nothing to Assess"], "value": 1',
            sankey_chart_call,
        )
        self.assertIn("Microsoft Graph", body)
        self.assertIn("Graph Report Settings", body)
        self.assertIn("Authorization_RequestDenied", body)
        self.assertIn("Endpoint Omission Reasons", body)
        self.assertIn("Upstream source returned no records", body)
        self.assertIn("Reason unavailable in legacy manifest", body)
        self.assertIn("Skipped Endpoint (parameterised)", body)
        self.assertIn("Unattempted Endpoint (base)", body)
        self.assertIn("Unsuccessful Collection Requests", body)
        self.assertIn('<details class="dashboard-request-details">', body)
        self.assertNotIn('<details class="dashboard-request-details" open>', body)
        self.assertIn("dashboard-request-table", body)
        self.assertIn("--bs-table-color: var(--text-color)", body)
        self.assertEqual(body.count('class="dashboard-sort-button"'), 49)
        self.assertEqual(body.count('class="dashboard-column-filter"'), 49)
        self.assertEqual(
            body.count('<select class="dashboard-column-filter"'),
            39,
        )
        self.assertEqual(
            body.count('<input class="dashboard-column-filter"'),
            10,
        )
        self.assertIn('data-filter-mode="exact"', body)
        self.assertIn('data-filter-mode="contains"', body)
        self.assertIn("filter.addEventListener('change', applyFilters)", body)
        self.assertIn("cellValue === query", body)
        self.assertIn(
            "one row is shown for each failed, incomplete, unauthorised or tenant-restricted",
            body.lower(),
        )
        self.assertIn("function applyFilters()", body)
        self.assertIn("leftValue.localeCompare", body)
        self.assertIn("Storage Account Keys", body)
        self.assertIn("AuthorizationFailed", body)
        self.assertIn("Principal cannot list storage account keys.", body)
        self.assertIn("Partially Collected Graph Endpoint", body)
        self.assertIn("Microsoft Graph", body)
        self.assertIn("Legacy manifest error message", body)
        self.assertIn("Flow Logs (legacy manifest)", body)
        self.assertIn("Unavailable Service", body)
        self.assertIn("Base Endpoint Results — Azure Base and Parameterised", body)
        self.assertIn("Microsoft Graph Endpoint Results", body)
        self.assertIn(
            "Successful Collection Requests — Base and Microsoft Graph",
            body,
        )
        self.assertIn(
            "Unsuccessful Collection Requests — Base and Microsoft Graph",
            body,
        )
        self.assertLess(
            body.index("Base Endpoint Results — Azure Base and Parameterised"),
            body.index("Microsoft Graph Endpoint Results"),
        )
        self.assertLess(
            body.index("Microsoft Graph Endpoint Results"),
            body.index("Unsuccessful Collection Requests — Base and Microsoft Graph"),
        )
        self.assertLess(
            body.index("Unsuccessful Collection Requests — Base and Microsoft Graph"),
            body.index("Successful Collection Requests — Base and Microsoft Graph"),
        )
        self.assertIn("dashboard-five-column", body)

    def test_dashboard_separates_tenant_restrictions_and_inherited_skip_causes(self):
        findings_rows = {
            "rows": [
                {
                    "status": "no_data_to_assess",
                    "reporting": {
                        "provenance": {
                            "insufficient_data": {
                                "cause": "tenant_capability_unavailable"
                            }
                        }
                    },
                }
            ]
        }
        manifest = {
            "endpoint_runs": [
                {
                    "endpoint_name": "Graph Registration Details",
                    "category": "base",
                    "status": "unauthorised",
                    "returncode": 1,
                    "response_error": json.dumps(
                        {
                            "error": {
                                "code": "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
                                "message": "Tenant does not have a premium licence",
                            }
                        }
                    ),
                },
                {
                    "endpoint_name": "Child of Unauthorised Source",
                    "category": "parameterised",
                    "status": "skipped",
                    "reason_code": "upstream_source_unauthorised",
                    "error": "Missing required parameters: name",
                },
                {
                    "endpoint_name": "Child of Tenant-Restricted Source",
                    "category": "parameterised",
                    "status": "skipped",
                    "reason_code": "upstream_source_tenant_unavailable",
                    "error": "Missing required parameters: name",
                },
                {
                    "endpoint_name": "Child of Empty Source",
                    "category": "parameterised",
                    "status": "skipped",
                    "reason_code": "upstream_source_returned_no_data",
                    "error": "Missing required parameters: name",
                },
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            (data_dir / azure_present.FINDINGS_FLAT_FILENAME).write_text(
                json.dumps(findings_rows), encoding="utf-8"
            )
            (data_dir / "azure-collection-manifest_20260803-120000.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                findings = azure_present.findings_summary()
                requests = azure_present.collection_request_summary()
                cards = azure_present.build_dashboard_summary_cards(
                    [], findings, requests
                )
                response = azure_present.app.test_client().get("/")

        self.assertEqual(requests["tenant_unavailable"], 1)
        self.assertEqual(requests["unauthorised"], 0)
        self.assertEqual(
            requests["skipped_reason_counts"]["upstream_source_unauthorised"],
            1,
        )
        self.assertEqual(
            requests["skipped_reason_counts"][
                "upstream_source_tenant_unavailable"
            ],
            1,
        )
        attempt_values = {
            card["label"]: card["value"]
            for card in cards["requests"]["attempts"]
        }
        skipped_values = {
            card["label"]: card["value"]
            for card in cards["requests"]["skipped"]
        }
        self.assertEqual(
            attempt_values["Tenant Capability Unavailable"], 1
        )
        self.assertEqual(skipped_values["Unauthorised Prerequisite"], 1)
        self.assertEqual(skipped_values["Tenant Capability Prerequisite"], 1)
        self.assertEqual(skipped_values["Empty Prerequisite"], 1)
        self.assertEqual(
            attempt_values["Total Attempts"],
            sum(
                value
                for label, value in attempt_values.items()
                if label != "Total Attempts"
            ),
        )
        self.assertEqual(
            skipped_values["Total Skipped"],
            sum(
                value
                for label, value in skipped_values.items()
                if label != "Total Skipped"
            ),
        )
        body = response.get_data(as_text=True)
        self.assertIn(
            '"label": "Unlicensed", "value": 1',
            body,
        )
        self.assertIn("Licence or Tenant Capability", body)

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
        self.assertEqual(
            azure_present.dataset_collection_metadata(
                "az_rest_--method_get_--url_https_graph.microsoft.com_"
                "v1.0_directoryroles_20260727-120000.json"
            )["source"],
            "Microsoft Graph",
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

    def test_parameterised_value_wrapper_with_no_records_is_empty(self):
        endpoint = {
            "name": "Wrapped Collection",
            "cli_command": "az rest --method get --url {id}",
        }

        with mock.patch.object(
            azure_collect,
            "timed_run_az_cli",
            return_value={
                "returncode": 0,
                "json": {"@odata.context": "metadata", "value": []},
            },
        ):
            records = azure_collect.collect_parameter_set(
                endpoint,
                {"id": "https://example.invalid/collection"},
            )

        self.assertEqual(records, [])

    def test_parameterised_collection_passes_an_argument_vector_to_runner(self):
        endpoint = {
            "name": "Metrics Namespaces",
            "cli_command": "az monitor metrics list-namespaces --resource {id}",
        }
        resource_id = "/subscriptions/sub/resourceGroups/group (primary)/providers/type/name"

        with mock.patch.object(
            azure_collect,
            "timed_run_az_cli",
            return_value={"returncode": 0, "json": [{"name": "namespace"}]},
        ) as timed_run:
            records = azure_collect.collect_parameter_set(
                endpoint,
                {"id": resource_id},
            )

        command = timed_run.call_args.args[0]
        self.assertIsInstance(command, list)
        self.assertEqual(command[-1], resource_id)
        self.assertEqual(records[0]["name"], "namespace")

    def test_successful_empty_result_can_be_preserved_as_assessment_evidence(self):
        endpoint = {
            "name": "Diagnostic Settings",
            "cli_command": "az monitor diagnostic-settings list --resource {id}",
            "preserve_empty_result": True,
        }
        resource_id = "/subscriptions/sub/resourceGroups/group/providers/type/name"

        with mock.patch.object(
            azure_collect,
            "timed_run_az_cli",
            return_value={"returncode": 0, "json": []},
        ):
            records = azure_collect.collect_parameter_set(
                endpoint,
                {"id": resource_id},
            )

        self.assertEqual(records[0]["_collectionResult"], {"status": "empty"})
        self.assertEqual(
            records[0]["_collectionContext"]["parameters"]["id"],
            resource_id,
        )

    def test_failed_empty_result_is_not_preserved(self):
        endpoint = {
            "name": "Diagnostic Settings",
            "cli_command": "az monitor diagnostic-settings list --resource {id}",
            "preserve_empty_result": True,
        }

        with mock.patch.object(
            azure_collect,
            "timed_run_az_cli",
            return_value={"returncode": 1, "json": None},
        ):
            records = azure_collect.collect_parameter_set(
                endpoint,
                {"id": "/subscriptions/sub/providers/type/name"},
            )

        self.assertEqual(records, [])

    def test_empty_upstream_collection_records_structured_skip_reason(self):
        endpoint = {
            "name": "Child Details",
            "cli_command": "az child show --name {name}",
            "required_params": {"name": "az_parent_list"},
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            recorder = azure_collect.CollectionManifestRecorder(
                "20260402-000000",
                output_dir,
                project_dir=output_dir,
            )
            recorder.record_execution(
                "Parents",
                "base",
                "az parent list",
                "2026-04-02T00:00:00Z",
                0.1,
                0,
                0,
                endpoint_identifier="az_parent_list",
                access_verification={
                    "status": "access_verified",
                    "plane": "azure_resource_manager",
                    "method": "arm_effective_permissions",
                    "reason_code": "subscription_wide_arm_read_verified",
                },
            )
            azure_collect.OUTPUT_DIR = output_dir

            with mock.patch.object(azure_collect, "COLLECTION_MANIFEST", recorder):
                azure_collect.collect_data_with_params([endpoint])

            manifest = recorder.finish()

        skipped = next(
            item for item in manifest["endpoint_runs"]
            if item["endpoint_name"] == "Child Details"
        )
        self.assertEqual(skipped["status"], "skipped")
        self.assertEqual(skipped["reason_code"], "upstream_source_returned_no_data")
        self.assertEqual(
            skipped["reason_details"]["sources"]["az_parent_list"]["collection_statuses"],
            ["empty"],
        )
        self.assertEqual(
            skipped["reason_details"]["contributing_visibility_statuses"],
            ["access_verified"],
        )

    def test_tenant_capability_root_is_available_to_downstream_collectors(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            recorder = azure_collect.CollectionManifestRecorder(
                "20260402-000000",
                output_dir,
                project_dir=output_dir,
            )
            recorder.record_execution(
                "Graph Registration Details",
                "base",
                "az rest --url https://graph.microsoft.com/registrationDetails",
                "2026-04-02T00:00:00Z",
                0.1,
                1,
                None,
                endpoint_identifier="graph_user_registration_details",
                diagnostic_text=json.dumps(
                    {
                        "error": {
                            "code": "Authentication_RequestFromNonPremiumTenantOrB2CTenant"
                        }
                    }
                ),
            )

            with mock.patch.object(azure_collect, "COLLECTION_MANIFEST", recorder):
                reason, statuses, details = azure_collect.upstream_source_skip_reason(
                    "graph_user_registration_details"
                )

        self.assertEqual(reason, "upstream_source_tenant_unavailable")
        self.assertEqual(statuses, ["tenant_unavailable"])
        self.assertEqual(
            details["root_cause_endpoint_ids"],
            ["graph_user_registration_details"],
        )

    def test_unauthorised_root_cause_survives_multiple_skipped_collectors(self):
        endpoints = [
            {
                "name": "Child List",
                "cli_command": "az child list --parent {name}",
                "output_prefix": "az_child_list",
                "required_params": {"name": "az_parent_list"},
            },
            {
                "name": "Grandchild Details",
                "cli_command": "az grandchild show --name {name}",
                "required_params": {"name": "az_child_list"},
            },
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            recorder = azure_collect.CollectionManifestRecorder(
                "20260402-000000",
                output_dir,
                project_dir=output_dir,
            )
            recorder.record_execution(
                "Parents",
                "base",
                "az parent list",
                "2026-04-02T00:00:00Z",
                0.1,
                1,
                None,
                endpoint_identifier="az_parent_list",
                diagnostic_text="(AuthorizationFailed) Access denied",
            )
            azure_collect.OUTPUT_DIR = output_dir

            with mock.patch.object(azure_collect, "COLLECTION_MANIFEST", recorder):
                azure_collect.collect_data_with_params(endpoints)

            manifest = recorder.finish()

        child = next(
            item for item in manifest["endpoint_runs"]
            if item["endpoint_name"] == "Child List"
        )
        grandchild = next(
            item for item in manifest["endpoint_runs"]
            if item["endpoint_name"] == "Grandchild Details"
        )
        self.assertEqual(child["reason_code"], "upstream_source_unauthorised")
        self.assertEqual(
            grandchild["reason_code"], "upstream_source_unauthorised"
        )
        self.assertEqual(
            grandchild["reason_details"]["root_cause_endpoint_ids"],
            ["az_parent_list"],
        )
        self.assertIn(
            "upstream_source_unauthorised",
            grandchild["reason_details"]["contributing_reason_codes"],
        )
        self.assertEqual(
            grandchild["reason_details"]["dependency_chains"],
            [["az_parent_list", "az_child_list", "az_grandchild_show_--name_name"]],
        )

    def test_filtered_upstream_records_are_classified_as_not_applicable(self):
        endpoint = {
            "name": "Storage Details",
            "cli_command": "az storage show --name {name}",
            "required_params": {"name": "az_resource_list"},
            "required_source_types": {
                "az_resource_list": ["Microsoft.Storage/storageAccounts"],
            },
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            (output_dir / "az_resource_list_20260402-000000.json").write_text(
                json.dumps(
                    [{"name": "vm-one", "type": "Microsoft.Compute/virtualMachines"}]
                ),
                encoding="utf-8",
            )
            recorder = azure_collect.CollectionManifestRecorder(
                "20260402-000000",
                output_dir,
                project_dir=output_dir,
            )
            azure_collect.OUTPUT_DIR = output_dir

            with mock.patch.object(azure_collect, "COLLECTION_MANIFEST", recorder):
                azure_collect.collect_data_with_params([endpoint])

            manifest = recorder.finish()

        skipped = manifest["endpoint_runs"][0]
        self.assertEqual(skipped["status"], "skipped")
        self.assertEqual(skipped["reason_code"], "no_applicable_source_records")
        source_details = skipped["reason_details"]["sources"]["az_resource_list"]
        self.assertEqual(source_details["raw_record_count"], 1)
        self.assertEqual(source_details["applicable_record_count"], 0)

    def test_invalid_parameter_template_records_collector_defect(self):
        endpoint = {
            "name": "Broken Child Details",
            "cli_command": "az child show --name {unexpected}",
            "required_params": {"name": "az_parent_list"},
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            (output_dir / "az_parent_list_20260402-000000.json").write_text(
                json.dumps([{"name": "parent-one"}]),
                encoding="utf-8",
            )
            recorder = azure_collect.CollectionManifestRecorder(
                "20260402-000000",
                output_dir,
                project_dir=output_dir,
            )
            azure_collect.OUTPUT_DIR = output_dir

            with mock.patch.object(azure_collect, "COLLECTION_MANIFEST", recorder):
                azure_collect.collect_data_with_params([endpoint])

            manifest = recorder.finish()

        skipped = manifest["endpoint_runs"][0]
        self.assertEqual(skipped["status"], "skipped")
        self.assertEqual(skipped["reason_code"], "parameter_template_mismatch")

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
            [["az", "apim", "show", "--name", "apim-one", "--resource-group", "apim-rg"]],
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
            [["az", "network", "list-service-tags", "--location", "uksouth"]],
        )
        self.assertEqual(len(saved_payloads), 1)

    def test_flow_logs_only_query_locations_with_enabled_network_watchers(self):
        endpoint = next(
            endpoint
            for endpoint in azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
            if endpoint["name"] == "Flow Logs (by location)"
        )
        commands_run = []
        saved_payloads = []

        def fake_run_az_cli(cmd):
            commands_run.append(cmd)
            return {
                "json": [{"name": "flow-log-one"}],
                "success": True,
                "stdout": "[]",
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            source_file = output_dir / "az_network_watcher_list_20260402-000000.json"
            source_file.write_text(
                json.dumps(
                    [
                        {"name": "NetworkWatcher_uksouth", "location": "uksouth"},
                        {"name": "NetworkWatcher_ukwest", "location": "ukwest"},
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
            [
                ["az", "network", "watcher", "flow-log", "list", "--location", "uksouth"],
                ["az", "network", "watcher", "flow-log", "list", "--location", "ukwest"],
            ],
        )
        self.assertEqual(len(saved_payloads), 1)
        self.assertTrue(saved_payloads[0][1].startswith("az_network_watcher_flow-log_list_"))

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

        self.assertEqual(
            commands_run,
            [["az", "appservice", "ase", "show", "--name", "ase-one"]],
        )
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
                ["az", "vm", "nic", "show", "--resource-group", "rg-one", "--vm-name", "vm-one", "--nic", "nic-1"],
                ["az", "vm", "nic", "show", "--resource-group", "rg-two", "--vm-name", "vm-two", "--nic", "nic-2"],
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

        self.assertEqual(
            commands_run,
            [["az", "disk", "list", "--resource-group", "rg(test)"]],
        )
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
                [
                    "az",
                    "rest",
                    "--method",
                    "get",
                    "--url",
                    "/subscriptions/sub-one/providers/Microsoft.Security/assessments?api-version=2020-01-01",
                ],
            ],
        )
        self.assertEqual(len(saved_payloads), 1)
        self.assertEqual(saved_payloads[0][0][0]["name"], "assessment-one")


class PermissionBaselineTests(unittest.TestCase):
    def test_separate_graph_identity_does_not_require_arm_user_directory_role(self):
        original_token = azure_collect.GRAPH_ACCESS_TOKEN
        original_checked = azure_collect.PERMISSION_BASELINE_CHECKED
        original_config = azure_collect.AUTH_CONFIG
        azure_collect.GRAPH_ACCESS_TOKEN = "graph-token"
        azure_collect.PERMISSION_BASELINE_CHECKED = False
        azure_collect.AUTH_CONFIG = {
            "subscription_id": "subscription-1",
            "continue_with_missing_permissions": False,
        }
        try:
            with mock.patch.object(
                azure_collect,
                "get_current_principal_context",
                return_value=({
                    "object_id": "arm-user",
                    "subscription_id": "subscription-1",
                    "principal_name": "user@example.test",
                    "principal_type": "user",
                }, None),
            ), mock.patch.object(
                azure_collect, "get_transitive_group_ids", return_value=(set(), None)
            ), mock.patch.object(
                azure_collect, "get_directory_role_names_for_principal_ids"
            ) as directory_roles, mock.patch.object(
                azure_collect,
                "get_subscription_role_names_for_principal_ids",
                return_value=({"Reader", "Security Reader"}, []),
            ), mock.patch.object(
                azure_collect,
                "check_custom_role_permissions",
                return_value={
                    "present_custom_roles": ["YGHT Azure Assessment Collector"],
                    "missing_actions": [],
                    "missing_data_actions": [],
                    "errors": [],
                },
            ):
                azure_collect.ensure_required_permission_baseline()
            directory_roles.assert_not_called()
        finally:
            azure_collect.GRAPH_ACCESS_TOKEN = original_token
            azure_collect.PERMISSION_BASELINE_CHECKED = original_checked
            azure_collect.AUTH_CONFIG = original_config

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
            [
                ["az", "iot", "hub", "list", "--output", "json"],
                ["az", "iot", "hub", "list", "--output", "json"],
            ],
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

    def test_not_applicable_azure_request_is_not_recorded_as_collection_error(self):
        output = "ERROR: network watcher is not enabled for region spaincentral."

        with mock.patch.object(
            azure_collect.subprocess,
            "Popen",
            return_value=FakeAzProcess(1, output),
        ):
            result = azure_collect.run_az_cli(
                "az network watcher flow-log list --location spaincentral",
                endpoint_name="Flow Logs (by location)",
                category="parameterised",
            )

        self.assertFalse(result["success"])
        self.assertEqual(result["returncode"], 1)
        self.assertEqual(
            result["collection_error"],
            "Azure CLI request failed with return code 1",
        )
        self.assertEqual(azure_collect.COLLECTION_ERRORS, [])

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
