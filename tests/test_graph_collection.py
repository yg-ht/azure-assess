#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later

import base64
import importlib.util
import json
import re
import tempfile
import unittest
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import azure_assess.graph_collection as graph_collection
from azure_assess.graph_endpoints import GRAPH_ENDPOINTS, validate_registry
from azure_assess.graph_collection import (
    graph_access_verification,
    selected_graph_endpoints,
    token_permissions,
)
from azure_assess.graph_runner import (
    GraphError,
    GraphRunner,
    SafeGraphRedirectHandler,
    endpoint_url,
    resolved_body,
    utc_interval,
)


PROJECT = Path(__file__).resolve().parents[1]


class GraphRegistryTests(unittest.TestCase):
    def test_default_all_permissions_have_collection_use(self):
        script = (PROJECT / "scripts/Azure-Graph-Collect-App.ps1").read_text(encoding="utf-8")
        profile_block = script.split("$PermissionProfiles = [ordered]@{", 1)[1].split("$SelectedProfiles", 1)[0]
        permissions = set(re.findall(r'^\s*"([A-Za-z][A-Za-z0-9.-]+)"', profile_block, re.MULTILINE))
        registered = {
            permission
            for endpoint in GRAPH_ENDPOINTS
            for permission in endpoint["permissions"]
        }
        original_permissions = {
            "Application.Read.All", "AuditLog.Read.All", "AuditLogsQuery-Exchange.Read.All",
            "AuditLogsQuery-OneDrive.Read.All", "AuditLogsQuery-SharePoint.Read.All",
            "AuditLogsQuery.Read.All", "BitlockerKey.Read.All",
            "DeviceManagementConfiguration.Read.All", "DeviceManagementManagedDevices.Read.All",
            "DeviceManagementRBAC.Read.All", "DeviceManagementServiceConfig.Read.All",
            "Directory.Read.All", "DirectoryRecommendations.Read.All",
            "EntitlementManagement.Read.All", "IdentityProvider.Read.All",
            "IdentityRiskEvent.Read.All", "NetworkAccess.Read.All",
            "OnPremDirectorySynchronization.Read.All", "OrgSettings-AppsAndServices.Read.All",
            "OrgSettings-Forms.Read.All", "Policy.Read.All", "Policy.Read.ConditionalAccess",
            "PrivilegedAccess.Read.AzureAD", "PrivilegedAccess.Read.AzureADGroup",
            "PrivilegedAccess.Read.AzureResources", "ProvisioningLog.Read.All",
            "ReportSettings.Read.All", "Reports.Read.All",
            "RoleEligibilitySchedule.Read.Directory", "RoleManagement.Read.All",
            "RoleManagementAlert.Read.Directory", "SecurityIdentitiesHealth.Read.All",
            "SecurityIdentitiesSensors.Read.All", "SecurityIncident.Read.All",
            "ServiceActivity-Exchange.Read.All", "ServiceActivity-Microsoft365Web.Read.All",
            "ServiceActivity-OneDrive.Read.All", "ServiceActivity-Teams.Read.All",
            "SharePointTenantSettings.Read.All", "ThreatHunting.Read.All",
            "UserAuthenticationMethod.Read.All",
        }
        self.assertEqual(41, len(original_permissions))
        self.assertTrue(original_permissions <= permissions)
        self.assertTrue(registered <= permissions)

    def test_registry_is_stable_and_beta_is_explicit(self):
        validate_registry()
        self.assertEqual(len(GRAPH_ENDPOINTS), len({item["id"] for item in GRAPH_ENDPOINTS}))
        self.assertTrue(all(item["api"] in {"v1.0", "beta"} for item in GRAPH_ENDPOINTS))
        self.assertTrue(all(item["output"].startswith("graph_") for item in GRAPH_ENDPOINTS))

    def test_bitlocker_endpoint_does_not_request_key_material(self):
        endpoint = next(item for item in GRAPH_ENDPOINTS if item["id"] == "bitlocker_key_metadata")
        self.assertIn("$select=", endpoint["path"])
        self.assertNotIn("key=", endpoint["path"].lower())
        self.assertNotIn("getKey", endpoint["path"])

    def test_security_defaults_and_supported_identity_apis_use_v1(self):
        endpoints = {item["id"]: item for item in GRAPH_ENDPOINTS}
        self.assertEqual(
            "/policies/identitySecurityDefaultsEnforcementPolicy",
            endpoints["security_defaults"]["path"],
        )
        for endpoint_id in (
            "security_defaults", "sign_ins", "provisioning_logs",
            "identity_providers", "pim_directory_active", "pim_group_active",
            "settings_sharepoint",
        ):
            self.assertEqual("v1.0", endpoints[endpoint_id]["api"])

    def test_group_pim_is_fanned_out_with_required_filter(self):
        group_endpoints = [
            item for item in GRAPH_ENDPOINTS if item["id"].startswith("pim_group_")
        ]
        self.assertTrue(group_endpoints)
        for endpoint in group_endpoints:
            self.assertEqual("groups", endpoint["fan_out"]["parent"])
            self.assertIn("$filter=groupId eq '{parent_id}'", endpoint["path"])

    def test_settings_catalog_settings_are_fanned_out_per_policy(self):
        endpoint = next(
            item for item in GRAPH_ENDPOINTS
            if item["id"] == "settings_catalog_settings"
        )

        self.assertEqual("beta", endpoint["api"])
        self.assertEqual("settings_catalog", endpoint["fan_out"]["parent"])
        self.assertEqual("id", endpoint["fan_out"]["id"])
        self.assertEqual(
            "/deviceManagement/configurationPolicies/{parent_id}/settings",
            endpoint["path"],
        )
        self.assertEqual(
            "DeviceManagementConfiguration.Read.All", endpoint["permission"]
        )

    def test_pim_alert_inventory_is_scoped_to_directory_roles(self):
        endpoints = {item["id"]: item for item in GRAPH_ENDPOINTS}
        for endpoint_id in ("pim_alerts", "pim_alert_configurations"):
            self.assertIn("scopeId eq '/'", endpoints[endpoint_id]["path"])
            self.assertIn("scopeType eq 'DirectoryRole'", endpoints[endpoint_id]["path"])

    def test_audit_filters_are_strings_and_usage_reports_are_stable_csv(self):
        endpoints = {item["id"]: item for item in GRAPH_ENDPOINTS}
        for endpoint_id in ("audit_exchange", "audit_onedrive", "audit_sharepoint"):
            self.assertIsInstance(endpoints[endpoint_id]["body"]["serviceFilter"], str)
        for endpoint_id in (
            "activity_exchange", "activity_m365_web", "activity_onedrive",
            "activity_teams",
        ):
            endpoint = endpoints[endpoint_id]
            self.assertEqual("v1.0", endpoint["api"])
            self.assertEqual("csv", endpoint["response_format"])
            self.assertNotIn("/serviceActivity/", endpoint["path"])

    def test_setup_helper_grants_only_required_azure_collection_access(self):
        script = (PROJECT / "scripts/Azure-Graph-Collect-App.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn('RoleDefinitionName "Reader"', script)
        self.assertIn('RoleDefinitionName "Security Reader"', script)
        self.assertIn('RoleDefinitionName "Key Vault Reader"', script)
        self.assertNotIn('RoleDefinitionName "Key Vault Secrets User"', script)
        self.assertIn(
            '"Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action"',
            script,
        )
        self.assertIn(
            '"Microsoft.Network/networkInterfaces/effectiveRouteTable/action"',
            script,
        )
        self.assertIn("-PermissionsToKeys List", script)
        self.assertIn("-PermissionsToSecrets List", script)
        self.assertNotIn("-PermissionsToSecrets Get", script)
        for action in (
            "Microsoft.Compute/virtualMachines/runCommands/read",
            "Microsoft.CostManagement/query/action",
            "Microsoft.Insights/Components/Query/Read",
            "Microsoft.KeyVault/vaults/secrets/read",
            "Microsoft.Storage/storageAccounts/listkeys/action",
            "Microsoft.Web/sites/config/list/Action",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        ):
            self.assertIn(f'"{action}"', script)

    def test_setup_helper_defaults_to_complete_permission_provisioning(self):
        script = (PROJECT / "scripts/Azure-Graph-Collect-App.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("[switch]$SkipAzureRoleAssignments", script)
        self.assertIn("[switch]$SkipLegacyKeyVaultAccessPolicies", script)
        self.assertNotIn("ConfigureLegacyKeyVaultAccessPolicies", script)
        self.assertNotIn("AdditionalApplicationPermissions", script)
        self.assertIn(
            "if (-not $SkipAzureRoleAssignments -and "
            "$AzureSubscriptionIds.Count -eq 0)",
            script,
        )
        self.assertIn("if (-not $SkipAzureRoleAssignments) {", script)
        self.assertIn("if (-not $SkipLegacyKeyVaultAccessPolicies) {", script)

    def test_legacy_graph_names_and_commands_select_native_endpoints(self):
        for selector, endpoint_id in (
            ("Active Directory Users", "users"),
            ("az ad app list", "applications"),
            ("identitySecurityDefaultsEnforcementPolicy", "security_defaults"),
        ):
            self.assertEqual(
                [endpoint_id],
                [item["id"] for item in selected_graph_endpoints(selector)],
            )

    def test_pim_selection_includes_group_fanout_inventory(self):
        selected_ids = {item["id"] for item in selected_graph_endpoints("PIM")}

        self.assertIn("groups", selected_ids)
        self.assertIn("pim_group_active", selected_ids)

    def test_token_permission_claims_support_app_and_existing_login_tokens(self):
        def token(claims):
            encoded = base64.urlsafe_b64encode(
                json.dumps(claims).encode("utf-8")
            ).decode("ascii").rstrip("=")
            return f"header.{encoded}.signature"

        self.assertEqual(
            {"Policy.Read.All"},
            token_permissions(token({"roles": ["Policy.Read.All"]})),
        )
        self.assertEqual(
            {"Policy.Read.All", "User.Read"},
            token_permissions(token({"scp": "Policy.Read.All User.Read"})),
        )
        self.assertEqual(
            "access_verified",
            graph_access_verification(
                ["Policy.Read.All"], {"Policy.Read.All"}
            )["status"],
        )


class GraphRunnerTests(unittest.TestCase):
    def test_exact_thirty_day_utc_interval(self):
        start, end = utc_interval(30, datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc))
        self.assertEqual("2026-07-05T12:00:00Z", start)
        self.assertEqual("2026-08-04T12:00:00Z", end)

    def test_cross_host_report_redirect_does_not_forward_bearer_token(self):
        request = urllib.request.Request(
            "https://graph.microsoft.com/v1.0/reports/example",
            headers={"Authorization": "Bearer secret", "Accept": "application/json"},
        )
        redirected = SafeGraphRedirectHandler().redirect_request(
            request, None, 302, "Found", {}, "https://reports.office.com/download"
        )

        self.assertNotIn("Authorization", redirected.headers)

    def test_url_and_body_resolution(self):
        endpoint = {"api": "beta", "path": "/things?$filter=time ge {start}", "body": {"end": "{end}"}}
        context = {"start": "2026-01-01T00:00:00Z", "end": "2026-01-31T00:00:00Z"}
        self.assertIn("/beta/things", endpoint_url(endpoint, context))
        self.assertEqual(context["end"], resolved_body(endpoint, context)["end"])

    def test_pagination_streams_duplicates_and_empty_last_page(self):
        calls = []
        pages = [
            (200, {}, {"value": [{"id": "a"}, {"id": "a"}], "@odata.nextLink": "https://next"}),
            (200, {}, {"value": []}),
        ]
        def transport(method, url, body):
            calls.append((method, url, body))
            return pages.pop(0)
        endpoint = {"id": "items", "name": "Items", "profile": "Test", "api": "v1.0", "method": "GET", "path": "/items", "pagination": True}
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "items.json"
            result = GraphRunner(transport).collect(endpoint, target, {"start": "s", "end": "e"})
            data = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual("success", result.status)
        self.assertEqual(2, result.pages)
        self.assertEqual(["a", "a"], [item["id"] for item in data])
        self.assertEqual(2, len(calls))

    def test_singleton_value_envelope_is_flattened(self):
        def transport(method, url, body):
            return 200, {}, {"value": {"id": "settings", "enabled": True}}
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "settings.json"
            result = GraphRunner(transport).collect(
                {"id": "settings", "name": "Settings", "profile": "T", "api": "beta", "method": "GET", "path": "/admin/settings", "pagination": False},
                target, {"start": "s", "end": "e"}
            )
            records = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual("success", result.status)
        self.assertEqual("settings", records[0]["id"])

    def test_hunting_results_are_flattened_without_treating_schema_as_evidence(self):
        def transport(method, url, body):
            return 200, {}, {"schema": [{"name": "Timestamp"}], "results": []}
        endpoint = {
            "id": "hunt", "name": "Hunt", "profile": "T", "api": "v1.0",
            "method": "POST", "path": "/security/runHuntingQuery",
            "pagination": False, "records_field": "results",
        }
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "hunt.json"
            result = GraphRunner(transport).collect(
                endpoint, target, {"start": "s", "end": "e"}
            )
            records = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual("empty", result.status)
        self.assertEqual([], records)

    def test_transient_retry_then_success(self):
        attempts = []
        def transport(method, url, body):
            attempts.append(url)
            if len(attempts) == 1:
                raise GraphError("busy", status=503)
            return 200, {}, {"value": []}
        with tempfile.TemporaryDirectory() as directory:
            result = GraphRunner(transport, sleeper=lambda _: None).collect(
                {"id": "x", "name": "X", "profile": "T", "api": "v1.0", "method": "GET", "path": "/x", "pagination": True},
                Path(directory) / "x.json", {"start": "s", "end": "e"})
        self.assertEqual("empty", result.status)
        self.assertEqual(2, result.attempts)

    def test_progress_reports_retry_and_streamed_page_without_request_details(self):
        events = []
        attempts = 0

        def transport(method, url, body):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise GraphError("busy", status=503)
            return 200, {}, {"value": [{"id": "record-one"}]}

        endpoint = {
            "id": "items",
            "name": "Friendly Items",
            "profile": "Test",
            "api": "v1.0",
            "method": "GET",
            "path": "/items",
            "pagination": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            result = GraphRunner(
                transport,
                sleeper=lambda _: None,
                progress=lambda event, details: events.append((event, details)),
            ).collect(
                endpoint,
                Path(directory) / "items.json",
                {"start": "s", "end": "e"},
            )

        self.assertEqual("success", result.status)
        self.assertEqual(
            ["retry_wait", "page_completed"],
            [event for event, _ in events],
        )
        self.assertEqual("Friendly Items", events[0][1]["endpoint_name"])
        self.assertEqual(1, events[1][1]["total_records"])
        self.assertNotIn("url", events[0][1])
        self.assertNotIn("url", events[1][1])

    def test_audit_query_progress_has_throttled_status_without_query_id(self):
        events = []
        statuses = iter(("running", "succeeded"))

        def transport(method, url, body):
            if method == "POST":
                return 200, {}, {"id": "sensitive-query-id"}
            if url.endswith("/records"):
                return 200, {}, {"value": []}
            return 200, {}, {"status": next(statuses)}

        endpoint = {
            "id": "audit",
            "name": "Unified Audit",
            "profile": "M365Audit",
            "api": "beta",
            "method": "POST",
            "path": "/security/auditLog/queries",
            "body": {"displayName": "Azure Assess"},
            "mode": "audit_query",
            "pagination": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            result = GraphRunner(
                transport,
                sleeper=lambda _: None,
                progress=lambda event, details: events.append((event, details)),
            ).collect(
                endpoint,
                Path(directory) / "audit.json",
                {"start": "s", "end": "e"},
            )

        self.assertEqual("empty", result.status)
        self.assertEqual(
            ["audit_query_created", "audit_poll", "audit_poll", "page_completed"],
            [event for event, _ in events],
        )
        self.assertNotIn("sensitive-query-id", repr(events))

    def test_completed_pages_are_retained_as_an_incomplete_dataset(self):
        calls = []
        def transport(method, url, body):
            calls.append(url)
            if len(calls) == 1:
                return 200, {}, {"value": [{"id": "first"}], "@odata.nextLink": "https://next"}
            raise GraphError(
                "failed", status=500,
                body=json.dumps({"error": {"code": "InternalError", "message": "later page failed"}}),
            )
        endpoint = {
            "id": "items", "name": "Items", "profile": "T", "api": "v1.0",
            "method": "GET", "path": "/items", "pagination": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "items.json"
            result = GraphRunner(
                transport, max_attempts=1, sleeper=lambda _: None
            ).collect(endpoint, target, {"start": "s", "end": "e"})
            records = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual("incomplete", result.status)
        self.assertTrue(result.incomplete)
        self.assertEqual(["first"], [item["id"] for item in records])

    def test_retry_after_header_is_honoured(self):
        delays = []
        calls = []
        def transport(method, url, body):
            calls.append(url)
            if len(calls) == 1:
                return 429, {"Retry-After": "3"}, {"error": {"code": "TooManyRequests"}}
            return 200, {}, {"value": []}
        with tempfile.TemporaryDirectory() as directory:
            result = GraphRunner(transport, sleeper=delays.append).collect(
                {"id": "x", "name": "X", "profile": "T", "api": "v1.0", "method": "GET", "path": "/x", "pagination": True},
                Path(directory) / "x.json", {"start": "s", "end": "e"})
        self.assertEqual("empty", result.status)
        self.assertEqual([3.0], delays)

    def test_unauthorised_invalid_path_and_beta_unavailable_are_distinct(self):
        for status, api, expected in (
            (403, "v1.0", "unauthorised"),
            (404, "v1.0", "failed"),
            (404, "beta", "tenant_unavailable"),
        ):
            def transport(method, url, body, status=status):
                raise GraphError("no", status=status)
            with tempfile.TemporaryDirectory() as directory:
                result = GraphRunner(transport).collect(
                    {"id": "x", "name": "X", "profile": "T", "api": api, "method": "GET", "path": "/x", "pagination": True},
                    Path(directory) / "x.json", {"start": "s", "end": "e"})
            self.assertEqual(expected, result.status)

    def test_licence_error_body_is_preserved_and_classified(self):
        body = json.dumps({"error": {
            "code": "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
            "message": "Premium licence required",
        }})
        def transport(method, url, request_body):
            raise GraphError("forbidden", status=403, body=body)
        with tempfile.TemporaryDirectory() as directory:
            result = GraphRunner(transport).collect(
                {"id": "x", "name": "X", "profile": "T", "api": "v1.0", "method": "GET", "path": "/x", "pagination": True},
                Path(directory) / "x.json", {"start": "s", "end": "e"})
        self.assertEqual("tenant_unavailable", result.status)
        self.assertEqual(body, result.diagnostic)
        self.assertIn("Premium licence required", result.error)

    def test_capability_message_classifies_unlicensed_global_secure_access(self):
        body = json.dumps({"error": {
            "code": "Forbidden",
            "message": "The tenant is not onboarded for this service",
        }})
        def transport(method, url, request_body):
            raise GraphError("forbidden", status=403, body=body)
        with tempfile.TemporaryDirectory() as directory:
            result = GraphRunner(transport).collect(
                {"id": "gsa", "name": "GSA", "profile": "T", "api": "beta", "method": "GET", "path": "/networkAccess/tenantStatus", "pagination": False},
                Path(directory) / "gsa.json", {"start": "s", "end": "e"})
        self.assertEqual("tenant_unavailable", result.status)

    def test_csv_report_is_flattened_to_json_records(self):
        def transport(method, url, body):
            return 200, {"Content-Type": "text/csv"}, "User Principal Name,Last Activity Date\nuser@example.com,2026-08-01\n"
        endpoint = {
            "id": "report", "name": "Report", "profile": "T", "api": "v1.0",
            "method": "GET", "path": "/reports/example", "pagination": False,
            "response_format": "csv",
        }
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "report.json"
            result = GraphRunner(transport).collect(
                endpoint, target, {"start": "s", "end": "e"}
            )
            records = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual("success", result.status)
        self.assertEqual("user@example.com", records[0]["User Principal Name"])


class GraphCollectionProgressTests(unittest.TestCase):
    class Manifest:
        def __init__(self):
            self.executions = []

        def register_endpoints(self, *args, **kwargs):
            pass

        def record_execution(self, **kwargs):
            self.executions.append(kwargs)

        def record_dataset(self, *args, **kwargs):
            pass

        def record_skipped_endpoint(self, *args, **kwargs):
            pass

        def add_limitation(self, *args, **kwargs):
            pass

    def test_orchestrator_reports_phase_endpoint_and_completion_counts(self):
        endpoint = {
            "id": "items",
            "name": "Graph Items",
            "profile": "Test",
            "permission": "Items.Read.All",
            "permissions": ["Items.Read.All"],
            "api": "v1.0",
            "method": "GET",
            "path": "/items",
            "pagination": True,
            "output": "graph_test_items",
            "licence": "Test capability",
        }
        events = []

        def transport(method, url, body):
            return 200, {}, {"value": [{"id": "one"}]}

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(graph_collection, "GRAPH_ENDPOINTS", [endpoint]):
                successful = graph_collection.collect_registered_graph(
                    output_dir=Path(directory),
                    run_id="run-one",
                    lookback_days=30,
                    endpoint_filter=None,
                    manifest=self.Manifest(),
                    runner=GraphRunner(transport),
                    progress=lambda event, details: events.append((event, details)),
                )

        self.assertTrue(successful)
        self.assertEqual(
            [
                "phase_started",
                "endpoint_started",
                "endpoint_completed",
                "phase_completed",
            ],
            [event for event, _ in events],
        )
        completion = events[2][1]
        self.assertEqual(1, completion["records"])
        self.assertEqual(1, completion["pages"])


if __name__ == "__main__":
    unittest.main()
