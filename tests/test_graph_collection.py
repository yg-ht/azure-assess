#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later

import importlib.util
import json
import re
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from azure_assess.graph_endpoints import GRAPH_ENDPOINTS, validate_registry
from azure_assess.graph_runner import GraphError, GraphRunner, endpoint_url, resolved_body, utc_interval


PROJECT = Path(__file__).resolve().parents[1]


class GraphRegistryTests(unittest.TestCase):
    def test_default_all_permissions_have_collection_use(self):
        script = (PROJECT / "scripts/Azure-Graph-Collect-App.ps1").read_text(encoding="utf-8")
        profile_block = script.split("$PermissionProfiles = [ordered]@{", 1)[1].split("$SelectedProfiles", 1)[0]
        permissions = set(re.findall(r'^\s*"([A-Za-z][A-Za-z0-9.-]+)"', profile_block, re.MULTILINE))
        registered = {endpoint["permission"] for endpoint in GRAPH_ENDPOINTS}
        self.assertEqual(permissions, registered)
        self.assertEqual(41, len(permissions))

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


class GraphRunnerTests(unittest.TestCase):
    def test_exact_thirty_day_utc_interval(self):
        start, end = utc_interval(30, datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc))
        self.assertEqual("2026-07-05T12:00:00Z", start)
        self.assertEqual("2026-08-04T12:00:00Z", end)

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

    def test_unauthorised_and_capability_are_distinct(self):
        for status, expected in ((403, "unauthorised"), (404, "tenant_unavailable")):
            def transport(method, url, body, status=status):
                raise GraphError("no", status=status)
            with tempfile.TemporaryDirectory() as directory:
                result = GraphRunner(transport).collect(
                    {"id": "x", "name": "X", "profile": "T", "api": "v1.0", "method": "GET", "path": "/x", "pagination": True},
                    Path(directory) / "x.json", {"start": "s", "end": "e"})
            self.assertEqual(expected, result.status)


if __name__ == "__main__":
    unittest.main()
