import importlib.util
import unittest
from collections import Counter
from pathlib import Path

from azure_assess.endpoint_requirements import (
    BASE,
    BASE_AND_GRAPH,
    EITHER,
    GRAPH,
    alternative_source_options,
    required_source_options,
    source_options_for_type,
    source_type_for_options,
)
from azure_assess.endpoint_assessment import (
    AUTOMATED,
    MANUAL,
    SUPPORTING,
    MANUAL_ASSESSMENT_ENDPOINTS,
    SUPPORTING_ONLY_ENDPOINTS,
    endpoint_assessment_role,
    manual_endpoint_groups,
)


ROOT = Path(__file__).resolve().parents[1]


def load_script(module_name, filename):
    spec = importlib.util.spec_from_file_location(module_name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


azure_collect = load_script("azure_collect_endpoint_audit", "azure-collect.py")
azure_findings = load_script("azure_findings_endpoint_audit", "azure-findings.py")


class ManualEndpointAssessmentTests(unittest.TestCase):
    def test_parameterised_executions_become_one_manual_item(self):
        manifest = {
            "endpoint_runs": [
                {
                    "endpoint_id": "az_monitor_metrics_list-namespaces_--resource_id",
                    "endpoint_name": "Azure Metrics Namespaces",
                    "category": "parameterised",
                    "status": "success",
                    "result_count": 2,
                    "parameter_context": {"resource_id": f"secret-{index}"},
                    "output_files": [f"metrics-{index}.json"],
                }
                for index in range(349)
            ]
        }

        groups = manual_endpoint_groups(manifest)

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["execution_count"], 349)
        self.assertEqual(groups[0]["record_count"], 698)
        self.assertTrue(groups[0]["usable_evidence"])
        self.assertNotIn("parameter_context", groups[0])
        self.assertNotIn("secret-", repr(groups[0]))

    def test_supporting_endpoint_does_not_create_a_manual_item(self):
        groups = manual_endpoint_groups({
            "endpoint_runs": [{
                "endpoint_id": "az_vm_list",
                "category": "base",
                "status": "success",
                "result_count": 10,
            }],
        })

        self.assertEqual(groups, [])

    def test_manual_finding_requires_usable_evidence(self):
        endpoint_id = "graph_identity_baseline_domains"
        manifest = {
            "endpoint_runs": [{
                "endpoint_id": endpoint_id,
                "endpoint_name": "Graph Domains",
                "category": "microsoft_graph",
                "status": "unauthorised",
                "result_count": 0,
            }],
        }
        findings, _sources = azure_findings.evaluate_manual_endpoint_findings({
            "azure-collection-manifest.json": {
                "data": manifest,
                "path": Path("azure-collection-manifest.json"),
            },
        })

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "no_data_to_assess")
        self.assertEqual(findings[0]["_endpoint_source_type"], GRAPH)

    def test_retained_manual_evidence_creates_one_review_item(self):
        filename = "graph_identity_baseline_domains_run-one.json"
        manifest = {
            "endpoint_runs": [{
                "endpoint_id": "graph_identity_baseline_domains",
                "endpoint_name": "Graph Domains",
                "category": "microsoft_graph",
                "status": "success",
                "result_count": 3,
                "output_files": [filename],
            }],
        }
        findings, _sources = azure_findings.evaluate_manual_endpoint_findings({
            "azure-collection-manifest.json": {
                "data": manifest,
                "path": Path("azure-collection-manifest.json"),
            },
            filename: {
                "data": [
                    {"id": "one"},
                    {"id": "two"},
                    {"id": "three"},
                ],
                "path": Path(filename),
            },
        })

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["status"], "manual_assessment_required"
        )
        self.assertEqual(findings[0]["title"], "Graph Domains")
        self.assertEqual(findings[0]["reason"], "")
        self.assertEqual(findings[0]["evidence"][0]["recordCount"], 3)
        self.assertEqual(azure_findings.flat_rows(findings)[0]["count"], 3)

    def test_empty_retained_dataset_is_not_a_manual_review_item(self):
        filename = "graph_identity_baseline_domains_run-one.json"
        manifest = {
            "endpoint_runs": [{
                "endpoint_id": "graph_identity_baseline_domains",
                "endpoint_name": "Graph Domains",
                "category": "microsoft_graph",
                "status": "success",
                "result_count": 3,
                "output_files": [filename],
            }],
        }
        findings, _sources = azure_findings.evaluate_manual_endpoint_findings({
            "azure-collection-manifest.json": {
                "data": manifest,
                "path": Path("azure-collection-manifest.json"),
            },
            filename: {"data": [], "path": Path(filename)},
        })

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "no_data_to_assess")
        self.assertEqual(findings[0]["evidence"], [])

    def test_missing_retained_dataset_is_not_a_manual_review_item(self):
        filename = "graph_identity_baseline_domains_run-one.json"
        manifest = {
            "endpoint_runs": [{
                "endpoint_id": "graph_identity_baseline_domains",
                "endpoint_name": "Graph Domains",
                "category": "microsoft_graph",
                "status": "success",
                "result_count": 3,
                "output_files": [filename],
            }],
        }
        findings, _sources = azure_findings.evaluate_manual_endpoint_findings({
            "azure-collection-manifest.json": {
                "data": manifest,
                "path": Path("azure-collection-manifest.json"),
            },
        })

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "no_data_to_assess")
        self.assertEqual(findings[0]["evidence"], [])

    def test_manual_items_are_excluded_from_sarif(self):
        sarif = azure_findings.sarif_output(
            "/tmp/input",
            {},
            [{"status": "manual_assessment_required"}],
        )

        self.assertEqual(sarif["runs"][0]["results"], [])
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["rules"], [])

    def test_function_app_auth_uses_its_own_collector_output(self):
        catalog = {
            "az_functionapp_auth_show.json": {
                "data": [{
                    "enabled": False,
                    "_collectionContext": {
                        "parameters": {
                            "name": "function-one",
                            "resourceGroup": "rg-one",
                        },
                    },
                }],
                "path": Path("az_functionapp_auth_show.json"),
            },
        }

        finding = next(
            item for item in azure_findings.evaluate_findings(catalog)
            if item["title"]
            == "Azure Function Apps do not have authentication configured"
        )

        self.assertEqual(finding["status"], "found")
        self.assertEqual(
            finding["references"]["required_endpoint_patterns"],
            [["az_functionapp_auth_show"]],
        )


class EndpointRequirementModelTests(unittest.TestCase):
    def test_alternative_base_and_graph_sources_are_either(self):
        options = alternative_source_options(
            source_options_for_type(BASE),
            source_options_for_type(GRAPH),
        )

        self.assertEqual(source_type_for_options(options), EITHER)

    def test_graph_alternative_plus_required_graph_remains_graph(self):
        alternatives = source_options_for_type(EITHER)

        options = required_source_options(
            alternatives,
            source_options_for_type(GRAPH),
        )

        self.assertEqual(source_type_for_options(options), GRAPH)

    def test_independent_base_and_graph_inputs_require_both(self):
        options = required_source_options(
            source_options_for_type(BASE),
            source_options_for_type(GRAPH),
        )

        self.assertEqual(source_type_for_options(options), BASE_AND_GRAPH)

    def test_alternative_reference_accumulation_retains_endpoint_metadata(self):
        references = azure_findings.SourceReferences()
        references += azure_findings.dataset_references_any(
            {},
            ("graph_identity_baseline_users",),
            ("az_ad_user_list",),
        )

        self.assertEqual(
            references.required_patterns,
            (
                ("graph_identity_baseline_users",),
                ("az_ad_user_list",),
            ),
        )
        self.assertEqual(
            source_type_for_options(references.source_options),
            EITHER,
        )


class FindingEndpointCoverageTests(unittest.TestCase):
    LEGACY_ENDPOINT_IDS = {
        "az_ad_app_list",
        "az_ad_group_list",
        "az_ad_sp_list_--all",
        "az_ad_user_list",
        "az_role_definition_list",
    }
    LEGACY_ENDPOINT_PATTERNS = {
        ("az_ad_user_list",),
        ("az_role_definition_list",),
        ("az_security_assessment_list",),
    }

    @classmethod
    def setUpClass(cls):
        cls.findings = azure_findings.evaluate_findings({})
        cls.current_endpoints = {}
        for endpoint in (
            azure_collect.AZURE_CLI_ENDPOINTS
            + azure_collect.AZURE_CLI_ENDPOINTS_PARAMS
        ):
            endpoint_id = azure_collect.endpoint_output_prefix(endpoint)
            cls.current_endpoints[endpoint_id] = " ".join(
                str(value)
                for value in (
                    endpoint_id,
                    endpoint.get("name"),
                    endpoint.get("cli_command"),
                )
            )
        for endpoint in azure_collect.GRAPH_ENDPOINTS:
            endpoint_id = endpoint["output"]
            cls.current_endpoints[endpoint_id] = " ".join(
                str(value)
                for value in (
                    endpoint_id,
                    endpoint.get("id"),
                    endpoint.get("name"),
                    endpoint.get("path"),
                    "https://graph.microsoft.com/"
                    + endpoint.get("api", "v1.0")
                    + str(endpoint.get("path") or ""),
                    *(endpoint.get("aliases") or ()),
                )
            )
        cls.graph_endpoint_ids = {
            endpoint["output"] for endpoint in azure_collect.GRAPH_ENDPOINTS
        }

    @staticmethod
    def current_matches(references):
        matches = {
            endpoint_id
            for endpoint_id in references.get("required_endpoint_ids", [])
            if endpoint_id in FindingEndpointCoverageTests.current_endpoints
        }
        for pattern in references.get("required_endpoint_patterns", []):
            matches.update(
                endpoint_id
                for endpoint_id, searchable in FindingEndpointCoverageTests.current_endpoints.items()
                if all(
                    str(fragment).casefold() in searchable.casefold()
                    for fragment in pattern
                )
            )
        return matches

    def test_every_check_declares_a_current_endpoint_and_source_type(self):
        missing = []
        for finding in self.findings:
            references = finding.get("references") or {}
            if (
                not references.get("required_endpoint_ids")
                and not references.get("required_endpoint_patterns")
            ):
                missing.append((finding["title"], "no endpoint declaration"))
            if references.get("endpoint_source_type") not in {
                BASE,
                GRAPH,
                EITHER,
                BASE_AND_GRAPH,
            }:
                missing.append((finding["title"], "no source type"))
            if not self.current_matches(references):
                missing.append((finding["title"], "no current registry match"))

        self.assertEqual(missing, [])

    def test_every_declared_identifier_is_current_or_an_explicit_legacy_mapping(self):
        invalid = []
        for finding in self.findings:
            references = finding["references"]
            for endpoint_id in references.get("required_endpoint_ids", []):
                if (
                    endpoint_id not in self.current_endpoints
                    and endpoint_id not in self.LEGACY_ENDPOINT_IDS
                ):
                    invalid.append((finding["title"], "id", endpoint_id))
            for pattern in references.get("required_endpoint_patterns", []):
                pattern_matches = any(
                    all(
                        str(fragment).casefold() in searchable.casefold()
                        for fragment in pattern
                    )
                    for searchable in self.current_endpoints.values()
                )
                if not pattern_matches and tuple(pattern) not in self.LEGACY_ENDPOINT_PATTERNS:
                    invalid.append((finding["title"], "pattern", pattern))

        self.assertEqual(invalid, [])

    def test_source_type_agrees_with_current_registry_matches(self):
        inconsistent = []
        for finding in self.findings:
            references = finding["references"]
            matches = self.current_matches(references)
            planes = {
                GRAPH if endpoint_id in self.graph_endpoint_ids else BASE
                for endpoint_id in matches
            }
            expected = {
                frozenset({BASE}): BASE,
                frozenset({GRAPH}): GRAPH,
                frozenset({BASE, GRAPH}): BASE_AND_GRAPH,
            }.get(frozenset(planes))
            if references["endpoint_source_type"] != expected:
                inconsistent.append(
                    (
                        finding["title"],
                        references["endpoint_source_type"],
                        expected,
                    )
                )

        self.assertEqual(inconsistent, [])

    def test_reporting_copies_the_declared_source_type(self):
        mismatched = [
            finding["title"]
            for finding in self.findings
            if finding["reporting"]["provenance"]["endpoint_source_type"]
            != finding["references"]["endpoint_source_type"]
        ]

        self.assertEqual(mismatched, [])

    def test_reporting_retains_endpoint_declarations_when_no_run_exists(self):
        missing = []
        for finding in self.findings:
            references = finding["references"]
            provenance = finding["reporting"]["provenance"]
            if (
                provenance["declared_endpoint_ids"]
                != references["required_endpoint_ids"]
                or provenance["declared_endpoint_patterns"]
                != references["required_endpoint_patterns"]
            ):
                missing.append(finding["title"])

        self.assertEqual(missing, [])

    def test_current_check_source_type_distribution_is_explicit(self):
        source_types = Counter(
            finding["references"]["endpoint_source_type"]
            for finding in self.findings
        )

        self.assertEqual(
            source_types,
            Counter({BASE: 214, GRAPH: 17, BASE_AND_GRAPH: 3}),
        )

    def test_graph_and_cross_plane_examples_are_classified_correctly(self):
        by_title = {finding["title"]: finding for finding in self.findings}

        self.assertEqual(
            by_title["Microsoft Entra security defaults are not enabled"]
            ["references"]["endpoint_source_type"],
            GRAPH,
        )
        self.assertEqual(
            by_title["Users with VM access do not have MFA"]
            ["references"]["endpoint_source_type"],
            BASE_AND_GRAPH,
        )
        self.assertEqual(
            by_title["Application identity credentials are expired or require rotation"]
            ["references"]["endpoint_source_type"],
            GRAPH,
        )

    def test_every_registered_endpoint_has_exactly_one_assessment_role(self):
        current_ids = set(self.current_endpoints)

        self.assertFalse(
            MANUAL_ASSESSMENT_ENDPOINTS & SUPPORTING_ONLY_ENDPOINTS
        )
        self.assertEqual(
            MANUAL_ASSESSMENT_ENDPOINTS | SUPPORTING_ONLY_ENDPOINTS,
            {
                endpoint_id
                for endpoint_id in current_ids
                if endpoint_assessment_role(endpoint_id) != AUTOMATED
            },
        )
        self.assertTrue(MANUAL_ASSESSMENT_ENDPOINTS <= current_ids)
        self.assertTrue(SUPPORTING_ONLY_ENDPOINTS <= current_ids)
        self.assertEqual(
            {
                endpoint_assessment_role(endpoint_id)
                for endpoint_id in current_ids
            },
            {AUTOMATED, SUPPORTING, MANUAL},
        )

    def test_every_automated_endpoint_is_referenced_by_a_current_check(self):
        # The two fan-out/conditional checks need representative parents in
        # order to appear in evaluate_findings' endpoint declarations.
        catalog = {
            "graph_probe.json": {
                "data": [],
                "path": Path("graph_probe.json"),
            },
            "graph_endpoint_intune_settings_catalog.json": {
                "data": [{"id": "policy-one"}],
                "path": Path("graph_endpoint_intune_settings_catalog.json"),
            },
            "graph_endpoint_intune_settings_catalog_settings.json": {
                "data": [{"parentId": "policy-one"}],
                "path": Path(
                    "graph_endpoint_intune_settings_catalog_settings.json"
                ),
            },
            "az_functionapp_auth_show.json": {
                "data": [],
                "path": Path("az_functionapp_auth_show.json"),
            },
        }
        matched = set()
        for finding in azure_findings.evaluate_findings(catalog):
            matched.update(self.current_matches(finding["references"]))

        missing = {
            endpoint_id
            for endpoint_id in self.current_endpoints
            if endpoint_assessment_role(endpoint_id) == AUTOMATED
            and endpoint_id not in matched
        }

        self.assertEqual(missing, set())
