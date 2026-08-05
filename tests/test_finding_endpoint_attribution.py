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


ROOT = Path(__file__).resolve().parents[1]


def load_script(module_name, filename):
    spec = importlib.util.spec_from_file_location(module_name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


azure_collect = load_script("azure_collect_endpoint_audit", "azure-collect.py")
azure_findings = load_script("azure_findings_endpoint_audit", "azure-findings.py")


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
            Counter({BASE: 213, GRAPH: 17, BASE_AND_GRAPH: 3}),
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
