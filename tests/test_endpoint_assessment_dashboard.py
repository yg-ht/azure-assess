import importlib.util
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_script(module_name, filename):
    spec = importlib.util.spec_from_file_location(module_name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


azure_present = load_script(
    "azure_present_endpoint_assessment", "azure-present.py"
)


class EndpointAssessmentDashboardTests(unittest.TestCase):
    @staticmethod
    def summary(rows, manifest):
        finding_file = mock.Mock()
        finding_file.exists.return_value = True
        with (
            mock.patch.object(
                azure_present, "findings_flat_path", return_value=finding_file
            ),
            mock.patch.object(
                azure_present,
                "load_json_file",
                return_value={"rows": rows},
            ),
        ):
            return azure_present.findings_summary(manifest)

    def test_manual_item_terminates_at_awaiting_analyst_assessment(self):
        endpoint_id = "az_monitor_metrics_list-namespaces_--resource_id"
        rows = [{
            "status": "manual_assessment_required",
            "reporting": {"provenance": {
                "collection_run": {"run_id": "run-one"},
                "required_endpoints": [{
                    "endpoint_id": endpoint_id,
                    "category": "parameterised",
                }],
            }},
        }]
        manifest = {"run_id": "run-one", "endpoint_runs": [{
            "endpoint_id": endpoint_id,
            "category": "parameterised",
            "status": "success",
            "result_count": 3,
        }]}

        summary = self.summary(rows, manifest)

        paths = {path for path, _colour in summary["sankey_paths"]}
        self.assertEqual(paths, {(
            "Base Endpoints",
            "Returned Data",
            "Awaiting Analyst Assessment",
        )})
        self.assertEqual(summary["manual_assessment_required"], 1)
        self.assertTrue(all(len(path) == 3 for path in paths))

    def test_supporting_execution_is_not_a_manual_finding(self):
        manifest = {"endpoint_runs": [{
            "endpoint_id": "az_vm_list",
            "category": "base",
            "status": "success",
            "result_count": 20,
        }]}

        summary = self.summary([], manifest)

        paths = {path for path, _colour in summary["sankey_paths"]}
        self.assertEqual(paths, {(
            "Base Endpoints",
            "Returned Data",
            "Supporting Endpoint Execution — Not Assessed",
        )})
        self.assertEqual(summary["manual_assessment_required"], 0)

    def test_mismatched_manifest_is_withheld_from_finding_flow(self):
        rows = [{
            "status": "not_found",
            "reporting": {"provenance": {
                "collection_run": {"run_id": "finding-run"},
                "required_endpoints": [{
                    "endpoint_id": "endpoint-one",
                    "category": "base",
                }],
            }},
        }]
        finding_file = mock.Mock()
        finding_file.exists.return_value = True
        with (
            mock.patch.object(
                azure_present, "findings_flat_path", return_value=finding_file
            ),
            mock.patch.object(
                azure_present,
                "load_json_file",
                return_value={"rows": rows},
            ),
            mock.patch.object(
                azure_present, "collection_manifest_paths", return_value=[]
            ),
        ):
            summary = azure_present.findings_summary({
                "run_id": "latest-run",
                "endpoint_runs": [{
                    "endpoint_id": "endpoint-one",
                    "category": "base",
                    "status": "success",
                }],
            })

        self.assertEqual(
            summary["collection_alignment"]["status"], "manifest_missing"
        )
        self.assertNotIn(
            "Returned Data",
            {node for path, _colour in summary["sankey_paths"] for node in path},
        )

    def test_manual_status_is_available_in_findings_filter(self):
        option = azure_present.FINDING_STATUS_OPTIONS[
            "manual_assessment_required"
        ]

        self.assertEqual(option["label"], "Manual Assessment Required")
        self.assertEqual(
            azure_present.filter_findings_by_status(
                [
                    {"status": "manual_assessment_required"},
                    {"status": "found"},
                ],
                "manual_assessment_required",
            ),
            [{"status": "manual_assessment_required"}],
        )


if __name__ == "__main__":
    unittest.main()
