import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "azure_present_data_store_search",
    ROOT / "azure-present.py",
)
azure_present = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(azure_present)


class DataStoreSearchTests(unittest.TestCase):
    def test_empty_search_does_not_load_dataset_contents(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            (data_dir / "az_resource_list_20260806-120000.json").write_text(
                json.dumps([{"name": "not scanned"}]),
                encoding="utf-8",
            )

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                with mock.patch.object(azure_present, "load_json_file") as loader:
                    response = azure_present.app.test_client().get("/search")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Enter a term to search all retained versions", response.get_data(as_text=True))
        loader.assert_not_called()

    def test_dataset_groups_are_sorted_by_friendly_display_name(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            for filename in (
                "az_resource_list_20260806-120000.json",
                "graph_identity_baseline_applications_20260806-120000.json",
                "az_vm_list_20260806-120000.json",
            ):
                (data_dir / filename).write_text("[]", encoding="utf-8")

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                groups = azure_present.dataset_groups()

        names = [group["name"] for group in groups]
        self.assertEqual(names, sorted(names, key=str.casefold))
        self.assertEqual(names, ["Graph Applications", "Resources", "Virtual Machines"])

    def test_data_source_selector_uses_the_same_alphabetical_order(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            filenames = (
                "az_vm_list_20260806-120000.json",
                "az_resource_list_20260806-120000.json",
                "graph_identity_baseline_applications_20260806-120000.json",
            )
            for filename in filenames:
                (data_dir / filename).write_text("[]", encoding="utf-8")

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                response = azure_present.app.test_client().get(
                    f"/query/{filenames[0]}"
                )

        selector = response.get_data(as_text=True).split(
            '<select id="dataSourceSelect"',
            1,
        )[1].split("</select>", 1)[0]
        self.assertLess(selector.index("Graph Applications"), selector.index("Resources"))
        self.assertLess(selector.index("Resources"), selector.index("Virtual Machines"))

    def test_search_covers_nested_records_all_datasets_and_all_versions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            (data_dir / "az_resource_list_20260805-120000.json").write_text(
                json.dumps([{"name": "old", "settings": {"owner": "Needle"}}]),
                encoding="utf-8",
            )
            (data_dir / "az_resource_list_20260806-120000.json").write_text(
                json.dumps([{"name": "new", "tags": ["NEEDLE"]}]),
                encoding="utf-8",
            )
            graph_filename = (
                "graph_identity_baseline_applications_20260806-120000.json"
            )
            (data_dir / graph_filename).write_text(
                json.dumps([{"displayName": "needle application"}]),
                encoding="utf-8",
            )
            (data_dir / azure_present.FINDINGS_FLAT_FILENAME).write_text(
                json.dumps({"rows": [{"title": "needle finding"}]}),
                encoding="utf-8",
            )
            (data_dir / "azure-collection-manifest_20260806-120000.json").write_text(
                json.dumps({"limitations": ["needle manifest"]}),
                encoding="utf-8",
            )

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                response = azure_present.app.test_client().get(
                    "/search?query=needle"
                )

        body = response.get_data(as_text=True)
        normalized_body = " ".join(body.split())
        self.assertEqual(response.status_code, 200)
        self.assertIn("3 matching records across 3 dataset files", normalized_body)
        self.assertIn("Graph Applications", body)
        self.assertIn("Resources", body)
        self.assertIn("needle application", body)
        self.assertIn('class="small table-muted"', body)
        self.assertNotIn('class="small text-secondary"', body)
        self.assertNotIn("needle finding", body)
        self.assertNotIn("needle manifest", body)
        self.assertIn(
            f"/query/{graph_filename}?query=needle",
            body,
        )

    def test_search_paginates_without_losing_the_total_match_count(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            filename = "az_resource_list_20260806-120000.json"
            (data_dir / filename).write_text(
                json.dumps([{"name": f"matching-record-{index}"} for index in range(101)]),
                encoding="utf-8",
            )

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                response = azure_present.app.test_client().get(
                    "/search?query=matching-record&page=2"
                )

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("101 matching records", body)
        self.assertIn("Page 2 of 2", body)
        self.assertIn("matching-record-100", body)
        self.assertNotIn("matching-record-99", body)
        self.assertIn("Record 101", body)

    def test_search_reports_unreadable_data_and_escapes_record_content(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            (data_dir / "az_resource_list_20260806-120000.json").write_text(
                json.dumps([{"name": "</pre><script>alert('unsafe')</script>"}]),
                encoding="utf-8",
            )
            (data_dir / "az_vm_list_20260806-120000.json").write_text(
                "{not-json",
                encoding="utf-8",
            )

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                response = azure_present.app.test_client().get(
                    "/search?query=script&page=not-a-number"
                )

        body = response.get_data(as_text=True)
        normalized_body = " ".join(body.split())
        self.assertEqual(response.status_code, 200)
        self.assertIn("1 matching record across 1 dataset file", normalized_body)
        self.assertIn("1 dataset file was unreadable", normalized_body)
        self.assertNotIn("<script>alert", body)
        self.assertIn(r"\u003cscript\u003e", body)
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_page_beyond_the_end_is_clamped_to_the_final_page(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            (data_dir / "az_resource_list_20260806-120000.json").write_text(
                json.dumps([{"name": f"match-{index}"} for index in range(3)]),
                encoding="utf-8",
            )

            with mock.patch.object(azure_present, "DATA_DIR", data_dir):
                result = azure_present.search_all_datasets(
                    "match",
                    page=999,
                    page_size=2,
                )

        self.assertEqual(result["page"], 2)
        self.assertEqual(result["total_pages"], 2)
        self.assertEqual(
            [item["record"]["name"] for item in result["results"]],
            ["match-2"],
        )


if __name__ == "__main__":
    unittest.main()
