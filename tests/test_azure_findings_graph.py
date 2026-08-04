#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later

import unittest

from azure_assess.findings_graph import evaluate_graph_findings


def result(title, severity, reason, evidence):
    return {"title": title, "severity": severity, "status": "finding" if evidence else "not_found", "reason": reason, "evidence": evidence}


def unsupported(title, severity, reason):
    return {"title": title, "severity": severity, "status": "no_data_to_assess", "reason": reason, "evidence": []}


def graph_manifest(*outputs):
    return {"schema_version": "2.5", "endpoint_runs": [
        {"category": "microsoft_graph", "endpoint_id": output, "status": "success"}
        for output in outputs
    ]}


class GraphFindingTests(unittest.TestCase):
    def test_positive_risk_and_passing_inventory(self):
        catalog = {
            "graph_identity_baseline_risk_detections_20260804.json": [
                {"id": "active", "riskState": "atRisk"},
                {"id": "closed", "riskState": "remediated"},
            ],
            "graph_identity_baseline_recommendations_20260804.json": [],
            "azure-collection-manifest.json": graph_manifest("graph_identity_baseline_risk_detections", "graph_identity_baseline_recommendations"),
        }
        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        by_title = {item["title"]: item for item in findings}
        self.assertEqual("finding", by_title["Active Microsoft Entra risk detections"]["status"])
        self.assertEqual(1, len(by_title["Active Microsoft Entra risk detections"]["evidence"]))
        self.assertEqual("not_found", by_title["Unresolved Microsoft Entra recommendations"]["status"])

    def test_missing_input_is_never_treated_as_proven_absence(self):
        findings, _ = evaluate_graph_findings({}, result, unsupported)
        self.assertEqual([], findings)

    def test_intune_absence_requires_both_complete_inventories(self):
        incomplete, _ = evaluate_graph_findings(
            {"graph_endpoint_intune_managed_devices_20260804.json": [{"id": "d"}], "azure-collection-manifest.json": graph_manifest("graph_endpoint_intune_managed_devices")}, result, unsupported
        )
        complete, _ = evaluate_graph_findings(
            {
                "graph_endpoint_intune_managed_devices_20260804.json": [{"id": "d"}],
                "graph_endpoint_intune_compliance_policies_20260804.json": [],
                "azure-collection-manifest.json": graph_manifest("graph_endpoint_intune_managed_devices", "graph_endpoint_intune_compliance_policies"),
            }, result, unsupported
        )
        title = "Applicable Intune estate has no compliance policy"
        self.assertEqual("no_data_to_assess", next(item for item in incomplete if item["title"] == title)["status"])
        self.assertEqual("finding", next(item for item in complete if item["title"] == title)["status"])

    def test_positive_hunting_result_is_local_to_affected_query(self):
        catalog = {
            "graph_defender_hunting_hunting_identity_recon_20260804.json": [{"DeviceName": "one"}],
            "graph_defender_hunting_hunting_remote_logon_20260804.json": [],
        }
        findings, sources = evaluate_graph_findings(catalog, result, unsupported)
        hunting = [item for item in findings if item["title"] == "Defender hunting query: Identity reconnaissance"]
        self.assertEqual(1, len(hunting))
        self.assertEqual(["graph_defender_hunting_hunting_identity_recon_20260804.json"], sources[hunting[0]["title"]])

    def test_only_active_pim_alerts_are_findings(self):
        catalog = {
            "graph_p_i_m_pim_alerts_20260804.json": [
                {"id": "active", "isActive": True, "incidentCount": 1},
                {"id": "inactive", "isActive": False, "incidentCount": 0},
            ],
            "azure-collection-manifest.json": graph_manifest("graph_p_i_m_pim_alerts"),
        }

        findings, _ = evaluate_graph_findings(catalog, result, unsupported)
        finding = next(
            item for item in findings
            if item["title"] == "Active privileged identity management alerts"
        )
        self.assertEqual("finding", finding["status"])
        self.assertEqual(["active"], [item["id"] for item in finding["evidence"]])


if __name__ == "__main__":
    unittest.main()
