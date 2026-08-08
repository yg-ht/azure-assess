#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025 Felix, You Gotta Hack That
#
# This file is part of an AGPLv3-licensed project.
# You are free to use, modify, and distribute this file under the terms of
# the GNU Affero General Public License, version 3 or later.
# For details, see: https://www.gnu.org/licenses/agpl-3.0.html
# ---------------------------------------------------------------------------
# Filename:        azure-present.py
# Description:     Presents the JSON Azure configuration details from the Azure Collect script in an easy to examine format
# Author:          Felix of You Gotta Hack That
# Created:         2025-04-02
# Last Modified:   2025-04-07
# Version:         0.9.0
#
# Purpose:         This script is part of the YGHT audit toolkit for secure
#                  Azure visibility. Designed for extensible JSON enrichment.
#
# Usage:           pipenv run python azure-present.py [-i ./data_directory]
# Requirements:    Install the libraries from the requirements file (e.g. pipenv install -r requirements.txt)
#                  Python 3.8+ (tested with Python 3.11)
#                  az cli installed from Microsoft repository and accessible via the PATH, for example:
#
#                  curl -sL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
#                  sudo install -o root -g root -m 644 packages.microsoft.gpg /etc/apt/trusted.gpg.d/
#                  rm packages.microsoft.gpg
#                  sudo sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ $(lsb_release -cs) main" > /etc/apt/sources.list.d/azure-cli.list'
#                  sudo apt update
#                  sudo apt install azure-cli
#
# Notes:           See the README.md for configuration options and examples.
# ---------------------------------------------------------------------------

import argparse
import copy
import importlib.util
import json
import re
import secrets
import threading
from collections import Counter, OrderedDict, deque
from datetime import datetime, timezone
from flask import Flask, Response, jsonify, render_template_string, request
from html import escape
from json2html import json2html
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

from azure_assess.collection_manifest import (
    extract_azure_error_code,
    interpreted_visibility_status,
    is_not_applicable_error,
    is_tenant_unavailable_error,
)
from azure_assess.findings_review import (
    apply_review_override,
    load_review_overrides,
    save_review_overrides,
    validate_finding_review,
)
from azure_assess.graph_endpoints import GRAPH_ENDPOINTS
from azure_assess.endpoint_assessment import (
    CONTEXT,
    MANUAL,
    RETIRED_CATCH_ALL_MANUAL_ENDPOINTS,
    SUPPORTING,
    endpoint_assessment_role,
)

app = Flask(__name__)
DATA_DIR = Path("azure-collect")
FINDINGS_FLAT_FILENAME = "azure-findings-flat.json"
FINDINGS_SARIF_FILENAME = "azure-findings-SARIF.json"
FINDINGS_REVIEW_FILENAME = "azure-findings-review.json"
VALIDATED_FINDINGS_SARIF_FILENAME = "azure-findings-validated-SARIF.json"
LEGACY_FINDINGS_SARIF_FILENAME = "azure-findings.json"
COLLECTION_MANIFEST_PREFIX = "azure-collection-manifest"
GLOBAL_SEARCH_PAGE_SIZE = 100
FINDINGS_FILENAMES = {
    FINDINGS_FLAT_FILENAME,
    FINDINGS_SARIF_FILENAME,
    FINDINGS_REVIEW_FILENAME,
    VALIDATED_FINDINGS_SARIF_FILENAME,
    LEGACY_FINDINGS_SARIF_FILENAME,
}
GRAPH_ENDPOINTS_BY_OUTPUT = {
    endpoint["output"]: endpoint for endpoint in GRAPH_ENDPOINTS
}
GRAPH_ENDPOINTS_BY_ID = {
    endpoint["id"]: endpoint for endpoint in GRAPH_ENDPOINTS
}
GRAPH_PROFILE_LABELS = {
    "IdentityBaseline": "Identity Baseline",
    "PIM": "Privileged Identity Management",
    "M365Audit": "Microsoft 365 Audit",
    "EndpointIntune": "Microsoft Intune",
    "GlobalSecureAccess": "Global Secure Access",
    "DefenderHunting": "Microsoft Defender Hunting",
}
FINDING_STATUS_OPTIONS = OrderedDict(
    [
        ("found", {"label": "Found Items", "statuses": {"found"}}),
        ("not_found", {"label": "Not Found Items", "statuses": {"not_found"}}),
        ("no_data_to_assess", {"label": "No Data To Assess", "statuses": {"no_data_to_assess"}}),
        ("manual_assessment_required", {"label": "Manual Assessment Required", "statuses": {"manual_assessment_required"}}),
        ("not_implemented", {"label": "Not Implemented", "statuses": {"not_implemented"}}),
        ("all", {"label": "All Findings", "statuses": None}),
    ]
)
VALIDATABLE_FINDING_STATUSES = {"found", "manual_assessment_required"}

OMISSION_REASON_LABELS = {
    "upstream_source_failed": "Upstream source collection failed",
    "upstream_source_unauthorised": "Upstream source was unauthorised",
    "upstream_source_tenant_unavailable": "Upstream tenant licence or capability was unavailable",
    "upstream_source_not_attempted": "Upstream source was not attempted",
    "upstream_source_skipped": "Upstream source was skipped",
    "upstream_source_returned_no_data": "Upstream source returned no records",
    "upstream_source_not_applicable": "Upstream source was not applicable",
    "upstream_source_unavailable": "Upstream source was unavailable",
    "required_parameter_missing": "Required field was missing from source records",
    "no_applicable_source_records": "No source records applied to this endpoint",
    "no_usable_parameter_records": "No usable parameter records were available",
    "parameter_template_mismatch": "Collector parameter-template defect",
    "skip_reason_unclassified": "Skip reason was not classified",
    "collection_interrupted": "Collection was interrupted by the operator",
    "collection_terminated_by_exception": "Collection terminated with an exception",
    "collector_outcome_not_recorded": "Collector did not record an endpoint outcome",
    "legacy_missing_required_parameters": "Required parameters were unavailable",
    "legacy_no_usable_parameter_records": "No usable parameter records were available",
    "legacy_reason_unavailable": "Reason unavailable in legacy manifest",
}
INSUFFICIENT_DATA_CAUSES = OrderedDict(
    [
        ("unauthorised_source", ("Unauthorised Source", "#6f42c1")),
        ("tenant_capability_unavailable", ("Licence or Tenant Capability", "#795548")),
        ("failed_request", ("Failed Request", "#fd7e14")),
        ("collection_incomplete", ("Interrupted or Unrecorded Collection", "#d63384")),
        ("scope_restricted_source", ("Source Scope Restricted", "#8a6d3b")),
        ("source_visibility_unverified", ("Source Visibility Unverified", "#e0a800")),
        ("skipped_prerequisite", ("Skipped Prerequisite", "#ffc107")),
        ("empty_source", ("Empty Upstream Source", "#0dcaf0")),
        ("missing_or_unattributed_source", ("Missing or Unattributed Source", "#adb5bd")),
    ]
)
FINDING_CHART_OUTCOMES = OrderedDict(
    [
        ("findings_raised", ("Findings Raised", "#dc3545")),
        ("checks_passed", ("Checks Passed", "#198754")),
        ("manual_assessment_required", ("Manual Assessment Required", "#446df6")),
        ("missing_source", ("Missing Source", "#adb5bd")),
        ("empty_upstream_source", ("Empty Upstream Source", "#0dcaf0")),
        ("scope_restricted", ("Scope Restricted", "#8a6d3b")),
        ("unlicensed", ("Unlicensed", "#795548")),
        ("failed", ("Failed", "#fd7e14")),
        ("unauthorised", ("Unauthorised", "#6f42c1")),
        ("missing_prerequisite", ("Missing Prerequisite", "#ffc107")),
    ]
)
FINDING_RESULT_OPTIONS = {
    "Passed": "#198754",
    "Failed": "#dc3545",
    "Nothing to Assess": "#0dcaf0",
    "Could Not Assess": "#6f42c1",
}
INSUFFICIENT_DATA_CHART_OUTCOMES = {
    "unauthorised_source": "unauthorised",
    "tenant_capability_unavailable": "unlicensed",
    "failed_request": "failed",
    "collection_incomplete": "failed",
    "scope_restricted_source": "scope_restricted",
    "source_visibility_unverified": "missing_source",
    "skipped_prerequisite": "missing_prerequisite",
    "empty_source": "empty_upstream_source",
    "missing_or_unattributed_source": "missing_source",
}
COLLECTION_OUTCOME_OPTIONS = OrderedDict(
    [
        ("success", ("Returned Data", "#198754")),
        ("empty_access_verified", ("No Data — Access Verified", "#20c997")),
        ("empty_scope_restricted", ("No Data — Scope Restricted", "#8a6d3b")),
        ("empty_visibility_unverified", ("No Data — Visibility Unverified", "#e0a800")),
        ("incomplete", ("Incomplete", "#d63384")),
        ("failed", ("Failed", "#fd7e14")),
        ("unauthorised", ("Unauthorised", "#6f42c1")),
        ("tenant_unavailable", ("Licence or Tenant Capability", "#795548")),
        ("not_applicable", ("Not Applicable", "#0dcaf0")),
        ("skipped", ("Skipped Prerequisite", "#ffc107")),
        ("not_attempted", ("No Recorded Outcome", "#adb5bd")),
        ("unknown", ("Unknown Outcome", "#6c757d")),
    ]
)

FINDINGS_PRIMARY_COLUMNS = (
    "title",
    "severity",
    "status",
    "reason",
    "count",
    "evidence",
    "viewer_links",
    "affected_entities",
)
FINDINGS_LINK_COLUMNS = ("viewer_links", "azure_portal_links")
FINDINGS_METADATA_COLUMNS = (
    "definition",
    "reporting",
    "context",
    "coverage",
    "review",
    "triage",
)
VIEW_JSON_SOURCE_ROW_KEY = "__azure_assess_view_json_source__"
AFFECTED_ENTITIES_DISPLAY_LIMIT = 8
COLUMN_HEADING_ACRONYMS = {
    "api": "API",
    "id": "ID",
    "ip": "IP",
    "json": "JSON",
    "mfa": "MFA",
    "nsg": "NSG",
    "sql": "SQL",
    "tls": "TLS",
    "url": "URL",
    "vm": "VM",
}
FINDINGS_HEADER_TOOLTIPS = {
    "definition": "What the check is and why it exists.",
    "reporting": "Affected assets, observations and provenance.",
    "context": "Relevant Azure service, subscription and engagement scope.",
    "coverage": "How much of the eligible environment was actually assessed.",
    "review": "Analyst decision, confidence, rationale and report inclusion.",
    "triage": "Contextual severity, grouping, deduplication and retest status.",
}
FINDINGS_REVIEW_CSRF_TOKEN = secrets.token_urlsafe(32)
FINDINGS_REVIEW_LOCK = threading.Lock()
MAX_FINDING_ID_LENGTH = 500

TIMESTAMP_SUFFIX_PATTERN = re.compile(r"_(\d{8}-\d{6})$")


def parse_arguments():
    parser = argparse.ArgumentParser(description="Azure Audit Data Presentation Tool")
    parser.add_argument(
        "-i", "--input-dir",
        type=str,
        default="azure-collect",
        help="Directory where input JSON files will be saved (default: 'azure-collect')"
    )
    return parser.parse_args()

# HTML Template with conditional sections for Dashboard and Data Table view.
HTML_TEMPLATE = """
<!doctype html>
<html lang="en" data-bs-theme="dark">
  <head>
    <meta charset="utf-8">
    <script>document.documentElement.classList.add('js-enabled');</script>
    <title>Azure Audit Data Viewer</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <style>
      html, body {
        height: 100%;
        margin: 0;
      }
      /* Define default light theme variables */
      :root {
        --bg-color: #ffffff;
        --text-color: #212529;
        --table-bg: #ffffff;
        --table-border: #dee2e6;
        --row-even-bg: #f8f8f8;
        --row-odd-bg: #ffffff;
        --dashboard-muted-text: #5c636a;
        --dashboard-card-border: #6c757d;
        --link-color: #0a58ca;
        --global-collapse-color: #765600;
        --local-collapse-color: #087990;
      }
      /* Dark theme overrides when .dark-mode is applied */
      .dark-mode {
        --bg-color: #121212;
        --text-color: #e0e0e0;
        --table-bg: #1e1e1e;
        --table-border: #444444;
        --row-even-bg: #1e1e1e;
        --row-odd-bg: #121212;
        --dashboard-muted-text: #b8c0c8;
        --dashboard-card-border: #69737d;
        --link-color: #6ea8fe;
        --global-collapse-color: #ffda6a;
        --local-collapse-color: #6edff6;
      }
      /* Apply theme variables */
      body {
        background-color: var(--bg-color);
        color: var(--text-color);
      }
      /* Use a fluid container that fills the viewport height */
      .container-fluid {
        height: 100vh;
        padding-left: 8px;
        padding-right: 8px;
        display: flex;
        flex-direction: column;
      }
      /* Header styling */
      .header {
        flex: 0 0 auto;
      }
      /* Table styling */
      table {
        width: 100%;
        border-collapse: collapse;
        background-color: var(--table-bg);
      }
      .table-container table {
        font-size: var(--table-font-size, 0.8rem);
      }
      table th, table td {
        border: 1px solid var(--table-border);
        padding: 8px;
        color: var(--text-color);
      }
      table tr:nth-child(even) {
        background-color: var(--row-even-bg);
      }
      table tr:nth-child(odd) {
        background-color: var(--row-odd-bg);
      }
      /* Freeze header row */
      table thead th {
        position: sticky;
        top: 0;
        background: var(--table-bg);
        z-index: 1;
      }
      table thead th.table-sortable {
        cursor: pointer;
        user-select: none;
        white-space: nowrap;
      }
      table thead th.table-sortable::after {
        content: " ↕";
        opacity: 0.55;
      }
      table thead th.table-sortable[aria-sort="ascending"]::after {
        content: " ↑";
        opacity: 1;
      }
      table thead th.table-sortable[aria-sort="descending"]::after {
        content: " ↓";
        opacity: 1;
      }
      table thead th.table-sortable:focus-visible {
        outline: 2px solid var(--link-color);
        outline-offset: -2px;
      }
      /* Nested sub-tables: hide them and add margin-top */
      table table {
        display: none;
        margin-top: 25px;
      }
      /* Override for unordered lists in nested tables */
      table table ul,
      table table li {
        list-style-type: none;
        margin: 0;
        padding: 0;
      }
      /* Styling for collapse icons */
      .toggle-row {
        cursor: pointer;
      }
      .collapse-icon {
        font-size: 1em;
        vertical-align: middle;
        margin-right: 8px;
      }
      .global-collapse-icon,
      .local-collapse-icon {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 1.5rem;
        font-weight: 700;
      }
      .global-collapse-icon {
        color: var(--global-collapse-color);
      }
      .local-collapse-icon {
        color: var(--local-collapse-color);
      }
      /* Keep large findings link lists compact until the user needs them. */
      .findings-links-disclosure summary {
        cursor: pointer;
        font-weight: 600;
      }
      .findings-links-disclosure[open] summary {
        margin-bottom: 8px;
      }
      /* Scrollable container for the table with fixed height */
      .table-container {
        position: relative;
        overflow-y: auto;
        width: 100%;
        /* Set height to fill remaining space. Adjust 250px as needed */
        height: calc(100vh - 360px);
      }
      .data-table-loading {
        display: none;
        min-height: 12rem;
        align-items: center;
        justify-content: center;
        text-align: center;
      }
      .data-table-loading-panel {
        width: min(32rem, 90%);
      }
      .js-enabled .data-table-loading {
        display: flex;
      }
      .js-enabled .data-table-loading[hidden] {
        display: none;
      }
      .js-enabled .table-content-pending {
        display: none;
      }
      .table-loading-progress {
        height: 0.75rem;
      }
      .table-font-controls {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
      }
      .affected-entities-toggle {
        display: block;
        margin-top: 0.35rem;
        padding: 0;
      }
      /* Data view container takes remaining height */
      .data-view {
        flex: 1 1 auto;
        display: flex;
        flex-direction: column;
      }
      /* Ensure the search form and drop-down take only needed space */
      .data-controls {
        flex: 0 0 auto;
      }
      .data-filter-form {
        margin-top: 1rem;
      }
      .data-filter-controls-row,
      .data-filter-actions-row,
      .data-inline-control {
        display: flex;
        align-items: center;
      }
      .data-filter-controls-row {
        gap: 1rem;
        flex-wrap: wrap;
      }
      .data-inline-control {
        gap: 0.5rem;
      }
      .data-inline-control label {
        margin: 0;
        white-space: nowrap;
      }
      .findings-status-control {
        flex: 0 1 24rem;
      }
      .findings-status-control select {
        min-width: 12rem;
      }
      .filter-data-control {
        flex: 1 1 30rem;
      }
      .filter-data-control input {
        min-width: 12rem;
      }
      .data-filter-actions-row {
        gap: 0.5rem;
        flex-wrap: wrap;
        margin-top: 0.75rem;
      }
      .data-filter-actions-row .table-font-controls {
        margin-left: 0.5rem;
      }
      .findings-reviewer-control {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        margin-left: 0.5rem;
      }
      .findings-reviewer-control label {
        margin: 0;
        white-space: nowrap;
      }
      .findings-reviewer-control input {
        min-width: 12rem;
      }
      .finding-validation-control {
        display: inline-flex;
        align-items: center;
        gap: 0.35rem;
        margin-left: 0.5rem;
        white-space: nowrap;
      }
      .finding-validation-status {
        min-width: 3rem;
        color: var(--dashboard-muted-text);
      }
      @media (max-width: 700px) {
        .data-inline-control {
          flex: 1 1 100%;
        }
        .data-inline-control input,
        .data-inline-control select {
          flex: 1 1 auto;
          min-width: 0;
        }
        .data-filter-actions-row .table-font-controls {
          margin-left: 0;
        }
      }
      .dashboard-chart-card {
        background-color: transparent;
        border: 1px solid var(--dashboard-card-border);
        color: var(--text-color);
      }
      .dashboard-summary-card {
        border-color: var(--dashboard-card-border) !important;
        color: var(--text-color);
      }
      @media (min-width: 1200px) {
        .dashboard-five-column {
          flex: 0 0 auto;
          width: 20%;
        }
        .dashboard-six-column {
          flex: 0 0 auto;
          width: 16.66666667%;
        }
      }
      .dashboard-muted {
        color: var(--dashboard-muted-text);
      }
      .table-muted {
        color: var(--dashboard-muted-text);
      }
      table a:not(.btn) {
        color: var(--link-color);
      }
      table code {
        color: var(--text-color);
      }
      .dashboard-chart-wrap {
        position: relative;
        width: 100%;
        min-height: 320px;
      }
      .dashboard-chart-canvas {
        width: 100%;
        height: 320px;
      }
      .dashboard-sankey-wrap {
        min-height: 420px;
        overflow-x: auto;
      }
      .dashboard-sankey-canvas {
        height: 420px;
      }
      .chart-legend {
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        margin-top: 16px;
      }
      .chart-legend-item {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        color: var(--text-color);
      }
      .chart-legend-swatch {
        width: 12px;
        height: 12px;
        border-radius: 50%;
        display: inline-block;
      }
      .dashboard-error-message {
        margin: 0;
        max-width: 48rem;
        white-space: pre-wrap;
        overflow-wrap: anywhere;
        color: var(--text-color);
      }
      .dashboard-request-details summary {
        cursor: pointer;
      }
      .dashboard-request-details summary .h5 {
        display: inline;
      }
      .table {
        --bs-table-color: var(--text-color);
        --bs-table-bg: var(--table-bg);
        --bs-table-border-color: var(--table-border);
        --bs-table-striped-color: var(--text-color);
        --bs-table-striped-bg: var(--row-even-bg);
        --bs-table-active-color: var(--text-color);
        --bs-table-hover-color: var(--text-color);
        color: var(--text-color);
      }
      .dashboard-request-table th,
      .dashboard-request-table td,
      .dashboard-request-table code {
        color: var(--text-color);
      }
      .dashboard-column-heading {
        display: flex;
        align-items: center;
        gap: 0.25rem;
        white-space: nowrap;
      }
      .dashboard-sort-button {
        border: 0;
        padding: 0;
        cursor: pointer;
        color: inherit;
        background: transparent;
        font: inherit;
        font-weight: 600;
      }
      .dashboard-sort-button::after {
        content: " ↕";
        opacity: 0.55;
      }
      th[aria-sort="ascending"] .dashboard-sort-button::after {
        content: " ↑";
        opacity: 1;
      }
      th[aria-sort="descending"] .dashboard-sort-button::after {
        content: " ↓";
        opacity: 1;
      }
      .dashboard-column-filter {
        box-sizing: border-box;
        width: 100%;
        min-width: 7rem;
        margin-top: 0.35rem;
        border: 1px solid var(--table-border);
        border-radius: 0.25rem;
        padding: 0.2rem 0.35rem;
        color: var(--text-color);
        background: var(--table-bg);
        font-size: 0.75rem;
      }
      .dashboard-column-filter::placeholder {
        color: var(--dashboard-muted-text);
        opacity: 1;
      }
    </style>
  </head>
  <!-- Dark mode enabled by default via the dark-mode class -->
  <body class="dark-mode">
    <div class="container-fluid">
      <!-- Header with Dark Mode Toggle -->
      <div class="header d-flex justify-content-between align-items-center mt-4">
        <h1>Azure Audit Data Viewer</h1>
        <div>
          <button id="returnToDashboard" class="btn btn-secondary">Dashboard</button>
          <button id="findingsView" class="btn btn-secondary">Findings</button>
          <button id="dataViewerIndex" class="btn btn-secondary">Data Viewer</button>
          <button id="manifestView" class="btn btn-secondary">Manifest</button>
        </div>
        <button id="darkModeToggle" class="btn btn-secondary">Toggle Dark Mode</button>
      </div>
      
      {% if dashboard %}
      <!-- DASHBOARD PAGE -->
      <div class="mt-4 dashboard-page">
        <h2>Dashboard</h2>
        {% macro dashboard_card_grid(cards, column_class="col-12 col-md-6 col-xl-3") %}
        <div class="row g-3 mb-4">
          {% for card in cards %}
          <div class="{{ column_class }}">
            <div class="card h-100 bg-transparent dashboard-summary-card">
              <div class="card-body">
                <h3 class="h6 text-uppercase dashboard-muted">{{ card.label }}</h3>
                <div class="fs-3 fw-bold"
                     {% if card.count_filenames %}
                     data-summary-count-filenames="{{ card.count_filenames|join(',') }}"
                     {% endif %}>{{ card.value }}</div>
                {% if card.detail %}
                <div class="small dashboard-muted">{{ card.detail }}</div>
                {% endif %}
              </div>
            </div>
          </div>
          {% endfor %}
        </div>
        {% endmacro %}

        {% macro endpoint_results_panel(title, table_id, rows, description) %}
        <div class="card dashboard-chart-card mt-4">
          <div class="card-body">
            <details class="dashboard-request-details">
              <summary><span class="h5">{{ title }}</span></summary>
              <p class="dashboard-muted my-3">{{ description }}</p>
              <div class="table-responsive">
                <table id="{{ table_id }}" class="table table-striped align-middle dashboard-request-table dashboard-filterable-table">
                  <thead>
                    <tr>
                      {% for heading in ["Endpoint", "Collection Category", "Workload", "API Channel", "Outcome", "Records", "Collected Data", "Service Error Code", "CLI Return Code", "Parameters", "Recorded Detail"] %}
                      <th aria-sort="none">
                        <div class="dashboard-column-heading">
                          <button type="button" class="dashboard-sort-button" data-column-index="{{ loop.index0 }}" aria-label="Sort by {{ heading }}">{{ heading }}</button>
                        </div>
                        {% if loop.index0 < 9 %}
                        <select class="dashboard-column-filter" data-column-index="{{ loop.index0 }}" data-filter-mode="exact" aria-label="Filter {{ heading }}">
                          <option value="">All</option>
                        </select>
                        {% else %}
                        <input class="dashboard-column-filter" data-column-index="{{ loop.index0 }}" data-filter-mode="contains" type="search" aria-label="Filter {{ heading }}" placeholder="Filter">
                        {% endif %}
                      </th>
                      {% endfor %}
                    </tr>
                  </thead>
                  <tbody>
                    {% if rows %}
                    {% for endpoint in rows %}
                    <tr>
                      <td>{{ endpoint.endpoint_name }}</td>
                      <td>{{ endpoint.category }}</td>
                      <td>{{ endpoint.workload }}</td>
                      <td>{{ endpoint.api_channel }}</td>
                      <td>{{ endpoint.outcome_label }}</td>
                      <td>{{ endpoint.record_count if endpoint.record_count is not none else "Unavailable" }}</td>
                      <td>
                        {% if endpoint.output_files %}
                          {% for output in endpoint.output_files %}
                          <a href="/query/{{ output.filename }}">{{ output.name }}</a>{% if not loop.last %}<br>{% endif %}
                          {% endfor %}
                        {% else %}
                          No dataset file
                        {% endif %}
                      </td>
                      <td>{{ endpoint.error_code or "Unavailable" }}</td>
                      <td>{{ endpoint.returncode if endpoint.returncode is not none else "Unavailable" }}</td>
                      <td><code>{{ endpoint.parameter_context|tojson }}</code></td>
                      <td>
                        <pre class="dashboard-error-message">{{ endpoint.message or "No error or limitation recorded" }}</pre>
                        {% if endpoint.message_truncated %}
                        <span class="small dashboard-muted">Stored message was truncated by the collection manifest.</span>
                        {% endif %}
                      </td>
                    </tr>
                    {% endfor %}
                    {% else %}
                    <tr><td colspan="11">No matching endpoint executions were recorded.</td></tr>
                    {% endif %}
                  </tbody>
                </table>
              </div>
            </details>
          </div>
        </div>
        {% endmacro %}

        {% if summary_cards.collection %}
        <section class="dashboard-section" aria-labelledby="collectionSnapshotHeading">
          <h3 id="collectionSnapshotHeading" class="h4">Collection Snapshot</h3>
          <p class="dashboard-muted">Inventory and dataset storage information. These measures describe different aspects of the collection and are not expected to add together.</p>
          {{ dashboard_card_grid(summary_cards.collection) }}
        </section>
        {% endif %}

        {% if summary_cards.findings %}
        <section class="dashboard-section" aria-labelledby="findingOutcomesHeading">
          <h3 id="findingOutcomesHeading" class="h4">Finding Outcomes</h3>
          <p class="dashboard-muted">One mutually exclusive outcome for every automated check or manual assessment item.</p>
          {% if findings.collection_alignment.warning %}
          <div class="alert alert-warning" role="alert">{{ findings.collection_alignment.warning }}</div>
          {% endif %}
          {{ dashboard_card_grid(summary_cards.findings, "col-12 col-md-6 dashboard-six-column") }}
        {% if findings_chart_data %}
        <div class="row g-3 mt-1">
          <div class="col-12 col-xl-4">
            <div class="card dashboard-chart-card h-100">
              <div class="card-body">
                <h4 class="h5">Finding Outcome Distribution</h4>
                <p class="dashboard-muted mb-3">Every check is counted once in a consolidated outcome, covering Azure and Microsoft Graph sources.</p>
                <div class="dashboard-chart-wrap">
                  <canvas id="findingsPieChart" class="dashboard-chart-canvas" role="img" aria-label="Pie chart of consolidated finding outcomes across all endpoint types"></canvas>
                </div>
                <div id="findingsPieLegend" class="chart-legend"></div>
              </div>
            </div>
          </div>
          <div class="col-12 col-xl-8">
            <div class="card dashboard-chart-card h-100">
              <div class="card-body">
                <h4 class="h5">Endpoint-to-Finding Flow</h4>
                <p class="dashboard-muted mb-3">Flow widths represent {{ findings.sankey_relationship_count }} endpoint-to-check dependency relationships. Node labels retain distinct execution and check counts; unmatched endpoints and unattributed checks remain visible. In the final stage, Failed means a check raised a finding. Nothing to Assess is limited to complete, access-verified empty evidence; every other inconclusive check is Could Not Assess.</p>
                <div class="dashboard-chart-wrap dashboard-sankey-wrap">
                  <canvas id="findingsSankeyChart" class="dashboard-chart-canvas dashboard-sankey-canvas" role="img" aria-label="Relationship-weighted Sankey chart from endpoint type and status through finding checks to finding results"></canvas>
                </div>
              </div>
            </div>
          </div>
        </div>
        {% endif %}
        </section>
        {% endif %}

        {% if graph_collection %}
        <section class="dashboard-section mt-4" aria-labelledby="graphCollectionHeading">
          <h3 id="graphCollectionHeading" class="h4">Microsoft Graph Collection</h3>
          <p class="dashboard-muted">{{ graph_collection.message }}</p>
          {{ dashboard_card_grid([
            {"label": "Graph Endpoints Selected", "value": graph_collection.selected_endpoints, "detail": "Logical Microsoft Graph endpoint executions recorded"},
            {"label": "Graph Endpoints With Data", "value": graph_collection.endpoints_with_data, "detail": "Endpoints that returned one or more records"},
            {"label": "Graph Records Written", "value": graph_collection.records_written, "detail": "Records retained in Graph dataset files"},
            {"label": "Graph Collection Outcome", "value": graph_collection.outcome, "detail": graph_collection.dataset_files|string + " Graph dataset files written"}
          ]) }}
          {% if graph_collection.status_counts %}<p class="dashboard-muted">
            Outcomes:
            {% for status, count in graph_collection.status_counts.items() %}
            <span class="badge text-bg-secondary me-1">{{ status }}: {{ count }}</span>
            {% endfor %}
          </p>{% endif %}
        </section>
        {% endif %}

        {% if summary_cards.requests %}
        <section class="dashboard-section mt-4" aria-labelledby="requestHealthHeading">
          <h3 id="requestHealthHeading" class="h4">Collection Request Health</h3>
          <p class="dashboard-muted">Collection activity is separated into attempted requests, deliberately skipped endpoint definitions and endpoint definitions with no recorded outcome. These populations use a different denominator from assessment checks.</p>
        {% if collection_requests.category_outcome_rows %}
        <div class="card dashboard-chart-card mt-4">
          <div class="card-body">
            <h4 class="h5">Endpoint Outcomes by Collection Type</h4>
            <p class="dashboard-muted mb-3">This breakdown shows {{ collection_requests.endpoint_count }} endpoint executions ({{ findings.executed if findings else 0 }} Finding checks) in the charts above.</p>
            <div class="table-responsive">
              <table id="endpointOutcomeTypeTable" class="table table-striped align-middle dashboard-request-table">
                <thead><tr><th>Collection Type</th><th>Total</th><th>Outcomes</th></tr></thead>
                <tbody>
                  {% for row in collection_requests.category_outcome_rows %}
                  <tr>
                    <td>{{ row.category }}</td>
                    <td>{{ row.total }}</td>
                    <td>
                      {% for outcome in row.outcomes %}
                      <span class="badge text-bg-secondary me-1">{{ outcome.label }}: {{ outcome.count }}</span>
                      {% endfor %}
                    </td>
                  </tr>
                  {% endfor %}
                </tbody>
              </table>
            </div>
          </div>
        </div>
        {% endif %}
          <h4 class="h5 mt-4">Request Attempt Outcomes — Base and Microsoft Graph</h4>
          <p class="dashboard-muted">These figures combine Azure base, Azure parameterised and Microsoft Graph requests. Each attempted request has one mutually exclusive outcome, and the cards below add up to Total Attempts.</p>
          {{ dashboard_card_grid(summary_cards.requests.attempts, "col-12 col-md-6 dashboard-five-column") }}
          <h4 class="h5 mt-4">Skipped Endpoint Definitions — Base and Microsoft Graph</h4>
          <p class="dashboard-muted">These figures combine Azure base, Azure parameterised and Microsoft Graph endpoint definitions that were deliberately not attempted. Each has one primary prerequisite or recorded skip cause, and the cause cards below add up to Total Skipped.</p>
          {{ dashboard_card_grid(summary_cards.requests.skipped, "col-12 col-md-6 dashboard-five-column") }}
          <h4 class="h5 mt-4">Unrecorded Endpoint Definitions — Base and Microsoft Graph</h4>
          <p class="dashboard-muted">These figures combine Azure base, Azure parameterised and Microsoft Graph endpoint definitions with neither a request outcome nor a deliberate skip outcome. They are an accounting gap and are not included in Total Skipped.</p>
          {{ dashboard_card_grid(summary_cards.requests.unrecorded) }}
        {% if collection_requests and collection_requests.omission_groups %}
        <div class="card dashboard-chart-card mt-4">
          <div class="card-body">
            <details class="dashboard-request-details">
            <summary><span class="h5">Endpoint Omission Reasons</span></summary>
            <p class="dashboard-muted my-3">Selected endpoint definitions are grouped by the recorded reason they were deliberately skipped or reached finalisation without an outcome.</p>
            <div class="table-responsive">
              <table id="endpointOmissionsTable" class="table table-striped align-middle dashboard-request-table dashboard-filterable-table">
                <thead>
                  <tr>
                    {% for heading in ["Status", "Reason", "Count", "Endpoints", "Recorded Details"] %}
                    <th aria-sort="none">
                      <div class="dashboard-column-heading">
                        <button type="button" class="dashboard-sort-button" data-column-index="{{ loop.index0 }}" aria-label="Sort by {{ heading }}">{{ heading }}</button>
                      </div>
                      {% if loop.index0 < 3 %}
                      <select class="dashboard-column-filter" data-column-index="{{ loop.index0 }}" data-filter-mode="exact" aria-label="Filter {{ heading }}">
                        <option value="">All</option>
                      </select>
                      {% else %}
                      <input class="dashboard-column-filter" data-column-index="{{ loop.index0 }}" data-filter-mode="contains" type="search" aria-label="Filter {{ heading }}" placeholder="Filter">
                      {% endif %}
                    </th>
                    {% endfor %}
                  </tr>
                </thead>
                <tbody>
                  {% for omission in collection_requests.omission_groups %}
                  <tr>
                    <td>{{ omission.status }}</td>
                    <td>{{ omission.reason_label }}</td>
                    <td>{{ omission.count }}</td>
                    <td>
                      <details>
                        <summary>{{ omission.endpoints|length }} endpoints</summary>
                        <ul>
                          {% for endpoint in omission.endpoints %}<li>{{ endpoint }}</li>{% endfor %}
                        </ul>
                      </details>
                    </td>
                    <td>
                      <details>
                        <summary>{{ omission.details|length }} recorded details</summary>
                        <ul>
                          {% for detail in omission.details %}<li><code>{{ detail }}</code></li>{% endfor %}
                        </ul>
                      </details>
                    </td>
                  </tr>
                  {% endfor %}
                </tbody>
              </table>
            </div>
            </details>
          </div>
        </div>
        {% endif %}
        {{ endpoint_results_panel(
          "Base Endpoint Results — Azure Base and Parameterised",
          "baseEndpointResultsTable",
          collection_requests.base_endpoint_results,
          "All recorded Azure base and parameterised endpoint outcomes are shown, including successful, empty, skipped, not-applicable, failed and unrecorded executions."
        ) }}
        {{ endpoint_results_panel(
          "Microsoft Graph Endpoint Results",
          "graphEndpointResultsTable",
          collection_requests.graph_endpoint_results,
          "All recorded Microsoft Graph endpoint outcomes are shown. Returned data confirms collection; empty responses and every incomplete, unavailable or unauthorised result remain explicit."
        ) }}
        {{ endpoint_results_panel(
          "Unsuccessful Collection Requests — Base and Microsoft Graph",
          "failedCollectionRequestsTable",
          collection_requests.failures,
          "This combines Azure base, Azure parameterised and Microsoft Graph executions. One row is shown for each failed, incomplete, unauthorised or tenant-restricted request; successful, empty and not-applicable outcomes are excluded."
        ) }}
        {{ endpoint_results_panel(
          "Successful Collection Requests — Base and Microsoft Graph",
          "successfulCollectionRequestsTable",
          collection_requests.successes,
          "This combines Azure base, Azure parameterised and Microsoft Graph executions that completed successfully, including requests that returned an empty result. Scope and visibility qualifications remain explicit in the Outcome column; not-applicable requests are excluded."
        ) }}
        </section>
        {% endif %}
      </div>

      {% elif manifest_page %}
      <!-- COLLECTION MANIFEST PAGE -->
      <div class="mt-4">
        <div class="d-flex flex-wrap justify-content-between align-items-start gap-3">
          <div>
            <h2>Collection Manifest</h2>
            <p class="dashboard-muted">The manifest is the authoritative record of collection scope, request outcomes, retained datasets and limitations.</p>
          </div>
          <div>
            <label for="manifestVersionSelect" class="form-label">Manifest version</label>
            <select id="manifestVersionSelect" class="form-select manifest-version-select">
              {% for version in manifest_versions %}
              <option value="/manifest?filename={{ version.filename }}" {% if version.filename == manifest_filename %}selected{% endif %}>{{ version.label }}</option>
              {% endfor %}
            </select>
          </div>
        </div>

        <div class="alert alert-warning" role="alert">
          Collection manifests can contain tenant identifiers, parameter values and returned error evidence. Protect this local view and retained file as assessment evidence.
        </div>

        <div class="row g-3 mb-4">
          {% for label, value, detail in [
            ("Run Status", manifest.get("status") or "Unknown", "Overall collection outcome"),
            ("Run ID", manifest.get("run_id") or "Unavailable", "Stable collection execution identifier"),
            ("Started", manifest.get("started_at") or "Unavailable", "Recorded UTC start"),
            ("Completed", manifest.get("completed_at") or "Unavailable", "Recorded UTC completion")
          ] %}
          <div class="col-12 col-md-6 col-xl-3">
            <div class="card h-100 bg-transparent dashboard-summary-card">
              <div class="card-body">
                <h3 class="h6 text-uppercase dashboard-muted">{{ label }}</h3>
                <div class="fs-5 fw-bold text-break">{{ value }}</div>
                <div class="small dashboard-muted">{{ detail }}</div>
              </div>
            </div>
          </div>
          {% endfor %}
        </div>

        <div class="d-flex gap-2 mb-4">
          <a class="btn btn-primary" href="/manifest/raw?filename={{ manifest_filename }}" target="_blank" rel="noopener">View Raw Manifest JSON</a>
        </div>

        <section class="dashboard-section mt-4">
          <h3 class="h4">Run Context and Options</h3>
          <div class="row g-3">
            <div class="col-12 col-xl-6"><pre class="dashboard-error-message">{{ manifest.get("context", {})|tojson(indent=2) }}</pre></div>
            <div class="col-12 col-xl-6"><pre class="dashboard-error-message">{{ manifest.get("options", {})|tojson(indent=2) }}</pre></div>
          </div>
        </section>

        <section class="dashboard-section mt-4">
          <h3 class="h4">Access Verification</h3>
          <pre class="dashboard-error-message">{{ manifest.get("access_verification", {})|tojson(indent=2) }}</pre>
        </section>

        <section class="dashboard-section mt-4">
          <h3 class="h4">Endpoint Outcomes</h3>
          <div class="table-responsive">
            <table class="table table-striped align-middle dashboard-request-table">
              <thead><tr><th>Endpoint</th><th>Category</th><th>Status</th><th>Records</th><th>Output</th><th>Recorded Detail</th></tr></thead>
              <tbody>
                {% for endpoint in manifest_endpoint_rows %}
                <tr>
                  <td>{{ endpoint.endpoint_name or "Unknown" }}</td>
                  <td>{{ endpoint.category_label }}</td>
                  <td>{{ endpoint.status or "unknown" }}</td>
                  <td>{{ endpoint.result_count if endpoint.result_count is not none else "Unavailable" }}</td>
                  <td>
                    {% for filename in endpoint.get("output_files", []) %}
                      {% if filename in manifest_dataset_links %}<a href="/query/{{ filename }}">{{ manifest_dataset_links[filename] }}</a>{% else %}{{ filename }}{% endif %}{% if not loop.last %}<br>{% endif %}
                    {% else %}No dataset file{% endfor %}
                  </td>
                  <td><pre class="dashboard-error-message">{{ endpoint.response_error or endpoint.error or "No error or limitation recorded" }}</pre></td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
        </section>

        <section class="dashboard-section mt-4">
          <h3 class="h4">Retained Datasets</h3>
          <div class="table-responsive">
            <table class="table table-striped align-middle">
              <thead><tr><th>Data Source</th><th>Collection Source</th><th>Records</th><th>Size</th><th>SHA-256</th><th>Action</th></tr></thead>
              <tbody>
                {% for dataset in manifest_datasets %}
                <tr>
                  <td>{{ dataset.name }}</td>
                  <td>{{ dataset.source }}</td>
                  <td>{{ dataset.record_count }}</td>
                  <td>{{ dataset.size_bytes }} bytes</td>
                  <td><code>{{ dataset.sha256 }}</code></td>
                  <td>{% if dataset.available %}<a class="btn btn-primary btn-sm" href="/query/{{ dataset.filename }}">View Data</a>{% else %}File unavailable{% endif %}</td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
        </section>

        <section class="dashboard-section mt-4">
          <h3 class="h4">Limitations and Errors</h3>
          {% if manifest.get("limitations") %}
          <h4 class="h5">Limitations</h4>
          <ul>{% for limitation in manifest.get("limitations", []) %}<li>{{ limitation }}</li>{% endfor %}</ul>
          {% else %}<p>No limitations were recorded.</p>{% endif %}
          {% if manifest.get("errors") %}
          <h4 class="h5">Errors</h4>
          <pre class="dashboard-error-message">{{ manifest.get("errors", [])|tojson(indent=2) }}</pre>
          {% else %}<p>No errors were recorded.</p>{% endif %}
        </section>
      </div>

      {% elif dataset_index %}
      <!-- DATASET INDEX PAGE -->
      <div class="mt-4">
        <h2>Data Viewer</h2>
        <form method="get" action="/search" class="data-filter-form mb-4">
          <div class="data-filter-controls-row">
            <div class="data-inline-control filter-data-control">
              <label for="globalDataSearch" class="form-label">Search All Data:</label>
              <input type="search"
                     class="form-control"
                     id="globalDataSearch"
                     name="query"
                     placeholder="Search every retained Data Viewer dataset"
                     value="{{ global_search_query or '' }}">
              <button type="submit" class="btn btn-primary">Search</button>
            </div>
          </div>
        </form>
        <table class="table table-striped">
          <thead>
            <tr>
              <th>Data Source</th>
              <th>Collection Source</th>
              <th>Workload</th>
              <th>Version</th>
              <th>Record Count</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {% for tab in tabs %}
            <tr>
              <td>{{ tab.name }}</td>
              <td>{{ tab.source }}</td>
              <td>
                {{ tab.workload }}
                {% if tab.api_channel %}<span class="badge text-bg-secondary">{{ tab.api_channel }}</span>{% endif %}
              </td>
              <td>
                {% if tab.versions|length > 1 %}
                <select class="form-select form-select-sm dataset-version-select" data-default-target="/query/{{ tab.filename }}">
                  {% for version in tab.versions %}
                  <option value="/query/{{ version.filename }}" {% if version.filename == tab.filename %}selected{% endif %}>
                    {{ version.label }}
                  </option>
                  {% endfor %}
                </select>
                {% else %}
                {{ tab.version_label }}
                {% endif %}
              </td>
              <td data-record-count-filename="{{ tab.filename }}">{{ tab.record_count }}</td>
              <td><a href="/query/{{ tab.filename }}" class="btn btn-primary btn-sm">View Data</a></td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      
      {% elif global_search_page %}
      <!-- WHOLE DATA STORE SEARCH PAGE -->
      <div class="mt-4">
        <h2>Search All Data</h2>
        <form method="get" action="/search" class="data-filter-form mb-4">
          <div class="data-filter-controls-row">
            <div class="data-inline-control filter-data-control">
              <label for="globalDataSearch" class="form-label">Search All Data:</label>
              <input type="search"
                     class="form-control"
                     id="globalDataSearch"
                     name="query"
                     placeholder="Search every retained Data Viewer dataset"
                     value="{{ global_search_query }}">
              <button type="submit" class="btn btn-primary">Search</button>
              <a href="/datasets" class="btn btn-secondary">Clear</a>
            </div>
          </div>
        </form>

        {% if global_search_query %}
        <p>
          {{ global_search_total }} matching record{% if global_search_total != 1 %}s{% endif %}
          across {{ global_search_files_searched }} dataset file{% if global_search_files_searched != 1 %}s{% endif %}.
          {% if global_search_unreadable %}{{ global_search_unreadable }} dataset file{% if global_search_unreadable != 1 %}s were{% else %} was{% endif %} unreadable and could not be searched.{% endif %}
        </p>
        {% if global_search_results %}
        <div class="table-responsive">
          <table class="table table-striped align-middle">
            <thead><tr><th>Data Source</th><th>Collection Source</th><th>Version</th><th>Record</th><th>Actions</th></tr></thead>
            <tbody>
              {% for result in global_search_results %}
              <tr>
                <td>{{ result.name }}</td>
                <td>{{ result.source }}{% if result.workload %}<br><span class="small table-muted">{{ result.workload }}</span>{% endif %}</td>
                <td>{{ result.version }}</td>
                <td>
                  <details>
                    <summary>Record {{ result.record_number }}</summary>
                    <pre class="dashboard-error-message">{{ result.record|tojson(indent=2) }}</pre>
                  </details>
                </td>
                <td><a class="btn btn-primary btn-sm" href="{{ result.viewer_url }}">View in Dataset</a></td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
        {% else %}
        <p>No matching records were found.</p>
        {% endif %}

        {% if global_search_total_pages > 1 %}
        <nav aria-label="Whole data store search results">
          <div class="d-flex align-items-center gap-2">
            {% if global_search_page_number > 1 %}<a class="btn btn-secondary btn-sm" href="/search?query={{ global_search_query_encoded }}&page={{ global_search_page_number - 1 }}">Previous</a>{% endif %}
            <span>Page {{ global_search_page_number }} of {{ global_search_total_pages }}</span>
            {% if global_search_page_number < global_search_total_pages %}<a class="btn btn-secondary btn-sm" href="/search?query={{ global_search_query_encoded }}&page={{ global_search_page_number + 1 }}">Next</a>{% endif %}
          </div>
        </nav>
        {% endif %}
        {% else %}
        <p>Enter a term to search all retained versions of every dataset shown in the Data Viewer.</p>
        {% endif %}
      </div>

      {% else %}
      <!-- DATA TABLE VIEW PAGE -->
      <div class="data-view">
        <!-- Controls: Drop-down and Search -->
        <div class="data-controls">
          <form method="get" action="/search" class="data-filter-form mb-3">
            <div class="data-filter-controls-row">
              <div class="data-inline-control filter-data-control">
                <label for="globalDataSearch" class="form-label">Search All Data:</label>
                <input type="search"
                       class="form-control"
                       id="globalDataSearch"
                       name="query"
                       placeholder="Search every retained Data Viewer dataset">
                <button type="submit" class="btn btn-primary">Search</button>
              </div>
            </div>
          </form>
          {% if show_data_source_select %}
          <!-- Drop-down for Data Source Selection -->
          <div class="mt-3 mb-3">
            <label for="dataSourceSelect" class="form-label">Select Data Source:</label>
            <select id="dataSourceSelect" class="form-select">
              {% for tab in tabs %}
              <option value="{{ tab.filename }}" {% if current_dataset_filename == tab.filename %}selected{% endif %}>
                {{ tab.name }}
              </option>
              {% endfor %}
            </select>
          </div>
          {% endif %}
          {% if show_version_select %}
          <div class="mt-3 mb-3">
            <label for="datasetVersionSelect" class="form-label">Select Dataset Version:</label>
            <select id="datasetVersionSelect" class="form-select">
              {% for version in current_versions %}
              <option value="{{ version.filename }}" {% if current_tab == version.filename %}selected{% endif %}>
                {{ version.label }}
              </option>
              {% endfor %}
            </select>
          </div>
          {% endif %}
          <!-- Search Form (using GET so the search term is preserved) -->
          <form method="get" action="{{ search_action }}" class="data-filter-form">
            <div class="data-filter-controls-row">
              {% if findings_status_options %}
              <div class="data-inline-control findings-status-control">
                <label for="findingsStatusSelect" class="form-label">Findings Status:</label>
                <select id="findingsStatusSelect" name="status" class="form-select">
                  {% for option in findings_status_options %}
                  <option value="{{ option.value }}" {% if findings_status == option.value %}selected{% endif %}>
                    {{ option.label }}
                  </option>
                  {% endfor %}
                </select>
              </div>
              {% endif %}
              <div class="data-inline-control filter-data-control">
                <label for="query" class="form-label">Filter Data:</label>
                <input type="text"
                       class="form-control"
                       id="query"
                       name="query"
                       placeholder="Enter search term"
                       value="{{ request.args.get('query', '') }}">
              </div>
            </div>
            <div class="data-filter-actions-row">
              <button type="submit" class="btn btn-primary">Search</button>
              <a href="{{ reset_action }}" class="btn btn-secondary">Reset Search</a>
              <div class="table-font-controls"
                   role="group"
                   aria-label="Table font size">
                <span class="small table-muted">Table font size</span>
                <button id="decreaseTableFont"
                        type="button"
                        class="btn btn-outline-secondary btn-sm"
                        aria-label="Decrease table font size">A−</button>
                <button id="increaseTableFont"
                        type="button"
                        class="btn btn-outline-secondary btn-sm"
                        aria-label="Increase table font size">A+</button>
              </div>
              {% if findings_validation_enabled %}
              <div class="findings-reviewer-control">
                <label for="findingsReviewer" class="form-label">Reviewer:</label>
                <input id="findingsReviewer"
                       class="form-control form-control-sm"
                       type="text"
                       maxlength="10000"
                       autocomplete="name"
                       placeholder="Analyst name">
              </div>
              <a id="exportValidatedSarif"
                 class="btn btn-success{% if not validated_findings_count %} disabled{% endif %}"
                 href="/findings/export-validated-sarif"
                 aria-disabled="{{ 'false' if validated_findings_count else 'true' }}">
                Export Validated SARIF ({{ validated_findings_count }})
              </a>
              <span id="findingsValidationMessage" class="small" role="status" aria-live="polite"></span>
              {% endif %}
            </div>
          </form>
        </div>
        <!-- Scrollable Table Container fills remaining height -->
        <div id="table-container" class="table-container mt-3">
          <div id="data-table-loading"
               class="data-table-loading"
               role="status"
               aria-live="polite"
               aria-busy="true">
            <div class="data-table-loading-panel">
              <div class="mb-2 fw-semibold">Preparing data view…</div>
              <div class="progress table-loading-progress"
                   aria-label="Preparing data view">
                <div class="progress-bar progress-bar-striped progress-bar-animated w-100"></div>
              </div>
            </div>
          </div>
          <div id="table-content" class="table-content-pending">
            <script>
              document.getElementById('table-content').setAttribute('aria-hidden', 'true');
            </script>
            {{ table|safe }}
          </div>
        </div>
      </div>
      {% endif %}
    </div>

    <!-- JavaScript for Dark Mode Toggle -->
    <script>
      document.getElementById('darkModeToggle').addEventListener('click', function() {
        const darkModeEnabled = document.body.classList.toggle('dark-mode');
        document.documentElement.setAttribute(
          'data-bs-theme',
          darkModeEnabled ? 'dark' : 'light'
        );
        window.dispatchEvent(new Event('azure-theme-change'));
      });
    </script>

    <script>
      document.getElementById('returnToDashboard').addEventListener('click', function() {
          window.location.href = "/";
      });
    </script>

    <script>
      document.getElementById('dataViewerIndex').addEventListener('click', function() {
          window.location.href = "/datasets";
      });
    </script>

    <script>
      document.getElementById('findingsView').addEventListener('click', function() {
          window.location.href = "/findings";
      });
    </script>

    <script>
      document.getElementById('manifestView').addEventListener('click', function() {
          window.location.href = "/manifest";
      });
    </script>

    <script>
      document.querySelectorAll('.manifest-version-select').forEach(function(select) {
        select.addEventListener('change', function() {
          window.location.href = this.value;
        });
      });
    </script>

    {% if dashboard or dataset_index %}
    <script>
      document.querySelectorAll('.dataset-version-select').forEach(function(select) {
        select.addEventListener('change', function() {
          window.location.href = this.value;
        });
      });

      (function() {
        const datasetCountCells = Array.from(document.querySelectorAll('[data-record-count-filename]'));
        const summaryCountValues = Array.from(document.querySelectorAll('[data-summary-count-filenames]'));
        const filenames = new Set();

        datasetCountCells.forEach(function(cell) {
          if (cell.dataset.recordCountFilename) {
            filenames.add(cell.dataset.recordCountFilename);
          }
        });

        summaryCountValues.forEach(function(value) {
          (value.dataset.summaryCountFilenames || '').split(',').forEach(function(filename) {
            if (filename) filenames.add(filename);
          });
        });

        if (filenames.size === 0) return;

        const params = new URLSearchParams();
        filenames.forEach(function(filename) {
          params.append('filename', filename);
        });

        fetch('/dataset-counts?' + params.toString(), {
          headers: {
            'Accept': 'application/json'
          }
        })
          .then(function(response) {
            if (!response.ok) {
              throw new Error('Count request failed');
            }
            return response.json();
          })
          .then(function(payload) {
            const counts = payload.counts || {};
            datasetCountCells.forEach(function(cell) {
              const filename = cell.dataset.recordCountFilename;
              cell.textContent = Object.prototype.hasOwnProperty.call(counts, filename)
                ? counts[filename]
                : 'Unavailable';
            });

            summaryCountValues.forEach(function(value) {
              const cardFilenames = (value.dataset.summaryCountFilenames || '').split(',').filter(Boolean);
              let total = 0;
              let complete = true;

              cardFilenames.forEach(function(filename) {
                if (Object.prototype.hasOwnProperty.call(counts, filename)) {
                  total += counts[filename];
                } else {
                  complete = false;
                }
              });

              value.textContent = complete ? total : 'Unavailable';
            });
          })
          .catch(function() {
            datasetCountCells.forEach(function(cell) {
              cell.textContent = 'Unavailable';
            });
            summaryCountValues.forEach(function(value) {
              value.textContent = 'Unavailable';
            });
          });
      })();
    </script>
    {% endif %}

    {% if dashboard and findings_chart_data %}
    <script>
      (function() {
        function renderDashboardPie(canvasId, legendId, chartData) {
          const canvas = document.getElementById(canvasId);
          const legend = document.getElementById(legendId);
          if (!canvas || !legend) return;
          const segments = chartData.filter(function(item) { return item.value > 0; });
          if (segments.length === 0) return;

          function drawPieChart() {
          const ratio = window.devicePixelRatio || 1;
          const rect = canvas.getBoundingClientRect();
          const width = Math.max(rect.width, 320);
          const height = Math.max(rect.height, 320);
          canvas.width = width * ratio;
          canvas.height = height * ratio;

          const ctx = canvas.getContext('2d');
          ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
          ctx.clearRect(0, 0, width, height);

          const total = segments.reduce(function(sum, item) { return sum + item.value; }, 0);
          const centerX = width / 2;
          const centerY = height / 2;
          const radius = Math.min(width, height) * 0.32;
          let startAngle = -Math.PI / 2;

          segments.forEach(function(segment) {
            const slice = (segment.value / total) * Math.PI * 2;
            const endAngle = startAngle + slice;

            ctx.beginPath();
            ctx.moveTo(centerX, centerY);
            ctx.arc(centerX, centerY, radius, startAngle, endAngle);
            ctx.closePath();
            ctx.fillStyle = segment.color;
            ctx.fill();

            const midAngle = startAngle + (slice / 2);
            const labelX = centerX + Math.cos(midAngle) * (radius + 24);
            const labelY = centerY + Math.sin(midAngle) * (radius + 24);
            const percentage = ((segment.value / total) * 100).toFixed(1);

            ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--text-color').trim() || '#212529';
            ctx.font = '14px sans-serif';
            ctx.textAlign = labelX >= centerX ? 'left' : 'right';
            ctx.textBaseline = 'middle';
            ctx.fillText(percentage + '%', labelX, labelY);

            startAngle = endAngle;
          });
          }

          legend.replaceChildren();
          segments.forEach(function(segment) {
            const item = document.createElement('div');
            const swatch = document.createElement('span');
            const label = document.createElement('span');
            item.className = 'chart-legend-item';
            swatch.className = 'chart-legend-swatch';
            swatch.style.backgroundColor = segment.color;
            label.textContent = segment.label + ': ' + segment.value;
            item.append(swatch, label);
            legend.appendChild(item);
          });

          drawPieChart();
          window.addEventListener('resize', drawPieChart);
          window.addEventListener('azure-theme-change', drawPieChart);
        }

        function renderDashboardSankey(canvasId, paths, nodeData) {
          const canvas = document.getElementById(canvasId);
          if (!canvas) return;
          const activePaths = paths.filter(function(path) {
            return path.value > 0 && Array.isArray(path.nodes) && path.nodes.length > 1;
          });
          if (activePaths.length === 0) return;
          const nodeDetails = new Map();
          nodeData.forEach(function(node) {
            nodeDetails.set(JSON.stringify([node.stage, node.name]), node);
          });
          const stageLabels = [
            'Endpoint Type',
            'Endpoint Status',
            'Finding Checks',
            'Finding Check Status',
            'Finding Result',
          ];

          function drawSankeyChart() {
            const stageCount = activePaths.reduce(function(maximum, path) {
              return Math.max(maximum, path.nodes.length);
            }, 0);
            const stageNames = Array.from({length: stageCount}, function() { return []; });
            const stageTotals = Array.from({length: stageCount}, function() { return new Map(); });
            activePaths.forEach(function(path) {
              path.nodes.forEach(function(name, stage) {
                if (!stageTotals[stage].has(name)) stageNames[stage].push(name);
                stageTotals[stage].set(name, (stageTotals[stage].get(name) || 0) + path.value);
              });
            });

            const ratio = window.devicePixelRatio || 1;
            const rect = canvas.getBoundingClientRect();
            const width = Math.max(rect.width, 1200);
            const largestStage = Math.max.apply(null, stageNames.map(function(names) {
              return names.length;
            }));
            const height = Math.max(rect.height, 500, largestStage * 52);
            canvas.style.width = width + 'px';
            canvas.style.height = height + 'px';
            canvas.width = width * ratio;
            canvas.height = height * ratio;

            const ctx = canvas.getContext('2d');
            ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
            ctx.clearRect(0, 0, width, height);

            const total = Array.from(stageTotals[0].values()).reduce(function(sum, value) {
              return sum + value;
            }, 0);
            const marginY = 48;
            const gap = 10;
            const largestGapTotal = Math.max(0, largestStage - 1) * gap;
            const scale = Math.max(0.25, (height - (marginY * 2) - largestGapTotal) / total);
            const firstX = 125;
            const lastX = width - 180;
            const nodeWidth = 14;
            const stageSpacing = (lastX - firstX) / Math.max(1, stageCount - 1);
            const stageX = Array.from({length: stageCount}, function(_value, stage) {
              return firstX + stage * stageSpacing;
            });

            function layoutNodes(names, totals, x) {
              const nodes = new Map();
              const usedHeight = names.reduce(function(sum, name) {
                return sum + totals.get(name) * scale;
              }, 0) + Math.max(0, names.length - 1) * gap;
              let y = Math.max(marginY, (height - usedHeight) / 2);
              names.forEach(function(name) {
                const nodeHeight = totals.get(name) * scale;
                nodes.set(name, {x: x, y: y, height: nodeHeight});
                y += nodeHeight + gap;
              });
              return nodes;
            }

            const stageNodes = stageNames.map(function(names, stage) {
              return layoutNodes(names, stageTotals[stage], stageX[stage]);
            });
            const outgoingOffsets = Array.from({length: stageCount}, function() { return new Map(); });
            const incomingOffsets = Array.from({length: stageCount}, function() { return new Map(); });
            const linksByStage = Array.from({length: stageCount - 1}, function() { return new Map(); });
            activePaths.forEach(function(path) {
              for (let stage = 0; stage < path.nodes.length - 1; stage += 1) {
                const source = path.nodes[stage];
                const target = path.nodes[stage + 1];
                const key = JSON.stringify([source, target, path.color]);
                const existing = linksByStage[stage].get(key);
                if (existing) {
                  existing.value += path.value;
                } else {
                  linksByStage[stage].set(key, {
                    source: source,
                    target: target,
                    value: path.value,
                    color: path.color,
                  });
                }
              }
            });

            linksByStage.forEach(function(stageLinks, stage) {
              stageLinks.forEach(function(link) {
                const source = stageNodes[stage].get(link.source);
                const target = stageNodes[stage + 1].get(link.target);
                const linkHeight = link.value * scale;
                const sourceOffset = outgoingOffsets[stage].get(link.source) || 0;
                const targetOffset = incomingOffsets[stage + 1].get(link.target) || 0;
                const sourceTop = source.y + sourceOffset;
                const targetTop = target.y + targetOffset;
                const controlX = (source.x + target.x) / 2;

                ctx.save();
                ctx.globalAlpha = 0.34;
                ctx.fillStyle = link.color;
                ctx.beginPath();
                ctx.moveTo(source.x + nodeWidth, sourceTop);
                ctx.bezierCurveTo(controlX, sourceTop, controlX, targetTop, target.x, targetTop);
                ctx.lineTo(target.x, targetTop + linkHeight);
                ctx.bezierCurveTo(
                  controlX,
                  targetTop + linkHeight,
                  controlX,
                  sourceTop + linkHeight,
                  source.x + nodeWidth,
                  sourceTop + linkHeight
                );
                ctx.closePath();
                ctx.fill();
                ctx.restore();
                outgoingOffsets[stage].set(link.source, sourceOffset + linkHeight);
                incomingOffsets[stage + 1].set(link.target, targetOffset + linkHeight);
              });
            });

            const textColor = getComputedStyle(document.body).getPropertyValue('--text-color').trim() || '#212529';
            ctx.font = '12px sans-serif';

            ctx.fillStyle = textColor;
            ctx.font = 'bold 12px sans-serif';
            stageX.forEach(function(x, stage) {
              ctx.textAlign = stage === 0 ? 'right' : 'left';
              ctx.textBaseline = 'top';
              ctx.fillText(stageLabels[stage] || ('Stage ' + (stage + 1)), stage === 0 ? x + nodeWidth : x, 10);
            });
            ctx.font = '12px sans-serif';

            function drawWrappedLabel(text, x, y, maxWidth, alignment) {
              const words = text.split(/\\s+/);
              const lines = [];
              let line = '';
              words.forEach(function(word) {
                const candidate = line ? line + ' ' + word : word;
                if (line && ctx.measureText(candidate).width > maxWidth) {
                  lines.push(line);
                  line = word;
                } else {
                  line = candidate;
                }
              });
              if (line) lines.push(line);
              ctx.textAlign = alignment;
              ctx.textBaseline = 'middle';
              const lineHeight = 13;
              const firstY = y - ((lines.length - 1) * lineHeight) / 2;
              lines.forEach(function(value, index) {
                ctx.fillText(value, x, firstY + index * lineHeight);
              });
            }

            stageNames.forEach(function(names, stage) {
              names.forEach(function(name) {
                const node = stageNodes[stage].get(name);
                const finalPath = activePaths.find(function(path) {
                  return path.nodes[stage] === name;
                });
                ctx.fillStyle = stage === stageCount - 1 ? finalPath.color : '#446df6';
                ctx.fillRect(node.x, node.y, nodeWidth, node.height);
                ctx.fillStyle = textColor;
                const isFirst = stage === 0;
                const isLast = stage === stageCount - 1;
                const detail = nodeDetails.get(JSON.stringify([stage, name]));
                const relationshipTotal = stageTotals[stage].get(name);
                const label = detail
                  ? name + ': ' + detail.count + ' ' + detail.unit + ' (' + relationshipTotal + ' flow links)'
                  : name + ': ' + relationshipTotal + ' flow links';
                drawWrappedLabel(
                  label,
                  isFirst ? node.x - 6 : node.x + nodeWidth + 5,
                  node.y + node.height / 2,
                  isFirst ? 115 : isLast ? 165 : Math.max(105, stageSpacing - 28),
                  isFirst ? 'right' : 'left'
                );
              });
            });
          }

          drawSankeyChart();
          window.addEventListener('resize', drawSankeyChart);
          window.addEventListener('azure-theme-change', drawSankeyChart);
        }

        renderDashboardPie('findingsPieChart', 'findingsPieLegend', {{ findings_chart_data|tojson }});
        renderDashboardSankey(
          'findingsSankeyChart',
          {{ findings_sankey_data|tojson }},
          {{ findings_sankey_nodes|tojson }}
        );
      })();
    </script>
    {% endif %}

    {% if dashboard and collection_requests and collection_requests.endpoint_count %}
    <script>
      (function() {
        function initialiseDashboardTable(table) {
        if (!table || !table.tBodies.length) return;
        const body = table.tBodies[0];
        const headers = Array.from(table.tHead.rows[0].cells);
        const filters = Array.from(table.querySelectorAll('.dashboard-column-filter'));

        function applyFilters() {
          Array.from(body.rows).forEach(function(row) {
            const visible = filters.every(function(filter) {
              const query = filter.value.trim().toLocaleLowerCase();
              if (!query) return true;
              const cell = row.cells[Number(filter.dataset.columnIndex)];
              const cellValue = (cell?.textContent || '').trim().toLocaleLowerCase();
              return filter.dataset.filterMode === 'exact'
                ? cellValue === query
                : cellValue.includes(query);
            });
            row.hidden = !visible;
          });
        }

        filters.forEach(function(filter) {
          if (filter.tagName === 'SELECT') {
            const columnIndex = Number(filter.dataset.columnIndex);
            const values = Array.from(body.rows)
              .map(function(row) { return (row.cells[columnIndex]?.textContent || '').trim(); })
              .filter(Boolean)
              .filter(function(value, index, items) { return items.indexOf(value) === index; })
              .sort(function(left, right) {
                return left.localeCompare(right, undefined, {numeric: true, sensitivity: 'base'});
              });
            values.forEach(function(value) {
              const option = document.createElement('option');
              option.value = value;
              option.textContent = value;
              filter.appendChild(option);
            });
            filter.addEventListener('change', applyFilters);
          } else {
            filter.addEventListener('input', applyFilters);
          }
          filter.addEventListener('click', function(event) { event.stopPropagation(); });
        });

        table.querySelectorAll('.dashboard-sort-button').forEach(function(button) {
          button.addEventListener('click', function() {
            const columnIndex = Number(button.dataset.columnIndex);
            const header = headers[columnIndex];
            const direction = header.getAttribute('aria-sort') === 'ascending'
              ? 'descending'
              : 'ascending';
            headers.forEach(function(candidate) { candidate.setAttribute('aria-sort', 'none'); });
            header.setAttribute('aria-sort', direction);

            const rows = Array.from(body.rows).map(function(row, index) {
              return {row: row, index: index};
            });
            rows.sort(function(left, right) {
              const leftValue = (left.row.cells[columnIndex]?.textContent || '').trim();
              const rightValue = (right.row.cells[columnIndex]?.textContent || '').trim();
              const leftNumber = Number(leftValue.replace(/,/g, ''));
              const rightNumber = Number(rightValue.replace(/,/g, ''));
              const bothNumeric = leftValue !== '' && rightValue !== ''
                && Number.isFinite(leftNumber) && Number.isFinite(rightNumber);
              const comparison = bothNumeric
                ? leftNumber - rightNumber
                : leftValue.localeCompare(rightValue, undefined, {numeric: true, sensitivity: 'base'});
              if (comparison === 0) return left.index - right.index;
              return direction === 'ascending' ? comparison : -comparison;
            });
            rows.forEach(function(item) { body.appendChild(item.row); });
            applyFilters();
          });
        });
        }

        document.querySelectorAll('.dashboard-filterable-table').forEach(initialiseDashboardTable);
      })();
    </script>
    {% endif %}


    <!-- JavaScript for Data Source Drop-down (only on data table view) -->
    {% if not dashboard %}
    {% if show_data_source_select %}
    <script>
      document.getElementById('dataSourceSelect').addEventListener('change', function() {
        var selected = this.value;
        window.location.href = "/query/" + selected;
      });
    </script>
    {% endif %}

    {% if show_version_select %}
    <script>
      document.getElementById('datasetVersionSelect').addEventListener('change', function() {
        var selected = this.value;
        window.location.href = "/query/" + selected;
      });
    </script>
    {% endif %}

    {% if findings_status_options %}
    <script>
      document.getElementById('findingsStatusSelect').addEventListener('change', function() {
        const params = new URLSearchParams(window.location.search);
        params.set('status', this.value);
        const queryInput = document.getElementById('query');
        if (queryInput && queryInput.value) {
          params.set('query', queryInput.value);
        } else {
          params.delete('query');
        }
        window.location.href = "{{ search_action }}" + "?" + params.toString();
      });
    </script>
    {% endif %}

<script>
document.addEventListener('DOMContentLoaded', function () {
  const tableContainer = document.getElementById('table-container');
  const decreaseButton = document.getElementById('decreaseTableFont');
  const increaseButton = document.getElementById('increaseTableFont');
  if (!tableContainer || !decreaseButton || !increaseButton) return;

  const minimumSize = 0.6;
  const maximumSize = 1.2;
  const step = 0.1;
  let currentSize = 0.8;

  const applyTableFontSize = () => {
    tableContainer.style.setProperty('--table-font-size', currentSize.toFixed(1) + 'rem');
    decreaseButton.disabled = currentSize <= minimumSize;
    increaseButton.disabled = currentSize >= maximumSize;
  };

  decreaseButton.addEventListener('click', function () {
    currentSize = Math.max(minimumSize, currentSize - step);
    applyTableFontSize();
  });
  increaseButton.addEventListener('click', function () {
    currentSize = Math.min(maximumSize, currentSize + step);
    applyTableFontSize();
  });
  applyTableFontSize();
});
</script>

<script>
document.addEventListener('DOMContentLoaded', function () {
  const table = document.querySelector('table');
  if (!table) return;

  const findingsValidationEnabled = {{ findings_validation_enabled|default(false)|tojson }};
  const findingsReviewCsrfToken = {{ findings_review_csrf_token|default('')|tojson }};
  const reviewerInput = document.getElementById('findingsReviewer');
  const validationMessage = document.getElementById('findingsValidationMessage');
  const exportValidatedButton = document.getElementById('exportValidatedSarif');
  let validatedFindingsCount = {{ validated_findings_count|default(0)|tojson }};

  if (exportValidatedButton) {
    exportValidatedButton.addEventListener('click', function (event) {
      if (exportValidatedButton.getAttribute('aria-disabled') === 'true') {
        event.preventDefault();
      }
    });
  }

  const updateExportButton = () => {
    if (!exportValidatedButton) return;
    exportValidatedButton.textContent = `Export Validated SARIF (${validatedFindingsCount})`;
    const disabled = validatedFindingsCount === 0;
    exportValidatedButton.classList.toggle('disabled', disabled);
    exportValidatedButton.setAttribute('aria-disabled', disabled ? 'true' : 'false');
  };

  const updateReviewSummary = (row, headerRow, review) => {
    const reviewHeader = Array.from(headerRow.cells).find((cell) =>
      cell.textContent.trim().toLowerCase() === 'review'
    );
    if (!reviewHeader) return;
    const reviewCell = row.cells[reviewHeader.cellIndex];
    if (!reviewCell) return;
    const analyst = review.analyst || {};
    const values = {
      'review state': review.review_state === 'reviewed' ? 'Reviewed' : 'Unreviewed',
      'disposition': review.disposition === 'confirmed' ? 'Confirmed' : 'Candidate',
      'reviewer': analyst.reviewer || 'Unassigned',
      'report inclusion': review.report_ready?.include ? 'Yes' : 'No'
    };
    reviewCell.querySelectorAll('tr').forEach((summaryRow) => {
      const heading = summaryRow.querySelector('th');
      const value = summaryRow.querySelector('td');
      const replacement = values[heading?.textContent.trim().toLowerCase()];
      if (value && replacement !== undefined) value.textContent = replacement;
    });
  };

  const headerRow = table.rows[0];
  if (!headerRow || headerRow.cells.length === 0) return;

  let jsonColumnIndex = -1;
  for (let i = 0; i < headerRow.cells.length; i++) {
    const headerText = headerRow.cells[i].textContent.trim().toLowerCase();
    if (headerText === 'json_string') {
      jsonColumnIndex = i;
      break;
    }
  }

  if (jsonColumnIndex === -1) return;

  headerRow.cells[jsonColumnIndex].style.display = 'none';

  const newTh = document.createElement('th');
  newTh.textContent = 'Actions';
  if (jsonColumnIndex + 1 < headerRow.cells.length) {
    headerRow.insertBefore(newTh, headerRow.cells[jsonColumnIndex + 1]);
  } else {
    headerRow.appendChild(newTh);
  }

  for (let i = 1; i < table.rows.length; i++) {
    const row = table.rows[i];
    if (row.cells.length === 0) continue;
    if (jsonColumnIndex >= row.cells.length) continue;

    const jsonCell = row.cells[jsonColumnIndex];
    jsonCell.style.display = 'none';

    const toggleCell = row.insertCell(Math.min(jsonColumnIndex + 1, row.cells.length));
    const toggleBtn = document.createElement('button');

    toggleBtn.textContent = 'View JSON';
    toggleBtn.className = 'btn btn-info btn-sm';
    toggleBtn.setAttribute('data-bs-toggle', 'modal');
    toggleBtn.setAttribute('data-bs-target', '#jsonModal');

    toggleBtn.addEventListener('click', () => {
      try {
        const rawText = decodeURIComponent(jsonCell.textContent.trim());
        const pretty = JSON.stringify(JSON.parse(rawText), null, 2);
        document.getElementById('jsonModalLabel').textContent = `Record #${i}`;
        document.getElementById('jsonModalContent').textContent = pretty;
      } catch (err) {
        document.getElementById('jsonModalContent').textContent = 'Broken or missing JSON for this row.';
      }
    });

    toggleCell.appendChild(toggleBtn);

    if (findingsValidationEnabled) {
      let sourceRow = null;
      try {
        sourceRow = JSON.parse(decodeURIComponent(jsonCell.textContent.trim()));
      } catch (err) {
        sourceRow = null;
      }
      if (
        ['found', 'manual_assessment_required'].includes(sourceRow?.status)
        && sourceRow?.finding_id
      ) {
        const validationControl = document.createElement('label');
        validationControl.className = 'finding-validation-control';
        const validationCheckbox = document.createElement('input');
        validationCheckbox.type = 'checkbox';
        validationCheckbox.className = 'form-check-input';
        validationCheckbox.checked = sourceRow.review?.disposition === 'confirmed';
        validationCheckbox.setAttribute(
          'aria-label',
          `Validated assessment item: ${sourceRow.title || sourceRow.finding_id}`
        );
        const validationLabel = document.createElement('span');
        validationLabel.textContent = 'Validated';
        const rowStatus = document.createElement('span');
        rowStatus.className = 'finding-validation-status small';
        rowStatus.setAttribute('aria-live', 'polite');
        validationControl.append(validationCheckbox, validationLabel, rowStatus);
        toggleCell.appendChild(validationControl);

        validationCheckbox.addEventListener('change', async function () {
          const requestedState = validationCheckbox.checked;
          const reviewer = reviewerInput?.value.trim() || '';
          if (!reviewer) {
            validationCheckbox.checked = !requestedState;
            if (validationMessage) {
              validationMessage.textContent = 'Enter the reviewer name before changing validation.';
            }
            reviewerInput?.focus();
            return;
          }

          validationCheckbox.disabled = true;
          rowStatus.textContent = 'Saving…';
          if (validationMessage) validationMessage.textContent = '';
          try {
            const response = await fetch('/findings/review', {
              method: 'POST',
              credentials: 'same-origin',
              headers: {
                'Content-Type': 'application/json',
                'X-Azure-Assess-CSRF': findingsReviewCsrfToken
              },
              body: JSON.stringify({
                finding_id: sourceRow.finding_id,
                confirmed: requestedState,
                reviewer: reviewer
              })
            });
            const responseBody = await response.json();
            if (!response.ok) {
              throw new Error(responseBody.error || `Request failed (${response.status})`);
            }
            sourceRow.review = responseBody.review;
            jsonCell.textContent = encodeURIComponent(JSON.stringify(sourceRow));
            validatedFindingsCount = responseBody.validated_findings;
            updateReviewSummary(row, headerRow, responseBody.review);
            updateExportButton();
            rowStatus.textContent = 'Saved';
          } catch (err) {
            validationCheckbox.checked = !requestedState;
            rowStatus.textContent = 'Not saved';
            if (validationMessage) validationMessage.textContent = err.message;
          } finally {
            validationCheckbox.disabled = false;
          }
        });
      }
    }
  }

  const tableBody = table.tBodies[0];
  if (!tableBody) return;

  const sortableHeaders = Array.from(headerRow.cells).filter((cell) =>
    cell.classList.contains('table-sortable')
  );

  sortableHeaders.forEach((header) => {
    const columnIndex = header.cellIndex;
    Array.from(tableBody.rows).forEach((row) => {
      const cell = row.cells[columnIndex];
      if (cell) {
        cell.dataset.findingsSortValue = cell.textContent.trim();
      }
    });

    const sortColumn = () => {
      const direction = header.getAttribute('aria-sort') === 'ascending'
        ? 'descending'
        : 'ascending';
      sortableHeaders.forEach((candidate) => candidate.setAttribute('aria-sort', 'none'));
      header.setAttribute('aria-sort', direction);

      const rows = Array.from(tableBody.rows).map((row, index) => ({row, index}));
      rows.sort((left, right) => {
        const leftCell = left.row.cells[columnIndex];
        const rightCell = right.row.cells[columnIndex];
        const leftValue = leftCell?.dataset.findingsSortValue || '';
        const rightValue = rightCell?.dataset.findingsSortValue || '';
        const leftNumber = Number(leftValue.replace(/,/g, ''));
        const rightNumber = Number(rightValue.replace(/,/g, ''));
        const bothNumeric = leftValue !== '' && rightValue !== ''
          && Number.isFinite(leftNumber) && Number.isFinite(rightNumber);
        const comparison = bothNumeric
          ? leftNumber - rightNumber
          : leftValue.localeCompare(rightValue, undefined, {
              numeric: true,
              sensitivity: 'base'
            });
        if (comparison === 0) return left.index - right.index;
        return direction === 'ascending' ? comparison : -comparison;
      });
      rows.forEach(({row}) => tableBody.appendChild(row));
    };

    header.addEventListener('click', sortColumn);
    header.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        sortColumn();
      }
    });
  });

  const affectedEntitiesHeader = Array.from(headerRow.cells).find((cell) =>
    cell.dataset.initialVisibleCount
  );
  if (affectedEntitiesHeader) {
    const affectedEntitiesIndex = affectedEntitiesHeader.cellIndex;
    const visibleCount = Number(affectedEntitiesHeader.dataset.initialVisibleCount);
    Array.from(tableBody.rows).forEach((row) => {
      const cell = row.cells[affectedEntitiesIndex];
      if (!cell) return;
      const list = Array.from(cell.children).find((child) => child.tagName === 'UL');
      if (!list) return;
      const items = Array.from(list.children).filter((child) => child.tagName === 'LI');
      if (items.length <= visibleCount) return;

      const hiddenItems = items.slice(visibleCount);
      hiddenItems.forEach((item) => { item.hidden = true; });

      const toggle = document.createElement('button');
      toggle.type = 'button';
      toggle.className = 'btn btn-link btn-sm affected-entities-toggle';
      toggle.setAttribute('aria-expanded', 'false');
      toggle.textContent = `Show ${hiddenItems.length} more`;
      toggle.addEventListener('click', function () {
        const expanded = toggle.getAttribute('aria-expanded') === 'true';
        hiddenItems.forEach((item) => { item.hidden = expanded; });
        toggle.setAttribute('aria-expanded', expanded ? 'false' : 'true');
        toggle.textContent = expanded ? `Show ${hiddenItems.length} more` : 'Show fewer';
      });
      cell.appendChild(toggle);
    });
  }
});
</script>

    <!-- JavaScript for handling nested table toggles with global and local icons -->
    <script>
      document.addEventListener('DOMContentLoaded', function() {
        // For every table cell, collapse nested tables and add toggle icons
        document.querySelectorAll('td, th').forEach(function(cell) {
          var nestedTables = cell.querySelectorAll('table');
          if (nestedTables.length > 0) {
            // Ensure all nested tables are collapsed
            nestedTables.forEach(function(table) {
              table.style.display = 'none';
            });
            // Add a global toggle icon to the cell (if not already present)
            if (!cell.querySelector('.global-collapse-icon')) {
              var globalIcon = document.createElement('span');
              globalIcon.className = 'global-collapse-icon collapse-icon';
              globalIcon.style.cursor = 'pointer';
              globalIcon.style.marginRight = '8px';
              globalIcon.innerHTML = '&#x229E;'; // Squared plus for expand all
              globalIcon.title = 'Expand all nested data in this cell';
              cell.insertBefore(globalIcon, cell.firstChild);
              
              // Global icon toggles all nested tables in this cell
              globalIcon.addEventListener('click', function(e) {
                var newState = (nestedTables[0].style.display === 'none') ? 'table' : 'none';
                nestedTables.forEach(function(table) {
                  table.style.display = newState;
                  var localIcon = table.previousElementSibling;
                  if (localIcon && localIcon.classList.contains('local-collapse-icon')) {
                    localIcon.innerHTML = (newState === 'table') ? '&#x2212;' : '&#x002B;';
                    localIcon.title = (newState === 'table')
                      ? 'Collapse this nested table'
                      : 'Expand this nested table only';
                  }
                });
                globalIcon.innerHTML = (newState === 'table') ? '&#x229F;' : '&#x229E;';
                globalIcon.title = (newState === 'table')
                  ? 'Collapse all nested data in this cell'
                  : 'Expand all nested data in this cell';
                e.stopPropagation();
              });
            }
            
            // Add a local toggle icon for each nested table (if not present)
            nestedTables.forEach(function(table) {
              if (!(table.previousElementSibling && table.previousElementSibling.classList.contains('local-collapse-icon'))) {
                var localIcon = document.createElement('span');
                localIcon.className = 'local-collapse-icon collapse-icon';
                localIcon.style.cursor = 'pointer';
                localIcon.style.marginRight = '8px';
                localIcon.innerHTML = '&#x002B;'; // Plus for expand one
                localIcon.title = 'Expand this nested table only';
                table.parentNode.insertBefore(localIcon, table);
                
                // Local icon toggles its specific nested table
                localIcon.addEventListener('click', function(e) {
                  table.style.display = (table.style.display === 'none') ? 'table' : 'none';
                  localIcon.innerHTML = (table.style.display === 'table') ? '&#x2212;' : '&#x002B;';
                  localIcon.title = (table.style.display === 'table')
                    ? 'Collapse this nested table'
                    : 'Expand this nested table only';
                  e.stopPropagation();
                });
              }
            });
          }
        });
      });
    </script>

    <script>
      document.addEventListener('DOMContentLoaded', function() {
        window.requestAnimationFrame(function() {
          var loading = document.getElementById('data-table-loading');
          var content = document.getElementById('table-content');
          if (content) {
            content.classList.remove('table-content-pending');
            content.removeAttribute('aria-hidden');
          }
          if (loading) {
            loading.setAttribute('aria-busy', 'false');
            loading.hidden = true;
          }
        });
      });
    </script>
    {% endif %}


<!-- JSON Viewer Modal -->
<div class="modal fade" id="jsonModal" tabindex="-1" aria-labelledby="jsonModalLabel" aria-hidden="true">
  <div class="modal-dialog modal-xl modal-dialog-scrollable">
    <div class="modal-content bg-dark text-white">
      <div class="modal-header">
        <h5 class="modal-title" id="jsonModalLabel">JSON Record</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <pre id="jsonModalContent" class="mb-0" style="white-space: pre-wrap;"></pre>
      </div>
    </div>
  </div>
</div>
  </body>
</html>
"""

def load_json_file(filepath):
    """Load JSON data from the specified file."""
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        return data
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        return None


def collect_filename_prefix(command, parameterized=False):
    prefix = command.lower().replace("(", "").replace(")", "").replace(" ", "_")
    if parameterized:
        prefix = prefix.replace("{", "").replace("}", "")
    return prefix


def load_collect_endpoint_name_map():
    endpoint_map = {}
    collect_script = Path(__file__).with_name("azure-collect.py")
    try:
        spec = importlib.util.spec_from_file_location("azure_collect_module", collect_script)
        if spec is None or spec.loader is None:
            return endpoint_map
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as exc:
        print(f"Warning: could not load dataset mappings from {collect_script}: {exc}")
        return endpoint_map

    base_endpoints = getattr(module, "AZURE_CLI_ENDPOINTS", [])
    parameterized_endpoints = getattr(module, "AZURE_CLI_ENDPOINTS_PARAMS", [])
    graph_endpoints = getattr(module, "GRAPH_ENDPOINTS", [])

    # Retain legacy aliases so datasets collected before the canonical filename
    # sanitiser was introduced continue to receive their friendly names.
    for endpoint in base_endpoints:
        endpoint_map[collect_filename_prefix(endpoint["cli_command"])] = endpoint["name"]

    for endpoint in parameterized_endpoints:
        endpoint_map[collect_filename_prefix(endpoint["cli_command"], parameterized=True)] = endpoint["name"]

    endpoint_output_prefix = getattr(module, "endpoint_output_prefix", None)
    if callable(endpoint_output_prefix):
        for endpoint in base_endpoints + parameterized_endpoints:
            endpoint_map[endpoint_output_prefix(endpoint)] = endpoint["name"]

    # These commands were replaced by the native Graph runner. Keep both old
    # filename representations discoverable for historical assessment data.
    legacy_graph_endpoints = [
        {
            "name": "Graph Directory Roles",
            "cli_command": "az rest --method get --url https://graph.microsoft.com/v1.0/directoryRoles",
            "needs_pagination": False,
        },
    ]
    for endpoint in legacy_graph_endpoints:
        endpoint_map[collect_filename_prefix(endpoint["cli_command"])] = endpoint["name"]
        if callable(endpoint_output_prefix):
            endpoint_map[endpoint_output_prefix(endpoint)] = endpoint["name"]

    for endpoint in graph_endpoints:
        endpoint_map[endpoint["output"]] = endpoint["name"]

    endpoint_map["role_enriched"] = "Role Assignments Enriched"
    endpoint_map["azure_public_endpoint_topology"] = "Public Endpoint Topology"
    endpoint_map["azure_public_endpoint_topology_coverage"] = (
        "Public Endpoint Topology Coverage"
    )
    endpoint_map["az_ams_account_list"] = "Media Services"
    endpoint_map["az_dls_account_list"] = "Data Lake Store Accounts"
    endpoint_map[
        "az_network_application-gateway_ssl-policy_show_--gateway-name_name_--resource-group_resourcegroup"
    ] = "Application Gateway SSL Policy"
    return endpoint_map


DATASET_NAME_MAP = load_collect_endpoint_name_map()


def display_name_for_dataset(filename):
    stem = Path(filename).stem
    normalized_stem = dataset_key_for_filename(filename)
    mapped_name = DATASET_NAME_MAP.get(normalized_stem)
    if mapped_name:
        return mapped_name
    return normalized_stem.replace("_", " ").strip().title()


def dataset_collection_metadata(filename):
    """Return human-facing collection-plane metadata for a dataset."""
    dataset_key = dataset_key_for_filename(filename)
    if dataset_key in {
        "azure_public_endpoint_topology",
        "azure_public_endpoint_topology_coverage",
    }:
        return {
            "source": "Azure",
            "workload": "Cross-service public endpoint topology",
            "api_channel": None,
        }
    graph_endpoint = GRAPH_ENDPOINTS_BY_OUTPUT.get(dataset_key)
    if graph_endpoint is not None:
        return {
            "source": "Microsoft Graph",
            "workload": GRAPH_PROFILE_LABELS.get(
                graph_endpoint["profile"], graph_endpoint["profile"]
            ),
            "api_channel": graph_endpoint["api"],
        }
    if dataset_key.startswith(COLLECTION_MANIFEST_PREFIX):
        return {
            "source": "Collection metadata",
            "workload": "Collection manifest",
            "api_channel": None,
        }
    if (
        dataset_key.startswith("graph_")
        or "graph.microsoft.com" in dataset_key
        or dataset_key.startswith("az_rest_--url_graph_")
        or dataset_key.startswith("az_ad_")
    ):
        return {
            "source": "Microsoft Graph",
            "workload": "Historical Graph dataset",
            "api_channel": None,
        }
    if dataset_key.startswith("az_"):
        return {
            "source": "Azure",
            "workload": "Azure inventory",
            "api_channel": None,
        }
    return {
        "source": "Assessment output",
        "workload": "Derived or supporting data",
        "api_channel": None,
    }


def dataset_key_for_filename(filename):
    return TIMESTAMP_SUFFIX_PATTERN.sub("", Path(filename).stem)


def extract_dataset_timestamp(filename):
    match = TIMESTAMP_SUFFIX_PATTERN.search(Path(filename).stem)
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), "%Y%m%d-%H%M%S")
    except ValueError:
        return None


def format_dataset_version_label(path):
    timestamp = extract_dataset_timestamp(path.name)
    if timestamp is None:
        return "Current"
    return timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")


def dataset_sort_key(path):
    timestamp = extract_dataset_timestamp(path.name)
    return (timestamp is not None, timestamp or datetime.min, path.name)


def build_dataset_version(path, data):
    return {
        "filename": path.name,
        "record_count": record_count_for_data(data) if data is not None else None,
        "label": format_dataset_version_label(path),
        "timestamp": extract_dataset_timestamp(path.name),
    }


def record_count_for_data(data):
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        if isinstance(data.get("value"), list):
            return len(data["value"])
        return 1 if data else 0
    return 0 if data is None else 1


def record_count_for_file(path):
    data = load_json_file(path)
    if data is None:
        return None
    return record_count_for_data(data)


def standard_data_files():
    return [
        path for path in sorted(DATA_DIR.glob("*.json"))
        if path.name not in FINDINGS_FILENAMES
        and not path.name.startswith(f"{COLLECTION_MANIFEST_PREFIX}_")
    ]


def dataset_groups(load_record_counts=False):
    groups = OrderedDict()
    for path in standard_data_files():
        key = dataset_key_for_filename(path.name)
        groups.setdefault(key, []).append(path)

    grouped_tabs = []
    for key, paths in groups.items():
        sorted_paths = sorted(paths, key=dataset_sort_key, reverse=True)
        versions = [build_dataset_version(path, None) for path in sorted_paths]
        if not versions:
            continue
        latest = versions[0]
        latest_record_count = record_count_for_file(sorted_paths[0]) if load_record_counts else None
        latest["record_count"] = latest_record_count
        collection_metadata = dataset_collection_metadata(latest["filename"])
        grouped_tabs.append({
            "dataset_key": key,
            "name": display_name_for_dataset(latest["filename"]),
            **collection_metadata,
            "filename": latest["filename"],
            "record_count": latest_record_count if latest_record_count is not None else "Loading...",
            "version_label": latest["label"],
            "versions": versions,
        })
    grouped_tabs.sort(
        key=lambda tab: (
            tab["name"].casefold(),
            tab["name"],
            tab["dataset_key"],
        )
    )
    return grouped_tabs


def search_all_datasets(query_text, page=1, page_size=GLOBAL_SEARCH_PAGE_SIZE):
    """Search every retained Data Viewer dataset while retaining one result page."""
    normalized_query = str(query_text or "").casefold()
    try:
        page = max(int(page), 1)
    except (TypeError, ValueError):
        page = 1
    try:
        page_size = max(int(page_size), 1)
    except (TypeError, ValueError):
        page_size = GLOBAL_SEARCH_PAGE_SIZE
    if not normalized_query:
        return {
            "query": "",
            "page": page,
            "page_size": page_size,
            "total": 0,
            "total_pages": 0,
            "files_searched": 0,
            "unreadable": 0,
            "results": [],
        }

    first_match = (page - 1) * page_size
    last_match = first_match + page_size
    total = 0
    files_searched = 0
    unreadable = 0
    results = []
    trailing_results = deque(maxlen=page_size)

    for group in dataset_groups(load_record_counts=False):
        for version in group["versions"]:
            path = DATA_DIR / version["filename"]
            if path.is_symlink() or not path.is_file():
                unreadable += 1
                continue
            data = load_json_file(path)
            if data is None:
                unreadable += 1
                continue
            files_searched += 1
            for record_index, record in enumerate(
                ensure_horizontal_json_table_format(data),
                start=1,
            ):
                if normalized_query not in json.dumps(
                    record,
                    ensure_ascii=False,
                ).casefold():
                    continue
                result = {
                    "name": group["name"],
                    "source": group["source"],
                    "workload": group["workload"],
                    "version": version["label"],
                    "filename": version["filename"],
                    "record_number": record_index,
                    "record": record,
                    "viewer_url": (
                        f"/query/{quote(version['filename'], safe='')}"
                        f"?query={quote(str(query_text), safe='')}"
                    ),
                }
                trailing_results.append(result)
                if first_match <= total < last_match:
                    results.append(result)
                total += 1

    total_pages = (total + page_size - 1) // page_size
    if total_pages and page > total_pages:
        page = total_pages
        final_page_size = total % page_size or page_size
        results = list(trailing_results)[-final_page_size:]

    return {
        "query": str(query_text),
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
        "files_searched": files_searched,
        "unreadable": unreadable,
        "results": results,
    }


def dataset_group_by_filename(filename):
    key = dataset_key_for_filename(filename)
    for group in dataset_groups(load_record_counts=False):
        if group["dataset_key"] == key:
            return group
    return None


def latest_resource_object_count(tabs):
    for tab in tabs:
        if tab["dataset_key"] == "az_resource_list":
            return (
                "Loading...",
                "Objects in the latest Azure resource inventory",
                [tab["filename"]],
            )
    if not tabs:
        return "Unavailable", "No collected datasets were found", []
    return (
        "Unavailable",
        "The Azure resource inventory was not collected",
        [],
    )


def collection_manifest_paths():
    """Return available collection manifests from newest to oldest."""
    return sorted(
        (
            path for path in DATA_DIR.glob(
                f"{COLLECTION_MANIFEST_PREFIX}_*.json"
            )
            if path.is_file() and not path.is_symlink()
        ),
        key=dataset_sort_key,
        reverse=True,
    )


def collection_manifest_versions():
    return [
        {
            "filename": path.name,
            "label": format_dataset_version_label(path),
        }
        for path in collection_manifest_paths()
    ]


def collection_manifest_path(filename=None):
    paths = collection_manifest_paths()
    if not paths:
        return None
    if filename is None:
        return paths[0]
    return next((path for path in paths if path.name == filename), None)


def latest_collection_manifest():
    """Load the latest collection manifest without inferring request outcomes."""
    paths = collection_manifest_paths()
    if not paths:
        return None
    manifest = load_json_file(paths[0])
    if not isinstance(manifest, dict) or not isinstance(manifest.get("endpoint_runs"), list):
        return None
    return manifest


def finding_collection_run_ids(rows):
    """Return collection run IDs retained by flat finding provenance."""
    return sorted({
        str(run_id)
        for row in rows
        if isinstance(row, dict)
        for run_id in [
            (
                ((row.get("reporting") or {}).get("provenance") or {})
                .get("collection_run") or {}
            ).get("run_id")
        ]
        if run_id
    })


def manifest_for_finding_rows(
    rows,
    preferred_manifest=None,
):
    """Use only a manifest belonging to the collection represented by findings."""
    finding_run_ids = finding_collection_run_ids(rows)
    rows_without_run_id = sum(
        1
        for row in rows
        if not isinstance(row, dict)
        or not isinstance(
            ((row.get("reporting") or {}).get("provenance") or {}).get(
                "collection_run"
            ),
            dict,
        )
        or not (
            ((row.get("reporting") or {}).get("provenance") or {})
            .get("collection_run", {})
            .get("run_id")
        )
    )
    preferred_run_id = (
        preferred_manifest.get("run_id")
        if isinstance(preferred_manifest, dict)
        else None
    )
    if not rows and isinstance(preferred_manifest, dict):
        return preferred_manifest, {
            "status": "no_findings",
            "warning": None,
            "finding_run_ids": [],
            "manifest_run_id": preferred_run_id,
        }
    if rows_without_run_id:
        return {}, {
            "status": "unverifiable",
            "warning": (
                "One or more finding rows have no collection run ID. Endpoint-to-finding "
                "flows are withheld; regenerate findings from the collected data."
            ),
            "finding_run_ids": [],
            "manifest_run_id": preferred_run_id,
        }
    if len(finding_run_ids) != 1:
        return {}, {
            "status": "inconsistent",
            "warning": (
                "Finding rows refer to multiple collection runs. Endpoint-to-finding "
                "flows are withheld; regenerate one coherent findings output."
            ),
            "finding_run_ids": finding_run_ids,
            "manifest_run_id": preferred_run_id,
        }

    finding_run_id = finding_run_ids[0]
    if preferred_run_id == finding_run_id:
        return preferred_manifest, {
            "status": "matched",
            "warning": None,
            "finding_run_ids": finding_run_ids,
            "manifest_run_id": preferred_run_id,
        }
    for path in collection_manifest_paths():
        candidate = load_json_file(path)
        if isinstance(candidate, dict) and candidate.get("run_id") == finding_run_id:
            return candidate, {
                "status": "matched_historical",
                "warning": (
                    "The findings belong to an earlier collection run. The "
                    "endpoint-to-finding flow uses its matching manifest; regenerate "
                    "findings to assess the latest collection shown elsewhere."
                ),
                "finding_run_ids": finding_run_ids,
                "manifest_run_id": finding_run_id,
            }
    return {}, {
        "status": "manifest_missing",
        "warning": (
            "No collection manifest matches the findings run. Endpoint-to-finding "
            "flows are withheld; regenerate findings from the current collection."
        ),
        "finding_run_ids": finding_run_ids,
        "manifest_run_id": preferred_run_id,
    }


def graph_collection_summary(manifest=None):
    """Summarise Graph records and outcomes using manifest provenance."""
    manifest = latest_collection_manifest() if manifest is None else manifest
    empty_summary = {
        "selected_endpoints": 0,
        "endpoints_with_data": 0,
        "records_written": 0,
        "dataset_files": 0,
        "status_counts": {},
        "endpoints": [],
    }
    if not isinstance(manifest, dict):
        return {
            **empty_summary,
            "outcome": "Manifest unavailable",
            "message": (
                "No collection manifest is available, so Microsoft Graph "
                "collection cannot be verified from this assessment output."
            ),
        }
    graph_runs = [
        item for item in manifest.get("endpoint_runs", [])
        if isinstance(item, dict)
        and item.get("category") == "microsoft_graph"
    ]
    if not graph_runs:
        return {
            **empty_summary,
            "outcome": "Not recorded",
            "message": (
                "The latest manifest contains no Microsoft Graph endpoint "
                "outcomes. No Graph collection can be confirmed for this run."
            ),
        }

    graph_endpoint_ids = {
        str(item.get("endpoint_id"))
        for item in graph_runs if item.get("endpoint_id")
    }
    graph_datasets = []
    for dataset in manifest.get("datasets", []):
        if not isinstance(dataset, dict):
            continue
        source_ids = dataset.get("source_endpoint_ids") or [
            dataset.get("source_endpoint_id")
        ]
        if any(str(source_id) in graph_endpoint_ids for source_id in source_ids):
            graph_datasets.append(dataset)

    status_counts = Counter(str(item.get("status") or "unknown") for item in graph_runs)
    problem_statuses = {
        "failed", "incomplete", "unauthorised", "tenant_unavailable",
        "not_attempted",
    }

    def record_count(value):
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError):
            return 0

    records_written = sum(
        record_count(dataset.get("record_count")) for dataset in graph_datasets
    )
    available_dataset_filenames = {
        path.name for path in standard_data_files()
    }
    endpoint_rows = []
    for item in graph_runs:
        context = (
            item.get("parameter_context")
            if isinstance(item.get("parameter_context"), dict) else {}
        )
        endpoint_definition = (
            GRAPH_ENDPOINTS_BY_OUTPUT.get(item.get("endpoint_id"))
            or GRAPH_ENDPOINTS_BY_ID.get(item.get("endpoint_id"))
        )
        profile = context.get("profile")
        api_channel = context.get("api_channel")
        if endpoint_definition is not None:
            profile = profile or endpoint_definition.get("profile")
            api_channel = api_channel or endpoint_definition.get("api")
        profile = GRAPH_PROFILE_LABELS.get(profile, profile)
        output_files = [
            {
                "filename": filename,
                "name": display_name_for_dataset(filename),
            }
            for filename in item.get("output_files", [])
            if filename in available_dataset_filenames
        ]
        endpoint_rows.append(
            {
                "name": item.get("endpoint_name") or "Unknown Graph endpoint",
                "profile": profile or "Unknown workload",
                "api_channel": api_channel or "Unknown",
                "status": item.get("status") or "unknown",
                "record_count": item.get("result_count"),
                "output_files": output_files,
                "message": (
                    item.get("response_error")
                    or item.get("error")
                    or ""
                ),
            }
        )
    endpoint_rows.sort(key=lambda item: (str(item["profile"]), str(item["name"])))
    has_problem = any(
        str(item.get("status") or "unknown") in problem_statuses
        or (
            item.get("status") == "skipped"
            and item.get("reason_code") not in {
                "upstream_source_returned_no_data",
                "no_applicable_source_records",
            }
        )
        for item in graph_runs
    )
    if has_problem:
        outcome = (
            "Partial — data retained"
            if records_written else "Partial — no data retained"
        )
    else:
        outcome = (
            "Complete — data collected"
            if records_written else "Complete — no records returned"
        )
    return {
        "selected_endpoints": len(graph_runs),
        "endpoints_with_data": sum(
            1 for item in graph_runs if record_count(item.get("result_count")) > 0
        ),
        "records_written": records_written,
        "dataset_files": len(graph_datasets),
        "outcome": outcome,
        "status_counts": dict(sorted(status_counts.items())),
        "endpoints": endpoint_rows,
        "message": (
            "These figures come from the latest collection manifest and show "
            "whether Microsoft Graph returned assessment data. Friendly "
            "workload and endpoint names are used throughout."
        ),
    }


def endpoint_omission_reason(request_record):
    """Return a stable reason code and label for an omitted endpoint."""
    reason_code = str(request_record.get("reason_code") or "")
    if not reason_code:
        message = str(request_record.get("error") or "")
        if request_record.get("status") == "skipped" and message.startswith(
            "Missing required parameters:"
        ):
            reason_code = "legacy_missing_required_parameters"
        elif request_record.get("status") == "skipped" and message.startswith(
            "Missing usable parameter records from source:"
        ):
            reason_code = "legacy_no_usable_parameter_records"
        else:
            reason_code = "legacy_reason_unavailable"
    return reason_code, OMISSION_REASON_LABELS.get(
        reason_code,
        reason_code.replace("_", " ").title(),
    )


def collection_category_label(value):
    category = str(value or "Unknown")
    return "Microsoft Graph" if category == "microsoft_graph" else category


def endpoint_family_label(category):
    """Collapse execution categories into readable Sankey endpoint families."""
    category = str(category or "")
    if category == "microsoft_graph":
        return "Microsoft Graph Endpoints"
    if category in {"base", "parameterised"}:
        return "Base Endpoints"
    if category:
        return "Other Endpoints"
    return "Unattributed Endpoint"


def declared_endpoint_families(source_type):
    """Return Sankey endpoint families for a check with no recorded execution."""
    if source_type == "Base":
        return ["Base Endpoints"]
    if source_type == "Graph":
        return ["Microsoft Graph Endpoints"]
    if source_type == "Either":
        return ["Base or Microsoft Graph Endpoints"]
    if source_type == "BaseAndGraph":
        return ["Base Endpoints", "Microsoft Graph Endpoints"]
    return []


def collection_outcome(request_record, schema_version=None):
    """Return the presentation status and mutually exclusive outcome key."""
    status = str(request_record.get("status") or "")
    response_message = request_record.get("response_error") or request_record.get(
        "error"
    )
    if status == "failed" and is_not_applicable_error(response_message):
        status = "not_applicable"
    if status in {"failed", "unauthorised"} and is_tenant_unavailable_error(
        request_record.get("error_code") or response_message
    ):
        status = "tenant_unavailable"
    outcome = status if status in COLLECTION_OUTCOME_OPTIONS else "unknown"
    visibility_status = None
    if status == "empty":
        visibility_status = interpreted_visibility_status(
            schema_version,
            request_record.get("access_verification"),
        )
        if visibility_status not in {
            "access_verified",
            "scope_restricted",
            "visibility_unverified",
        }:
            visibility_status = "visibility_unverified"
        outcome = f"empty_{visibility_status}"
    return status, outcome, visibility_status


def required_endpoint_outcome_labels(endpoint):
    """Translate aggregated finding provenance statuses into chart outcomes."""
    labels = []
    visibility_statuses = set(endpoint.get("visibility_statuses") or [])
    for status in endpoint.get("statuses") or ["not_attempted"]:
        if status == "empty":
            if "scope_restricted" in visibility_statuses:
                outcome = "empty_scope_restricted"
            elif "access_verified" in visibility_statuses:
                outcome = "empty_access_verified"
            else:
                outcome = "empty_visibility_unverified"
        else:
            outcome = str(status)
        labels.append(
            COLLECTION_OUTCOME_OPTIONS.get(
                outcome,
                COLLECTION_OUTCOME_OPTIONS["unknown"],
            )[0]
        )
    return labels


def grouped_endpoint_omissions(records):
    """Group omitted endpoint definitions by their structured operational reason."""
    groups = {}
    for record in records:
        reason_code, reason_label = endpoint_omission_reason(record)
        key = (str(record.get("status") or "unknown"), reason_code)
        group = groups.setdefault(
            key,
            {
                "status": key[0],
                "reason_code": reason_code,
                "reason_label": reason_label,
                "count": 0,
                "endpoints": [],
                "details": [],
            },
        )
        group["count"] += 1
        endpoint_name = str(record.get("endpoint_name") or "Unknown")
        category = collection_category_label(record.get("category"))
        group["endpoints"].append(f"{endpoint_name} ({category})")
        detail = str(record.get("error") or "No reason was recorded")
        reason_details = record.get("reason_details")
        if isinstance(reason_details, dict) and reason_details:
            detail += f" | {json.dumps(reason_details, sort_keys=True, default=str)}"
        group["details"].append(detail)

    for group in groups.values():
        group["endpoints"] = sorted(set(group["endpoints"]), key=str.casefold)
        group["details"] = sorted(set(group["details"]), key=str.casefold)
    return sorted(
        groups.values(),
        key=lambda item: (item["status"], item["reason_label"].casefold()),
    )


def collection_request_summary(manifest=None):
    """Summarise mutually exclusive request and non-attempt outcomes."""
    manifest = latest_collection_manifest() if manifest is None else manifest
    if manifest is None:
        return None
    status_counts = Counter()
    endpoint_results = []
    successes = []
    failures = []
    omissions = []
    empty_visibility_counts = Counter()
    outcome_counts = Counter()
    category_outcome_counts = {}
    available_dataset_filenames = {path.name for path in standard_data_files()}
    for request_record in manifest.get("endpoint_runs", []):
        if not isinstance(request_record, dict):
            continue
        # Local Azure CLI configuration commands do not call an Azure service
        # endpoint and therefore do not belong in request-health statistics.
        if str(request_record.get("category") or "") == "setup":
            continue
        response_message = (
            request_record.get("response_error")
            or request_record.get("error")
        )
        status, outcome, visibility_status = collection_outcome(
            request_record,
            manifest.get("schema_version"),
        )
        status_counts[status] += 1
        if visibility_status:
            empty_visibility_counts[visibility_status] += 1
        outcome_counts[outcome] += 1
        category = collection_category_label(request_record.get("category"))
        category_outcome_counts.setdefault(category, Counter())[outcome] += 1
        parameter_context = (
            request_record.get("parameter_context")
            if isinstance(request_record.get("parameter_context"), dict)
            else {}
        )
        endpoint_definition = (
            GRAPH_ENDPOINTS_BY_OUTPUT.get(request_record.get("endpoint_id"))
            or GRAPH_ENDPOINTS_BY_ID.get(request_record.get("endpoint_id"))
        )
        workload = parameter_context.get("profile")
        api_channel = parameter_context.get("api_channel")
        if endpoint_definition is not None:
            workload = workload or endpoint_definition.get("profile")
            api_channel = api_channel or endpoint_definition.get("api")
        workload = GRAPH_PROFILE_LABELS.get(workload, workload)
        endpoint_result = {
            "endpoint_name": request_record.get("endpoint_name") or "Unknown",
            "category": category,
            "status": status,
            "outcome_label": COLLECTION_OUTCOME_OPTIONS.get(
                outcome,
                COLLECTION_OUTCOME_OPTIONS["unknown"],
            )[0],
            "workload": workload or (
                "Azure" if category != "Microsoft Graph" else "Unknown"
            ),
            "api_channel": api_channel or (
                "Azure CLI" if category != "Microsoft Graph" else "Unknown"
            ),
            "record_count": request_record.get("result_count"),
            "output_files": [
                {
                    "filename": filename,
                    "name": display_name_for_dataset(filename),
                }
                for filename in (request_record.get("output_files") or [])
                if isinstance(filename, str)
                and filename in available_dataset_filenames
            ],
            "error_code": (
                request_record.get("error_code")
                or extract_azure_error_code(response_message)
            ),
            "returncode": request_record.get("returncode"),
            "parameter_context": parameter_context,
            "message": response_message,
            "message_truncated": bool(
                request_record.get("response_error_truncated")
            ),
        }
        endpoint_results.append(endpoint_result)
        if status in {"success", "empty"}:
            successes.append(endpoint_result)
        if status in {"skipped", "not_attempted"}:
            omissions.append(request_record)
        if status not in {
            "failed", "incomplete", "unauthorised", "tenant_unavailable",
        }:
            continue
        failures.append(endpoint_result)
    endpoint_results.sort(
        key=lambda item: (
            str(item["status"]),
            str(item["category"]),
            str(item["endpoint_name"]),
            json.dumps(item["parameter_context"], sort_keys=True, default=str),
        )
    )
    successes.sort(
        key=lambda item: (
            str(item["category"]),
            str(item["endpoint_name"]),
            json.dumps(item["parameter_context"], sort_keys=True, default=str),
        )
    )
    failures.sort(
        key=lambda item: (
            str(item["status"]),
            str(item["category"]),
            str(item["endpoint_name"]),
            json.dumps(item["parameter_context"], sort_keys=True, default=str),
        )
    )
    attempted = sum(
        status_counts[status]
        for status in (
            "success",
            "empty",
            "incomplete",
            "failed",
            "unauthorised",
            "tenant_unavailable",
            "not_applicable",
        )
    )
    endpoint_count = sum(outcome_counts.values())
    category_outcome_rows = []
    for category, counts in sorted(
        category_outcome_counts.items(), key=lambda item: item[0].casefold()
    ):
        category_outcome_rows.append(
            {
                "category": category,
                "total": sum(counts.values()),
                "outcomes": [
                    {
                        "key": key,
                        "label": COLLECTION_OUTCOME_OPTIONS[key][0],
                        "count": counts[key],
                    }
                    for key in COLLECTION_OUTCOME_OPTIONS
                    if counts[key]
                ],
            }
        )
    return {
        "endpoint_count": endpoint_count,
        "outcome_counts": outcome_counts,
        "category_outcome_rows": category_outcome_rows,
        "attempted": attempted,
        "success": status_counts["success"],
        "empty": status_counts["empty"],
        "empty_access_verified": empty_visibility_counts["access_verified"],
        "empty_scope_restricted": empty_visibility_counts["scope_restricted"],
        "empty_visibility_unverified": empty_visibility_counts[
            "visibility_unverified"
        ],
        "failed": status_counts["failed"],
        "incomplete": status_counts["incomplete"],
        "unauthorised": status_counts["unauthorised"],
        "tenant_unavailable": status_counts["tenant_unavailable"],
        "not_applicable": status_counts["not_applicable"],
        "skipped": status_counts["skipped"],
        "not_attempted": status_counts["not_attempted"],
        "unattempted": status_counts["skipped"] + status_counts["not_attempted"],
        "successes": successes,
        "failures": failures,
        "base_endpoint_results": [
            item for item in endpoint_results
            if item["category"] != "Microsoft Graph"
        ],
        "graph_endpoint_results": [
            item for item in endpoint_results
            if item["category"] == "Microsoft Graph"
        ],
        "omission_groups": grouped_endpoint_omissions(omissions),
        "skipped_reason_counts": Counter(
            endpoint_omission_reason(record)[0]
            for record in omissions
            if record.get("status") == "skipped"
        ),
    }


def finding_check_classification(row, status, outcome_key):
    """Return the check-stage and final result labels for dashboard accounting."""
    if status in {"found", "not_found"}:
        check_status = "Assessed"
    elif status == "no_data_to_assess":
        check_status = "No Data to Assess"
    elif status == "not_implemented":
        check_status = "Not Implemented"
    elif status == "manual_assessment_required":
        check_status = "Awaiting Analyst Assessment"
    else:
        check_status = "Unknown Check Status"

    if status == "found":
        result = "Failed"
    elif status == "not_found":
        result = "Passed"
    elif status == "no_data_to_assess" and outcome_key == "empty_upstream_source":
        result = "Nothing to Assess"
    else:
        result = "Could Not Assess"

    definition = row.get("definition") if isinstance(row, dict) else None
    category = definition.get("category") if isinstance(definition, dict) else None
    category = category or (row.get("category") if isinstance(row, dict) else None)
    check_group = f"{category} Finding Checks" if category else "Finding Checks"
    return check_group, check_status, result


def findings_summary(manifest=None):
    filepath = findings_flat_path()
    if not filepath.exists():
        return None
    data = load_json_file(filepath)
    if data is None:
        return None
    if isinstance(data, dict) and "rows" in data:
        rows = data["rows"]
    elif isinstance(data, list):
        rows = data
    else:
        return None

    counts = {
        "executed": len(rows),
        "found": 0,
        "not_found": 0,
        "no_data_to_assess": 0,
        "not_implemented": 0,
        "manual_assessment_required": 0,
        "insufficient_data_causes": Counter(),
        "chart_segments": Counter(),
        "sankey_paths": Counter(),
        "sankey_node_counts": Counter(),
        "sankey_relationship_count": 0,
    }
    preferred_manifest = latest_collection_manifest() if manifest is None else manifest
    manifest, collection_alignment = manifest_for_finding_rows(
        rows,
        preferred_manifest,
    )
    counts["collection_alignment"] = collection_alignment
    schema_version = manifest.get("schema_version") if isinstance(manifest, dict) else None
    endpoint_runs = []
    endpoint_runs_by_id = {}
    for run_index, endpoint_run in enumerate(
        manifest.get("endpoint_runs", []) if isinstance(manifest, dict) else []
    ):
        if (
            not isinstance(endpoint_run, dict)
            or endpoint_run.get("category") == "setup"
        ):
            continue
        endpoint_id = str(endpoint_run.get("endpoint_id") or "").casefold()
        status, outcome, _visibility = collection_outcome(
            endpoint_run,
            schema_version,
        )
        execution = {
            "run_index": run_index,
            "endpoint_id": endpoint_id,
            "family": endpoint_family_label(endpoint_run.get("category")),
            "status": status,
            "outcome": outcome,
            "outcome_label": COLLECTION_OUTCOME_OPTIONS.get(
                outcome,
                COLLECTION_OUTCOME_OPTIONS["unknown"],
            )[0],
        }
        endpoint_runs.append(execution)
        if endpoint_id:
            endpoint_runs_by_id.setdefault(endpoint_id, []).append(execution)
        counts["sankey_node_counts"][(
            0,
            execution["family"],
            "endpoint executions",
        )] += 1
        counts["sankey_node_counts"][(
            1,
            execution["outcome_label"],
            "endpoint executions",
        )] += 1

    linked_run_indexes = set()
    for row in rows:
        status = canonical_finding_status(row.get("status") if isinstance(row, dict) else None)
        if status in counts:
            counts[status] += 1
        provenance = (
            row.get("reporting", {}).get("provenance", {})
            if isinstance(row, dict) else {}
        )
        required_endpoints = provenance.get("required_endpoints") or []
        outcome_key = "missing_source"
        if status == "found":
            outcome_key = "findings_raised"
        elif status == "not_found":
            outcome_key = "checks_passed"
        elif status == "manual_assessment_required":
            outcome_key = "manual_assessment_required"
        if status == "no_data_to_assess" and isinstance(row, dict):
            insufficient_data = provenance.get("insufficient_data")
            cause = (
                insufficient_data.get("cause")
                if isinstance(insufficient_data, dict)
                else None
            )
            if cause not in INSUFFICIENT_DATA_CAUSES:
                cause = "missing_or_unattributed_source"
            counts["insufficient_data_causes"][cause] += 1
            outcome_key = INSUFFICIENT_DATA_CHART_OUTCOMES[cause]

        segment_label, segment_color = FINDING_CHART_OUTCOMES[outcome_key]
        counts["chart_segments"][(outcome_key, segment_label, segment_color)] += 1
        manual_assessment = status == "manual_assessment_required"
        if manual_assessment:
            check_group, check_status, _finding_result = finding_check_classification(
                row,
                status,
                outcome_key,
            )
            finding_result = None
            result_color = "#446df6"
            counts["sankey_node_counts"][(
                2,
                check_group,
                "finding checks",
            )] += 1
            counts["sankey_node_counts"][(
                3,
                check_status,
                "manual assessment items",
            )] += 1
        else:
            check_group, check_status, finding_result = finding_check_classification(
                row,
                status,
                outcome_key,
            )
            result_color = FINDING_RESULT_OPTIONS[finding_result]
            counts["sankey_node_counts"][(2, check_group, "finding checks")] += 1
            counts["sankey_node_counts"][(3, check_status, "finding checks")] += 1
            counts["sankey_node_counts"][(4, finding_result, "finding checks")] += 1

        insufficient_data = provenance.get("insufficient_data")
        root_cause_ids = (
            insufficient_data.get("root_cause_endpoint_ids") or []
            if isinstance(insufficient_data, dict)
            else []
        )
        endpoint_records = [
            endpoint for endpoint in required_endpoints
            if isinstance(endpoint, dict)
        ]
        endpoint_ids = {
            str(endpoint_id).casefold()
            for endpoint_id in root_cause_ids
            if endpoint_id
        }
        if not endpoint_ids:
            endpoint_ids = {
                str(endpoint.get("endpoint_id")).casefold()
                for endpoint in endpoint_records
                if endpoint.get("endpoint_id")
            }

        relationships = []
        for endpoint_id in sorted(endpoint_ids):
            for execution in endpoint_runs_by_id.get(endpoint_id, []):
                relationships.append((execution["family"], execution["outcome_label"]))
                linked_run_indexes.add(execution["run_index"])

        if not relationships and endpoint_records:
            for endpoint in endpoint_records:
                family = endpoint_family_label(endpoint.get("category"))
                for outcome_label in required_endpoint_outcome_labels(endpoint):
                    relationships.append((family, outcome_label))

        if not relationships:
            declared_families = declared_endpoint_families(
                provenance.get("endpoint_source_type")
            )
            if declared_families:
                relationships.extend(
                    (family, "Endpoint Not Recorded")
                    for family in declared_families
                )
                for family in declared_families:
                    counts["sankey_node_counts"][(
                        0,
                        family,
                        "finding checks with an unrecorded required endpoint",
                    )] += 1
                    counts["sankey_node_counts"][(
                        1,
                        "Endpoint Not Recorded",
                        "finding checks with an unrecorded required endpoint",
                    )] += 1
            else:
                relationships.append(
                    ("Unattributed Endpoint", "Unattributed Check Source")
                )
                counts["sankey_node_counts"][(
                    0,
                    "Unattributed Endpoint",
                    "unattributed finding checks",
                )] += 1
                counts["sankey_node_counts"][(
                    1,
                    "Unattributed Check Source",
                    "unattributed finding checks",
                )] += 1

        for family, endpoint_status in relationships:
            path = (
                (family, endpoint_status, check_group, check_status)
                if manual_assessment
                else (
                    family,
                    endpoint_status,
                    check_group,
                    check_status,
                    finding_result,
                )
            )
            counts["sankey_paths"][(path, result_color)] += 1
            counts["sankey_relationship_count"] += 1

    for execution in endpoint_runs:
        if execution["run_index"] in linked_run_indexes:
            continue
        assessment_role = endpoint_assessment_role(execution["endpoint_id"])
        if assessment_role == SUPPORTING:
            terminal = "Supporting Endpoint Execution — Not Assessed"
            unit = "supporting endpoint executions"
        elif assessment_role == MANUAL:
            terminal = "No Linked Finding Check"
            unit = "manual endpoint executions without a review item"
        elif assessment_role == CONTEXT:
            terminal = "Context or Inventory — No Assessment"
            unit = "context-only endpoint executions"
        else:
            terminal = "No Linked Finding Check"
            unit = "endpoint executions"
        path = (
            execution["family"],
            execution["outcome_label"],
            terminal,
        )
        counts["sankey_paths"][(path, "#adb5bd")] += 1
        counts["sankey_node_counts"][(
            2,
            terminal,
            unit,
        )] += 1
    return counts


def build_dashboard_summary_cards(tabs, findings=None, collection_requests=None):
    object_count, object_detail, object_count_filenames = latest_resource_object_count(tabs)
    total_versions = sum(len(tab["versions"]) for tab in tabs)
    historical_versions = sum(max(len(tab["versions"]) - 1, 0) for tab in tabs)
    latest_collection = None
    for tab in tabs:
        timestamp = tab["versions"][0]["timestamp"]
        if timestamp is not None and (latest_collection is None or timestamp > latest_collection):
            latest_collection = timestamp

    collection_cards = [
        {
            "label": "Azure Resources Discovered",
            "value": object_count,
            "detail": object_detail,
            "count_filenames": object_count_filenames,
        },
        {"label": "Dataset Families", "value": len(tabs), "detail": "Distinct types of collected assessment data"},
        {
            "label": "Dataset Snapshots",
            "value": total_versions,
            "detail": f"{len(tabs)} latest and {historical_versions} earlier snapshots",
        },
        {
            "label": "Latest Collection",
            "value": latest_collection.strftime("%Y-%m-%d %H:%M:%S") if latest_collection else "Unknown",
            "detail": "Most recent timestamp among collected datasets",
        },
    ]

    finding_cards = []
    if findings is not None:
        finding_cards.extend([
            {"label": "Finding and Review Items", "value": findings["executed"], "detail": "Automated checks and manual assessment items with a recorded outcome"},
            {"label": "Findings Raised", "value": findings["found"], "detail": "Checks that identified an issue"},
            {"label": "Checks Passed", "value": findings["not_found"], "detail": "Checks that did not identify an issue"},
            {"label": "Checks Without Sufficient Data", "value": findings["no_data_to_assess"], "detail": "Checks that could not assess the required evidence"},
            {"label": "Manual Assessment Required", "value": findings["manual_assessment_required"], "detail": "Collected context that requires tenant-aware analyst judgement"},
            {"label": "Checks Not Implemented", "value": findings["not_implemented"], "detail": "Defined checks without an implemented assessment"},
        ])

    request_cards = None
    if collection_requests is not None:
        skipped_reasons = collection_requests["skipped_reason_counts"]
        skipped_unauthorised = skipped_reasons["upstream_source_unauthorised"]
        skipped_tenant = skipped_reasons["upstream_source_tenant_unavailable"]
        skipped_empty = skipped_reasons["upstream_source_returned_no_data"]
        skipped_other = max(
            0,
            collection_requests["skipped"]
            - skipped_unauthorised
            - skipped_tenant
            - skipped_empty,
        )
        request_cards = {
            "attempts": [
                {
                    "label": "Total Attempts",
                    "value": collection_requests["attempted"],
                    "detail": "Requests made to Azure or Microsoft Graph with a recorded outcome",
                },
                {
                    "label": "Returned Data",
                    "value": collection_requests["success"],
                    "detail": "Requests completed successfully and returned one or more records",
                },
                {
                    "label": "Returned No Data — Access Verified",
                    "value": collection_requests["empty_access_verified"],
                    "detail": "Empty responses where the required access and intended scope were verified",
                },
                {
                    "label": "Returned No Data — Scope Restricted",
                    "value": collection_requests["empty_scope_restricted"],
                    "detail": "Empty responses where verified access covered less than the endpoint's intended scope",
                },
                {
                    "label": "Returned No Data — Visibility Unverified",
                    "value": collection_requests["empty_visibility_unverified"],
                    "detail": "Empty responses where complete visibility could not be demonstrated",
                },
                {
                    "label": "Incomplete",
                    "value": collection_requests["incomplete"],
                    "detail": "Requests retained partial data but did not complete",
                },
                {
                    "label": "Failed",
                    "value": collection_requests["failed"],
                    "detail": "Requests returned a non-authorisation error",
                },
                {
                    "label": "Unauthorised",
                    "value": collection_requests["unauthorised"],
                    "detail": "Requests returned a permission-related error",
                },
                {
                    "label": "Tenant Capability Unavailable",
                    "value": collection_requests["tenant_unavailable"],
                    "detail": "Requests were blocked by tenant licensing or service capability",
                },
                {
                    "label": "Not Applicable",
                    "value": collection_requests["not_applicable"],
                    "detail": "The service reported that the requested workload or scope was not applicable",
                },
            ],
            "skipped": [
                {
                    "label": "Total Skipped",
                    "value": collection_requests["skipped"],
                    "detail": "Endpoint definitions deliberately not attempted for a recorded reason",
                },
                {
                    "label": "Unauthorised Prerequisite",
                    "value": skipped_unauthorised,
                    "detail": "Skipped because a required upstream request was unauthorised",
                },
                {
                    "label": "Tenant Capability Prerequisite",
                    "value": skipped_tenant,
                    "detail": "Skipped because a required upstream tenant capability was unavailable",
                },
                {
                    "label": "Empty Prerequisite",
                    "value": skipped_empty,
                    "detail": "Skipped because a required upstream request returned no records",
                },
                {
                    "label": "Other Recorded Reason",
                    "value": skipped_other,
                    "detail": "Skipped for another recorded reason",
                },
            ],
            "unrecorded": [
                {
                    "label": "Total Without Recorded Outcome",
                    "value": collection_requests["not_attempted"],
                    "detail": "Planned endpoint definitions with no request or deliberate skip outcome",
                },
            ],
        }
    return {
        "collection": collection_cards,
        "findings": finding_cards,
        "requests": request_cards,
    }


def findings_flat_path():
    return DATA_DIR / FINDINGS_FLAT_FILENAME


def findings_review_path():
    return DATA_DIR / FINDINGS_REVIEW_FILENAME


def findings_sarif_path():
    current = DATA_DIR / FINDINGS_SARIF_FILENAME
    if current.exists():
        return current
    legacy = DATA_DIR / LEGACY_FINDINGS_SARIF_FILENAME
    return legacy if legacy.exists() else current


def load_flat_finding_rows():
    """Load and validate the current flat findings envelope."""
    filepath = findings_flat_path()
    data = load_json_file(filepath)
    if data is None:
        raise ValueError(f"Could not load findings from {filepath}")
    if isinstance(data, dict):
        data = data.get("rows")
    if not isinstance(data, list) or not all(isinstance(row, dict) for row in data):
        raise ValueError("Flat findings data must contain a rows list of objects")

    rows = copy.deepcopy(data)
    finding_ids = []
    for row in rows:
        finding_id = row.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id:
            raise ValueError("Every flat finding row must have a finding_id")
        if len(finding_id) > MAX_FINDING_ID_LENGTH:
            raise ValueError("A flat finding_id exceeds the supported length")
        finding_ids.append(finding_id)
        row["status"] = canonical_finding_status(row.get("status"))
    if len(finding_ids) != len(set(finding_ids)):
        raise ValueError("Flat findings data contains duplicate finding_id values")
    return rows


def load_effective_finding_rows():
    """Apply persisted analyst decisions to the current flat findings rows."""
    rows = load_flat_finding_rows()
    review_path = findings_review_path()
    overrides = load_review_overrides(review_path) if review_path.exists() else {}
    rows_by_id = {row["finding_id"]: row for row in rows}
    retired_manual_ids = {
        re.sub(
            r"[^a-z0-9]+",
            "_",
            f"manual_assessment_required_{endpoint_id}".lower(),
        ).strip("_")
        for endpoint_id in RETIRED_CATCH_ALL_MANUAL_ENDPOINTS
    }
    unknown_ids = sorted(
        set(overrides) - set(rows_by_id) - retired_manual_ids
    )
    if unknown_ids:
        raise ValueError(
            "Review file contains unknown finding IDs: " + ", ".join(unknown_ids)
        )

    for row in rows:
        override = overrides.get(row["finding_id"])
        if override is not None:
            apply_review_override(row, override)
        elif row.get("review"):
            validate_finding_review(row)
        else:
            apply_review_override(row)
    return rows, overrides


def review_override_from_effective_review(row, reviewer, confirmed):
    """Create a minimal override without dropping existing analyst metadata."""
    review = row.get("review") if isinstance(row.get("review"), dict) else {}
    analyst = review.get("analyst") if isinstance(review.get("analyst"), dict) else {}
    override = {
        "finding_id": row["finding_id"],
        "disposition": (
            "confirmed"
            if confirmed
            else "inconclusive"
            if row.get("status") == "manual_assessment_required"
            else "candidate"
        ),
        "reviewer": reviewer,
        "reviewed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    if analyst.get("notes") is not None:
        override["notes"] = analyst["notes"]
    if isinstance(analyst.get("contextual_severity"), dict):
        override["contextual_severity"] = copy.deepcopy(
            analyst["contextual_severity"]
        )
    confidence = review.get("confidence")
    if isinstance(confidence, dict) and confidence.get("source") == "analyst":
        rationale = confidence.get("rationale") or []
        override["confidence"] = {
            "level": confidence.get("level"),
            "rationale": "\n".join(rationale),
        }
    return override


def confirmed_finding_rows(rows):
    """Return exportable findings carrying an analyst confirmation."""
    return [
        row
        for row in rows
        if row.get("status") in VALIDATABLE_FINDING_STATUSES
        and isinstance(row.get("review"), dict)
        and row["review"].get("disposition") == "confirmed"
    ]


def manual_assessment_sarif_rule(row):
    """Build a SARIF rule for a confirmed manual assessment item."""
    finding_id = row["finding_id"]
    title = str(row.get("title") or finding_id)
    definition = copy.deepcopy(row.get("definition") or {})
    return {
        "id": finding_id,
        "name": title,
        "shortDescription": {"text": title},
        "fullDescription": {
            "text": "Collected evidence was reviewed and validated by an analyst."
        },
        "defaultConfiguration": {"level": "note"},
        "properties": {
            "finding_id": finding_id,
            "definition": definition,
            "manual_assessment": copy.deepcopy(
                row.get("manual_assessment") or {}
            ),
            "severity": row.get("severity") or "Informational",
            "headline_ids": definition.get("check_ids") or [],
            "assessment_status": "manual_assessment_required",
        },
    }


def manual_assessment_sarif_result(row):
    """Build a SARIF review result from one confirmed flat manual item."""
    finding_id = row["finding_id"]
    title = str(row.get("title") or finding_id)
    record_count = row.get("count") if isinstance(row.get("count"), int) else 0
    properties = {
        "finding_id": finding_id,
        "definition": copy.deepcopy(row.get("definition") or {}),
        "reporting": copy.deepcopy(row.get("reporting") or {}),
        "context": copy.deepcopy(row.get("context") or {}),
        "coverage": copy.deepcopy(row.get("coverage") or {}),
        "review": copy.deepcopy(row.get("review") or {}),
        "triage": copy.deepcopy(row.get("triage") or {}),
        "manual_assessment": copy.deepcopy(
            row.get("manual_assessment") or {}
        ),
        "title": title,
        "severity": row.get("severity") or "Informational",
        "status": "manual_assessment_required",
        "reason": row.get("reason") or "",
        "record_count": record_count,
        "references": {"source_files": copy.deepcopy(row.get("source_file") or [])},
        "evidence": copy.deepcopy(row.get("evidence") or []),
    }
    return {
        "ruleId": finding_id,
        "level": "note",
        "kind": "review",
        "message": {
            "text": (
                f"{title} was validated by an analyst with {record_count} "
                "viewable source record(s)."
            )
        },
        "properties": properties,
    }


def build_validated_sarif(source, confirmed_rows):
    """Export confirmed findings and manual reviews as SARIF results."""
    if not isinstance(source, dict) or source.get("version") != "2.1.0":
        raise ValueError("Findings SARIF must be a SARIF 2.1.0 object")
    runs = source.get("runs")
    if not isinstance(runs, list) or not all(isinstance(run, dict) for run in runs):
        raise ValueError("Findings SARIF must contain a runs list")

    output = copy.deepcopy(source)
    confirmed_by_id = {row["finding_id"]: row for row in confirmed_rows}
    source_result_ids = set()
    for run in output["runs"]:
        results = run.get("results", [])
        if not isinstance(results, list) or not all(
            isinstance(result, dict) for result in results
        ):
            raise ValueError("Each findings SARIF run must contain a results list")
        for result in results:
            properties = result.get("properties")
            if properties is not None and not isinstance(properties, dict):
                raise ValueError(
                    "Each findings SARIF result properties value must be an object"
                )
            properties = properties or {}
            property_finding_id = properties.get("finding_id")
            rule_id = result.get("ruleId")
            if property_finding_id and rule_id and property_finding_id != rule_id:
                raise ValueError(
                    "A findings SARIF result has conflicting finding_id and ruleId values"
                )
            finding_id = property_finding_id or rule_id
            if finding_id:
                source_result_ids.add(finding_id)

    manual_rows = [
        row
        for row in confirmed_rows
        if row.get("status") == "manual_assessment_required"
        and row.get("finding_id") not in source_result_ids
    ]
    if manual_rows:
        if not output["runs"]:
            raise ValueError("Findings SARIF must contain a run for manual results")
        target_run = output["runs"][0]
        target_run.setdefault("results", []).extend(
            manual_assessment_sarif_result(row) for row in manual_rows
        )
        tool = target_run.get("tool")
        if tool is None:
            tool = target_run.setdefault("tool", {})
        if not isinstance(tool, dict):
            raise ValueError("Each findings SARIF run tool value must be an object")
        driver = tool.get("driver")
        if driver is None:
            driver = tool.setdefault("driver", {})
        if not isinstance(driver, dict):
            raise ValueError("Each findings SARIF driver must be an object")
        rules = driver.setdefault("rules", [])
        if not isinstance(rules, list) or not all(
            isinstance(rule, dict) for rule in rules
        ):
            raise ValueError("Each findings SARIF driver rules value must be a list")
        existing_rule_ids = {rule.get("id") for rule in rules}
        rules.extend(
            manual_assessment_sarif_rule(row)
            for row in manual_rows
            if row["finding_id"] not in existing_rule_ids
        )

    matched_ids = set()
    for run in output["runs"]:
        results = run.get("results", [])
        if not isinstance(results, list) or not all(
            isinstance(result, dict) for result in results
        ):
            raise ValueError("Each findings SARIF run must contain a results list")
        retained_results = []
        run_matched_ids = set()
        for result in results:
            properties = result.get("properties")
            if properties is not None and not isinstance(properties, dict):
                raise ValueError("Each findings SARIF result properties value must be an object")
            properties = properties or {}
            property_finding_id = properties.get("finding_id")
            rule_id = result.get("ruleId")
            if property_finding_id and rule_id and property_finding_id != rule_id:
                raise ValueError(
                    "A findings SARIF result has conflicting finding_id and ruleId values"
                )
            finding_id = property_finding_id or rule_id
            row = confirmed_by_id.get(finding_id)
            if row is None:
                continue
            if "properties" not in result:
                result["properties"] = {}
            result["properties"]["review"] = copy.deepcopy(row["review"])
            retained_results.append(result)
            matched_ids.add(finding_id)
            run_matched_ids.add(finding_id)
        run["results"] = retained_results
        run_found_count = sum(
            confirmed_by_id[finding_id].get("status") == "found"
            for finding_id in run_matched_ids
        )
        run_manual_count = sum(
            confirmed_by_id[finding_id].get("status")
            == "manual_assessment_required"
            for finding_id in run_matched_ids
        )

        tool = run.get("tool")
        if tool is not None and not isinstance(tool, dict):
            raise ValueError("Each findings SARIF run tool value must be an object")
        driver = (tool or {}).get("driver")
        if driver is not None and not isinstance(driver, dict):
            raise ValueError("Each findings SARIF tool driver must be an object")
        if isinstance(driver, dict):
            rules = driver.get("rules", [])
            if not isinstance(rules, list) or not all(
                isinstance(rule, dict) for rule in rules
            ):
                raise ValueError("Each findings SARIF driver rules value must be a list")
            retained_rule_ids = {
                result.get("ruleId") for result in retained_results if result.get("ruleId")
            }
            driver["rules"] = [
                rule
                for rule in rules
                if rule.get("id") in retained_rule_ids
            ]
        automation = run.get("automationDetails")
        if automation is not None and not isinstance(automation, dict):
            raise ValueError("Each findings SARIF automationDetails value must be an object")
        if isinstance(automation, dict):
            automation["description"] = {
                "text": (
                    "Azure findings and manual assessment items confirmed by "
                    "an analyst in azure-present."
                )
            }
        run_properties = run.get("properties")
        if run_properties is not None and not isinstance(run_properties, dict):
            raise ValueError("Each findings SARIF run properties value must be an object")
        run_properties = run.setdefault("properties", {})
        run_properties["result_origin"] = "azure-present confirmed assessment items"
        run_properties["validated_findings"] = len(run_matched_ids)
        run_properties["validated_raised_findings"] = run_found_count
        run_properties["validated_manual_assessments"] = run_manual_count
        invocations = run.get("invocations", [])
        if not isinstance(invocations, list) or not all(
            isinstance(invocation, dict) for invocation in invocations
        ):
            raise ValueError("Each findings SARIF run invocations value must be a list")
        for invocation in invocations:
            invocation_properties = invocation.get("properties")
            if invocation_properties is not None and not isinstance(
                invocation_properties, dict
            ):
                raise ValueError(
                    "Each findings SARIF invocation properties value must be an object"
                )
            invocation_properties = invocation.setdefault("properties", {})
            if "found_findings" in invocation_properties:
                invocation_properties["source_found_findings"] = (
                    invocation_properties["found_findings"]
                )
                invocation_properties["found_findings"] = run_found_count
            invocation_properties["validated_findings"] = len(run_matched_ids)
            invocation_properties["validated_raised_findings"] = run_found_count
            invocation_properties["validated_manual_assessments"] = (
                run_manual_count
            )

    missing_ids = sorted(set(confirmed_by_id) - matched_ids)
    if missing_ids:
        raise ValueError(
            "Confirmed findings were absent from the source SARIF: "
            + ", ".join(missing_ids)
        )
    output_properties = output.get("properties")
    if output_properties is not None and not isinstance(output_properties, dict):
        raise ValueError("Findings SARIF properties must be an object")
    output_properties = output.setdefault("properties", {})
    output_properties["validated_findings"] = len(matched_ids)
    output_properties["validated_raised_findings"] = sum(
        row.get("status") == "found" for row in confirmed_rows
    )
    output_properties["validated_manual_assessments"] = sum(
        row.get("status") == "manual_assessment_required"
        for row in confirmed_rows
    )
    return output


def missing_findings_message(filepath):
    data_dir = escape(str(DATA_DIR), quote=True)
    expected_path = escape(str(filepath), quote=True)
    return (
        f"<p>Findings data has not been generated for input directory "
        f"<code>{data_dir}</code>.</p>"
        f"<p>Expected file: <code>{expected_path}</code></p>"
        f"<p>Run <code>python azure-findings.py -i {data_dir}</code> and reload this page.</p>"
    )


def standard_data_file_map():
    return {path.name: path for path in standard_data_files()}


def dataset_count_payload(filenames):
    valid_files = standard_data_file_map()
    counts = {}
    errors = {}

    for filename in filenames:
        if filename in counts or filename in errors:
            continue
        path = valid_files.get(filename)
        if path is None:
            errors[filename] = "Unknown dataset file"
            continue

        record_count = record_count_for_file(path)
        if record_count is None:
            errors[filename] = "Could not load dataset file"
            continue
        counts[filename] = record_count

    return {"counts": counts, "errors": errors}


def canonical_finding_status(value):
    normalized = str(value or "").strip().lower().replace(" ", "_")
    if normalized in {"supported", "confirmed", "confirmed_findings"}:
        return "found"
    if normalized in {"not_evaluated", "unsupported", "unimplemented"}:
        return "not_implemented"
    return normalized


def normalize_findings_status_filter(value):
    if not value:
        return "found"
    normalized = canonical_finding_status(value)
    if normalized not in FINDING_STATUS_OPTIONS:
        return "found"
    return normalized


def filter_findings_by_status(data, status_filter):
    allowed_statuses = FINDING_STATUS_OPTIONS[status_filter]["statuses"]
    if allowed_statuses is None or not isinstance(data, list):
        return data
    return [item for item in data if canonical_finding_status(item.get("status")) in allowed_statuses]


def unique_non_empty_strings(values):
    """Return non-empty strings once, preserving their first-seen order."""
    return list(dict.fromkeys(
        value
        for value in values
        if isinstance(value, str) and value
    ))


def affected_entity_labels(row):
    """Return compact asset labels from a flat finding row."""
    reporting = row.get("reporting")
    assets = reporting.get("assets", []) if isinstance(reporting, dict) else []
    return unique_non_empty_strings(
        asset.get("name") or asset.get("identifier")
        for asset in assets
        if isinstance(asset, dict)
    )


def display_metadata_value(value, unavailable="Not available"):
    """Return a compact, readable label for a findings metadata value."""
    if value in (None, "", [], {}):
        return unavailable
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, str):
        return title_case_column_heading(value)
    return value


def first_summary_text(values):
    """Show one rationale without expanding a potentially long rationale list."""
    if isinstance(values, str):
        return values
    if not isinstance(values, list) or not values:
        return "Not recorded"
    first = str(values[0])
    return first if len(values) == 1 else f"{first} (+{len(values) - 1} more)"


def definition_display_summary(value):
    definition = value if isinstance(value, dict) else {}
    report = definition.get("report")
    report = report if isinstance(report, dict) else {}
    summary = OrderedDict(
        [
            ("Category", display_metadata_value(definition.get("category"))),
            ("Check IDs", definition.get("check_ids") or []),
            ("Narrative", display_metadata_value(report.get("narrative_status"))),
        ]
    )
    for label, key in (
        ("Description", "description"),
        ("Impact", "impact"),
        ("Recommendation", "recommendation"),
    ):
        if report.get(key):
            summary[label] = report[key]
    return summary


def manual_assessment_display_summary(value):
    definition = value if isinstance(value, dict) else {}
    return OrderedDict(
        [
            ("Review Question", definition.get("question") or "Not recorded"),
            ("Applicability", definition.get("applicability") or "Not recorded"),
            ("Why Judgement Is Required", definition.get("rationale") or "Not recorded"),
            ("Evidence Fields", definition.get("evidence_fields") or []),
            ("Possible Outcomes", definition.get("outcomes") or []),
        ]
    )


def reporting_display_summary(value):
    reporting = value if isinstance(value, dict) else {}
    provenance = reporting.get("provenance")
    provenance = provenance if isinstance(provenance, dict) else {}
    collection_run = provenance.get("collection_run")
    collection_run = collection_run if isinstance(collection_run, dict) else {}
    insufficient = provenance.get("insufficient_data")
    insufficient = insufficient if isinstance(insufficient, dict) else {}
    endpoint_source = provenance.get("endpoint_source_type")
    endpoint_source = {
        "BaseAndGraph": "Base and Graph",
    }.get(endpoint_source, endpoint_source)
    declaration_count = len(provenance.get("declared_endpoint_ids") or []) + len(
        provenance.get("declared_endpoint_patterns") or []
    )
    summary = OrderedDict(
        [
            ("Assets", len(reporting.get("assets") or [])),
            ("Observations", len(reporting.get("observations") or [])),
            ("Source Datasets", len(provenance.get("source_datasets") or [])),
            ("Required Endpoints", len(provenance.get("required_endpoints") or [])),
            ("Endpoint Source", display_metadata_value(endpoint_source)),
            ("Endpoint Declarations", declaration_count),
            ("Collection Run", display_metadata_value(collection_run.get("status"))),
            ("Limitations", len(provenance.get("limitations") or [])),
        ]
    )
    if insufficient:
        summary["Insufficient Data"] = display_metadata_value(
            insufficient.get("label") or insufficient.get("cause")
        )
    return summary


def context_display_summary(value):
    context = value if isinstance(value, dict) else {}
    family = context.get("family")
    family = family if isinstance(family, dict) else {}
    engagement = context.get("engagement")
    engagement = engagement if isinstance(engagement, dict) else {}
    scope = context.get("scope")
    scope = scope if isinstance(scope, dict) else {}
    subscriptions = engagement.get("subscriptions") or []
    selected_subscription_id = engagement.get("selected_subscription_id")
    selected_subscription = selected_subscription_id
    for subscription in subscriptions:
        if not isinstance(subscription, dict):
            continue
        if subscription.get("subscription_id") == selected_subscription_id:
            selected_subscription = subscription.get("name") or selected_subscription_id
            break
    return OrderedDict(
        [
            ("Azure Service", display_metadata_value(family.get("service_label"))),
            ("Control Plane", display_metadata_value(family.get("control_plane"))),
            ("Scope", display_metadata_value(scope.get("level"))),
            ("Tenants", len(engagement.get("tenant_ids") or [])),
            ("Selected Subscription", selected_subscription or "Not available"),
            ("Subscriptions In Scope", len(scope.get("subscription_ids") or [])),
            ("Affected Assets", scope.get("affected_asset_count", 0)),
            ("Limitations", len(context.get("limitations") or [])),
        ]
    )


def coverage_display_summary(value):
    coverage = value if isinstance(value, dict) else {}
    denominator = coverage.get("denominator")
    denominator = denominator if isinstance(denominator, dict) else {}
    affected = coverage.get("affected")
    affected = affected if isinstance(affected, dict) else {}
    percentage = coverage.get("affected_percentage")
    percentage_label = "Not available" if percentage is None else f"{percentage}%"
    eligible = denominator.get("value")
    unit = denominator.get("unit")
    eligible_label = "Not available" if eligible is None else f"{eligible} {unit or 'items'}"
    return OrderedDict(
        [
            ("Assessment", display_metadata_value(coverage.get("status"))),
            ("Eligible Population", eligible_label),
            ("Affected Assets", affected.get("assets", 0)),
            ("Affected Percentage", percentage_label),
            ("Limitations", len(coverage.get("limitations") or [])),
        ]
    )


def review_display_summary(value):
    review = value if isinstance(value, dict) else {}
    confidence = review.get("confidence")
    confidence = confidence if isinstance(confidence, dict) else {}
    analyst = review.get("analyst")
    analyst = analyst if isinstance(analyst, dict) else {}
    report_ready = review.get("report_ready")
    report_ready = report_ready if isinstance(report_ready, dict) else {}
    return OrderedDict(
        [
            ("Review State", display_metadata_value(review.get("review_state"))),
            ("Disposition", display_metadata_value(review.get("disposition"))),
            ("Confidence", display_metadata_value(confidence.get("level"))),
            ("Confidence Basis", first_summary_text(confidence.get("rationale"))),
            ("Reviewer", analyst.get("reviewer") or "Unassigned"),
            ("Report Inclusion", display_metadata_value(report_ready.get("include"))),
        ]
    )


def triage_display_summary(value):
    triage = value if isinstance(value, dict) else {}
    grouping = triage.get("grouping")
    grouping = grouping if isinstance(grouping, dict) else {}
    severity = triage.get("severity")
    severity = severity if isinstance(severity, dict) else {}
    deduplication = triage.get("deduplication")
    deduplication = deduplication if isinstance(deduplication, dict) else {}
    retest = triage.get("retest")
    retest = retest if isinstance(retest, dict) else {}
    return OrderedDict(
        [
            ("Contextual Severity", display_metadata_value(severity.get("contextual"))),
            ("Severity Changed", display_metadata_value(severity.get("changed"))),
            ("Observation Groups", len(grouping.get("observation_groups") or [])),
            ("Deduplication", display_metadata_value(deduplication.get("status"))),
            ("Duplicate Observations", deduplication.get("duplicate_observation_count", 0)),
            ("Retest", display_metadata_value(retest.get("outcome"))),
        ]
    )


FINDINGS_METADATA_SUMMARISERS = {
    "manual_assessment": manual_assessment_display_summary,
    "definition": definition_display_summary,
    "reporting": reporting_display_summary,
    "context": context_display_summary,
    "coverage": coverage_display_summary,
    "review": review_display_summary,
    "triage": triage_display_summary,
}


def prepare_findings_rows(data):
    """Build concise finding rows while retaining the full source for View JSON."""
    if not isinstance(data, list):
        return data

    prepared = []
    for item in data:
        if not isinstance(item, dict):
            prepared.append(item)
            continue

        source_row = dict(item)
        row = dict(item)
        for column in FINDINGS_LINK_COLUMNS:
            values = row.get(column)
            if isinstance(values, list):
                row[column] = unique_non_empty_strings(values)
        entities = row.get("affected_entities")
        if not isinstance(entities, list):
            entities = affected_entity_labels(row)
        row["affected_entities"] = unique_non_empty_strings(entities)
        if "manual_assessment" in row:
            row["manual_assessment"] = manual_assessment_display_summary(
                row["manual_assessment"]
            )
        for column in FINDINGS_METADATA_COLUMNS:
            if column in row:
                row[column] = FINDINGS_METADATA_SUMMARISERS[column](row[column])
        has_finding_id = "finding_id" in row
        finding_id = row.pop("finding_id", None)

        ordered = OrderedDict()
        for column in FINDINGS_PRIMARY_COLUMNS:
            if column in row:
                ordered[column] = row[column]
        for column, value in row.items():
            if column not in ordered:
                ordered[column] = value
        ordered[VIEW_JSON_SOURCE_ROW_KEY] = source_row
        if has_finding_id:
            ordered["finding_id"] = finding_id
        prepared.append(ordered)
    return prepared


def contains_nested_list_of_dicts(obj):
    if isinstance(obj, list):
        return any(
            isinstance(item, dict)
            or contains_nested_dict_or_list_of_dicts(item)
            for item in obj
        )

    return False


def ensure_horizontal_json_table_format(data, debug=False):
    """
    Ensures input is shaped as a list of dicts suitable for horizontal table rendering by json2html.
    Adds instrumentation for debugging.
    """
    def log(msg):
        if debug:
            print(f"[DEBUG] {msg}")

    log(f"Original data type: {type(data).__name__}")
    log(f"Original data preview: {repr(str(data)[:100])}")

    if isinstance(data, dict) and isinstance(data.get("value"), list):
        log("Detected: Collection response envelope — using its value records.")
        data = data["value"]

    # Case 1: Already a list of dicts
    if isinstance(data, list) and all(isinstance(row, dict) for row in data):
        log("Detected: List of dictionaries — passing through unchanged.")
        return data

    # Case 2: Single dictionary
    elif isinstance(data, dict):
        if not data:
            return []
        log("Detected: Single dictionary — wrapping in a list.")
        return [data]

    # Case 3: Flat list
    elif isinstance(data, list):
        log("Detected: Flat list — converting to list of dicts with index/value.")
        transformed = [{"index": i, "value": v} for i, v in enumerate(data)]
        log(f"Transformed data preview: {repr(transformed[:2])}")
        return transformed

    # Case 4: Scalar (string, int, bool, etc.)
    else:
        log("Detected: Scalar value — wrapping in list with key 'value'.")
        return [{"value": data}]


def has_consistent_keys(data, debug=False):
    """
    Returns True if all dictionaries in the list have the same keys.
    Also logs differences if debug is True.
    """
    if not isinstance(data, list) or not all(isinstance(d, dict) for d in data):
        if debug:
            print("[DEBUG] Input is not a list of dicts — cannot check key consistency.")
        return False

    if not data:
        return True

    keysets = [set(d.keys()) for d in data]
    base_keys = keysets[0]
    inconsistent = []

    for i, keys in enumerate(keysets[1:], start=1):
        if keys != base_keys:
            inconsistent.append((i, keys))

    if inconsistent:
        if debug:
            print(f"[DEBUG] Key inconsistency detected. Expected keys: {sorted(base_keys)}")
            for idx, keys in inconsistent:
                print(f"[DEBUG] Row {idx} keys: {sorted(keys)}")
        return False

    if debug:
        print("[DEBUG] All rows have consistent keys.")
    return True


def normalize_list_of_dicts(data, fill_value="n/a", debug=False):
    """
    Ensures all dictionaries in a list have the same keys.
    Adds missing keys with `fill_value`.
    Returns the normalized list.
    """
    if not isinstance(data, list) or not all(isinstance(d, dict) for d in data):
        raise ValueError("Input must be a list of dictionaries")

    # Find all unique keys
    all_keys = set()
    for d in data:
        all_keys.update(d.keys())

    if debug:
        print(f"[DEBUG] Union of all keys: {sorted(all_keys)}")

    # Add missing keys to each dict
    normalized = []
    for i, d in enumerate(data):
        norm = {k: d.get(k, fill_value) for k in all_keys}
        if debug:
            missing = [k for k in all_keys if k not in d]
            if missing:
                print(f"[DEBUG] Row {i} missing keys: {missing}")
        normalized.append(norm)

    return normalized


def encode_json_action_payload(row):
    """Encode one source record so HTML linkification cannot alter its JSON."""
    return quote(json.dumps(row), safe="")


def generate_html_table(original_data):
    """Convert any valid JSON shape to a consistent horizontal HTML table."""
    try:
        horizontal_data = ensure_horizontal_json_table_format(original_data)
        if not horizontal_data:
            return '<p class="data-table-empty">No records were returned.</p>'

        if not has_consistent_keys(horizontal_data):
            data_for_use = normalize_list_of_dicts(
                horizontal_data,
                "not in data",
            )
        else:
            data_for_use = horizontal_data

        data = []
        for row in data_for_use:
            source_row = row.get(VIEW_JSON_SOURCE_ROW_KEY, row)
            new_row = OrderedDict(
                [("json_string", encode_json_action_payload(source_row))]
            )
            new_row.update(
                (key, value)
                for key, value in row.items()
                if key != VIEW_JSON_SOURCE_ROW_KEY
            )
            data.append(new_row)

        html_table = json2html.convert(json=data)
        html_table = linkify_rendered_urls(html_table)
        return html_table
    except Exception as e:
        print(f"Error converting JSON to HTML: {e}")
        return "<p>Error displaying data.</p>"


def resource_label_from_id(resource_id):
    parts = [part for part in str(resource_id or "").strip("/").split("/") if part]
    if not parts:
        return None

    if len(parts) >= 2 and parts[-2].lower() != "providers":
        return f"{parts[-2]}/{parts[-1]}"
    return parts[-1]


def portal_link_label(url):
    parsed = urlparse(url)
    fragment = parsed.fragment or ""
    resource_marker = "resource/"
    if resource_marker in fragment:
        resource_path = fragment.split(resource_marker, 1)[1]
        if resource_path.endswith("/overview"):
            resource_path = resource_path[:-len("/overview")]
        label = resource_label_from_id(unquote(resource_path))
        if label:
            return label

    id_marker = "/id/"
    if id_marker in fragment:
        resource_path = fragment.split(id_marker, 1)[1]
        label = resource_label_from_id(unquote(resource_path))
        if label:
            return label

    return "Azure Portal"


def viewer_link_label(url):
    parsed = urlparse(url)
    filename = Path(unquote(parsed.path).removeprefix("/query/")).stem
    service = display_name_for_dataset(filename)
    query = parse_qs(parsed.query).get("query", [""])[0]
    query_label = resource_label_from_id(query) or query
    if query_label:
        return f"{service}: {query_label}"
    return service or "Data Viewer"


def label_for_url(url):
    if "portal.azure.com" in url:
        return portal_link_label(url)
    if url.startswith("/query/"):
        return viewer_link_label(url)
    return url


def linkify_rendered_urls(html):
    patterns = [
        re.compile(r'(?P<url>https?://[^\s<]+)'),
        re.compile(r'(?P<url>/query/[^\s<]+)'),
    ]

    def replace_anchor(match):
        url = match.group("url")
        label = label_for_url(url)
        return (
            f'<a href="{escape(url, quote=True)}" target="_blank" rel="noopener noreferrer">'
            f'{escape(label)}</a>'
        )

    updated = html
    for pattern in patterns:
        updated = pattern.sub(replace_anchor, updated)
    return updated


FINDINGS_LINK_COLLAPSE_THRESHOLD = 10
FINDINGS_LINK_LIST_PATTERN = re.compile(r"<td>(?P<list><ul>.*?</ul>)</td>", re.DOTALL)
ANCHOR_HREF_PATTERN = re.compile(r'<a\s+href="(?P<href>[^"]+)"')


def collapse_findings_link_cells(
    html: str,
    threshold: int = FINDINGS_LINK_COLLAPSE_THRESHOLD,
) -> str:
    """Collapse long Azure Portal and data-viewer link lists in findings cells."""
    def replace_link_list(match):
        list_html = match.group("list")
        hrefs = ANCHOR_HREF_PATTERN.findall(list_html)

        # Leave short lists and unrelated list cells exactly as json2html rendered them.
        if len(hrefs) <= threshold:
            return match.group(0)
        if not all(
            href.startswith("/query/") or href.startswith("https://portal.azure.com/")
            for href in hrefs
        ):
            return match.group(0)

        return (
            '<td><details class="findings-links-disclosure">'
            f'<summary>{len(hrefs)} links</summary>{list_html}'
            '</details></td>'
        )

    return FINDINGS_LINK_LIST_PATTERN.sub(replace_link_list, html)


def title_case_column_heading(name):
    """Convert a JSON field name to a compact title-cased table heading."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", str(name))
    words = re.split(r"[_\-\s]+", spaced.strip("_ -"))
    return " ".join(
        COLUMN_HEADING_ACRONYMS.get(word.lower(), word.capitalize())
        for word in words
        if word
    )


def prepare_top_level_headers(html, sortable=False):
    """Title-case top-level headers and optionally attach findings controls."""
    header_start = html.find("<thead>")
    header_end = html.find("</thead>", header_start)
    if header_start == -1 or header_end == -1:
        return html

    header = html[header_start:header_end]

    def prepare_header(match):
        name = match.group("name")
        if name == "json_string":
            return match.group(0)
        label = title_case_column_heading(name)
        if not sortable:
            return f"<th>{label}</th>"

        tooltip = FINDINGS_HEADER_TOOLTIPS.get(name)
        title = f' title="{escape(tooltip, quote=True)}"' if tooltip else ""
        affected_entities_limit = (
            f' data-initial-visible-count="{AFFECTED_ENTITIES_DISPLAY_LIMIT}"'
            if name == "affected_entities"
            else ""
        )
        return (
            f'<th class="table-sortable" tabindex="0" role="button" '
            f'aria-sort="none"{title}{affected_entities_limit}>{label}</th>'
        )

    header = re.sub(
        r"<th>(?P<name>[^<]+)</th>",
        prepare_header,
        header,
    )
    return html[:header_start] + header + html[header_end:]


def add_findings_header_tooltips(html):
    """Add title casing, sorting controls and tooltips to findings headers."""
    return prepare_top_level_headers(html, sortable=True)


@app.route('/')
def dashboard():
    if not DATA_DIR.exists():
        return "<p>Data directory not found. Please create a 'data' folder with JSON files.</p>"
    tabs = dataset_groups()
    manifest = latest_collection_manifest()
    findings = findings_summary(manifest)
    collection_requests = collection_request_summary(manifest)
    graph_collection = graph_collection_summary(manifest)
    findings_chart_data = None
    findings_sankey_data = None
    findings_sankey_nodes = None
    if findings is not None and findings["executed"]:
        findings_chart_data = [
            {
                "label": label,
                "value": findings["chart_segments"][(outcome, label, color)],
                "color": color,
            }
            for outcome, (label, color) in FINDING_CHART_OUTCOMES.items()
            if findings["chart_segments"][(outcome, label, color)]
        ]
        findings_sankey_data = [
            {
                "nodes": list(path),
                "value": count,
                "color": color,
            }
            for (path, color), count in findings["sankey_paths"].items()
        ]
        findings_sankey_nodes = [
            {
                "stage": stage,
                "name": name,
                "count": count,
                "unit": unit,
            }
            for (stage, name, unit), count
            in findings["sankey_node_counts"].items()
        ]
    return render_template_string(
        HTML_TEMPLATE,
        tabs=tabs,
        summary_cards=build_dashboard_summary_cards(
            tabs,
            findings,
            collection_requests,
        ),
        dashboard=True,
        findings_chart_data=findings_chart_data,
        findings_sankey_data=findings_sankey_data,
        findings_sankey_nodes=findings_sankey_nodes,
        findings=findings,
        collection_requests=collection_requests,
        graph_collection=graph_collection,
        dataset_index=False,
    )


def manifest_dataset_rows(manifest):
    """Prepare retained manifest datasets for human-facing presentation."""
    available_filenames = {path.name for path in standard_data_files()}
    rows = []
    for dataset in manifest.get("datasets", []):
        if not isinstance(dataset, dict) or not dataset.get("filename"):
            continue
        filename = str(dataset["filename"])
        metadata = dataset_collection_metadata(filename)
        rows.append(
            {
                **dataset,
                **metadata,
                "name": display_name_for_dataset(filename),
                "available": filename in available_filenames,
            }
        )
    return rows


def manifest_endpoint_rows(manifest):
    """Prepare well-formed endpoint rows without changing retained evidence."""
    return [
        {
            **endpoint,
            "category_label": collection_category_label(endpoint.get("category")),
        }
        for endpoint in manifest.get("endpoint_runs", [])
        if isinstance(endpoint, dict)
    ]


@app.route('/manifest')
def manifest_view():
    if not DATA_DIR.exists():
        return "<p>Data directory not found.</p>", 404
    requested_filename = request.args.get("filename")
    path = collection_manifest_path(requested_filename)
    if path is None:
        message = (
            "The requested collection manifest was not found."
            if requested_filename else "No collection manifest was found."
        )
        return f"<p>{message}</p>", 404
    manifest = load_json_file(path)
    if not isinstance(manifest, dict):
        return "<p>The collection manifest could not be loaded.</p>", 500
    dataset_rows = manifest_dataset_rows(manifest)
    dataset_links = {
        item["filename"]: item["name"]
        for item in dataset_rows if item["available"]
    }
    response = app.make_response(
        render_template_string(
            HTML_TEMPLATE,
            tabs=dataset_groups(),
            summary_cards=None,
            dashboard=False,
            findings_chart_data=None,
            dataset_index=False,
            manifest_page=True,
            manifest=manifest,
            manifest_filename=path.name,
            manifest_versions=collection_manifest_versions(),
            manifest_endpoint_rows=manifest_endpoint_rows(manifest),
            manifest_datasets=dataset_rows,
            manifest_dataset_links=dataset_links,
        )
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route('/manifest/raw')
def raw_manifest():
    requested_filename = request.args.get("filename")
    path = collection_manifest_path(requested_filename)
    if path is None:
        return jsonify({"error": "Collection manifest not found"}), 404
    manifest = load_json_file(path)
    if not isinstance(manifest, dict):
        return jsonify({"error": "Collection manifest could not be loaded"}), 500
    response = Response(
        json.dumps(manifest, indent=2) + "\n",
        content_type="application/json; charset=utf-8",
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route('/datasets')
def datasets():
    if not DATA_DIR.exists():
        return "<p>Data directory not found. Please create a 'data' folder with JSON files.</p>"
    tabs = dataset_groups()
    return render_template_string(
        HTML_TEMPLATE,
        tabs=tabs,
        summary_cards=None,
        dashboard=False,
        findings_chart_data=None,
        dataset_index=True,
    )


@app.route('/search')
def search_all_data():
    if not DATA_DIR.exists():
        return "<p>Data directory not found.</p>", 404
    query_text = str(request.args.get("query") or "").strip()
    try:
        page = max(int(request.args.get("page", "1")), 1)
    except (TypeError, ValueError):
        page = 1
    search_result = search_all_datasets(query_text, page=page)
    response = app.make_response(render_template_string(
        HTML_TEMPLATE,
        tabs=dataset_groups(),
        summary_cards=None,
        dashboard=False,
        findings_chart_data=None,
        dataset_index=False,
        global_search_page=True,
        global_search_query=search_result["query"],
        global_search_query_encoded=quote(search_result["query"], safe=""),
        global_search_results=search_result["results"],
        global_search_total=search_result["total"],
        global_search_total_pages=search_result["total_pages"],
        global_search_page_number=search_result["page"],
        global_search_files_searched=search_result["files_searched"],
        global_search_unreadable=search_result["unreadable"],
    ))
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route('/dataset-counts')
def dataset_counts():
    if not DATA_DIR.exists():
        return jsonify({"counts": {}, "errors": {"input_dir": "Data directory not found"}}), 404
    return jsonify(dataset_count_payload(request.args.getlist("filename")))


@app.route('/findings', methods=['GET', 'POST'])
def findings():
    query_param = (request.form.get('query') or request.args.get('query') or "").lower()
    status_filter = normalize_findings_status_filter(request.form.get('status') or request.args.get('status'))
    filepath = findings_flat_path()
    if not filepath.exists():
        return missing_findings_message(filepath)
    try:
        all_data, _ = load_effective_finding_rows()
    except (OSError, ValueError) as exc:
        return (
            "<p>Could not prepare findings review data: "
            f"<code>{escape(str(exc))}</code></p>"
        ), 500

    validated_rows = confirmed_finding_rows(all_data)
    data = filter_findings_by_status(all_data, status_filter)

    if query_param:
        if isinstance(data, list):
            filtered_data = [item for item in data if query_param in json.dumps(item).lower()]
        elif isinstance(data, dict):
            filtered_data = {k: v for k, v in data.items() if query_param in str(v).lower()}
        else:
            filtered_data = data
    else:
        filtered_data = data

    display_data = prepare_findings_rows(filtered_data)
    table = add_findings_header_tooltips(
        collapse_findings_link_cells(generate_html_table(display_data))
    )
    tabs = [{
        "name": "Findings",
        "filename": FINDINGS_FLAT_FILENAME,
        "record_count": len(data) if isinstance(data, list) else len(data.keys()) if isinstance(data, dict) else 1,
    }]
    return render_template_string(
        HTML_TEMPLATE,
        tabs=tabs,
        table=table,
        current_tab=FINDINGS_FLAT_FILENAME,
        current_dataset_filename=FINDINGS_FLAT_FILENAME,
        findings_status=status_filter,
        summary_cards=None,
        findings_chart_data=None,
        dataset_index=False,
        findings_status_options=[
            {"value": value, "label": meta["label"]}
            for value, meta in FINDING_STATUS_OPTIONS.items()
        ],
        show_data_source_select=False,
        search_action="/findings",
        reset_action=f"/findings?status={status_filter}",
        dashboard=False,
        findings_validation_enabled=True,
        findings_review_csrf_token=FINDINGS_REVIEW_CSRF_TOKEN,
        validated_findings_count=len(validated_rows),
    )


@app.route('/findings/review', methods=['POST'])
def update_finding_review():
    if request.headers.get("X-Azure-Assess-CSRF") != FINDINGS_REVIEW_CSRF_TOKEN:
        return jsonify({"error": "The findings review request token was invalid."}), 403
    if request.content_length is not None and request.content_length > 16_384:
        return jsonify({"error": "The findings review request was too large."}), 413
    if not request.is_json:
        return jsonify({"error": "The findings review request must be JSON."}), 415
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "The findings review request was malformed."}), 400

    finding_id = payload.get("finding_id")
    confirmed = payload.get("confirmed")
    reviewer = payload.get("reviewer")
    if (
        not isinstance(finding_id, str)
        or not finding_id
        or len(finding_id) > MAX_FINDING_ID_LENGTH
    ):
        return jsonify({"error": "A valid finding_id is required."}), 400
    if not isinstance(confirmed, bool):
        return jsonify({"error": "confirmed must be true or false."}), 400
    if not isinstance(reviewer, str) or not reviewer.strip():
        return jsonify({"error": "A reviewer name is required."}), 400
    reviewer = reviewer.strip()

    try:
        with FINDINGS_REVIEW_LOCK:
            rows, overrides = load_effective_finding_rows()
            rows_by_id = {row["finding_id"]: row for row in rows}
            row = rows_by_id.get(finding_id)
            if row is None:
                return jsonify({"error": "The finding is not in the current assessment."}), 404
            if row.get("status") not in VALIDATABLE_FINDING_STATUSES:
                return jsonify({
                    "error": (
                        "Only raised findings and manual assessment items can "
                        "be validated."
                    )
                }), 409

            override = review_override_from_effective_review(
                row,
                reviewer,
                confirmed,
            )
            overrides[finding_id] = override
            save_review_overrides(findings_review_path(), overrides)
            apply_review_override(row, override)
            validated_count = len(confirmed_finding_rows(rows))
    except (OSError, ValueError) as exc:
        return jsonify({"error": f"Could not save the findings review: {exc}"}), 500

    return jsonify(
        {
            "finding_id": finding_id,
            "confirmed": confirmed,
            "review": row["review"],
            "validated_findings": validated_count,
        }
    )


@app.route('/findings/export-validated-sarif')
def export_validated_findings_sarif():
    try:
        with FINDINGS_REVIEW_LOCK:
            rows, _ = load_effective_finding_rows()
            validated_rows = confirmed_finding_rows(rows)
            sarif_path = findings_sarif_path()
            source_sarif = load_json_file(sarif_path)
            if source_sarif is None:
                raise ValueError(f"Could not load source SARIF from {sarif_path}")
            output = build_validated_sarif(source_sarif, validated_rows)
    except (OSError, ValueError) as exc:
        return (
            "<p>Could not export validated SARIF: "
            f"<code>{escape(str(exc))}</code></p>"
        ), 409

    response = Response(
        json.dumps(output, indent=2) + "\n",
        content_type="application/sarif+json; charset=utf-8",
    )
    response.headers["Content-Disposition"] = (
        f'attachment; filename="{VALIDATED_FINDINGS_SARIF_FILENAME}"'
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

@app.route('/query/<filename>', methods=['GET', 'POST'])
def query(filename):
    # Retrieve search term from GET or POST
    query_param = (request.form.get('query') or request.args.get('query') or "").lower()
    filepath = DATA_DIR / filename
    dataset_group = dataset_group_by_filename(filename)
    if dataset_group is None:
        return f"<p>Unknown dataset requested: {filename}.</p>"
    data = load_json_file(filepath)
    if data is None:
        return f"<p>Error loading data from {filename}.</p>"
    display_rows = ensure_horizontal_json_table_format(data)
    if query_param:
        filtered_data = [
            item
            for item in display_rows
            if query_param in json.dumps(item).lower()
        ]
    else:
        filtered_data = display_rows
    table = prepare_top_level_headers(
        generate_html_table(filtered_data),
        sortable=True,
    )
    tabs = dataset_groups()
    return render_template_string(
        HTML_TEMPLATE,
        tabs=tabs,
        table=table,
        current_tab=filename,
        current_dataset_filename=dataset_group["filename"],
        findings_status=None,
        findings_status_options=None,
        summary_cards=None,
        findings_chart_data=None,
        dataset_index=False,
        show_data_source_select=True,
        show_version_select=len(dataset_group["versions"]) > 1,
        current_versions=dataset_group["versions"],
        search_action=f"/query/{filename}",
        reset_action=f"/query/{filename}",
        dashboard=False,
    )

if __name__ == '__main__':
    args = parse_arguments()
    DATA_DIR = Path(args.input_dir)
    app.run(host='127.0.0.1', port=5000, debug=False)
