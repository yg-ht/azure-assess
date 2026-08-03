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
import importlib.util
import json
import re
from collections import Counter, OrderedDict
from datetime import datetime
from flask import Flask, jsonify, render_template_string, request
from html import escape
from json2html import json2html
from pathlib import Path
from urllib.parse import unquote, urlparse, parse_qs

from azure_assess.collection_manifest import (
    extract_azure_error_code,
    is_not_applicable_error,
    is_tenant_unavailable_error,
)

app = Flask(__name__)
DATA_DIR = Path("azure-collect")
FINDINGS_FLAT_FILENAME = "azure-findings-flat.json"
FINDINGS_SARIF_FILENAME = "azure-findings-SARIF.json"
LEGACY_FINDINGS_SARIF_FILENAME = "azure-findings.json"
COLLECTION_MANIFEST_PREFIX = "azure-collection-manifest"
FINDINGS_FILENAMES = {
    FINDINGS_FLAT_FILENAME,
    FINDINGS_SARIF_FILENAME,
    LEGACY_FINDINGS_SARIF_FILENAME,
}
FINDING_STATUS_OPTIONS = OrderedDict(
    [
        ("found", {"label": "Found Items", "statuses": {"found"}}),
        ("not_found", {"label": "Not Found Items", "statuses": {"not_found"}}),
        ("no_data_to_assess", {"label": "No Data To Assess", "statuses": {"no_data_to_assess"}}),
        ("not_implemented", {"label": "Not Implemented", "statuses": {"not_implemented"}}),
        ("all", {"label": "All Findings", "statuses": None}),
    ]
)

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
        ("skipped_prerequisite", ("Skipped Prerequisite", "#ffc107")),
        ("empty_source", ("Empty Upstream Source", "#0dcaf0")),
        ("missing_or_unattributed_source", ("Missing or Unattributed Source", "#adb5bd")),
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
<html lang="en">
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
        color: #ffc107;
      }
      .local-collapse-icon {
        color: #0dcaf0;
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
      .dashboard-muted {
        color: var(--dashboard-muted-text);
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
      .dashboard-request-table {
        --bs-table-color: var(--text-color);
        --bs-table-bg: var(--table-bg);
        --bs-table-striped-color: var(--text-color);
        --bs-table-striped-bg: var(--row-even-bg);
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
        </div>
        <button id="darkModeToggle" class="btn btn-secondary">Toggle Dark Mode</button>
      </div>
      
      {% if dashboard %}
      <!-- DASHBOARD PAGE -->
      <div class="mt-4 dashboard-page">
        <h2>Dashboard</h2>
        {% macro dashboard_card_grid(cards) %}
        <div class="row g-3 mb-4">
          {% for card in cards %}
          <div class="col-12 col-md-6 col-xl-3">
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
          <p class="dashboard-muted">One mutually exclusive outcome for every assessment check.</p>
          {{ dashboard_card_grid(summary_cards.findings) }}
        {% if findings_chart_data %}
        <div class="card dashboard-chart-card">
          <div class="card-body">
            <h4 class="h5">Finding Outcome Distribution</h4>
            <p class="dashboard-muted mb-3">Percentages use the total number of assessed checks as their denominator. Checks with insufficient data are split by one primary cause derived from their required endpoint outcomes.</p>
            <div class="dashboard-chart-wrap">
              <canvas id="findingsPieChart" class="dashboard-chart-canvas"></canvas>
            </div>
            <div id="findingsPieLegend" class="chart-legend"></div>
          </div>
        </div>
        {% endif %}
        </section>
        {% endif %}

        {% if summary_cards.requests %}
        <section class="dashboard-section mt-4" aria-labelledby="requestHealthHeading">
          <h3 id="requestHealthHeading" class="h4">Azure Request Health</h3>
          <p class="dashboard-muted">Direct outcomes from Azure request attempts and explicit reasons why selected endpoint definitions were omitted. These counts describe collection activity and use a different denominator from assessment checks.</p>
          {{ dashboard_card_grid(summary_cards.requests) }}
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
        {% if collection_requests and collection_requests.failures %}
        <div class="card dashboard-chart-card mt-4">
          <div class="card-body">
            <details class="dashboard-request-details">
            <summary><span class="h5">Unsuccessful Azure Requests</span></summary>
            <p class="dashboard-muted my-3">One row is shown for each failed, unauthorised or tenant-restricted logical execution in the latest collection manifest. Successful, empty and not-applicable outcomes are excluded.</p>
            <div class="table-responsive">
              <table id="failedAzureRequestsTable" class="table table-striped align-middle dashboard-request-table dashboard-filterable-table">
                <thead>
                  <tr>
                    {% for heading in ["Endpoint", "Category", "Status", "Azure Error Code", "CLI Return Code", "Parameters", "Returned Error"] %}
                    <th aria-sort="none">
                      <div class="dashboard-column-heading">
                        <button type="button" class="dashboard-sort-button" data-column-index="{{ loop.index0 }}" aria-label="Sort by {{ heading }}">{{ heading }}</button>
                      </div>
                      {% if loop.index0 < 5 %}
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
                  {% for failure in collection_requests.failures %}
                  <tr>
                    <td>{{ failure.endpoint_name }}</td>
                    <td>{{ failure.category }}</td>
                    <td>{{ failure.status }}</td>
                    <td>{{ failure.error_code or "Unavailable" }}</td>
                    <td>{{ failure.returncode if failure.returncode is not none else "Unavailable" }}</td>
                    <td><code>{{ failure.parameter_context|tojson }}</code></td>
                    <td>
                      <pre class="dashboard-error-message">{{ failure.message or "No error message was recorded" }}</pre>
                      {% if failure.message_truncated %}
                      <span class="small dashboard-muted">Stored message was truncated by the collection manifest.</span>
                      {% endif %}
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
        </section>
        {% endif %}
      </div>

      {% elif dataset_index %}
      <!-- DATASET INDEX PAGE -->
      <div class="mt-4">
        <h2>Data Viewer</h2>
        <table class="table table-striped">
          <thead>
            <tr>
              <th>Data Source</th>
              <th>Version</th>
              <th>Record Count</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {% for tab in tabs %}
            <tr>
              <td>{{ tab.name }}</td>
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
      
      {% else %}
      <!-- DATA TABLE VIEW PAGE -->
      <div class="data-view">
        <!-- Controls: Drop-down and Search -->
        <div class="data-controls">
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
                <span class="small text-secondary">Table font size</span>
                <button id="decreaseTableFont"
                        type="button"
                        class="btn btn-outline-secondary btn-sm"
                        aria-label="Decrease table font size">A−</button>
                <button id="increaseTableFont"
                        type="button"
                        class="btn btn-outline-secondary btn-sm"
                        aria-label="Increase table font size">A+</button>
              </div>
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
        document.body.classList.toggle('dark-mode');
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

        {% if findings_chart_data %}
        renderDashboardPie('findingsPieChart', 'findingsPieLegend', {{ findings_chart_data|tojson }});
        {% endif %}
      })();
    </script>
    {% endif %}

    {% if dashboard and collection_requests and (collection_requests.failures or collection_requests.omission_groups) %}
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
        const rawText = jsonCell.textContent.trim();
        const pretty = JSON.stringify(JSON.parse(rawText), null, 2);
        document.getElementById('jsonModalLabel').textContent = `Record #${i}`;
        document.getElementById('jsonModalContent').textContent = pretty;
      } catch (err) {
        document.getElementById('jsonModalContent').textContent = 'Broken or missing JSON for this row.';
      }
    });

    toggleCell.appendChild(toggleBtn);
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

    endpoint_map["role_enriched"] = "Role Assignments Enriched"
    return endpoint_map


DATASET_NAME_MAP = load_collect_endpoint_name_map()


def display_name_for_dataset(filename):
    stem = Path(filename).stem
    normalized_stem = dataset_key_for_filename(filename)
    mapped_name = DATASET_NAME_MAP.get(normalized_stem)
    if mapped_name:
        return mapped_name
    return normalized_stem.replace("_", " ").strip().title()


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
        return len(data.keys())
    return 0


def record_count_for_file(path):
    data = load_json_file(path)
    if data is None:
        return None
    return record_count_for_data(data)


def standard_data_files():
    return [path for path in sorted(DATA_DIR.glob("*.json")) if path.name not in FINDINGS_FILENAMES]


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
        grouped_tabs.append({
            "dataset_key": key,
            "name": display_name_for_dataset(latest["filename"]),
            "filename": latest["filename"],
            "record_count": latest_record_count if latest_record_count is not None else "Loading...",
            "version_label": latest["label"],
            "versions": versions,
        })
    return grouped_tabs


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


def latest_collection_manifest():
    """Load the latest collection manifest without inferring request outcomes."""
    paths = sorted(
        DATA_DIR.glob(f"{COLLECTION_MANIFEST_PREFIX}_*.json"),
        key=dataset_sort_key,
        reverse=True,
    )
    if not paths:
        return None
    manifest = load_json_file(paths[0])
    if not isinstance(manifest, dict) or not isinstance(manifest.get("endpoint_runs"), list):
        return None
    return manifest


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
        category = str(record.get("category") or "Unknown")
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


def collection_request_summary():
    """Summarise mutually exclusive request and non-attempt outcomes."""
    manifest = latest_collection_manifest()
    if manifest is None:
        return None
    status_counts = Counter()
    failures = []
    omissions = []
    for request_record in manifest.get("endpoint_runs", []):
        if not isinstance(request_record, dict):
            continue
        # Local Azure CLI configuration commands do not call an Azure service
        # endpoint and therefore do not belong in request-health statistics.
        if str(request_record.get("category") or "") == "setup":
            continue
        status = str(request_record.get("status") or "")
        response_message = (
            request_record.get("response_error")
            or request_record.get("error")
        )
        # Manifests written before schema 2.1 classified this explicit Azure
        # applicability response as a generic failure. Reclassify it for
        # presentation without modifying the retained evidence.
        if status == "failed" and is_not_applicable_error(response_message):
            status = "not_applicable"
        if status in {"failed", "unauthorised"} and is_tenant_unavailable_error(
            request_record.get("error_code") or response_message
        ):
            status = "tenant_unavailable"
        status_counts[status] += 1
        if status in {"skipped", "not_attempted"}:
            omissions.append(request_record)
        if status not in {"failed", "unauthorised", "tenant_unavailable"}:
            continue
        failures.append(
            {
                "endpoint_name": request_record.get("endpoint_name") or "Unknown",
                "category": request_record.get("category") or "Unknown",
                "status": status,
                "error_code": (
                    request_record.get("error_code")
                    or extract_azure_error_code(response_message)
                ),
                "returncode": request_record.get("returncode"),
                "parameter_context": (
                    request_record.get("parameter_context")
                    if isinstance(request_record.get("parameter_context"), dict)
                    else {}
                ),
                "message": response_message,
                "message_truncated": bool(
                    request_record.get("response_error_truncated")
                ),
            }
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
            "failed",
            "unauthorised",
            "tenant_unavailable",
            "not_applicable",
        )
    )
    return {
        "attempted": attempted,
        "success": status_counts["success"],
        "empty": status_counts["empty"],
        "failed": status_counts["failed"],
        "unauthorised": status_counts["unauthorised"],
        "tenant_unavailable": status_counts["tenant_unavailable"],
        "not_applicable": status_counts["not_applicable"],
        "skipped": status_counts["skipped"],
        "not_attempted": status_counts["not_attempted"],
        "unattempted": status_counts["skipped"] + status_counts["not_attempted"],
        "failures": failures,
        "omission_groups": grouped_endpoint_omissions(omissions),
        "skipped_reason_counts": Counter(
            endpoint_omission_reason(record)[0]
            for record in omissions
            if record.get("status") == "skipped"
        ),
    }


def findings_summary():
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
        "insufficient_data_causes": Counter(),
    }
    for row in rows:
        status = canonical_finding_status(row.get("status") if isinstance(row, dict) else None)
        if status in counts:
            counts[status] += 1
        if status == "no_data_to_assess" and isinstance(row, dict):
            insufficient_data = (
                row.get("reporting", {})
                .get("provenance", {})
                .get("insufficient_data")
            )
            cause = (
                insufficient_data.get("cause")
                if isinstance(insufficient_data, dict)
                else None
            )
            if cause not in INSUFFICIENT_DATA_CAUSES:
                cause = "missing_or_unattributed_source"
            counts["insufficient_data_causes"][cause] += 1
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
        {"label": "Dataset Families", "value": len(tabs), "detail": "Distinct types of collected Azure data"},
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
            {"label": "Checks Assessed", "value": findings["executed"], "detail": "Total assessment checks with a recorded outcome"},
            {"label": "Findings Raised", "value": findings["found"], "detail": "Checks that identified an issue"},
            {"label": "Checks Passed", "value": findings["not_found"], "detail": "Checks that did not identify an issue"},
            {"label": "Checks Without Sufficient Data", "value": findings["no_data_to_assess"], "detail": "Checks that could not assess the required evidence"},
            {"label": "Checks Not Implemented", "value": findings["not_implemented"], "detail": "Defined checks without an implemented assessment"},
        ])

    request_cards = []
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
        request_cards.extend([
            {
                "label": "Request Attempts",
                "value": collection_requests["attempted"],
                "detail": "Azure requests that returned a direct outcome",
            },
            {
                "label": "Requests Returning Data",
                "value": collection_requests["success"],
                "detail": "Successful requests with one or more returned records",
            },
            {
                "label": "Requests Returning No Data",
                "value": collection_requests["empty"],
                "detail": "Successful requests whose response contained no records",
            },
            {
                "label": "Failed Request Attempts",
                "value": collection_requests["failed"],
                "detail": "Non-authorisation errors returned by attempted requests",
            },
            {
                "label": "Unauthorised Request Attempts",
                "value": collection_requests["unauthorised"],
                "detail": "Permission-related errors returned by attempted requests",
            },
            {
                "label": "Licence or Tenant Capability Restrictions",
                "value": collection_requests["tenant_unavailable"],
                "detail": "Requests blocked by tenant licensing or service capability",
            },
            {
                "label": "Not Applicable Request Attempts",
                "value": collection_requests["not_applicable"],
                "detail": "Azure reported that the requested service or scope was not applicable",
            },
            {
                "label": "Endpoint Definitions Skipped",
                "value": collection_requests["skipped"],
                "detail": "Deliberately omitted because a recorded prerequisite was unavailable or unusable",
            },
            {
                "label": "Skipped — Unauthorised Prerequisite",
                "value": skipped_unauthorised,
                "detail": "Endpoint definitions omitted because an upstream request was unauthorised",
            },
            {
                "label": "Skipped — Licence/Tenant Capability",
                "value": skipped_tenant,
                "detail": "Endpoint definitions omitted because an upstream tenant capability was unavailable",
            },
            {
                "label": "Skipped — Empty Prerequisite",
                "value": skipped_empty,
                "detail": "Endpoint definitions omitted because an upstream request returned no records",
            },
            {
                "label": "Skipped — Other Reasons",
                "value": skipped_other,
                "detail": "Endpoint definitions omitted for all other recorded reasons",
            },
            {
                "label": "Endpoint Outcomes Not Recorded",
                "value": collection_requests["not_attempted"],
                "detail": "Planned endpoints for which collection recorded no execution or deliberate skip outcome",
            },
        ])
    return {
        "collection": collection_cards,
        "findings": finding_cards,
        "requests": request_cards,
    }


def findings_flat_path():
    return DATA_DIR / FINDINGS_FLAT_FILENAME


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


def prepare_findings_rows(data):
    """Normalise findings for display while retaining all source columns."""
    if not isinstance(data, list):
        return data

    prepared = []
    for item in data:
        if not isinstance(item, dict):
            prepared.append(item)
            continue

        row = dict(item)
        for column in FINDINGS_LINK_COLUMNS:
            values = row.get(column)
            if isinstance(values, list):
                row[column] = unique_non_empty_strings(values)
        entities = row.get("affected_entities")
        if not isinstance(entities, list):
            entities = affected_entity_labels(row)
        row["affected_entities"] = unique_non_empty_strings(entities)
        has_finding_id = "finding_id" in row
        finding_id = row.pop("finding_id", None)

        ordered = OrderedDict()
        for column in FINDINGS_PRIMARY_COLUMNS:
            if column in row:
                ordered[column] = row[column]
        for column, value in row.items():
            if column not in ordered:
                ordered[column] = value
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

    # Case 1: Already a list of dicts
    if isinstance(data, list) and all(isinstance(row, dict) for row in data):
        log("Detected: List of dictionaries — passing through unchanged.")
        return data

    # Case 2: Single dictionary
    elif isinstance(data, dict):
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


def generate_html_table(original_data):
    """Convert JSON data to an HTML table using json2html."""
    try:
        # If the original data is a non-empty list of dicts, process each row.
        if len(original_data) > 0 and isinstance(original_data, list) and isinstance(original_data[0], dict):
            horizontal_data = ensure_horizontal_json_table_format(original_data)
            if not has_consistent_keys(horizontal_data):
                print("[WARNING] Data has inconsistent keys... attempting to correct")
                data_for_use = normalize_list_of_dicts(horizontal_data, 'not in data')
            else:
                data_for_use = horizontal_data
            modified_data = []
            for row in data_for_use:
                row_json_string = str(json.dumps(row))
                new_row = OrderedDict([("json_string", row_json_string)])
                new_row.update(row)
                modified_data.append(new_row)
            data = modified_data
        else:
            print("[DEBUG] Working with something which is neither a list-of-dictionaries or just a dictionary")
            # For non-list-of-dicts, simply wrap it under the "data" key.
            data = OrderedDict([("data", original_data)])
            print(f"This is the JSON object being sent to json2html:\n {data}")

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
    findings = findings_summary()
    collection_requests = collection_request_summary()
    findings_chart_data = None
    if findings is not None:
        findings_chart_data = [
            {"label": "Findings Raised", "value": findings["found"], "color": "#dc3545"},
            {"label": "Checks Passed", "value": findings["not_found"], "color": "#198754"},
        ]
        findings_chart_data.extend(
            {
                "label": f"Insufficient Data — {label}",
                "value": findings["insufficient_data_causes"][cause],
                "color": color,
            }
            for cause, (label, color) in INSUFFICIENT_DATA_CAUSES.items()
        )
        findings_chart_data.append(
            {"label": "Not Implemented", "value": findings["not_implemented"], "color": "#6c757d"}
        )
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
        collection_requests=collection_requests,
        dataset_index=False,
    )


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
    data = load_json_file(filepath)
    if data is None:
        return f"<p>Error loading data from <code>{filepath}</code>.</p>"

    if isinstance(data, dict) and "rows" in data:
        data = data["rows"]

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                item["status"] = canonical_finding_status(item.get("status"))

    data = filter_findings_by_status(data, status_filter)

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
    )

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
    if query_param:
        if isinstance(data, list):
            filtered_data = [item for item in data if query_param in json.dumps(item).lower()]
        elif isinstance(data, dict):
            filtered_data = {k: v for k, v in data.items() if query_param in str(v).lower()}
        else:
            filtered_data = data
    else:
        filtered_data = data
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
