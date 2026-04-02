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
from collections import OrderedDict
from datetime import datetime
from flask import Flask, render_template_string, request
from json2html import json2html
from pathlib import Path

app = Flask(__name__)
DATA_DIR = Path("azure-collect")
FINDINGS_FLAT_FILENAME = "azure-findings-flat.json"
FINDINGS_STRUCTURED_FILENAME = "azure-findings.json"
FINDINGS_FILENAMES = {FINDINGS_FLAT_FILENAME, FINDINGS_STRUCTURED_FILENAME}
FINDING_STATUS_OPTIONS = OrderedDict(
    [
        ("found", {"label": "Found Items", "statuses": {"found"}}),
        ("not_found", {"label": "Not Found Items", "statuses": {"not_found"}}),
        ("no_data_to_assess", {"label": "No Data To Assess", "statuses": {"no_data_to_assess"}}),
        ("not_implemented", {"label": "Not Implemented", "statuses": {"not_implemented"}}),
        ("all", {"label": "All Findings", "statuses": None}),
    ]
)

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
      }
      /* Dark theme overrides when .dark-mode is applied */
      .dark-mode {
        --bg-color: #121212;
        --text-color: #e0e0e0;
        --table-bg: #1e1e1e;
        --table-border: #444444;
        --row-even-bg: #1e1e1e;
        --row-odd-bg: #121212;
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
      /* Scrollable container for the table with fixed height */
      .table-container {
        position: relative;
        overflow-y: auto;
        width: 100%;
        /* Set height to fill remaining space. Adjust 250px as needed */
        height: calc(100vh - 360px);
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
      .dashboard-chart-card {
        background-color: transparent;
        border: 1px solid var(--table-border);
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
      }
      .chart-legend-swatch {
        width: 12px;
        height: 12px;
        border-radius: 50%;
        display: inline-block;
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
          <button id="dataViewerIndex" class="btn btn-secondary">Data Viewer</button>
          <button id="findingsView" class="btn btn-secondary">Findings</button>
          <button id="returnToDashboard" class="btn btn-secondary">Dashboard</button>
        </div>
        <button id="darkModeToggle" class="btn btn-secondary">Toggle Dark Mode</button>
      </div>
      
      {% if dashboard %}
      <!-- DASHBOARD PAGE -->
      <div class="mt-4">
        <h2>Dashboard</h2>
        {% if summary_cards %}
        <div class="row g-3 mb-4">
          {% for card in summary_cards %}
          <div class="col-12 col-md-6 col-xl-3">
            <div class="card h-100 bg-transparent border-secondary">
              <div class="card-body">
                <h3 class="h6 text-uppercase text-secondary">{{ card.label }}</h3>
                <div class="fs-3 fw-bold">{{ card.value }}</div>
                {% if card.detail %}
                <div class="small text-secondary">{{ card.detail }}</div>
                {% endif %}
              </div>
            </div>
          </div>
          {% endfor %}
        </div>
        {% endif %}
        {% if findings_chart_data %}
        <div class="card dashboard-chart-card">
          <div class="card-body">
            <h3 class="h5">Findings Overview</h3>
            <p class="text-secondary mb-3">Current distribution of findings, clear checks, and checks with no data to assess.</p>
            <div class="dashboard-chart-wrap">
              <canvas id="findingsPieChart" class="dashboard-chart-canvas"></canvas>
            </div>
            <div id="findingsPieLegend" class="chart-legend"></div>
          </div>
        </div>
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
              <td>{{ tab.record_count }}</td>
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
          {% if findings_status_options %}
          <div class="mt-3 mb-3">
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
          <!-- Search Form (using GET so the search term is preserved) -->
          <form method="get" action="{{ search_action }}">
            <div class="mb-3 mt-3">
              <label for="query" class="form-label">Filter Data (search within JSON):</label>
              <input type="text"
                     class="form-control"
                     id="query"
                     name="query"
                     placeholder="Enter search term"
                     value="{{ request.args.get('query', '') }}">
            </div>
            {% if findings_status_options %}
            <input type="hidden" id="findingsStatusInput" name="status" value="{{ findings_status }}">
            {% endif %}
            <button type="submit" class="btn btn-primary">Search</button>
            <a href="{{ reset_action }}" class="btn btn-secondary">Reset Search</a>
          </form>
        </div>
        <!-- Scrollable Table Container fills remaining height -->
        <div id="table-container" class="table-container mt-3">
          {{ table|safe }}
        </div>
      </div>
      {% endif %}
    </div>

    <!-- JavaScript for Dark Mode Toggle -->
    <script>
      document.getElementById('darkModeToggle').addEventListener('click', function() {
        document.body.classList.toggle('dark-mode');
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
    </script>
    {% endif %}

    {% if dashboard and findings_chart_data %}
    <script>
      (function() {
        const canvas = document.getElementById('findingsPieChart');
        const legend = document.getElementById('findingsPieLegend');
        if (!canvas || !legend) return;

        const chartData = {{ findings_chart_data|tojson }};
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

        legend.innerHTML = '';
        segments.forEach(function(segment) {
          const item = document.createElement('div');
          item.className = 'chart-legend-item';
          item.innerHTML = '<span class="chart-legend-swatch" style="background-color: ' + segment.color + ';"></span>' +
            '<span>' + segment.label + ': ' + segment.value + '</span>';
          legend.appendChild(item);
        });

        drawPieChart();
        window.addEventListener('resize', drawPieChart);
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
  const table = document.querySelector('table');
  if (!table) return;

  // Use table.rows to access every row (header and data rows)
  const rows = table.rows;
  if (rows.length === 0) return;

  // Process header row (assumed to be the first row)
  const headerRow = rows[0];
  if (headerRow.cells.length > 0) {
    // Hide the first header cell (assumed to be 'json')
    headerRow.cells[0].style.display = 'none';

    // Create and insert a new header cell for "Actions"
    const newTh = document.createElement('th');
    newTh.textContent = 'Actions';
    headerRow.insertBefore(newTh, headerRow.cells[1]);
  }

  // Loop through all remaining rows
  for (let i = 1; i < rows.length; i++) {
    const row = rows[i];
    if (row.cells.length === 0) continue;

    // Hide the first cell (raw JSON)
    row.cells[0].style.display = 'none';

    // Insert a new cell for the "View JSON" button
    const toggleCell = row.insertCell(1);
    const toggleBtn = document.createElement('button');

    toggleBtn.textContent = 'View JSON';
    toggleBtn.className = 'btn btn-info btn-sm';
    toggleBtn.setAttribute('data-bs-toggle', 'modal');
    toggleBtn.setAttribute('data-bs-target', '#jsonModal');

    toggleBtn.addEventListener('click', () => {
      try {
        // Retrieve and pretty-print the JSON from the hidden cell
        const rawText = row.cells[0].textContent.trim();
        const pretty = JSON.stringify(JSON.parse(rawText), null, 2);
        document.getElementById('jsonModalLabel').textContent = `Record #${i}`;
        document.getElementById('jsonModalContent').textContent = pretty;
      } catch (err) {
        document.getElementById('jsonModalContent').textContent = 'Invalid JSON or corrupted entry.';
      }
    });

    toggleCell.appendChild(toggleBtn);
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

    for endpoint in getattr(module, "AZURE_CLI_ENDPOINTS", []):
        endpoint_map[collect_filename_prefix(endpoint["cli_command"])] = endpoint["name"]

    for endpoint in getattr(module, "AZURE_CLI_ENDPOINTS_PARAMS", []):
        endpoint_map[collect_filename_prefix(endpoint["cli_command"], parameterized=True)] = endpoint["name"]

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
    if isinstance(data, list):
        record_count = len(data)
    elif isinstance(data, dict):
        record_count = len(data.keys())
    else:
        record_count = 0
    return {
        "filename": path.name,
        "record_count": record_count,
        "label": format_dataset_version_label(path),
        "timestamp": extract_dataset_timestamp(path.name),
    }


def standard_data_files():
    return [path for path in sorted(DATA_DIR.glob("*.json")) if path.name not in FINDINGS_FILENAMES]


def dataset_groups():
    groups = OrderedDict()
    for path in standard_data_files():
        key = dataset_key_for_filename(path.name)
        groups.setdefault(key, []).append(path)

    grouped_tabs = []
    for key, paths in groups.items():
        sorted_paths = sorted(paths, key=dataset_sort_key, reverse=True)
        versions = []
        for path in sorted_paths:
            data = load_json_file(path)
            if data is None:
                continue
            versions.append(build_dataset_version(path, data))
        if not versions:
            continue
        latest = versions[0]
        grouped_tabs.append({
            "dataset_key": key,
            "name": display_name_for_dataset(latest["filename"]),
            "filename": latest["filename"],
            "record_count": latest["record_count"],
            "version_label": latest["label"],
            "versions": versions,
        })
    return grouped_tabs


def dataset_group_by_filename(filename):
    key = dataset_key_for_filename(filename)
    for group in dataset_groups():
        if group["dataset_key"] == key:
            return group
    return None


def latest_resource_object_count(tabs):
    for tab in tabs:
        if tab["dataset_key"] == "az_resource_list":
            return tab["record_count"], "From latest Azure Resource List dataset"
    return sum(tab["record_count"] for tab in tabs), "Fallback: sum of latest dataset record counts"


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
    }
    for row in rows:
        status = canonical_finding_status(row.get("status") if isinstance(row, dict) else None)
        if status in counts:
            counts[status] += 1
    return counts


def build_dashboard_summary_cards(tabs):
    object_count, object_detail = latest_resource_object_count(tabs)
    total_versions = sum(len(tab["versions"]) for tab in tabs)
    historical_versions = sum(max(len(tab["versions"]) - 1, 0) for tab in tabs)
    latest_collection = None
    for tab in tabs:
        timestamp = tab["versions"][0]["timestamp"]
        if timestamp is not None and (latest_collection is None or timestamp > latest_collection):
            latest_collection = timestamp

    cards = [
        {"label": "Objects In Subscription", "value": object_count, "detail": object_detail},
        {"label": "Dataset Types Collected", "value": len(tabs), "detail": "Logical dataset families on the dashboard"},
        {"label": "Stored Dataset Snapshots", "value": total_versions, "detail": f"{historical_versions} older versions available"},
        {
            "label": "Latest Collection",
            "value": latest_collection.strftime("%Y-%m-%d %H:%M:%S") if latest_collection else "Unknown",
            "detail": "Most recent timestamp found in collected dataset filenames",
        },
    ]

    findings = findings_summary()
    if findings is not None:
        cards.extend([
            {"label": "Finding Checks Executed", "value": findings["executed"], "detail": "Rows in azure-findings-flat.json"},
            {"label": "Finding Checks Found", "value": findings["found"], "detail": "Status: found"},
            {"label": "Finding Checks Clear", "value": findings["not_found"], "detail": "Status: not_found"},
            {"label": "Finding Checks With No Data", "value": findings["no_data_to_assess"], "detail": "Status: no_data_to_assess"},
            {"label": "Finding Checks Not Implemented", "value": findings["not_implemented"], "detail": "Status: not_implemented"},
        ])
    return cards


def findings_flat_path():
    return DATA_DIR / FINDINGS_FLAT_FILENAME


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


def linkify_rendered_urls(html):
    patterns = [
        re.compile(r'(?P<url>https?://[^\s<]+)'),
        re.compile(r'(?P<url>/query/[^\s<]+)'),
    ]

    def replace_anchor(match):
        url = match.group("url")
        return f'<a href="{url}" target="_blank" rel="noopener noreferrer">{url}</a>'

    updated = html
    for pattern in patterns:
        updated = pattern.sub(replace_anchor, updated)
    return updated

@app.route('/')
def dashboard():
    if not DATA_DIR.exists():
        return "<p>Data directory not found. Please create a 'data' folder with JSON files.</p>"
    tabs = dataset_groups()
    findings = findings_summary()
    findings_chart_data = None
    if findings is not None:
        findings_chart_data = [
            {"label": "Findings", "value": findings["found"], "color": "#dc3545"},
            {"label": "No Findings", "value": findings["not_found"], "color": "#198754"},
            {"label": "No Data To Assess", "value": findings["no_data_to_assess"], "color": "#ffc107"},
        ]
    return render_template_string(
        HTML_TEMPLATE,
        tabs=tabs,
        summary_cards=build_dashboard_summary_cards(tabs),
        dashboard=True,
        findings_chart_data=findings_chart_data,
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


@app.route('/findings', methods=['GET', 'POST'])
def findings():
    query_param = (request.form.get('query') or request.args.get('query') or "").lower()
    status_filter = normalize_findings_status_filter(request.form.get('status') or request.args.get('status'))
    filepath = findings_flat_path()
    data = load_json_file(filepath)
    if data is None:
        return f"<p>Error loading data from {FINDINGS_FLAT_FILENAME}.</p>"

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

    table = generate_html_table(filtered_data)
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
    table = generate_html_table(filtered_data)
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
