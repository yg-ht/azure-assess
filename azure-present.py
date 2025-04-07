#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025 Felix, You Gotta Hack That
#
# This file is part of an AGPLv3-licensed project.
# You are free to use, modify, and distribute this file under the terms of
# the GNU Affero General Public License, version 3 or later.
# For details, see: https://www.gnu.org/licenses/agpl-3.0.html
# ---------------------------------------------------------------------------
# Filename:        azure-collect.py
# Description:     Presents the JSON Azure configuration details from the Azure Collect script in an easy to examine format
# Author:          Felix of You Gotta Hack That
# Created:         2025-04-02
# Last Modified:   2025-04-07
# Version:         0.9.0
#
# Purpose:         This script is part of the YGHT audit toolkit for secure
#                  Azure visibility. Designed for extensible JSON enrichment.
#
# Usage:           pipenv run python azure-collect.py -i ./audit_output
# Requirements:    Install the libraries from the requirements file (e.g. pipenv install -r requirements.txt)
#                  Python 3.8+ (tested with Python 3.11)
#                  az cli installed from package manager and accessible via the PATH
#
# Notes:           See the README.md for configuration options and examples.
# ---------------------------------------------------------------------------

import argparse
import json
from collections import OrderedDict
from flask import Flask, render_template_string, request
from json2html import json2html
from pathlib import Path

app = Flask(__name__)

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
    </style>
  </head>
  <!-- Dark mode enabled by default via the dark-mode class -->
  <body class="dark-mode">
    <div class="container-fluid">
      <!-- Header with Dark Mode Toggle -->
      <div class="header d-flex justify-content-between align-items-center mt-4">
        <h1>Azure Audit Data Viewer</h1>
        <button id="returnToDashboard" class="btn btn-secondary">Dashboard</button>
        <button id="darkModeToggle" class="btn btn-secondary">Toggle Dark Mode</button>
      </div>
      
      {% if dashboard %}
      <!-- DASHBOARD PAGE -->
      <div class="mt-4">
        <h2>Dashboard</h2>
        <table class="table table-striped">
          <thead>
            <tr>
              <th>Data Source</th>
              <th>Record Count</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {% for tab in tabs %}
            <tr>
              <td>{{ tab.name }}</td>
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
          <!-- Drop-down for Data Source Selection -->
          <div class="mt-3 mb-3">
            <label for="dataSourceSelect" class="form-label">Select Data Source:</label>
            <select id="dataSourceSelect" class="form-select">
              {% for tab in tabs %}
              <option value="{{ tab.filename }}" {% if current_tab == tab.filename %}selected{% endif %}>
                {{ tab.name }}
              </option>
              {% endfor %}
            </select>
          </div>
          <!-- Search Form (using GET so the search term is preserved) -->
          <form method="get" action="/query/{{ current_tab }}">
            <div class="mb-3 mt-3">
              <label for="query" class="form-label">Filter Data (search within JSON):</label>
              <input type="text"
                     class="form-control"
                     id="query"
                     name="query"
                     placeholder="Enter search term"
                     value="{{ request.args.get('query', '') }}">
            </div>
            <button type="submit" class="btn btn-primary">Search</button>
            <a href="/query/{{ current_tab }}" class="btn btn-secondary">Reset Search</a>
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


    <!-- JavaScript for Data Source Drop-down (only on data table view) -->
    {% if not dashboard %}
    <script>
      document.getElementById('dataSourceSelect').addEventListener('change', function() {
        var selected = this.value;
        window.location.href = "/query/" + selected;
      });
    </script>

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
              globalIcon.innerHTML = '&#x25BA;'; // Right arrow (collapsed)
              cell.insertBefore(globalIcon, cell.firstChild);
              
              // Global icon toggles all nested tables in this cell
              globalIcon.addEventListener('click', function(e) {
                var newState = (nestedTables[0].style.display === 'none') ? 'table' : 'none';
                nestedTables.forEach(function(table) {
                  table.style.display = newState;
                  var localIcon = table.previousElementSibling;
                  if (localIcon && localIcon.classList.contains('local-collapse-icon')) {
                    localIcon.innerHTML = (newState === 'table') ? '&#x25BC;' : '&#x25BA;';
                  }
                });
                globalIcon.innerHTML = (newState === 'table') ? '&#x25BC;' : '&#x25BA;';
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
                localIcon.innerHTML = '&#x25BA;'; // Start collapsed
                table.parentNode.insertBefore(localIcon, table);
                
                // Local icon toggles its specific nested table
                localIcon.addEventListener('click', function(e) {
                  table.style.display = (table.style.display === 'none') ? 'table' : 'none';
                  localIcon.innerHTML = (table.style.display === 'table') ? '&#x25BC;' : '&#x25BA;';
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


def contains_nested_list_of_dicts(obj):
    if isinstance(obj, list):
        return any(
            isinstance(item, dict)
            or contains_nested_dict_or_list_of_dicts(item)
            for item in obj
        )

    return False


def ensure_horizontal_json_table_format(data, debug=True):
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
        return html_table
    except Exception as e:
        print(f"Error converting JSON to HTML: {e}")
        return "<p>Error displaying data.</p>"

@app.route('/')
def dashboard():
    tabs = []
    if not DATA_DIR.exists():
        return "<p>Data directory not found. Please create a 'data' folder with JSON files.</p>"
    for filepath in sorted(DATA_DIR.glob("*.json")):
        data = load_json_file(filepath)
        if data is None:
            continue
        record_count = 0
        if isinstance(data, list):
            record_count = len(data)
        elif isinstance(data, dict):
            record_count = len(data.keys())
        tabs.append({
            "name": filepath.stem,
            "filename": filepath.name,
            "record_count": record_count
        })
    return render_template_string(HTML_TEMPLATE, tabs=tabs, dashboard=True)

@app.route('/query/<filename>', methods=['GET', 'POST'])
def query(filename):
    # Retrieve search term from GET or POST
    query_param = (request.form.get('query') or request.args.get('query') or "").lower()
    filepath = DATA_DIR / filename
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
    tabs = []
    # Build tabs info for drop-down
    for path in sorted(DATA_DIR.glob("*.json")):
        file_data = load_json_file(path)
        if file_data is None:
            continue
        record_count = 0
        if isinstance(file_data, list):
            record_count = len(file_data)
        elif isinstance(file_data, dict):
            record_count = len(file_data.keys())
        tabs.append({
            "name": path.stem,
            "filename": path.name,
            "record_count": record_count
        })
    return render_template_string(HTML_TEMPLATE, tabs=tabs, table=table, current_tab=filename, dashboard=False)

if __name__ == '__main__':
    args = parse_arguments()
    global DATA_DIR
    DATA_DIR = Path(args.input_dir)
    app.run(host='127.0.0.1', port=5000, debug=True)
