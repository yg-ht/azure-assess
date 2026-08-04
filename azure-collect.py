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
# Description:     Collects the JSON Azure configuration details from a target Azure account for later presentation
# Author:          Felix of You Gotta Hack That
# Created:         2025-04-02
# Last Modified:   2025-04-07
# Version:         0.9.0
#
# Purpose:         This script is part of the YGHT audit toolkit for secure
#                  Azure visibility. Designed for extensible JSON enrichment.
#
# Usage:
#   pipenv run pythonn azure-collect.py [options]
#
# Options:
#   -o, --output-dir DIR          Directory to save output files [default: azure-collect]
#   -d, --debug                   Enable debug output
#   -e, --endpoint NAME           Specify one or more endpoints to process (e.g., "Azure Subscriptions")
#   -l, --listendpoints           List all available API endpoints defined in this script
#   -L, --listparamendpoints      List only API endpoints that require parameters
#   -n, --donotenrich             Disable enrichment — perform enumeration only
#   -p, --paramendpointsonly      Collect only from endpoints that require parameters (no effect on enrichment)
#   --max-workers N              Maximum concurrent Azure CLI collection workers [default: 4]
#   --no-timing-summary          Disable the final Azure CLI timing summary
#   --collect-managed-role-definitions-cache
#                                Collect only Microsoft-managed role definitions into the cache and exit
#
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
import base64
import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys
import resource
import tempfile
import threading
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from datetime import datetime, timezone
from itertools import product
from pathlib import Path
from time import monotonic, sleep
from tqdm import tqdm

from azure_assess.collection_manifest import (
    CollectionManifestRecorder,
    endpoint_id,
    is_not_applicable_error,
    result_item_count,
    utc_timestamp,
)
from azure_assess.graph_collection import collect_registered_graph
from azure_assess.graph_collection import selected_graph_endpoints
from azure_assess.graph_endpoints import GRAPH_ENDPOINTS
from azure_assess.graph_runner import utc_interval

AUTH_CONFIG = {}
DEBUG = False
MAX_DEBUG_STDOUT_CHARS = 8000
DEFAULT_MAX_WORKERS = 4
DEFAULT_MANAGED_ROLE_DEFINITIONS_CACHE_PATH = Path("reference/azure_builtin_role_definitions.json")

PRINCIPAL_RESOLUTION_CACHE = {}
SOURCE_RECORD_CACHE = {}
SOURCE_FILE_INDEX_CACHE = {}
SUBSCRIPTION_ROLE_ASSIGNMENTS_CACHE = {}
TIMING_RECORDS = []
COLLECTION_ERRORS = []
COLLECTION_MANIFEST = None
ACCESS_VERIFICATION = {
    "arm": {"status": "not_evaluated"},
    "graph": {"status": "not_evaluated"},
}

PERMISSION_BASELINE_CHECKED = False
SOURCE_FILE_INDEX_LOCK = threading.Lock()
TIMING_RECORDS_LOCK = threading.Lock()
AZURE_CLI_EXTENSION_LOCK = threading.Lock()
COLLECTION_ERRORS_LOCK = threading.Lock()
AZURE_CLI_CONTEXT = threading.local()

REQUIRED_DIRECTORY_ROLES = {
    "Global Reader",
}

REQUIRED_SUBSCRIPTION_ROLES = {
    "Reader",
    "Security Reader",
}

REQUIRED_CUSTOM_ROLE_ACTIONS = {
    "microsoft.web/sites/config/web/connectionstrings/read",
    "Microsoft.KeyVault/vaults/secrets/read",
    "Microsoft.Storage/storageAccounts/listkeys/action",
    "Microsoft.Compute/virtualMachines/runCommands/read",
    "Microsoft.Insights/Components/Read",
    "Microsoft.Insights/Components/Query/Read",
    "Microsoft.CostManagement/query/action",
    "Microsoft.Web/sites/config/list/Action",
    "Microsoft.Web/sites/slots/config/list/Action",
}

REQUIRED_CUSTOM_ROLE_DATA_ACTIONS = {
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
}

GRAPH_ENDPOINT_PERMISSION_ALTERNATIVES = {
    "Active Directory Applications": ({
        "Application.Read.All",
        "Application.ReadWrite.All",
        "Application.ReadWrite.OwnedBy",
        "Directory.Read.All",
        "Directory.ReadWrite.All",
    },),
    "Active Directory Groups": ({
        "Group.Read.All",
        "Group.ReadWrite.All",
        "Directory.Read.All",
        "Directory.ReadWrite.All",
    },),
    "Active Directory Service Principals": ({
        "Application.Read.All",
        "Application.ReadWrite.All",
        "Application.ReadWrite.OwnedBy",
        "Directory.Read.All",
        "Directory.ReadWrite.All",
    },),
    "Active Directory Users": ({
        "User.Read.All",
        "User.ReadWrite.All",
        "Directory.Read.All",
        "Directory.ReadWrite.All",
    },),
    "Graph Conditional Access Policies": ({
        "Policy.Read.All",
        "Policy.Read.ConditionalAccess",
        "Policy.ReadWrite.ConditionalAccess",
    },),
    "Graph Named Locations": ({
        "Policy.Read.All",
        "Policy.Read.ConditionalAccess",
        "Policy.ReadWrite.ConditionalAccess",
    },),
    "Graph Authorization Policy": ({
        "Policy.Read.All",
        "Policy.ReadWrite.Authorization",
    },),
    "Graph Security Defaults Policy": ({
        "Policy.Read.All",
        "Policy.ReadWrite.SecurityDefaults",
    },),
    "Graph Directory Roles": ({
        "RoleManagement.Read.Directory",
        "Directory.Read.All",
        "Directory.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
    },),
    "Graph Directory Role Assignments": ({
        "RoleManagement.Read.All",
        "RoleManagement.Read.Directory",
        "Directory.Read.All",
        "Directory.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
    },),
    "Graph User Registration Details": ({"AuditLog.Read.All"},),
    "Graph Group Settings": ({
        "GroupSettings.Read.All",
        "GroupSettings.ReadWrite.All",
        "Directory.Read.All",
        "Directory.ReadWrite.All",
    },),
}
ARM_SCOPE_RESTRICTED_ENDPOINTS = {
    "Billing Accounts",
    "Management Groups",
    "Subscriptions",
}
NON_READ_COMMAND_MARKERS = (
    " list-keys",
    " listkeys",
    " connection-string",
    " appsettings ",
    " keys ",
    " keyvault key ",
    " query ",
    " run-command",
    " secret ",
    " storage blob ",
    " list-effective",
    " show-effective",
    "--auth-mode login",
)

AZURE_CLI_EXTENSION_COMMAND_PREFIXES = {
    ("appconfig",): "appconfig",
    ("iot",): "azure-iot",
    ("ml",): "ml",
    ("monitor", "app-insights"): "application-insights",
}
AZURE_CLI_EXTENSION_CACHE = set()
AZURE_CLI_OUTPUT_WARNING_SIGNATURES = [
    "behavior of this command has been altered",
    "is experimental and under development",
    "is in preview and under development",
    "is scheduled for retirement by",
    "command requires the extension",
    "command requires extension",
    "it will be installed first",
    "was successfully installed",
    "is already installed",
]
AZURE_CLI_MISSING_EXTENSION_SIGNATURES = [
    "requires the extension",
    "requires extension",
    "az extension add --name",
    "from the following extension",
    "not in the 'az' command group",
    "is misspelled or not recognized by the system",
]
AZURE_CLI_EXTENSION_NAME_PATTERNS = [
    re.compile(r"requires\s+the\s+extension\s+['\"]?([A-Za-z0-9_.-]+)", re.IGNORECASE),
    re.compile(r"requires\s+extension\s+['\"]?([A-Za-z0-9_.-]+)", re.IGNORECASE),
    re.compile(r"extension\s+['\"]?([A-Za-z0-9_.-]+)['\"]?\s+is\s+required", re.IGNORECASE),
    re.compile(r"az\s+extension\s+add\s+--name\s+['\"]?([A-Za-z0-9_.-]+)", re.IGNORECASE),
    re.compile(r"from\s+the\s+following\s+extension:\s*['\"]?([A-Za-z0-9_.-]+)", re.IGNORECASE),
]


def command_filename_prefix(command):
    """Build a filesystem-safe dataset prefix from an Azure CLI command."""
    normalized = command.lower().replace("{", "").replace("}", "")
    safe_chars = [
        char if char.isalnum() or char in "._-" else "_"
        for char in normalized
    ]
    return "_".join(part for part in "".join(safe_chars).split("_") if part)


def endpoint_output_prefix(endpoint):
    """Return the dataset prefix for an endpoint, allowing explicit overrides."""
    return endpoint.get("output_prefix") or command_filename_prefix(endpoint["cli_command"])


def bounded_worker_count(value):
    """Normalise a user-supplied worker count to a safe positive integer."""
    try:
        count = int(value)
    except (TypeError, ValueError):
        return DEFAULT_MAX_WORKERS
    return max(1, count)


def record_timing(endpoint_name, category, command, duration, returncode=None, result_count=None, retry_count=0):
    """Record command timing metadata for the final summary."""
    with TIMING_RECORDS_LOCK:
        TIMING_RECORDS.append(
            {
                "endpoint": endpoint_name or "unknown",
                "category": category or "command",
                "command": command,
                "duration": duration,
                "returncode": returncode,
                "result_count": result_count,
                "retry_count": retry_count,
            }
        )


def record_collection_error(command, message, result=None, endpoint_name=None, category="collection"):
    """Record a command failure so collection can continue and report all failures together."""
    result = result or {}
    stdout = result.get("stdout") or ""
    stderr = result.get("stderr") or ""
    process_output = "\n".join(
        stream.strip()
        for stream in (stdout, stderr)
        if stream and stream.strip()
    )
    with COLLECTION_ERRORS_LOCK:
        COLLECTION_ERRORS.append(
            {
                "endpoint": endpoint_name or "unknown",
                "category": category or "collection",
                "command": command,
                "message": message,
                "returncode": result.get("returncode"),
                "process_output": process_output,
            }
        )


def print_collection_error_summary():
    """Print all collection command failures seen during this run."""
    with COLLECTION_ERRORS_LOCK:
        errors = list(COLLECTION_ERRORS)

    if not errors:
        return

    print("\n\n")
    print("===========================================")
    print(f"[ERROR] Azure CLI collection completed with {len(errors)} command error(s).")
    print("The script continued after each endpoint failure so all observed errors are listed below.")
    for index, error in enumerate(errors, start=1):
        print("-------------------------------------------")
        print(f"[{index}] Endpoint: {error['endpoint']}")
        print(f"    Category: {error['category']}")
        print(f"    Command: {error['command']}")
        print(f"    Application message: {error['message']}")
        print(f"    Return code: {error['returncode']}")
        if error["process_output"]:
            print(f"    Process details: {error['process_output']}")
    print("===========================================")


def timed_run_az_cli(
    cmd,
    endpoint_name=None,
    category="collection",
    command_template=None,
    parameter_context=None,
    endpoint_identifier=None,
):
    """Run an Azure CLI command and capture timing metadata."""
    command_text = command_display(cmd)
    started_at = utc_timestamp()
    started = monotonic()
    previous_endpoint = getattr(AZURE_CLI_CONTEXT, "endpoint_name", None)
    previous_category = getattr(AZURE_CLI_CONTEXT, "category", None)
    AZURE_CLI_CONTEXT.endpoint_name = endpoint_name
    AZURE_CLI_CONTEXT.category = category
    try:
        result = run_az_cli(cmd)
    finally:
        AZURE_CLI_CONTEXT.endpoint_name = previous_endpoint
        AZURE_CLI_CONTEXT.category = previous_category
    duration = monotonic() - started
    retry_count = result.get("_retry_count", 0)
    record_timing(
        endpoint_name,
        category,
        command_text,
        duration,
        returncode=result.get("returncode"),
        result_count=result_item_count(result.get("json")),
        retry_count=retry_count,
    )
    if COLLECTION_MANIFEST is not None:
        # Keep the application-level classification separate from the direct
        # Azure CLI diagnostic returned by the attempted request.
        manifest_error = result.get("collection_error")
        diagnostic_output = (
            result.get("stdout")
            if result.get("returncode") not in (None, 0) or manifest_error
            else None
        )
        COLLECTION_MANIFEST.record_execution(
            endpoint_name=endpoint_name or "unknown",
            category=category,
            command_template=command_template or command_text,
            parameter_context=parameter_context,
            started_at=started_at,
            duration_seconds=duration,
            returncode=result.get("returncode"),
            result_count=result_item_count(result.get("json")),
            error_message=manifest_error,
            diagnostic_text=diagnostic_output,
            endpoint_identifier=endpoint_identifier,
            retry_count=retry_count,
            access_verification=endpoint_access_verification(
                endpoint_name,
                command_template or command_text,
            ),
        )
    return result


def print_timing_summary(limit=15):
    """Print the slowest commands without exposing command output."""
    if not TIMING_RECORDS:
        return

    total_duration = sum(item["duration"] for item in TIMING_RECORDS)
    print("\n[*] Azure CLI timing summary")
    print(f"    Commands timed: {len(TIMING_RECORDS)}")
    print(f"    Aggregate command time: {total_duration:.1f}s")

    slowest = sorted(TIMING_RECORDS, key=lambda item: item["duration"], reverse=True)[:limit]
    print("    Slowest commands:")
    for item in slowest:
        result_count = item["result_count"]
        count_text = "unknown" if result_count is None else str(result_count)
        print(
            f"      {item['duration']:.1f}s rc={item['returncode']} "
            f"count={count_text} [{item['category']}] {item['endpoint']}"
        )


def managed_role_cache_path(path=None):
    """Return the configured cache path for Microsoft-managed role definitions."""
    return Path(path or DEFAULT_MANAGED_ROLE_DEFINITIONS_CACHE_PATH)


def is_builtin_role_definition(role_definition):
    return str(role_definition.get("roleType") or "").lower() == "builtinrole"


def role_definition_guid(role_definition_id):
    """Return the stable role definition GUID from any Azure role definition ID form."""
    value = str(role_definition_id or "").strip()
    if not value:
        return None
    parts = value.rstrip("/").split("/")
    return parts[-1].lower()


def canonical_builtin_role_definition_id(role_definition_id):
    """Return a subscription-neutral ID for Microsoft-managed built-in roles."""
    guid = role_definition_guid(role_definition_id)
    if not guid:
        return role_definition_id
    return f"/providers/Microsoft.Authorization/roleDefinitions/{guid}"


def normalize_builtin_role_definition(role_definition):
    """Remove tenant-specific subscription paths from a built-in role definition."""
    normalized = deepcopy(role_definition)
    if normalized.get("id"):
        normalized["id"] = canonical_builtin_role_definition_id(normalized["id"])
    return normalized


def normalize_builtin_role_definitions(role_definitions):
    """Return built-in role definitions in the subscription-neutral cache shape."""
    return [normalize_builtin_role_definition(role) for role in role_definitions]


def strings_containing_subscription_path(value):
    """Yield strings that still contain customer-scoped Azure resource paths."""
    if isinstance(value, str):
        if value.lower().startswith("/subscriptions/"):
            yield value
        return
    if isinstance(value, dict):
        for child in value.values():
            yield from strings_containing_subscription_path(child)
        return
    if isinstance(value, list):
        for child in value:
            yield from strings_containing_subscription_path(child)


def validate_builtin_role_definitions(role_definitions):
    """Ensure the managed-role cache is not contaminated by custom roles."""
    if not isinstance(role_definitions, list):
        raise ValueError("Managed role definition cache payload must be a list.")

    invalid = [
        role.get("name") or role.get("id") or "<unknown>"
        for role in role_definitions
        if not isinstance(role, dict) or not is_builtin_role_definition(role)
    ]
    if invalid:
        sample = ", ".join(str(item) for item in invalid[:5])
        raise ValueError(f"Managed role definition cache contains non-built-in roles: {sample}")

    subscription_scoped_values = []
    for role in role_definitions:
        if isinstance(role, dict):
            subscription_scoped_values.extend(strings_containing_subscription_path(role))
    if subscription_scoped_values:
        sample = ", ".join(str(item) for item in subscription_scoped_values[:3])
        raise ValueError(f"Managed role definition cache contains subscription-scoped values: {sample}")


def load_managed_role_definitions_cache(path=None):
    """Load cached Microsoft-managed role definitions, normalising legacy cache IDs."""
    cache_path = managed_role_cache_path(path)
    if not cache_path.exists():
        return None

    with open(cache_path, encoding="utf-8") as f:
        payload = json.load(f)

    if isinstance(payload, dict):
        role_definitions = payload.get("roleDefinitions")
    else:
        role_definitions = payload

    # Older cache files stored built-in role IDs under the subscription used to
    # collect them. Normalise before validation so offline runs can keep using
    # those caches without leaking customer-specific identifiers downstream.
    role_definitions = normalize_builtin_role_definitions(role_definitions)
    validate_builtin_role_definitions(role_definitions)
    return role_definitions


def write_managed_role_definitions_cache(role_definitions, path=None, az_version=None):
    """Atomically write validated, subscription-neutral managed role definitions."""
    role_definitions = normalize_builtin_role_definitions(role_definitions)
    validate_builtin_role_definitions(role_definitions)
    cache_path = managed_role_cache_path(path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "schemaVersion": 2,
        "generatedAtUtc": utc_timestamp(),
        "collectionCommand": "az role definition list --query \"[?roleType=='BuiltInRole']\" --output json",
        "roleDefinitionIdFormat": "/providers/Microsoft.Authorization/roleDefinitions/{roleGuid}",
        "subscriptionIdentifiers": "removed",
        "azureCliVersion": az_version,
        "recordCount": len(role_definitions),
        "roleDefinitions": role_definitions,
    }

    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=str(cache_path.parent),
        delete=False,
    ) as temp_file:
        json.dump(payload, temp_file, indent=2)
        temp_name = temp_file.name

    os.replace(temp_name, cache_path)
    print(f"[+] Saved managed role definition cache: {cache_path}")
    return cache_path


def collect_managed_role_definitions_cache(path=None):
    """Collect only Microsoft-managed role definitions and write the dedicated cache."""
    command = "az role definition list --query \"[?roleType=='BuiltInRole']\" --output json"
    started_at = utc_timestamp()
    started = monotonic()
    role_definitions, error = run_json_command(command)
    if error:
        if COLLECTION_MANIFEST is not None:
            COLLECTION_MANIFEST.record_execution(
                endpoint_name="Managed Role Definitions",
                category="cache",
                command_template=command,
                started_at=started_at,
                duration_seconds=monotonic() - started,
                returncode=1,
                result_count=None,
                error_message=error,
                diagnostic_text=error,
            )
        print(f"[ERROR] Failed to collect managed role definitions: {error}")
        exit(1)

    role_definitions = normalize_builtin_role_definitions(role_definitions)
    validate_builtin_role_definitions(role_definitions)

    az_version, version_error = run_json_command("az version --output json")
    if version_error:
        az_version = {"error": version_error}

    cache_path = write_managed_role_definitions_cache(
        role_definitions,
        path=path,
        az_version=az_version,
    )
    if COLLECTION_MANIFEST is not None:
        if version_error:
            COLLECTION_MANIFEST.add_limitation(
                f"Could not determine Azure CLI version: {version_error}"
            )
        COLLECTION_MANIFEST.set_azure_cli_version(
            az_version.get("azure-cli") if isinstance(az_version, dict) else None
        )
        COLLECTION_MANIFEST.record_execution(
            endpoint_name="Managed Role Definitions",
            category="cache",
            command_template=command,
            started_at=started_at,
            duration_seconds=monotonic() - started,
            returncode=0,
            result_count=len(role_definitions),
            endpoint_identifier="managed_role_definitions_cache",
        )
        if cache_path is not None:
            COLLECTION_MANIFEST.record_dataset(
                cache_path,
                role_definitions,
                record_count=len(role_definitions),
                source_endpoint_identifier="managed_role_definitions_cache",
            )
    print(f"[✓] Cached {len(role_definitions)} managed role definitions.")
    return cache_path


AZURE_CLI_ENDPOINTS = [
    {"name": "API Management Services", "cli_command": "az apim list", "needs_pagination": False},
    {"name": "App Configuration Stores", "cli_command": "az appconfig list", "needs_pagination": False},
    {"name": "App Service Environments", "cli_command": "az appservice ase list", "needs_pagination": False},
    {"name": "App Service Plans", "cli_command": "az appservice plan list", "needs_pagination": False},
    {"name": "Application Gateways", "cli_command": "az network application-gateway list", "needs_pagination": False},
    {"name": "Application Insights", "cli_command": "az monitor app-insights component show", "needs_pagination": False},
    {"name": "Application Insights web tests", "cli_command": "az monitor app-insights web-test list", "needs_pagination": False},
    {"name": "Active Directory Applications", "cli_command": "az ad app list", "needs_pagination": True},
    {"name": "Active Directory Groups", "cli_command": "az ad group list", "needs_pagination": True},
    {"name": "Active Directory Service Principals", "cli_command": "az ad sp list --all", "needs_pagination": True},
    {"name": "Active Directory Users", "cli_command": "az ad user list", "needs_pagination": False},
    {"name": "Advisor Recommendations", "cli_command": "az advisor recommendation list", "needs_pagination": False},
    {"name": "Backups", "cli_command": "az backup vault list", "needs_pagination": False},
    {"name": "Bastion Hosts", "cli_command": "az network bastion list", "needs_pagination": False},
    {"name": "Batch Accounts", "cli_command": "az batch account list", "needs_pagination": False},
    {"name": "Billing Accounts", "cli_command": "az billing account list", "needs_pagination": False},
    {"name": "CDN Profiles", "cli_command": "az cdn profile list", "needs_pagination": False},
    {"name": "Consumption Usage", "cli_command": "az consumption usage list", "needs_pagination": True},
    {"name": "Container Instances", "cli_command": "az container list", "needs_pagination": False},
    {"name": "Container Registries", "cli_command": "az acr list", "needs_pagination": False},
    {"name": "Cognitive Services Accounts", "cli_command": "az cognitiveservices account list", "needs_pagination": False},
    {"name": "Cosmos DB Accounts", "cli_command": "az cosmosdb list", "needs_pagination": False},
    {"name": "Databricks Workspaces", "cli_command": "az databricks workspace list", "needs_pagination": False},
    {"name": "Data Factory Instances", "cli_command": "az datafactory list", "needs_pagination": False},
    {"name": "Defender Settings", "cli_command": "az security pricing list", "needs_pagination": False},
    {"name": "Defender Auto Provisioning Settings", "cli_command": "az security auto-provisioning-setting list", "needs_pagination": False},
    {"name": "Defender JIT Policies", "cli_command": "az security jit-policy list", "needs_pagination": False},
    {"name": "Defender General Settings", "cli_command": "az security setting list", "needs_pagination": False},
    {"name": "Defender Workspace Settings", "cli_command": "az security workspace-setting list", "needs_pagination": False},
    {"name": "DNS Zones", "cli_command": "az network dns zone list", "needs_pagination": False},
    {"name": "Event Grid Domains", "cli_command": "az eventgrid domain list", "needs_pagination": False},
    {"name": "Event Grid Topics", "cli_command": "az eventgrid topic list", "needs_pagination": False},
    {"name": "Event Hubs Namespaces", "cli_command": "az eventhubs namespace list", "needs_pagination": False},
    {"name": "ExpressRoute Circuits", "cli_command": "az network express-route list", "needs_pagination": False},
    {"name": "Front Door", "cli_command": "az afd profile list", "needs_pagination": False},
    {"name": "Function Apps", "cli_command": "az functionapp list", "needs_pagination": False},
    {"name": "HDInsight Clusters", "cli_command": "az hdinsight list", "needs_pagination": False},
    {"name": "IoT Hubs", "cli_command": "az iot hub list", "needs_pagination": False},
    {"name": "IoT DPS Instances", "cli_command": "az iot dps list", "needs_pagination": False},
    {"name": "Key Vaults", "cli_command": "az keyvault list", "needs_pagination": False},
    {"name": "Kubernetes Service", "cli_command": "az aks list", "needs_pagination": False},
    {"name": "Load Balancers", "cli_command": "az network lb list", "needs_pagination": False},
    {"name": "Locations", "cli_command": "az account list-locations", "needs_pagination": False},
    {"name": "Locks", "cli_command": "az lock list", "needs_pagination": False},
    {"name": "Logic Apps", "cli_command": "az logicapp list", "needs_pagination": False},
    {"name": "Log Analytics Workspaces", "cli_command": "az monitor log-analytics workspace list", "needs_pagination": False},
    {"name": "Managed Apps", "cli_command": "az managedapp list", "needs_pagination": False},
    {"name": "Managed Identities", "cli_command": "az identity list", "needs_pagination": False},
    {"name": "Machine Learning Workspaces", "cli_command": "az ml workspace list", "needs_pagination": False},
    {"name": "Maps Accounts", "cli_command": "az maps account list", "needs_pagination": False},
    {"name": "Monitor Activity Logs", "cli_command": "az monitor activity-log list", "needs_pagination": True},
    {"name": "NAT Gateways", "cli_command": "az network nat gateway list", "needs_pagination": False},
    {"name": "Network Interfaces", "cli_command": "az network nic list", "needs_pagination": False},
    {"name": "NSGs", "cli_command": "az network nsg list", "needs_pagination": False},
    {"name": "Policy Assignments", "cli_command": "az policy assignment list", "needs_pagination": True},
    {"name": "Policy Definitions", "cli_command": "az policy definition list --filter \"policyType eq 'Custom '\"", "needs_pagination": True},
    {"name": "Policy Set Definitions", "cli_command": "az policy set-definition list", "needs_pagination": True},
    {"name": "Policy Events", "cli_command": "az policy event list", "needs_pagination": True},
    {"name": "Policy Metadata", "cli_command": "az policy metadata list", "needs_pagination": True},
    {"name": "Policy States", "cli_command": "az policy state list --all", "needs_pagination": True},
    {"name": "PostgreSQL Servers", "cli_command": "az postgres flexible-server list", "needs_pagination": False},
    {"name": "Private DNS Zones", "cli_command": "az network private-dns zone list", "needs_pagination": False},
    {"name": "Private Endpoints", "cli_command": "az network private-endpoint list", "needs_pagination": False},
    {"name": "Public IP Addresses", "cli_command": "az network public-ip list", "needs_pagination": False},
    {"name": "Purview Accounts", "cli_command": "az purview account list", "needs_pagination": False},
    {"name": "Red Hat OpenShift", "cli_command": "az aro list", "needs_pagination": False},
    {"name": "Redis Caches", "cli_command": "az redis list", "needs_pagination": False},
    {"name": "Relay Namespaces", "cli_command": "az relay namespace list", "needs_pagination": False},
    {"name": "Resource Groups", "cli_command": "az group list", "needs_pagination": False},
    {"name": "Resources", "cli_command": "az resource list", "needs_pagination": True},
    {"name": "Role Assignments", "cli_command": "az role assignment list", "needs_pagination": True},
    {
        "name": "Role Definitions",
        "cli_command": "az role definition list --custom-role-only true",
        "needs_pagination": False,
        "output_prefix": "az_role_definition_custom_list",
    },
    {"name": "Security Alerts", "cli_command": "az security alert list", "needs_pagination": True},
    {"name": "Service Bus", "cli_command": "az servicebus namespace list", "needs_pagination": False},
    {"name": "SQL Servers", "cli_command": "az sql server list", "needs_pagination": False},
    {"name": "Storage Accounts", "cli_command": "az storage account list", "needs_pagination": False},
    {"name": "Subscriptions", "cli_command": "az account list", "needs_pagination": False},
    {"name": "Synapse Workspaces", "cli_command": "az synapse workspace list", "needs_pagination": False},
    {"name": "Template Specs", "cli_command": "az ts list", "needs_pagination": False},
    {"name": "Virtual Machines", "cli_command": "az vm list", "needs_pagination": False},
    {"name": "Virtual Machines IPs", "cli_command": "az vm list-ip-addresses", "needs_pagination": False},
    {"name": "VM Dedicated Host Groups", "cli_command": "az vm host group list", "needs_pagination": True},
    {"name": "VM Scale Sets", "cli_command": "az vmss list", "needs_pagination": False},
    {"name": "Web Apps", "cli_command": "az webapp list", "needs_pagination": False},
    {"name": "Kubernetes Environments", "cli_command": "az resource list --resource-type Microsoft.Web/kubeEnvironments", "needs_pagination": False},
    {"name": "Management Groups", "cli_command": "az account management-group list", "needs_pagination": False},
    {"name": "Workspaces", "cli_command": "az monitor account list", "needs_pagination": False},
    {"name": "Action Groups", "cli_command": "az monitor action-group list", "needs_pagination": False},
    {"name": "Data Collection", "cli_command": "az monitor data-collection endpoint list", "needs_pagination": False},
    {"name": "Data Collection Rules", "cli_command": "az monitor data-collection rule list", "needs_pagination": False},
    {"name": "Log Analytics Clusters", "cli_command": "az monitor log-analytics cluster list", "needs_pagination": False},
    {"name": "Log Analytics Solutions", "cli_command": "az monitor log-analytics solution list", "needs_pagination": False},
    {"name": "Log Profiles", "cli_command": "az monitor log-profiles list", "needs_pagination": False},
    {"name": "Metric-based alert rules", "cli_command": "az monitor metrics alert list", "needs_pagination": False},
    {"name": "Activity Log Alert rules", "cli_command": "az monitor activity-log alert list", "needs_pagination": False},
    {"name": "Scheduled Queries", "cli_command": "az monitor scheduled-query list", "needs_pagination": False},
    {"name": "Application Gateway WAF Policies", "cli_command": "az network application-gateway waf-policy list", "needs_pagination": False},
    {"name": "Network Watchers", "cli_command": "az network watcher list", "needs_pagination": False},
    {"name": "MySQL Servers", "cli_command": "az mysql flexible-server list", "needs_pagination": False},
    {"name": "Security Contacts", "cli_command": "az security contact list", "needs_pagination": False},
    {"name": "SignalR Services", "cli_command": "az signalr list", "needs_pagination": False},
    {"name": "Snapshots", "cli_command": "az snapshot list", "needs_pagination": False},
    {"name": "Graph Conditional Access Policies", "cli_command": "az rest --method get --url https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies", "needs_pagination": False},
    {"name": "Graph Named Locations", "cli_command": "az rest --method get --url https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations", "needs_pagination": False},
    {"name": "Graph Authorization Policy", "cli_command": "az rest --method get --url https://graph.microsoft.com/v1.0/policies/authorizationPolicy", "needs_pagination": False},
    {"name": "Graph Security Defaults Policy", "cli_command": "az rest --method get --url https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy", "needs_pagination": False},
    {"name": "Graph Directory Roles", "cli_command": "az rest --method get --url https://graph.microsoft.com/v1.0/directoryRoles", "needs_pagination": False},
    {"name": "Graph Directory Role Assignments", "cli_command": "az rest --method get --url https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments", "needs_pagination": False},
    {"name": "Graph User Registration Details", "cli_command": "az rest --method get --url https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails", "needs_pagination": False},
    {"name": "Graph Group Settings", "cli_command": "az rest --method get --url https://graph.microsoft.com/v1.0/groupSettings", "needs_pagination": False},
]

AZURE_CLI_ENDPOINTS_PARAMS = [
    {
        "name": "App Service Environment Details",
        "cli_command": "az appservice ase show --name {name}",
        "required_params": {"name": "az_appservice_ase_list"},
        "required_source_types": {"az_appservice_ase_list": {"Microsoft.Web/hostingEnvironments"}},
    },
    {
        "name": "App Service Environment VIPs",
        "cli_command": "az appservice ase list-addresses --name {name}",
        "required_params": {"name": "az_appservice_ase_list"},
        "required_source_types": {"az_appservice_ase_list": {"Microsoft.Web/hostingEnvironments"}},
    },
    {
        "name": "App Service Plan Details",
        "cli_command": "az appservice plan show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_appservice_plan_list", "resourceGroup": "az_appservice_plan_list"}
    },
    {
        "name": "API Management Service Details",
        "cli_command": "az apim show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_apim_list", "resourceGroup": "az_apim_list"},
        "required_source_types": {"az_apim_list": {"Microsoft.ApiManagement/service"}},
    },
    {
        "name": "App Service Plans in ASE",
        "cli_command": "az appservice ase list-plans --name {name}",
        "required_params": {"name": "az_appservice_ase_list"},
        "required_source_types": {"az_appservice_ase_list": {"Microsoft.Web/hostingEnvironments"}},
    },
    {
        "name": "Azure Metrics Namespaces",
        "cli_command": "az monitor metrics list-namespaces --resource {id}",
        "required_params": {"id": "az_resource_list"}
    },
    {
        "name": "Azure Network Resources",
        "cli_command": "az network list-service-tags --location {name}",
        "required_params": {"name": "az_account_list-locations"},
        "required_source_values": {
            "az_account_list-locations": {
                "type": {"Region"},
                "metadata.regionType": {"Physical"},
            }
        },
        # The location selects the service-tag release version; it does not
        # filter the returned tags. One physical region is therefore enough.
        "max_parameter_sets": 1,
    },
    {
        "name": "Virtual Networks",
        "cli_command": "az network vnet list --resource-group \"{name}\"",
        "required_params": {"name": "az_group_list"},
        "output_prefix": "az_network_vnet_list",
    },
    {
        "name": "Azure Subnet Resources",
        "cli_command": "az network vnet subnet list --resource-group {resourceGroup} --vnet-name {name}",
        "required_params": {"resourceGroup": "az_network_vnet_list", "name": "az_network_vnet_list"}
    },
    {
        "name": "Deployment (Resource Group Scope)",
        "cli_command": "az deployment group list --resource-group {name}",
        "required_params": {"name": "az_group_list"}
    },
    {
        "name": "Policy Assignment Details",
        "cli_command": "az rest --method get --url \"{id}?api-version=2025-11-01\"",
        "required_params": {"id": "az_policy_assignment_list"}
    },
    {
        "name": "Policy Definition Details",
        "cli_command": "az policy definition show --name {name}",
        "required_params": {"name": "az_policy_definition_list"}
    },
    {
        "name": "Policy Set Definition Details",
        "cli_command": "az policy set-definition show --name {name}",
        "required_params": {"name": "az_policy_set-definition_list"}
    },
    {
        "name": "Kubernetes Environment Details",
        "cli_command": "az resource show --ids {id} --api-version 2024-11-01 --include-response-body true",
        "required_params": {"id": "az_resource_list_--resource-type_microsoft.web_kubeenvironments"}
    },
    {
        "name": "VM Details",
        "cli_command": "az vm show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_vm_list", "resourceGroup": "az_vm_list"}
    },
    {
        "name": "VM NIC IDs",
        "cli_command": "az vm nic list --resource-group {resourceGroup} --vm-name {name}",
        "required_params": {"resourceGroup": "az_vm_list", "name": "az_vm_list"}
    },
    {
        "name": "VM Secrets",
        "cli_command": "az vm secret list --resource-group {resourceGroup} --name {name}",
        "required_params": {"resourceGroup": "az_vm_list", "name": "az_vm_list"}
    },
    {
        "name": "VM NIC details",
        "cli_command": "az vm nic show --resource-group {resourceGroup} --vm-name {vm_name} --nic {id}",
        "required_params": {"resourceGroup": "az_vm_nic_list", "vm_name": "az_vm_nic_list", "id": "az_vm_nic_list"}
    },
    {
        "name": "Function App Config",
        "cli_command": "az functionapp config show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_functionapp_list", "resourceGroup": "az_functionapp_list"},
    },
    {
        "name": "Function App Auth Settings",
        "cli_command": "az webapp auth show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_functionapp_list", "resourceGroup": "az_functionapp_list"},
        "output_prefix": "az_functionapp_auth_show",
    },
    {
        "name": "Function App AppSettings",
        "cli_command": "az functionapp config appsettings list --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_functionapp_list", "resourceGroup": "az_functionapp_list"},
    },
    {
        "name": "Function App Host Keys",
        "cli_command": "az functionapp keys list --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_functionapp_list", "resourceGroup": "az_functionapp_list"},
    },
    {
        "name": "Function App Access Restrictions",
        "cli_command": "az functionapp config access-restriction show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_functionapp_list", "resourceGroup": "az_functionapp_list"},
    },
    {
        "name": "Key Vault Details",
        "cli_command": "az keyvault show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_keyvault_list", "resourceGroup": "az_keyvault_list"},
    },
    {
        "name": "Key Vault Network Rules",
        "cli_command": "az keyvault network-rule list --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_keyvault_list", "resourceGroup": "az_keyvault_list"},
    },
    {
        "name": "Key Vault Private Endpoint Connections",
        "cli_command": "az keyvault show --name {name} --resource-group {resourceGroup} --query privateEndpointConnections",
        "required_params": {"name": "az_keyvault_list", "resourceGroup": "az_keyvault_list"},
    },
    {
        "name": "Key Vault Keys",
        "cli_command": "az keyvault key list --vault-name {name}",
        "required_params": {"name": "az_keyvault_list"},
    },
    {
        "name": "Key Vault Key Rotation Policies",
        "cli_command": "az keyvault key rotation-policy show --id {kid}",
        "required_params": {"kid": "az_keyvault_key_list"},
    },
    {
        "name": "Key Vault Secrets",
        "cli_command": "az keyvault secret list --vault-name {name}",
        "required_params": {"name": "az_keyvault_list"},
    },
    {
        "name": "Storage Account Keys",
        "cli_command": "az storage account keys list --account-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_storage_account_list", "resourceGroup": "az_storage_account_list"},
    },
    {
        "name": "Storage Queue CORS Rules",
        "cli_command": "az rest --method get --url \"{id}/queueServices/default?api-version=2025-06-01\" --query properties.cors.corsRules",
        "required_params": {"id": "az_storage_account_list"},
        "output_prefix": "az_storage_cors_list_--services_q_--account-name_name_--auth-mode_login",
    },
    {
        "name": "Storage File Service Properties",
        "cli_command": "az storage account file-service-properties show --account-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_storage_account_list", "resourceGroup": "az_storage_account_list"},
    },
    {
        "name": "Storage Shares",
        "cli_command": "az storage share-rm list --storage-account {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_storage_account_list", "resourceGroup": "az_storage_account_list"},
    },
    {
        "name": "Storage Containers",
        "cli_command": "az storage container list --account-name {name} --auth-mode login --query '[].{{container_name:name, storage_account_name:`{name}`, metadata:metadata, properties:properties}}'",
        "required_params": {"name": "az_storage_account_list"},
    },
    {
        "name": "Storage Queues",
        "cli_command": "az storage queue list --account-name {name} --auth-mode login",
        "required_params": {"name": "az_storage_account_list"},
    },
    {
        "name": "Storage Tables",
        "cli_command": "az storage table list --account-name {name} --auth-mode login",
        "required_params": {"name": "az_storage_account_list"},
    },
    {
        "name": "Storage Blob Service Properties",
        "cli_command": "az storage account blob-service-properties show --account-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_storage_account_list", "resourceGroup": "az_storage_account_list"},
    },
    {
        "name": "Storage Private Endpoint Connections",
        "cli_command": "az network private-endpoint-connection list --id {id}",
        "required_params": {"id": "az_storage_account_list"},
        "output_prefix": "az_network_private-endpoint-connection_list_--resource-group_resourcegroup_--resource-name_name_--type_microsoft.storage_storageaccounts",
    },
    {
        "name": "Storage Blobs",
        "cli_command": "az storage blob list --account-name {storage_account_name} --container-name {container_name}",
        "required_params": {"storage_account_name": "az_storage_container_list", "container_name": "az_storage_container_list"},
    },
    {
        "name": "Application Gateway Details",
        "cli_command": "az network application-gateway show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_network_application-gateway_list",
                            "resourceGroup": "az_network_application-gateway_list"},
    },
    {
        "name": "Application Gateway WAF Config",
        "cli_command": "az network application-gateway waf-config show --gateway-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_network_application-gateway_list",
                            "resourceGroup": "az_network_application-gateway_list"},
        "required_source_values": {
            "az_network_application-gateway_list": {
                "sku.tier": {"WAF", "WAF_v2"},
            }
        },
    },
    {
        "name": "App Service Private Endpoint Connections",
        "cli_command": "az network private-endpoint-connection list --id {id}",
        "required_params": {"id": "az_webapp_list"},
        "output_prefix": "az_network_private-endpoint-connection_list_--resource-group_resourcegroup_--resource-name_name_--type_microsoft.web_sites",
    },
    {
        "name": "Private Endpoint Details",
        "cli_command": "az network private-endpoint show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_network_private-endpoint_list",
                            "resourceGroup": "az_network_private-endpoint_list"},
    },
    {
        "name": "Private Endpoint DNS Zone Groups",
        "cli_command": "az network private-endpoint dns-zone-group list --endpoint-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_network_private-endpoint_list",
                            "resourceGroup": "az_network_private-endpoint_list"},
    },
    {
        "name": "NSG Details",
        "cli_command": "az network nsg show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_network_nsg_list", "resourceGroup": "az_network_nsg_list"},
    },
    {
        "name": "NSG Rule List",
        "cli_command": "az network nsg rule list --nsg-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_network_nsg_list", "resourceGroup": "az_network_nsg_list"},
    },
    {
        "name": "NAT Gateway Details",
        "cli_command": "az network nat gateway show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_network_nat_gateway_list", "resourceGroup": "az_network_nat_gateway_list"},
    },
    {
        "name": "Diagnostic Settings Categories",
        "cli_command": "az monitor diagnostic-settings categories list --resource {id}",
        "required_params": {"id": "az_resource_list"},
    },
    {
        "name": "Diagnostic Settings",
        "cli_command": "az monitor diagnostic-settings list --resource {id}",
        "required_params": {
            "id": "az_monitor_diagnostic-settings_categories_list",
        },
        "prefer_collection_context_params": {"id"},
        "preserve_empty_result": True,
    },
    {
        "name": "Application Insights Details",
        "cli_command": "az monitor app-insights component show --app {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_monitor_app-insights_component_show",
                            "resourceGroup": "az_monitor_app-insights_component_show"},
    },
    {
        "name": "Cognitive Services Account Details",
        "cli_command": "az cognitiveservices account show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_cognitiveservices_account_list", "resourceGroup": "az_cognitiveservices_account_list"},
    },
    {
        "name": "App Configuration KeyValues",
        "cli_command": "az appconfig kv list --name {name} --all",
        "required_params": {"name": "az_appconfig_list"},
    },
    {
        "name": "App Configuration KeyValue Revisions",
        "cli_command": "az appconfig revision list --name {name} --all",
        "required_params": {"name": "az_appconfig_list"},
    },
    {
        "name": "App Configuration Feature Flags",
        "cli_command": "az appconfig feature list --name {name} --all",
        "required_params": {"name": "az_appconfig_list"},
    },
    {
        "name": "App Configuration Snapshots",
        "cli_command": "az appconfig snapshot list --name {name} --all",
        "required_params": {"name": "az_appconfig_list"},
    },
    {
        "name": "App Configuration Private Endpoint Connections",
        "cli_command": "az network private-endpoint-connection list --id {id}",
        "required_params": {"id": "az_appconfig_list"},
        "output_prefix": "az_network_private-endpoint-connection_list_--resource-group_resourcegroup_--resource-name_name_--type_microsoft.appconfiguration_configurationstores",
    },
    {
        "name": "Function App Identity",
        "cli_command": "az functionapp identity show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_functionapp_list", "resourceGroup": "az_functionapp_list"},
    },
    {
        "name": "Function App VNet Integration",
        "cli_command": "az functionapp vnet-integration list --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_functionapp_list", "resourceGroup": "az_functionapp_list"},
    },
    {
        "name": "Function App CORS",
        "cli_command": "az functionapp cors show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_functionapp_list", "resourceGroup": "az_functionapp_list"},
    },
    {
        "name": "Function App Slots",
        "cli_command": "az functionapp deployment slot list --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_functionapp_list", "resourceGroup": "az_functionapp_list"},
    },
    {
        "name": "Web App VNet Integration",
        "cli_command": "az webapp vnet-integration list --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_webapp_list", "resourceGroup": "az_webapp_list"},
    },
    {
        "name": "Web App Auth Settings",
        "cli_command": "az webapp auth show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_webapp_list", "resourceGroup": "az_webapp_list"},
    },
    {
        "name": "Web App Access Restrictions",
        "cli_command": "az webapp config access-restriction show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_webapp_list", "resourceGroup": "az_webapp_list"},
    },
    {
        "name": "Web App Config",
        "cli_command": "az webapp config show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_webapp_list", "resourceGroup": "az_webapp_list"},
    },
    {
        "name": "Web App AppSettings",
        "cli_command": "az webapp config appsettings list --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_webapp_list", "resourceGroup": "az_webapp_list"},
    },
    {
        "name": "Web App Log Config",
        "cli_command": "az webapp log show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_webapp_list", "resourceGroup": "az_webapp_list"},
    },
    {
        "name": "App Service Plan VNet Integrations",
        "cli_command": "az appservice vnet-integration list --resource-group {resourceGroup} --plan {name}",
        "required_params": {"name": "az_appservice_plan_list", "resourceGroup": "az_appservice_plan_list"},
    },
    {
        "name": "Key Vault Private Link Resources",
        "cli_command": "az keyvault private-link-resource list --vault-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_keyvault_list", "resourceGroup": "az_keyvault_list"},
    },
    {
        "name": "Key Vault Private Endpoint Connections (explicit)",
        "cli_command": "az network private-endpoint-connection list --id {id}",
        "required_params": {"id": "az_keyvault_list"},
        "output_prefix": "az_network_private-endpoint-connection_list_--resource-group_resourcegroup_--resource-name_name_--type_microsoft.keyvault_vaults",
    },
    {
        "name": "Application Gateway SSL Certs",
        "cli_command": "az network application-gateway ssl-cert list --gateway-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_network_application-gateway_list",
                            "resourceGroup": "az_network_application-gateway_list"},
    },
    {
        "name": "Application Gateway SSL Profiles",
        "cli_command": "az network application-gateway ssl-profile list --gateway-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_network_application-gateway_list",
                            "resourceGroup": "az_network_application-gateway_list"},
    },
    {
        "name": "Application Gateway HTTP Settings",
        "cli_command": "az network application-gateway http-settings list --gateway-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_network_application-gateway_list",
                            "resourceGroup": "az_network_application-gateway_list"},
    },
    {
        "name": "Application Gateway Rules",
        "cli_command": "az network application-gateway rule list --gateway-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_network_application-gateway_list",
                            "resourceGroup": "az_network_application-gateway_list"},
    },
    {
        "name": "Application Gateway URL Path Maps",
        "cli_command": "az network application-gateway url-path-map list --gateway-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_network_application-gateway_list",
                            "resourceGroup": "az_network_application-gateway_list"},
    },
    {
        "name": "Application Gateway Rewrite Rule Sets",
        "cli_command": "az network application-gateway rewrite-rule set list --gateway-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_network_application-gateway_list",
                            "resourceGroup": "az_network_application-gateway_list"},
    },
    {
        "name": "Application Gateway Private Endpoint Connections",
        "cli_command": "az network private-endpoint-connection list --id {id}",
        "required_params": {"id": "az_network_application-gateway_list"},
        "output_prefix": "az_network_private-endpoint-connection_list_--resource-group_resourcegroup_--resource-name_name_--type_microsoft.network_applicationgateways",
    },
    {
        "name": "Private Endpoint IP Configs",
        "cli_command": "az network private-endpoint ip-config list --endpoint-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_network_private-endpoint_list", "resourceGroup": "az_network_private-endpoint_list"},
    },
    {
        "name": "NIC Effective NSG",
        "cli_command": "az network nic list-effective-nsg --ids {id}",
        "required_params": {"id": "az_network_nic_list"},
    },
    {
        "name": "Route Tables",
        "cli_command": "az network route-table list --resource-group {name}",
        "required_params": {"name": "az_group_list"},
    },
    {
        "name": "NIC Effective Route Table",
        "cli_command": "az network nic show-effective-route-table --ids {id}",
        "required_params": {"id": "az_network_nic_list"},
    },
    {
        "name": "Flow Logs (by location)",
        "cli_command": "az network watcher flow-log list --location {location}",
        "required_params": {"location": "az_network_watcher_list"},
        "output_prefix": "az_network_watcher_flow-log_list",
    },
    {
        "name": "Container Registry Private Endpoint Connections",
        "cli_command": "az network private-endpoint-connection list --id {id}",
        "required_params": {"id": "az_acr_list"},
        "output_prefix": "az_network_private-endpoint-connection_list_--resource-group_resourcegroup_--resource-name_name_--type_microsoft.containerregistry_registries",
    },
    {
        "name": "Cosmos DB SQL Role Assignments",
        "cli_command": "az cosmosdb sql role assignment list --account-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_cosmosdb_list", "resourceGroup": "az_cosmosdb_list"},
    },
    {
        "name": "Cosmos DB SQL Role Definitions",
        "cli_command": "az cosmosdb sql role definition list --account-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_cosmosdb_list", "resourceGroup": "az_cosmosdb_list"},
    },
    {
        "name": "Databricks Workspace Details",
        "cli_command": "az databricks workspace show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_databricks_workspace_list", "resourceGroup": "az_databricks_workspace_list"},
    },
    {
        "name": "Event Grid Domain Details",
        "cli_command": "az eventgrid domain show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_eventgrid_domain_list", "resourceGroup": "az_eventgrid_domain_list"},
    },
    {
        "name": "HDInsight Details",
        "cli_command": "az hdinsight show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_hdinsight_list", "resourceGroup": "az_hdinsight_list"},
    },
    {
        "name": "Machine Learning Workspace Details",
        "cli_command": "az ml workspace show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_ml_workspace_list", "resourceGroup": "az_ml_workspace_list"},
    },
    {
        "name": "Search Services",
        "cli_command": "az search service list --resource-group {name}",
        "required_params": {"name": "az_group_list"},
        "output_prefix": "az_search_service_list",
    },
    {
        "name": "Search Service Details",
        "cli_command": "az search service show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_search_service_list", "resourceGroup": "az_search_service_list"},
    },
    {
        "name": "Search Service Shared Private Links",
        "cli_command": "az search shared-private-link-resource list --service-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_search_service_list", "resourceGroup": "az_search_service_list"},
    },
    {
        "name": "Service Bus Namespace Details",
        "cli_command": "az servicebus namespace show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_servicebus_namespace_list", "resourceGroup": "az_servicebus_namespace_list"},
    },
    {
        "name": "Service Bus Queues",
        "cli_command": "az servicebus queue list --namespace-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_servicebus_namespace_list", "resourceGroup": "az_servicebus_namespace_list"},
    },
    {
        "name": "Service Bus Topics",
        "cli_command": "az servicebus topic list --namespace-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_servicebus_namespace_list", "resourceGroup": "az_servicebus_namespace_list"},
    },
    {
        "name": "SignalR Details",
        "cli_command": "az signalr show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_signalr_list", "resourceGroup": "az_signalr_list"},
    },
    {
        "name": "SQL Server Details",
        "cli_command": "az sql server show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_sql_server_list", "resourceGroup": "az_sql_server_list"},
    },
    {
        "name": "SQL Databases",
        "cli_command": "az sql db list --server {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_sql_server_list", "resourceGroup": "az_sql_server_list"},
    },
    {
        "name": "SQL Server Firewall Rules",
        "cli_command": "az sql server firewall-rule list --server {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_sql_server_list", "resourceGroup": "az_sql_server_list"},
    },
    {
        "name": "SQL Server AAD Admins",
        "cli_command": "az sql server ad-admin list --server {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_sql_server_list", "resourceGroup": "az_sql_server_list"},
    },
    {
        "name": "SQL Server Auditing Policy",
        "cli_command": "az sql server audit-policy show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_sql_server_list", "resourceGroup": "az_sql_server_list"},
    },
    {
        "name": "SQL Server Threat Policy",
        "cli_command": "az rest --method get --url \"{id}/securityAlertPolicies/Default?api-version=2023-08-01\"",
        "required_params": {"id": "az_sql_server_list"},
        "output_prefix": "az_sql_server_threat-policy_show",
    },
    {
        "name": "SQL Server TDE Protector",
        "cli_command": "az sql server tde-key show --server {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_sql_server_list", "resourceGroup": "az_sql_server_list"},
    },
    {
        "name": "SQL Database TDE",
        "cli_command": "az sql db tde show --server {serverName} --name {name} --resource-group {resourceGroup}",
        "required_params": {"serverName": "az_sql_db_list", "name": "az_sql_db_list", "resourceGroup": "az_sql_db_list"},
    },
    {
        "name": "SQL Database Auditing Policy",
        "cli_command": "az sql db audit-policy show --server {serverName} --name {name} --resource-group {resourceGroup}",
        "required_params": {"serverName": "az_sql_db_list", "name": "az_sql_db_list", "resourceGroup": "az_sql_db_list"},
    },
    {
        "name": "SQL Database Threat Policy",
        "cli_command": "az rest --method get --url \"{id}/securityAlertPolicies/default?api-version=2023-08-01\"",
        "required_params": {"id": "az_sql_db_list"},
        "output_prefix": "az_sql_db_threat-policy_show",
    },
    {
        "name": "SQL Server Vulnerability Assessment",
        "cli_command": "az rest --method get --url \"{id}/vulnerabilityAssessments/default?api-version=2023-08-01\"",
        "required_params": {"id": "az_sql_server_list"},
        "output_prefix": "az_sql_server_vuln-assessment_show",
    },
    {
        "name": "Backup Items",
        "cli_command": "az backup item list --vault-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_backup_vault_list", "resourceGroup": "az_backup_vault_list"},
    },
    {
        "name": "Backup Policies",
        "cli_command": "az backup policy list --vault-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_backup_vault_list", "resourceGroup": "az_backup_vault_list"},
    },
    {
        "name": "Managed Disks",
        "cli_command": "az disk list --resource-group \"{name}\"",
        "required_params": {"name": "az_group_list"},
    },
    {
        "name": "Managed Disk Details",
        "cli_command": "az disk show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_disk_list", "resourceGroup": "az_disk_list"},
    },
    {
        "name": "VM Extensions",
        "cli_command": "az vm extension list --vm-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_vm_list", "resourceGroup": "az_vm_list"},
    },
    {
        "name": "PostgreSQL Firewall Rules",
        "cli_command": "az postgres flexible-server firewall-rule list --resource-group {resourceGroup} --name {name}",
        "required_params": {"name": "az_postgres_flexible-server_list", "resourceGroup": "az_postgres_flexible-server_list"},
    },
    {
        "name": "PostgreSQL Configuration Parameters",
        "cli_command": "az postgres flexible-server parameter list --resource-group {resourceGroup} --server-name {name}",
        "required_params": {"name": "az_postgres_flexible-server_list", "resourceGroup": "az_postgres_flexible-server_list"},
    },
    {
        "name": "MySQL Configuration Parameters",
        "cli_command": "az mysql flexible-server parameter list --resource-group {resourceGroup} --server-name {name}",
        "required_params": {"name": "az_mysql_flexible-server_list", "resourceGroup": "az_mysql_flexible-server_list"},
    },
    {
        "name": "Subscription Diagnostic Settings",
        "cli_command": "az monitor diagnostic-settings subscription list --subscription {id}",
        "required_params": {"id": "az_account_list"},
    },
    {
        "name": "Defender Assessments",
        "cli_command": "az rest --method get --url \"/subscriptions/{id}/providers/Microsoft.Security/assessments?api-version=2020-01-01\"",
        "required_params": {"id": "az_account_list"},
        "extract_value": True,
    },
]


def parse_arguments():
    parser = argparse.ArgumentParser(description="Azure Audit Data Collection Tool")
    parser.add_argument(
        "-o", "--output-dir",
        type=str,
        default="azure-collect",
        help="Directory where output files will be saved (default: 'azure-collect')"
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Enabled debug output (default: disabled)"
    )
    parser.add_argument(
        "-e", "--endpoint",
        type=str,
        help="Specify one or more endpoints to process (e.g., 'Azure Subscriptions', 'Azure Role Assignments'). "
             "If not provided, all endpoints are processed."
    )
    parser.add_argument(
        "-l", "--listendpoints",
        action="store_true",
        help="Lists all available API end points in this script"
    )
    parser.add_argument(
        "-L", "--listparamendpoints",
        action="store_true",
        help="Lists all available API end points in this script that require parameters"
    )
    parser.add_argument(
        "-n", "--donotenrich",
        action="store_true",
        help="Disables all functionality that attempts to enrich the data sets with each other - enumeration only"
    )
    parser.add_argument(
        "-p", "--paramendpointsonly",
        action="store_true",
        help="Restricts collection to just datasets that require parameters, does not affect enrichment"
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=DEFAULT_MAX_WORKERS,
        help="Maximum concurrent Azure CLI collection workers. Use 1 for serial execution. Default: 4."
    )
    parser.add_argument(
        "--timing-summary",
        dest="timing_summary",
        action="store_true",
        default=True,
        help="Print a timing summary for Azure CLI collection commands. Enabled by default."
    )
    parser.add_argument(
        "--no-timing-summary",
        dest="timing_summary",
        action="store_false",
        help="Disable the Azure CLI timing summary."
    )
    parser.add_argument(
        "--collect-managed-role-definitions-cache",
        action="store_true",
        help=(
            "Collect only Microsoft-managed built-in Azure RBAC role definitions "
            "into the dedicated cache path, sanitise subscription-specific IDs, then exit."
        )
    )
    parser.add_argument(
        "--managed-role-definitions-cache-path",
        type=str,
        default=str(DEFAULT_MANAGED_ROLE_DEFINITIONS_CACHE_PATH),
        help=(
            "Path for the Microsoft-managed role definition cache. "
            f"Default: {DEFAULT_MANAGED_ROLE_DEFINITIONS_CACHE_PATH}"
        )
    )
    parser.add_argument(
        "--auth-method",
        choices=["existing", "device-code", "browser", "service-principal", "managed-identity"],
        default="existing",
        help=(
            "Azure authentication mode. 'existing' reuses the current Azure CLI session "
            "and will not trigger a login flow."
        )
    )
    parser.add_argument(
        "--tenant-id",
        type=str,
        help="Azure tenant ID for login and/or context selection. Defaults to AZURE_TENANT_ID."
    )
    parser.add_argument(
        "--subscription-id",
        type=str,
        help="Azure subscription ID to select after authentication. Defaults to AZURE_SUBSCRIPTION_ID."
    )
    parser.add_argument(
        "--client-id",
        type=str,
        help="Service principal or user-assigned managed identity client ID. Defaults to AZURE_CLIENT_ID."
    )
    parser.add_argument(
        "--client-secret",
        type=str,
        help="Service principal client secret. Defaults to AZURE_CLIENT_SECRET."
    )
    parser.add_argument(
        "--client-certificate",
        type=str,
        help="Client certificate path for service principal auth. Defaults to AZURE_CLIENT_CERTIFICATE_PATH."
    )
    parser.add_argument(
        "--client-certificate-password",
        type=str,
        help=(
            "Client certificate password for service principal auth. "
            "Defaults to AZURE_CLIENT_CERTIFICATE_PASSWORD."
        )
    )
    parser.add_argument(
        "--continue-with-missing-permissions",
        action="store_true",
        help=(
            "Non-interactively confirm that collection should continue when the initial "
            "permission baseline check reports missing or unverifiable permissions."
        )
    )
    parser.add_argument(
        "--graph-lookback-days", type=int, default=30,
        help="UTC lookback interval for time-bounded Microsoft Graph activity (default: 30).",
    )
    return parser.parse_args()


def summarise_statuses(assignments):
    """Print summary of resolvedPrincipal status types."""
    statuses = []

    for ra in assignments:
        rp = ra.get("resolvedPrincipal")
        if not rp:
            statuses.append("missing")
        else:
            statuses.append(rp.get("status", "unknown"))

    counter = Counter(statuses)
    print("\n🎯 Summary of Resolved Principal Statuses:\n")
    for status, count in counter.items():
        print(f"  {status:<10} : {count}")
    print("\n🧮 Total role assignments processed:", len(assignments))


def run_and_parse(cmd, entity_type, object_id):
    result = run_az_cli(cmd)
    stdout = result["stdout"].lower()

    if result["success"] and result["json"]:
        return {
            "type": entity_type,
            "name": result["json"].get("userPrincipalName") or result["json"].get("displayName"),
            "objectId": object_id,
            "status": "resolved",
            "details": result["json"]
        }

    if any(err in stdout for err in [
        "does not exist", "resource not found", "no match found", "could not be found"
    ]):
        return {"type": entity_type, "objectId": object_id, "status": "deleted", "name": None}

    if any(err in stdout for err in [
        "another tenant", "cross-tenant", "not found in tenant", "not part of tenant", "unable to find principal"
    ]):
        return {"type": entity_type, "objectId": object_id, "status": "foreign", "name": None}

    if "permission" in stdout or "insufficient" in stdout:
        return {"type": entity_type, "objectId": object_id, "status": "forbidden", "name": None}

    print(f"[~] Unresolved object ID {object_id} → status: unknown\n[DEBUG] stdout: {stdout.strip()}")
    return {
        "type": entity_type,
        "objectId": object_id,
        "status": "unknown",
        "name": None,
        "details": stdout.strip()
    }

def debug_memory(label):
    if not DEBUG:
        return

    usage_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    # Linux reports ru_maxrss in KiB. macOS reports bytes.
    if usage_kb > 10_000_000:
        usage_mb = usage_kb / (1024 * 1024)
    else:
        usage_mb = usage_kb / 1024

    print(f"[DEBUG] Memory after {label}: maxrss={usage_mb:.1f} MiB")

def get_argument_or_env(argument_value, env_name):
    if argument_value:
        return argument_value
    return os.getenv(env_name)

def build_auth_config(args):
    return {
        "auth_method": args.auth_method,
        "tenant_id": get_argument_or_env(args.tenant_id, "AZURE_TENANT_ID"),
        "subscription_id": get_argument_or_env(args.subscription_id, "AZURE_SUBSCRIPTION_ID"),
        "client_id": get_argument_or_env(args.client_id, "AZURE_CLIENT_ID"),
        "client_secret": get_argument_or_env(args.client_secret, "AZURE_CLIENT_SECRET"),
        "client_certificate": get_argument_or_env(args.client_certificate, "AZURE_CLIENT_CERTIFICATE_PATH"),
        "client_certificate_password": get_argument_or_env(
            args.client_certificate_password,
            "AZURE_CLIENT_CERTIFICATE_PASSWORD"
        ),
        "continue_with_missing_permissions": args.continue_with_missing_permissions,
    }


def shell_quote(value):
    return shlex.quote(str(value))


def command_argv(command):
    """Return a validated argument vector without invoking a command shell."""
    if isinstance(command, str):
        arguments = shlex.split(command)
    elif isinstance(command, (list, tuple)):
        arguments = list(command)
    else:
        raise TypeError("Azure CLI command must be a string or argument sequence")
    if not arguments or not all(
        isinstance(argument, str) and argument for argument in arguments
    ):
        raise ValueError("Azure CLI command arguments must be non-empty strings")
    if any("\x00" in argument for argument in arguments):
        raise ValueError("Azure CLI command arguments cannot contain NUL characters")
    return arguments


def command_display(command):
    """Return a shell-readable representation used only for diagnostics."""
    return shlex.join(command_argv(command))


def format_parameterised_cli_command(template, parameters):
    """Substitute parameter values after parsing the trusted CLI template."""
    markers = {
        name: f"__AZURE_ASSESS_PARAMETER_{index}__"
        for index, name in enumerate(parameters)
    }
    formatted_template = template.format(**markers)
    arguments = shlex.split(formatted_template)
    marker_values = {
        marker: str(parameters[name])
        for name, marker in markers.items()
    }
    if not marker_values:
        return arguments
    marker_pattern = re.compile(
        "|".join(re.escape(marker) for marker in marker_values)
    )
    return [
        marker_pattern.sub(lambda match: marker_values[match.group(0)], argument)
        for argument in arguments
    ]


def run_az_command(command, capture_output=False):
    return subprocess.run(
        command_argv(command),
        capture_output=capture_output,
        text=True,
    )


def run_az_cli_process(cmd):
    arguments = command_argv(cmd)
    process = subprocess.Popen(
        arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    stdout_lines = []
    debug_chars_printed = 0
    debug_truncated = False

    # Read both stdout and stderr in real time
    while True:
        stdout_line = process.stdout.readline()
        if stdout_line:
            stdout_lines.append(stdout_line)

            if DEBUG:
                remaining = MAX_DEBUG_STDOUT_CHARS - debug_chars_printed
                if remaining > 0:
                    print(stdout_line[:remaining], end='')
                    debug_chars_printed += min(len(stdout_line), remaining)
                elif not debug_truncated:
                    print("\n[DEBUG] stdout preview truncated")
                    debug_truncated = True
        if not stdout_line and process.poll() is not None:
            break
    process.wait()

    stdout = ''.join(stdout_lines).strip()
    return {
        "args": command_display(arguments),
        "returncode": process.returncode,
        "success": process.returncode == 0,
        "stdout": stdout,
        "json": None,
        "raw": stdout,
    }


def extract_required_extension_name(output):
    output = output or ""
    requirement_lines = [
        line
        for line in output.splitlines()
        if "requires" in line.lower() or "required" in line.lower() or "from the following extension" in line.lower()
    ]
    for pattern in AZURE_CLI_EXTENSION_NAME_PATTERNS:
        match = pattern.search("\n".join(requirement_lines))
        if match:
            return match.group(1).strip("'\".,")
    return None


def infer_extension_from_command(cmd):
    try:
        tokens = command_argv(cmd)
    except (TypeError, ValueError):
        return None

    if len(tokens) < 2 or tokens[0] != "az" or tokens[1] == "extension":
        return None

    command_parts = []
    for token in tokens[1:]:
        if token.startswith("-"):
            break
        command_parts.append(token)

    for prefix, extension_name in sorted(
        AZURE_CLI_EXTENSION_COMMAND_PREFIXES.items(),
        key=lambda item: len(item[0]),
        reverse=True,
    ):
        if tuple(command_parts[:len(prefix)]) == prefix:
            return extension_name

    return None


def resolve_missing_extension_name(cmd, output):
    explicit_extension_name = extract_required_extension_name(output)
    if explicit_extension_name:
        return explicit_extension_name

    output_lower = (output or "").lower()
    not_in_command_group = "not in the" in output_lower and "command group" in output_lower
    if any(sig in output_lower for sig in AZURE_CLI_MISSING_EXTENSION_SIGNATURES) or not_in_command_group:
        return infer_extension_from_command(cmd)

    return None


def ensure_az_extension_installed(extension_name):
    with AZURE_CLI_EXTENSION_LOCK:
        if extension_name in AZURE_CLI_EXTENSION_CACHE:
            return True

        extension_arg = shell_quote(extension_name)
        show_result = run_az_command(
            f"az extension show --name {extension_arg} --output json",
            capture_output=True,
        )
        if show_result.returncode == 0:
            AZURE_CLI_EXTENSION_CACHE.add(extension_name)
            return True

        print(f"[*] Installing missing Azure CLI extension: {extension_name}")
        add_result = run_az_command(
            f"az extension add --name {extension_arg} --yes",
            capture_output=True,
        )
        if add_result.returncode == 0:
            AZURE_CLI_EXTENSION_CACHE.add(extension_name)
            return True

        print(f"[!] Failed to install Azure CLI extension: {extension_name}")
        install_output = "\n".join(
            stream.strip()
            for stream in (add_result.stdout or "", add_result.stderr or "")
            if stream and stream.strip()
        )
        if install_output:
            print(install_output)
        return False


def install_missing_extension_and_retry(cmd, result):
    extension_name = resolve_missing_extension_name(cmd, result.get("stdout", ""))
    if not extension_name:
        return None

    if not ensure_az_extension_installed(extension_name):
        return None

    print(f"[*] Retrying command after ensuring Azure CLI extension '{extension_name}' is installed.")
    return run_az_cli_process(cmd)

def filter_az_cli_warning_output(output):
    output = output or ""
    output_lower = output.lower()

    matched_sigs = [
        sig
        for sig in AZURE_CLI_OUTPUT_WARNING_SIGNATURES
        if sig in output_lower
    ]

    if not matched_sigs:
        return output, matched_sigs

    filtered_lines = []
    for line in output.splitlines():
        line_lower = line.lower()
        if not any(sig in line_lower for sig in matched_sigs):
            filtered_lines.append(line)

    return "\n".join(filtered_lines), matched_sigs

def parse_json_from_az_output(output):
    """Parse JSON from Azure CLI output without making avoidable large copies.

    Fast path:
      Azure CLI normally returns output beginning with '[' or '{'. In that case,
      parse it directly.

    Fallback path:
      Some commands or extensions may print warning text before the JSON. For
      those cases, scan for the first JSON-looking character and attempt a raw
      decode from there.
    """
    stripped_output = (output or "").strip()
    if not stripped_output:
        return None

    decoder = json.JSONDecoder()

    if stripped_output[0] in ("{", "["):
        try:
            return json.loads(stripped_output)
        except json.JSONDecodeError:
            pass

    for index, char in enumerate(stripped_output):
        if char not in ("{", "["):
            continue

        try:
            value, _ = decoder.raw_decode(stripped_output[index:])
            return value
        except json.JSONDecodeError:
            continue

    raise ValueError("Azure CLI output did not contain valid JSON")


def set_az_account_context(subscription_id=None):
    if not subscription_id:
        return

    print(f"[*] Selecting Azure subscription context: {subscription_id}")
    result = run_az_command(
        f"az account set --subscription {shell_quote(subscription_id)}",
        capture_output=True
    )
    if result.returncode != 0:
        print("[ERROR] Failed to set Azure subscription context.")
        if result.stderr:
            print(result.stderr.strip())
        exit(1)


def validate_access_token(resource):
    result = run_az_command(
        f"az account get-access-token --resource {shell_quote(resource)} --output json",
        capture_output=True
    )
    return result.returncode == 0


def validate_auth_session(subscription_id=None):
    global AUTH_CONFIG

    print("[*] Verifying Azure CLI authentication context...")
    account_result = run_az_command("az account show --output json", capture_output=True)
    if account_result.returncode != 0:
        return False

    try:
        account = json.loads(account_result.stdout)
    except json.JSONDecodeError:
        return False

    if subscription_id and account.get("id") != subscription_id:
        print(
            f"[!] Azure CLI is authenticated for subscription {account.get('id')}, "
            f"expected {subscription_id}."
        )
        return False

    for resource in ("https://management.azure.com/", "https://graph.microsoft.com/"):
        if not validate_access_token(resource):
            print(f"[!] Azure CLI could not obtain an access token for {resource}")
            return False

    AUTH_CONFIG["tenant_id"] = account.get("tenantId") or AUTH_CONFIG.get("tenant_id")
    AUTH_CONFIG["subscription_id"] = account.get("id") or AUTH_CONFIG.get("subscription_id")

    return True


def run_json_command(command):
    """Run an Azure CLI command expected to return JSON."""
    result = run_az_command(command, capture_output=True)
    output = "\n".join(
        stream.strip()
        for stream in (result.stdout or "", result.stderr or "")
        if stream and stream.strip()
    )

    if result.returncode != 0:
        return None, output or f"Command failed with exit code {result.returncode}"

    if not result.stdout.strip():
        return None, "Command returned empty output"

    try:
        return json.loads(result.stdout), None
    except json.JSONDecodeError as exc:
        return None, f"Could not parse JSON output: {exc}"


def graph_rest_json(url):
    return run_json_command(
        f"az rest --method get --url {shell_quote(url)} --output json"
    )


def decode_jwt_payload(token):
    """Decode a JWT payload without validating the signature.

    This is only used to read Azure-issued token claims such as oid and tid.
    It is not an authentication decision.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode("utf-8")))
    except Exception as exc:
        raise ValueError(f"Could not decode access token payload: {exc}") from exc


def get_current_principal_context(subscription_id=None):
    account, account_error = run_json_command("az account show --output json")
    if account_error:
        return None, account_error

    token_response, token_error = run_json_command(
        "az account get-access-token --resource https://graph.microsoft.com/ --output json"
    )
    if token_error:
        return None, token_error

    try:
        claims = decode_jwt_payload(token_response["accessToken"])
    except (KeyError, ValueError) as exc:
        return None, str(exc)

    object_id = claims.get("oid")
    if not object_id:
        return None, "Could not determine current principal object ID from Graph token claim 'oid'."

    user_info = account.get("user") or {}

    return {
        "object_id": object_id,
        "tenant_id": claims.get("tid") or account.get("tenantId"),
        "subscription_id": subscription_id or account.get("id"),
        "principal_name": user_info.get("name") or claims.get("preferred_username") or claims.get("appid"),
        "principal_type": user_info.get("type") or claims.get("idtyp") or "unknown",
    }, None


def collection_records(payload):
    """Return dictionary records from a list or a common value[] wrapper."""
    if isinstance(payload, dict) and isinstance(payload.get("value"), list):
        payload = payload["value"]
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def arm_action_pattern_may_include_reads(action):
    """Conservatively identify an ARM action pattern that can include reads."""
    pattern = str(action or "").strip().lower()
    if not pattern:
        return False
    final_segment = pattern.rsplit("/", 1)[-1]
    if final_segment in {"write", "delete", "action"}:
        return False
    return True


def block_grants_unrestricted_arm_reads(block):
    """Return whether one role permission block grants every ARM read action."""
    actions = {
        str(item).strip().lower() for item in (block.get("actions") or [])
    }
    not_actions = {
        str(item).strip().lower() for item in (block.get("notActions") or [])
    }
    broad_read = bool(actions.intersection({"*", "*/read"}))
    read_exclusions = {
        item for item in not_actions if arm_action_pattern_may_include_reads(item)
    }
    return broad_read and not read_exclusions


def assigned_role_definitions(role_assignments):
    """Load role definitions for unconditional assignments relevant to the caller."""
    definitions = []
    errors = []
    definition_ids = {
        str(assignment.get("roleDefinitionId"))
        for assignment in role_assignments
        if assignment.get("roleDefinitionId") and not assignment.get("condition")
    }
    for definition_id in sorted(definition_ids):
        definition_name = definition_id.rstrip("/").split("/")[-1]
        payload, error = run_json_command(
            "az role definition list "
            f"--name {shell_quote(definition_name)} "
            "--output json"
        )
        if error:
            errors.append(error)
            continue
        definitions.extend(collection_records(payload))
    return definitions, errors


def deny_permission_may_block_reads(permission):
    """Conservatively identify a deny permission that could remove ARM reads."""
    actions = {
        str(item).strip().lower()
        for item in (permission.get("actions") or [])
        if item
    }
    not_actions = {
        str(item).strip().lower()
        for item in (permission.get("notActions") or [])
        if item
    }
    for action in actions:
        if not arm_action_pattern_may_include_reads(action):
            continue
        if action.endswith("/read"):
            if not any(fnmatch.fnmatchcase(action, exclusion) for exclusion in not_actions):
                return True
            continue
        if "*" not in action:
            # Unknown control-plane operations are treated conservatively.
            return True
        if action == "*" and not_actions.intersection({"*", "*/read"}):
            continue
        if action.endswith("/*"):
            read_exclusion = f"{action}/read"
            if read_exclusion in not_actions:
                continue
        return True
    return False


def deny_assignment_read_effect(deny_assignments, principal_ids, groups_complete):
    """Return whether an applicable read deny exists and evaluation was complete."""
    all_principals_id = "00000000-0000-0000-0000-000000000000"
    known_ids = {str(item).lower() for item in principal_ids if item}
    evaluation_complete = True
    applicable_read_denies = 0

    for assignment in deny_assignments:
        properties = assignment.get("properties")
        if not isinstance(properties, dict):
            properties = assignment
        permissions = properties.get("permissions")
        if not isinstance(permissions, list):
            evaluation_complete = False
            continue
        if not any(
            isinstance(permission, dict)
            and deny_permission_may_block_reads(permission)
            for permission in permissions
        ):
            continue

        principals = properties.get("principals")
        exclusions = properties.get("excludePrincipals")
        if not isinstance(principals, list) or not isinstance(exclusions, list):
            evaluation_complete = False
            continue
        principal_entries = [item for item in principals if isinstance(item, dict)]
        exclusion_ids = {
            str(item.get("id")).lower()
            for item in exclusions
            if isinstance(item, dict) and item.get("id")
        }
        if known_ids.intersection(exclusion_ids):
            continue
        target_ids = {
            str(item.get("id")).lower()
            for item in principal_entries
            if item.get("id")
        }
        if all_principals_id in target_ids or known_ids.intersection(target_ids):
            applicable_read_denies += 1
            continue
        targets_groups = any(
            str(item.get("type") or "").lower() == "group"
            for item in principal_entries
        )
        if targets_groups and not groups_complete:
            evaluation_complete = False

    return applicable_read_denies, evaluation_complete


def collect_arm_access_verification(principal_object_id):
    """Prove broad subscription reads using documented RBAC evidence."""
    subscription_id = AUTH_CONFIG.get("subscription_id")
    scope = f"/subscriptions/{subscription_id}" if subscription_id else None
    record = {
        "status": "visibility_unverified",
        "scope": scope,
        "method": "arm_role_and_deny_assignments",
        "reason_code": "subscription_scope_unavailable",
        "broad_read_granted": False,
        "role_assignment_count": 0,
        "role_definition_count": 0,
        "deny_assignment_count": 0,
        "applicable_read_deny_count": 0,
    }
    if not subscription_id:
        return record
    if not principal_object_id:
        record["reason_code"] = "principal_object_id_unavailable"
        return record

    group_ids, group_error = get_transitive_group_ids(principal_object_id)
    principal_ids = {
        str(item).lower()
        for item in {principal_object_id, *group_ids}
        if item
    }
    assignments, assignment_error = get_subscription_role_assignments(subscription_id)
    if assignment_error:
        record["reason_code"] = "role_assignment_query_failed"
        return record
    relevant_assignments = [
        assignment
        for assignment in collection_records(assignments)
        if str(assignment.get("principalId") or "").lower() in principal_ids
    ]
    record["role_assignment_count"] = len(relevant_assignments)
    definitions, definition_errors = assigned_role_definitions(relevant_assignments)
    record["role_definition_count"] = len(definitions)
    broad_read_granted = any(
        block_grants_unrestricted_arm_reads(permission)
        for definition in definitions
        for permission in (definition.get("permissions") or [])
        if isinstance(permission, dict)
    )
    record["broad_read_granted"] = broad_read_granted

    deny_assignments, deny_error = run_json_command(
        "az role deny-assignment list "
        f"--scope {shell_quote(scope)} "
        "--output json"
    )
    deny_records = collection_records(deny_assignments)
    record["deny_assignment_count"] = len(deny_records)
    applicable_denies, deny_evaluation_complete = deny_assignment_read_effect(
        deny_records,
        principal_ids,
        groups_complete=not bool(group_error),
    )
    record["applicable_read_deny_count"] = applicable_denies

    if not broad_read_granted:
        record["reason_code"] = (
            "role_definition_query_incomplete"
            if definition_errors
            else "subscription_wide_arm_read_not_verified"
        )
    elif deny_error:
        record["reason_code"] = "deny_assignment_query_failed"
    elif not deny_evaluation_complete:
        record["reason_code"] = "deny_assignment_evaluation_incomplete"
    elif applicable_denies:
        record["reason_code"] = "applicable_read_deny_assignment_present"
    else:
        record.update(
            {
                "status": "access_verified",
                "reason_code": "subscription_wide_arm_read_verified",
            }
        )
    return record


def collect_automatic_access_verification():
    """Collect non-secret ARM and Graph access evidence without prompting."""

    graph_record = {
        "status": "visibility_unverified",
        "method": "graph_access_token_claims",
        "reason_code": "graph_token_unavailable",
        "token_type": "unknown",
        "granted_permissions": [],
    }
    token_response, token_error = run_json_command(
        "az account get-access-token "
        "--resource https://graph.microsoft.com/ "
        "--output json"
    )
    claims = {}
    if not token_error:
        try:
            claims = decode_jwt_payload(token_response["accessToken"])
        except (KeyError, ValueError):
            claims = {}
        roles = sorted(
            {str(item) for item in claims.get("roles", []) if item}
        )
        scopes = sorted(
            {item for item in str(claims.get("scp") or "").split() if item}
        )
        token_type = (
            "application"
            if claims.get("idtyp") == "app" or (roles and not scopes)
            else "delegated" if scopes else "unknown"
        )
        granted_permissions = roles if token_type == "application" else scopes
        graph_record.update(
            {
                # Observing token claims supplies endpoint-specific evidence, but
                # it does not prove complete Graph visibility in the abstract.
                "status": "visibility_unverified",
                "reason_code": (
                    "application_roles_observed"
                    if token_type == "application" and roles
                    else (
                        "delegated_scopes_observed"
                        if token_type == "delegated" and scopes
                        else "graph_permission_claims_unavailable"
                    )
                ),
                "token_type": token_type,
                "granted_permissions": granted_permissions,
            }
        )
    elif COLLECTION_MANIFEST is not None:
        COLLECTION_MANIFEST.add_limitation(
            "Could not inspect Microsoft Graph permission claims for visibility verification"
        )

    arm_record = collect_arm_access_verification(claims.get("oid"))
    if (
        arm_record["status"] != "access_verified"
        and COLLECTION_MANIFEST is not None
    ):
        COLLECTION_MANIFEST.add_limitation(
            "Could not prove unrestricted Azure read visibility at the selected subscription scope"
        )

    verification = {"arm": arm_record, "graph": graph_record}
    global ACCESS_VERIFICATION
    ACCESS_VERIFICATION = verification
    if COLLECTION_MANIFEST is not None:
        COLLECTION_MANIFEST.set_access_verification(verification)
    return verification


def endpoint_access_verification(endpoint_name, command_template):
    """Apply collected access evidence conservatively to one endpoint."""
    name = str(endpoint_name or "unknown")
    command = str(command_template or "")
    lowered_command = command.lower()
    if lowered_command.startswith("az config "):
        return {
            "status": "not_evaluated",
            "plane": "local",
            "method": "not_applicable",
            "reason_code": "local_cli_configuration",
        }

    is_graph = (
        name in GRAPH_ENDPOINT_PERMISSION_ALTERNATIVES
        or "graph.microsoft.com" in lowered_command
        or lowered_command.startswith("az ad ")
    )
    if is_graph:
        alternatives = GRAPH_ENDPOINT_PERMISSION_ALTERNATIVES.get(name)
        required_permissions = sorted(
            {
                permission
                for group in (alternatives or ())
                for permission in group
            }
        )
        graph = ACCESS_VERIFICATION.get("graph", {})
        granted = set(graph.get("granted_permissions") or [])
        if graph.get("token_type") == "application" and alternatives and any(
            granted.intersection(group) for group in alternatives
        ):
            status = "access_verified"
            reason_code = "required_graph_application_permission_present"
        elif graph.get("token_type") == "delegated":
            status = "visibility_unverified"
            reason_code = "delegated_graph_access_requires_user_privileges"
        elif not alternatives:
            status = "visibility_unverified"
            reason_code = "endpoint_permission_not_mapped"
        else:
            status = "visibility_unverified"
            reason_code = "required_graph_application_permission_not_verified"
        return {
            "status": status,
            "plane": "microsoft_graph",
            "scope": AUTH_CONFIG.get("tenant_id"),
            "method": "graph_access_token_claims",
            "reason_code": reason_code,
            "required_permissions": required_permissions,
        }

    arm_scope = ACCESS_VERIFICATION.get("arm", {}).get("scope")
    arm = ACCESS_VERIFICATION.get("arm", {})
    if name in ARM_SCOPE_RESTRICTED_ENDPOINTS and arm.get("status") == "access_verified":
        return {
            "status": "scope_restricted",
            "plane": "azure_resource_manager",
            "scope": arm_scope,
            "method": "arm_role_and_deny_assignments",
            "reason_code": "endpoint_scope_exceeds_selected_subscription",
        }
    if name in ARM_SCOPE_RESTRICTED_ENDPOINTS:
        return {
            "status": "visibility_unverified",
            "plane": "azure_resource_manager",
            "scope": arm_scope,
            "method": "arm_role_and_deny_assignments",
            "reason_code": "endpoint_and_subscription_scope_access_unverified",
        }
    if any(marker in lowered_command for marker in NON_READ_COMMAND_MARKERS):
        return {
            "status": "visibility_unverified",
            "plane": "azure_or_service_data_plane",
            "scope": arm_scope,
            "method": "endpoint_permission_not_mapped",
            "reason_code": "specialised_action_not_verified",
        }
    if arm.get("status") == "access_verified":
        return {
            "status": "access_verified",
            "plane": "azure_resource_manager",
            "scope": arm_scope,
            "method": "arm_role_and_deny_assignments",
            "reason_code": "subscription_wide_arm_read_verified",
            "required_permissions": ["*/read"],
        }
    return {
        "status": "visibility_unverified",
        "plane": "azure_resource_manager",
        "scope": arm_scope,
        "method": "arm_role_and_deny_assignments",
        "reason_code": arm.get("reason_code") or "arm_read_access_not_verified",
        "required_permissions": ["*/read"],
    }


def graph_collection_values(url):
    """Return all value[] entries from a Microsoft Graph collection, following nextLink."""
    values = []
    next_url = url

    while next_url:
        data, error = graph_rest_json(next_url)
        if error:
            return values, error

        if isinstance(data, dict):
            values.extend(data.get("value", []))
            next_url = data.get("@odata.nextLink")
        else:
            return values, "Unexpected Microsoft Graph response shape"

    return values, None


def get_transitive_group_ids(principal_object_id):
    encoded_id = urllib.parse.quote(principal_object_id)
    url = (
        f"https://graph.microsoft.com/v1.0/directoryObjects/{encoded_id}/transitiveMemberOf"
        "?%24select=id,displayName"
    )

    memberships, error = graph_collection_values(url)
    if error:
        return set(), error

    return {
        item.get("id")
        for item in memberships
        if item.get("id")
    }, None


def get_directory_role_names_for_principal_ids(principal_ids):
    role_names = set()
    query = urllib.parse.urlencode({
        "$expand": "roleDefinition($select=id,displayName)",
        "$select": "id,principalId,roleDefinitionId",
    })
    url = f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?{query}"

    assignments, error = graph_collection_values(url)
    if error:
        return role_names, [error]

    for assignment in assignments:
        if assignment.get("principalId") not in principal_ids:
            continue

        role_definition = assignment.get("roleDefinition") or {}
        display_name = role_definition.get("displayName")
        if display_name:
            role_names.add(display_name)

    return role_names, []


def permission_pattern_covers(required_permission, granted_patterns, denied_patterns=None):
    required = required_permission.lower()
    granted_patterns = [pattern.lower() for pattern in (granted_patterns or [])]
    denied_patterns = [pattern.lower() for pattern in (denied_patterns or [])]

    granted = any(fnmatch.fnmatchcase(required, pattern) for pattern in granted_patterns)
    denied = any(fnmatch.fnmatchcase(required, pattern) for pattern in denied_patterns)

    return granted and not denied


def get_subscription_role_assignments(subscription_id):
    if subscription_id in SUBSCRIPTION_ROLE_ASSIGNMENTS_CACHE:
        return deepcopy(SUBSCRIPTION_ROLE_ASSIGNMENTS_CACHE[subscription_id]), None

    scope = f"/subscriptions/{subscription_id}"
    assignments, error = run_json_command(
        "az role assignment list "
        f"--scope {shell_quote(scope)} "
        "--include-inherited "
        "--output json"
    )
    if not error:
        SUBSCRIPTION_ROLE_ASSIGNMENTS_CACHE[subscription_id] = deepcopy(assignments)
    return assignments, error


def get_subscription_role_names_for_principal_ids(subscription_id, principal_ids):
    assignments, assignment_error = get_subscription_role_assignments(subscription_id)
    if assignment_error:
        return set(), [assignment_error]

    role_names = {
        assignment.get("roleDefinitionName")
        for assignment in assignments or []
        if assignment.get("principalId") in principal_ids
        and assignment.get("roleDefinitionName")
    }

    return role_names, []


def get_custom_role_definitions_for_assignments(role_assignments):
    role_definition_ids = {
        assignment.get("roleDefinitionId")
        for assignment in role_assignments
        if assignment.get("roleDefinitionId")
    }

    if not role_definition_ids:
        return [], None

    role_definitions, error = run_json_command(
        "az role definition list --custom-role-only true --output json"
    )
    if error:
        return [], error

    matched_definitions = []
    missing_definition_ids = set(role_definition_ids)

    for role_definition in role_definitions or []:
        role_id = role_definition.get("id")
        role_name_guid = role_definition.get("name")

        if role_id in role_definition_ids or any(
            role_id and role_id.lower().endswith(f"/{definition_id.split('/')[-1].lower()}")
            for definition_id in role_definition_ids
        ) or any(
            role_name_guid and definition_id.lower().endswith(f"/{role_name_guid.lower()}")
            for definition_id in role_definition_ids
        ):
            matched_definitions.append(role_definition)
            if role_id:
                missing_definition_ids.discard(role_id)
            if role_name_guid:
                missing_definition_ids = {
                    definition_id
                    for definition_id in missing_definition_ids
                    if not definition_id.lower().endswith(f"/{role_name_guid.lower()}")
                }

    for definition_id in sorted(missing_definition_ids):
        definition_name = definition_id.split("/")[-1]
        role_definition, show_error = run_json_command(
            f"az role definition list --name {shell_quote(definition_name)} --output json"
        )
        if show_error:
            continue

        if role_definition:
            candidate = role_definition[0] if isinstance(role_definition, list) else role_definition
            if candidate.get("roleType") == "CustomRole":
                matched_definitions.append(candidate)

    return matched_definitions, None


def check_custom_role_permissions(subscription_id, principal_ids):
    assignments, assignment_error = get_subscription_role_assignments(subscription_id)
    if assignment_error:
        return {
            "present_custom_roles": [],
            "missing_actions": sorted(REQUIRED_CUSTOM_ROLE_ACTIONS),
            "missing_data_actions": sorted(REQUIRED_CUSTOM_ROLE_DATA_ACTIONS),
            "errors": [assignment_error],
        }

    relevant_assignments = [
        assignment for assignment in assignments or []
        if assignment.get("principalId") in principal_ids
    ]

    custom_role_definitions, definition_error = get_custom_role_definitions_for_assignments(relevant_assignments)
    errors = []
    if definition_error:
        errors.append(definition_error)

    allowed_actions = []
    denied_actions = []
    allowed_data_actions = []
    denied_data_actions = []
    present_custom_roles = []

    for role_definition in custom_role_definitions:
        present_custom_roles.append(role_definition.get("roleName") or role_definition.get("name"))

        for permission_block in role_definition.get("permissions", []):
            allowed_actions.extend(permission_block.get("actions", []))
            denied_actions.extend(permission_block.get("notActions", []))
            allowed_data_actions.extend(permission_block.get("dataActions", []))
            denied_data_actions.extend(permission_block.get("notDataActions", []))

    missing_actions = [
        action for action in REQUIRED_CUSTOM_ROLE_ACTIONS
        if not permission_pattern_covers(action, allowed_actions, denied_actions)
    ]

    missing_data_actions = [
        action for action in REQUIRED_CUSTOM_ROLE_DATA_ACTIONS
        if not permission_pattern_covers(action, allowed_data_actions, denied_data_actions)
    ]

    return {
        "present_custom_roles": sorted({role for role in present_custom_roles if role}),
        "missing_actions": sorted(missing_actions),
        "missing_data_actions": sorted(missing_data_actions),
        "errors": errors,
    }


def print_permission_baseline_warning(report):
    print("\n[!] Permission baseline check did not pass cleanly.")
    print("    The collection may be incomplete, especially for identity, security, secret, storage, cost, and app service configuration data.\n")

    print("    Principal:")
    print(f"      Name:          {report['principal'].get('principal_name')}")
    print(f"      Type:          {report['principal'].get('principal_type')}")
    print(f"      Object ID:     {report['principal'].get('object_id')}")
    print(f"      Subscription:  {report['principal'].get('subscription_id')}")
    print("")

    if report["missing_directory_roles"]:
        print("    Missing or unverifiable Microsoft Entra directory roles:")
        for role in report["missing_directory_roles"]:
            print(f"      - {role}")
        print("")

    if report["directory_role_errors"]:
        print("    Directory role check errors:")
        for error in report["directory_role_errors"]:
            print(f"      - {error}")
        print("")

    if report["missing_subscription_roles"]:
        print("    Missing or unverifiable Azure subscription roles:")
        for role in report["missing_subscription_roles"]:
            print(f"      - {role}")
        print("")

    if report["subscription_role_errors"]:
        print("    Azure subscription role check errors:")
        for error in report["subscription_role_errors"]:
            print(f"      - {error}")
        print("")

    custom_role_report = report["custom_role_report"]
    if not custom_role_report["present_custom_roles"]:
        print("    No assigned custom Azure RBAC role was found for this principal at the selected subscription scope.")
        print("")
    else:
        print("    Assigned custom Azure RBAC role(s) considered:")
        for role in custom_role_report["present_custom_roles"]:
            print(f"      - {role}")
        print("")

    if custom_role_report["missing_actions"]:
        print("    Missing custom role actions:")
        for action in custom_role_report["missing_actions"]:
            print(f"      - {action}")
        print("")

    if custom_role_report["missing_data_actions"]:
        print("    Missing custom role dataActions:")
        for action in custom_role_report["missing_data_actions"]:
            print(f"      - {action}")
        print("")

    if custom_role_report["errors"]:
        print("    Azure RBAC custom role check errors:")
        for error in custom_role_report["errors"]:
            print(f"      - {error}")
        print("")

    if report["group_membership_error"]:
        print("    Group membership warning:")
        print(f"      - {report['group_membership_error']}")
        print("")


def confirm_continue_after_permission_warning(auto_confirm=False):
    if auto_confirm:
        print("[!] Continuing despite missing or unverifiable permissions because --continue-with-missing-permissions was supplied.")
        return

    if not sys.stdin.isatty():
        print("[ERROR] Permission baseline check failed and this is not an interactive terminal.")
        print("[ERROR] Re-run interactively and type 'continue', or supply --continue-with-missing-permissions deliberately.")
        exit(1)

    response = input("Type 'continue' to proceed with potentially incomplete collection, or anything else to abort: ")
    if response.strip() != "continue":
        print("[*] Aborted by user.")
        exit(1)


def ensure_required_permission_baseline():
    global PERMISSION_BASELINE_CHECKED

    if PERMISSION_BASELINE_CHECKED:
        return

    PERMISSION_BASELINE_CHECKED = True

    subscription_id = AUTH_CONFIG.get("subscription_id")
    auto_confirm = AUTH_CONFIG.get("continue_with_missing_permissions", False)

    print("[*] Checking Azure permission baseline...")

    principal, principal_error = get_current_principal_context(subscription_id)
    if principal_error:
        report = {
            "principal": {
                "principal_name": "unknown",
                "principal_type": "unknown",
                "object_id": "unknown",
                "subscription_id": subscription_id or "unknown",
            },
            "missing_directory_roles": sorted(REQUIRED_DIRECTORY_ROLES),
            "directory_role_errors": [principal_error],
            "missing_subscription_roles": sorted(REQUIRED_SUBSCRIPTION_ROLES),
            "subscription_role_errors": [principal_error],
            "custom_role_report": {
                "present_custom_roles": [],
                "missing_actions": sorted(REQUIRED_CUSTOM_ROLE_ACTIONS),
                "missing_data_actions": sorted(REQUIRED_CUSTOM_ROLE_DATA_ACTIONS),
                "errors": [principal_error],
            },
            "group_membership_error": None,
        }
        print_permission_baseline_warning(report)
        confirm_continue_after_permission_warning(auto_confirm)
        return

    if not principal.get("subscription_id"):
        print("[ERROR] Could not determine Azure subscription ID for permission baseline check.")
        exit(1)

    principal_ids = {principal["object_id"]}
    group_ids, group_membership_error = get_transitive_group_ids(principal["object_id"])
    principal_ids.update(group_ids)

    directory_role_names, directory_role_errors = get_directory_role_names_for_principal_ids(principal_ids)
    missing_directory_roles = sorted(REQUIRED_DIRECTORY_ROLES - directory_role_names)

    subscription_role_names, subscription_role_errors = get_subscription_role_names_for_principal_ids(
        principal["subscription_id"],
        principal_ids,
    )
    missing_subscription_roles = sorted(REQUIRED_SUBSCRIPTION_ROLES - subscription_role_names)

    custom_role_report = check_custom_role_permissions(
        principal["subscription_id"],
        principal_ids,
    )

    has_permission_problem = (
        missing_directory_roles
        or directory_role_errors
        or missing_subscription_roles
        or subscription_role_errors
        or custom_role_report["missing_actions"]
        or custom_role_report["missing_data_actions"]
        or custom_role_report["errors"]
        or not custom_role_report["present_custom_roles"]
    )

    report = {
        "principal": principal,
        "missing_directory_roles": missing_directory_roles,
        "directory_role_errors": directory_role_errors,
        "missing_subscription_roles": missing_subscription_roles,
        "subscription_role_errors": subscription_role_errors,
        "custom_role_report": custom_role_report,
        "group_membership_error": group_membership_error,
    }

    if has_permission_problem:
        print_permission_baseline_warning(report)
        confirm_continue_after_permission_warning(auto_confirm)
        return

    print("[✓] Permission baseline check passed.")


def authenticate_with_selected_method(auth_config):
    method = auth_config["auth_method"]
    tenant_id = auth_config["tenant_id"]
    subscription_id = auth_config["subscription_id"]
    client_id = auth_config["client_id"]
    client_secret = auth_config["client_secret"]
    client_certificate = auth_config["client_certificate"]
    client_certificate_password = auth_config["client_certificate_password"]

    if method == "existing":
        return

    if method == "device-code":
        login_cmd = "az login --use-device-code"
        if tenant_id:
            login_cmd = f"{login_cmd} --tenant {shell_quote(tenant_id)}"
    elif method == "browser":
        login_cmd = "az login"
        if tenant_id:
            login_cmd = f"{login_cmd} --tenant {shell_quote(tenant_id)}"
    elif method == "service-principal":
        if not tenant_id:
            print("[ERROR] Service principal auth requires --tenant-id or AZURE_TENANT_ID.")
            exit(1)
        if not client_id:
            print("[ERROR] Service principal auth requires --client-id or AZURE_CLIENT_ID.")
            exit(1)
        if not client_secret and not client_certificate:
            print(
                "[ERROR] Service principal auth requires either "
                "--client-secret/AZURE_CLIENT_SECRET or "
                "--client-certificate/AZURE_CLIENT_CERTIFICATE_PATH."
            )
            exit(1)

        login_cmd = (
            "az login --service-principal "
            f"--username {shell_quote(client_id)} "
            f"--tenant {shell_quote(tenant_id)}"
        )
        if client_secret:
            login_cmd = f"{login_cmd} --password {shell_quote(client_secret)}"
        else:
            login_cmd = f"{login_cmd} --password {shell_quote(client_certificate)}"
            if client_certificate_password:
                login_cmd = f"{login_cmd} --certificate-password {shell_quote(client_certificate_password)}"
    elif method == "managed-identity":
        login_cmd = "az login --identity"
        if client_id:
            login_cmd = f"{login_cmd} --username {shell_quote(client_id)}"
        if tenant_id:
            login_cmd = f"{login_cmd} --tenant {shell_quote(tenant_id)}"
    else:
        print(f"[ERROR] Unsupported auth method: {method}")
        exit(1)

    print(f"[*] Authenticating to Azure using '{method}' mode...")
    login_result = run_az_command(login_cmd)
    if login_result.returncode != 0:
        print("[ERROR] Azure authentication failed. Exiting.")
        exit(1)

    set_az_account_context(subscription_id)


def ensure_az_login(force_reauth=False, skip_permission_baseline=False):
    global AUTH_CONFIG

    auth_method = AUTH_CONFIG.get("auth_method", "existing")
    subscription_id = AUTH_CONFIG.get("subscription_id")

    if validate_auth_session(subscription_id) and not force_reauth:
        print("[✓] Azure CLI is authenticated.")
        set_az_account_context(subscription_id)
        if not skip_permission_baseline:
            ensure_required_permission_baseline()
        return

    if auth_method == "existing":
        print("[ERROR] No usable Azure CLI session found.")
        print("Authenticate before running this tool, or select --auth-method explicitly.")
        print("Examples: az login, az login --service-principal ..., az login --identity")
        exit(1)

    authenticate_with_selected_method(AUTH_CONFIG)

    if not validate_auth_session(subscription_id):
        print("[ERROR] Azure authentication completed but token validation failed.")
        exit(1)

    print("[✓] Azure CLI authentication is ready.")
    if not skip_permission_baseline:
        ensure_required_permission_baseline()


def run_az_cli(cmd, endpoint_name=None, category=None):
    """Run an Azure CLI command and return structured output with stderr and parsed JSON."""
    cmd = command_argv(cmd)
    if "--output" not in cmd and "-o" not in cmd:
        cmd.extend(["--output", "json"])
    command_text = command_display(cmd)
    endpoint_name = endpoint_name if endpoint_name is not None else getattr(AZURE_CLI_CONTEXT, "endpoint_name", None)
    category = category if category is not None else getattr(AZURE_CLI_CONTEXT, "category", "collection")
    if category is None:
        category = "collection"
    global DEBUG
    error_message = None
    result = None
    try:
        result = run_az_cli_process(cmd)
        if DEBUG:
            debug_memory(f"process completed: {command_text}")
            print(f"Return code: {result['returncode']}")

        if result["returncode"] != 0:
            error_auth_signatures = [
                "tokenissuedbeforerevocationtimestamp",
                "interactionrequired",
            ]
            if any(sig in result["stdout"].lower() for sig in error_auth_signatures):
                print("[!] Azure token not valid. Attempting authentication refresh...")
                ensure_az_login(force_reauth=True)
                result = run_az_cli_process(cmd)
                if not result["success"]:
                    error_message = "Authentication refresh failed to restore Azure CLI access."

        if result["returncode"] != 0 and not error_message:
            retry_result = install_missing_extension_and_retry(cmd, result)
            if retry_result:
                retry_result["_retry_count"] = result.get("_retry_count", 0) + 1
                result = retry_result
                if DEBUG:
                    print(f"Return code after extension retry: {result['returncode']}")

        if result["returncode"] != 0:
            error_cli_signatures = [
                "is misspelled or not recognized by the system",
                "the following arguments are required",
            ]
            if any(sig in result["stdout"].lower() for sig in error_cli_signatures):
                error_message = "Unrecognised or malformed CLI command"

            if not error_message:
                error_message = (
                    "Azure CLI request failed with return code "
                    f"{result['returncode']}"
                )

        else:
            if DEBUG:
                debug_memory(f"before warning filter: {command_text}")
            result["stdout"], matched_sigs = filter_az_cli_warning_output(result["stdout"])
            if DEBUG:
                debug_memory(f"after warning filter: {command_text}")
            if matched_sigs:
                if DEBUG:
                    print(f"[DEBUG] Found warning message signature(s): {matched_sigs}, attempting to filter")
                if DEBUG:
                    print(f"Filter result is: {result['stdout'][:30]} [END]")

            if result["stdout"].strip():
                try:
                    if DEBUG:
                        debug_memory(f"before JSON parse: {command_text}")
                    result["json"] = parse_json_from_az_output(result["stdout"])
                    if DEBUG:
                        debug_memory(f"after JSON parse: {command_text}")
                except Exception as e:
                    print(f"JSON parsing error: {e}")
                    if not any(sig in result["stdout"].lower() for sig in AZURE_CLI_OUTPUT_WARNING_SIGNATURES):
                        error_message = "Something has gone wrong - data returned but not JSON"
            elif len(result["stdout"]) > 0:
                if not any(sig in result["stdout"].lower() for sig in AZURE_CLI_OUTPUT_WARNING_SIGNATURES):
                    error_message = "Something has gone wrong - data returned but not JSON"

        if error_message:
            # Keep a concise classification alongside the command output. The
            # manifest recorder combines both and applies its error-length limit.
            result["collection_error"] = error_message
            context = endpoint_name or command_text
            if is_not_applicable_error(result.get("stdout")):
                print(f"[~] Request not applicable for {context}")
            else:
                record_collection_error(command_text, error_message, result, endpoint_name=endpoint_name, category=category)
                print(f"[!] Recorded command error for {context}: {error_message}")
                if not result or not result.get("returncode"):
                    sleep(1)

        # return result - with or without nested JSON object
        return result

    except Exception as e:
        print("\n\n")
        print(f"===========================================")
        print(f"[ERROR] Exception running command: {command_text}")
        if result and result.get("stdout"):
            print(f"Process details: {str(result['stdout'])}")
        print(f"Exception message: {str(e)}")
        print(f"===========================================")
        exit(1)


def save_json(data, filename, append=False, source_endpoint_identifiers=None):
    """Save data to a JSON file."""
    OUTPUT_DIR.mkdir(exist_ok=True)
    if append:
        mode = 'a'
    else:
        mode = 'w'
    path = OUTPUT_DIR / filename
    with open(path, mode) as f:
        json.dump(data, f, indent=2)
    print(f"[+] Saved: {path}")
    with SOURCE_FILE_INDEX_LOCK:
        SOURCE_FILE_INDEX_CACHE.clear()
    if COLLECTION_MANIFEST is not None:
        try:
            COLLECTION_MANIFEST.record_dataset(
                path,
                data,
                append=append,
                source_endpoint_identifiers=source_endpoint_identifiers,
            )
        except (OSError, ValueError) as exc:
            # Dataset persistence remains the primary operation. A failed
            # integrity calculation is reported as a manifest limitation.
            COLLECTION_MANIFEST.add_limitation(
                f"Could not record integrity metadata for {path.name}: {exc}"
            )
    return path


def attach_collection_context(data, endpoint_name, param_set):
    """Preserve the source parameters that produced a parameterised record."""
    context = {
        "endpoint": endpoint_name,
        "parameters": dict(param_set),
    }

    def enrich(item):
        if not isinstance(item, dict):
            return item
        enriched = dict(item)
        enriched.setdefault("_collectionContext", context)
        return enriched

    if isinstance(data, list):
        return [enrich(item) for item in data]
    if isinstance(data, dict):
        return enrich(data)
    return data

def source_filename_prefix(source):
    """Return the filename prefix used for a parameter source dataset."""
    return source.lower().replace(" ", "_").replace("(", "").replace(")", "")


def known_endpoint_output_prefixes():
    """Return explicit dataset prefixes generated by configured endpoints."""
    return {
        endpoint_output_prefix(endpoint)
        for endpoint in AZURE_CLI_ENDPOINTS + AZURE_CLI_ENDPOINTS_PARAMS
    }


def source_filename_matches(filename, source, current_run_only=True):
    """Return True when a generated JSON file exactly belongs to a source prefix."""
    if not filename.endswith(".json"):
        return False

    prefix = source_filename_prefix(source)
    exact_source = prefix in known_endpoint_output_prefixes()
    if current_run_only:
        if not source_file_belongs_to_current_run(filename):
            return False
        if exact_source:
            return filename == f"{prefix}_{START_TIMESTAMP}.json"
        return filename.startswith(f"{prefix}_")

    if exact_source:
        generated_pattern = re.compile(rf"^{re.escape(prefix)}_\d{{8}}-\d{{6}}\.json$")
    else:
        generated_pattern = re.compile(rf"^{re.escape(prefix)}_.*_\d{{8}}-\d{{6}}\.json$")
    return bool(generated_pattern.match(filename))


def source_file_belongs_to_current_run(filename):
    """Return True when a generated JSON file belongs to this execution."""
    return filename.endswith(f"_{START_TIMESTAMP}.json")


def source_file_index(current_run_only=True):
    """Return cached JSON filenames available for parameter sources."""
    cache_key = (
        str(OUTPUT_DIR.resolve()),
        START_TIMESTAMP if current_run_only else "all-runs",
    )
    with SOURCE_FILE_INDEX_LOCK:
        if cache_key in SOURCE_FILE_INDEX_CACHE:
            return SOURCE_FILE_INDEX_CACHE[cache_key]

        try:
            filenames = sorted(
                filename
                for filename in os.listdir(OUTPUT_DIR)
                if filename.endswith(".json")
                and (
                    not current_run_only
                    or source_file_belongs_to_current_run(filename)
                )
            )
        except FileNotFoundError:
            filenames = []

        SOURCE_FILE_INDEX_CACHE[cache_key] = filenames
        return filenames


def list_source_files_for_run(source, current_run_only=True):
    """List JSON files that can be used as parameter sources.

    In normal full collection mode, current_run_only should be True so that
    stale files from previous executions are not re-used accidentally.

    In parameter-only replay mode, current_run_only can be False to preserve
    the existing ability to use previously collected source files.
    """
    return [
        filename
        for filename in source_file_index(current_run_only=current_run_only)
        if source_filename_matches(filename, source, current_run_only=current_run_only)
    ]


def load_source_records(source, current_run_only=True):
    """Load and cache source records for a parameter source dataset."""
    cache_key = (
        str(OUTPUT_DIR.resolve()),
        source,
        START_TIMESTAMP if current_run_only else "all-runs",
    )

    if cache_key in SOURCE_RECORD_CACHE:
        if DEBUG:
            print(f"[DEBUG] Source record cache hit for {source}: {len(SOURCE_RECORD_CACHE[cache_key])} records")
        return SOURCE_RECORD_CACHE[cache_key]

    records = []
    files = list_source_files_for_run(source, current_run_only=current_run_only)

    if DEBUG:
        run_scope = "current run only" if current_run_only else "all matching runs"
        print(f"[DEBUG] Loading source '{source}' from {len(files)} file(s), scope: {run_scope}")

    for filename in files:
        filepath = OUTPUT_DIR / filename

        if DEBUG:
            print(f"[DEBUG] Loading source file: {filepath}")

        try:
            with open(filepath) as f:
                data = json.load(f)

            records.extend(iter_source_records(data))

        except Exception as e:
            print(f"[!] Failed to parse {filename}: {e}")

    SOURCE_RECORD_CACHE[cache_key] = records
    return records


def load_current_dataset(prefix):
    """Load records for a generated dataset from the current run."""
    return load_source_records(prefix, current_run_only=True)


def upstream_source_skip_reason(source):
    """Classify and preserve why a parameter source supplied no records."""
    outcomes = (
        COLLECTION_MANIFEST.endpoint_outcomes(source)
        if COLLECTION_MANIFEST is not None
        else []
    )
    statuses = sorted(
        {
            str(outcome.get("status"))
            for outcome in outcomes
            if outcome.get("status")
        }
    )
    status_reasons = (
        ("unauthorised", "upstream_source_unauthorised"),
        ("tenant_unavailable", "upstream_source_tenant_unavailable"),
        ("failed", "upstream_source_failed"),
        ("not_attempted", "upstream_source_not_attempted"),
        ("empty", "upstream_source_returned_no_data"),
        ("not_applicable", "upstream_source_not_applicable"),
        ("skipped", "upstream_source_skipped"),
    )
    reason_priority = tuple(reason for _, reason in status_reasons) + (
        "upstream_source_unavailable",
    )
    contributing_reason_codes = {
        reason
        for status, reason in status_reasons
        if status in statuses
    }
    root_cause_endpoint_ids = set()
    dependency_chains = []
    contributing_visibility_statuses = set()
    source_id = endpoint_id(source)
    for outcome in outcomes:
        verification = outcome.get("access_verification")
        if isinstance(verification, dict) and verification.get("status"):
            verification_status = str(verification["status"])
            if not (
                outcome.get("status") in {"skipped", "not_attempted"}
                and verification_status == "not_evaluated"
            ):
                contributing_visibility_statuses.add(verification_status)
        details = outcome.get("reason_details")
        if not isinstance(details, dict):
            details = {}
        inherited_reasons = details.get("contributing_reason_codes") or []
        contributing_reason_codes.update(
            str(reason) for reason in inherited_reasons if reason
        )
        if outcome.get("reason_code"):
            contributing_reason_codes.add(str(outcome["reason_code"]))
        inherited_roots = details.get("root_cause_endpoint_ids") or []
        root_cause_endpoint_ids.update(
            endpoint_id(root) for root in inherited_roots if root
        )
        inherited_chains = details.get("dependency_chains") or []
        for chain in inherited_chains:
            if isinstance(chain, list) and chain:
                normalised_chain = [endpoint_id(item) for item in chain if item]
                if normalised_chain:
                    dependency_chains.append(normalised_chain)

    if not root_cause_endpoint_ids:
        root_cause_endpoint_ids.add(source_id)
    if not dependency_chains:
        dependency_chains.append([source_id])
    reason_code = next(
        (code for code in reason_priority if code in contributing_reason_codes),
        "upstream_source_unavailable",
    )
    return reason_code, statuses, {
        "contributing_reason_codes": sorted(contributing_reason_codes),
        "contributing_visibility_statuses": sorted(
            contributing_visibility_statuses
        ),
        "root_cause_endpoint_ids": sorted(root_cause_endpoint_ids),
        "dependency_chains": dependency_chains,
    }


def record_parameter_endpoint_skip(endpoint, reason_code, reason, reason_details=None):
    """Record one structured reason for omitting a parameterised endpoint."""
    if COLLECTION_MANIFEST is None:
        return
    COLLECTION_MANIFEST.record_skipped_endpoint(
        endpoint["name"],
        "parameterised",
        endpoint["cli_command"],
        reason,
        endpoint_identifier=endpoint_output_prefix(endpoint),
        reason_code=reason_code,
        reason_details=reason_details,
    )


def merge_role_definition_dataset(cache_path=None):
    """Create the compatibility role-definition dataset from cached built-ins and live custom roles."""
    custom_roles = load_current_dataset("az_role_definition_custom_list")
    try:
        builtin_roles = load_managed_role_definitions_cache(cache_path)
    except Exception as exc:
        print(f"[!] Managed role definition cache is unusable: {exc}")
        builtin_roles = None

    if builtin_roles is None:
        print("[~] Managed role definition cache not found; collecting full role definition list live.")
        result = timed_run_az_cli(
            "az role definition list",
            endpoint_name="Role Definitions",
            category="role-definition-fallback",
        )
        role_definitions = result.get("json") or []
    else:
        role_definitions = list(builtin_roles) + list(custom_roles)

    if not role_definitions:
        print("[!] No role definitions available for merged role definition dataset.")
        return []

    source_endpoint_ids = ["az_role_definition_custom_list"]
    if builtin_roles is None:
        source_endpoint_ids.append("az_role_definition_list")
    save_json(
        role_definitions,
        f"az_role_definition_list_{START_TIMESTAMP}.json",
        source_endpoint_identifiers=source_endpoint_ids,
    )
    return role_definitions


def iter_source_records(data):
    """Yield dict records from supported JSON payload shapes."""
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                yield item
        return

    if not isinstance(data, dict):
        return

    value = data.get("value")
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                yield item
        return

    yield data


def resource_type_from_id(resource_id):
    """Extract the Azure resource type from a resource ID when `type` is absent."""
    if not resource_id or not isinstance(resource_id, str):
        return None

    parts = [part for part in resource_id.strip("/").split("/") if part]
    try:
        provider_index = next(
            index
            for index, part in enumerate(parts)
            if part.lower() == "providers"
        )
    except StopIteration:
        return None

    provider_parts = parts[provider_index + 1:]
    if len(provider_parts) < 2:
        return None

    namespace = provider_parts[0]
    type_parts = provider_parts[1::2]
    if not type_parts:
        return None
    return "/".join([namespace] + type_parts)


def resource_name_from_id(resource_id):
    """Extract the final Azure resource name segment from a resource ID."""
    if not resource_id or not isinstance(resource_id, str):
        return None

    parts = [part for part in resource_id.strip("/").split("/") if part]
    if not parts:
        return None
    return parts[-1]


def record_resource_type(item):
    """Return a lower-case resource type for source-record compatibility checks."""
    resource_type = item.get("type") or resource_type_from_id(item.get("id"))
    if not resource_type or isinstance(resource_type, (dict, list)):
        return None
    resource_type = str(resource_type).strip()
    return resource_type.lower() or None


def filter_source_records_for_endpoint(endpoint, source, records):
    """Filter parameter-source records to the values an endpoint accepts."""
    required_source_types = endpoint.get("required_source_types", {})
    allowed_types = required_source_types.get(source)
    required_values = endpoint.get("required_source_values", {}).get(source, {})

    if allowed_types:
        allowed_types = {resource_type.lower() for resource_type in allowed_types}

    def nested_value(item, field_path):
        value = item
        for field in field_path.split("."):
            if not isinstance(value, dict):
                return None
            value = value.get(field)
        return value

    normalised_required_values = {
        field_path: {str(value).strip().lower() for value in values}
        for field_path, values in required_values.items()
    }
    filtered_records = []
    for item in records:
        # Generic fields such as `name` are only safe when the source record is
        # known to describe the resource type that the follow-on command targets.
        if allowed_types and record_resource_type(item) not in allowed_types:
            continue
        if any(
            str(nested_value(item, field_path) or "").strip().lower() not in allowed_values
            for field_path, allowed_values in normalised_required_values.items()
        ):
            continue
        filtered_records.append(item)
    return filtered_records


def resolve_param_value(item, param, prefer_collection_context=False):
    """Resolve a parameter from a record or its collection context."""
    context_value = item.get("_collectionContext", {}).get("parameters", {}).get(param)
    value = context_value if prefer_collection_context else item.get(param)
    if value is None:
        value = item.get(param) if prefer_collection_context else context_value
    if value is None and param == "name":
        value = resource_name_from_id(item.get("id"))
    if value is None or isinstance(value, (dict, list)):
        return None
    value = str(value).strip()
    return value or None


def resolve_principal(object_id):
    """Resolve an Azure AD object ID to a readable name/type with status classification.

    Results are cached for the lifetime of the process. This avoids repeated
    az ad user/group/sp lookups for principals that appear in many role
    assignments.
    """
    if not object_id:
        return {
            "type": "Unknown",
            "objectId": object_id,
            "name": None,
            "status": "missing"
        }

    cache_key = str(object_id)

    if cache_key in PRINCIPAL_RESOLUTION_CACHE:
        if DEBUG:
            print(f"[DEBUG] Principal cache hit: {cache_key}")
        return deepcopy(PRINCIPAL_RESOLUTION_CACHE[cache_key])

    if DEBUG:
        print(f"[DEBUG] Principal cache miss: {cache_key}")

    for entity_type, cmd in {
        "User": f"az ad user show --id {shell_quote(object_id)}",
        "Group": f"az ad group show --group {shell_quote(object_id)}",
        "ServicePrincipal": f"az ad sp show --id {shell_quote(object_id)}"
    }.items():
        result = run_and_parse(cmd, entity_type, object_id)
        if result and result["status"] != "unknown":
            print(f"[~] {entity_type} {object_id} → status: {result['status']}")
            PRINCIPAL_RESOLUTION_CACHE[cache_key] = deepcopy(result)
            return deepcopy(result)

    result = {
        "type": "Unknown",
        "objectId": object_id,
        "name": None,
        "status": "unknown"
    }

    print(f"[~] Unresolved object ID {object_id} → status: unknown")
    PRINCIPAL_RESOLUTION_CACHE[cache_key] = deepcopy(result)
    return deepcopy(result)

def resolve_role_assignments(assignments, role_definitions):
    """
    Resolve role assignments and map each to its corresponding permission set.
    This function enriches each role assignment by:
      - Resolving the principal (user, group, or service principal)
      - Mapping the roleDefinitionId to a role definition and extracting the permission set.
    """
    # Built-in role definitions in the shared cache are subscription-neutral.
    # Match by the final role GUID so live assignment IDs still resolve.
    role_def_map = {}
    for role_def in role_definitions:
        role_guid = role_definition_guid(role_def.get("id"))
        if role_guid:
            role_def_map[role_guid] = role_def

    enriched = []
    print(f"[*] Resolving {len(assignments)} role assignments and mapping permissions...\n")

    for ra in tqdm(assignments, desc="Resolving principals", unit="ra"):
        # Resolve principal details.
        principal_id = ra.get("principalId")
        principal_details = resolve_principal(principal_id)
        ra["resolvedPrincipal"] = principal_details

        # Map the role assignment to its corresponding role definition.
        role_def_id = role_definition_guid(ra.get("roleDefinitionId"))
        role_def = role_def_map.get(role_def_id)
        if role_def:
            # Add human-readable role name and permission details.
            ra["roleDefinitionName"] = role_def.get("roleName") or role_def.get("name")
            ra["permissionSet"] = role_def.get("permissions", [])
        else:
            ra["roleDefinitionName"] = None
            ra["permissionSet"] = None

        enriched.append(ra)

    print(f"[✓] Resolution and permission mapping complete.\n")
    return enriched


def run_tasks(tasks, worker_count):
    """Run callables serially or with a bounded worker pool."""
    if worker_count <= 1 or len(tasks) <= 1:
        return [task() for task in tasks]

    results = []
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_index = {
            executor.submit(task): index
            for index, task in enumerate(tasks)
        }
        ordered_results = [None] * len(tasks)
        for future in as_completed(future_to_index):
            index = future_to_index[future]
            ordered_results[index] = future.result()
        results.extend(ordered_results)
    return results


def collect_parameter_set(endpoint, param_set):
    """Run one parameterised endpoint command for one aligned parameter set."""
    name = endpoint["name"]
    cli_template = endpoint["cli_command"]

    try:
        cli_command = format_parameterised_cli_command(cli_template, param_set)
    except KeyError as e:
        print(f"[!] Skipping {name}: Missing placeholder for {str(e)}")
        return []
    except (IndexError, ValueError) as e:
        print(f"[!] Skipping {name}: Invalid parameter template: {e}")
        return []

    if DEBUG:
        print(f"[DEBUG] Running command: {command_display(cli_command)}")

    print(f"[*] Fetching: {name} with parameters: {param_set} ...")
    try:
        result = timed_run_az_cli(
            cli_command,
            endpoint_name=name,
            category="parameterised",
            command_template=cli_template,
            parameter_context=param_set,
            endpoint_identifier=endpoint_output_prefix(endpoint),
        )
        data = result.get("json", [])

        if endpoint.get("extract_value") and isinstance(data, dict) and isinstance(data.get("value"), list):
            data = data["value"]

        if result_item_count(data) == 0:
            print(f"[!] No data returned for: {name} with {param_set}")
            if endpoint.get("preserve_empty_result") and result.get("returncode") == 0:
                return [
                    attach_collection_context(
                        {"_collectionResult": {"status": "empty"}},
                        name,
                        param_set,
                    )
                ]
            return []

        data = attach_collection_context(data, name, param_set)

        if name == "VM NIC IDs" and isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                # Preserve the originating VM context so follow-up NIC detail
                # queries can be driven from a single source dataset.
                item.setdefault("vm_name", param_set.get("name"))
                item.setdefault("resourceGroup", param_set.get("resourceGroup"))

        if isinstance(data, list):
            return data

        if name == "VM NIC IDs" and isinstance(data, dict):
            data.setdefault("vm_name", param_set.get("name"))
            data.setdefault("resourceGroup", param_set.get("resourceGroup"))
        return [data]

    except Exception as e:
        if COLLECTION_MANIFEST is not None:
            COLLECTION_MANIFEST.record_execution(
                endpoint_name=name,
                category="parameterised",
                command_template=cli_template,
                parameter_context=param_set,
                started_at=utc_timestamp(),
                duration_seconds=0,
                returncode=1,
                result_count=None,
                error_message=f"Collected data could not be post-processed: {e}",
                diagnostic_text=str(e),
                endpoint_identifier=endpoint_output_prefix(endpoint),
            )
        print(f"[!] Data collect with params failed for {name} with {param_set}: {e}")
        return []


def collect_data_with_params(param_endpoints, current_run_only=True, max_workers=1):
    global DEBUG
    """
    Run parameterized commands from AZURE_CLI_ENDPOINTS and store JSON data.

    Args:
        param_endpoints: List of endpoint dictionaries with `cli_command` and `required_params`
    """
    global OUTPUT_DIR

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("\n[*] Starting parameterized CLI commands...\n")

    for endpoint in tqdm(param_endpoints, desc="parameter collection tasks", unit="endpoint"):
        name = endpoint["name"]
        cli_template = endpoint["cli_command"]
        required_param_sources = endpoint.get("required_params", {})
        required_params = list(required_param_sources.keys())
        preferred_context_params = set(
            endpoint.get("prefer_collection_context_params", ())
        )

        if DEBUG:
            print(f"[DEBUG] Processing endpoint: {name}")
            print(f"[DEBUG] Required parameters and sources: {required_param_sources}")

        raw_source_records = {}
        source_records = {}

        sources_needed = sorted(set(required_param_sources.values()))

        for source in sources_needed:
            raw_source_records[source] = load_source_records(
                source,
                current_run_only=current_run_only,
            )
            source_records[source] = filter_source_records_for_endpoint(
                endpoint,
                source,
                raw_source_records[source],
            )

            if DEBUG:
                print(
                    f"[DEBUG] Source '{source}' provided "
                    f"{len(source_records[source])} record(s)"
                )

        if DEBUG:
            print(f"[DEBUG] Collected source records: "
                  f"{ {source: len(records) for source, records in source_records.items()} }")

        # Ensure all required parameters have values
        missing_params = []
        for param, source in required_param_sources.items():
            values = []
            for item in source_records.get(source, []):
                value = resolve_param_value(
                    item,
                    param,
                    prefer_collection_context=param in preferred_context_params,
                )
                if value:
                    values.append(value)
            if not values:
                missing_params.append(param)

        if missing_params:
            print(f"[~] Skipping {name}: Missing required parameters: {missing_params}")
            missing_sources = sorted(
                {required_param_sources[param] for param in missing_params}
            )
            source_diagnostics = {}
            reason_codes = []
            contributing_reason_codes = set()
            contributing_visibility_statuses = set()
            root_cause_endpoint_ids = set()
            dependency_chains = []
            for source in missing_sources:
                if not raw_source_records.get(source):
                    reason_code, statuses, cause_details = upstream_source_skip_reason(
                        source
                    )
                elif not source_records.get(source):
                    reason_code = "no_applicable_source_records"
                    cause_details = {}
                    statuses = (
                        COLLECTION_MANIFEST.endpoint_statuses(source)
                        if COLLECTION_MANIFEST is not None
                        else []
                    )
                else:
                    reason_code = "required_parameter_missing"
                    cause_details = {}
                    statuses = (
                        COLLECTION_MANIFEST.endpoint_statuses(source)
                        if COLLECTION_MANIFEST is not None
                        else []
                    )
                reason_codes.append(reason_code)
                contributing_reason_codes.add(reason_code)
                contributing_reason_codes.update(
                    cause_details.get("contributing_reason_codes", [])
                )
                contributing_visibility_statuses.update(
                    cause_details.get("contributing_visibility_statuses", [])
                )
                root_cause_endpoint_ids.update(
                    cause_details.get("root_cause_endpoint_ids", [])
                )
                dependency_chains.extend(
                    cause_details.get("dependency_chains", [])
                )
                source_diagnostics[source] = {
                    "collection_statuses": statuses,
                    "raw_record_count": len(raw_source_records.get(source, [])),
                    "applicable_record_count": len(source_records.get(source, [])),
                    **cause_details,
                }

            reason_priority = (
                "upstream_source_unauthorised",
                "upstream_source_tenant_unavailable",
                "upstream_source_failed",
                "upstream_source_not_attempted",
                "upstream_source_returned_no_data",
                "upstream_source_not_applicable",
                "upstream_source_skipped",
                "upstream_source_unavailable",
                "no_applicable_source_records",
                "required_parameter_missing",
            )
            primary_reason = next(
                (code for code in reason_priority if code in reason_codes),
                "required_parameter_missing",
            )
            record_parameter_endpoint_skip(
                endpoint,
                primary_reason,
                f"Missing required parameters: {', '.join(missing_params)}",
                {
                    "parameters": missing_params,
                    "sources": source_diagnostics,
                    "contributing_reason_codes": sorted(contributing_reason_codes),
                    "contributing_visibility_statuses": sorted(
                        contributing_visibility_statuses
                    ),
                    "immediate_upstream_endpoint_ids": [
                        endpoint_id(source) for source in missing_sources
                    ],
                    "root_cause_endpoint_ids": sorted(root_cause_endpoint_ids),
                    "dependency_chains": [
                        list(chain)
                        for chain in dict.fromkeys(
                            tuple(
                                dict.fromkeys(
                                    list(chain) + [endpoint_output_prefix(endpoint)]
                                )
                            )
                            for chain in dependency_chains
                        )
                    ],
                },
            )
            continue

        from collections import defaultdict

        # Group params by their source file
        grouped_params = defaultdict(list)
        for param, source in required_param_sources.items():
            grouped_params[source].append(param)

        zipped_groups = []

        for source, params_in_group in grouped_params.items():
            grouped_records = []
            seen_group_records = set()

            for item in source_records.get(source, []):
                grouped_record = {}
                missing_value = False

                for param in params_in_group:
                    value = resolve_param_value(
                        item,
                        param,
                        prefer_collection_context=param in preferred_context_params,
                    )
                    if not value:
                        missing_value = True
                        break
                    grouped_record[param] = value

                if missing_value:
                    continue

                dedupe_key = tuple((param, grouped_record[param]) for param in params_in_group)
                if dedupe_key in seen_group_records:
                    continue
                seen_group_records.add(dedupe_key)
                grouped_records.append(grouped_record)

            if not grouped_records:
                print(f"[~] Skipping {name}: Missing usable parameter records from source: {source}")
                record_parameter_endpoint_skip(
                    endpoint,
                    "no_usable_parameter_records",
                    f"Missing usable parameter records from source: {source}",
                    {
                        "source": source,
                        "parameters": params_in_group,
                        "raw_record_count": len(raw_source_records.get(source, [])),
                        "applicable_record_count": len(source_records.get(source, [])),
                    },
                )
                zipped_groups = []
                break

            if DEBUG:
                print(f"[DEBUG] Aligned group from {source}: {grouped_records}")
            zipped_groups.append(grouped_records)

        if not zipped_groups:
            continue

        # Cartesian product across the zipped groups
        param_combinations = []
        for combo in product(*zipped_groups):
            merged = {}
            for d in combo:
                merged.update(d)
            param_combinations.append(merged)

        try:
            format_parameterised_cli_command(
                cli_template,
                {param: "validation-value" for param in required_params},
            )
        except (IndexError, KeyError, ValueError) as exc:
            print(f"[!] Skipping {name}: Invalid parameter template: {exc}")
            record_parameter_endpoint_skip(
                endpoint,
                "parameter_template_mismatch",
                f"Invalid parameter template: {exc}",
                {
                    "required_parameters": required_params,
                    "exception_type": type(exc).__name__,
                },
            )
            continue

        max_parameter_sets = endpoint.get("max_parameter_sets")
        if max_parameter_sets is not None:
            param_combinations = param_combinations[:max(0, int(max_parameter_sets))]

        if DEBUG:
            print(f"[DEBUG] Hybrid-aligned param combinations: {param_combinations}")
            print(f"[DEBUG] Generated {len(param_combinations)} parameter combinations for {name}")

        tasks = [
            (lambda param_set=param_set, endpoint=endpoint: collect_parameter_set(endpoint, param_set))
            for param_set in param_combinations
        ]
        all_results = []
        for result_group in run_tasks(tasks, bounded_worker_count(max_workers)):
            all_results.extend(result_group or [])

        if all_results:
            filename = endpoint_output_prefix(endpoint) + f"_{START_TIMESTAMP}.json"
            if DEBUG:
                print(f"[DEBUG] Writing {len(all_results)} results to {filename}")
            save_json(all_results, filename)

    print("\n[✓] Data collect with params phase complete.\n")


def list_all_enabled_cli_endpoints(param_endpoints=False):
    global AZURE_CLI_ENDPOINTS

    param_or_not = 'parameterised' if param_endpoints else 'non-parameterised'

    print(f"These are the {param_or_not} Azure CLI endpoints that can be enumerated with this tool:\n\n")

    print("[*] Command name, Main keyword, Secondary keyword, Typical command syntax")
    print("-------------------------------------------------------------------------")

    if param_endpoints:
        endpoints = AZURE_CLI_ENDPOINTS_PARAMS
    else:
        endpoints = AZURE_CLI_ENDPOINTS

    for endpoint in endpoints:
        name = endpoint["name"]
        keyword_main = endpoint["cli_command"].split()[1]
        keyword_sub = endpoint["cli_command"].split()[2]
        cmd = endpoint["cli_command"]

        print(f"[*] {name}, {keyword_main}, {keyword_sub}, {cmd}")

    print("\n\n")
    exit(0)


def collect_endpoint(endpoint):
    """Collect and save one non-parameterised endpoint."""
    name = endpoint["name"]
    cmd = endpoint["cli_command"]

    print(f"[*] Fetching: {name} ...")
    try:
        result = timed_run_az_cli(
            cmd,
            endpoint_name=name,
            category="base",
            command_template=cmd,
            endpoint_identifier=endpoint_output_prefix(endpoint),
        )
        data = result.get("json", [])

        if endpoint.get("extract_value") and isinstance(data, dict) and isinstance(data.get("value"), list):
            data = data["value"]

        count = result_item_count(data)

        if DEBUG:
            print(f"[DEBUG] Returned data is type: {type(data)}")

        if count == 0:
            print(f"[!] No data returned for: {name}")
            return None

        print(f"[~] {name} returned {count}")

        filename = endpoint_output_prefix(endpoint) + f"_{START_TIMESTAMP}.json"
        if DEBUG:
            debug_memory(f"before save_json: {filename}")
        save_json(data, filename)
        if DEBUG:
            debug_memory(f"after save_json: {filename}")
        return data

    except Exception as e:
        if COLLECTION_MANIFEST is not None:
            COLLECTION_MANIFEST.record_execution(
                endpoint_name=name,
                category="base",
                command_template=cmd,
                started_at=utc_timestamp(),
                duration_seconds=0,
                returncode=1,
                result_count=None,
                error_message=f"Collected data could not be post-processed: {e}",
                diagnostic_text=str(e),
                endpoint_identifier=endpoint_output_prefix(endpoint),
            )
        print(f"[!] Failed to collect {name}: {e}")
        return None


def collect_data(endpoints, max_workers=1):
    global START_TIMESTAMP

    # ensure the script doesn't hang waiting for user input about installing extensions
    timed_run_az_cli("az config set extension.use_dynamic_install=yes_without_prompt", endpoint_name="Azure CLI config", category="setup")
    timed_run_az_cli("az config set extension.dynamic_install_allow_preview=true", endpoint_name="Azure CLI config", category="setup")

    tasks = [
        (lambda endpoint=endpoint: collect_endpoint(endpoint))
        for endpoint in endpoints
    ]
    run_tasks(tasks, bounded_worker_count(max_workers))


def filter_endpoints(keyword=None, endpoints=None, allow_empty=False):
    """
    Filter the endpoints list based on selected endpoint name.
    Matching is case-insensitive.
    """
    global DEBUG

    if not keyword:
        if DEBUG:
           print("No keyword to filter on so returning all")
        return endpoints

    print(f"Searching for endpoint match {keyword}.")
    filtered = []
    keyword_lowered = str(keyword).lower()
    for ep in endpoints:
        if str(keyword_lowered) in ep["cli_command"].lower():
            filtered.append(ep)
            print(f"Selecting {ep['name']} endpoint")
    if not filtered and not allow_empty:
        print(f"No matching endpoints found for selection: {keyword}")
        exit(1)
    return filtered


def execute_collection(args, max_workers):
    """Run the selected collection workflow and return whether it completed cleanly."""
    ensure_az_login(skip_permission_baseline=args.collect_managed_role_definitions_cache)
    if COLLECTION_MANIFEST is not None:
        COLLECTION_MANIFEST.update_context(
            {
                "tenant_id": AUTH_CONFIG.get("tenant_id"),
                "subscription_id": AUTH_CONFIG.get("subscription_id"),
            }
        )

    if args.collect_managed_role_definitions_cache:
        if COLLECTION_MANIFEST is not None:
            COLLECTION_MANIFEST.register_endpoints(
                [
                    {
                        "name": "Managed Role Definitions",
                        "cli_command": "az role definition list --query \"[?roleType=='BuiltInRole']\" --output json",
                        "output_prefix": "managed_role_definitions_cache",
                    }
                ],
                "cache",
            )
        collect_managed_role_definitions_cache(args.managed_role_definitions_cache_path)
        if args.timing_summary:
            print_timing_summary()
        return True

    print("[*] Verifying collection visibility without additional user input...")
    access_verification = collect_automatic_access_verification()
    print(
        "[~] Azure subscription read visibility: "
        f"{access_verification['arm']['status']}"
    )
    print(
        "[~] Microsoft Graph permission evidence: "
        f"{access_verification['graph']['reason_code']}"
    )

    # Azure CLI version collection is diagnostic only. A version lookup failure
    # must not prevent assessment data from being collected.
    az_version, version_error = run_json_command("az version --output json")
    if COLLECTION_MANIFEST is not None:
        if isinstance(az_version, dict):
            COLLECTION_MANIFEST.set_azure_cli_version(az_version.get("azure-cli"))
        elif version_error:
            COLLECTION_MANIFEST.add_limitation(
                f"Could not determine Azure CLI version: {version_error}"
            )

    graph_successful = collect_registered_graph(
        output_dir=OUTPUT_DIR, run_id=START_TIMESTAMP,
        lookback_days=args.graph_lookback_days, endpoint_filter=args.endpoint,
        manifest=COLLECTION_MANIFEST,
    )

    base_endpoints = []
    if not args.paramendpointsonly:
        base_endpoints = filter_endpoints(args.endpoint, AZURE_CLI_ENDPOINTS, allow_empty=True)
        if COLLECTION_MANIFEST is not None:
            COLLECTION_MANIFEST.register_endpoints(base_endpoints, "base")
        collect_data(base_endpoints, max_workers=max_workers)
        if not args.endpoint or "role definition" in str(args.endpoint).lower():
            merge_role_definition_dataset(args.managed_role_definitions_cache_path)

    current_run_only = not args.paramendpointsonly

    if args.paramendpointsonly:
        print("[~] Parameter-only mode enabled: allowing existing source files from previous runs.")

    parameterised_endpoints = filter_endpoints(args.endpoint, AZURE_CLI_ENDPOINTS_PARAMS, allow_empty=True)
    if args.endpoint and not base_endpoints and not parameterised_endpoints and not selected_graph_endpoints(args.endpoint):
        print(f"No matching endpoints found for selection: {args.endpoint}")
        exit(1)
    if COLLECTION_MANIFEST is not None:
        COLLECTION_MANIFEST.register_endpoints(parameterised_endpoints, "parameterised")
    collect_data_with_params(
        parameterised_endpoints,
        current_run_only=current_run_only,
        max_workers=max_workers,
    )

    if not args.donotenrich and not args.endpoint:
        # Special handling for role assignments
        try:
            print("[+] Enriching roles with assignments and permissions...")
            assignment_result = load_current_dataset("az_role_assignment_list")
            if not assignment_result:
                assignment_result = timed_run_az_cli(
                    "az role assignment list",
                    endpoint_name="Role Assignments",
                    category="enrichment-fallback",
                ).get("json", [])

            role_def_result = load_current_dataset("az_role_definition_list")
            if not role_def_result:
                role_def_result = timed_run_az_cli(
                    "az role definition list",
                    endpoint_name="Role Definitions",
                    category="enrichment-fallback",
                ).get("json", [])

            if assignment_result and role_def_result:
                enriched_data = resolve_role_assignments(assignment_result, role_def_result)
                save_json(
                    enriched_data,
                    f"role_enriched_{START_TIMESTAMP}.json",
                    source_endpoint_identifiers=[
                        "az_role_assignment_list",
                        "az_role_definition_custom_list",
                        "az_role_definition_list",
                    ],
                )
                summarise_statuses(assignment_result)
            else:
                print("No assignments or role definitions found - cannot enrich")
        except Exception as exc:
            print(f"[!] Failed to enrich data: {exc}")
            if COLLECTION_MANIFEST is not None:
                COLLECTION_MANIFEST.add_limitation(
                    f"Role assignment enrichment failed: {exc}"
                )

    if args.timing_summary:
        print_timing_summary()

    print_collection_error_summary()
    if COLLECTION_ERRORS or not graph_successful:
        return False

    print("[✓] Azure audit data collection complete.")
    return True


if __name__ == "__main__":
    global START_TIMESTAMP
    START_TIMESTAMP = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    args = parse_arguments()
    graph_interval = utc_interval(args.graph_lookback_days)
    AUTH_CONFIG = build_auth_config(args)
    max_workers = bounded_worker_count(args.max_workers)

    if args.debug == True:
        DEBUG = True
    else:
        DEBUG = False

    if args.listendpoints or args.listparamendpoints:
        list_all_enabled_cli_endpoints(args.listparamendpoints)

    # Set the output directory dynamically
    global OUTPUT_DIR
    OUTPUT_DIR = Path(args.output_dir)
    COLLECTION_MANIFEST = CollectionManifestRecorder(
        run_id=START_TIMESTAMP,
        output_dir=OUTPUT_DIR,
        context={
            "auth_method": AUTH_CONFIG.get("auth_method"),
            "tenant_id": AUTH_CONFIG.get("tenant_id"),
            "subscription_id": AUTH_CONFIG.get("subscription_id"),
        },
        options={
            "endpoint_filter": args.endpoint,
            "parameter_endpoints_only": args.paramendpointsonly,
            "enrichment_enabled": not args.donotenrich,
            "max_workers": max_workers,
            "graph_lookback_days": args.graph_lookback_days,
            "graph_lookback_start": graph_interval[0],
            "graph_lookback_end": graph_interval[1],
        },
        project_dir=Path(__file__).resolve().parent,
    )

    collection_successful = False
    collection_completed = False
    manifest_written = False
    unattempted_reason_code = None
    unattempted_reason = None
    unattempted_reason_details = None
    try:
        collection_successful = execute_collection(args, max_workers)
        collection_completed = True
    except KeyboardInterrupt:
        unattempted_reason_code = "collection_interrupted"
        unattempted_reason = "Collection was interrupted by the operator before this endpoint was reached"
        unattempted_reason_details = {"termination_type": "KeyboardInterrupt"}
        raise
    except BaseException as exc:
        unattempted_reason_code = "collection_terminated_by_exception"
        unattempted_reason = (
            "Collection terminated before this endpoint was reached: "
            f"{type(exc).__name__}: {str(exc)[:500]}"
        )
        unattempted_reason_details = {"termination_type": type(exc).__name__}
        raise
    finally:
        if collection_completed:
            unattempted_reason_code = "collector_outcome_not_recorded"
            unattempted_reason = (
                "Collector completed without recording an outcome for this endpoint"
            )
            unattempted_reason_details = {
                "collection_completed": True,
                "classification": "internal_instrumentation_defect",
            }
        try:
            manifest_path = COLLECTION_MANIFEST.write(
                execution_successful=collection_successful,
                unattempted_reason_code=unattempted_reason_code,
                unattempted_reason=unattempted_reason,
                unattempted_reason_details=unattempted_reason_details,
            )
            manifest_written = True
            print(f"[+] Saved collection manifest: {manifest_path}")
        except (OSError, TypeError, ValueError) as exc:
            print(f"[ERROR] Failed to save collection manifest: {exc}")

    if not collection_successful or not manifest_written:
        exit(1)
