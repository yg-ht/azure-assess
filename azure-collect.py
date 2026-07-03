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
from datetime import datetime
from itertools import product
from pathlib import Path
from time import monotonic, sleep
from tqdm import tqdm

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

PERMISSION_BASELINE_CHECKED = False
SOURCE_FILE_INDEX_LOCK = threading.Lock()
TIMING_RECORDS_LOCK = threading.Lock()
AZURE_CLI_EXTENSION_LOCK = threading.Lock()

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
    """Record non-sensitive command timing metadata for the final summary."""
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


def result_item_count(data):
    """Return a human-scale count for a command JSON payload."""
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        return len(data.keys())
    return 0


def timed_run_az_cli(cmd, endpoint_name=None, category="collection"):
    """Run an Azure CLI command and capture timing metadata."""
    started = monotonic()
    result = run_az_cli(cmd)
    duration = monotonic() - started
    record_timing(
        endpoint_name,
        category,
        cmd,
        duration,
        returncode=result.get("returncode"),
        result_count=result_item_count(result.get("json")),
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
        "generatedAtUtc": datetime.utcnow().isoformat(timespec="seconds") + "Z",
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


def collect_managed_role_definitions_cache(path=None):
    """Collect only Microsoft-managed role definitions and write the dedicated cache."""
    command = "az role definition list --query \"[?roleType=='BuiltInRole']\" --output json"
    role_definitions, error = run_json_command(command)
    if error:
        print(f"[ERROR] Failed to collect managed role definitions: {error}")
        exit(1)

    role_definitions = normalize_builtin_role_definitions(role_definitions)
    validate_builtin_role_definitions(role_definitions)

    az_version, version_error = run_json_command("az version --output json")
    if version_error:
        az_version = {"error": version_error}

    write_managed_role_definitions_cache(role_definitions, path=path, az_version=az_version)
    print(f"[✓] Cached {len(role_definitions)} managed role definitions.")


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
    {"name": "Media Services", "cli_command": "az ams account list", "needs_pagination": False},
    {"name": "Monitor Activity Logs", "cli_command": "az monitor activity-log list", "needs_pagination": True},
    {"name": "NAT Gateways", "cli_command": "az network nat gateway list", "needs_pagination": False},
    {"name": "Network Interfaces", "cli_command": "az network nic list", "needs_pagination": False},
    {"name": "NSGs", "cli_command": "az network nsg list", "needs_pagination": False},
    {"name": "Peering Services", "cli_command": "az network cross-connection list", "needs_pagination": False},
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
    {"name": "Data Lake Store Accounts", "cli_command": "az dls account list", "needs_pagination": False},
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
        "required_params": {"name": "az_account_list-locations"}
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
        "cli_command": "az storage cors list --services q --account-name {name} --auth-mode login",
        "required_params": {"name": "az_storage_account_list"},
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
        "cli_command": "az network private-endpoint-connection list --resource-group {resourceGroup} --resource-name {name} --type Microsoft.Storage/storageAccounts",
        "required_params": {"name": "az_storage_account_list", "resourceGroup": "az_storage_account_list"},
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
    },
    {
        "name": "App Service Private Endpoint Connections",
        "cli_command": "az network private-endpoint-connection list --resource-group {resourceGroup} --resource-name {name} --type Microsoft.Web/sites",
        "required_params": {"name": "az_webapp_list", "resourceGroup": "az_webapp_list"},
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
        "name": "Diagnostic Settings",
        "cli_command": "az monitor diagnostic-settings list --resource {id}",
        "required_params": {"id": "az_resource_list"},
    },
    {
        "name": "Diagnostic Settings Categories",
        "cli_command": "az monitor diagnostic-settings categories list --resource {id}",
        "required_params": {"id": "az_resource_list"},
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
        "cli_command": "az network private-endpoint-connection list --resource-group {resourceGroup} --resource-name {name} --type Microsoft.AppConfiguration/configurationStores",
        "required_params": {"name": "az_appconfig_list", "resourceGroup": "az_appconfig_list"},
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
        "cli_command": "az network private-endpoint-connection list --resource-group {resourceGroup} --resource-name {name} --type Microsoft.KeyVault/vaults",
        "required_params": {"name": "az_keyvault_list", "resourceGroup": "az_keyvault_list"},
    },
    {
        "name": "Application Gateway SSL Certs",
        "cli_command": "az network application-gateway ssl-cert list --gateway-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_network_application-gateway_list",
                            "resourceGroup": "az_network_application-gateway_list"},
    },
    {
        "name": "Application Gateway SSL Policy",
        "cli_command": "az network application-gateway ssl-policy show --gateway-name {name} --resource-group {resourceGroup}",
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
        "cli_command": "az network private-endpoint-connection list --resource-group {resourceGroup} --resource-name {name} --type Microsoft.Network/applicationGateways",
        "required_params": {"name": "az_network_application-gateway_list",
                            "resourceGroup": "az_network_application-gateway_list"},
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
        "cli_command": "az network watcher flow-log list --location {name}",
        "required_params": {"name": "az_account_list-locations"},
    },
    {
        "name": "Container Registry Private Endpoint Connections",
        "cli_command": "az network private-endpoint-connection list --resource-group {resourceGroup} --resource-name {name} --type Microsoft.ContainerRegistry/registries",
        "required_params": {"name": "az_acr_list", "resourceGroup": "az_acr_list"},
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
        "cli_command": "az sql server vuln-assessment show --server {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_sql_server_list", "resourceGroup": "az_sql_server_list"},
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


def run_az_command(command, capture_output=False):
    return subprocess.run(command, shell=True, capture_output=capture_output, text=True)


def run_az_cli_process(cmd):
    process = subprocess.Popen(
        cmd,
        shell=True,
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
        "args": cmd,
        "returncode": process.returncode,
        "success": process.returncode == 0,
        "stdout": stdout,
        "json": None,
        "raw": stdout,
    }


def extract_required_extension_name(output):
    for pattern in AZURE_CLI_EXTENSION_NAME_PATTERNS:
        match = pattern.search(output or "")
        if match:
            return match.group(1).strip("'\".,")
    return None


def infer_extension_from_command(cmd):
    try:
        tokens = shlex.split(cmd)
    except ValueError:
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

    return True


def run_json_command(command):
    """Run a shell command expected to return JSON."""
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


def run_az_cli(cmd):
    """Run an Azure CLI command and return structured output with stderr and parsed JSON."""
    if '--output json' not in cmd:
        cmd = cmd + ' --output json'
    global DEBUG
    must_exit = False
    error_message = None
    result = None
    try:
        result = run_az_cli_process(cmd)
        if DEBUG:
            debug_memory(f"process completed: {cmd}")
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
                    must_exit = True

        if result["returncode"] != 0 and not must_exit:
            retry_result = install_missing_extension_and_retry(cmd, result)
            if retry_result:
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
                must_exit = True

        else:
            if DEBUG:
                debug_memory(f"before warning filter: {cmd}")
            result["stdout"], matched_sigs = filter_az_cli_warning_output(result["stdout"])
            if DEBUG:
                debug_memory(f"after warning filter: {cmd}")
            if matched_sigs:
                if DEBUG:
                    print(f"[DEBUG] Found warning message signature(s): {matched_sigs}, attempting to filter")
                if DEBUG:
                    print(f"Filter result is: {result['stdout'][:30]} [END]")

            if result["stdout"].strip():
                try:
                    if DEBUG:
                        debug_memory(f"before JSON parse: {cmd}")
                    result["json"] = parse_json_from_az_output(result["stdout"])
                    if DEBUG:
                        debug_memory(f"after JSON parse: {cmd}")
                except Exception as e:
                    print(f"JSON parsing error: {e}")
                    if not any(sig in result["stdout"].lower() for sig in AZURE_CLI_OUTPUT_WARNING_SIGNATURES):
                        error_message = "Something has gone wrong - data returned but not JSON"
            elif len(result["stdout"]) > 0:
                if not any(sig in result["stdout"].lower() for sig in AZURE_CLI_OUTPUT_WARNING_SIGNATURES):
                    error_message = "Something has gone wrong - data returned but not JSON"

        if error_message:
            if must_exit:
                prefix = "[ERROR]"
            else:
                prefix = "[WARNING]"
            print("\n\n")
            print("===========================================")
            print(f"{prefix} Issue running command: {cmd}")
            print(f"Application message: {error_message}")
            if result["stdout"]:
                print(f"    Process details: {str(result['stdout'])}")
            if must_exit:
                print("!!!FATAL!!! Exiting...")
            print("===========================================")
            if must_exit:
                exit(1)
            else:
                sleep(1)

        # return result - with or without nested JSON object
        return result

    except Exception as e:
        print("\n\n")
        print(f"===========================================")
        print(f"[ERROR] Exception running command: {cmd}")
        if result and result.get("stdout"):
            print(f"Process details: {str(result['stdout'])}")
        print(f"Exception message: {str(e)}")
        print(f"===========================================")
        exit(1)


def save_json(data, filename, append=False):
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

    save_json(role_definitions, f"az_role_definition_list_{START_TIMESTAMP}.json")
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
    """Filter parameter-source records to the Azure resource types an endpoint accepts."""
    required_source_types = endpoint.get("required_source_types", {})
    allowed_types = required_source_types.get(source)
    if not allowed_types:
        return records

    allowed_types = {resource_type.lower() for resource_type in allowed_types}
    filtered_records = []
    for item in records:
        # Generic fields such as `name` are only safe when the source record is
        # known to describe the resource type that the follow-on command targets.
        if record_resource_type(item) in allowed_types:
            filtered_records.append(item)
    return filtered_records


def resolve_param_value(item, param):
    """Resolve a parameter from a record or its collection context."""
    value = item.get(param)
    if value is None:
        value = item.get("_collectionContext", {}).get("parameters", {}).get(param)
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
        cli_command = cli_template.format(**param_set)
    except KeyError as e:
        print(f"[!] Skipping {name}: Missing placeholder for {str(e)}")
        return []

    if DEBUG:
        print(f"[DEBUG] Running command: {cli_command}")

    print(f"[*] Fetching: {name} with parameters: {param_set} ...")
    try:
        result = timed_run_az_cli(cli_command, endpoint_name=name, category="parameterised")
        data = result.get("json", [])

        if endpoint.get("extract_value") and isinstance(data, dict) and isinstance(data.get("value"), list):
            data = data["value"]

        if not data:
            print(f"[!] No data returned for: {name} with {param_set}")
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

        if DEBUG:
            print(f"[DEBUG] Processing endpoint: {name}")
            print(f"[DEBUG] Required parameters and sources: {required_param_sources}")

        source_records = {}

        sources_needed = sorted(set(required_param_sources.values()))

        for source in sources_needed:
            source_records[source] = filter_source_records_for_endpoint(
                endpoint,
                source,
                load_source_records(
                    source,
                    current_run_only=current_run_only,
                ),
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
                value = resolve_param_value(item, param)
                if value:
                    values.append(value)
            if not values:
                missing_params.append(param)

        if missing_params:
            print(f"[~] Skipping {name}: Missing required parameters: {missing_params}")
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
                    value = resolve_param_value(item, param)
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
        result = timed_run_az_cli(cmd, endpoint_name=name, category="base")
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


def filter_endpoints(keyword=None, endpoints=None):
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
    if not filtered:
        print(f"No matching endpoints found for selection: {keyword}")
        exit(1)
    return filtered


if __name__ == "__main__":
    global START_TIMESTAMP
    START_TIMESTAMP = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    args = parse_arguments()
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

    if args.collect_managed_role_definitions_cache:
        ensure_az_login(skip_permission_baseline=True)
        collect_managed_role_definitions_cache(args.managed_role_definitions_cache_path)
        if args.timing_summary:
            print_timing_summary()
        exit(0)

    ensure_az_login()

    if not args.paramendpointsonly:
        collect_data(filter_endpoints(args.endpoint, AZURE_CLI_ENDPOINTS), max_workers=max_workers)
        if not args.endpoint or "role definition" in str(args.endpoint).lower():
            merge_role_definition_dataset(args.managed_role_definitions_cache_path)

    current_run_only = not args.paramendpointsonly

    if args.paramendpointsonly:
        print("[~] Parameter-only mode enabled: allowing existing source files from previous runs.")

    collect_data_with_params(
        filter_endpoints(args.endpoint, AZURE_CLI_ENDPOINTS_PARAMS),
        current_run_only=current_run_only,
        max_workers=max_workers,
    )

    if not args.donotenrich and not args.endpoint:
        # Special handling for role assignments
        try:
            print(f"[+] Enriching roles with assignments and permissions...")
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
                save_json(enriched_data, f"role_enriched_{START_TIMESTAMP}.json")
                summarise_statuses(assignment_result)
            else:
                print(f"No assignments or role definitions found - cannot enrich")
        except Exception as e:
            print(f"[!] Failed to enrich data: {e}")

    if args.timing_summary:
        print_timing_summary()

    print("[✓] Azure audit data collection complete.")
