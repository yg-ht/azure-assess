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

import json
import subprocess
import argparse
import os
import shlex
from collections import Counter
from datetime import datetime
from itertools import product
from pathlib import Path
from time import sleep
from tqdm import tqdm

AUTH_CONFIG = {}

AZURE_CLI_ENDPOINTS = [
    {"name": "API Management Services", "cli_command": "az apim list", "needs_pagination": False},
    {"name": "App Configuration Stores", "cli_command": "az appconfig list", "needs_pagination": False},
    {"name": "App Service Environments", "cli_command": "az appservice ase list", "needs_pagination": False},
    {"name": "App Service Plans", "cli_command": "az appservice plan list", "needs_pagination": False},
    {"name": "Application Gateways", "cli_command": "az network application-gateway list", "needs_pagination": False},
    {"name": "Application Insights", "cli_command": "az monitor app-insights component list", "needs_pagination": False},
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
    {"name": "Virtual Networks", "cli_command": "az network vnet list", "needs_pagination": False},
    {"name": "NSGs", "cli_command": "az network nsg list", "needs_pagination": False},
    {"name": "Peering Services", "cli_command": "az network cross-connection list", "needs_pagination": False},
    {"name": "Policy Assignments", "cli_command": "az policy assignment list", "needs_pagination": True},
    {"name": "Policy Definitions", "cli_command": "az policy definition list", "needs_pagination": True},
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
    {"name": "Role Definitions", "cli_command": "az role definition list", "needs_pagination": False},
    {"name": "Route Tables", "cli_command": "az network route-table list", "needs_pagination": False},
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
    {"name": "Kubernetes Environments", "cli_command": "az appservice kube list", "needs_pagination": False},
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
    {"name": "Search Services", "cli_command": "az search service list", "needs_pagination": False},
    {"name": "Application Gateway WAF Policies", "cli_command": "az network application-gateway waf-policy list", "needs_pagination": False},
    {"name": "Network Watchers", "cli_command": "az network watcher list", "needs_pagination": False},
    {"name": "MySQL Servers", "cli_command": "az mysql flexible-server list", "needs_pagination": False},
    {"name": "Security Contacts", "cli_command": "az security contact list", "needs_pagination": False},
    {"name": "SignalR Services", "cli_command": "az signalr list", "needs_pagination": False},
    {"name": "Managed Disks", "cli_command": "az disk list", "needs_pagination": False},
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
        "required_params": {"name": "az_appservice_ase_list"}
    },
    {
        "name": "App Service Environment VIPs",
        "cli_command": "az appservice ase list-addresses --name {name}",
        "required_params": {"name": "az_appservice_ase_list"}
    },
    {
        "name": "App Service Plan Details",
        "cli_command": "az appservice plan show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_appservice_plan_list", "resourceGroup": "az_appservice_plan_list"}
    },
    {
        "name": "API Management Service Details",
        "cli_command": "az apim show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_apim_list", "resourceGroup": "az_apim_list"}
    },
    {
        "name": "App Service Plans in ASE",
        "cli_command": "az appservice ase list-plans --name {name}",
        "required_params": {"name": "az_appservice_ase_list"}
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
        "cli_command": "az policy assignment show --id {id}",
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
        "cli_command": "az appservice kube show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_appservice_kube_list", "resourceGroup": "az_appservice_kube_list"}
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
        "name": "Storage Account Keys",
        "cli_command": "az storage account keys list --account-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_storage_account_list", "resourceGroup": "az_storage_account_list"},
    },
    {
        "name": "Storage Queue Service Properties",
        "cli_command": "az storage account queue-service-properties show --account-name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_storage_account_list", "resourceGroup": "az_storage_account_list"},
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
        "cli_command": "az storage container list --account-name {name} --auth-mode login",
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
        "required_params": {"name": "az_monitor_app-insights_component_list",
                            "resourceGroup": "az_monitor_app-insights_component_list"},
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
        "cli_command": "az appconfig kv revision list --name {name} --all",
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
        "cli_command": "az sql server threat-policy show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_sql_server_list", "resourceGroup": "az_sql_server_list"},
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
        "name": "Managed Disk Details",
        "cli_command": "az disk show --name {name} --resource-group {resourceGroup}",
        "required_params": {"name": "az_disk_list", "resourceGroup": "az_disk_list"},
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
    }


def shell_quote(value):
    return shlex.quote(str(value))


def run_az_command(command, capture_output=False):
    return subprocess.run(command, shell=True, capture_output=capture_output, text=True)


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


def ensure_az_login(force_reauth=False):
    global AUTH_CONFIG

    auth_method = AUTH_CONFIG.get("auth_method", "existing")
    subscription_id = AUTH_CONFIG.get("subscription_id")

    if validate_auth_session(subscription_id) and not force_reauth:
        print("[✓] Azure CLI is authenticated.")
        set_az_account_context(subscription_id)
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


def run_az_cli(cmd):
    """Run an Azure CLI command and return structured output with stderr and parsed JSON."""
    if '--output json' not in cmd:
        cmd = cmd + ' --output json'
    global DEBUG
    must_exit = False
    error_message = None
    result = None
    try:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        stdout_lines = []

        # Read both stdout and stderr in real time
        while True:
            stdout_line = process.stdout.readline()
            if stdout_line:
                if DEBUG:
                    print(stdout_line, end='')
                stdout_lines.append(stdout_line)
            if not stdout_line and process.poll() is not None:
                break
        process.wait()
        result = {
            "args": cmd,
            "returncode": process.returncode,
            "success": process.returncode == 0,
            "stdout": ''.join(stdout_lines).strip(),
            "json": None,  # You can add JSON parsing here if needed
            "raw": None
        }
        result["raw"] = str(result["stdout"])
        if DEBUG:
            print(f"Return code: {result['returncode']}")
        if not result["returncode"] == 0:
            error_auth_signatures = [
                "tokenissuedbeforerevocationtimestamp",
                "interactionrequired",
            ]
            if any(sig in result["stdout"].lower() for sig in error_auth_signatures):
                print("[!] Azure token not valid. Attempting authentication refresh...")
                ensure_az_login(force_reauth=True)
                retry_result = run_az_command(cmd, capture_output=True)
                result = {
                    "args": cmd,
                    "returncode": retry_result.returncode,
                    "success": retry_result.returncode == 0,
                    "stdout": retry_result.stdout.strip(),
                    "json": None,
                    "raw": retry_result.stdout
                }
                if result["success"] and (result["stdout"].strip().startswith("{") or result["stdout"].strip().startswith("[")):
                    try:
                        result["json"] = json.loads(result["stdout"])
                    except Exception as e:
                        print(f"JSON parsing error: {e}")
                if not result["success"]:
                    error_message = "Authentication refresh failed to restore Azure CLI access."
                    must_exit = True

            error_cli_signatures = [
                "is misspelled or not recognized by the system",
                "the following arguments are required",
            ]
            if any(sig in result["stdout"].lower() for sig in error_cli_signatures):
                error_message = "Unrecognised or malformed CLI command"
                must_exit = True

        else:
            output_warning_signatures = [
                "behavior of this command has been altered",
                "is experimental and under development",
                "is in preview and under development",
                "is scheduled for retirement by",
                "command requires the extension"
            ]
            matched_sigs = [sig for sig in output_warning_signatures if sig in result["stdout"].lower()]
            if matched_sigs:
                if DEBUG:
                    print(f"[DEBUG] Found warning message signature(s): {matched_sigs}, attempting to filter")
                result["stdout"] = "\n".join(
                    line for line in result["stdout"].splitlines()
                    if not any(sig in line.lower() for sig in matched_sigs)
                )
                if DEBUG:
                    print(f"Filter result is: {result['stdout'][:30]} [END]")

            if (result["stdout"].strip().startswith("{") or result["stdout"].strip().startswith("[")):
                try:
                    result["json"] = json.loads(result["stdout"])
                except Exception as e:
                    print(f"JSON parsing error: {e}")
            elif len(result["stdout"]) > 0:
                if not any(sig in result["stdout"].lower() for sig in output_warning_signatures):
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
        if result["stdout"]:
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


def resolve_principal(object_id):
    """Resolve an Azure AD object ID to a readable name/type with status classification."""
    for entity_type, cmd in {
        "User": f"az ad user show --id {object_id}",
        "Group": f"az ad group show --group {object_id}",
        "ServicePrincipal": f"az ad sp show --id {object_id}"
    }.items():
        result = run_and_parse(cmd, entity_type, object_id)
        if result and result["status"] != "unknown":
            print(f"[~] {entity_type} {object_id} → status: {result['status']}")
            return result

    # Unknown fallback
    print(f"[~] Unresolved object ID {object_id} → status: unknown")
    return {
        "type": "Unknown",
        "objectId": object_id,
        "name": None,
        "status": "unknown"
    }


def resolve_role_assignments(assignments, role_definitions):
    """
    Resolve role assignments and map each to its corresponding permission set.
    This function enriches each role assignment by:
      - Resolving the principal (user, group, or service principal)
      - Mapping the roleDefinitionId to a role definition and extracting the permission set.
    """
    # Build a dictionary to map role definition IDs (in lower case) to their details.
    role_def_map = {}
    for role_def in role_definitions:
        role_def_map[role_def["id"].lower()] = role_def

    enriched = []
    print(f"[*] Resolving {len(assignments)} role assignments and mapping permissions...\n")

    for ra in tqdm(assignments, desc="Resolving principals", unit="ra"):
        # Resolve principal details.
        principal_id = ra.get("principalId")
        principal_details = resolve_principal(principal_id)
        ra["resolvedPrincipal"] = principal_details

        # Map the role assignment to its corresponding role definition.
        role_def_id = ra.get("roleDefinitionId", "").lower()
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


def collect_data_with_params(param_endpoints):
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

        for param, source in required_param_sources.items():
            filename_prefix = source.lower().replace(" ", "_").replace("(", "").replace(")", "")

            if DEBUG:
                print(f"[DEBUG] Looking for param '{param}' in files prefixed with: {filename_prefix}")

            source_records.setdefault(source, [])

            for file in os.listdir(OUTPUT_DIR):
                if not file.startswith(filename_prefix) or not file.endswith(".json"):
                    continue

                filepath = Path(OUTPUT_DIR) / file
                if DEBUG:
                    print(f"[DEBUG] Scanning file for parameter '{param}': {filepath}")

                try:
                    with open(filepath) as f:
                        data = json.load(f)
                    if not isinstance(data, list):
                        continue

                    for item in data:
                        if not isinstance(item, dict):
                            continue
                        source_records[source].append(item)
                except Exception as e:
                    print(f"[!] Failed to parse {file}: {e}")

        if DEBUG:
            print(f"[DEBUG] Collected source records: "
                  f"{ {source: len(records) for source, records in source_records.items()} }")

        # Ensure all required parameters have values
        missing_params = []
        for param, source in required_param_sources.items():
            values = []
            for item in source_records.get(source, []):
                value = item.get(param)
                if value and isinstance(value, str):
                    values.append(value)
            if not values:
                missing_params.append(param)

        if missing_params:
            print(f"[~] Skipping {name}: Missing required parameters: {required_params}")
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
                    value = item.get(param)
                    if not value or not isinstance(value, str):
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

        all_results = []

        for param_set in param_combinations:
            try:
                cli_command = cli_template.format(**param_set)
            except KeyError as e:
                print(f"[!] Skipping {name}: Missing placeholder for {str(e)}")
                continue

            if DEBUG:
                print(f"[DEBUG] Running command: {cli_command}")

            print(f"[*] Fetching: {name} with parameters: {param_set} ...")
            try:
                result = run_az_cli(cli_command)
                data = result.get("json", [])

                if not data:
                    print(f"[!] No data returned for: {name} with {param_set}")
                    continue

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
                    all_results.extend(data)
                else:
                    if name == "VM NIC IDs" and isinstance(data, dict):
                        data.setdefault("vm_name", param_set.get("name"))
                        data.setdefault("resourceGroup", param_set.get("resourceGroup"))
                    all_results.append(data)

            except Exception as e:
                print(f"[!] Data collect with params failed for {name} with {param_set}: {e}")

        if all_results:
            filename = cli_template.lower().replace("{", "").replace("}", "").replace(" ", "_").replace("(", "").replace(")", "") + f"_{START_TIMESTAMP}.json"
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


def collect_data(endpoints):
    global START_TIMESTAMP

    # ensure the script doesn't hang waiting for user input about installing extensions
    run_az_cli("az config set extension.use_dynamic_install=yes_without_prompt")
    run_az_cli("az config set extension.dynamic_install_allow_preview=true")

    for endpoint in endpoints:
        name = endpoint["name"]
        cmd = endpoint["cli_command"]

        print(f"[*] Fetching: {name} ...")
        try:
            result = run_az_cli(cmd)
            data = result.get("json", [])

            if isinstance(data, list):
                count = len(data)
            elif isinstance(data, dict):
                count = len(data.keys())
            else:
                count = 0

            if DEBUG:
                print(f"[DEBUG] Returned data is type: {type(data)}")

            if count == 0:
                print(f"[!] No data returned for: {name}")
                continue
            else:
                print(f"[~] {name} returned {count}")

            filename = cmd.lower().replace(" ", "_").replace("(", "").replace(")", "") + f"_{START_TIMESTAMP}.json"
            save_json(data, filename)

        except Exception as e:
            print(f"[!] Failed to collect {name}: {e}")


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
    global DEBUG
    START_TIMESTAMP = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    args = parse_arguments()
    AUTH_CONFIG = build_auth_config(args)

    if args.debug == True:
        DEBUG = True
    else:
        DEBUG = False

    if args.listendpoints or args.listparamendpoints:
        list_all_enabled_cli_endpoints(args.listparamendpoints)

    # Set the output directory dynamically
    global OUTPUT_DIR
    OUTPUT_DIR = Path(args.output_dir)

    ensure_az_login()
    if not args.paramendpointsonly:
        collect_data(filter_endpoints(args.endpoint, AZURE_CLI_ENDPOINTS))
    collect_data_with_params(filter_endpoints(args.endpoint, AZURE_CLI_ENDPOINTS_PARAMS))


    if not args.donotenrich and not args.endpoint:
        # Special handling for role assignments
        try:
            print(f"[+] Enriching roles with assignments and permissions...")
            assignment_result = run_az_cli("az role assignment list").get("json", [])
            role_def_result = run_az_cli("az role definition list").get("json", [])
            if assignment_result and role_def_result:
                enriched_data = resolve_role_assignments(assignment_result, role_def_result)
                save_json(enriched_data, f"role_enriched_{START_TIMESTAMP}.json")
                summarise_statuses(assignment_result)
            else:
                print(f"No assignments or role definitions found - cannot enrich")
        except Exception as e:
            print(f"[!] Failed to enrich data: {e}")

    print("[✓] Azure audit data collection complete.")
