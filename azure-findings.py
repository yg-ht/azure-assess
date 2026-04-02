#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Search previously collected Azure JSON data for evidence supporting known findings.

import argparse
from datetime import datetime, timezone
import json
import re
from pathlib import Path
from urllib.parse import quote

from azure_findings_checks import *
from azure_findings_definitions import EXISTING_FINDING_HEADLINES, REQUESTED_HEADLINES
from azure_findings_shared import (
    normalize_text,
    unsupported,
)

TIMESTAMP_SUFFIX_RE = re.compile(r"_\d{8}-\d{6}$")
NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"

def parse_arguments():
    parser = argparse.ArgumentParser(description="Search collected Azure JSON for known-bad findings")
    parser.add_argument(
        "-i",
        "--input-dir",
        type=str,
        default="azure-collect",
        help="Directory containing JSON produced by azure-collect.py",
    )
    parser.add_argument(
        "-o",
        "--output-file",
        type=str,
        default=None,
        help="Path to save found findings as SARIF 2.1.0 JSON (defaults to <input-dir>/azure-findings.json)",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Do not save JSON output; only print a summary",
    )
    parser.add_argument(
        "--flat-output-file",
        type=str,
        default=None,
        help="Path to save a flat list of findings for easier viewing in azure-present (defaults to <input-dir>/azure-findings-flat.json)",
    )
    return parser.parse_args()


def resolve_output_path(input_dir, output_file, default_filename):
    if output_file:
        return Path(output_file)
    return Path(input_dir) / default_filename


def strip_timestamp(path):
    return TIMESTAMP_SUFFIX_RE.sub("", path.stem.lower())


def extract_path_timestamp(path):
    match = TIMESTAMP_SUFFIX_RE.search(path.stem)
    if not match:
        return None
    suffix = match.group(0).lstrip("_")
    try:
        return datetime.strptime(suffix, "%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def latest_dataset_timestamp(paths):
    latest = None
    for path in paths:
        timestamp = extract_path_timestamp(Path(path))
        if timestamp is not None and (latest is None or timestamp > latest):
            latest = timestamp
    return latest


def load_catalog(input_dir):
    base = Path(input_dir)
    if not base.exists():
        raise FileNotFoundError(f"Input directory not found: {base}")

    files_by_base = {}
    for path in sorted(base.glob("*.json")):
        files_by_base[strip_timestamp(path)] = path

    catalog = {}
    for base_name, path in files_by_base.items():
        try:
            with open(path, encoding="utf-8") as handle:
                payload = json.load(handle)
        except Exception as exc:
            catalog[base_name] = {"path": str(path), "data": None, "error": str(exc)}
            continue
        catalog[base_name] = {"path": str(path), "data": payload, "error": None}
    return catalog


def as_list(payload):
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    return [payload]


def expand_value_records(records):
    expanded = []
    for record in records:
        if isinstance(record, dict) and isinstance(record.get("value"), list):
            expanded.extend(record.get("value") or [])
        else:
            expanded.extend(as_list(record))
    return expanded


def dataset_records(catalog, *fragments):
    fragments = [fragment.lower() for fragment in fragments]
    matched = []
    for base_name, item in catalog.items():
        if all(fragment in base_name for fragment in fragments):
            matched.extend(as_list(item["data"]))
    return matched


def dataset_present(catalog, *fragments):
    fragments = [fragment.lower() for fragment in fragments]
    return any(all(fragment in base_name for fragment in fragments) for base_name in catalog)


def dataset_paths(catalog, *fragments):
    fragments = [fragment.lower() for fragment in fragments]
    paths = []
    for base_name, item in catalog.items():
        if all(fragment in base_name for fragment in fragments):
            paths.append(item["path"])
    return sorted(set(paths))


def resource_portal_link(resource_id):
    if not resource_id:
        return None
    return f"https://portal.azure.com/#view/HubsExtension/ResourceMenuBlade/~/overview/resourceId/{quote(str(resource_id), safe='')}"


def subscription_portal_link(subscription_id):
    if not subscription_id:
        return None
    value = str(subscription_id)
    if value.lower().startswith("/subscriptions/"):
        value = value.split("/", 3)[2]
    return f"https://portal.azure.com/#view/Microsoft_Azure_Billing/SubscriptionsBlade/subscriptionId/{quote(value, safe='')}"


def extract_reference_ids(evidence):
    ids = []
    for key in (
        "id",
        "resourceId",
        "scope",
        "nsgId",
        "appGatewayId",
        "vmId",
        "subscriptionId",
        "target",
        "pe",
    ):
        value = evidence.get(key)
        if isinstance(value, str) and value:
            ids.append(value)
    return sorted(set(ids))


def build_evidence_references(evidence):
    references = []
    seen = set()
    for ref_id in extract_reference_ids(evidence):
        if ref_id in seen:
            continue
        seen.add(ref_id)
        link = resource_portal_link(ref_id) if ref_id.lower().startswith("/subscriptions/") else None
        references.append({"type": "azure_resource", "id": ref_id, "portal": link})

    subscription_id = evidence.get("subscriptionId")
    if isinstance(subscription_id, str) and subscription_id:
        key = f"subscription:{subscription_id}"
        if key not in seen:
            seen.add(key)
            references.append(
                {"type": "azure_subscription", "id": subscription_id, "portal": subscription_portal_link(subscription_id)}
            )
    return references


def evidence_query_term(evidence):
    for key in (
        "id",
        "resourceId",
        "scope",
        "name",
        "ruleName",
        "serverName",
        "webApp",
        "nsgName",
        "subscriptionId",
    ):
        value = evidence.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def build_present_links(source_files, evidence, finding_title):
    query = evidence_query_term(evidence) or finding_title
    links = []
    seen = set()
    for source_file in source_files:
        filename = Path(source_file).name
        href = f"/query/{quote(filename, safe='')}?query={quote(str(query), safe='')}"
        if href in seen:
            continue
        seen.add(href)
        links.append({"type": "azure_present", "file": filename, "query": query, "href": href})
    return links


def attach_references(finding, source_files):
    references = {"source_files": sorted(set(source_files)), "evidence_links": []}
    for evidence in finding["evidence"]:
        item_refs = build_evidence_references(evidence)
        item_refs.extend(build_present_links(source_files, evidence, finding["title"]))
        evidence["_references"] = item_refs
        references["evidence_links"].extend(item_refs)

    deduped_links = []
    seen = set()
    for item in references["evidence_links"]:
        key = (
            item.get("type"),
            item.get("id"),
            item.get("portal"),
            item.get("href"),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped_links.append(item)
    references["evidence_links"] = deduped_links
    finding["references"] = references
    return finding


def flat_rows(findings):
    rows = []
    for finding in findings:
        row = {
            "title": finding["title"],
            "severity": finding["severity"],
            "status": finding["status"],
            "reason": finding["reason"],
            "count": finding["evidence_count"],
            "evidence": finding["evidence"] if finding["evidence"] else [],
            "viewer_links": [item.get("href") for item in finding.get("references", {}).get("evidence_links", []) if item.get("href")],
            "source_file": finding.get("references", {}).get("source_files", []),
            "azure_portal_links": [item.get("portal") for item in finding.get("references", {}).get("evidence_links", []) if item.get("portal")],
        }
        rows.append(row)
    return rows


def finding_headline_ids(finding):
    return EXISTING_FINDING_HEADLINES.get(finding["title"], [])


def sarif_rule_id(finding):
    headline_ids = finding_headline_ids(finding)
    if headline_ids:
        return headline_ids[0]
    normalized = NON_ALNUM_RE.sub("_", finding["title"].strip().lower()).strip("_")
    return normalized or "azure_finding"


def sarif_level(severity):
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "unknown": "warning",
    }.get(normalize_text(severity), "warning")


def sarif_rule_descriptor(finding):
    descriptor = {
        "id": sarif_rule_id(finding),
        "name": finding["title"],
        "shortDescription": {"text": finding["title"]},
        "fullDescription": {"text": finding["reason"]},
        "defaultConfiguration": {"level": sarif_level(finding["severity"])},
        "properties": {
            "severity": finding["severity"],
            "headline_ids": finding_headline_ids(finding),
        },
    }
    references = finding.get("references", {}).get("source_files", [])
    if references:
        descriptor["help"] = {
            "text": f"Derived from {len(references)} Azure dataset file(s) collected by azure-collect."
        }
    return descriptor


def sarif_result_message(finding):
    return (
        f"{finding['title']} found with {finding['evidence_count']} evidence item(s). "
        f"{finding['reason']}"
    )


def sarif_locations(finding):
    locations = []
    seen = set()
    for evidence in finding.get("evidence", []):
        for reference in evidence.get("_references", []):
            if reference.get("type") not in {"azure_resource", "azure_subscription"}:
                continue
            ref_id = reference.get("id")
            if not ref_id or ref_id in seen:
                continue
            seen.add(ref_id)
            name = evidence.get("name") or evidence.get("resourceGroup") or ref_id
            locations.append(
                {
                    "logicalLocations": [
                        {
                            "fullyQualifiedName": ref_id,
                            "name": name,
                            "kind": reference["type"],
                        }
                    ],
                    "message": {"text": f"Azure scope: {ref_id}"},
                }
            )
    return locations


def sarif_result(finding):
    result = {
        "ruleId": sarif_rule_id(finding),
        "level": sarif_level(finding["severity"]),
        "kind": "fail",
        "message": {"text": sarif_result_message(finding)},
        "properties": {
            "title": finding["title"],
            "severity": finding["severity"],
            "status": finding["status"],
            "reason": finding["reason"],
            "evidence_count": finding["evidence_count"],
            "headline_ids": finding_headline_ids(finding),
            "references": finding.get("references", {}),
            "evidence": finding.get("evidence", []),
        },
    }
    locations = sarif_locations(finding)
    if locations:
        result["locations"] = locations
    return result


def sarif_output(input_dir, catalog, findings):
    found = [finding for finding in findings if finding["status"] == "found"]
    unique_rules = {}
    for finding in found:
        unique_rules.setdefault(sarif_rule_id(finding), sarif_rule_descriptor(finding))
    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "azure-findings",
                        "informationUri": "https://github.com/yg-ht/azure-assess",
                        "rules": list(unique_rules.values()),
                    }
                },
                "automationDetails": {
                    "id": str(Path(input_dir)),
                    "description": {
                        "text": "Azure findings in the found state generated from azure-collect datasets."
                    },
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "input_dir": str(Path(input_dir)),
                            "files_loaded": sorted(catalog.keys()),
                            "found_findings": len(found),
                        },
                    }
                ],
                "results": [sarif_result(finding) for finding in found],
                "properties": {
                    "input_dir": str(Path(input_dir)),
                    "files_loaded": sorted(catalog.keys()),
                    "result_origin": "azure-findings found results only",
                },
            }
        ],
    }


def annotate_requested_headlines(findings):
    covered = set()
    for finding in findings:
        headline_ids = EXISTING_FINDING_HEADLINES.get(finding["title"], [])
        covered.update(headline_ids)

    for headline in REQUESTED_HEADLINES:
        if headline in covered:
            continue
        findings.append(
            unsupported(
                headline,
                "Unknown",
                "azure-findings does not currently implement this requested headline with the datasets collected today.",
            )
        )

    return findings


def evaluate_findings(catalog):
    apim_services = dataset_records(catalog, "az_apim_show")
    ad_users = dataset_records(catalog, "az_ad_user_list")
    app_service_environments = dataset_records(catalog, "az_appservice_ase_show")
    storage_accounts = dataset_records(catalog, "az_storage_account_list")
    storage_keys = dataset_records(catalog, "az_storage_account_keys_list")
    storage_blob_service_properties = dataset_records(catalog, "az_storage_account_blob-service-properties_show")
    storage_file_service_properties = dataset_records(catalog, "az_storage_account_file-service-properties_show")
    storage_shares = dataset_records(catalog, "az_storage_share-rm_list")
    storage_queues = dataset_records(catalog, "az_storage_queue_list")
    storage_tables = dataset_records(catalog, "az_storage_table_list")
    role_definitions = dataset_records(catalog, "az_role_definition_list")
    role_assignments = dataset_records(catalog, "role_enriched") or dataset_records(catalog, "az_role_assignment_list")
    postgres_servers = dataset_records(catalog, "az_postgres_flexible-server_list")
    postgres_firewall_rules = dataset_records(catalog, "az_postgres_flexible-server_firewall-rule_list")
    postgres_parameters = dataset_records(catalog, "az_postgres_flexible-server_parameter_list")
    mysql_servers = dataset_records(catalog, "az_mysql_flexible-server_list")
    mysql_parameters = dataset_records(catalog, "az_mysql_flexible-server_parameter_list")
    key_vaults = dataset_records(catalog, "az_keyvault_list")
    key_vault_network_rules = dataset_records(catalog, "az_keyvault_network-rule_list")
    key_vault_private_endpoint_connections = dataset_records(catalog, "az_keyvault_show", "privateendpointconnections")
    key_vault_keys = dataset_records(catalog, "az_keyvault_key_list")
    key_vault_key_rotation_policies = dataset_records(catalog, "az_keyvault_key_rotation-policy_show")
    key_vault_secrets = dataset_records(catalog, "az_keyvault_secret_list")
    metric_alerts = dataset_records(catalog, "az_monitor_metrics_alert_list")
    defender_assessments = dataset_records(catalog, "az_security_assessment_list")
    defender_settings = dataset_records(catalog, "az_security_pricing_list")
    defender_general_settings = dataset_records(catalog, "az_security_setting_list")
    defender_auto_provisioning_settings = dataset_records(catalog, "az_security_auto-provisioning-setting_list")
    defender_jit_policies = dataset_records(catalog, "az_security_jit-policy_list")
    security_contacts = dataset_records(catalog, "az_security_contact_list")
    locations = dataset_records(catalog, "az_account_list-locations")
    resources = dataset_records(catalog, "az_resource_list")
    network_watchers = dataset_records(catalog, "az_network_watcher_list")
    subscriptions = dataset_records(catalog, "az_account_list")
    subscription_diagnostic_settings = dataset_records(catalog, "az_monitor_diagnostic-settings_subscription_list")
    diagnostic_settings = dataset_records(catalog, "az_monitor_diagnostic-settings_list")
    diagnostic_categories = dataset_records(catalog, "az_monitor_diagnostic-settings_categories_list")
    activity_log_alerts = dataset_records(catalog, "az_monitor_activity-log_alert_list")
    log_profiles = dataset_records(catalog, "az_monitor_log-profiles_list")
    web_app_configs = dataset_records(catalog, "az_webapp_config_show")
    web_app_access_restrictions = dataset_records(catalog, "az_webapp_config_access-restriction_show")
    web_app_auth_settings = dataset_records(catalog, "az_webapp_auth_show")
    web_app_logs = dataset_records(catalog, "az_webapp_log_show")
    web_apps = dataset_records(catalog, "az_webapp_list")
    web_app_appsettings = dataset_records(catalog, "az_webapp_config_appsettings_list")
    function_apps = dataset_records(catalog, "az_functionapp_list")
    function_app_configs = dataset_records(catalog, "az_functionapp_config_show")
    function_app_auth_settings = dataset_records(catalog, "az_webapp_auth_show", "az_functionapp_list")
    function_app_appsettings = dataset_records(catalog, "az_functionapp_config_appsettings_list")
    function_app_keys = dataset_records(catalog, "az_functionapp_keys_list")
    function_app_access_restrictions = dataset_records(catalog, "az_functionapp_config_access-restriction_show")
    function_app_identities = dataset_records(catalog, "az_functionapp_identity_show")
    function_app_vnet_integrations = dataset_records(catalog, "az_functionapp_vnet-integration_list")
    aks_clusters = dataset_records(catalog, "az_aks_list")
    container_registries = dataset_records(catalog, "az_acr_list")
    acr_private_endpoint_connections = dataset_records(catalog, "microsoft.containerregistry", "private-endpoint-connection")
    cosmosdb_accounts = dataset_records(catalog, "az_cosmosdb_list")
    cosmosdb_sql_role_assignments = dataset_records(catalog, "az_cosmosdb_sql_role_assignment_list")
    eventgrid_topics = dataset_records(catalog, "az_eventgrid_topic_list")
    eventgrid_domains = dataset_records(catalog, "az_eventgrid_domain_list")
    iot_dps_instances = dataset_records(catalog, "az_iot_dps_list")
    cognitive_services_accounts = dataset_records(catalog, "az_cognitiveservices_account_list")
    databricks_workspaces = dataset_records(catalog, "az_databricks_workspace_show")
    machine_learning_workspaces = dataset_records(catalog, "az_ml_workspace_show")
    redis_caches = dataset_records(catalog, "az_redis_list")
    search_services = dataset_records(catalog, "az_search_service_show")
    search_shared_private_links = dataset_records(catalog, "az_search_shared-private-link-resource_list")
    signalr_services = dataset_records(catalog, "az_signalr_show")
    sql_servers = dataset_records(catalog, "az_sql_server_list")
    sql_server_details = dataset_records(catalog, "az_sql_server_show")
    sql_server_aad_admins = dataset_records(catalog, "az_sql_server_ad-admin_list")
    sql_server_audit_policies = dataset_records(catalog, "az_sql_server_audit-policy_show")
    sql_server_firewall_rules = dataset_records(catalog, "az_sql_server_firewall-rule_list")
    sql_server_threat_policies = dataset_records(catalog, "az_sql_server_threat-policy_show")
    sql_server_tde_keys = dataset_records(catalog, "az_sql_server_tde-key_show")
    sql_server_vuln_assessments = dataset_records(catalog, "az_sql_server_vuln-assessment_show")
    sql_database_audit_policies = dataset_records(catalog, "az_sql_db_audit-policy_show")
    sql_database_threat_policies = dataset_records(catalog, "az_sql_db_threat-policy_show")
    sql_database_tde = dataset_records(catalog, "az_sql_db_tde_show")
    backup_items = dataset_records(catalog, "az_backup_item_list")
    backup_policies = dataset_records(catalog, "az_backup_policy_list")
    hdinsight_clusters = dataset_records(catalog, "az_hdinsight_show")
    managed_disks = dataset_records(catalog, "az_disk_list")
    synapse_workspaces = dataset_records(catalog, "az_synapse_workspace_list")
    bastion_hosts = dataset_records(catalog, "az_network_bastion_list")
    flow_logs = dataset_records(catalog, "az_network_watcher_flow-log_list")
    public_ip_addresses = dataset_records(catalog, "az_network_public-ip_list")
    vm_details = dataset_records(catalog, "az_vm_show")
    vm_extensions = dataset_records(catalog, "az_vm_extension_list")
    vm_scale_sets = dataset_records(catalog, "az_vmss_list")
    nsgs = dataset_records(catalog, "az_network_nsg_list")
    graph_conditional_access_policies = expand_value_records(dataset_records(catalog, "graph.microsoft.com", "conditionalaccess", "policies"))
    graph_directory_roles = expand_value_records(dataset_records(catalog, "graph.microsoft.com", "directoryroles"))
    graph_directory_role_assignments = expand_value_records(dataset_records(catalog, "graph.microsoft.com", "rolemanagement", "roleassignments"))
    graph_group_settings = expand_value_records(dataset_records(catalog, "graph.microsoft.com", "groupsettings"))
    graph_named_locations = expand_value_records(dataset_records(catalog, "graph.microsoft.com", "namedlocations"))
    graph_authorization_policy = expand_value_records(dataset_records(catalog, "graph.microsoft.com", "authorizationpolicy"))
    graph_security_defaults_policy = expand_value_records(dataset_records(catalog, "graph.microsoft.com", "identitysecuritydefaultsenforcementpolicy"))
    graph_user_registration_details = expand_value_records(dataset_records(catalog, "graph.microsoft.com", "userregistrationdetails"))
    source_map = {
        "apim_services": dataset_paths(catalog, "az_apim_show"),
        "ad_users": dataset_paths(catalog, "az_ad_user_list"),
        "app_service_environments": dataset_paths(catalog, "az_appservice_ase_show"),
        "storage_accounts": dataset_paths(catalog, "az_storage_account_list"),
        "storage_keys": dataset_paths(catalog, "az_storage_account_keys_list"),
        "storage_blob_service_properties": dataset_paths(catalog, "az_storage_account_blob-service-properties_show"),
        "storage_file_service_properties": dataset_paths(catalog, "az_storage_account_file-service-properties_show"),
        "storage_shares": dataset_paths(catalog, "az_storage_share-rm_list"),
        "storage_queues": dataset_paths(catalog, "az_storage_queue_list"),
        "storage_tables": dataset_paths(catalog, "az_storage_table_list"),
        "role_definitions": dataset_paths(catalog, "az_role_definition_list"),
        "role_assignments": dataset_paths(catalog, "role_enriched") or dataset_paths(catalog, "az_role_assignment_list"),
        "postgres_parameters": dataset_paths(catalog, "az_postgres_flexible-server_parameter_list"),
        "postgres_firewall_rules": dataset_paths(catalog, "az_postgres_flexible-server_firewall-rule_list"),
        "mysql_servers": dataset_paths(catalog, "az_mysql_flexible-server_list"),
        "mysql_parameters": dataset_paths(catalog, "az_mysql_flexible-server_parameter_list"),
        "key_vaults": dataset_paths(catalog, "az_keyvault_list"),
        "key_vault_network_rules": dataset_paths(catalog, "az_keyvault_network-rule_list"),
        "key_vault_private_endpoint_connections": dataset_paths(catalog, "az_keyvault_show", "privateendpointconnections"),
        "key_vault_keys": dataset_paths(catalog, "az_keyvault_key_list"),
        "key_vault_key_rotation_policies": dataset_paths(catalog, "az_keyvault_key_rotation-policy_show"),
        "key_vault_secrets": dataset_paths(catalog, "az_keyvault_secret_list"),
        "metric_alerts": dataset_paths(catalog, "az_monitor_metrics_alert_list"),
        "defender_assessments": dataset_paths(catalog, "az_security_assessment_list"),
        "defender_settings": dataset_paths(catalog, "az_security_pricing_list"),
        "defender_general_settings": dataset_paths(catalog, "az_security_setting_list"),
        "defender_auto_provisioning_settings": dataset_paths(catalog, "az_security_auto-provisioning-setting_list"),
        "defender_jit_policies": dataset_paths(catalog, "az_security_jit-policy_list"),
        "security_contacts": dataset_paths(catalog, "az_security_contact_list"),
        "locations": dataset_paths(catalog, "az_account_list-locations"),
        "resources": dataset_paths(catalog, "az_resource_list"),
        "network_watchers": dataset_paths(catalog, "az_network_watcher_list"),
        "subscriptions": dataset_paths(catalog, "az_account_list"),
        "subscription_diagnostic_settings": dataset_paths(catalog, "az_monitor_diagnostic-settings_subscription_list"),
        "diagnostic_settings": dataset_paths(catalog, "az_monitor_diagnostic-settings_list"),
        "diagnostic_categories": dataset_paths(catalog, "az_monitor_diagnostic-settings_categories_list"),
        "activity_log_alerts": dataset_paths(catalog, "az_monitor_activity-log_alert_list"),
        "log_profiles": dataset_paths(catalog, "az_monitor_log-profiles_list"),
        "web_app_configs": dataset_paths(catalog, "az_webapp_config_show"),
        "web_app_access_restrictions": dataset_paths(catalog, "az_webapp_config_access-restriction_show"),
        "web_app_auth_settings": dataset_paths(catalog, "az_webapp_auth_show"),
        "web_app_logs": dataset_paths(catalog, "az_webapp_log_show"),
        "web_apps": dataset_paths(catalog, "az_webapp_list"),
        "web_app_appsettings": dataset_paths(catalog, "az_webapp_config_appsettings_list"),
        "function_apps": dataset_paths(catalog, "az_functionapp_list"),
        "function_app_configs": dataset_paths(catalog, "az_functionapp_config_show"),
        "function_app_auth_settings": dataset_paths(catalog, "az_webapp_auth_show"),
        "function_app_appsettings": dataset_paths(catalog, "az_functionapp_config_appsettings_list"),
        "function_app_keys": dataset_paths(catalog, "az_functionapp_keys_list"),
        "function_app_access_restrictions": dataset_paths(catalog, "az_functionapp_config_access-restriction_show"),
        "function_app_identities": dataset_paths(catalog, "az_functionapp_identity_show"),
        "function_app_vnet_integrations": dataset_paths(catalog, "az_functionapp_vnet-integration_list"),
        "aks_clusters": dataset_paths(catalog, "az_aks_list"),
        "container_registries": dataset_paths(catalog, "az_acr_list"),
        "acr_private_endpoint_connections": dataset_paths(catalog, "microsoft.containerregistry", "private-endpoint-connection"),
        "cosmosdb_accounts": dataset_paths(catalog, "az_cosmosdb_list"),
        "cosmosdb_sql_role_assignments": dataset_paths(catalog, "az_cosmosdb_sql_role_assignment_list"),
        "eventgrid_topics": dataset_paths(catalog, "az_eventgrid_topic_list"),
        "eventgrid_domains": dataset_paths(catalog, "az_eventgrid_domain_list"),
        "iot_dps_instances": dataset_paths(catalog, "az_iot_dps_list"),
        "cognitive_services_accounts": dataset_paths(catalog, "az_cognitiveservices_account_list"),
        "databricks_workspaces": dataset_paths(catalog, "az_databricks_workspace_show"),
        "machine_learning_workspaces": dataset_paths(catalog, "az_ml_workspace_show"),
        "redis_caches": dataset_paths(catalog, "az_redis_list"),
        "search_services": dataset_paths(catalog, "az_search_service_show"),
        "search_shared_private_links": dataset_paths(catalog, "az_search_shared-private-link-resource_list"),
        "signalr_services": dataset_paths(catalog, "az_signalr_show"),
        "sql_servers": dataset_paths(catalog, "az_sql_server_list"),
        "sql_server_details": dataset_paths(catalog, "az_sql_server_show"),
        "sql_server_aad_admins": dataset_paths(catalog, "az_sql_server_ad-admin_list"),
        "sql_server_audit_policies": dataset_paths(catalog, "az_sql_server_audit-policy_show"),
        "sql_server_firewall_rules": dataset_paths(catalog, "az_sql_server_firewall-rule_list"),
        "sql_server_threat_policies": dataset_paths(catalog, "az_sql_server_threat-policy_show"),
        "sql_server_tde_keys": dataset_paths(catalog, "az_sql_server_tde-key_show"),
        "sql_server_vuln_assessments": dataset_paths(catalog, "az_sql_server_vuln-assessment_show"),
        "sql_database_audit_policies": dataset_paths(catalog, "az_sql_db_audit-policy_show"),
        "sql_database_threat_policies": dataset_paths(catalog, "az_sql_db_threat-policy_show"),
        "sql_database_tde": dataset_paths(catalog, "az_sql_db_tde_show"),
        "backup_items": dataset_paths(catalog, "az_backup_item_list"),
        "backup_policies": dataset_paths(catalog, "az_backup_policy_list"),
        "hdinsight_clusters": dataset_paths(catalog, "az_hdinsight_show"),
        "managed_disks": dataset_paths(catalog, "az_disk_list"),
        "synapse_workspaces": dataset_paths(catalog, "az_synapse_workspace_list"),
        "bastion_hosts": dataset_paths(catalog, "az_network_bastion_list"),
        "flow_logs": dataset_paths(catalog, "az_network_watcher_flow-log_list"),
        "public_ip_addresses": dataset_paths(catalog, "az_network_public-ip_list"),
        "vm_details": dataset_paths(catalog, "az_vm_show"),
        "vm_extensions": dataset_paths(catalog, "az_vm_extension_list"),
        "vm_scale_sets": dataset_paths(catalog, "az_vmss_list"),
        "nsgs": dataset_paths(catalog, "az_network_nsg_list"),
        "graph_conditional_access_policies": dataset_paths(catalog, "graph.microsoft.com", "conditionalaccess", "policies"),
        "graph_directory_roles": dataset_paths(catalog, "graph.microsoft.com", "directoryroles"),
        "graph_directory_role_assignments": dataset_paths(catalog, "graph.microsoft.com", "rolemanagement", "roleassignments"),
        "graph_group_settings": dataset_paths(catalog, "graph.microsoft.com", "groupsettings"),
        "graph_named_locations": dataset_paths(catalog, "graph.microsoft.com", "namedlocations"),
        "graph_authorization_policy": dataset_paths(catalog, "graph.microsoft.com", "authorizationpolicy"),
        "graph_security_defaults_policy": dataset_paths(catalog, "graph.microsoft.com", "identitysecuritydefaultsenforcementpolicy"),
        "graph_user_registration_details": dataset_paths(catalog, "graph.microsoft.com", "userregistrationdetails"),
    }

    findings = []

    findings.append(
        find_public_blob_access(storage_accounts)
        if storage_accounts
        else unsupported(
            "Azure blob container permits public access",
            "High",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_custom_subscription_owner_roles(role_definitions, role_assignments)
        if role_definitions and role_assignments
        else unsupported(
            "Custom Azure subscription owner roles permitted",
            "Medium",
            "Role definitions and enriched role assignments are required.",
        )
    )
    findings.append(
        find_guest_users_present(ad_users, graph_user_registration_details)
        if ad_users
        else unsupported(
            "Unauthenticated Guest Users Present in Azure AD",
            "Medium",
            "Azure AD user inventory is required.",
        )
    )
    findings.append(
        find_storage_keys_not_rotated(
            storage_accounts,
            storage_keys,
            latest_dataset_timestamp(source_map["storage_keys"] or source_map["storage_accounts"]),
            title="Stale Azure access keys present",
        )
        if storage_accounts
        else unsupported(
            "Stale Azure access keys present",
            "Medium",
            "Storage account dataset is required.",
        )
    )
    findings.append(
        find_unencrypted_transfer(storage_accounts)
        if storage_accounts
        else unsupported(
            "Azure Storage accounts do not enforce encrypted data transfer",
            "Medium",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_entra_users_can_create_security_groups(graph_authorization_policy)
        if graph_authorization_policy
        else unsupported(
            "Azure policy permits users to create security groups",
            "Medium",
            "Microsoft Graph authorization policy data is required.",
        )
    )
    findings.append(
        find_storage_deprecated_tls(storage_accounts)
        if storage_accounts
        else unsupported(
            "Azure Storage Accounts permitting deprecated TLS versions",
            "Medium",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_storage_default_network_access(storage_accounts)
        if storage_accounts
        else unsupported(
            "Storage accounts with default network access permitted",
            "Medium",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_resource_diagnostic_settings_missing(resources, diagnostic_settings)
        if resources and dataset_present(catalog, "az_monitor_diagnostic-settings_list")
        else unsupported(
            "Diagnostic Settings Not Configured",
            "Low",
            "Azure resource inventory and resource-scoped diagnostic settings are required.",
        )
    )
    findings.append(
        find_postgres_azure_services_access(postgres_firewall_rules)
        if postgres_firewall_rules
        else unsupported(
            "Access permitted to PostgreSQL server from Azure services",
            "Medium",
            "No PostgreSQL firewall rule dataset was found.",
        )
    )
    findings.append(
        find_key_vault_unrestricted_access(key_vaults, key_vault_network_rules)
        if key_vaults and dataset_present(catalog, "az_keyvault_network-rule_list")
        else unsupported(
            "Access to Azure Key Vault not restricted to trusted source addresses",
            "Low",
            "Key Vault list and network-rule datasets are required.",
        )
    )
    findings.append(
        find_keyvault_public_network_enabled(key_vaults)
        if key_vaults
        else unsupported(
            "Key Vault Allows Public Network Access",
            "Low",
            "No Key Vault dataset was found.",
        )
    )
    findings.append(
        find_monitor_alert_notification_gaps(metric_alerts)
        if metric_alerts
        else unsupported(
            "Azure Monitor Alerts not configured to notify high severity events",
            "Low",
            "No metric alert dataset was found.",
        )
    )
    findings.append(
        find_storage_without_private_endpoints(storage_accounts)
        if storage_accounts
        else unsupported(
            "Storage Accounts not using private IP endpoints",
            "Low",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_storage_soft_delete_disabled(storage_blob_service_properties)
        if storage_blob_service_properties
        else unsupported(
            "Azure Storage Containers without Soft Delete protection",
            "Low",
            "No storage blob service properties dataset was found.",
        )
    )
    findings.append(
        find_activity_log_alert_gaps(activity_log_alerts)
        if activity_log_alerts
        else unsupported(
            "Azure Activity Log Alerts missing for key event types",
            "Low",
            "No activity log alert dataset was found.",
        )
    )
    findings.append(
        find_defender_not_enabled(defender_settings)
        if defender_settings
        else unsupported(
            "Microsoft Defender for Cloud is not enabled",
            "Low",
            "No Defender pricing dataset was found.",
        )
    )
    findings.append(
        find_key_vault_rbac_disabled(key_vaults)
        if key_vaults
        else unsupported(
            "Role-Based Access Control (RBAC) not enabled for Azure Key Vault",
            "Low",
            "No Key Vault dataset was found.",
        )
    )
    findings.append(
        find_security_contact_phone_missing(security_contacts)
        if security_contacts
        else unsupported(
            "Security contact phone number is not set in Azure tenant",
            "Low",
            "No security contact dataset was found.",
        )
    )
    findings.append(
        find_security_contacts_missing(security_contacts)
        if dataset_present(catalog, "az_security_contact_list")
        else unsupported(
            "Security Contacts Not Configured",
            "Low",
            "No security contact dataset was found.",
        )
    )
    findings.append(
        find_security_contact_email_missing(security_contacts)
        if dataset_present(catalog, "az_security_contact_list")
        else unsupported(
            "Security Contact Email Address Not Configured",
            "Low",
            "No security contact dataset was found.",
        )
    )
    findings.append(
        find_appservice_http_logs_disabled(web_app_logs)
        if web_app_logs
        else unsupported(
            "Azure AppService HTTP logs not enabled enabled",
            "Low",
            "No App Service log configuration dataset was found.",
        )
    )
    findings.append(
        find_network_watcher_gaps(locations, resources, network_watchers)
        if network_watchers and (resources or locations)
        else unsupported(
            "Azure Network Watcher not enabled for all subscription locations",
            "Low",
            "Network watcher data plus either resource or location data is required.",
        )
    )
    findings.append(
        find_key_vault_not_recoverable(key_vaults)
        if key_vaults
        else unsupported(
            "Azure Key Vault not recoverable",
            "Low",
            "No Key Vault dataset was found.",
        )
    )
    findings.append(
        find_keyvault_recovery_protection_disabled(key_vaults)
        if key_vaults
        else unsupported(
            "Key Vault Recovery Protection Not Enabled",
            "Low",
            "No Key Vault dataset was found.",
        )
    )
    findings.append(
        find_diagnostic_category_gaps(diagnostic_settings, diagnostic_categories)
        if diagnostic_settings and diagnostic_categories
        else unsupported(
            "Ensure Diagnostic Setting captures appropriate categories",
            "Low",
            "Diagnostic settings and diagnostic category datasets are required.",
        )
    )
    findings.append(
        find_resource_lock_admin_role_gap(role_definitions, role_assignments)
        if role_definitions and role_assignments
        else unsupported(
            "Users with Permission to Administer Resource Locks Assigned",
            "Low",
            "Role definitions and role assignments are required.",
        )
    )
    findings.append(
        find_app_service_deprecated_http(web_app_configs)
        if web_app_configs
        else unsupported(
            "Azure App Services using deprecated HTTP Version",
            "Low",
            "No Web App configuration dataset was found.",
        )
    )
    findings.append(
        find_storage_microsoft_managed_keys(storage_accounts)
        if storage_accounts
        else unsupported(
            "Data at rest in Azure storage accounts use Microsoft managed encryption keys",
            "Low",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_subscription_activity_logs_without_diagnostics(subscriptions, subscription_diagnostic_settings)
        if subscriptions
        else unsupported(
            "Azure Subscription-level activity logs without a 'Diagnostic Setting' exist",
            "Low",
            "No subscription dataset was found.",
        )
    )
    findings.append(
        find_storage_no_infra_encryption(storage_accounts)
        if storage_accounts
        else unsupported(
            "Azure Storage Accounts without infrastructure encryption enabled",
            "Low",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_acr_admin_user_enabled(container_registries)
        if container_registries
        else unsupported(
            "Azure Container Registry admin user enabled",
            "Low",
            "No container registry dataset was found.",
        )
    )
    findings.append(
        find_aks_rbac_disabled(aks_clusters)
        if aks_clusters
        else unsupported(
            "AKS clusters without RBAC enabled",
            "Low",
            "No AKS dataset was found.",
        )
    )
    findings.append(
        find_aks_local_accounts_enabled(aks_clusters)
        if aks_clusters
        else unsupported(
            "AKS clusters with local accounts enabled",
            "Low",
            "No AKS dataset was found.",
        )
    )
    findings.append(
        find_aks_no_authorized_ip_ranges(aks_clusters)
        if aks_clusters
        else unsupported(
            "AKS clusters without authorized API server IP ranges",
            "Low",
            "No AKS dataset was found.",
        )
    )
    findings.append(
        find_aks_not_private(aks_clusters)
        if aks_clusters
        else unsupported(
            "AKS clusters not using a private control plane",
            "Low",
            "No AKS dataset was found.",
        )
    )
    findings.append(
        find_nsg_open_admin_ports(nsgs)
        if nsgs
        else unsupported(
            "Network security groups expose administrative ports to the Internet",
            "Medium",
            "No NSG dataset was found.",
        )
    )
    findings.append(
        find_nsg_open_data_ports(nsgs)
        if nsgs
        else unsupported(
            "Network security groups expose common data ports to the Internet",
            "Medium",
            "No NSG dataset was found.",
        )
    )
    findings.append(
        find_nsg_open_all_ports(nsgs)
        if nsgs
        else unsupported(
            "NSG Inbound Rule Allows Internet Access to All Ports",
            "High",
            "No NSG dataset was found.",
        )
    )
    findings.append(
        find_nsg_open_mssql(nsgs)
        if nsgs
        else unsupported(
            "NSG Inbound Rule Allows Internet Access to MSSQL Service",
            "Medium",
            "No NSG dataset was found.",
        )
    )
    findings.append(
        find_nsg_open_udp(nsgs)
        if nsgs
        else unsupported(
            "NSG Inbound Rule Allows Internet Access to UDP Services",
            "Medium",
            "No NSG dataset was found.",
        )
    )
    findings.append(
        find_nsg_open_exposed_services(nsgs)
        if nsgs
        else unsupported(
            "NSG Inbound Rule Allows Internet Access to Exposed Services",
            "Medium",
            "No NSG dataset was found.",
        )
    )
    findings.append(
        find_appservice_https_disabled(web_apps)
        if web_apps
        else unsupported(
            "Azure App Services do not enforce HTTPS",
            "Medium",
            "No Web App dataset was found.",
        )
    )
    findings.append(
        find_appservice_ftps_not_strict(web_apps)
        if web_apps
        else unsupported(
            "Azure App Services do not enforce FTPS-only",
            "Low",
            "No Web App dataset was found.",
        )
    )
    findings.append(
        find_appservice_remote_debugging_enabled(web_apps)
        if web_apps
        else unsupported(
            "Azure App Services have remote debugging enabled",
            "Low",
            "No Web App dataset was found.",
        )
    )
    findings.append(
        find_appservice_permissive_cors(web_apps)
        if web_apps
        else unsupported(
            "Azure App Services allow wildcard CORS origins",
            "Low",
            "No Web App dataset was found.",
        )
    )
    findings.append(
        find_appservice_access_restrictions_missing(web_app_access_restrictions)
        if web_app_access_restrictions
        else unsupported(
            "Azure App Services have no access restrictions configured",
            "Low",
            "No Web App access restriction dataset was found.",
        )
    )
    findings.append(
        find_appservice_scm_restrictions_missing(web_app_access_restrictions)
        if web_app_access_restrictions
        else unsupported(
            "Azure App Services have unrestricted SCM endpoints",
            "Low",
            "No Web App access restriction dataset was found.",
        )
    )
    findings.append(
        find_appservice_client_cert_disabled(web_apps)
        if web_apps
        else unsupported(
            "Azure App Services do not require client certificates",
            "Low",
            "No Web App dataset was found.",
        )
    )
    findings.append(
        find_appservice_auth_not_configured(web_app_auth_settings)
        if web_app_auth_settings
        else unsupported(
            "Azure App Services do not have authentication configured",
            "Low",
            "No Web App auth settings dataset was found.",
        )
    )
    findings.append(
        find_webapp_missing_app_insights(web_apps, web_app_appsettings)
        if web_apps and web_app_appsettings
        else unsupported(
            "Azure App Services are missing Application Insights configuration",
            "Low",
            "Web App and app settings datasets are required.",
        )
    )
    findings.append(
        find_appservice_tls_below_12(web_app_configs)
        if web_app_configs
        else unsupported(
            "Azure App Services permit TLS versions below 1.2",
            "Low",
            "No Web App configuration dataset was found.",
        )
    )
    findings.append(
        find_appservice_ftp_not_disabled(web_apps)
        if web_apps
        else unsupported(
            "Azure App Services do not disable FTP deployment",
            "Low",
            "No Web App dataset was found.",
        )
    )
    findings.append(
        find_appservice_missing_identity(web_apps)
        if web_apps
        else unsupported(
            "Azure App Services are not registered with a managed identity",
            "Low",
            "No Web App dataset was found.",
        )
    )
    findings.append(
        find_appservice_outdated_runtime(web_app_configs, "dotnet", (8, 0), "App Service Running Outdated .NET Version")
        if web_app_configs
        else unsupported(
            "App Service Running Outdated .NET Version",
            "Low",
            "No Web App configuration dataset was found.",
        )
    )
    findings.append(
        find_appservice_outdated_runtime(web_app_configs, "java", (17, 0), "App Service Running Outdated Java Version")
        if web_app_configs
        else unsupported(
            "App Service Running Outdated Java Version",
            "Low",
            "No Web App configuration dataset was found.",
        )
    )
    findings.append(
        find_appservice_outdated_runtime(web_app_configs, "php", (8, 1), "App Service Running Outdated PHP Version")
        if web_app_configs
        else unsupported(
            "App Service Running Outdated PHP Version",
            "Low",
            "No Web App configuration dataset was found.",
        )
    )
    findings.append(
        find_appservice_outdated_runtime(web_app_configs, "python", (3, 10), "App Service Running Outdated Python Version")
        if web_app_configs
        else unsupported(
            "App Service Running Outdated Python Version",
            "Low",
            "No Web App configuration dataset was found.",
        )
    )
    findings.append(
        find_appservice_outdated_programming_language(web_app_configs)
        if web_app_configs
        else unsupported(
            "App Service Running Outdated Programming Language Version",
            "Low",
            "No Web App configuration dataset was found.",
        )
    )
    findings.append(
        find_app_service_environment_missing(app_service_environments)
        if dataset_present(catalog, "az_appservice_ase_show")
        else unsupported(
            "App Service Environment vNet injection not deployed",
            "Low",
            "No App Service Environment dataset was found.",
        )
    )
    findings.append(
        find_functionapp_missing_app_insights(function_apps, function_app_appsettings)
        if function_apps and dataset_present(catalog, "az_functionapp_config_appsettings_list")
        else unsupported(
            "Function Apps are missing Application Insights configuration",
            "Low",
            "Function App and app settings datasets are required.",
        )
    )
    findings.append(
        find_functionapp_ftp_not_disabled(function_apps)
        if function_apps
        else unsupported(
            "Function Apps do not disable FTP deployment",
            "Low",
            "No Function App dataset was found.",
        )
    )
    findings.append(
        find_functionapp_missing_identity(function_apps, function_app_identities)
        if function_apps and dataset_present(catalog, "az_functionapp_identity_show")
        else unsupported(
            "Function Apps do not have a managed identity configured",
            "Low",
            "Function App and identity datasets are required.",
        )
    )
    findings.append(
        find_functionapp_publicly_accessible(function_apps, function_app_access_restrictions)
        if function_apps and dataset_present(catalog, "az_functionapp_config_access-restriction_show")
        else unsupported(
            "Function Apps are publicly reachable",
            "Low",
            "Function App and access restriction datasets are required.",
        )
    )
    findings.append(
        find_functionapp_missing_vnet_integration(function_apps, function_app_vnet_integrations)
        if function_apps and dataset_present(catalog, "az_functionapp_vnet-integration_list")
        else unsupported(
            "Function Apps are not integrated with a virtual network",
            "Low",
            "Function App and VNet integration datasets are required.",
        )
    )
    findings.append(
        find_functionapp_missing_access_keys(function_apps, function_app_keys)
        if function_apps and function_app_keys
        else unsupported(
            "Function Apps do not have access keys configured",
            "Low",
            "Function App and host keys datasets are required.",
        )
    )
    findings.append(
        find_functionapp_identity_with_admin_privileges(function_apps, function_app_identities, role_assignments)
        if function_apps and function_app_identities and role_assignments
        else unsupported(
            "Function Apps have managed identities with administrative privileges",
            "Medium",
            "Function App, identity, and role assignment datasets are required.",
        )
    )
    findings.append(
        find_functionapp_outdated_runtime(function_app_configs, function_app_appsettings)
        if function_app_configs
        else unsupported(
            "Function Apps are not using the latest Functions runtime major version",
            "Low",
            "Function App config dataset is required.",
        )
    )
    findings.append(
        find_acr_public_network_enabled(container_registries)
        if container_registries
        else unsupported(
            "Azure Container Registries allow public network access",
            "Low",
            "No container registry dataset was found.",
        )
    )
    findings.append(
        find_acr_without_private_link(container_registries, acr_private_endpoint_connections)
        if container_registries and dataset_present(catalog, "microsoft.containerregistry", "private-endpoint-connection")
        else unsupported(
            "Azure Container Registries do not use private link",
            "Low",
            "Container Registry and private endpoint connection datasets are required.",
        )
    )
    findings.append(
        find_cosmosdb_unrestricted_network(cosmosdb_accounts)
        if cosmosdb_accounts
        else unsupported(
            "Cosmos DB accounts do not restrict network access",
            "Low",
            "No Cosmos DB dataset was found.",
        )
    )
    findings.append(
        find_cosmosdb_without_private_endpoints(cosmosdb_accounts)
        if cosmosdb_accounts
        else unsupported(
            "Cosmos DB accounts do not use private endpoints",
            "Low",
            "No Cosmos DB dataset was found.",
        )
    )
    findings.append(
        find_cosmosdb_without_aad_rbac(cosmosdb_accounts, cosmosdb_sql_role_assignments)
        if cosmosdb_accounts and cosmosdb_sql_role_assignments
        else unsupported(
            "Cosmos DB accounts do not use Microsoft Entra ID and RBAC",
            "Low",
            "Cosmos DB and SQL role assignment datasets are required.",
        )
    )
    findings.append(
        find_cognitive_services_local_auth_enabled(cognitive_services_accounts)
        if cognitive_services_accounts
        else unsupported(
            "Cognitive Services accounts permit local authentication",
            "Low",
            "No Cognitive Services dataset was found.",
        )
    )
    findings.append(
        find_databricks_without_cmk(databricks_workspaces)
        if databricks_workspaces
        else unsupported(
            "Databricks workspaces do not enable customer-managed key encryption",
            "Low",
            "No Databricks workspace details dataset was found.",
        )
    )
    findings.append(
        find_databricks_without_vnet_injection(databricks_workspaces)
        if databricks_workspaces
        else unsupported(
            "Databricks workspaces do not use VNet injection",
            "Low",
            "No Databricks workspace details dataset was found.",
        )
    )
    findings.append(
        find_eventgrid_topics_public_network_enabled(eventgrid_topics)
        if eventgrid_topics
        else unsupported(
            "Event Grid Topics allow public network access",
            "Low",
            "No Event Grid Topic dataset was found.",
        )
    )
    findings.append(
        find_eventgrid_domains_public_network_enabled(eventgrid_domains)
        if eventgrid_domains
        else unsupported(
            "Event Grid Domains allow public network access",
            "Low",
            "No Event Grid Domain dataset was found.",
        )
    )
    findings.append(
        find_iot_dps_public_network_enabled(iot_dps_instances)
        if iot_dps_instances
        else unsupported(
            "IoT Device Provisioning Services allow public network access",
            "Low",
            "No IoT DPS dataset was found.",
        )
    )
    findings.append(
        find_defender_auto_provisioning_disabled(defender_auto_provisioning_settings)
        if defender_auto_provisioning_settings
        else unsupported(
            "Defender auto provisioning for Log Analytics agents is not enabled",
            "Low",
            "No Defender auto-provisioning settings dataset was found.",
        )
    )
    findings.append(
        find_defender_auto_provisioning_vulnerability_assessment_disabled(defender_auto_provisioning_settings)
        if defender_auto_provisioning_settings
        else unsupported(
            "Defender auto provisioning for vulnerability assessments is not enabled on machines",
            "Low",
            "No Defender auto-provisioning settings dataset was found.",
        )
    )
    findings.append(
        find_assessment_failures(
            defender_assessments,
            "Defender endpoint protection is not installed on virtual machines",
            "Checks Defender assessment recommendations for missing endpoint protection on VM resources.",
            any_keywords=("endpoint protection",),
            resource_type_fragment="microsoft.compute/virtualmachines",
        )
        if defender_assessments
        else unsupported(
            "Defender endpoint protection is not installed on virtual machines",
            "Low",
            "No Defender assessment dataset was found.",
        )
    )
    findings.append(
        find_assessment_failures(
            defender_assessments,
            "Defender assessments report unresolved container image vulnerabilities",
            "Checks Defender assessment recommendations for unresolved container registry or image vulnerabilities.",
            any_keywords=("container image", "container registry"),
        )
        if defender_assessments
        else unsupported(
            "Defender assessments report unresolved container image vulnerabilities",
            "Low",
            "No Defender assessment dataset was found.",
        )
    )
    findings.append(
        find_assessment_failures(
            defender_assessments,
            "Container image vulnerability scanning is not enabled",
            "Checks Defender assessment recommendations for missing container image vulnerability scanning coverage.",
            any_keywords=("vulnerability scanning", "vulnerability assessment"),
        )
        if defender_assessments
        else unsupported(
            "Container image vulnerability scanning is not enabled",
            "Low",
            "No Defender assessment dataset was found.",
        )
    )
    findings.append(
        find_assessment_failures(
            defender_assessments,
            "System updates are not fully applied on machines",
            "Checks Defender assessment recommendations for missing operating-system security updates.",
            any_keywords=("system updates", "security updates"),
        )
        if defender_assessments
        else unsupported(
            "System updates are not fully applied on machines",
            "Low",
            "No Defender assessment dataset was found.",
        )
    )
    findings.append(
        find_assessment_failures(
            defender_assessments,
            "API Management services are missing LLM jacking threat-detection coverage",
            "Checks Defender assessment recommendations for API Management resources referencing LLM jacking or prompt-injection protections.",
            any_keywords=("llm", "jacking", "prompt injection"),
            resource_type_fragment="microsoft.apimanagement/service",
        )
        if defender_assessments
        else unsupported(
            "API Management services are missing LLM jacking threat-detection coverage",
            "Low",
            "No Defender assessment dataset was found.",
        )
    )
    findings.append(
        find_security_contacts_not_notifying_owners(security_contacts)
        if security_contacts
        else unsupported(
            "Microsoft Defender security contacts do not notify subscription owners",
            "Low",
            "No security contact dataset was found.",
        )
    )
    findings.append(
        find_security_contact_alert_notifications_disabled(security_contacts)
        if dataset_present(catalog, "az_security_contact_list")
        else unsupported(
            "Security Contact Email Notifications Not Enabled",
            "Low",
            "No security contact dataset was found.",
        )
    )
    findings.append(
        find_security_contact_admin_notifications_disabled(security_contacts)
        if dataset_present(catalog, "az_security_contact_list")
        else unsupported(
            "Security Contact Admin Email Notifications Not Enabled",
            "Low",
            "No security contact dataset was found.",
        )
    )
    findings.append(
        find_defender_setting_disabled(defender_general_settings, "mcas", "Microsoft Cloud App Security Integration Not Enabled")
        if dataset_present(catalog, "az_security_setting_list")
        else unsupported(
            "Microsoft Cloud App Security Integration Not Enabled",
            "Low",
            "No Defender general settings dataset was found.",
        )
    )
    findings.append(
        find_defender_setting_disabled(defender_general_settings, "wdatp", "Microsoft Defender ATP Integration Not Enabled")
        if dataset_present(catalog, "az_security_setting_list")
        else unsupported(
            "Microsoft Defender ATP Integration Not Enabled",
            "Low",
            "No Defender general settings dataset was found.",
        )
    )
    findings.append(
        find_entra_conditional_access_mfa_for_admin_portals(graph_conditional_access_policies)
        if dataset_present(catalog, "graph.microsoft.com", "conditionalaccess", "policies")
        else unsupported(
            "Conditional Access does not require MFA for admin portals",
            "Medium",
            "No Graph Conditional Access policy dataset was found.",
        )
    )
    findings.append(
        find_entra_conditional_access_mfa_for_management_api(graph_conditional_access_policies)
        if dataset_present(catalog, "graph.microsoft.com", "conditionalaccess", "policies")
        else unsupported(
            "Conditional Access does not require MFA for the Azure management API",
            "Medium",
            "No Graph Conditional Access policy dataset was found.",
        )
    )
    findings.append(
        find_entra_global_admin_over_assignment(graph_directory_roles, graph_directory_role_assignments)
        if graph_directory_roles and graph_directory_role_assignments
        else unsupported(
            "Global Administrator role is assigned to five or more users",
            "Medium",
            "Graph directory role and role assignment datasets are required.",
        )
    )
    findings.append(
        find_entra_users_without_mfa(ad_users, graph_user_registration_details, graph_directory_roles, graph_directory_role_assignments, privileged=False)
        if ad_users and graph_user_registration_details and graph_directory_roles and graph_directory_role_assignments
        else unsupported(
            "Non-privileged Microsoft Entra users do not have MFA",
            "Medium",
            "Azure AD users, Graph registration details, and directory role datasets are required.",
        )
    )
    findings.append(
        find_entra_users_without_mfa(ad_users, graph_user_registration_details, graph_directory_roles, graph_directory_role_assignments, privileged=True)
        if ad_users and graph_user_registration_details and graph_directory_roles and graph_directory_role_assignments
        else unsupported(
            "Privileged Microsoft Entra users do not have MFA",
            "Medium",
            "Azure AD users, Graph registration details, and directory role datasets are required.",
        )
    )
    findings.append(
        find_entra_user_consent_policy(graph_authorization_policy, require_verified_apps=False)
        if dataset_present(catalog, "graph.microsoft.com", "authorizationpolicy")
        else unsupported(
            "User consent for applications is not sufficiently restricted",
            "Low",
            "No Graph authorization policy dataset was found.",
        )
    )
    findings.append(
        find_entra_user_consent_policy(graph_authorization_policy, require_verified_apps=True)
        if dataset_present(catalog, "graph.microsoft.com", "authorizationpolicy")
        else unsupported(
            "User consent for verified applications is not enforced",
            "Low",
            "No Graph authorization policy dataset was found.",
        )
    )
    findings.append(
        find_entra_vm_access_users_without_mfa(ad_users, graph_user_registration_details, role_assignments)
        if ad_users and graph_user_registration_details and role_assignments
        else unsupported(
            "Users with VM access do not have MFA",
            "Medium",
            "Azure AD users, Graph registration details, and Azure role assignments are required.",
        )
    )
    findings.append(
        find_entra_m365_group_creation_enabled(graph_group_settings)
        if dataset_present(catalog, "graph.microsoft.com", "groupsettings")
        else unsupported(
            "Users can create Microsoft 365 groups",
            "Low",
            "No Graph group settings dataset was found.",
        )
    )
    findings.append(
        find_hdinsight_kafka_manual_auth_enabled(hdinsight_clusters)
        if dataset_present(catalog, "az_hdinsight_show")
        else unsupported(
            "HDInsight Kafka clusters do not disable manual authentication",
            "Low",
            "No HDInsight details dataset was found.",
        )
    )
    findings.append(
        find_user_access_admin_assigned_to_users(role_assignments)
        if role_assignments
        else unsupported(
            "User Access Administrator role is assigned directly to users",
            "Medium",
            "No Azure role assignment dataset was found.",
        )
    )
    findings.append(
        find_keyvault_expiry_missing(key_vaults, key_vault_keys, "Non-RBAC Key Vault keys do not have expiration dates", "key", require_rbac=False)
        if key_vaults and key_vault_keys
        else unsupported(
            "Non-RBAC Key Vault keys do not have expiration dates",
            "Low",
            "Key Vault and key metadata datasets are required.",
        )
    )
    findings.append(
        find_keyvault_key_rotation_disabled(key_vaults, key_vault_keys, key_vault_key_rotation_policies)
        if key_vaults and key_vault_keys and dataset_present(catalog, "az_keyvault_key_rotation-policy_show")
        else unsupported(
            "Key Vault keys do not have rotation enabled",
            "Low",
            "Key Vault, key, and key rotation-policy datasets are required.",
        )
    )
    findings.append(
        find_keyvault_keys_older_than_365_days(
            key_vaults,
            key_vault_keys,
            latest_dataset_timestamp(source_map["key_vault_keys"]),
        )
        if key_vaults and key_vault_keys
        else unsupported(
            "Key Vault keys are older than 365 days",
            "Low",
            "Key Vault and key metadata datasets are required.",
        )
    )
    findings.append(
        find_keyvault_expiry_missing(key_vaults, key_vault_secrets, "Non-RBAC Key Vault secrets do not have expiration dates", "secret", require_rbac=False)
        if key_vaults and key_vault_secrets
        else unsupported(
            "Non-RBAC Key Vault secrets do not have expiration dates",
            "Low",
            "Key Vault and secret metadata datasets are required.",
        )
    )
    findings.append(
        find_keyvault_expiry_missing(key_vaults, key_vault_keys, "RBAC Key Vault keys do not have expiration dates", "key", require_rbac=True)
        if key_vaults and key_vault_keys
        else unsupported(
            "RBAC Key Vault keys do not have expiration dates",
            "Low",
            "Key Vault and key metadata datasets are required.",
        )
    )
    findings.append(
        find_keyvault_expiry_missing(key_vaults, key_vault_secrets, "RBAC Key Vault secrets do not have expiration dates", "secret", require_rbac=True)
        if key_vaults and key_vault_secrets
        else unsupported(
            "RBAC Key Vault secrets do not have expiration dates",
            "Low",
            "Key Vault and secret metadata datasets are required.",
        )
    )
    findings.append(
        find_keyvault_expiry_missing(key_vaults, key_vault_secrets, "Key Vault secrets do not have expiration dates", "secret")
        if key_vaults and key_vault_secrets
        else unsupported(
            "Key Vault secrets do not have expiration dates",
            "Low",
            "Key Vault and secret metadata datasets are required.",
        )
    )
    findings.append(
        find_entra_security_defaults_disabled(graph_security_defaults_policy)
        if dataset_present(catalog, "graph.microsoft.com", "identitysecuritydefaultsenforcementpolicy")
        else unsupported(
            "Microsoft Entra security defaults are not enabled",
            "Low",
            "No Graph security defaults policy dataset was found.",
        )
    )
    findings.append(
        find_entra_named_locations_missing(graph_named_locations)
        if dataset_present(catalog, "graph.microsoft.com", "namedlocations")
        else unsupported(
            "Microsoft Entra trusted named locations are not configured",
            "Low",
            "No Graph named locations dataset was found.",
        )
    )
    findings.append(
        find_entra_users_can_create_apps(graph_authorization_policy)
        if dataset_present(catalog, "graph.microsoft.com", "authorizationpolicy")
        else unsupported(
            "Microsoft Entra default users can create applications",
            "Low",
            "No Graph authorization policy dataset was found.",
        )
    )
    findings.append(
        find_entra_users_can_create_tenants(graph_authorization_policy)
        if dataset_present(catalog, "graph.microsoft.com", "authorizationpolicy")
        else unsupported(
            "Microsoft Entra default users can create tenants",
            "Low",
            "No Graph authorization policy dataset was found.",
        )
    )
    findings.append(
        find_entra_guest_invites_not_admin_only(graph_authorization_policy)
        if dataset_present(catalog, "graph.microsoft.com", "authorizationpolicy")
        else unsupported(
            "Microsoft Entra guest invites are not restricted to admins",
            "Low",
            "No Graph authorization policy dataset was found.",
        )
    )
    findings.append(
        find_entra_guest_access_not_restricted(graph_authorization_policy)
        if dataset_present(catalog, "graph.microsoft.com", "authorizationpolicy")
        else unsupported(
            "Microsoft Entra guest user access restrictions are not configured",
            "Low",
            "No Graph authorization policy dataset was found.",
        )
    )
    findings.append(
        find_key_vault_without_private_endpoints(key_vaults, key_vault_private_endpoint_connections)
        if key_vaults and dataset_present(catalog, "az_keyvault_show", "privateendpointconnections")
        else unsupported(
            "Azure Key Vaults do not use private endpoints",
            "Low",
            "Key Vault list and private endpoint connection datasets are required.",
        )
    )
    findings.append(
        find_key_vault_logging_disabled(key_vaults, diagnostic_settings)
        if key_vaults and diagnostic_settings
        else unsupported(
            "Azure Key Vaults do not have diagnostic logging enabled",
            "Low",
            "Key Vault and diagnostic setting datasets are required.",
        )
    )
    findings.append(
        find_aks_azure_policy_disabled(aks_clusters)
        if aks_clusters
        else unsupported(
            "AKS clusters do not have Azure Policy enabled",
            "Low",
            "No AKS dataset was found.",
        )
    )
    findings.append(
        find_aks_network_policy_disabled(aks_clusters)
        if aks_clusters
        else unsupported(
            "AKS clusters do not have a network policy configured",
            "Low",
            "No AKS dataset was found.",
        )
    )
    findings.append(
        find_aks_public_nodes_enabled(aks_clusters)
        if aks_clusters
        else unsupported(
            "AKS clusters use public node IPs",
            "Low",
            "No AKS dataset was found.",
        )
    )
    findings.append(
        find_ml_workspace_public_network_enabled(machine_learning_workspaces)
        if machine_learning_workspaces
        else unsupported(
            "Machine Learning workspaces allow public network access",
            "Low",
            "No Machine Learning workspace dataset was found.",
        )
    )
    findings.append(
        find_ml_workspace_without_vnet(machine_learning_workspaces)
        if machine_learning_workspaces
        else unsupported(
            "Machine Learning workspaces do not use virtual network integration",
            "Low",
            "No Machine Learning workspace dataset was found.",
        )
    )
    findings.append(
        find_monitor_service_health_alert_missing(activity_log_alerts)
        if activity_log_alerts
        else unsupported(
            "Azure Activity Log Alerts missing for service health events",
            "Low",
            "No activity log alert dataset was found.",
        )
    )
    findings.append(
        find_activity_log_alert_security_solution_gaps(activity_log_alerts)
        if activity_log_alerts
        else unsupported(
            "Azure Activity Log Alerts missing for security solution changes",
            "Low",
            "No activity log alert dataset was found.",
        )
    )
    findings.append(
        find_activity_log_profile_incomplete(log_profiles)
        if dataset_present(catalog, "az_monitor_log-profiles_list")
        else unsupported(
            "Activity Log Profile Does Not Capture All Events",
            "Low",
            "No Azure Monitor log profile dataset was found.",
        )
    )
    findings.append(
        find_monitor_storage_targets_not_cmk(subscriptions, subscription_diagnostic_settings, storage_accounts)
        if subscription_diagnostic_settings and storage_accounts
        else unsupported(
            "Subscription activity logs are stored in accounts without customer-managed keys",
            "Low",
            "Subscription diagnostic settings and storage account datasets are required.",
        )
    )
    findings.append(
        find_monitor_storage_targets_not_private(subscription_diagnostic_settings, storage_accounts)
        if subscription_diagnostic_settings and storage_accounts
        else unsupported(
            "Subscription activity logs are stored in accounts without private endpoints",
            "Low",
            "Subscription diagnostic settings and storage account datasets are required.",
        )
    )
    findings.append(
        find_mysql_audit_logging_disabled(mysql_servers, mysql_parameters)
        if mysql_servers and mysql_parameters
        else unsupported(
            "MySQL flexible servers do not have audit logging enabled",
            "Low",
            "MySQL server and parameter datasets are required.",
        )
    )
    findings.append(
        find_mysql_audit_log_connection_disabled(mysql_servers, mysql_parameters)
        if mysql_servers and mysql_parameters
        else unsupported(
            "MySQL flexible servers do not audit connection events",
            "Low",
            "MySQL server and parameter datasets are required.",
        )
    )
    findings.append(
        find_mysql_geo_backup_disabled(mysql_servers)
        if mysql_servers
        else unsupported(
            "MySQL flexible servers do not enable geo-redundant backup",
            "Low",
            "No MySQL server dataset was found.",
        )
    )
    findings.append(
        find_mysql_tls_below_12(mysql_servers, mysql_parameters)
        if mysql_servers and mysql_parameters
        else unsupported(
            "MySQL flexible servers permit TLS versions below 1.2",
            "Low",
            "MySQL server and parameter datasets are required.",
        )
    )
    findings.append(
        find_server_data_encryption_gap(mysql_servers, "MySQL flexible servers do not enable infrastructure double encryption")
        if mysql_servers
        else unsupported(
            "MySQL flexible servers do not enable infrastructure double encryption",
            "Low",
            "No MySQL server dataset was found.",
        )
    )
    findings.append(
        find_server_private_access_disabled(mysql_servers, "MySQL flexible servers do not use private access")
        if mysql_servers
        else unsupported(
            "MySQL flexible servers do not use private access",
            "Low",
            "No MySQL server dataset was found.",
        )
    )
    findings.append(
        find_defender_pricing_gap(
            defender_settings,
            ("opensource", "relational"),
            "MySQL flexible servers do not have Defender threat detection enabled",
            "Uses Microsoft Defender pricing coverage for open-source relational databases as the tenant-level signal for MySQL threat-detection protection.",
        )
        if defender_settings and mysql_servers
        else unsupported(
            "MySQL flexible servers do not have Defender threat detection enabled",
            "Low",
            "Defender pricing and MySQL server datasets are required.",
        )
    )
    findings.append(
        find_mysql_ssl_disabled(mysql_servers, mysql_parameters)
        if mysql_servers and mysql_parameters
        else unsupported(
            "MySQL flexible servers do not enforce SSL connections",
            "Low",
            "MySQL server and parameter datasets are required.",
        )
    )
    findings.append(
        find_postgres_ssl_disabled(postgres_servers, postgres_parameters)
        if postgres_servers and postgres_parameters
        else unsupported(
            "PostgreSQL flexible servers do not enforce SSL connections",
            "Low",
            "PostgreSQL server and parameter datasets are required.",
        )
    )
    findings.append(
        find_postgres_geo_backup_disabled(postgres_servers)
        if postgres_servers
        else unsupported(
            "PostgreSQL flexible servers do not enable geo-redundant backup",
            "Low",
            "No PostgreSQL server dataset was found.",
        )
    )
    findings.append(
        find_postgres_parameter_disabled(
            postgres_servers,
            postgres_parameters,
            "connection_throttling",
            "PostgreSQL Server Connection Throttling Not Enabled",
            "Uses the PostgreSQL flexible server parameter dataset to check connection_throttling.",
            "connectionThrottling",
        )
        if postgres_servers and postgres_parameters
        else unsupported(
            "PostgreSQL Server Connection Throttling Not Enabled",
            "Low",
            "PostgreSQL server and parameter datasets are required.",
        )
    )
    findings.append(
        find_postgres_parameter_disabled(
            postgres_servers,
            postgres_parameters,
            "log_checkpoints",
            "PostgreSQL flexible servers do not log checkpoints",
            "Uses the PostgreSQL flexible server parameter dataset to check log_checkpoints.",
            "logCheckpoints",
        )
        if postgres_servers and postgres_parameters
        else unsupported(
            "PostgreSQL flexible servers do not log checkpoints",
            "Low",
            "PostgreSQL server and parameter datasets are required.",
        )
    )
    findings.append(
        find_postgres_parameter_disabled(
            postgres_servers,
            postgres_parameters,
            "log_connections",
            "PostgreSQL flexible servers do not log connections",
            "Uses the PostgreSQL flexible server parameter dataset to check log_connections.",
            "logConnections",
        )
        if postgres_servers and postgres_parameters
        else unsupported(
            "PostgreSQL flexible servers do not log connections",
            "Low",
            "PostgreSQL server and parameter datasets are required.",
        )
    )
    findings.append(
        find_postgres_parameter_disabled(
            postgres_servers,
            postgres_parameters,
            "log_duration",
            "PostgreSQL Server Duration Logging Not Enabled",
            "Uses the PostgreSQL flexible server parameter dataset to check log_duration.",
            "logDuration",
        )
        if postgres_servers and postgres_parameters
        else unsupported(
            "PostgreSQL Server Duration Logging Not Enabled",
            "Low",
            "PostgreSQL server and parameter datasets are required.",
        )
    )
    findings.append(
        find_postgres_firewall_any_ip(postgres_firewall_rules)
        if postgres_firewall_rules
        else unsupported(
            "PostgreSQL Server Firewall Allows Access from Any IP",
            "High",
            "No PostgreSQL firewall rule dataset was found.",
        )
    )
    findings.append(
        find_postgres_parameter_disabled(
            postgres_servers,
            postgres_parameters,
            "log_disconnections",
            "PostgreSQL flexible servers do not log disconnections",
            "Uses the PostgreSQL flexible server parameter dataset to check log_disconnections.",
            "logDisconnections",
        )
        if postgres_servers and postgres_parameters
        else unsupported(
            "PostgreSQL flexible servers do not log disconnections",
            "Low",
            "PostgreSQL server and parameter datasets are required.",
        )
    )
    findings.append(
        find_postgres_log_retention_too_short(postgres_servers, postgres_parameters)
        if postgres_servers and postgres_parameters
        else unsupported(
            "PostgreSQL server with short log retention period",
            "Low",
            "PostgreSQL server and parameter datasets are required.",
        )
    )
    findings.append(
        find_postgres_private_dns_missing(postgres_servers)
        if postgres_servers
        else unsupported(
            "PostgreSQL flexible servers do not have a private DNS zone configured",
            "Low",
            "No PostgreSQL server dataset was found.",
        )
    )
    findings.append(
        find_postgres_private_network_disabled(postgres_servers)
        if postgres_servers
        else unsupported(
            "PostgreSQL flexible servers do not use private network access",
            "Low",
            "No PostgreSQL server dataset was found.",
        )
    )
    findings.append(
        find_server_data_encryption_gap(postgres_servers, "PostgreSQL flexible servers do not enable infrastructure double encryption")
        if postgres_servers
        else unsupported(
            "PostgreSQL flexible servers do not enable infrastructure double encryption",
            "Low",
            "No PostgreSQL server dataset was found.",
        )
    )
    findings.append(
        find_defender_pricing_gap(
            defender_settings,
            ("opensource", "relational"),
            "PostgreSQL flexible servers do not have Defender threat detection enabled",
            "Uses Microsoft Defender pricing coverage for open-source relational databases as the tenant-level signal for PostgreSQL threat-detection protection.",
        )
        if defender_settings and postgres_servers
        else unsupported(
            "PostgreSQL flexible servers do not have Defender threat detection enabled",
            "Low",
            "Defender pricing and PostgreSQL server datasets are required.",
        )
    )
    findings.append(
        find_redis_rdb_backup_disabled(redis_caches)
        if redis_caches
        else unsupported(
            "Redis caches do not have RDB backup enabled",
            "Low",
            "No Redis cache dataset was found.",
        )
    )
    findings.append(
        find_search_public_network_enabled(search_services)
        if search_services
        else unsupported(
            "Azure AI Search services allow public network access",
            "Low",
            "No Search service details dataset was found.",
        )
    )
    findings.append(
        find_search_without_shared_private_links(search_services, search_shared_private_links)
        if search_services and dataset_present(catalog, "az_search_shared-private-link-resource_list")
        else unsupported(
            "Azure AI Search services do not use shared private links",
            "Low",
            "Search service and shared private link datasets are required.",
        )
    )
    findings.append(
        find_signalr_public_network_enabled(signalr_services)
        if signalr_services
        else unsupported(
            "SignalR services allow public network access",
            "Low",
            "No SignalR service details dataset was found.",
        )
    )
    findings.append(
        find_servicebus_public_access(
            dataset_records(catalog, "az_servicebus_namespace_show"),
            dataset_records(catalog, "az_servicebus_queue_list"),
            "Service Bus queues allow public network access",
            "queue",
        )
        if dataset_present(catalog, "az_servicebus_namespace_show") and dataset_present(catalog, "az_servicebus_queue_list")
        else unsupported(
            "Service Bus queues allow public network access",
            "Low",
            "Service Bus namespace and queue datasets are required.",
        )
    )
    findings.append(
        find_servicebus_public_access(
            dataset_records(catalog, "az_servicebus_namespace_show"),
            dataset_records(catalog, "az_servicebus_topic_list"),
            "Service Bus topics allow public network access",
            "topic",
        )
        if dataset_present(catalog, "az_servicebus_namespace_show") and dataset_present(catalog, "az_servicebus_topic_list")
        else unsupported(
            "Service Bus topics allow public network access",
            "Low",
            "Service Bus namespace and topic datasets are required.",
        )
    )
    findings.append(
        find_sqlserver_atp_disabled(sql_server_threat_policies)
        if sql_server_threat_policies
        else unsupported(
            "SQL servers do not have Advanced Threat Protection enabled",
            "Low",
            "No SQL server threat policy dataset was found.",
        )
    )
    findings.append(
        find_sql_policy_alerts_disabled(sql_server_threat_policies, "SQL Server Threat Detection Alerts Not Enabled")
        if sql_server_threat_policies
        else unsupported(
            "SQL Server Threat Detection Alerts Not Enabled",
            "Low",
            "No SQL server threat policy dataset was found.",
        )
    )
    findings.append(
        find_sql_policy_retention_short(sql_server_threat_policies, "SQL Server Threat Detection Retention Period Too Low")
        if sql_server_threat_policies
        else unsupported(
            "SQL Server Threat Detection Retention Period Too Low",
            "Low",
            "No SQL server threat policy dataset was found.",
        )
    )
    findings.append(
        find_sql_policy_email_alerts_disabled(sql_server_threat_policies, "SQL Server Threat Detection Email Alerts Not Enabled")
        if sql_server_threat_policies
        else unsupported(
            "SQL Server Threat Detection Email Alerts Not Enabled",
            "Low",
            "No SQL server threat policy dataset was found.",
        )
    )
    findings.append(
        find_sqlserver_auditing_disabled(sql_server_audit_policies)
        if sql_server_audit_policies
        else unsupported(
            "SQL servers do not have auditing enabled",
            "Low",
            "No SQL server auditing dataset was found.",
        )
    )
    findings.append(
        find_sqlserver_audit_retention_short(sql_server_audit_policies)
        if sql_server_audit_policies
        else unsupported(
            "SQL servers do not retain audit logs for at least 90 days",
            "Low",
            "No SQL server auditing dataset was found.",
        )
    )
    findings.append(
        find_sqlserver_no_aad_admin(sql_server_aad_admins, sql_servers)
        if sql_servers and dataset_present(catalog, "az_sql_server_ad-admin_list")
        else unsupported(
            "SQL servers do not have an Azure AD administrator configured",
            "Low",
            "SQL server and Azure AD admin datasets are required.",
        )
    )
    findings.append(
        find_sqlserver_tde_not_cmk(sql_server_tde_keys)
        if sql_server_tde_keys
        else unsupported(
            "SQL servers do not encrypt TDE with customer-managed keys",
            "Low",
            "No SQL server TDE protector dataset was found.",
        )
    )
    findings.append(
        find_sql_database_tde_disabled(sql_database_tde)
        if sql_database_tde
        else unsupported(
            "SQL databases do not have Transparent Data Encryption enabled",
            "Low",
            "No SQL database TDE dataset was found.",
        )
    )
    findings.append(
        find_sql_policy_disabled(sql_database_audit_policies, "SQL Database Auditing Not Enabled")
        if sql_database_audit_policies
        else unsupported(
            "SQL Database Auditing Not Enabled",
            "Low",
            "No SQL database auditing dataset was found.",
        )
    )
    findings.append(
        find_sql_policy_retention_short(sql_database_audit_policies, "SQL Database Auditing Retention Period Too Low")
        if sql_database_audit_policies
        else unsupported(
            "SQL Database Auditing Retention Period Too Low",
            "Low",
            "No SQL database auditing dataset was found.",
        )
    )
    findings.append(
        find_sql_policy_disabled(sql_database_threat_policies, "SQL Database Threat Detection Not Enabled")
        if sql_database_threat_policies
        else unsupported(
            "SQL Database Threat Detection Not Enabled",
            "Low",
            "No SQL database threat policy dataset was found.",
        )
    )
    findings.append(
        find_sql_policy_alerts_disabled(sql_database_threat_policies, "SQL Database Threat Detection Alerts Not Enabled")
        if sql_database_threat_policies
        else unsupported(
            "SQL Database Threat Detection Alerts Not Enabled",
            "Low",
            "No SQL database threat policy dataset was found.",
        )
    )
    findings.append(
        find_sql_policy_retention_short(sql_database_threat_policies, "SQL Database Threat Detection Retention Period Too Low")
        if sql_database_threat_policies
        else unsupported(
            "SQL Database Threat Detection Retention Period Too Low",
            "Low",
            "No SQL database threat policy dataset was found.",
        )
    )
    findings.append(
        find_sql_policy_email_alerts_disabled(sql_database_threat_policies, "SQL Database Threat Detection Email Alerts Not Enabled")
        if sql_database_threat_policies
        else unsupported(
            "SQL Database Threat Detection Email Alerts Not Enabled",
            "Low",
            "No SQL database threat policy dataset was found.",
        )
    )
    findings.append(
        find_sqlserver_unrestricted_inbound_access(sql_server_firewall_rules)
        if sql_server_firewall_rules
        else unsupported(
            "SQL servers permit unrestricted inbound access",
            "Low",
            "No SQL server firewall rule dataset was found.",
        )
    )
    findings.append(
        find_sqlserver_va_disabled(sql_server_vuln_assessments)
        if sql_server_vuln_assessments
        else unsupported(
            "SQL servers do not have vulnerability assessment configured",
            "Low",
            "No SQL server vulnerability assessment dataset was found.",
        )
    )
    findings.append(
        find_sqlserver_va_admin_notifications_disabled(sql_server_vuln_assessments)
        if sql_server_vuln_assessments
        else unsupported(
            "SQL Server Vulnerability Assessment Email Notifications to Admins and Owners Not Enabled",
            "Low",
            "No SQL server vulnerability assessment dataset was found.",
        )
    )
    findings.append(
        find_sql_server_tls_below_recommendation(sql_server_details or sql_servers)
        if sql_server_details or sql_servers
        else unsupported(
            "SQL servers use a minimal TLS version below the recommended baseline",
            "Low",
            "No SQL server dataset was found.",
        )
    )
    findings.append(
        find_sqlserver_va_recipients_missing(sql_server_vuln_assessments)
        if sql_server_vuln_assessments
        else unsupported(
            "SQL Server Vulnerability Assessment Scan Report Recipients Not Configured",
            "Low",
            "No SQL server vulnerability assessment dataset was found.",
        )
    )
    findings.append(
        find_storage_shared_key_access_enabled(storage_accounts)
        if storage_accounts
        else unsupported(
            "Storage accounts permit shared key access",
            "Low",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_storage_file_soft_delete_disabled(storage_file_service_properties)
        if storage_file_service_properties
        else unsupported(
            "Storage accounts do not enable file share soft delete",
            "Low",
            "No storage file service properties dataset was found.",
        )
    )
    findings.append(
        find_storage_blob_versioning_disabled(storage_blob_service_properties)
        if storage_blob_service_properties
        else unsupported(
            "Storage accounts do not have blob versioning enabled",
            "Low",
            "No storage blob service properties dataset was found.",
        )
    )
    findings.append(
        find_storage_cross_tenant_replication_enabled(storage_accounts)
        if storage_accounts
        else unsupported(
            "Storage accounts allow cross-tenant replication",
            "Low",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_storage_entra_auth_not_default(storage_accounts)
        if storage_accounts
        else unsupported(
            "Storage accounts do not default to Microsoft Entra authorization",
            "Low",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_storage_azure_services_bypass_disabled(storage_accounts)
        if storage_accounts
        else unsupported(
            "Storage accounts do not trust Azure services network bypass",
            "Low",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_storage_azure_services_bypass_enabled(storage_accounts)
        if storage_accounts
        else unsupported(
            "Storage Account Permits Trusted Microsoft Services Bypass",
            "Low",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_storage_child_public_access(storage_accounts, storage_queues, "Storage queues allow public access", "queue")
        if storage_accounts and storage_queues
        else unsupported(
            "Storage queues allow public access",
            "Low",
            "Storage account and queue datasets are required.",
        )
    )
    findings.append(
        find_storage_child_public_access(storage_accounts, storage_shares, "Storage shares allow public access", "share")
        if storage_accounts and storage_shares
        else unsupported(
            "Storage shares allow public access",
            "Low",
            "Storage account and share datasets are required.",
        )
    )
    findings.append(
        find_storage_smb_secure_channel_encryption(storage_file_service_properties)
        if storage_file_service_properties
        else unsupported(
            "Storage accounts do not use secure SMB channel encryption algorithms",
            "Low",
            "No storage file service properties dataset was found.",
        )
    )
    findings.append(
        find_storage_smb_protocol_not_latest(storage_file_service_properties)
        if storage_file_service_properties
        else unsupported(
            "Storage accounts do not use the latest SMB protocol version",
            "Low",
            "No storage file service properties dataset was found.",
        )
    )
    findings.append(
        find_storage_child_public_access(storage_accounts, storage_tables, "Storage tables allow public access", "table")
        if storage_accounts and storage_tables
        else unsupported(
            "Storage tables allow public access",
            "Low",
            "Storage account and table datasets are required.",
        )
    )
    findings.append(
        find_storage_geo_replication_disabled(storage_accounts)
        if storage_accounts
        else unsupported(
            "Storage accounts do not use geo-redundant replication",
            "Low",
            "No storage account dataset was found.",
        )
    )
    findings.append(
        find_synapse_exfiltration_protection_disabled(synapse_workspaces)
        if synapse_workspaces
        else unsupported(
            "Synapse workspaces do not enable data exfiltration protection",
            "Low",
            "No Synapse workspace dataset was found.",
        )
    )
    findings.append(
        find_vm_backup_disabled(vm_details, backup_items)
        if vm_details and backup_items
        else unsupported(
            "Virtual machines are not protected by backup",
            "Low",
            "VM detail and backup item datasets are required.",
        )
    )
    findings.append(
        find_vm_jit_disabled(vm_details, defender_jit_policies)
        if vm_details and defender_jit_policies
        else unsupported(
            "Virtual machines do not have JIT access enabled",
            "Low",
            "VM detail and Defender JIT policy datasets are required.",
        )
    )
    findings.append(
        find_vm_attached_disks_not_cmk(vm_details, managed_disks)
        if vm_details and managed_disks
        else unsupported(
            "VM OS and Data Disks Not Encrypted with Customer Managed Keys",
            "Low",
            "VM detail and managed disk datasets are required.",
        )
    )
    findings.append(
        find_unattached_disks_not_cmk(managed_disks)
        if managed_disks
        else unsupported(
            "Unattached managed disks are not encrypted with customer-managed keys",
            "Low",
            "No managed disk dataset was found.",
        )
    )
    findings.append(
        find_vm_disk_encryption_not_enabled(managed_disks)
        if managed_disks
        else unsupported(
            "VM Disk Encryption Not Enabled",
            "Low",
            "No managed disk dataset was found.",
        )
    )
    findings.append(
        find_vm_not_using_managed_disks(vm_details)
        if vm_details
        else unsupported(
            "VM Not Using Managed Disks",
            "Low",
            "No VM detail dataset was found.",
        )
    )
    findings.append(
        find_synapse_managed_vnet_disabled(synapse_workspaces)
        if synapse_workspaces
        else unsupported(
            "Synapse workspaces do not use a managed virtual network",
            "Low",
            "No Synapse workspace dataset was found.",
        )
    )
    findings.append(
        find_bastion_host_absent(bastion_hosts, subscriptions)
        if dataset_present(catalog, "az_network_bastion_list")
        else unsupported(
            "Azure Bastion hosts are not deployed",
            "Low",
            "No Bastion host dataset was found.",
        )
    )
    findings.append(
        find_flow_logs_not_captured(flow_logs)
        if flow_logs
        else unsupported(
            "Network Watcher flow logs are not captured to storage",
            "Low",
            "No flow log dataset was found.",
        )
    )
    findings.append(
        find_flow_logs_retention_short(flow_logs)
        if flow_logs
        else unsupported(
            "Network Watcher flow logs do not retain data for more than 90 days",
            "Low",
            "No flow log dataset was found.",
        )
    )
    findings.append(
        find_nsg_open_http(nsgs)
        if nsgs
        else unsupported(
            "HTTP is exposed to the internet through NSG rules",
            "Medium",
            "No NSG dataset was found.",
        )
    )
    findings.append(
        find_public_ip_exposure(public_ip_addresses)
        if public_ip_addresses
        else unsupported(
            "Public IP addresses are exposed to internet indexing services",
            "Medium",
            "No public IP dataset was found.",
        )
    )
    findings.append(
        find_vm_linux_password_auth_enabled(vm_details)
        if vm_details
        else unsupported(
            "Linux virtual machines allow password-based SSH authentication",
            "Low",
            "No VM detail dataset was found.",
        )
    )
    findings.append(
        find_vmss_without_load_balancer(vm_scale_sets)
        if vm_scale_sets
        else unsupported(
            "Virtual machine scale sets are not associated with a load balancer",
            "Low",
            "No VM scale set dataset was found.",
        )
    )
    findings.append(
        find_unapproved_vm_extensions(vm_extensions)
        if dataset_present(catalog, "az_vm_extension_list")
        else unsupported(
            "Unapproved VM Extensions Installed",
            "Low",
            "No VM extension dataset was found.",
        )
    )
    findings.append(
        find_vm_unapproved_images(vm_details)
        if vm_details
        else unsupported(
            "Virtual machines are not using approved base images",
            "Low",
            "No VM detail dataset was found.",
        )
    )
    findings.append(
        find_vm_backup_retention_too_short(backup_items, backup_policies)
        if backup_items and backup_policies
        else unsupported(
            "Virtual machine backup policies do not retain daily restore points long enough",
            "Low",
            "Backup item and backup policy datasets are required.",
        )
    )

    if postgres_servers and not postgres_firewall_rules:
        for finding in findings:
            if finding["title"] in {
                "Access permitted to PostgreSQL server from Azure services",
                "PostgreSQL Server Firewall Allows Access from Any IP",
            }:
                finding["reason"] += " PostgreSQL servers were collected, but the required supporting sub-resource data was not."

    reference_sources = {
        "Azure blob container permits public access": source_map["storage_accounts"],
        "Custom Azure subscription owner roles permitted": source_map["role_definitions"] + source_map["role_assignments"],
        "Stale Azure access keys present": source_map["storage_accounts"] + source_map["storage_keys"],
        "Azure Storage accounts do not enforce encrypted data transfer": source_map["storage_accounts"],
        "Azure policy permits users to create security groups": source_map["graph_authorization_policy"],
        "Azure Storage Accounts permitting deprecated TLS versions": source_map["storage_accounts"],
        "Storage accounts with default network access permitted": source_map["storage_accounts"],
        "Access permitted to PostgreSQL server from Azure services": source_map["postgres_firewall_rules"],
        "Access to Azure Key Vault not restricted to trusted source addresses": source_map["key_vaults"] + source_map["key_vault_network_rules"],
        "Azure Monitor Alerts not configured to notify high severity events": source_map["metric_alerts"],
        "Storage Accounts not using private IP endpoints": source_map["storage_accounts"],
        "PostgreSQL server without connection throttling": dataset_paths(catalog, "az_postgres_flexible-server_parameter_list"),
        "Azure Storage Containers without Soft Delete protection": source_map["storage_blob_service_properties"],
        "Azure Activity Log Alerts missing for key event types": source_map["activity_log_alerts"],
        "Microsoft Defender for Cloud is not enabled": source_map["defender_settings"],
        "Role-Based Access Control (RBAC) not enabled for Azure Key Vault": source_map["key_vaults"],
        "MySQL server without audit logging enabled": dataset_paths(catalog, "az_mysql_flexible-server_parameter_list"),
        "PostgreSQL server with short log retention period": dataset_paths(catalog, "az_postgres_flexible-server_parameter_list"),
        "Security contact phone number is not set in Azure tenant": source_map["security_contacts"],
        "Azure AppService HTTP logs not enabled enabled": source_map["web_app_logs"],
        "Azure Network Watcher not enabled for all subscription locations": source_map["network_watchers"] + source_map["resources"] + source_map["locations"],
        "Azure Key Vault not recoverable": source_map["key_vaults"],
        "Ensure Diagnostic Setting captures appropriate categories": source_map["diagnostic_settings"] + source_map["diagnostic_categories"],
        "Azure subscription does not have a role for administration of resource locks": source_map["role_definitions"],
        "Azure App Services using deprecated HTTP Version": source_map["web_app_configs"],
        "Data at rest in Azure storage accounts use Microsoft managed encryption keys": source_map["storage_accounts"],
        "Azure Subscription-level activity logs without a 'Diagnostic Setting' exist": source_map["subscriptions"] + source_map["subscription_diagnostic_settings"],
        "Azure Storage Accounts without infrastructure encryption enabled": source_map["storage_accounts"],
        "Azure Container Registry admin user enabled": source_map["container_registries"],
        "AKS clusters without RBAC enabled": source_map["aks_clusters"],
        "AKS clusters with local accounts enabled": source_map["aks_clusters"],
        "AKS clusters without authorized API server IP ranges": source_map["aks_clusters"],
        "AKS clusters not using a private control plane": source_map["aks_clusters"],
        "Network security groups expose administrative ports to the Internet": source_map["nsgs"],
        "Network security groups expose common data ports to the Internet": source_map["nsgs"],
        "Azure App Services do not enforce HTTPS": source_map["web_apps"],
        "Azure App Services do not enforce FTPS-only": source_map["web_apps"],
        "Azure App Services have remote debugging enabled": source_map["web_apps"],
        "Azure App Services allow wildcard CORS origins": source_map["web_apps"],
        "Azure App Services have no access restrictions configured": source_map["web_app_access_restrictions"],
        "Azure App Services have unrestricted SCM endpoints": source_map["web_app_access_restrictions"],
        "Azure App Services do not require client certificates": source_map["web_apps"],
        "Azure App Services permit TLS versions below 1.2": source_map["web_app_configs"],
        "Azure App Services do not disable FTP deployment": source_map["web_apps"],
        "Azure App Services are not registered with a managed identity": source_map["web_apps"],
        "Azure App Services do not have authentication configured": source_map["web_app_auth_settings"],
        "Azure App Services are missing Application Insights configuration": source_map["web_apps"] + source_map["web_app_appsettings"],
        "Function Apps are missing Application Insights configuration": source_map["function_apps"] + source_map["function_app_appsettings"],
        "Function Apps do not have access keys configured": source_map["function_apps"] + source_map["function_app_keys"],
        "Function Apps do not disable FTP deployment": source_map["function_apps"],
        "Function Apps do not have a managed identity configured": source_map["function_apps"] + source_map["function_app_identities"],
        "Function Apps are publicly reachable": source_map["function_apps"] + source_map["function_app_access_restrictions"],
        "Function Apps are not integrated with a virtual network": source_map["function_apps"] + source_map["function_app_vnet_integrations"],
        "Azure Container Registries allow public network access": source_map["container_registries"],
        "Azure Container Registries do not use private link": source_map["container_registries"] + source_map["acr_private_endpoint_connections"],
        "Cosmos DB accounts do not restrict network access": source_map["cosmosdb_accounts"],
        "Cosmos DB accounts do not use private endpoints": source_map["cosmosdb_accounts"],
        "Cosmos DB accounts do not use Microsoft Entra ID and RBAC": source_map["cosmosdb_accounts"] + source_map["cosmosdb_sql_role_assignments"],
        "Cognitive Services accounts permit local authentication": source_map["cognitive_services_accounts"],
        "Databricks workspaces do not enable customer-managed key encryption": source_map["databricks_workspaces"],
        "Databricks workspaces do not use VNet injection": source_map["databricks_workspaces"],
        "Event Grid Topics allow public network access": source_map["eventgrid_topics"],
        "Event Grid Domains allow public network access": source_map["eventgrid_domains"],
        "IoT Device Provisioning Services allow public network access": source_map["iot_dps_instances"],
        "Defender auto provisioning for Log Analytics agents is not enabled": source_map["defender_auto_provisioning_settings"],
        "Microsoft Defender security contacts do not notify subscription owners": source_map["security_contacts"],
        "Microsoft Entra security defaults are not enabled": source_map["graph_security_defaults_policy"],
        "Microsoft Entra trusted named locations are not configured": source_map["graph_named_locations"],
        "Microsoft Entra default users can create applications": source_map["graph_authorization_policy"],
        "Microsoft Entra default users can create tenants": source_map["graph_authorization_policy"],
        "Microsoft Entra guest invites are not restricted to admins": source_map["graph_authorization_policy"],
        "Microsoft Entra guest user access restrictions are not configured": source_map["graph_authorization_policy"],
        "Azure Key Vaults do not use private endpoints": source_map["key_vaults"] + source_map["key_vault_private_endpoint_connections"],
        "Azure Key Vaults do not have diagnostic logging enabled": source_map["key_vaults"] + source_map["diagnostic_settings"],
        "AKS clusters do not have Azure Policy enabled": source_map["aks_clusters"],
        "AKS clusters do not have a network policy configured": source_map["aks_clusters"],
        "AKS clusters use public node IPs": source_map["aks_clusters"],
        "Machine Learning workspaces allow public network access": source_map["machine_learning_workspaces"],
        "Machine Learning workspaces do not use virtual network integration": source_map["machine_learning_workspaces"],
        "Azure Activity Log Alerts missing for service health events": source_map["activity_log_alerts"],
        "Azure Activity Log Alerts missing for security solution changes": source_map["activity_log_alerts"],
        "Subscription activity logs are stored in accounts without customer-managed keys": source_map["subscription_diagnostic_settings"] + source_map["storage_accounts"],
        "Subscription activity logs are stored in accounts without private endpoints": source_map["subscription_diagnostic_settings"] + source_map["storage_accounts"],
        "MySQL flexible servers do not have audit logging enabled": source_map["mysql_servers"] + source_map["mysql_parameters"],
        "MySQL flexible servers do not enable geo-redundant backup": source_map["mysql_servers"],
        "MySQL flexible servers permit TLS versions below 1.2": source_map["mysql_servers"] + source_map["mysql_parameters"],
        "MySQL flexible servers do not enforce SSL connections": source_map["mysql_servers"] + source_map["mysql_parameters"],
        "PostgreSQL flexible servers do not enforce SSL connections": source_map["postgres_parameters"] + dataset_paths(catalog, "az_postgres_flexible-server_list"),
        "PostgreSQL flexible servers do not enable geo-redundant backup": dataset_paths(catalog, "az_postgres_flexible-server_list"),
        "PostgreSQL flexible servers do not log checkpoints": source_map["postgres_parameters"] + dataset_paths(catalog, "az_postgres_flexible-server_list"),
        "PostgreSQL flexible servers do not log connections": source_map["postgres_parameters"] + dataset_paths(catalog, "az_postgres_flexible-server_list"),
        "PostgreSQL flexible servers do not log disconnections": source_map["postgres_parameters"] + dataset_paths(catalog, "az_postgres_flexible-server_list"),
        "PostgreSQL flexible servers do not have a private DNS zone configured": dataset_paths(catalog, "az_postgres_flexible-server_list"),
        "PostgreSQL flexible servers do not use private network access": dataset_paths(catalog, "az_postgres_flexible-server_list"),
        "Redis caches do not have RDB backup enabled": source_map["redis_caches"],
        "Azure AI Search services allow public network access": source_map["search_services"],
        "Azure AI Search services do not use shared private links": source_map["search_services"] + source_map["search_shared_private_links"],
        "SignalR services allow public network access": source_map["signalr_services"],
        "SQL servers do not have Advanced Threat Protection enabled": source_map["sql_server_threat_policies"],
        "SQL servers do not have auditing enabled": source_map["sql_server_audit_policies"],
        "SQL servers do not retain audit logs for at least 90 days": source_map["sql_server_audit_policies"],
        "SQL servers do not have an Azure AD administrator configured": source_map["sql_servers"] + source_map["sql_server_aad_admins"],
        "SQL servers do not encrypt TDE with customer-managed keys": source_map["sql_server_tde_keys"],
        "SQL databases do not have Transparent Data Encryption enabled": source_map["sql_database_tde"],
        "SQL servers permit unrestricted inbound access": source_map["sql_server_firewall_rules"],
        "SQL servers do not have vulnerability assessment configured": source_map["sql_server_vuln_assessments"],
        "Storage accounts permit shared key access": source_map["storage_accounts"],
        "Storage accounts do not enable file share soft delete": source_map["storage_file_service_properties"],
        "Storage accounts do not have blob versioning enabled": source_map["storage_blob_service_properties"],
        "Storage accounts allow cross-tenant replication": source_map["storage_accounts"],
        "Storage accounts do not default to Microsoft Entra authorization": source_map["storage_accounts"],
        "Storage accounts do not trust Azure services network bypass": source_map["storage_accounts"],
        "Storage accounts do not use geo-redundant replication": source_map["storage_accounts"],
        "Synapse workspaces do not enable data exfiltration protection": source_map["synapse_workspaces"],
        "Synapse workspaces do not use a managed virtual network": source_map["synapse_workspaces"],
        "Azure Bastion hosts are not deployed": source_map["bastion_hosts"] + source_map["subscriptions"],
        "Network Watcher flow logs are not captured to storage": source_map["flow_logs"],
        "Network Watcher flow logs do not retain data for more than 90 days": source_map["flow_logs"],
        "Virtual machines are not protected by backup": source_map["vm_details"] + source_map["backup_items"],
        "Virtual machines do not have JIT access enabled": source_map["vm_details"] + source_map["defender_jit_policies"],
        "Virtual machine attached disks are not encrypted with customer-managed keys": source_map["vm_details"] + source_map["managed_disks"],
        "Unattached managed disks are not encrypted with customer-managed keys": source_map["managed_disks"],
        "Linux virtual machines allow password-based SSH authentication": source_map["vm_details"],
        "Virtual machine scale sets are not associated with a load balancer": source_map["vm_scale_sets"],
        "Unauthenticated Guest Users Present in Azure AD": source_map["ad_users"] + source_map["graph_user_registration_details"],
        "App Service Running Outdated .NET Version": source_map["web_app_configs"],
        "App Service Running Outdated Java Version": source_map["web_app_configs"],
        "App Service Running Outdated PHP Version": source_map["web_app_configs"],
        "App Service Running Outdated Python Version": source_map["web_app_configs"],
        "App Service Running Outdated Programming Language Version": source_map["web_app_configs"],
        "Key Vault Allows Public Network Access": source_map["key_vaults"],
        "Key Vault Recovery Protection Not Enabled": source_map["key_vaults"],
        "Diagnostic Settings Not Configured": source_map["resources"] + source_map["diagnostic_settings"],
        "Activity Log Profile Does Not Capture All Events": source_map["log_profiles"],
        "Users with Permission to Administer Resource Locks Assigned": source_map["role_definitions"] + source_map["role_assignments"],
        "NSG Inbound Rule Allows Internet Access to All Ports": source_map["nsgs"],
        "NSG Inbound Rule Allows Internet Access to MSSQL Service": source_map["nsgs"],
        "NSG Inbound Rule Allows Internet Access to UDP Services": source_map["nsgs"],
        "NSG Inbound Rule Allows Internet Access to Exposed Services": source_map["nsgs"],
        "PostgreSQL Server Connection Throttling Not Enabled": source_map["postgres_parameters"] + dataset_paths(catalog, "az_postgres_flexible-server_list"),
        "PostgreSQL Server Duration Logging Not Enabled": source_map["postgres_parameters"] + dataset_paths(catalog, "az_postgres_flexible-server_list"),
        "PostgreSQL Server Firewall Allows Access from Any IP": source_map["postgres_firewall_rules"],
        "Security Contacts Not Configured": source_map["security_contacts"],
        "Security Contact Email Address Not Configured": source_map["security_contacts"],
        "Security Contact Email Notifications Not Enabled": source_map["security_contacts"],
        "Security Contact Admin Email Notifications Not Enabled": source_map["security_contacts"],
        "Microsoft Cloud App Security Integration Not Enabled": source_map["defender_general_settings"],
        "Microsoft Defender ATP Integration Not Enabled": source_map["defender_general_settings"],
        "SQL Server Threat Detection Alerts Not Enabled": source_map["sql_server_threat_policies"],
        "SQL Server Threat Detection Retention Period Too Low": source_map["sql_server_threat_policies"],
        "SQL Server Threat Detection Email Alerts Not Enabled": source_map["sql_server_threat_policies"],
        "SQL Database Auditing Not Enabled": source_map["sql_database_audit_policies"],
        "SQL Database Auditing Retention Period Too Low": source_map["sql_database_audit_policies"],
        "SQL Database Threat Detection Not Enabled": source_map["sql_database_threat_policies"],
        "SQL Database Threat Detection Alerts Not Enabled": source_map["sql_database_threat_policies"],
        "SQL Database Threat Detection Retention Period Too Low": source_map["sql_database_threat_policies"],
        "SQL Database Threat Detection Email Alerts Not Enabled": source_map["sql_database_threat_policies"],
        "SQL Server Vulnerability Assessment Email Notifications to Admins and Owners Not Enabled": source_map["sql_server_vuln_assessments"],
        "SQL Server Vulnerability Assessment Scan Report Recipients Not Configured": source_map["sql_server_vuln_assessments"],
        "Storage Account Permits Trusted Microsoft Services Bypass": source_map["storage_accounts"],
        "Storage Account Access Keys Not Rotated": source_map["storage_accounts"] + source_map["storage_keys"],
        "App Service Environment vNet injection not deployed": source_map["app_service_environments"] + source_map["subscriptions"],
        "Function Apps have managed identities with administrative privileges": source_map["function_apps"] + source_map["function_app_identities"] + source_map["role_assignments"],
        "Function Apps are not using the latest Functions runtime major version": source_map["function_app_configs"] + source_map["function_app_appsettings"],
        "Defender endpoint protection is not installed on virtual machines": source_map["defender_assessments"],
        "Defender auto provisioning for vulnerability assessments is not enabled on machines": source_map["defender_auto_provisioning_settings"],
        "Defender assessments report unresolved container image vulnerabilities": source_map["defender_assessments"],
        "Container image vulnerability scanning is not enabled": source_map["defender_assessments"],
        "System updates are not fully applied on machines": source_map["defender_assessments"],
        "API Management services are missing LLM jacking threat-detection coverage": source_map["defender_assessments"] + source_map["apim_services"],
        "Conditional Access does not require MFA for admin portals": source_map["graph_conditional_access_policies"],
        "Conditional Access does not require MFA for the Azure management API": source_map["graph_conditional_access_policies"],
        "Global Administrator role is assigned to five or more users": source_map["graph_directory_roles"] + source_map["graph_directory_role_assignments"],
        "Non-privileged Microsoft Entra users do not have MFA": source_map["ad_users"] + source_map["graph_user_registration_details"] + source_map["graph_directory_roles"] + source_map["graph_directory_role_assignments"],
        "User consent for applications is not sufficiently restricted": source_map["graph_authorization_policy"],
        "User consent for verified applications is not enforced": source_map["graph_authorization_policy"],
        "Privileged Microsoft Entra users do not have MFA": source_map["ad_users"] + source_map["graph_user_registration_details"] + source_map["graph_directory_roles"] + source_map["graph_directory_role_assignments"],
        "Users with VM access do not have MFA": source_map["ad_users"] + source_map["graph_user_registration_details"] + source_map["role_assignments"],
        "Users can create Microsoft 365 groups": source_map["graph_group_settings"],
        "HDInsight Kafka clusters do not disable manual authentication": source_map["hdinsight_clusters"],
        "User Access Administrator role is assigned directly to users": source_map["role_assignments"],
        "Non-RBAC Key Vault keys do not have expiration dates": source_map["key_vaults"] + source_map["key_vault_keys"],
        "Key Vault keys do not have rotation enabled": source_map["key_vaults"] + source_map["key_vault_keys"] + source_map["key_vault_key_rotation_policies"],
        "Key Vault keys are older than 365 days": source_map["key_vaults"] + source_map["key_vault_keys"],
        "Non-RBAC Key Vault secrets do not have expiration dates": source_map["key_vaults"] + source_map["key_vault_secrets"],
        "RBAC Key Vault keys do not have expiration dates": source_map["key_vaults"] + source_map["key_vault_keys"],
        "RBAC Key Vault secrets do not have expiration dates": source_map["key_vaults"] + source_map["key_vault_secrets"],
        "Key Vault secrets do not have expiration dates": source_map["key_vaults"] + source_map["key_vault_secrets"],
        "MySQL flexible servers do not audit connection events": source_map["mysql_servers"] + source_map["mysql_parameters"],
        "MySQL flexible servers do not enable infrastructure double encryption": source_map["mysql_servers"],
        "MySQL flexible servers do not use private access": source_map["mysql_servers"],
        "MySQL flexible servers do not have Defender threat detection enabled": source_map["mysql_servers"] + source_map["defender_settings"],
        "HTTP is exposed to the internet through NSG rules": source_map["nsgs"],
        "Public IP addresses are exposed to internet indexing services": source_map["public_ip_addresses"],
        "PostgreSQL flexible servers do not enable infrastructure double encryption": dataset_paths(catalog, "az_postgres_flexible-server_list"),
        "PostgreSQL flexible servers do not have Defender threat detection enabled": dataset_paths(catalog, "az_postgres_flexible-server_list") + source_map["defender_settings"],
        "Service Bus queues allow public network access": dataset_paths(catalog, "az_servicebus_namespace_show") + dataset_paths(catalog, "az_servicebus_queue_list"),
        "Service Bus topics allow public network access": dataset_paths(catalog, "az_servicebus_namespace_show") + dataset_paths(catalog, "az_servicebus_topic_list"),
        "SQL servers use a minimal TLS version below the recommended baseline": source_map["sql_server_details"] + source_map["sql_servers"],
        "Storage queues allow public access": source_map["storage_accounts"] + source_map["storage_queues"],
        "Storage shares allow public access": source_map["storage_accounts"] + source_map["storage_shares"],
        "Storage accounts do not use secure SMB channel encryption algorithms": source_map["storage_file_service_properties"],
        "Storage accounts do not use the latest SMB protocol version": source_map["storage_file_service_properties"],
        "Storage tables allow public access": source_map["storage_accounts"] + source_map["storage_tables"],
        "VM Disk Encryption Not Enabled": source_map["managed_disks"],
        "VM Not Using Managed Disks": source_map["vm_details"],
        "Unapproved VM Extensions Installed": source_map["vm_extensions"],
        "VM OS and Data Disks Not Encrypted with Customer Managed Keys": source_map["vm_details"] + source_map["managed_disks"],
        "Virtual machines are not using approved base images": source_map["vm_details"],
        "Virtual machine backup policies do not retain daily restore points long enough": source_map["backup_items"] + source_map["backup_policies"],
    }

    findings = annotate_requested_headlines(findings)

    for finding in findings:
        attach_references(finding, reference_sources.get(finding["title"], []))

    return findings


def print_summary(findings):
    print("Known-bad finding search results")
    print("=" * 31)
    for finding in findings:
        print(
            f"[{finding['status']}] {finding['title']} | severity={finding['severity']} | evidence={finding['evidence_count']}"
        )


def main():
    args = parse_arguments()
    catalog = load_catalog(args.input_dir)
    findings = evaluate_findings(catalog)
    output = sarif_output(args.input_dir, catalog, findings)
    flat_output = {
        "input_dir": str(Path(args.input_dir)),
        "files_loaded": sorted(catalog.keys()),
        "rows": flat_rows(findings),
    }

    print_summary(findings)

    if not args.no_save:
        output_path = resolve_output_path(args.input_dir, args.output_file, "azure-findings.json")
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(output, handle, indent=2)
        flat_output_path = resolve_output_path(args.input_dir, args.flat_output_file, "azure-findings-flat.json")
        with open(flat_output_path, "w", encoding="utf-8") as handle:
            json.dump(flat_output, handle, indent=2)
        print(f"\nSaved findings JSON to: {output_path}")
        print(f"Saved flat findings JSON to: {flat_output_path}")


if __name__ == "__main__":
    main()
