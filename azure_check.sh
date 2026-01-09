#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

# ---------------------------------------------------------------------------
# azure-checks.sh
# Runs a curated battery of jq-based checks over Azure inventory JSON exported
# by your collector, without unsafe *.json globs.
#
# Usage:
#   ./azure-checks.sh [output-dir]
#
# Default output-dir: azure-collect
# Output file: ./potentialfindings (appends by default)
# ---------------------------------------------------------------------------

OUTDIR="."
#OUTDIR="${1:-azure-collect}"
FINDINGS="${FINDINGS:-potentialfindings}"
INDEX="${INDEX:-1}"

log()  { printf '[*] %s\n' "$*" >&2; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[X] %s\n' "$*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"; }

tmp_files=()
cleanup() { rm -f "${tmp_files[@]:-}"; }
trap cleanup EXIT

normalise_to_array() {
  local in="$1"
  [[ -n "$in" && -f "$in" ]] || { printf '%s\n' "$in"; return 0; }

  local out
  out="$(mktemp "${TMPDIR:-/tmp}/azure-checks.XXXXXX.json")"
  tmp_files+=("$out")

  jq '
    if type=="array" then .
    elif type=="object" and (.value? | type=="array") then .value
    else . end
  ' "$in" >"$out"

  printf '%s\n' "$out"
}


# Return newest JSON file matching prefix_<timestamp>.json
latest_json() {
  local prefix="$1"
  local f latest=""
  local -a files

  # Expand the glob safely
  local old_nullglob
  old_nullglob="$(shopt -p nullglob)"
  shopt -s nullglob
  files=( "${OUTDIR:?}/${prefix}"_*.json )
  eval "${old_nullglob}"

  ((${#files[@]})) || return 0

  LC_ALL=C
  for f in "${files[@]}"; do
    [[ -z "$latest" || "${f##*/}" > "${latest##*/}" ]] && latest="$f"
  done

  printf '%s\n' "$latest"
}

file_exists() {
  [[ -e "$1" ]]
}

assert_json() {
  jq -e . "$1" >/dev/null 2>&1
}

task_hdr() {
  local desc="$1"
  echo "==== Completing task ${INDEX} ${desc} ====" | tee -a "${FINDINGS}"
  INDEX=$((INDEX + 1))
}

# Usage: run_jq <dataset-var-name> <jq-args...>
# Example: run_jq RESOURCES_JSON -r '<filter>'
run_jq() {
  local ds_name="$1"; shift
  local ds_pre_norm="${!ds_name:-}"
  local ds="$(normalise_to_array "$ds_pre_norm")"

  task_hdr "$ds_name"

  if [[ -z "${ds}" ]]; then
    warn "Skipping check: dataset var ${ds_name} is empty"
    return 0
  fi

  if ! jq "$@" "${ds}" | tee -a "${FINDINGS}"; then
    warn "jq failed for ${ds_name} (${ds}), continuing"
    return 0
  fi
}

run_jq_multi() {
  # Usage: run_jq_multi <desc> <jq-args...> -- <file1> <file2> ...
  local ds_name="$1"; shift
  local marker="--"
  local args=()

  task_hdr "$ds_name"

  while [[ $# -gt 0 && "$1" != "${marker}" ]]; do
    args+=("$1"); shift
  done
  [[ $# -gt 0 && "$1" == "${marker}" ]] || die "run_jq_multi: missing -- separator"
  shift
  if ! jq "${args[@]}" "$@" | tee -a "${FINDINGS}"; then
    warn "jq failed for $1 , continuing"
    return 0
  fi
}

main() {
  need_cmd jq
  [[ -d "${OUTDIR}" ]] || die "Output directory does not exist: ${OUTDIR}"

  # -------------------------------------------------------------------------
  # Core dataset bindings (required)
  # -------------------------------------------------------------------------
  RESOURCES_JSON="$(latest_json az_resource_list)"
  ROLE_ASSIGNMENTS_JSON="$(latest_json az_role_assignment_list)"
  ROLE_DEFINITIONS_JSON="$(latest_json az_role_definition_list)"
  NSGS_JSON="$(latest_json az_network_nsg_list)"
  STORAGE_JSON="$(latest_json az_storage_account_list)"
  KEYVAULTS_JSON="$(latest_json az_keyvault_list)"
  VMS_JSON="$(latest_json az_vm_list)"
  POLICY_ASSIGNMENTS_JSON="$(latest_json az_policy_assignment_list)"

  # -------------------------------------------------------------------------
  # Optional datasets (only used if present)
  # Prefixes below assume your collector uses azure CLI-ish names.
  # If your collector uses different prefixes, rename them here.
  # -------------------------------------------------------------------------
  APP_SITES_JSON="$(latest_json az_webapp_list)"
  APP_SLOTS_JSON="$(latest_json az_webapp_slot_list)"
  APP_SITE_CONFIG_JSON="$(latest_json az_webapp_config_list)"             # Microsoft.Web/sites/config
  APP_INSIGHTS_WEBTESTS_JSON="$(latest_json az_appinsights_webtests_list)" # Microsoft.Insights/webtests
  REDIS_JSON="$(latest_json az_redis_list)"
  SQL_SERVERS_JSON="$(latest_json az_sql_servers_list)"
  SQL_MANAGED_INSTANCES_JSON="$(latest_json az_sql_managed_instances_list)"
  SQL_FIREWALL_RULES_JSON="$(latest_json az_sql_firewall_rules_list)"    # Microsoft.Sql/servers/firewallRules
  COSMOS_JSON="$(latest_json az_cosmosdb_list)"
  EVENTING_JSON="$(latest_json az_eventing_list)"                         # EH/SB/EG topics/domains etc
  ACR_JSON="$(latest_json az_acr_list)"
  APIM_JSON="$(latest_json az_apim_list)"
  BATCH_JSON="$(latest_json az_batch_list)"
  PURVIEW_JSON="$(latest_json az_purview_list)"
  RECOVERY_JSON="$(latest_json az_recovery_vaults_list)"
  BACKUPVAULTS_JSON="$(latest_json az_dataprotection_backupvaults_list)"
  AKS_JSON="$(latest_json az_aks_list)"
  NICS_JSON="$(latest_json az_network_nic_list)"
  PUBLIC_IPS_JSON="$(latest_json az_network_public_ip_list)"
  PRIVATE_ENDPOINTS_JSON="$(latest_json az_network_private_endpoint_list)"
  PRIVATE_DNS_ZONE_GROUPS_JSON="$(latest_json az_network_private_endpoint_dns_zone_group_list)"
  ROUTE_TABLES_JSON="$(latest_json az_network_route_table_list)"
  LOADBALANCERS_JSON="$(latest_json az_network_lb_list)"
  APPGATEWAYS_JSON="$(latest_json az_network_appgw_list)"
  VMSS_JSON="$(latest_json az_vmss_list)"

  DIAG_SETTINGS_JSON="$(latest_json az_monitor_diagnostic_settings_list)" # Microsoft.Insights/diagnosticSettings
  METRIC_ALERTS_JSON="$(latest_json az_monitor_metric_alert_list)"
  SCHEDULED_QUERY_RULES_JSON="$(latest_json az_monitor_scheduled_query_rules_list)"
  ACTION_GROUPS_JSON="$(latest_json az_monitor_action_group_list)"
  DCR_JSON="$(latest_json az_monitor_data_collection_rule_list)"
  DCR_ASSOC_JSON="$(latest_json az_monitor_data_collection_rule_association_list)"

  ACTIVITY_LOG_JSON="$(latest_json az_monitor_activity_log_list)"
  SECURITY_PRICINGS_JSON="$(latest_json az_security_pricings_list)"
  SECURITY_RECS_JSON="$(latest_json az_security_recommendations_list)"
  SECURITY_ALERTS_JSON="$(latest_json az_security_alerts_list)"

  USERS_JSON="$(latest_json az_ad_user_list)"
  SPS_JSON="$(latest_json az_ad_sp_list)"
  APPS_JSON="$(latest_json az_ad_app_list)"
  GROUP_MEMBERSHIPS_JSON="$(latest_json az_ad_group_member_list)"         # array of {groupId, memberId}
  PRIV_GROUP_IDS_JSON="$(latest_json privileged_group_ids)"               # array of groupId strings
  REQUIRED_INITIATIVES_JSON="$(latest_json required_initiative_ids)"      # array of policySetDefinitionIds
  PERMISSION_SETS_JSON="$(latest_json permission_sets)"                   # enriched permission set list
  CONSUMPTION_JSON="$(latest_json consumption_records)"                   # usage/consumption-like

  VM_IPS_JSON="$(latest_json az_vm_list_ip_addresses)"
  EFFECTIVE_RULES_JSON="$(latest_json az_network_effective_security_rules)"
  VM_SECRETS_JSON="$(latest_json vm_secrets_inventory)"
  CERTS_JSON="$(latest_json appgw_certs_inventory)"
  CIDR_REGEX_ALLOW_JSON="$(latest_json allowed_virtual_appliance_cidr_regex)"
  PE_GROUPID_ALLOW_JSON="$(latest_json allowed_private_endpoint_groupids)"
  SENSITIVE_SUBS_JSON="$(latest_json sensitive_subscription_ids)"
  MARKETPLACE_AGREEMENTS_JSON="$(latest_json marketplace_agreements)"

  ROLE_ENRICHED_JSON="$(latest_json role_enriched)"

  # Fallbacks: if specific dataset not present, use RESOURCES_JSON when the check is type-filterable.
  [[ -n "${APP_SITES_JSON}" ]] || APP_SITES_JSON="${RESOURCES_JSON}"
  [[ -n "${APP_SLOTS_JSON}" ]] || APP_SLOTS_JSON="${RESOURCES_JSON}"
  [[ -n "${APP_SITE_CONFIG_JSON}" ]] || APP_SITE_CONFIG_JSON="${RESOURCES_JSON}"
  [[ -n "${APP_INSIGHTS_WEBTESTS_JSON}" ]] || APP_INSIGHTS_WEBTESTS_JSON="${RESOURCES_JSON}"
  [[ -n "${REDIS_JSON}" ]] || REDIS_JSON="${RESOURCES_JSON}"
  [[ -n "${SQL_SERVERS_JSON}" ]] || SQL_SERVERS_JSON="${RESOURCES_JSON}"
  [[ -n "${SQL_MANAGED_INSTANCES_JSON}" ]] || SQL_MANAGED_INSTANCES_JSON="${RESOURCES_JSON}"
  [[ -n "${SQL_FIREWALL_RULES_JSON}" ]] || SQL_FIREWALL_RULES_JSON="${RESOURCES_JSON}"
  [[ -n "${COSMOS_JSON}" ]] || COSMOS_JSON="${RESOURCES_JSON}"
  [[ -n "${EVENTING_JSON}" ]] || EVENTING_JSON="${RESOURCES_JSON}"
  [[ -n "${ACR_JSON}" ]] || ACR_JSON="${RESOURCES_JSON}"
  [[ -n "${APIM_JSON}" ]] || APIM_JSON="${RESOURCES_JSON}"
  [[ -n "${BATCH_JSON}" ]] || BATCH_JSON="${RESOURCES_JSON}"
  [[ -n "${PURVIEW_JSON}" ]] || PURVIEW_JSON="${RESOURCES_JSON}"
  [[ -n "${RECOVERY_JSON}" ]] || RECOVERY_JSON="${RESOURCES_JSON}"
  [[ -n "${BACKUPVAULTS_JSON}" ]] || BACKUPVAULTS_JSON="${RESOURCES_JSON}"
  [[ -n "${AKS_JSON}" ]] || AKS_JSON="${RESOURCES_JSON}"
  [[ -n "${NICS_JSON}" ]] || NICS_JSON="${RESOURCES_JSON}"
  [[ -n "${PUBLIC_IPS_JSON}" ]] || PUBLIC_IPS_JSON="${RESOURCES_JSON}"
  [[ -n "${PRIVATE_ENDPOINTS_JSON}" ]] || PRIVATE_ENDPOINTS_JSON="${RESOURCES_JSON}"
  [[ -n "${PRIVATE_DNS_ZONE_GROUPS_JSON}" ]] || PRIVATE_DNS_ZONE_GROUPS_JSON="${RESOURCES_JSON}"
  [[ -n "${ROUTE_TABLES_JSON}" ]] || ROUTE_TABLES_JSON="${RESOURCES_JSON}"
  [[ -n "${LOADBALANCERS_JSON}" ]] || LOADBALANCERS_JSON="${RESOURCES_JSON}"
  [[ -n "${APPGATEWAYS_JSON}" ]] || APPGATEWAYS_JSON="${RESOURCES_JSON}"
  [[ -n "${VMSS_JSON}" ]] || VMSS_JSON="${RESOURCES_JSON}"

  # Validate required JSON
  for f in \
    "${RESOURCES_JSON}" \
    "${ROLE_ASSIGNMENTS_JSON}" \
    "${ROLE_DEFINITIONS_JSON}" \
    "${NSGS_JSON}" \
    "${STORAGE_JSON}" \
    "${KEYVAULTS_JSON}" \
    "${VMS_JSON}" \
    "${POLICY_ASSIGNMENTS_JSON}" \
    "${DIAG_SETTINGS_JSON}" \
    "${METRIC_ALERTS_JSON}" \
    "${SCHEDULED_QUERY_RULES_JSON}" \
    "${ACTION_GROUPS_JSON}" \
    "${DCR_JSON}" \
    "${DCR_ASSOC_JSON}" \
    "${ACTIVITY_LOG_JSON}" \
    "${SECURITY_PRICINGS_JSON}" \
    "${SECURITY_RECS_JSON}" \
    "${SECURITY_ALERTS_JSON}" \
    "${USERS_JSON}" \
    "${SPS_JSON}" \
    "${APPS_JSON}" \
    "${GROUP_MEMBERSHIPS_JSON}" \
    "${PRIV_GROUP_IDS_JSON}" \
    "${REQUIRED_INITIATIVES_JSON}" \
    "${PERMISSION_SETS_JSON}" \
    "${CONSUMPTION_JSON}" \
    "${VM_IPS_JSON}" \
    "${EFFECTIVE_RULES_JSON}" \
    "${VM_SECRETS_JSON}" \
    "${CERTS_JSON}" \
    "${CIDR_REGEX_ALLOW_JSON}" \
    "${PE_GROUPID_ALLOW_JSON}" \
    "${SENSITIVE_SUBS_JSON}" \
    "${MARKETPLACE_AGREEMENTS_JSON}" \
    "${ROLE_ENRICHED_JSON}"
  do
    if file_exists "$f"; then
      echo "Testing ${f}"
      assert_json "${f}"
    fi
  done

  log "Using datasets from: ${OUTDIR}"
  log "Writing findings to: ${FINDINGS}"

  # -------------------------------------------------------------------------
  # Checks begin
  # -------------------------------------------------------------------------

#1
  # App Service (sites/slots): httpsOnly explicitly false
  run_jq RESOURCES_JSON -r '.[] | select(.type|test("^Microsoft\\.Web/(sites|sites/slots)$";"i")) | select(.properties.httpsOnly==false) | "\(.id)\t\(.name)"'


  # App Service (sites/slots): httpsOnly explicitly false (duplicate)
  run_jq RESOURCES_JSON -r '.[] | select(.type|test("^Microsoft\\.Web/(sites|sites/slots)$";"i")) | select(.properties.httpsOnly==false) | "\(.id)\t\(.name)"'


  # App Service (sites/slots): FTPS not FtpsOnly or missing
  run_jq RESOURCES_JSON -r '.[] | select(.type|test("^Microsoft\\.Web/(sites|sites/slots)$";"i")) | select((.properties.ftpsState? // "") | ascii_downcase != "ftpsonly") | "\(.id)\t\(.name)\tftpsState=\(.properties.ftpsState? // "MISSING")"'


  # Application Insights webtests: http:// usage
  run_jq RESOURCES_JSON -r '.[] | select(.type|test("^Microsoft\\.Insights/webtests$";"i")) | select((.properties.RequestUrl? // .properties.syntheticMonitorId? // "" )|tostring|test("^http://";"i")) | "\(.id)\t\(.name)\turl=\(.properties.RequestUrl? // "UNKNOWN")"'


  # Storage accounts: supportsHttpsTrafficOnly == false
  run_jq STORAGE_JSON -r '.[] | select(.type|test("^Microsoft\\.Storage/storageAccounts$";"i")) | select(.properties.supportsHttpsTrafficOnly==false) | "\(.id)\t\(.name)"'


  # Storage accounts: minimumTlsVersion missing or TLS1_0/TLS1_1
  run_jq STORAGE_JSON -r '.[] | select(.type|test("^Microsoft\\.Storage/storageAccounts$";"i")) | select((.properties.minimumTlsVersion? // "MISSING") as $v | ($v=="MISSING") or ($v|tostring|test("TLS1_0|TLS1_1";"i"))) | "\(.id)\t\(.name)\tminimumTlsVersion=\(.properties.minimumTlsVersion? // "MISSING")"'


  # Azure Cache for Redis: enableNonSslPort == true
  run_jq REDIS_JSON -r '.[] | select(.type|test("^Microsoft\\.Cache/Redis$";"i")) | select((.properties.enableNonSslPort? // false)==true) | "\(.id)\t\(.name)\tenableNonSslPort=true"'


  # SQL servers/managed instances: minimum TLS missing or weak
  run_jq RESOURCES_JSON -r '.[] | select(.type|test("^Microsoft\\.Sql/(servers|managedInstances)$";"i")) | select((.properties.minimalTlsVersion? // .properties.minTlsVersion? // "MISSING") as $v | ($v=="MISSING") or ($v|tostring|test("1\\.0|1\\.1|TLS1_0|TLS1_1";"i"))) | "\(.id)\t\(.name)\tminTls=\(.properties.minimalTlsVersion? // .properties.minTlsVersion? // "MISSING")"'


  # Storage accounts: publicNetworkAccess enabled (default Enabled)
  run_jq STORAGE_JSON -r '.[] | select(.type|test("^Microsoft\\.Storage/storageAccounts$";"i")) | select((.properties.publicNetworkAccess? // "Enabled")|ascii_downcase=="enabled") | "\(.id)\t\(.name)\tpublicNetworkAccess=\(.properties.publicNetworkAccess? // "Enabled")"'


#10
  # Key Vaults: publicNetworkAccess enabled (default Enabled)
  run_jq KEYVAULTS_JSON -r '.[] | select(.type|test("^Microsoft\\.KeyVault/vaults$";"i")) | select((.properties.publicNetworkAccess? // "Enabled")|ascii_downcase=="enabled") | "\(.id)\t\(.name)"'


  # SQL servers: publicNetworkAccess enabled (default Enabled)
  run_jq SQL_SERVERS_JSON -r '.[] | select(.type|test("^Microsoft\\.Sql/servers$";"i")) | select((.properties.publicNetworkAccess? // "Enabled")|ascii_downcase=="enabled") | "\(.id)\t\(.name)"'


  # Cosmos DB accounts: publicNetworkAccess enabled (default Enabled)
  run_jq COSMOS_JSON -r '.[] | select(.type|test("^Microsoft\\.DocumentDB/databaseAccounts$";"i")) | select((.properties.publicNetworkAccess? // "Enabled")|ascii_downcase=="enabled") | "\(.id)\t\(.name)"'


  # Eventing/messaging: publicNetworkAccess enabled (default Enabled)
  run_jq EVENTING_JSON -r '.[] | select(.type|test("^Microsoft\\.(EventHub/namespaces|ServiceBus/namespaces|EventGrid/topics|EventGrid/domains)$";"i")) | select((.properties.publicNetworkAccess? // "Enabled")|ascii_downcase=="enabled") | "\(.id)\t\(.type)\t\(.name)"'


  # Container registries: publicNetworkAccess enabled (default Enabled)
  run_jq ACR_JSON -r '.[] | select(.type|test("^Microsoft\\.ContainerRegistry/registries$";"i")) | select((.properties.publicNetworkAccess? // "Enabled")|ascii_downcase=="enabled") | "\(.id)\t\(.name)"'


  # API Management: public IPs or hostname configs present
  run_jq APIM_JSON -r '.[] | select(.type|test("^Microsoft\\.ApiManagement/service$";"i")) | select((.properties.publicIPAddresses? // [])|length>0 or (.properties.hostnameConfigurations? // [])|length>0) | "\(.id)\t\(.name)\tpublicIPs=\((.properties.publicIPAddresses? // [])|length)\thostnames=\((.properties.hostnameConfigurations? // [])|length)"'


  # Batch accounts: publicNetworkAccess enabled (default Enabled)
  run_jq BATCH_JSON -r '.[] | select(.type|test("^Microsoft\\.Batch/batchAccounts$";"i")) | select((.properties.publicNetworkAccess? // "Enabled")|ascii_downcase=="enabled") | "\(.id)\t\(.name)"'


  # Purview accounts: publicNetworkAccess enabled (default Enabled)
  run_jq PURVIEW_JSON -r '.[] | select(.type|test("^Microsoft\\.Purview/accounts$";"i")) | select((.properties.publicNetworkAccess? // "Enabled")|ascii_downcase=="enabled") | "\(.id)\t\(.name)"'


  # Key Vaults: purge protection disabled or missing
  run_jq KEYVAULTS_JSON -r '.[] | select(.type|test("^Microsoft\\.KeyVault/vaults$";"i")) | select((.properties.enablePurgeProtection? // false)==false) | "\(.id)\t\(.name)\tenablePurgeProtection=false"'


  # Storage accounts: versioning/soft delete/change feed/immutability missing or disabled
  run_jq STORAGE_JSON -r '.[] | select(.type|test("^Microsoft\\.Storage/storageAccounts$";"i")) | select( (.properties.isVersioningEnabled? // null)==false or (.properties.deleteRetentionPolicy.enabled? // null)==false or (.properties.changeFeed.enabled? // null)==false or (.properties.immutableStorageWithVersioning.enabled? // null)==false ) | "\(.id)\t\(.name)\tver=\(.properties.isVersioningEnabled? // "NA")\tsoftDel=\(.properties.deleteRetentionPolicy.enabled? // "NA")\tcf=\(.properties.changeFeed.enabled? // "NA")\timmut=\(.properties.immutableStorageWithVersioning.enabled? // "NA")"'

#20
  # Recovery Services / Data Protection vaults: soft delete or immutability not enabled
  run_jq RESOURCES_JSON -r '.[] | select(.type|test("^Microsoft\\.(RecoveryServices/vaults|DataProtection/backupVaults)$";"i")) | select((.properties.securitySettings.softDeleteSettings.state? // "")|ascii_downcase!="enabled" or (.properties.securitySettings.immutabilitySettings.state? // "")|ascii_downcase!="enabled") | "\(.id)\t\(.name)\tsoftDelete=\(.properties.securitySettings.softDeleteSettings.state? // "NA")\timmut=\(.properties.securitySettings.immutabilitySettings.state? // "NA")"'


  # Container registries: adminUserEnabled == true
  run_jq ACR_JSON -r '.[] | select(.type|test("^Microsoft\\.ContainerRegistry/registries$";"i")) | select(.properties.adminUserEnabled==true) | "\(.id)\t\(.name)"'


  # AKS: enableRBAC == false
  run_jq AKS_JSON -r '.[] | select(.type|test("^Microsoft\\.ContainerService/managedClusters$";"i")) | select(.properties.enableRBAC==false) | "\(.id)\t\(.name)"'


  # AKS: disableLocalAccounts missing or false
  run_jq AKS_JSON -r '.[] | select(.type|test("^Microsoft\\.ContainerService/managedClusters$";"i")) | select((.properties.disableLocalAccounts? // false)==false) | "\(.id)\t\(.name)\tdisableLocalAccounts=\(.properties.disableLocalAccounts? // "MISSING")"'


  # AKS: authorised API server IP ranges empty
  run_jq AKS_JSON -r '.[] | select(.type|test("^Microsoft\\.ContainerService/managedClusters$";"i")) | select((.properties.apiServerAccessProfile.authorizedIPRanges? // [])|length==0) | "\(.id)\t\(.name)\tauthorisedIPRanges=EMPTY"'


  # App Service (sites/slots): missing managed identity type
  run_jq RESOURCES_JSON -r '.[] | select(.type|test("^Microsoft\\.Web/(sites|sites/slots)$";"i")) | select((.identity.type? // "")=="") | "\(.id)\t\(.name)\tidentity=MISSING"'


  # Tags hygiene: require specific tag keys
  run_jq RESOURCES_JSON -r --argjson req '["owner","environment","dataClassification","serviceTier"]' '.[] | select(type=="object" and (.id? != null)) | (.tags? // {}) as $t | ([ $req[] | select(($t[.]? // "")=="") ]) as $missing | select($missing|length>0) | "\(.id)\t\(.name)\tmissing=\($missing|join(","))"'


  # Naming vs tagging: prod in name but environment tag not prod
  run_jq RESOURCES_JSON -r '.[] | select((.name|tostring|test("(^|[^a-z])prod([^a-z]|$)";"i"))) | select(((.tags.environment? // "")|ascii_downcase) != "prod") | "\(.id)\t\(.name)\tenvTag=\(.tags.environment? // "MISSING")"'


  # Region policy: not in uksouth/ukwest
  run_jq RESOURCES_JSON -r --argjson regs '["uksouth","ukwest"]' '.[] | select((.location? // "") as $loc | ($regs|index($loc|ascii_downcase))==null) | "\(.id)\t\(.name)\tloc=\(.location? // "MISSING")"'

#30
  # Application Gateway: WAF disabled
  run_jq APPGATEWAYS_JSON -r '.[] | select(.type|test("^Microsoft\\.Network/applicationGateways$";"i")) | select((.properties.webApplicationFirewallConfiguration.enabled? // false)==false) | "\(.id)\t\(.name)\twafEnabled=false"'


  # Application Gateway: WAF enabled but Detection mode
  run_jq APPGATEWAYS_JSON -r '.[] | select(.type|test("^Microsoft\\.Network/applicationGateways$";"i")) | select((.properties.webApplicationFirewallConfiguration.enabled? // false)==true) | select((.properties.webApplicationFirewallConfiguration.firewallMode? // "")|ascii_downcase=="detection") | "\(.id)\t\(.name)\tmode=Detection"'


  # Application Gateway: SSL policy min protocol TLSv1.0/1.1
  run_jq APPGATEWAYS_JSON -r '.[] | select(.type|test("^Microsoft\\.Network/applicationGateways$";"i")) | select((.properties.sslPolicy.minProtocolVersion? // "")|tostring|test("TLSv1_0|TLSv1_1|1\\.0|1\\.1";"i")) | "\(.id)\t\(.name)\tminProto=\(.properties.sslPolicy.minProtocolVersion)"'


  # IoT Hubs: iothubowner shared access policy present
  run_jq RESOURCES_JSON -r '.[] | select(.type|test("^Microsoft\\.Devices/IotHubs$";"i")) | select((.properties.authorizationPolicies? // []) | any(.keyName?=="iothubowner")) | "\(.id)\t\(.name)\tiothubowner=present"'


  # App Configuration: feature flags referencing debug/admin/verbose
  run_jq RESOURCES_JSON -r '.[] | select(.type|test("^Microsoft\\.AppConfiguration/configurationStores$";"i")) | select((.properties.featureFlags? // [] ) | any((.key? // "" )|test("debug|admin|verbose";"i"))) | "\(.id)\t\(.name)"'


  # NSGs: inbound Allow any source to admin ports
  run_jq NSGS_JSON -r 'def anysrc:   ((.sourceAddressPrefix? // "")|IN("*","0.0.0.0/0","Internet"))   or ((.sourceAddressPrefixes? // [])|any(IN("*","0.0.0.0/0","Internet"))); def adminport:   ((.destinationPortRange? // "")|test("^(22|3389|5985|5986)$|^(22|3389|5985|5986)-|-(22|3389|5985|5986)$|\\*$"))  or ((.destinationPortRanges? // [])|any(test("^(22|3389|5985|5986)$|\\*$"))); .[] | select(.type|test("^Microsoft\\.Network/networkSecurityGroups$";"i")) | (.properties.securityRules? // []) | map(select(.direction=="Inbound" and .access=="Allow" and anysrc and adminport)) | .[] | "\(.id)\t\(.name)\trule=\(.name)\tprio=\(.priority)"'


  # NSGs: inbound Allow any source to common data ports
  run_jq NSGS_JSON -r 'def anysrc: ((.sourceAddressPrefix? // "")|IN("*","0.0.0.0/0","Internet")) or ((.sourceAddressPrefixes? // [])|any(IN("*","0.0.0.0/0","Internet"))); def dataport: ((.destinationPortRange? // "")|test("^(1433|3306|5432|6379|9200|27017|5601|8080|8443|2375|2376|10250)$|\\*$")) or ((.destinationPortRanges? // [])|any(test("^(1433|3306|5432|6379|9200|27017|5601|8080|8443|2375|2376|10250)$|\\*$"))); .[] | select(.type|test("^Microsoft\\.Network/networkSecurityGroups$";"i")) | (.properties.securityRules? // []) | map(select(.direction=="Inbound" and .access=="Allow" and anysrc and dataport)) | .[] | "\(.id)\t\(.name)\trule=\(.name)\tprio=\(.priority)"'


  # NSGs: inbound Allow any source to overly-wide port ranges
  run_jq NSGS_JSON -r 'def anysrc: ((.sourceAddressPrefix? // "")|IN("*","0.0.0.0/0","Internet")) or ((.sourceAddressPrefixes? // [])|any(IN("*","0.0.0.0/0","Internet"))); def wideports: ((.destinationPortRange? // "")|test("^\\*$|^0-65535$|^1-65535$|^1000-65535$")) or ((.destinationPortRanges? // [])|any(test("^\\*$|^0-65535$|^1-65535$|^1000-65535$"))); .[] | select(.type|test("^Microsoft\\.Network/networkSecurityGroups$";"i")) | (.properties.securityRules? // []) | map(select(.direction=="Inbound" and .access=="Allow" and anysrc and wideports)) | .[] | "\(.id)\t\(.name)\trule=\(.name)\tports=\(.destinationPortRange? // ((.destinationPortRanges? // [])|join(",")) )"'


  # NSGs: suspicious temp/test/debug Allow rules with high precedence
  run_jq NSGS_JSON -r '.[] | select(.type|test("^Microsoft\\.Network/networkSecurityGroups$";"i")) | (.properties.securityRules? // []) | map(select(.access=="Allow" and (.name|test("temp|test|debug";"i")) and (.priority? // 99999) < 2000)) | .[] | "\(.id)\t\(.name)\trule=\(.name)\tprio=\(.priority)"'

#40
  # NSGs: outbound Allow rules to Internet/any destination
  run_jq NSGS_JSON -r 'def internetdst: ((.destinationAddressPrefix? // "")|IN("*","0.0.0.0/0","Internet")) or ((.destinationAddressPrefixes? // [])|any(IN("*","0.0.0.0/0","Internet"))); .[] | select(.type|test("^Microsoft\\.Network/networkSecurityGroups$";"i")) | (.properties.securityRules? // []) | map(select(.direction=="Outbound" and .access=="Allow" and internetdst)) | .[] | "\(.id)\t\(.name)\trule=\(.name)\tprio=\(.priority)"'


  # Storage accounts: networkAcls defaultAction Allow
  run_jq STORAGE_JSON -r '.[] | select(.type|test("^Microsoft\\.Storage/storageAccounts$";"i")) | select((.properties.networkAcls.defaultAction? // "")=="Allow") | "\(.id)\t\(.name)\tdefaultAction=Allow"'


  # Storage accounts: networkAcls bypass includes AzureServices
  run_jq STORAGE_JSON -r '.[] | select(.type|test("^Microsoft\\.Storage/storageAccounts$";"i")) | select((.properties.networkAcls.bypass? // "")|test("AzureServices";"i")) | "\(.id)\t\(.name)\tbypass=\(.properties.networkAcls.bypass)"'


  # Storage accounts: publicNetworkAccess enabled but no ipRules
  run_jq STORAGE_JSON -r '.[] | select(.type|test("^Microsoft\\.Storage/storageAccounts$";"i")) | select((.properties.publicNetworkAccess? // "Enabled")|ascii_downcase=="enabled") | select((.properties.networkAcls.ipRules? // [])|length==0) | "\(.id)\t\(.name)\tipRules=EMPTY publicNetworkAccess=Enabled"'


  # Storage accounts: no virtualNetworkRules
  run_jq STORAGE_JSON -r '.[] | select(.type|test("^Microsoft\\.Storage/storageAccounts$";"i")) | select((.properties.networkAcls.virtualNetworkRules? // [])|length==0) | "\(.id)\t\(.name)\tvnetRules=EMPTY"'


  # SQL firewall rules: allow all IPs or Azure services shortcut
  run_jq SQL_FIREWALL_RULES_JSON -r '.[] | select(.type|test("^Microsoft\\.Sql/servers/firewallRules$";"i")) | select((.properties.startIpAddress?=="0.0.0.0" and .properties.endIpAddress?=="255.255.255.255") or (.properties.startIpAddress?=="0.0.0.0" and .properties.endIpAddress?=="0.0.0.0")) | "\(.id)\t\(.name)\t\(.properties.startIpAddress)-\(.properties.endIpAddress)"'


  # App Service config: no ipSecurityRestrictions
  run_jq APP_SITE_CONFIG_JSON -r '.[] | select(.type|test("^Microsoft\\.Web/sites/config$";"i")) | select((.properties.ipSecurityRestrictions? // [])|length==0) | "\(.id)\t\(.name)\tipSecurityRestrictions=EMPTY"'


  # App Service config: no scmIpSecurityRestrictions
  run_jq APP_SITE_CONFIG_JSON -r '.[] | select(.type|test("^Microsoft\\.Web/sites/config$";"i")) | select((.properties.scmIpSecurityRestrictions? // [])|length==0) | "\(.id)\t\(.name)\tscmIpSecurityRestrictions=EMPTY"'


  # ServiceBus/EventHub auth rules and EventGrid role assignments: Manage rights
  run_jq RESOURCES_JSON -r '.[] | select(.type|test("^Microsoft\\.(ServiceBus/namespaces/authorizationRules|EventHub/namespaces/authorizationRules|EventGrid/topics/providers/Microsoft\\.Authorization/roleAssignments)$";"i")) | select((.properties.rights? // [])|any(.=="Manage")) | "\(.id)\t\(.name)\trights=\((.properties.rights)|join(","))"'

#50
  # Diagnostics coverage: resources missing any diagnostic setting (requires DIAG_SETTINGS_JSON)
  if [[ -n "${DIAG_SETTINGS_JSON}" && -f "${DIAG_SETTINGS_JSON}" ]]; then
    run_jq_multi DIAG_SETTINGS_JSON -r -s '
      .[0] as $res
      | .[1] as $diag
      | ($diag
          | map(select(.type|test("^Microsoft\\.Insights/diagnosticSettings$";"i")))
          | map(.properties.scope? // .properties.resourceId? // "")
          | map(select(.!=""))
          | unique) as $have
      | $res[]
      | select(.id? and (.type|test("^Microsoft\\."; "i")))
      | select(($have|index(.id))==null)
      | "\(.id)\t\(.type)\t\(.name)\tNO_DIAG"
    ' -- "${RESOURCES_JSON}" "${DIAG_SETTINGS_JSON}"
  else
    warn "Skipping diagnostics coverage: DIAG_SETTINGS_JSON not found"
  fi


  # Diagnostic settings: no sinks configured
  run_jq DIAG_SETTINGS_JSON -r '.[] | select(.type|test("^Microsoft\\.Insights/diagnosticSettings$";"i")) | select((.properties.workspaceId? // "")=="" and (.properties.storageAccountId? // "")=="" and (.properties.eventHubAuthorizationRuleId? // "")=="") | "\(.id)\tsinks=NONE"'


  # Diagnostic settings: no log categories enabled
  run_jq DIAG_SETTINGS_JSON -r '.[] | select(.type|test("^Microsoft\\.Insights/diagnosticSettings$";"i")) | select((.properties.logs? // []) | map(select(.enabled==true)) | length==0) | "\(.id)\tNO_ENABLED_LOGS"'


  # Diagnostic settings: enabled retentionPolicy days < 90
  run_jq DIAG_SETTINGS_JSON -r --argjson min 90 '.[] | select(.type|test("^Microsoft\\.Insights/diagnosticSettings$";"i")) | (.properties.logs? // [])[] | select((.retentionPolicy.enabled? // false)==true and (.retentionPolicy.days? // 0) < $min) | "\(.id)\tcategory=\(.category)\tdays=\(.retentionPolicy.days)"'


  # Network Watcher coverage: locations missing a Network Watcher
  run_jq_multi NO_NETWORK_WATCHER -r -s '
    .[0] as $res
    | ($res | map(.location? // empty | ascii_downcase) | unique) as $all
    | ($res | map(select(.type|test("^Microsoft\\.Network/networkWatchers$";"i")) | (.location|ascii_downcase)) | unique) as $have
    | $all[]
    | select(($have|index(.))==null)
    | "NO_NETWORK_WATCHER\t\(.)"
  ' -- "${RESOURCES_JSON}"


  # Management locks: resources not covered by any lock scope prefix
  run_jq_multi NO_LOCK_MATCH -r -s '
    .[0] as $res
    | ($res
        | map(select(.type|test("^Microsoft\\.Authorization/locks$";"i"))
              | (.properties.scope? // .id? // "" ) | tostring)
        | map(select(.!=""))
        | unique) as $locks
    | $res[]
    | select(.id? and (.type|test("^Microsoft\\."; "i")))
    | .id as $rid
    | select(($locks | any(. != "" and ($rid|startswith(.)))) | not)
    | "\(.id)\t\(.type)\t\(.name)\tNO_LOCK_MATCH"
  ' -- "${RESOURCES_JSON}"


  # Policy assignments: non-default enforcementMode (policyDefinitionId present)
  run_jq POLICY_ASSIGNMENTS_JSON -r '.[] | select(.type|test("^Microsoft\\.Authorization/policyAssignments$";"i")) | select((.properties.policyDefinitionId? // "")!="" and ((.properties.enforcementMode? // "Default")|ascii_downcase) != "default") | "\(.id)\t\(.name)\tenforcementMode=\(.properties.enforcementMode)"'


  # Privileged RBAC at top scope: Owner/UAA/Contributor at MG root or subscription root
  run_jq_multi PRIVILEGED_RBAC_AT_ROOT -r -s '
    .[0] as $res
    | ($res
        | map(select(.type|test("^Microsoft\\.Authorization/roleDefinitions$";"i"))
              | {k:(.id|ascii_downcase), n:(.properties.roleName? // "")})
        | from_entries) as $rd
    | $res[]
    | select(.type|test("^Microsoft\\.Authorization/roleAssignments$";"i"))
    | (.properties.roleDefinitionId? // "" | ascii_downcase) as $rid
    | ($rd[$rid] // "") as $rname
    | select($rname|IN("Owner","User Access Administrator","Contributor"))
    | select((.properties.scope? // "") | test("^/providers/Microsoft\\.Management/managementGroups/|^/subscriptions/[^/]+$";"i"))
    | "\(.id)\trole=\($rname)\tscope=\(.properties.scope)"
  ' -- "${RESOURCES_JSON}"


  # Role assignments: orphaned principals, guest principals, disabled principals (requires USERS_JSON)
  if [[ -n "${USERS_JSON}" && -f "${USERS_JSON}" ]]; then
    run_jq_multi ORPHANED_PRINCIPALS -r -s '
      .[0] as $ra
      | .[1] as $p
      | ($p | map({k:((.id? // .objectId?)|tostring), v:.}) | from_entries) as $pm
      | $ra[]
      | select(.type|test("^Microsoft\\.Authorization/roleAssignments$";"i"))
      | (.properties.principalId? // "" | tostring) as $pid
      | ($pm[$pid] // null) as $pr
      | if $pr==null then
          "\(.id)\tORPHAN_PRINCIPAL\tprincipalId=\($pid)\tscope=\(.properties.scope)"
        elif (($pr.userType? // "")=="Guest") then
          "\(.id)\tGUEST_PRINCIPAL\tprincipalId=\($pid)\tscope=\(.properties.scope)"
        elif (($pr.accountEnabled? // true)==false) then
          "\(.id)\tDISABLED_PRINCIPAL\tprincipalId=\($pid)\tscope=\(.properties.scope)"
        else empty end
    ' -- "${ROLE_ASSIGNMENTS_JSON}" "${USERS_JSON}"
  else
    warn "Skipping principal join checks: USERS_JSON not found"
  fi


  # Role assignments: no condition string
  run_jq ROLE_ASSIGNMENTS_JSON -r '.[] | select(.type|test("^Microsoft\\.Authorization/roleAssignments$";"i")) | select((.properties.condition? // "")=="") | "\(.id)\t\(.properties.scope)\tNO_CONDITION"'

#60
  # Role definitions: wildcard actions or Microsoft.Authorization write
  run_jq ROLE_DEFINITIONS_JSON -r '.[] | select(.type|test("^Microsoft\\.Authorization/roleDefinitions$";"i")) | (.properties.permissions? // [])[] as $perm | select(($perm.actions? // [])|any(.=="*" or test("Microsoft\\.Authorization/.*/write";"i"))) | "\(.id)\t\(.properties.roleName)\tWILDCARD_OR_AUTHZ_WRITE"'


  # Role definitions: assignable to "/" or management group scope
  run_jq ROLE_DEFINITIONS_JSON -r '.[] | select(.type|test("^Microsoft\\.Authorization/roleDefinitions$";"i")) | select((.properties.assignableScopes? // [])|any(.=="/" or test("^/providers/Microsoft\\.Management/managementGroups/[^/]+$";"i"))) | "\(.id)\t\(.properties.roleName)\tscopes=\((.properties.assignableScopes)|join(","))"'


  # User-assigned managed identities: UAIs referenced by multiple resources
  run_jq RESOURCES_JSON -r -s '.[0] as $res | ($res | map(select(.identity.userAssignedIdentities?) | (.identity.userAssignedIdentities|keys[] as $uai | {rid:.id, uai:$uai})) | group_by(.uai) | map(select(length>1)) | .[] | "\(.uai)\tused_by=\([.[].rid]|join(","))" )' "${RESOURCES_JSON}" || true


  # App Service sites: no MI and secrets in appSettings
  run_jq RESOURCES_JSON -r '.[] | select(.type|test("^Microsoft\\.Web/sites$";"i")) | select((.identity.type? // "")=="") | select((.properties.siteConfig.appSettings? // []) | any((.value? // "")|test("AccountKey=|SharedAccessKey=|sig=|eyJ[A-Za-z0-9_-]+\\."; "i"))) | "\(.id)\t\(.name)\tNO_MI_BUT_SECRETS_IN_SETTINGS"'


  # App Service config: secret-like patterns in appSettings values
  run_jq APP_SITE_CONFIG_JSON -r 'def is_secret: test("AccountKey=|SharedAccessKey=|SharedAccessSignature|sig=|se=|spr=|sv=|eyJ[A-Za-z0-9_-]+\\.|Bearer\\s+|-----BEGIN [A-Z ]+-----"; "i"); .[] | select(.type|test("^Microsoft\\.Web/sites/config$";"i")) | (.properties.appSettings? // [])[] | select((.value? // "")|tostring|is_secret) | "\(.id)\tkey=\(.name)\tvalue_snip=\((.value|tostring)[0:80])"'


  # Virtual Machines: osProfile.customData secret-like patterns
  run_jq VMS_JSON -r 'def is_secret: test("AccountKey=|SharedAccessKey=|sig=|eyJ[A-Za-z0-9_-]+\\.|-----BEGIN [A-Z ]+-----"; "i"); .[] | select(.type|test("^Microsoft\\.Compute/virtualMachines$";"i")) | select((.properties.osProfile.customData? // "")|tostring|is_secret) | "\(.id)\t\(.name)\tCUSTOMDATA_SECRET"'


  # Template Specs: mainTemplate contains secret-ish strings or risky defaults
  run_jq RESOURCES_JSON -r 'def bad: test("AccountKey=|SharedAccessKey=|sig=|publicNetworkAccess\"\\s*:\\s*\"Enabled\"|defaultAction\"\\s*:\\s*\"Allow\""; "i"); .[] | select(.type|test("^Microsoft\\.Resources/templateSpecs/versions$";"i")) | select((.properties.mainTemplate? // "" )|tostring|bad) | "\(.id)\t\(.name)\tTEMPLATESPEC_SUSPECT"'


  # App Configuration: properties contain debug/admin/verbose/trace tokens
  run_jq RESOURCES_JSON -r 'def bad: test("debug|admin|verbose|trace";"i"); .[] | select(.type|test("^Microsoft\\.AppConfiguration/configurationStores$";"i")) | select((.properties|tostring)|bad) | "\(.id)\t\(.name)\tPOSSIBLE_DEBUG_TOGGLE"'


  # App Service sites: CORS allowedOrigins includes "*"
  run_jq RESOURCES_JSON -r '.[] | select(.type|test("^Microsoft\\.Web/sites$";"i")) | select((.properties.siteConfig.cors.allowedOrigins? // []) | any(.=="*")) | "\(.id)\t\(.name)\tCORS_STAR"'


  # Network interfaces: NICs referencing any public IP (requires NICS_JSON and PUBLIC_IPS_JSON ideally)
  run_jq_multi HAS_PUBLIC_IP -r -s '
    .[0] as $res
    | ($res | map(select(.type|test("^Microsoft\\.Network/publicIPAddresses$";"i")) | {k:.id, v:1}) | from_entries) as $pips
    | $res[]
    | select(.type|test("^Microsoft\\.Network/networkInterfaces$";"i"))
    | select((.properties.ipConfigurations? // []) | any(.properties.publicIPAddress.id? as $pid | $pips[$pid]==1))
    | "\(.id)\t\(.name)\tHAS_PUBLIC_IP"
  ' -- "${RESOURCES_JSON}"

#70
  # App Service exposure: publicNetworkAccess enabled, no IP restrictions, auth disabled
  run_jq_multi PUBLIC_NO_RESTRICTIONS_AUTH_OFF -r -s '
    .[0] as $res
    | ($res
        | map(select(.type|test("^Microsoft\\.Web/sites/config$";"i"))
              | {k:(.id|sub("/config/[^/]+$";"")), v:.})
        | from_entries) as $cfg
    | $res[]
    | select(.type|test("^Microsoft\\.Web/sites$";"i"))
    | (.id) as $id
    | ($cfg[$id] // {}) as $c
    | select((.properties.publicNetworkAccess? // "Enabled")|ascii_downcase=="enabled")
    | select((($c.properties.ipSecurityRestrictions? // [])|length)==0)
    | select((($c.properties.authSettingsV2.enabled? // $c.properties.authSettings.enabled? // false))==false)
    | "\($id)\t\(.name)\tPUBLIC_NO_RESTRICTIONS_AUTH_OFF"
  ' -- "${RESOURCES_JSON}"


  # Private Endpoints: targets whose publicNetworkAccess is enabled
  run_jq_multi TARGET_PUBLIC_ACCESS_ENABLED -r -s '
    .[0] as $res
    | ($res
        | map(select(.type|test("^Microsoft\\.Network/privateEndpoints$";"i"))
              | (.properties.privateLinkServiceConnections? // [])[]
              | {pe:.id, target:(.properties.privateLinkServiceId? // "")})
        | map(select(.target!="")) ) as $links
    | ($res | map({k:.id, v:.}) | from_entries) as $rm
    | $links[]
    | ($rm[.target] // null) as $t
    | select($t!=null)
    | select((($t.properties.publicNetworkAccess? // "Enabled")|ascii_downcase)=="enabled")
    | "\(.pe)\ttarget=\(.target)\tTARGET_PUBLIC_ACCESS_ENABLED"
  ' -- "${RESOURCES_JSON}"


  # Effective security rules: inbound Allow from Internet/*
  run_jq EFFECTIVE_RULES_JSON -r '.[] | select(.effectiveSecurityRules?) | (.effectiveSecurityRules[] | select(.access=="Allow" and .direction=="Inbound" and ((.sourceAddressPrefix? // "")|IN("*","Internet","0.0.0.0/0")))) | "\(.name)\t\(.destinationPortRange? // "")"'


  # Route tables: 0.0.0.0/0 -> Internet (generic schema)
  run_jq ROUTE_TABLES_JSON -r '.[] | (.value? // .routes? // .properties.routes? // [])[] | select((.addressPrefix? // .properties.addressPrefix? // "")=="0.0.0.0/0" and ((.nextHopType? // .properties.nextHopType? // "")|ascii_downcase=="internet")) | "\(.name)\t0.0.0.0/0 -> Internet"'


  # Private Endpoints: Pending or Rejected state
  run_jq PRIVATE_ENDPOINTS_JSON -r '.[] | select(.type|test("^Microsoft\\.Network/privateEndpoints$";"i")) | (.properties.privateLinkServiceConnections? // [])[] | select((.properties.privateLinkServiceConnectionState.status? // "")|test("Pending|Rejected";"i")) | "\(.id)\tstatus=\(.properties.privateLinkServiceConnectionState.status)\tdesc=\(.properties.privateLinkServiceConnectionState.description? // "")"'


  # Public IPs: unassociated (no ipConfiguration)
  run_jq PUBLIC_IPS_JSON -r '.[] | select(.type|test("^Microsoft\\.Network/publicIPAddresses$";"i")) | select((.properties.ipConfiguration? // null)==null) | "\(.id)\t\(.name)\tUNATTACHED_PUBLIC_IP"'


  # User-assigned identities: unused UAIs
  run_jq_multi UNUSED_UAI -r -s '
    .[0] as $res
    | ($res | map(select(.type|test("^Microsoft\\.ManagedIdentity/userAssignedIdentities$";"i"))|.id) | unique) as $uais
    | ($res | map(.identity.userAssignedIdentities? // {} | keys[]) | add | unique) as $refs
    | $uais[]
    | select(($refs|index(.))==null)
    | "UNUSED_UAI\t\(.)"
  ' -- "${RESOURCES_JSON}"


  # Metric alerts: no actions
  run_jq METRIC_ALERTS_JSON -r '.[] | select(.type|test("^Microsoft\\.Insights/metricAlerts$";"i")) | select((.properties.actions? // [])|length==0) | "\(.id)\t\(.name)\tNO_ACTIONS"'


  # Scheduled query rules: disabled
  run_jq SCHEDULED_QUERY_RULES_JSON -r '.[] | select(.type|test("^Microsoft\\.Insights/scheduledQueryRules$";"i")) | select((.properties.enabled? // true)==false) | "\(.id)\t\(.name)\tDISABLED"'


  # Policy assignments: enforcementMode not Default
  run_jq POLICY_ASSIGNMENTS_JSON -r '.[] | select(.type|test("^Microsoft\\.Authorization/policyAssignments$";"i")) | select((.properties.enforcementMode? // "Default")|ascii_downcase!="default") | "\(.id)\t\(.name)\tenforcementMode=\(.properties.enforcementMode)"'

#80
  # Policy exemptions: missing expiresOn or description
  run_jq RESOURCES_JSON -r '.[] | select(.type|test("^Microsoft\\.Authorization/policyExemptions$";"i")) | select((.properties.expiresOn? // "")=="" or (.properties.description? // "")=="" ) | "\(.id)\t\(.name)\texpiresOn=\(.properties.expiresOn? // "MISSING")\tdesc=\(.properties.description? // "MISSING")"'


  # Consumption/usage-like records: quantity > 0
  run_jq CONSUMPTION_JSON -r '.[] | select((.quantity? // 0) > 0) | "\(.date)\t\(.resourceId)\t\(.meter)\t\(.quantity)"'


  # Defender for Cloud pricing: Free or missing
  run_jq SECURITY_PRICINGS_JSON -r '.[] | select(.type|test("^Microsoft\\.Security/pricings$";"i")) | select((.properties.pricingTier? // "")|ascii_downcase=="free" or (.properties.pricingTier? // "")=="") | "\(.id)\t\(.name)\tpricingTier=\(.properties.pricingTier? // "MISSING")"'


  # Entra users: all guest users
  run_jq USERS_JSON -r '.[] | select((.userType? // "")=="Guest") | "\(.id // .objectId)\t\(.userPrincipalName)\tGuest"'


  # Guests with any RBAC role assignment (join users + role assignments)
  if [[ -n "${USERS_JSON}" && -f "${USERS_JSON}" ]]; then
    run_jq_multi GUESTS_WITH_RBAC -r -s '
      .[0] as $u
      | .[1] as $ra
      | ($u | map({k:((.id // .objectId)|tostring), v:.}) | from_entries) as $um
      | $ra[]
      | select((.properties.principalId? // "") != "")
      | (.properties.principalId|tostring) as $pid
      | ($um[$pid] // null) as $usr
      | select($usr != null and ($usr.userType? // "")=="Guest")
      | "\(.id)\tscope=\(.properties.scope)\troleDef=\(.properties.roleDefinitionId)\tprincipal=\($usr.userPrincipalName)\tGuest"
    ' -- "${USERS_JSON}" "${ROLE_ASSIGNMENTS_JSON}"
  else
    warn "Skipping guest RBAC join: USERS_JSON not found"
  fi


  # Guests in privileged groups (requires group membership inventory + privileged group list)
  if [[ -n "${GROUP_MEMBERSHIPS_JSON}" && -f "${GROUP_MEMBERSHIPS_JSON}" && -n "${PRIV_GROUP_IDS_JSON}" && -f "${PRIV_GROUP_IDS_JSON}" && -n "${USERS_JSON}" && -f "${USERS_JSON}" ]]; then
    run_jq_multi PRIVILEGED_GROUP_GUESTS -r -s '
      .[0] as $u
      | .[1] as $m
      | .[2] as $pg
      | ($pg | map(tostring) | unique) as $priv
      | ($u | map({k:((.id // .objectId)|tostring), v:.}) | from_entries) as $um
      | $m[]
      | select(($priv | index((.groupId|tostring))) != null)
      | (.memberId|tostring) as $mid
      | ($um[$mid] // null) as $usr
      | select($usr != null and ($usr.userType? // "")=="Guest")
      | "group=\(.groupId)\tmember=\($usr.userPrincipalName)\tGuest"
    ' -- "${USERS_JSON}" "${GROUP_MEMBERSHIPS_JSON}" "${PRIV_GROUP_IDS_JSON}"
  else
    warn "Skipping privileged group guest check: missing USERS_JSON/GROUP_MEMBERSHIPS_JSON/PRIV_GROUP_IDS_JSON"
  fi


  # Entra users: disabled accounts
  run_jq USERS_JSON -r '.[] | select((.accountEnabled? // true)==false) | "\(.id // .objectId)\t\(.userPrincipalName)\taccountEnabled=false"'


  # Disabled users that still have RBAC assignments
  if [[ -n "${USERS_JSON}" && -f "${USERS_JSON}" ]]; then
    run_jq_multi DISABLED_USERS_WITH_RBAC -r -s '
      .[0] as $u
      | .[1] as $ra
      | ($u | map({k:((.id // .objectId)|tostring), v:.}) | from_entries) as $um
      | $ra[]
      | (.properties.principalId|tostring) as $pid
      | ($um[$pid] // null) as $usr
      | select($usr != null and ($usr.accountEnabled? // true)==false)
      | "\(.id)\tscope=\(.properties.scope)\troleDef=\(.properties.roleDefinitionId)\tprincipal=\($usr.userPrincipalName)\tDISABLED_HAS_RBAC"
    ' -- "${USERS_JSON}" "${ROLE_ASSIGNMENTS_JSON}"
  else
    warn "Skipping disabled-user RBAC join: USERS_JSON not found"
  fi


  # Entra users: weak passwordPolicies flags
  run_jq USERS_JSON -r '.[] | select((.passwordPolicies? // "") | test("DisableStrongPassword|DisablePasswordExpiration")) | "\(.id // .objectId)\t\(.userPrincipalName)\tpasswordPolicies=\(.passwordPolicies)"'


  # On-prem synced accounts holding privileged roles (requires USERS, ROLE_ASSIGNMENTS, ROLE_DEFINITIONS)
  if [[ -n "${USERS_JSON}" && -f "${USERS_JSON}" ]]; then
    run_jq_multi PRIVILEGED_ON_PREM_ACCOUNTS -r -s '
      .[0] as $u
      | .[1] as $ra
      | .[2] as $rd
      | ($u | map({k:((.id // .objectId)|tostring), v:.}) | from_entries) as $um
      | ($rd | map({k:(.id|ascii_downcase), v:(.properties.roleName? // "")}) | from_entries) as $rmap
      | $ra[]
      | (.properties.principalId|tostring) as $pid
      | ($um[$pid] // null) as $usr
      | select($usr != null and ($usr.onPremisesSyncEnabled? // false)==true)
      | (.properties.roleDefinitionId|ascii_downcase) as $rid
      | ($rmap[$rid] // "") as $rname
      | select($rname|test("Global Administrator|Privileged Role Administrator|User Access Administrator|Owner|Security Administrator|Conditional Access Administrator|Exchange Administrator|SharePoint Administrator|Cloud Application Administrator"; "i"))
      | "\(.id)\tscope=\(.properties.scope)\trole=\($rname)\tprincipal=\($usr.userPrincipalName)\tonPremSync=true"
    ' -- "${USERS_JSON}" "${ROLE_ASSIGNMENTS_JSON}" "${ROLE_DEFINITIONS_JSON}"
  else
    warn "Skipping on-prem synced privileged roles: USERS_JSON not found"
  fi

#90
  # App registrations: multi-tenant or personal audiences
  run_jq APPS_JSON -r '.[] | select((.signInAudience? // .api.signInAudience? // "") | test("AzureADMultipleOrgs|AzureADandPersonalMicrosoftAccount|PersonalMicrosoftAccount"; "i")) | "\(.appId)\t\(.displayName)\tsignInAudience=\(.signInAudience? // .api.signInAudience?)"'


  # App registrations: OAuth implicit grant enabled
  run_jq APPS_JSON -r '.[] | select((.oauth2AllowImplicitFlow? // false)==true or (.oauth2AllowIdTokenImplicitFlow? // false)==true) | "\(.appId)\t\(.displayName)\timplicitFlow=\(.oauth2AllowImplicitFlow? // false)\tidTokenImplicit=\(.oauth2AllowIdTokenImplicitFlow? // false)"'


  # App registrations: public client flows enabled
  run_jq APPS_JSON -r '.[] | select((.isFallbackPublicClient? // false)==true or (.allowPublicClient? // false)==true or ((.publicClient? // {})|length>0)) | "\(.appId)\t\(.displayName)\tpublicClient=true"'


  # App registrations: missing/empty owners array
  run_jq APPS_JSON -r '.[] | select(((.owners? // [])|length)==0) | "\(.appId)\t\(.displayName)\tNO_OWNERS"'


  # App registrations owners are disabled or guests (requires APPS enriched with .owners)
  if [[ -n "${APPS_JSON}" && -f "${APPS_JSON}" && -n "${USERS_JSON}" && -f "${USERS_JSON}" ]]; then
    run_jq_multi APP_OWNER_REGISTRATIONS  -r -s '
      .[0] as $apps
      | .[1] as $u
      | ($u | map({k:((.id // .objectId)|tostring), v:.}) | from_entries) as $um
      | $apps[]
      | (.owners? // [])[]? as $oid
      | ($um[($oid|tostring)] // null) as $owner
      | select($owner != null and ((($owner.accountEnabled? // true)==false) or (($owner.userType? // "")=="Guest")))
      | "\(.appId)\t\(.displayName)\towner=\($owner.userPrincipalName)\townerEnabled=\($owner.accountEnabled? // true)\townerType=\($owner.userType? // "")"
    ' -- "${APPS_JSON}" "${USERS_JSON}"
  else
    warn "Skipping app-owner user join: missing APPS_JSON/USERS_JSON"
  fi


  # Service principals: disabled entities
  run_jq SPS_JSON -r '.[] | select((.accountEnabled? // true)==false) | "\(.id // .objectId)\t\(.appId)\t\(.displayName)\taccountEnabled=false"'


  # Disabled SPs that still have RBAC (requires SPS_JSON)
  if [[ -n "${SPS_JSON}" && -f "${SPS_JSON}" ]]; then
    run_jq_multi DISABLED_SPS_WITH_RBACK -r -s '
      .[0] as $sp
      | .[1] as $ra
      | ($sp | map({k:((.id // .objectId)|tostring), v:.}) | from_entries) as $spm
      | $ra[]
      | (.properties.principalId|tostring) as $pid
      | ($spm[$pid] // null) as $p
      | select($p != null and ($p.accountEnabled? // true)==false)
      | "\(.id)\tscope=\(.properties.scope)\troleDef=\(.properties.roleDefinitionId)\tsp=\($p.displayName)\tappId=\($p.appId)\tDISABLED_SP_HAS_RBAC"
    ' -- "${SPS_JSON}" "${ROLE_ASSIGNMENTS_JSON}"
  else
    warn "Skipping disabled SP RBAC join: SPS_JSON not found"
  fi


  # Service principals: legacy tags
  run_jq SPS_JSON -r '.[] | select(((.tags? // []) | map(tostring) | join(" ")) | test("WindowsAzureActiveDirectoryIntegratedApp|legacy"; "i")) | "\(.id // .objectId)\t\(.displayName)\tappId=\(.appId)\ttags=\((.tags? // [])|join(","))"'


  # Legacy-tagged SPs with top-scope RBAC or toxic roles (requires SPS + ROLE_ASSIGNMENTS + ROLE_DEFINITIONS)
  if [[ -n "${SPS_JSON}" && -f "${SPS_JSON}" ]]; then
    run_jq_multi LEGACY_SPS_WITH_BAD_RBAC -r -s '
      .[0] as $sp
      | .[1] as $ra
      | .[2] as $rd
      | ($sp | map({k:((.id // .objectId)|tostring), v:.}) | from_entries) as $spm
      | ($rd | map({k:(.id|ascii_downcase), v:(.properties.roleName? // "")}) | from_entries) as $rmap
      | $ra[]
      | (.properties.principalId|tostring) as $pid
      | ($spm[$pid] // null) as $p
      | select($p != null)
      | select(((($p.tags? // [])|map(tostring)|join(" ")) | test("WindowsAzureActiveDirectoryIntegratedApp|legacy"; "i")))
      | (.properties.roleDefinitionId|ascii_downcase) as $rid
      | ($rmap[$rid] // "ROLE_NAME_UNKNOWN") as $rname
      | select((.properties.scope? // "") | test("^/subscriptions/[^/]+$|^/providers/Microsoft\\.Management/managementGroups/"; "i") or ($rname|test("Owner|User Access Administrator|Contributor";"i")))
      | "\(.id)\tscope=\(.properties.scope)\trole=\($rname)\tsp=\($p.displayName)\tappId=\($p.appId)"
    ' -- "${SPS_JSON}" "${ROLE_ASSIGNMENTS_JSON}" "${ROLE_DEFINITIONS_JSON}"
  else
    warn "Skipping legacy SP RBAC join: SPS_JSON not found"
  fi


  # Permission sets: Microsoft.Authorization ops
  run_jq PERMISSION_SETS_JSON -r '.[] | select((.actions? // []) | any(test("^Microsoft\\.Authorization/";"i")) or (.dataActions? // []) | any(test("^Microsoft\\.Authorization/";"i"))) | "\(.roleId // .id)\t\(.roleName)\tHAS_MICROSOFT_AUTHORIZATION"'

#100
  # Permission sets: Key Vault vault write + secret read
  run_jq PERMISSION_SETS_JSON -r '.[] | select(((.actions? // []) | any(test("^Microsoft\\.KeyVault/vaults/.*/write$";"i"))) and (((.actions? // []) | any(test("^Microsoft\\.KeyVault/vaults/secrets/(get|list)/action$";"i"))) or ((.dataActions? // []) | any(test("^Microsoft\\.KeyVault/vaults/secrets/(get|list)/action$";"i"))))) | "\(.roleId // .id)\t\(.roleName)\tKV_WRITE_PLUS_SECRET_READ"'


  # Permission sets: Storage listKeys
  run_jq PERMISSION_SETS_JSON -r '.[] | select((.actions? // []) | any(.=="Microsoft.Storage/storageAccounts/listKeys/action") or (.dataActions? // []) | any(.=="Microsoft.Storage/storageAccounts/listKeys/action")) | "\(.roleId // .id)\t\(.roleName)\tSTORAGE_LIST_KEYS"'


  # Permission sets: VM runCommand or extensions/write
  run_jq PERMISSION_SETS_JSON -r '.[] | select(((.actions? // []) | any(.=="Microsoft.Compute/virtualMachines/runCommand/action" or test("^Microsoft\\.Compute/virtualMachines/extensions/write$";"i"))) or ((.dataActions? // []) | any(.=="Microsoft.Compute/virtualMachines/runCommand/action" or test("^Microsoft\\.Compute/virtualMachines/extensions/write$";"i")))) | "\(.roleId // .id)\t\(.roleName)\tVM_CODE_EXEC_PRIMITIVE"'


  # Permission sets: wildcard actions
  run_jq PERMISSION_SETS_JSON -r '.[] | select((.actions? // []) | any(.=="*") or (.dataActions? // []) | any(.=="*")) | "\(.roleId // .id)\t\(.roleName)\tWILDCARD_ACTIONS"'


  # Policy state records: top 50 policyDefinitionId by NonCompliant count
  run_jq RESOURCES_JSON -r 'map(select((.complianceState? // "")=="NonCompliant")) | group_by(.policyDefinitionId) | map({policyDefinitionId: .[0].policyDefinitionId, nonCompliant: length}) | sort_by(.nonCompliant) | reverse | .[0:50][] | "\(.nonCompliant)\t\(.policyDefinitionId)"'


  # Policy state records: NonCompliant per baseline assignment (SEC-BASELINE prefix)
  run_jq RESOURCES_JSON -r 'map(select((.complianceState? // "")=="NonCompliant" and ((.policyAssignmentName? // "")|test("^SEC-BASELINE";"i")))) | group_by(.policyAssignmentId) | map({policyAssignmentId: .[0].policyAssignmentId, nonCompliant: length}) | sort_by(.nonCompliant) | reverse | .[] | "\(.nonCompliant)\t\(.policyAssignmentId)"'


  # Generic: enforcementMode not Default
  run_jq RESOURCES_JSON -r '.[] | select(((.properties.enforcementMode? // "Default")|ascii_downcase) != "default") | "\(.id)\t\(.name)\tenforcementMode=\(.properties.enforcementMode)"'


  # Activity/event records: top 50 resources by event count
  run_jq RESOURCES_JSON -r 'group_by(.resourceId) | map({resourceId: .[0].resourceId, events: length}) | sort_by(.events) | reverse | .[0:50][] | "\(.events)\t\(.resourceId)"'


  # Activity/event records: top 50 (resourceId, policyAssignmentId)
  run_jq RESOURCES_JSON -r 'group_by([.resourceId, .policyAssignmentId]) | map({resourceId: .[0].resourceId, policyAssignmentId: .[0].policyAssignmentId, events: length}) | sort_by(.events) | reverse | .[0:50][] | "\(.events)\t\(.policyAssignmentId)\t\(.resourceId)"'


  # Policy assignments referencing initiatives (policySetDefinitions)
  run_jq POLICY_ASSIGNMENTS_JSON -r '.[] | select((.properties.policyDefinitionId? // "") | test("/providers/Microsoft\\.Authorization/policySetDefinitions/"; "i")) | "\(.id)\tscope=\(.properties.scope)\tsetDef=\(.properties.policyDefinitionId)"'

#110
  # Required initiative IDs missing at MG/sub scope (requires REQUIRED_INITIATIVES_JSON)
  if [[ -n "${REQUIRED_INITIATIVES_JSON}" && -f "${REQUIRED_INITIATIVES_JSON}" ]]; then
    run_jq_multi MISSING_REQUIRED_INITIATIVE_ID -r -s '
      .[0] as $assign
      | .[1] as $req
      | ($assign
          | map(select((.properties.policyDefinitionId? // "") | test("/providers/Microsoft\\.Authorization/policySetDefinitions/"; "i")))
          | map(.properties.policyDefinitionId)
          | unique) as $have
      | $req[]
      | select(($have|index(.))==null)
      | "MISSING_REQUIRED_INITIATIVE\t\(.)"
    ' -- "${POLICY_ASSIGNMENTS_JSON}" "${REQUIRED_INITIATIVES_JSON}"
  else
    warn "Skipping required initiative comparison: REQUIRED_INITIATIVES_JSON not found"
  fi


  # Activity log: roleAssignments write/delete
  run_jq ACTIVITY_LOG_JSON -r '.[] | select((.operationName.value? // "") | test("^Microsoft\\.Authorization/roleAssignments/(write|delete)$"; "i")) | "\(.eventTimestamp)\tcaller=\(.caller)\top=\(.operationName.value)\tstatus=\(.status.value)\tresourceId=\(.resourceId)"'


  # Activity log: NSG rules, route table routes, public IP write/delete
  run_jq ACTIVITY_LOG_JSON -r '.[] | select((.operationName.value? // "") | test("^Microsoft\\.Network/(networkSecurityGroups/securityRules|routeTables/routes|publicIPAddresses)/(write|delete)$"; "i")) | "\(.eventTimestamp)\tcaller=\(.caller)\top=\(.operationName.value)\tresourceId=\(.resourceId)"'


  # Activity log: Key Vault accessPolicies/write, keys/list, secrets/list
  run_jq ACTIVITY_LOG_JSON -r '.[] | select((.operationName.value? // "") | test("^Microsoft\\.KeyVault/vaults/(accessPolicies/write|keys/list|secrets/list)$"; "i")) | "\(.eventTimestamp)\tcaller=\(.caller)\top=\(.operationName.value)\tresourceId=\(.resourceId)"'


  # Activity log: Storage listKeys/regenerateKey
  run_jq ACTIVITY_LOG_JSON -r '.[] | select((.operationName.value? // "") | test("^Microsoft\\.Storage/storageAccounts/(listKeys/action|regenerateKey/action)$"; "i")) | "\(.eventTimestamp)\tcaller=\(.caller)\top=\(.operationName.value)\tresourceId=\(.resourceId)"'


  # Activity log: per-caller 10-minute bucket counts (top 50)
  run_jq ACTIVITY_LOG_JSON -r 'map(select(.eventTimestamp? and .caller?)) | map({caller:.caller, bucket:(.eventTimestamp[0:15] + "0"), op:(.operationName.value? // "")}) | group_by([.caller,.bucket]) | map({caller:.[0].caller, bucket:.[0].bucket, count:length}) | sort_by(.count) | reverse | .[0:50][] | "\(.count)\t\(.bucket)\t\(.caller)"'


  # Join activity caller to SPs, flag SPs with empty owners (requires SPS enriched with owners)
  if [[ -n "${ACTIVITY_LOG_JSON}" && -f "${ACTIVITY_LOG_JSON}" && -n "${SPS_JSON}" && -f "${SPS_JSON}" ]]; then
    run_jq_multi SP_WITH_EMPTY_OWNER -r -s '
      .[0] as $al
      | .[1] as $sp
      | ($sp | map({k:((.appId? // .id // .objectId)|tostring), v:.}) | from_entries) as $spm
      | $al[]
      | select((.caller? // "") != "")
      | (.caller|tostring) as $c
      | ($spm[$c] // null) as $p
      | select($p != null and ((($p.owners? // [])|length)==0))
      | "\(.eventTimestamp)\tcaller=\(.caller)\top=\(.operationName.value)\tSP_NO_OWNERS=\($p.displayName)"
    ' -- "${ACTIVITY_LOG_JSON}" "${SPS_JSON}"
  else
    warn "Skipping activity->SP owners join: missing ACTIVITY_LOG_JSON or SPS_JSON"
  fi


  # Security recommendations/findings: category==security
  run_jq SECURITY_RECS_JSON -r '.[] | select((.category? // .properties.category? // "") | ascii_downcase == "security") | "\(.id)\timpact=\(.impact? // .properties.impact? // "")\tshort=\(.shortDescription.problem? // .properties.shortDescription.problem? // "")\tresource=\(.resourceMetadata.resourceId? // .properties.resourceMetadata.resourceId? // "")"'


  # Security recommendations: keyword focus inside security category
  run_jq SECURITY_RECS_JSON -r '.[] | select((.category? // .properties.category? // "") | ascii_downcase == "security") | select((.shortDescription.problem? // .properties.shortDescription.problem? // "") | test("exposed|diagnostic|encryption|mfa";"i")) | "\(.id)\t\(.shortDescription.problem? // .properties.shortDescription.problem?)"'


  # Security alerts: high severity and not resolved
  run_jq SECURITY_ALERTS_JSON -r '.[] | select((.properties.severity? // "")|ascii_downcase=="high") | select((.properties.status? // "")|ascii_downcase!="resolved") | "\(.id)\tsev=\(.properties.severity)\tstatus=\(.properties.status)\tentity=\(.properties.compromisedEntity? // "")\ttitle=\(.properties.alertDisplayName? // "")"'

#120
  # Security alerts: count alerts per compromisedEntity (>1)
  run_jq SECURITY_ALERTS_JSON -r 'map({entity:(.properties.compromisedEntity? // "UNKNOWN"), id:.id}) | group_by(.entity) | map(select(.[0].entity!="UNKNOWN" and length>1) | {entity:.[0].entity, count:length}) | sort_by(.count) | reverse | .[] | "\(.count)\t\(.entity)"'


  # VMs: Linux with password SSH enabled
  run_jq VMS_JSON -r '.[] | select((.storageProfile.osDisk.osType? // "")=="Linux") | select((.osProfile.linuxConfiguration.disablePasswordAuthentication? // true)==false) | "\(.id)\t\(.name)\tLinux\tpasswordSSH=true"'


  # VMs: Linux with no SSH public keys
  run_jq VMS_JSON -r '.[] | select((.storageProfile.osDisk.osType? // "")=="Linux") | select((.osProfile.linuxConfiguration.ssh.publicKeys? // [])|length==0) | "\(.id)\t\(.name)\tLinux\tNO_SSH_KEYS"'


  # VMs: Windows with automatic updates disabled
  run_jq VMS_JSON -r '.[] | select((.storageProfile.osDisk.osType? // "")=="Windows") | select((.osProfile.windowsConfiguration.enableAutomaticUpdates? // true)==false) | "\(.id)\t\(.name)\tWindows\tautoUpdates=false"'


  # VMs: Secure Boot not true (false or missing)
  run_jq VMS_JSON -r '.[] | select((.securityProfile.uefiSettings.secureBootEnabled? // null) != true) | "\(.id)\t\(.name)\tsecureBoot=\(.securityProfile.uefiSettings.secureBootEnabled? // "MISSING")"'


  # VMs: vTPM not true (false or missing)
  run_jq VMS_JSON -r '.[] | select((.securityProfile.uefiSettings.vTpmEnabled? // null) != true) | "\(.id)\t\(.name)\tvTPM=\(.securityProfile.uefiSettings.vTpmEnabled? // "MISSING")"'


  # VMs: encryptionAtHost not true (false or missing)
  run_jq VMS_JSON -r '.[] | select((.securityProfile.encryptionAtHost? // null) != true) | "\(.id)\t\(.name)\tencryptionAtHost=\(.securityProfile.encryptionAtHost? // "MISSING")"'


  # VMs: boot diagnostics disabled
  run_jq VMS_JSON -r '.[] | select((.diagnosticsProfile.bootDiagnostics.enabled? // false)==false) | "\(.id)\t\(.name)\tbootDiagnostics=false"'


  # VMs: missing/empty identity.type (no managed identity)
  run_jq VMS_JSON -r '.[] | select((.identity? // {}) | (has("type")|not) or ((.type? // "")=="")) | "\(.id)\t\(.name)\tNO_MANAGED_IDENTITY"'


  # VM extensions/secrets inventory: secrets array present
  run_jq VM_SECRETS_JSON -r '.[] | select((.secrets? // .properties.secrets? // [])|length>0) | "\(.vmId? // .id)\tsecretsCount=\((.secrets? // .properties.secrets?)|length)"'

#130
  # Join secrets inventory to VMs: secrets present but no MI
  if [[ -n "${VM_SECRETS_JSON}" && -f "${VM_SECRETS_JSON}" ]]; then
    run_jq_multi SECRETS_WITH_NO_MI -r -s '
      .[0] as $se
      | .[1] as $vm
      | ($vm | map({k:(.id|tostring), v:.}) | from_entries) as $vmm
      | $se[]
      | (.vmId? // .id // "" | tostring) as $vid
      | ($vmm[$vid] // null) as $v
      | select($v != null)
      | select(((.secrets? // .properties.secrets? // [])|length>0) and (((($v.identity.type? // "")|tostring)=="")))
      | "\($vid)\t\($v.name)\tSECRETS_PRESENT_NO_MI"
    ' -- "${VM_SECRETS_JSON}" "${VMS_JSON}"
  else
    warn "Skipping secrets->VM join: VM_SECRETS_JSON not found"
  fi


  # VM IP inventory: VMs with public IP addresses
  run_jq VM_IPS_JSON -r '.[] | select((.virtualMachine? // {})|length>0) | select((.network? .publicIpAddresses? // [])|length>0) | "\(.virtualMachine.id)\t\(.virtualMachine.name)\tpublicIPs=\((.network.publicIpAddresses)|map(.ipAddress)|join(","))"'


  # NIC inventory: NICs with any publicIPAddress.id reference
  run_jq NICS_JSON -r '.[] | select((.properties.ipConfigurations? // []) | any(.properties.publicIPAddress.id?)) | "\(.id)\t\(.name)\tHAS_PUBLIC_IP_REF"'


  # Effective security rules per NIC: inbound Allow from Internet/* to admin ports
  run_jq EFFECTIVE_RULES_JSON -r '.[] | (.effectiveSecurityRules? // [])[] | select((.direction? // "")=="Inbound" and (.access? // "")=="Allow") | select((.sourceAddressPrefix? // "") | IN("Internet","*","0.0.0.0/0")) | select((.destinationPortRange? // "") | test("^(22|3389|5985|5986)$|\\*$")) | "\(.associatedNicId? // .nicId? // "NIC_UNKNOWN")\trule=\(.name)\tports=\(.destinationPortRange)\tsrc=\(.sourceAddressPrefix)"'


  # VM scale sets: upgradePolicy.mode == Manual
  run_jq VMSS_JSON -r '.[] | select((.upgradePolicy.mode? // "")|ascii_downcase=="manual") | "\(.id)\t\(.name)\tupgradeMode=Manual"'


  # VM scale sets: publicIPAddressConfiguration present
  run_jq VMSS_JSON -r '.[] | select((.virtualMachineProfile.networkProfile.networkInterfaceConfigurations? // []) | any(.properties.ipConfigurations? // [] | any(.properties.publicIPAddressConfiguration?))) | "\(.id)\t\(.name)\tVMSS_HAS_PUBLIC_IP_CONFIG"'


  # Azure Bastion (or similar): ipAddress.type == Public
  run_jq RESOURCES_JSON -r '.[] | select((.ipAddress.type? // "")=="Public") | "\(.id)\t\(.name)\tpublicPorts=\((.ipAddress.ports? // [])|map(.port|tostring)|join(","))"'


  # Public endpoints: dnsNameLabel set
  run_jq RESOURCES_JSON -r '.[] | select((.ipAddress.dnsNameLabel? // "") != "") | "\(.id)\t\(.name)\tdnsNameLabel=\(.ipAddress.dnsNameLabel)"'


  # Container Apps (or similar): env vars with secret-like patterns
  run_jq RESOURCES_JSON -r 'def secretish: test("AccountKey=|SharedAccessKey=|SharedAccessSignature|sig=|eyJ[A-Za-z0-9_-]+\\.|-----BEGIN [A-Z ]+-----|Bearer\\s+";"i"); .[] | (.containers? // [])[] as $c | ($c.environmentVariables? // [])[] | select((.value? // "")|tostring|secretish) | "\(.id)\t\(.name)\tcontainer=\($c.name)\tenv=\(.name)\tvalue_snip=\((.value|tostring)[0:80])"'


  # AKS: private cluster not enabled
  run_jq AKS_JSON -r '.[] | select((.apiServerAccessProfile.enablePrivateCluster? // false)==false) | "\(.id)\t\(.name)\tprivateCluster=false"'

#140
  # AKS: authorisedIpRanges empty (alternate schema)
  run_jq AKS_JSON -r '.[] | select((.apiServerAccessProfile.authorizedIpRanges? // [])|length==0) | "\(.id)\t\(.name)\tauthorisedIpRanges=EMPTY"'


  # AKS: disableLocalAccounts false (alternate schema)
  run_jq AKS_JSON -r '.[] | select((.disableLocalAccounts? // false)==false) | "\(.id)\t\(.name)\tdisableLocalAccounts=false"'


  # AKS: enableRBAC false (alternate schema)
  run_jq AKS_JSON -r '.[] | select((.enableRBAC? // true)==false) | "\(.id)\t\(.name)\tenableRBAC=false"'


  # AKS: missing aadProfile object
  run_jq AKS_JSON -r '.[] | select((.aadProfile? // {})|length==0) | "\(.id)\t\(.name)\tNO_AAD_PROFILE"'


  # AKS: outboundType loadBalancer or userDefinedRouting
  run_jq AKS_JSON -r '.[] | select((.networkProfile.outboundType? // "") | test("loadBalancer|userDefinedRouting";"i")) | "\(.id)\t\(.name)\toutboundType=\(.networkProfile.outboundType)"'


  # OpenShift/AKS-like: apiserverProfile.visibility public
  run_jq RESOURCES_JSON -r '.[] | select((.apiserverProfile.visibility? // "")|ascii_downcase=="public") | "\(.id)\t\(.name)\tapiserverPublic"'


  # OpenShift/AKS-like: any ingressProfiles public
  run_jq RESOURCES_JSON -r '.[] | select((.ingressProfiles? // []) | any((.visibility? // "")|ascii_downcase=="public")) | "\(.id)\t\(.name)\tingressPublic"'


  # Route tables: 0.0.0.0/0 -> Internet (alternate schema)
  run_jq ROUTE_TABLES_JSON -r '.[] | (.routes? // .properties.routes? // [])[]? | select((.addressPrefix? // .properties.addressPrefix? // "")=="0.0.0.0/0") | select((.nextHopType? // .properties.nextHopType? // "")|ascii_downcase=="internet") | "\(.id)\t\(.name)\t0.0.0.0/0 -> Internet"'


  # Route tables: virtual appliance nextHopIpAddress not matching allowed CIDR regex list
  if [[ -n "${CIDR_REGEX_ALLOW_JSON}" && -f "${CIDR_REGEX_ALLOW_JSON}" ]]; then
    run_jq_multi UNAUTH_CIDR -r -s '
      .[0] as $rt
      | .[1] as $cidrRe
      | $rt[]
      | (.routes? // .properties.routes? // [])[]?
      | select((.nextHopType? // .properties.nextHopType? // "")|ascii_downcase=="virtualappliance")
      | (.nextHopIpAddress? // .properties.nextHopIpAddress? // "") as $ip
      | select(($cidrRe | any($ip|test(.))) | not)
      | "\(.id)\t\(.name)\tVAppliance=\($ip)\tprefix=\(.addressPrefix? // .properties.addressPrefix?)"
    ' -- "${ROUTE_TABLES_JSON}" "${CIDR_REGEX_ALLOW_JSON}"
  else
    warn "Skipping virtual appliance CIDR allow-list check: CIDR_REGEX_ALLOW_JSON not found"
  fi


  # Route tables: blackhole routes (nextHopType none)
  run_jq ROUTE_TABLES_JSON -r '.[] | (.routes? // .properties.routes? // [])[]? | select((.nextHopType? // .properties.nextHopType? // "")|ascii_downcase=="none") | "\(.id)\t\(.name)\tBLACKHOLE\tprefix=\(.addressPrefix? // .properties.addressPrefix?)"'

#150
  # Generic resource summary: counts of publicIpAddresses/subnets arrays
  run_jq RESOURCES_JSON -r '.[] | "\(.id)\t\(.name)\tpublicIPs=\((.publicIpAddresses? // .properties.publicIpAddresses? // [])|length)\tsubnets=\((.subnets? // .properties.subnets? // [])|length)"'


  # Generic resource summary: 5+ public IPs
  run_jq RESOURCES_JSON -r '.[] | select(((.publicIpAddresses? // .properties.publicIpAddresses? // [])|length) >= 5) | "\(.id)\t\(.name)\tpublicIPs=\((.publicIpAddresses? // .properties.publicIpAddresses?)|length)"'


  # Azure Maps (or similar): enableTunneling
  run_jq RESOURCES_JSON -r '.[] | select((.properties.enableTunneling? // false)==true) | "\(.id)\t\(.name)\tenableTunneling=true"'


  # Azure Maps (or similar): enableShareableLink
  run_jq RESOURCES_JSON -r '.[] | select((.properties.enableShareableLink? // false)==true) | "\(.id)\t\(.name)\tenableShareableLink=true"'


  # Azure Maps (or similar): enableIpConnect
  run_jq RESOURCES_JSON -r '.[] | select((.properties.enableIpConnect? // false)==true) | "\(.id)\t\(.name)\tenableIpConnect=true"'


  # Bastion presence vs NSG exposure: inbound Allow Internet/* to 22/3389 or *
  run_jq_multi OVER_EXPOSED_NETWORK_RULES -r -s '
    .[0] as $b
    | .[1] as $nsg
    | ($b | map(.id) | length) as $bcount
    | $nsg[]
    | (.properties.securityRules? // [])[]?
    | select((.direction? // "")=="Inbound" and (.access? // "")=="Allow")
    | select((.sourceAddressPrefix? // "") | IN("Internet","*","0.0.0.0/0") or ((.sourceAddressPrefixes? // [])|any(IN("Internet","*","0.0.0.0/0"))))
    | select((.destinationPortRange? // "")|test("^(22|3389)$|\\*$") or ((.destinationPortRanges? // [])|any(test("^(22|3389)$|\\*$"))))
    | "BASTION_PRESENT=\($bcount>0)\tNSG=\($nsg.name)\trule=\(.name)\tports=\(.destinationPortRange? // ((.destinationPortRanges? // [])|join(",")))"
  ' -- "${RESOURCES_JSON}" "${NSGS_JSON}"


  # Load balancers: inbound NAT rules exposing admin ports
  run_jq LOADBALANCERS_JSON -r '.[] | (.inboundNatRules? // .properties.inboundNatRules? // [])[]? | select((.properties.frontendPort? // 0) | IN(22,3389,5985,5986)) | "\(.id)\t\(.name)\tNAT\tfrontendPort=\(.properties.frontendPort)\tbackendPort=\(.properties.backendPort)"'


  # Load balancers: HTTP health probes
  run_jq LOADBALANCERS_JSON -r '.[] | (.probes? // .properties.probes? // [])[]? | select((.properties.protocol? // "")|ascii_downcase=="http") | "\(.id)\t\(.name)\tprobe=\(.name)\tprotocol=HTTP\tport=\(.properties.port)"'


  # Load balancers: rules using frontend port 0/80/443
  run_jq LOADBALANCERS_JSON -r '.[] | (.loadBalancingRules? // .properties.loadBalancingRules? // [])[]? | select((.properties.frontendPort? // 0) == 0 or (.properties.frontendPort? // 0) == 80 or (.properties.frontendPort? // 0) == 443) | "\(.id)\t\(.name)\tlbRule=\(.name)\tfrontendPort=\(.properties.frontendPort)\tbackendPool=\(.properties.backendAddressPool.id? // "")"'


  # Application Gateway: HTTP listeners
  run_jq APPGATEWAYS_JSON -r '.[] | (.properties.httpListeners? // [])[]? | select((.properties.protocol? // "")|ascii_downcase=="http") | "\(.id)\t\(.name)\tlistener=\(.name)\tprotocol=HTTP"'

#160
  # Application Gateway: backend HTTP settings using HTTP
  run_jq APPGATEWAYS_JSON -r '.[] | (.properties.backendHttpSettingsCollection? // [])[]? | select((.properties.protocol? // "")|ascii_downcase=="http") | "\(.id)\t\(.name)\tbackendSetting=\(.name)\tprotocol=HTTP\tport=\(.properties.port)"'


  # Application Gateway: WAF disabled (alternate selector)
  run_jq APPGATEWAYS_JSON -r '.[] | select((.properties.webApplicationFirewallConfiguration.enabled? // false)==false) | "\(.id)\t\(.name)\tWAF_DISABLED"'


  # Application Gateway: WAF detection mode (alternate selector)
  run_jq APPGATEWAYS_JSON -r '.[] | select((.properties.webApplicationFirewallConfiguration.enabled? // false)==true) | select((.properties.webApplicationFirewallConfiguration.firewallMode? // "")|ascii_downcase=="detection") | "\(.id)\t\(.name)\tWAF_DETECTION_MODE"'


  # Application Gateway: SSL min protocol TLSv1.0/1.1 (alternate selector)
  run_jq APPGATEWAYS_JSON -r '.[] | select((.properties.sslPolicy.minProtocolVersion? // "")|test("TLSv1_0|TLSv1_1|1\\.0|1\\.1";"i")) | "\(.id)\t\(.name)\tminProto=\(.properties.sslPolicy.minProtocolVersion)"'


  # Certificates: expiring before cutoff (defaults to 30 days from 2026-01-09)
  # Override by exporting CERT_CUTOFF="YYYY-MM-DDTHH:MM:SSZ"
  CERT_CUTOFF="${CERT_CUTOFF:-2026-02-08T00:00:00Z}"
  run_jq CERTS_JSON -r --arg cutoff "${CERT_CUTOFF}" '.[] | select((.notAfter? // "") != "" and (.notAfter < $cutoff)) | "\(.appGatewayId)\tcert=\(.certName)\tnotAfter=\(.notAfter)"'


  # Private Endpoints vs DNS zone groups: PEs with no dnsZoneGroup attachment
  if [[ -n "${PRIVATE_ENDPOINTS_JSON}" && -f "${PRIVATE_ENDPOINTS_JSON}" && -n "${PRIVATE_DNS_ZONE_GROUPS_JSON}" && -f "${PRIVATE_DNS_ZONE_GROUPS_JSON}" ]]; then
    run_jq_multi NO_DNSZONEGROUP_ATTACHMENT -r -s '
      .[0] as $pe
      | .[1] as $zg
      | ($zg | map(.properties.privateEndpoint.id? // .privateEndpointId? // "" ) | map(tostring) | unique) as $have
      | $pe[]
      | select(($have|index((.id|tostring)))==null)
      | "\(.id)\t\(.name)\tDNS_ZONE_GROUP_MISSING"
    ' -- "${PRIVATE_ENDPOINTS_JSON}" "${PRIVATE_DNS_ZONE_GROUPS_JSON}"
  else
    warn "Skipping PE DNS zone-group attachment check: missing PRIVATE_ENDPOINTS_JSON or PRIVATE_DNS_ZONE_GROUPS_JSON"
  fi


  # Private Endpoints: Pending/Rejected connection states (alternate selector)
  run_jq PRIVATE_ENDPOINTS_JSON -r '.[] | (.properties.privateLinkServiceConnections? // [])[]? | select((.properties.privateLinkServiceConnectionState.status? // "")|test("Pending|Rejected";"i")) | "\(.id)\tstatus=\(.properties.privateLinkServiceConnectionState.status)\tdesc=\(.properties.privateLinkServiceConnectionState.description? // "")"'


  # Private Endpoints: unexpected groupIds (requires PE_GROUPID_ALLOW_JSON)
  if [[ -n "${PE_GROUPID_ALLOW_JSON}" && -f "${PE_GROUPID_ALLOW_JSON}" ]]; then
    run_jq_multi UNEXPECTED_GROUP_IDS -r -s '
      .[0] as $pe
      | .[1] as $allow
      | ($allow | map(tostring) | unique) as $ok
      | $pe[]
      | (.properties.privateLinkServiceConnections? // [])[]?
      | (.properties.groupIds? // [])[]? as $gid
      | select(($ok|index(($gid|tostring)))==null)
      | "\(.id)\t\(.name)\tUNEXPECTED_GROUPID=\($gid)"
    ' -- "${PRIVATE_ENDPOINTS_JSON}" "${PE_GROUPID_ALLOW_JSON}"
  else
    warn "Skipping PE groupId allow-list check: PE_GROUPID_ALLOW_JSON not found"
  fi


  # App Service: httpsOnly false (schema tolerant)
  run_jq APP_SITES_JSON -r '.[] | select((.properties.httpsOnly? // .httpsOnly? // true)==false) | "\(.id)\t\(.name)\thttpsOnly=false"'


  # App Service: minTlsVersion missing/weak
  run_jq APP_SITES_JSON -r '.[] | (.properties.minTlsVersion? // .minTlsVersion? // "") as $v | select(($v=="") or ($v|tostring|test("1\\.0|1\\.1|TLS1_0|TLS1_1";"i"))) | "\(.id)\t\(.name)\tminTlsVersion=\($v|tostring)"'

#170
  # App Service: FTPS not FTPS-only (schema tolerant)
  run_jq APP_SITES_JSON -r '.[] | select(((.properties.ftpsState? // .ftpsState? // "")|ascii_downcase) != "ftpsonly") | "\(.id)\t\(.name)\tftpsState=\(.properties.ftpsState? // .ftpsState? // "MISSING")"'


  # App Service: remote debugging enabled
  run_jq APP_SITES_JSON -r '.[] | select((.properties.remoteDebuggingEnabled? // .remoteDebuggingEnabled? // false)==true) | "\(.id)\t\(.name)\tremoteDebuggingEnabled=true"'


  # App Service: CORS allowedOrigins includes "*" (duplicate check)
  run_jq APP_SITES_JSON -r '.[] | select((.properties.cors.allowedOrigins? // []) | any(.=="*")) | "\(.id)\t\(.name)\tCORS_STAR"'


  # App Service: CORS "*" with supportCredentials true
  run_jq APP_SITES_JSON -r '.[] | select((.properties.cors.allowedOrigins? // []) | any(.=="*")) | select((.properties.cors.supportCredentials? // false)==true) | "\(.id)\t\(.name)\tCORS_STAR_WITH_CREDS"'


  # App Service config: no ipSecurityRestrictions configured
  run_jq APP_SITE_CONFIG_JSON -r '.[] | select((.properties.ipSecurityRestrictions? // [])|length==0) | "\(.id)\t\(.name)\tNO_ACCESS_RESTRICTIONS"'


  # App Service config: SCM unrestricted
  run_jq APP_SITE_CONFIG_JSON -r '.[] | select((.properties.scmIpSecurityRestrictions? // [])|length==0) | "\(.id)\t\(.name)\tSCM_UNRESTRICTED"'


  # App Service config: scan appSettings for secret-ish patterns (duplicate logic)
  run_jq APP_SITE_CONFIG_JSON -r 'def secretish: test("AccountKey=|SharedAccessKey=|SharedAccessSignature|sig=|eyJ[A-Za-z0-9_-]+\\.|-----BEGIN [A-Z ]+-----|Bearer\\s+";"i"); .[] | (.properties.appSettings? // [])[]? | select((.value? // "")|tostring|secretish) | "\(.id)\tkey=\(.name)\tvalue_snip=\((.value|tostring)[0:80])"'


  # App Configuration key-values: scan values for secret-ish patterns
  run_jq RESOURCES_JSON -r 'def secretish: test("AccountKey=|SharedAccessKey=|SharedAccessSignature|sig=|eyJ[A-Za-z0-9_-]+\\.|-----BEGIN [A-Z ]+-----|Bearer\\s+";"i"); .[] | select((.value? // "")|tostring|secretish) | "\(.key)\tlabel=\(.label? // "")\tvalue_snip=\((.value|tostring)[0:80])"'


  # App Configuration key-values: prod label + debug/admin/verbose/trace
  run_jq RESOURCES_JSON -r '.[] | select((.label? // "")|test("prod|production";"i")) | select(((.key? // "")|test("debug|admin|verbose|trace";"i")) or ((.value? // "")|tostring|test("debug|admin|verbose|trace";"i"))) | "\(.key)\tlabel=\(.label)\tvalue_snip=\((.value|tostring)[0:80])"'


  # App Configuration key-values: top 50 keys by revision count
  run_jq RESOURCES_JSON -r 'group_by(.key) | map({key:.[0].key, revisions:length}) | sort_by(.revisions) | reverse | .[0:50][] | "\(.revisions)\t\(.key)"'

#180
  # Log Analytics workspaces: publicNetworkAccessForIngestion/query enabled
  run_jq RESOURCES_JSON -r '.[] | select((.publicNetworkAccessForIngestion? // .properties.publicNetworkAccessForIngestion? // "")|ascii_downcase=="enabled" or (.publicNetworkAccessForQuery? // .properties.publicNetworkAccessForQuery? // "")|ascii_downcase=="enabled") | "\(.id)\t\(.name)\tingest=\(.publicNetworkAccessForIngestion? // .properties.publicNetworkAccessForIngestion? // "NA")\tquery=\(.publicNetworkAccessForQuery? // .properties.publicNetworkAccessForQuery? // "NA")"'


  # Workspaces: retention below min=90
  run_jq RESOURCES_JSON -r --argjson min 90 '.[] | select((.retentionInDays? // .properties.retentionInDays? // 0) < $min) | "\(.id)\t\(.name)\tretentionDays=\(.retentionInDays? // .properties.retentionInDays?)"'


  # Workspaces: workspaceCount
  run_jq RESOURCES_JSON -r 'map({id:.id, name:.name, retention:(.retentionInDays? // .properties.retentionInDays? // 0)}) | length as $n | "workspaceCount=\($n)"'


  # Generic public access: publicNetworkAccess enabled
  run_jq RESOURCES_JSON -r '.[] | select(((.properties.publicNetworkAccess? // "Enabled")|ascii_downcase)=="enabled") | "\(.id)\t\(.name)\tpublicNetworkAccess=Enabled"'


  # Generic public access: duplicate
  run_jq RESOURCES_JSON -r '.[] | select(((.properties.publicNetworkAccess? // "Enabled")|ascii_downcase)=="enabled") | "\(.id)\t\(.name)\tpublicNetworkAccess=Enabled"'


  # Generic public access: duplicate
  run_jq RESOURCES_JSON -r '.[] | select(((.properties.publicNetworkAccess? // "Enabled")|ascii_downcase)=="enabled") | "\(.id)\t\(.name)\tpublicNetworkAccess=Enabled"'


  # Generic TLS policy: minimumTlsVersion missing or weak
  run_jq RESOURCES_JSON -r '.[]
    | (.properties.minimumTlsVersion? // "MISSING") as $v
    | select($v=="MISSING" or ($v|tostring|test("1\\.0|1\\.1|TLS1_0|TLS1_1";"i")))
    | "\(.id)\t\(.name)\tminimumTlsVersion=\($v)"'


  # Event Hubs/Service Bus/etc networkRuleSet defaultAction Allow
  run_jq RESOURCES_JSON -r '.[] | select((.properties.networkRuleSet.defaultAction? // "")=="Allow") | "\(.id)\t\(.name)\tnetworkDefaultAction=Allow"'


  # Resource local auth: disableLocalAuth false
  run_jq RESOURCES_JSON -r '.[] | select((.properties.disableLocalAuth? // false)==false) | "\(.id)\t\(.name)\tdisableLocalAuth=false"'


  # Generic public access: duplicate
  run_jq RESOURCES_JSON -r '.[] | select(((.properties.publicNetworkAccess? // "Enabled")|ascii_downcase)=="enabled") | "\(.id)\t\(.name)\tpublicNetworkAccess=Enabled"'

#190
  # Resource local auth: duplicate
  run_jq RESOURCES_JSON -r '.[] | select((.properties.disableLocalAuth? // false)==false) | "\(.id)\t\(.name)\tdisableLocalAuth=false"'


  # Resource network filtering: isVirtualNetworkFilterEnabled false
  run_jq RESOURCES_JSON -r '.[] | select((.properties.isVirtualNetworkFilterEnabled? // false)==false) | "\(.id)\t\(.name)\tVNetFilter=false"'


  # Generic public access: duplicate
  run_jq RESOURCES_JSON -r '.[] | select(((.properties.publicNetworkAccess? // "Enabled")|ascii_downcase)=="enabled") | "\(.id)\t\(.name)\tpublicNetworkAccess=Enabled"'


  # Generic SQL TLS: minimalTlsVersion/minTlsVersion missing or weak
  run_jq RESOURCES_JSON -r '.[] | (.properties.minimalTlsVersion? // .properties.minTlsVersion? // "MISSING") as $v | select($v=="MISSING" or ($v|tostring|test("1\\.0|1\\.1|TLS1_0|TLS1_1";"i"))) | "\(.id)\t\(.name)\tminTls=\($v)"'


  # Generic public access: duplicate
  run_jq RESOURCES_JSON -r '.[] | select(((.properties.publicNetworkAccess? // "Enabled")|ascii_downcase)=="enabled") | "\(.id)\t\(.name)\tpublicNetworkAccess=Enabled"'


  # SQL + Private Endpoints: SQL public and no PE targeting it
  run_jq_multi PRIVATE_ENDPOINT_SQL -r -s '
    .[0] as $sql
    | .[1] as $pe
    | ($pe | map((.properties.privateLinkServiceConnections? // [])[]? | .properties.privateLinkServiceId? // "") | map(select(.!="")) | unique) as $targets
    | $sql[]
    | select(((.properties.publicNetworkAccess? // "Enabled")|ascii_downcase)=="enabled")
    | select(($targets|index(.id))==null)
    | "\(.id)\t\(.name)\tSQL_PUBLIC_NO_PRIVATE_ENDPOINT"
  ' -- "${SQL_SERVERS_JSON}" "${PRIVATE_ENDPOINTS_JSON}"


  # Tags: empty tags object or missing owner tag
  run_jq RESOURCES_JSON -r '.[] | select((((.tags? // {})|length)==0) or ((.tags.owner? // "")=="")) | "\(.id)\t\(.name)\tMISSING_TAGS_OR_OWNER"'


  # Template specs: templateSpecCount
  run_jq RESOURCES_JSON -r 'map(select(.type|test("^Microsoft\\.Resources/templateSpecs/";"i"))) | length as $n | "templateSpecCount=\($n)"'


  # Marketplace agreements: sensitive subscription list join
  if [[ -n "${MARKETPLACE_AGREEMENTS_JSON}" && -f "${MARKETPLACE_AGREEMENTS_JSON}" && -n "${SENSITIVE_SUBS_JSON}" && -f "${SENSITIVE_SUBS_JSON}" ]]; then
    run_jq_multi SENSITIVE_SUBSCRIPTIONS -r -s '
      .[0] as $ma
      | .[1] as $sens
      | ($sens | map(tostring) | unique) as $s
      | $ma[]
      | select(($s|index((.id|capture("^/subscriptions/(?<sid>[^/]+)").sid)|tostring))!=null)
      | "\(.id)\t\(.name)\tpublisher=\(.properties.publisher? // "NA")"
    ' -- "${MARKETPLACE_AGREEMENTS_JSON}" "${SENSITIVE_SUBS_JSON}"
  else
    warn "Skipping marketplace sensitive-sub join: missing MARKETPLACE_AGREEMENTS_JSON or SENSITIVE_SUBS_JSON"
  fi


  # Marketplace agreements: missing publisher or empty tags
  run_jq MARKETPLACE_AGREEMENTS_JSON -r '.[] | select((((.tags? // {}) | length)==0) or ((.properties.publisher? // "")=="")) | "\(.id)\t\(.name)\tpublisher=\(.properties.publisher? // "MISSING")\ttags=\(((.tags? // {})|keys)|join(","))"'

#200
  # Local auth: disableLocalAuth false (duplicate)
  run_jq RESOURCES_JSON -r '.[] | select((.properties.disableLocalAuth? // false)==false) | "\(.id)\t\(.name)\tdisableLocalAuth=false"'


  # Maps accounts: mapsAccountCount
  run_jq RESOURCES_JSON -r 'map(select(.type|test("^Microsoft\\.Maps/accounts$";"i"))) | length as $n | "mapsAccountCount=\($n)"'


  # Action Groups: unused action groups (requires ACTION_GROUPS + METRIC_ALERTS + SCHEDULED_QUERY_RULES)
  if [[ -n "${ACTION_GROUPS_JSON}" && -f "${ACTION_GROUPS_JSON}" && -n "${METRIC_ALERTS_JSON}" && -f "${METRIC_ALERTS_JSON}" && -n "${SCHEDULED_QUERY_RULES_JSON}" && -f "${SCHEDULED_QUERY_RULES_JSON}" ]]; then
    run_jq_multi UNUSED_ACTION_GROUPS -r -s '
      .[0] as $ag
      | .[1] as $ma
      | .[2] as $sq
      | ($ma | map((.properties.actions? // [])[]? .actionGroupId? // "") | map(select(.!="")) | unique) as $maUsed
      | ($sq | map((.properties.actions? // [])[]? .actionGroupId? // "") | map(select(.!="")) | unique) as $sqUsed
      | ($maUsed + $sqUsed | unique) as $used
      | $ag[]
      | select(($used|index(.id))==null)
      | "\(.id)\t\(.name)\tUNUSED_ACTION_GROUP"
    ' -- "${ACTION_GROUPS_JSON}" "${METRIC_ALERTS_JSON}" "${SCHEDULED_QUERY_RULES_JSON}"
  else
    warn "Skipping unused action group join: missing ACTION_GROUPS_JSON/METRIC_ALERTS_JSON/SCHEDULED_QUERY_RULES_JSON"
  fi


  # Action Groups: email only receivers
  run_jq ACTION_GROUPS_JSON -r '.[] | select((.properties.emailReceivers? // [])|length>0) | select((.properties.webhookReceivers? // [])|length==0 and (.properties.azureAppPushReceivers? // [])|length==0 and (.properties.itsmReceivers? // [])|length==0) | "\(.id)\t\(.name)\tEMAIL_ONLY"'


  # Generic monitoring objects: disabled entries
  run_jq RESOURCES_JSON -r '.[] | select((.properties.enabled? // true)==false) | "\(.id)\t\(.name)\tDISABLED"'


  # Generic monitoring objects: disabled entries (duplicate)
  run_jq RESOURCES_JSON -r '.[] | select((.properties.enabled? // true)==false) | "\(.id)\t\(.name)\tDISABLED"'


  # Generic monitoring rules: no actions configured
  run_jq RESOURCES_JSON -r '.[] | select((.properties.actions? // [])|length==0) | "\(.id)\t\(.name)\tNO_ACTION_GROUPS"'


  # Generic monitoring rules: no actions configured (duplicate)
  run_jq RESOURCES_JSON -r '.[] | select((.properties.actions? // [])|length==0) | "\(.id)\t\(.name)\tNO_ACTION_GROUPS"'


  # Generic monitoring rules: exactly 1 scope
  run_jq RESOURCES_JSON -r '.[] | select((.properties.scopes? // [])|length==1) | "\(.id)\t\(.name)\tscopes=1\t\(.properties.scopes[0])"'


  # Generic monitoring rules: exactly 1 scope (duplicate)
  run_jq RESOURCES_JSON -r '.[] | select((.properties.scopes? // [])|length==1) | "\(.id)\t\(.name)\tscopes=1\t\(.properties.scopes[0])"'

#210
  # Monitoring/export: no export sinks
  run_jq RESOURCES_JSON -r '.[] | select((.properties.storageAccountId? // "")=="" and (.properties.serviceBusRuleId? // "")=="" and (.properties.workspaceId? // "")=="") | "\(.id)\t\(.name)\tNO_EXPORT_SINKS"'


  # Monitoring/export: retentionPolicy days < 90
  run_jq RESOURCES_JSON -r --argjson min 90 '.[] | select((.properties.retentionPolicy.enabled? // false)==true and (.properties.retentionPolicy.days? // 0) < $min) | "\(.id)\t\(.name)\tretentionDays=\(.properties.retentionPolicy.days)"'


  # Data Collection Rules: unattached DCRs (requires DCR + DCR_ASSOC)
  if [[ -n "${DCR_JSON}" && -f "${DCR_JSON}" && -n "${DCR_ASSOC_JSON}" && -f "${DCR_ASSOC_JSON}" ]]; then
    run_jq_multi UNATTACHED_DCRS -r -s '
      .[0] as $dcr
      | .[1] as $assoc
      | ($assoc | map(.properties.dataCollectionRuleId? // "") | map(select(.!="")) | unique) as $attached
      | $dcr[]
      | select(($attached|index(.id))==null)
      | "\(.id)\t\(.name)\tDCR_UNATTACHED"
    ' -- "${DCR_JSON}" "${DCR_ASSOC_JSON}"
  else
    warn "Skipping DCR unattached check: missing DCR_JSON or DCR_ASSOC_JSON"
  fi


  # DCR associations: count
  if [[ -n "${DCR_ASSOC_JSON}" && -f "${DCR_ASSOC_JSON}" ]]; then
    run_jq_multi -r -s '.[0] as $assoc | ($assoc | length) as $a | "dcrAssociationCount=\($a)"' -- "${DCR_ASSOC_JSON}"
  else
    warn "Skipping DCR association count: DCR_ASSOC_JSON not found"
  fi

  log "Checks completed."
}

main "$@"
