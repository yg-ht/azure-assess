# SPDX-License-Identifier: AGPL-3.0-or-later

REQUESTED_HEADLINES = [
    "aisearch_service_not_publicly_accessible",
    "aks_cluster_rbac_enabled",
    "aks_clusters_created_with_private_nodes",
    "aks_clusters_public_access_disabled",
    "aks_network_policy_enabled",
    "apim_threat_detection_llm_jacking",
    "app_client_certificates_on",
    "app_ensure_auth_is_set_up",
    "app_ensure_http_is_redirected_to_https",
    "app_ensure_java_version_is_latest",
    "app_ensure_php_version_is_latest",
    "app_ensure_python_version_is_latest",
    "app_ensure_using_http20",
    "app_ftp_deployment_disabled",
    "app_function_access_keys_configured",
    "app_function_application_insights_enabled",
    "app_function_ftps_deployment_disabled",
    "app_function_identity_is_configured",
    "app_function_identity_without_admin_privileges",
    "app_function_latest_runtime_version",
    "app_function_not_publicly_accessible",
    "app_function_vnet_integration_enabled",
    "app_http_logs_enabled",
    "app_minimum_tls_version_12",
    "app_register_with_identity",
    "app_service_environment_injection_deployed",
    "appinsights_ensure_is_configured",
    "cognitive_services_local_auth_disabled",
    "containerregistry_admin_user_disabled",
    "containerregistry_not_publicly_accessible",
    "containerregistry_uses_private_link",
    "cosmosdb_account_firewall_use_selected_networks",
    "cosmosdb_account_use_aad_and_rbac",
    "cosmosdb_account_use_private_endpoints",
    "databricks_workspace_cmk_encryption_enabled",
    "databricks_workspace_vnet_injection_enabled",
    "defender_additional_email_configured_with_a_security_contact",
    "defender_assessments_vm_endpoint_protection_installed",
    "defender_auto_provisioning_log_analytics_agent_vms_on",
    "defender_auto_provisioning_vulnerabilty_assessments_machines_on",
    "defender_container_images_resolved_vulnerabilities",
    "defender_container_images_scan_enabled",
    "defender_ensure_defender_for_app_services_is_on",
    "defender_ensure_defender_for_arm_is_on",
    "defender_ensure_defender_for_azure_sql_databases_is_on",
    "defender_ensure_defender_for_containers_is_on",
    "defender_ensure_defender_for_cosmosdb_is_on",
    "defender_ensure_defender_for_databases_is_on",
    "defender_ensure_defender_for_dns_is_on",
    "defender_ensure_defender_for_keyvault_is_on",
    "defender_ensure_defender_for_os_relational_databases_is_on",
    "defender_ensure_defender_for_server_is_on",
    "defender_ensure_defender_for_sql_servers_is_on",
    "defender_ensure_defender_for_storage_is_on",
    "defender_ensure_iot_hub_defender_is_on",
    "defender_ensure_mcas_is_enabled",
    "defender_ensure_notify_alerts_severity_is_high",
    "defender_ensure_notify_emails_to_owners",
    "defender_ensure_system_updates_are_applied",
    "defender_ensure_wdatp_is_enabled",
    "entra_conditional_access_policy_require_mfa_for_admin_portals",
    "entra_conditional_access_policy_require_mfa_for_management_api",
    "entra_global_admin_in_less_than_five_users",
    "entra_non_privileged_user_has_mfa",
    "entra_policy_default_users_cannot_create_security_groups",
    "entra_policy_ensure_default_user_cannot_create_apps",
    "entra_policy_ensure_default_user_cannot_create_tenants",
    "entra_policy_guest_invite_only_for_admin_roles",
    "entra_policy_guest_users_access_restrictions",
    "entra_policy_restricts_user_consent_for_apps",
    "entra_policy_user_consent_for_verified_apps",
    "entra_privileged_user_has_mfa",
    "entra_security_defaults_enabled",
    "entra_trusted_named_locations_exists",
    "entra_user_with_vm_access_has_mfa",
    "entra_users_cannot_create_microsoft_365_groups",
    "eventgrid_domain_public_network_access_disabled",
    "eventgrid_topic_public_network_access_disabled",
    "hdinsight_kafka_cluster_manual_auth_disabled",
    "iam_custom_role_has_permissions_to_administer_resource_locks",
    "iam_role_user_access_admin_restricted",
    "iam_subscription_roles_owner_custom_not_created",
    "iot_dps_public_network_access_disabled",
    "keyvault_access_only_through_private_endpoints",
    "keyvault_key_expiration_set_in_non_rbac",
    "keyvault_key_rotation_enabled",
    "keyvault_logging_enabled",
    "keyvault_non_rbac_secret_expiration_set",
    "keyvault_private_endpoints",
    "keyvault_purge_protection_enabled",
    "keyvault_rbac_enabled",
    "keyvault_rbac_key_expiration_set",
    "keyvault_rbac_secret_expiration_set",
    "keyvault_recoverable",
    "keyvault_recoverable_secrets_should_be_enabled",
    "keyvault_secret_expiration_set",
    "keyvault_soft_delete_enabled",
    "kubernetes_cluster_azure_policy_enabled",
    "machine_learning_workspace_public_access_disabled",
    "machine_learning_workspace_vnet_configured",
    "monitor_alert_create_policy_assignment",
    "monitor_alert_create_update_nsg",
    "monitor_alert_create_update_public_ip_address_rule",
    "monitor_alert_create_update_security_solution",
    "monitor_alert_create_update_sqlserver_fr",
    "monitor_alert_delete_nsg",
    "monitor_alert_delete_policy_assignment",
    "monitor_alert_delete_public_ip_address_rule",
    "monitor_alert_delete_security_solution",
    "monitor_alert_delete_sqlserver_fr",
    "monitor_alert_service_health_exists",
    "monitor_diagnostic_setting_with_appropriate_categories",
    "monitor_diagnostic_settings_exists",
    "monitor_storage_account_with_activity_logs_cmk_encrypted",
    "monitor_storage_account_with_activity_logs_is_private",
    "mysql_flexible_server_audit_log_connection_activated",
    "mysql_flexible_server_audit_log_enabled",
    "mysql_flexible_server_geo_redundant_backup_enabled",
    "mysql_flexible_server_infra_double_encryption_enabled",
    "mysql_flexible_server_minimum_tls_version_12",
    "mysql_flexible_server_private_access_enabled",
    "mysql_flexible_server_ssl_connection_enabled",
    "mysql_flexible_server_threat_detection_enabled",
    "network_bastion_host_exists",
    "network_flow_log_captured_sent",
    "network_flow_log_more_than_90_days",
    "network_http_internet_access_restricted",
    "network_public_ip_shodan",
    "network_rdp_internet_access_restricted",
    "network_ssh_internet_access_restricted",
    "network_udp_internet_access_restricted",
    "network_watcher_enabled",
    "postgresql_flexible_server_allow_access_services_disabled",
    "postgresql_flexible_server_enforce_ssl_enabled",
    "postgresql_flexible_server_geo_redundant_backup_enabled",
    "postgresql_flexible_server_infra_double_encryption_enabled",
    "postgresql_flexible_server_log_checkpoints_on",
    "postgresql_flexible_server_log_connections_on",
    "postgresql_flexible_server_log_disconnections_on",
    "postgresql_flexible_server_log_retention_days_greater_3",
    "postgresql_flexible_server_private_dns_zone_configured",
    "postgresql_flexible_server_private_network_access_enabled",
    "postgresql_flexible_server_threat_detection_enabled",
    "redis_cache_rdb_backup_enabled",
    "search_service_public_network_access_disabled",
    "search_service_shared_private_links_enabled",
    "servicebus_queue_public_network_access_disabled",
    "servicebus_topic_public_network_access_disabled",
    "signalr_public_network_access_disabled",
    "sqlserver_atp_enabled",
    "sqlserver_auditing_enabled",
    "sqlserver_auditing_retention_90_days",
    "sqlserver_azuread_administrator_enabled",
    "sqlserver_microsoft_defender_enabled",
    "sqlserver_recommended_minimal_tls_version",
    "sqlserver_tde_encrypted_with_cmk",
    "sqlserver_tde_encryption_enabled",
    "sqlserver_unrestricted_inbound_access",
    "sqlserver_va_emails_notifications_admins_enabled",
    "sqlserver_va_periodic_recurring_scans_enabled",
    "sqlserver_va_scan_reports_configured",
    "sqlserver_vulnerability_assessment_enabled",
    "storage_account_key_access_disabled",
    "storage_blob_public_access_level_is_disabled",
    "storage_blob_versioning_is_enabled",
    "storage_container_public_access_disabled",
    "storage_cross_tenant_replication_disabled",
    "storage_default_network_access_rule_denied",
    "storage_default_network_access_rule_is_denied",
    "storage_default_to_entra_authorization_enabled",
    "storage_ensure_azure_services_are_trusted_to_access_is_enabled",
    "storage_ensure_encryption_with_customer_managed_keys",
    "storage_ensure_file_shares_soft_delete_is_enabled",
    "storage_ensure_minimum_tls_version_12",
    "storage_ensure_private_endpoints_in_storage_accounts",
    "storage_ensure_soft_delete_is_enabled",
    "storage_geo_redundant_enabled",
    "storage_infrastructure_encryption_is_enabled",
    "storage_key_rotation_90_days",
    "storage_queue_public_access_disabled",
    "storage_secure_transfer_required_is_enabled",
    "storage_share_public_access_disabled",
    "storage_smb_channel_encryption_with_secure_algorithm",
    "storage_smb_protocol_version_is_latest",
    "storage_table_public_access_disabled",
    "synapse_workspace_data_exfiltration_protection_enabled",
    "synapse_workspace_managed_virtual_network_enabled",
    "vm_backup_enabled",
    "vm_ensure_attached_disks_encrypted_with_cmk",
    "vm_ensure_unattached_disks_encrypted_with_cmk",
    "vm_ensure_using_approved_images",
    "vm_jit_access_enabled",
    "vm_linux_enforce_ssh_authentication",
    "vm_scaleset_associated_with_load_balancer",
    "vm_sufficient_daily_backup_retention_period",
]

EXISTING_FINDING_HEADLINES = {
    "Azure blob container permits public access": [
        "storage_blob_public_access_level_is_disabled",
        "storage_container_public_access_disabled",
    ],
    "Custom Azure subscription owner roles permitted": [
        "iam_subscription_roles_owner_custom_not_created",
    ],
    "Azure Storage accounts do not enforce encrypted data transfer": [
        "storage_secure_transfer_required_is_enabled",
    ],
    "Stale Azure access keys present": [
        "storage_key_rotation_90_days",
    ],
    "Azure policy permits users to create security groups": [
        "entra_policy_default_users_cannot_create_security_groups",
    ],
    "Azure Storage Accounts permitting deprecated TLS versions": [
        "storage_ensure_minimum_tls_version_12",
    ],
    "Storage accounts with default network access permitted": [
        "storage_default_network_access_rule_denied",
        "storage_default_network_access_rule_is_denied",
    ],
    "Access permitted to PostgreSQL server from Azure services": [
        "postgresql_flexible_server_allow_access_services_disabled",
    ],
    "Azure Monitor Alerts not configured to notify high severity events": [
        "defender_ensure_notify_alerts_severity_is_high",
    ],
    "Storage Accounts not using private IP endpoints": [
        "storage_ensure_private_endpoints_in_storage_accounts",
    ],
    "Azure Storage Containers without Soft Delete protection": [
        "storage_ensure_soft_delete_is_enabled",
    ],
    "Azure Activity Log Alerts missing for key event types": [
        "monitor_alert_create_policy_assignment",
        "monitor_alert_delete_policy_assignment",
        "monitor_alert_create_update_nsg",
        "monitor_alert_delete_nsg",
        "monitor_alert_create_update_public_ip_address_rule",
        "monitor_alert_delete_public_ip_address_rule",
        "monitor_alert_create_update_sqlserver_fr",
        "monitor_alert_delete_sqlserver_fr",
    ],
    "Microsoft Defender for Cloud is not enabled": [
        "defender_ensure_defender_for_app_services_is_on",
        "defender_ensure_defender_for_arm_is_on",
        "defender_ensure_defender_for_azure_sql_databases_is_on",
        "defender_ensure_defender_for_containers_is_on",
        "defender_ensure_defender_for_cosmosdb_is_on",
        "defender_ensure_defender_for_databases_is_on",
        "defender_ensure_defender_for_dns_is_on",
        "defender_ensure_defender_for_keyvault_is_on",
        "defender_ensure_defender_for_os_relational_databases_is_on",
        "defender_ensure_defender_for_server_is_on",
        "defender_ensure_defender_for_sql_servers_is_on",
        "defender_ensure_defender_for_storage_is_on",
        "defender_ensure_iot_hub_defender_is_on",
    ],
    "Role-Based Access Control (RBAC) not enabled for Azure Key Vault": [
        "keyvault_rbac_enabled",
    ],
    "MySQL server without audit logging enabled": [
        "mysql_flexible_server_audit_log_enabled",
    ],
    "PostgreSQL server with short log retention period": [
        "postgresql_flexible_server_log_retention_days_greater_3",
    ],
    "Security contact phone number is not set in Azure tenant": [
        "defender_additional_email_configured_with_a_security_contact",
    ],
    "Azure AppService HTTP logs not enabled enabled": [
        "app_http_logs_enabled",
    ],
    "Azure Network Watcher not enabled for all subscription locations": [
        "network_watcher_enabled",
    ],
    "Azure Key Vault not recoverable": [
        "keyvault_purge_protection_enabled",
        "keyvault_recoverable",
        "keyvault_recoverable_secrets_should_be_enabled",
        "keyvault_soft_delete_enabled",
    ],
    "Ensure Diagnostic Setting captures appropriate categories": [
        "monitor_diagnostic_setting_with_appropriate_categories",
    ],
    "Azure subscription does not have a role for administration of resource locks": [
        "iam_custom_role_has_permissions_to_administer_resource_locks",
    ],
    "Azure App Services using deprecated HTTP Version": [
        "app_ensure_using_http20",
    ],
    "Data at rest in Azure storage accounts use Microsoft managed encryption keys": [
        "storage_ensure_encryption_with_customer_managed_keys",
    ],
    "Azure Subscription-level activity logs without a 'Diagnostic Setting' exist": [
        "monitor_diagnostic_settings_exists",
    ],
    "Azure Storage Accounts without infrastructure encryption enabled": [
        "storage_infrastructure_encryption_is_enabled",
    ],
    "Azure Container Registry admin user enabled": [
        "containerregistry_admin_user_disabled",
    ],
    "AKS clusters without RBAC enabled": [
        "aks_cluster_rbac_enabled",
    ],
    "AKS clusters not using a private control plane": [
        "aks_clusters_public_access_disabled",
    ],
    "Network security groups expose administrative ports to the Internet": [
        "network_rdp_internet_access_restricted",
        "network_ssh_internet_access_restricted",
    ],
    "Azure App Services do not enforce HTTPS": [
        "app_ensure_http_is_redirected_to_https",
    ],
    "Azure App Services do not require client certificates": [
        "app_client_certificates_on",
    ],
    "Azure App Services permit TLS versions below 1.2": [
        "app_minimum_tls_version_12",
    ],
    "Azure App Services do not disable FTP deployment": [
        "app_ftp_deployment_disabled",
    ],
    "Azure App Services are not registered with a managed identity": [
        "app_register_with_identity",
    ],
    "Azure App Services do not have authentication configured": [
        "app_ensure_auth_is_set_up",
    ],
    "Azure App Services are missing Application Insights configuration": [
        "appinsights_ensure_is_configured",
    ],
    "Function Apps are missing Application Insights configuration": [
        "app_function_application_insights_enabled",
    ],
    "Function Apps do not have access keys configured": [
        "app_function_access_keys_configured",
    ],
    "Function Apps do not disable FTP deployment": [
        "app_function_ftps_deployment_disabled",
    ],
    "Function Apps do not have a managed identity configured": [
        "app_function_identity_is_configured",
    ],
    "Function Apps are publicly reachable": [
        "app_function_not_publicly_accessible",
    ],
    "Function Apps are not integrated with a virtual network": [
        "app_function_vnet_integration_enabled",
    ],
    "Azure Container Registries allow public network access": [
        "containerregistry_not_publicly_accessible",
    ],
    "Azure Container Registries do not use private link": [
        "containerregistry_uses_private_link",
    ],
    "Cosmos DB accounts do not restrict network access": [
        "cosmosdb_account_firewall_use_selected_networks",
    ],
    "Cosmos DB accounts do not use private endpoints": [
        "cosmosdb_account_use_private_endpoints",
    ],
    "Cosmos DB accounts do not use Microsoft Entra ID and RBAC": [
        "cosmosdb_account_use_aad_and_rbac",
    ],
    "Cognitive Services accounts permit local authentication": [
        "cognitive_services_local_auth_disabled",
    ],
    "Databricks workspaces do not enable customer-managed key encryption": [
        "databricks_workspace_cmk_encryption_enabled",
    ],
    "Databricks workspaces do not use VNet injection": [
        "databricks_workspace_vnet_injection_enabled",
    ],
    "Event Grid Topics allow public network access": [
        "eventgrid_topic_public_network_access_disabled",
    ],
    "Event Grid Domains allow public network access": [
        "eventgrid_domain_public_network_access_disabled",
    ],
    "IoT Device Provisioning Services allow public network access": [
        "iot_dps_public_network_access_disabled",
    ],
    "Defender auto provisioning for Log Analytics agents is not enabled": [
        "defender_auto_provisioning_log_analytics_agent_vms_on",
    ],
    "Microsoft Defender security contacts do not notify subscription owners": [
        "defender_ensure_notify_emails_to_owners",
    ],
    "Microsoft Entra security defaults are not enabled": [
        "entra_security_defaults_enabled",
    ],
    "Microsoft Entra trusted named locations are not configured": [
        "entra_trusted_named_locations_exists",
    ],
    "Microsoft Entra default users can create applications": [
        "entra_policy_ensure_default_user_cannot_create_apps",
    ],
    "Microsoft Entra default users can create tenants": [
        "entra_policy_ensure_default_user_cannot_create_tenants",
    ],
    "Microsoft Entra guest invites are not restricted to admins": [
        "entra_policy_guest_invite_only_for_admin_roles",
    ],
    "Microsoft Entra guest user access restrictions are not configured": [
        "entra_policy_guest_users_access_restrictions",
    ],
    "Azure Key Vaults do not use private endpoints": [
        "keyvault_access_only_through_private_endpoints",
        "keyvault_private_endpoints",
    ],
    "Azure Key Vaults do not have diagnostic logging enabled": [
        "keyvault_logging_enabled",
    ],
    "AKS clusters do not have Azure Policy enabled": [
        "kubernetes_cluster_azure_policy_enabled",
    ],
    "AKS clusters do not have a network policy configured": [
        "aks_network_policy_enabled",
    ],
    "AKS clusters use public node IPs": [
        "aks_clusters_created_with_private_nodes",
    ],
    "Machine Learning workspaces allow public network access": [
        "machine_learning_workspace_public_access_disabled",
    ],
    "Machine Learning workspaces do not use virtual network integration": [
        "machine_learning_workspace_vnet_configured",
    ],
    "Azure Activity Log Alerts missing for service health events": [
        "monitor_alert_service_health_exists",
    ],
    "Azure Activity Log Alerts missing for security solution changes": [
        "monitor_alert_create_update_security_solution",
        "monitor_alert_delete_security_solution",
    ],
    "Subscription activity logs are stored in accounts without customer-managed keys": [
        "monitor_storage_account_with_activity_logs_cmk_encrypted",
    ],
    "Subscription activity logs are stored in accounts without private endpoints": [
        "monitor_storage_account_with_activity_logs_is_private",
    ],
    "MySQL flexible servers do not have audit logging enabled": [
        "mysql_flexible_server_audit_log_enabled",
    ],
    "MySQL flexible servers do not enable geo-redundant backup": [
        "mysql_flexible_server_geo_redundant_backup_enabled",
    ],
    "MySQL flexible servers permit TLS versions below 1.2": [
        "mysql_flexible_server_minimum_tls_version_12",
    ],
    "MySQL flexible servers do not enforce SSL connections": [
        "mysql_flexible_server_ssl_connection_enabled",
    ],
    "PostgreSQL flexible servers do not enforce SSL connections": [
        "postgresql_flexible_server_enforce_ssl_enabled",
    ],
    "PostgreSQL flexible servers do not enable geo-redundant backup": [
        "postgresql_flexible_server_geo_redundant_backup_enabled",
    ],
    "PostgreSQL flexible servers do not log checkpoints": [
        "postgresql_flexible_server_log_checkpoints_on",
    ],
    "PostgreSQL flexible servers do not log connections": [
        "postgresql_flexible_server_log_connections_on",
    ],
    "PostgreSQL flexible servers do not log disconnections": [
        "postgresql_flexible_server_log_disconnections_on",
    ],
    "PostgreSQL flexible servers do not have a private DNS zone configured": [
        "postgresql_flexible_server_private_dns_zone_configured",
    ],
    "PostgreSQL flexible servers do not use private network access": [
        "postgresql_flexible_server_private_network_access_enabled",
    ],
    "Redis caches do not have RDB backup enabled": [
        "redis_cache_rdb_backup_enabled",
    ],
    "Azure AI Search services allow public network access": [
        "aisearch_service_not_publicly_accessible",
        "search_service_public_network_access_disabled",
    ],
    "Azure AI Search services do not use shared private links": [
        "search_service_shared_private_links_enabled",
    ],
    "SignalR services allow public network access": [
        "signalr_public_network_access_disabled",
    ],
    "SQL servers do not have Advanced Threat Protection enabled": [
        "sqlserver_atp_enabled",
        "sqlserver_microsoft_defender_enabled",
    ],
    "SQL servers do not have auditing enabled": [
        "sqlserver_auditing_enabled",
    ],
    "SQL servers do not retain audit logs for at least 90 days": [
        "sqlserver_auditing_retention_90_days",
    ],
    "SQL servers do not have an Azure AD administrator configured": [
        "sqlserver_azuread_administrator_enabled",
    ],
    "SQL servers do not encrypt TDE with customer-managed keys": [
        "sqlserver_tde_encrypted_with_cmk",
    ],
    "SQL databases do not have Transparent Data Encryption enabled": [
        "sqlserver_tde_encryption_enabled",
    ],
    "SQL servers permit unrestricted inbound access": [
        "sqlserver_unrestricted_inbound_access",
    ],
    "SQL servers do not have vulnerability assessment configured": [
        "sqlserver_va_periodic_recurring_scans_enabled",
        "sqlserver_va_scan_reports_configured",
        "sqlserver_vulnerability_assessment_enabled",
    ],
    "Storage accounts permit shared key access": [
        "storage_account_key_access_disabled",
    ],
    "Storage accounts do not enable file share soft delete": [
        "storage_ensure_file_shares_soft_delete_is_enabled",
    ],
    "Storage accounts do not have blob versioning enabled": [
        "storage_blob_versioning_is_enabled",
    ],
    "Storage accounts allow cross-tenant replication": [
        "storage_cross_tenant_replication_disabled",
    ],
    "Storage accounts do not default to Microsoft Entra authorization": [
        "storage_default_to_entra_authorization_enabled",
    ],
    "Storage accounts do not trust Azure services network bypass": [
        "storage_ensure_azure_services_are_trusted_to_access_is_enabled",
    ],
    "Storage accounts do not use geo-redundant replication": [
        "storage_geo_redundant_enabled",
    ],
    "Synapse workspaces do not enable data exfiltration protection": [
        "synapse_workspace_data_exfiltration_protection_enabled",
    ],
    "Synapse workspaces do not use a managed virtual network": [
        "synapse_workspace_managed_virtual_network_enabled",
    ],
    "Azure Bastion hosts are not deployed": [
        "network_bastion_host_exists",
    ],
    "Network Watcher flow logs are not captured to storage": [
        "network_flow_log_captured_sent",
    ],
    "Network Watcher flow logs do not retain data for more than 90 days": [
        "network_flow_log_more_than_90_days",
    ],
    "Virtual machines are not protected by backup": [
        "vm_backup_enabled",
    ],
    "Virtual machines do not have JIT access enabled": [
        "vm_jit_access_enabled",
    ],
    "Virtual machine attached disks are not encrypted with customer-managed keys": [
        "vm_ensure_attached_disks_encrypted_with_cmk",
    ],
    "Unattached managed disks are not encrypted with customer-managed keys": [
        "vm_ensure_unattached_disks_encrypted_with_cmk",
    ],
    "Linux virtual machines allow password-based SSH authentication": [
        "vm_linux_enforce_ssh_authentication",
    ],
    "Virtual machine scale sets are not associated with a load balancer": [
        "vm_scaleset_associated_with_load_balancer",
    ],
    "Azure AD Users Can Create Security Groups": [
        "entra_policy_default_users_cannot_create_security_groups",
    ],
    "App Service Authentication Not Enabled": [
        "app_ensure_auth_is_set_up",
    ],
    "App Service Client Certificates Not Required": [
        "app_client_certificates_on",
    ],
    "App Service FTP Deployment Enabled": [
        "app_ftp_deployment_disabled",
    ],
    "App Service HTTP/2 Not Enabled": [
        "app_ensure_using_http20",
    ],
    "App Service Allows Unencrypted HTTP": [
        "app_ensure_http_is_redirected_to_https",
    ],
    "App Service Managed Identity Not Enabled": [
        "app_register_with_identity",
    ],
    "App Service Running Outdated Java Version": [
        "app_ensure_java_version_is_latest",
    ],
    "App Service Running Outdated PHP Version": [
        "app_ensure_php_version_is_latest",
    ],
    "App Service Running Outdated Python Version": [
        "app_ensure_python_version_is_latest",
    ],
    "App Service Supports TLS 1.0 or 1.1": [
        "app_minimum_tls_version_12",
    ],
    "Key Vault Recovery Protection Not Enabled": [
        "keyvault_purge_protection_enabled",
    ],
    "Key Vault RBAC Authorisation Not Enabled": [
        "keyvault_rbac_enabled",
    ],
    "Key Vault Logging Not Enabled": [
        "keyvault_logging_enabled",
    ],
    "Diagnostic Settings Not Configured": [
        "monitor_diagnostic_settings_exists",
    ],
    "Users with Permission to Administer Resource Locks Assigned": [
        "iam_custom_role_has_permissions_to_administer_resource_locks",
    ],
    "MySQL Server SSL Enforcement Not Enabled": [
        "mysql_flexible_server_ssl_connection_enabled",
    ],
    "Network Watcher Not Enabled": [
        "network_watcher_enabled",
    ],
    "Network Watcher Not Provisioned": [
        "network_watcher_enabled",
    ],
    "PostgreSQL Server Checkpoint Logging Not Enabled": [
        "postgresql_flexible_server_log_checkpoints_on",
    ],
    "PostgreSQL Server Connection Logging Not Enabled": [
        "postgresql_flexible_server_log_connections_on",
    ],
    "PostgreSQL Server Disconnection Logging Not Enabled": [
        "postgresql_flexible_server_log_disconnections_on",
    ],
    "PostgreSQL Server Log Retention Below 4 Days": [
        "postgresql_flexible_server_log_retention_days_greater_3",
    ],
    "PostgreSQL Server SSL Enforcement Not Enabled": [
        "postgresql_flexible_server_enforce_ssl_enabled",
    ],
    "SQL Server Allows Access from Any IP": [
        "sqlserver_unrestricted_inbound_access",
    ],
    "SQL Database Transparent Data Encryption Not Enabled": [
        "sqlserver_tde_encryption_enabled",
    ],
    "SQL Server TDE Not Using Customer Managed Keys": [
        "sqlserver_tde_encrypted_with_cmk",
    ],
    "SQL Server Auditing Retention Period Too Low": [
        "sqlserver_auditing_retention_90_days",
    ],
    "SQL Server Azure AD Administrator Not Configured": [
        "sqlserver_azuread_administrator_enabled",
    ],
    "SQL Server Auditing Not Enabled": [
        "sqlserver_auditing_enabled",
    ],
    "SQL Server Threat Detection Not Enabled": [
        "sqlserver_atp_enabled",
    ],
    "SQL Server Vulnerability Assessment Not Enabled": [
        "sqlserver_vulnerability_assessment_enabled",
    ],
    "SQL Server Vulnerability Assessment Recurring Scans Not Enabled": [
        "sqlserver_va_periodic_recurring_scans_enabled",
    ],
    "Storage Account Allows Unencrypted Traffic": [
        "storage_secure_transfer_required_is_enabled",
    ],
    "Storage Account Not Encrypted with Customer Managed Keys": [
        "storage_ensure_encryption_with_customer_managed_keys",
    ],
    "Blob Containers Allow Public Access": [
        "storage_container_public_access_disabled",
    ],
    "Storage Account Allows Public Network Access": [
        "storage_default_network_access_rule_denied",
    ],
    "Storage Account Soft Delete Not Enabled": [
        "storage_ensure_soft_delete_is_enabled",
    ],
    "Storage Account Permits Trusted Microsoft Services Bypass": [
        "storage_ensure_azure_services_are_trusted_to_access_is_enabled",
    ],
    "VM OS and Data Disks Not Encrypted with Customer Managed Keys": [
        "vm_ensure_attached_disks_encrypted_with_cmk",
    ],
    "Unattached Managed Disks Not Encrypted with Customer Managed Keys": [
        "vm_ensure_unattached_disks_encrypted_with_cmk",
    ],
    "API Management services are missing LLM jacking threat-detection coverage": [
        "apim_threat_detection_llm_jacking",
    ],
    "Function Apps have managed identities with administrative privileges": [
        "app_function_identity_without_admin_privileges",
    ],
    "Function Apps are not using the latest Functions runtime major version": [
        "app_function_latest_runtime_version",
    ],
    "App Service Environment vNet injection not deployed": [
        "app_service_environment_injection_deployed",
    ],
    "Defender endpoint protection is not installed on virtual machines": [
        "defender_assessments_vm_endpoint_protection_installed",
    ],
    "Defender auto provisioning for vulnerability assessments is not enabled on machines": [
        "defender_auto_provisioning_vulnerabilty_assessments_machines_on",
    ],
    "Defender assessments report unresolved container image vulnerabilities": [
        "defender_container_images_resolved_vulnerabilities",
    ],
    "Container image vulnerability scanning is not enabled": [
        "defender_container_images_scan_enabled",
    ],
    "Microsoft Cloud App Security Integration Not Enabled": [
        "defender_ensure_mcas_is_enabled",
    ],
    "System updates are not fully applied on machines": [
        "defender_ensure_system_updates_are_applied",
    ],
    "Microsoft Defender ATP Integration Not Enabled": [
        "defender_ensure_wdatp_is_enabled",
    ],
    "Conditional Access does not require MFA for admin portals": [
        "entra_conditional_access_policy_require_mfa_for_admin_portals",
    ],
    "Conditional Access does not require MFA for the Azure management API": [
        "entra_conditional_access_policy_require_mfa_for_management_api",
    ],
    "Global Administrator role is assigned to five or more users": [
        "entra_global_admin_in_less_than_five_users",
    ],
    "Non-privileged Microsoft Entra users do not have MFA": [
        "entra_non_privileged_user_has_mfa",
    ],
    "User consent for applications is not sufficiently restricted": [
        "entra_policy_restricts_user_consent_for_apps",
    ],
    "User consent for verified applications is not enforced": [
        "entra_policy_user_consent_for_verified_apps",
    ],
    "Privileged Microsoft Entra users do not have MFA": [
        "entra_privileged_user_has_mfa",
    ],
    "Users with VM access do not have MFA": [
        "entra_user_with_vm_access_has_mfa",
    ],
    "Users can create Microsoft 365 groups": [
        "entra_users_cannot_create_microsoft_365_groups",
    ],
    "HDInsight Kafka clusters do not disable manual authentication": [
        "hdinsight_kafka_cluster_manual_auth_disabled",
    ],
    "User Access Administrator role is assigned directly to users": [
        "iam_role_user_access_admin_restricted",
    ],
    "Non-RBAC Key Vault keys do not have expiration dates": [
        "keyvault_key_expiration_set_in_non_rbac",
    ],
    "Key Vault keys do not have rotation enabled": [
        "keyvault_key_rotation_enabled",
    ],
    "Key Vault keys are older than 365 days": [
        "keyvault_keys_older_than_365_days",
    ],
    "Non-RBAC Key Vault secrets do not have expiration dates": [
        "keyvault_non_rbac_secret_expiration_set",
    ],
    "RBAC Key Vault keys do not have expiration dates": [
        "keyvault_rbac_key_expiration_set",
    ],
    "RBAC Key Vault secrets do not have expiration dates": [
        "keyvault_rbac_secret_expiration_set",
    ],
    "Key Vault secrets do not have expiration dates": [
        "keyvault_secret_expiration_set",
    ],
    "MySQL flexible servers do not audit connection events": [
        "mysql_flexible_server_audit_log_connection_activated",
    ],
    "MySQL flexible servers do not enable infrastructure double encryption": [
        "mysql_flexible_server_infra_double_encryption_enabled",
    ],
    "MySQL flexible servers do not use private access": [
        "mysql_flexible_server_private_access_enabled",
    ],
    "MySQL flexible servers do not have Defender threat detection enabled": [
        "mysql_flexible_server_threat_detection_enabled",
    ],
    "HTTP is exposed to the internet through NSG rules": [
        "network_http_internet_access_restricted",
    ],
    "NSG Inbound Rule Allows Internet Access to UDP Services": [
        "network_udp_internet_access_restricted",
    ],
    "Public IP addresses are exposed to internet indexing services": [
        "network_public_ip_shodan",
    ],
    "PostgreSQL flexible servers do not enable infrastructure double encryption": [
        "postgresql_flexible_server_infra_double_encryption_enabled",
    ],
    "PostgreSQL flexible servers do not have Defender threat detection enabled": [
        "postgresql_flexible_server_threat_detection_enabled",
    ],
    "Service Bus queues allow public network access": [
        "servicebus_queue_public_network_access_disabled",
    ],
    "Service Bus topics allow public network access": [
        "servicebus_topic_public_network_access_disabled",
    ],
    "SQL servers use a minimal TLS version below the recommended baseline": [
        "sqlserver_recommended_minimal_tls_version",
    ],
    "SQL Server Vulnerability Assessment Email Notifications to Admins and Owners Not Enabled": [
        "sqlserver_va_emails_notifications_admins_enabled",
    ],
    "Storage Account Access Keys Not Rotated": [
        "storage_key_rotation_90_days",
    ],
    "Storage queues allow public access": [
        "storage_queue_public_access_disabled",
    ],
    "Storage shares allow public access": [
        "storage_share_public_access_disabled",
    ],
    "Storage accounts do not use secure SMB channel encryption algorithms": [
        "storage_smb_channel_encryption_with_secure_algorithm",
    ],
    "Storage accounts do not use the latest SMB protocol version": [
        "storage_smb_protocol_version_is_latest",
    ],
    "Storage tables allow public access": [
        "storage_table_public_access_disabled",
    ],
    "Virtual machines are not using approved base images": [
        "vm_ensure_using_approved_images",
    ],
    "Virtual machine backup policies do not retain daily restore points long enough": [
        "vm_sufficient_daily_backup_retention_period",
    ],
}
