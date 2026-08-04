#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Declarative Microsoft Graph collection registry.

Endpoints in this registry are assessment reads.  Beta entries are deliberately
labelled and are used only where Microsoft Graph has no equivalent v1.0 API.
"""

import re
from typing import Dict, Iterable, List, Mapping, Sequence, Union


def _endpoint(
    endpoint_id: str,
    name: str,
    profile: str,
    permission: Union[str, Sequence[str]],
    path: str,
    *,
    api: str = "v1.0",
    method: str = "GET",
    pagination: bool = True,
    licence: str = "Microsoft Graph capability and applicable workload licence",
    mode: str = "collection",
    body: Mapping = None,
    fan_out: Mapping = None,
    response_format: str = "json",
    aliases: Sequence[str] = (),
    records_field: str = None,
) -> Dict:
    profile_slug = re.sub(r"(?<!^)(?=[A-Z])", "_", profile).lower()
    permissions = (
        [permission] if isinstance(permission, str)
        else list(permission)
    )
    if not permissions:
        raise ValueError("Graph endpoints require at least one application permission")
    return {
        "id": endpoint_id,
        "name": name,
        "profile": profile,
        # `permission` remains for manifest 2.5 and older consumers. New code
        # uses `permissions` to represent endpoints requiring every listed role.
        "permission": permissions[0],
        "permissions": permissions,
        "api": api,
        "method": method,
        "path": path,
        "pagination": pagination,
        "output": f"graph_{profile_slug}_{endpoint_id}",
        "licence": licence,
        "mode": mode,
        "response_format": response_format,
        "aliases": list(aliases),
        **({"records_field": records_field} if records_field else {}),
        **({"body": dict(body)} if body else {}),
        **({"fan_out": dict(fan_out)} if fan_out else {}),
    }


E = _endpoint
GRAPH_ENDPOINTS: List[Dict] = [
    # Identity baseline
    E("applications", "Graph Applications", "IdentityBaseline", "Application.Read.All", "/applications", aliases=("Active Directory Applications", "az ad app list")),
    E("service_principals", "Graph Service Principals", "IdentityBaseline", "Application.Read.All", "/servicePrincipals", aliases=("Active Directory Service Principals", "az ad sp list --all")),
    E("groups", "Graph Groups", "IdentityBaseline", "Directory.Read.All", "/groups", aliases=("Active Directory Groups", "az ad group list")),
    E("directory_audits", "Graph Directory Audits", "IdentityBaseline", "AuditLog.Read.All", "/auditLogs/directoryAudits?$filter=activityDateTime ge {start}"),
    E("sign_ins", "Graph Sign-ins", "IdentityBaseline", "AuditLog.Read.All", "/auditLogs/signIns?$filter=createdDateTime ge {start}"),
    E("organisation", "Graph Organisation", "IdentityBaseline", "Directory.Read.All", "/organization"),
    E("domains", "Graph Domains", "IdentityBaseline", "Directory.Read.All", "/domains"),
    E("administrative_units", "Graph Administrative Units", "IdentityBaseline", "Directory.Read.All", "/directory/administrativeUnits"),
    E("recommendations", "Graph Directory Recommendations", "IdentityBaseline", "DirectoryRecommendations.Read.All", "/directory/recommendations", api="beta"),
    E("recommendation_impacted_resources", "Graph Recommendation Impacted Resources", "IdentityBaseline", "DirectoryRecommendations.Read.All", "/directory/recommendations/{parent_id}/impactedResources", api="beta", fan_out={"parent": "recommendations", "id": "id"}),
    E("entitlement_catalogs", "Graph Entitlement Catalogs", "IdentityBaseline", "EntitlementManagement.Read.All", "/identityGovernance/entitlementManagement/catalogs"),
    E("entitlement_packages", "Graph Entitlement Packages", "IdentityBaseline", "EntitlementManagement.Read.All", "/identityGovernance/entitlementManagement/accessPackages"),
    E("entitlement_policies", "Graph Entitlement Assignment Policies", "IdentityBaseline", "EntitlementManagement.Read.All", "/identityGovernance/entitlementManagement/assignmentPolicies"),
    E("entitlement_assignments", "Graph Entitlement Assignments", "IdentityBaseline", "EntitlementManagement.Read.All", "/identityGovernance/entitlementManagement/assignments"),
    E("connected_organisations", "Graph Connected Organisations", "IdentityBaseline", "EntitlementManagement.Read.All", "/identityGovernance/entitlementManagement/connectedOrganizations"),
    E("identity_providers", "Graph Identity Providers", "IdentityBaseline", "IdentityProvider.Read.All", "/identity/identityProviders"),
    E("risk_detections", "Graph Risk Detections", "IdentityBaseline", "IdentityRiskEvent.Read.All", "/identityProtection/riskDetections?$filter=detectedDateTime ge {start}"),
    E("onprem_sync", "Graph On-premises Synchronisation", "IdentityBaseline", "OnPremDirectorySynchronization.Read.All", "/directory/onPremisesSynchronization"),
    E("identity_policies", "Graph Authorization Policy", "IdentityBaseline", "Policy.Read.All", "/policies/authorizationPolicy", pagination=False),
    E("security_defaults", "Graph Security Defaults Policy", "IdentityBaseline", "Policy.Read.All", "/policies/identitySecurityDefaultsEnforcementPolicy", pagination=False),
    E("conditional_access", "Graph Conditional Access Policies", "IdentityBaseline", "Policy.Read.ConditionalAccess", "/identity/conditionalAccess/policies"),
    E("named_locations", "Graph Named Locations", "IdentityBaseline", "Policy.Read.ConditionalAccess", "/identity/conditionalAccess/namedLocations"),
    E("provisioning_logs", "Graph Provisioning Logs", "IdentityBaseline", ("AuditLog.Read.All", "Directory.Read.All"), "/auditLogs/provisioning?$filter=activityDateTime ge {start}"),
    E("credential_usage_report", "Graph Credential Usage Report", "IdentityBaseline", "Reports.Read.All", "/reports/getCredentialUsageSummary(period='D30')", api="beta"),
    E("report_settings", "Graph Report Settings", "IdentityBaseline", "ReportSettings.Read.All", "/admin/reportSettings", pagination=False),
    E("directory_role_assignments", "Graph Directory Role Assignments", "IdentityBaseline", "RoleManagement.Read.Directory", "/roleManagement/directory/roleAssignments"),
    E("directory_roles", "Graph Directory Roles", "IdentityBaseline", "RoleManagement.Read.Directory", "/directoryRoles"),
    E("user_registration_details", "Graph User Registration Details", "IdentityBaseline", "AuditLog.Read.All", "/reports/authenticationMethods/userRegistrationDetails"),
    E("group_settings", "Graph Group Settings", "IdentityBaseline", "Directory.Read.All", "/groupSettings"),
    E("user_authentication_methods", "Graph User Authentication Methods", "IdentityBaseline", "UserAuthenticationMethod.Read.All", "/users/{parent_id}/authentication/methods", fan_out={"parent": "users", "id": "id"}),
    E("users", "Graph Users", "IdentityBaseline", "Directory.Read.All", "/users?$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,externalUserState", aliases=("Active Directory Users", "az ad user list")),

    # Privileged identity management
    E("pim_directory_eligible", "PIM Directory Eligible Schedules", "PIM", "RoleEligibilitySchedule.Read.Directory", "/roleManagement/directory/roleEligibilitySchedules"),
    E("pim_directory_eligibility_requests", "PIM Directory Eligibility Requests", "PIM", "RoleEligibilitySchedule.Read.Directory", "/roleManagement/directory/roleEligibilityScheduleRequests"),
    E("pim_directory_eligibility_instances", "PIM Directory Eligibility Instances", "PIM", "RoleEligibilitySchedule.Read.Directory", "/roleManagement/directory/roleEligibilityScheduleInstances"),
    E("pim_directory_active", "PIM Directory Active Schedules", "PIM", "RoleAssignmentSchedule.Read.Directory", "/roleManagement/directory/roleAssignmentSchedules"),
    E("pim_directory_requests", "PIM Directory Assignment Requests", "PIM", "RoleAssignmentSchedule.Read.Directory", "/roleManagement/directory/roleAssignmentScheduleRequests"),
    E("pim_directory_schedule_instances", "PIM Directory Assignment Instances", "PIM", "RoleAssignmentSchedule.Read.Directory", "/roleManagement/directory/roleAssignmentScheduleInstances"),
    E("pim_group_eligible", "PIM Group Eligible Schedules", "PIM", "PrivilegedEligibilitySchedule.Read.AzureADGroup", "/identityGovernance/privilegedAccess/group/eligibilitySchedules?$filter=groupId eq '{parent_id}'", fan_out={"parent": "groups", "id": "id"}),
    E("pim_group_eligibility_requests", "PIM Group Eligibility Requests", "PIM", "PrivilegedEligibilitySchedule.Read.AzureADGroup", "/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests?$filter=groupId eq '{parent_id}'", fan_out={"parent": "groups", "id": "id"}),
    E("pim_group_eligibility_instances", "PIM Group Eligibility Instances", "PIM", "PrivilegedEligibilitySchedule.Read.AzureADGroup", "/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?$filter=groupId eq '{parent_id}'", fan_out={"parent": "groups", "id": "id"}),
    E("pim_group_active", "PIM Group Active Schedules", "PIM", "PrivilegedAssignmentSchedule.Read.AzureADGroup", "/identityGovernance/privilegedAccess/group/assignmentSchedules?$filter=groupId eq '{parent_id}'", fan_out={"parent": "groups", "id": "id"}),
    E("pim_group_requests", "PIM Group Assignment Requests", "PIM", "PrivilegedAssignmentSchedule.Read.AzureADGroup", "/identityGovernance/privilegedAccess/group/assignmentScheduleRequests?$filter=groupId eq '{parent_id}'", fan_out={"parent": "groups", "id": "id"}),
    E("pim_group_schedule_instances", "PIM Group Assignment Instances", "PIM", "PrivilegedAssignmentSchedule.Read.AzureADGroup", "/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?$filter=groupId eq '{parent_id}'", fan_out={"parent": "groups", "id": "id"}),
    E("pim_alerts", "PIM Role Management Alerts", "PIM", "RoleManagementAlert.Read.Directory", "/identityGovernance/roleManagementAlerts/alerts?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'", api="beta"),
    E("pim_alert_configurations", "PIM Alert Configurations", "PIM", "RoleManagementAlert.Read.Directory", "/identityGovernance/roleManagementAlerts/alertConfigurations?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'", api="beta"),

    # Microsoft 365 audit and service activity
    E("audit_general", "Microsoft 365 Unified Audit General", "M365Audit", "AuditLogsQuery.Read.All", "/security/auditLog/queries", api="beta", method="POST", mode="audit_query", body={"displayName": "Azure Assess general", "filterStartDateTime": "{start}", "filterEndDateTime": "{end}"}),
    E("audit_exchange", "Microsoft 365 Unified Audit Exchange", "M365Audit", "AuditLogsQuery-Exchange.Read.All", "/security/auditLog/queries", api="beta", method="POST", mode="audit_query", body={"displayName": "Azure Assess Exchange", "filterStartDateTime": "{start}", "filterEndDateTime": "{end}", "serviceFilter": "Exchange"}),
    E("audit_onedrive", "Microsoft 365 Unified Audit OneDrive", "M365Audit", "AuditLogsQuery-OneDrive.Read.All", "/security/auditLog/queries", api="beta", method="POST", mode="audit_query", body={"displayName": "Azure Assess OneDrive", "filterStartDateTime": "{start}", "filterEndDateTime": "{end}", "serviceFilter": "OneDrive"}),
    E("audit_sharepoint", "Microsoft 365 Unified Audit SharePoint", "M365Audit", "AuditLogsQuery-SharePoint.Read.All", "/security/auditLog/queries", api="beta", method="POST", mode="audit_query", body={"displayName": "Azure Assess SharePoint", "filterStartDateTime": "{start}", "filterEndDateTime": "{end}", "serviceFilter": "SharePoint"}),
    E("activity_exchange", "Exchange Service Activity", "M365Audit", "Reports.Read.All", "/reports/getEmailActivityUserDetail(period='D30')", response_format="csv"),
    E("activity_m365_web", "Microsoft 365 Web Activity", "M365Audit", "Reports.Read.All", "/reports/getOffice365ActiveUserDetail(period='D30')", response_format="csv"),
    E("activity_onedrive", "OneDrive Service Activity", "M365Audit", "Reports.Read.All", "/reports/getOneDriveActivityUserDetail(period='D30')", response_format="csv"),
    E("activity_teams", "Teams Service Activity", "M365Audit", "Reports.Read.All", "/reports/getTeamsUserActivityUserDetail(period='D30')", response_format="csv"),
    E("settings_apps_services", "Apps and Services Settings", "M365Audit", "OrgSettings-AppsAndServices.Read.All", "/admin/appsAndServices", api="beta", pagination=False),
    E("settings_forms", "Microsoft Forms Settings", "M365Audit", "OrgSettings-Forms.Read.All", "/admin/forms", api="beta", pagination=False),
    E("settings_sharepoint", "SharePoint Tenant Settings", "M365Audit", "SharePointTenantSettings.Read.All", "/admin/sharepoint/settings", pagination=False),

    # Endpoint and Intune. BitLocker deliberately excludes the recovery key value.
    E("bitlocker_key_metadata", "BitLocker Recovery Key Metadata", "EndpointIntune", "BitlockerKey.Read.All", "/informationProtection/bitlocker/recoveryKeys?$select=id,createdDateTime,volumeType,deviceId"),
    E("managed_devices", "Intune Managed Devices", "EndpointIntune", "DeviceManagementManagedDevices.Read.All", "/deviceManagement/managedDevices"),
    E("detected_apps", "Intune Detected Applications", "EndpointIntune", "DeviceManagementManagedDevices.Read.All", "/deviceManagement/detectedApps"),
    E("device_configurations", "Intune Device Configurations", "EndpointIntune", "DeviceManagementConfiguration.Read.All", "/deviceManagement/deviceConfigurations"),
    E("compliance_policies", "Intune Compliance Policies", "EndpointIntune", "DeviceManagementConfiguration.Read.All", "/deviceManagement/deviceCompliancePolicies"),
    E("settings_catalog", "Intune Settings Catalog Policies", "EndpointIntune", "DeviceManagementConfiguration.Read.All", "/deviceManagement/configurationPolicies", api="beta"),
    E("intune_role_definitions", "Intune Role Definitions", "EndpointIntune", "DeviceManagementRBAC.Read.All", "/deviceManagement/roleDefinitions"),
    E("intune_role_assignments", "Intune Role Assignments", "EndpointIntune", "DeviceManagementRBAC.Read.All", "/deviceManagement/roleAssignments"),
    E("intune_scope_tags", "Intune Scope Tags", "EndpointIntune", "DeviceManagementRBAC.Read.All", "/deviceManagement/roleScopeTags"),
    E("enrolment_restrictions", "Intune Enrolment Restrictions", "EndpointIntune", "DeviceManagementServiceConfig.Read.All", "/deviceManagement/deviceEnrollmentConfigurations"),
    E("autopilot_profiles", "Windows Autopilot Profiles", "EndpointIntune", "DeviceManagementServiceConfig.Read.All", "/deviceManagement/windowsAutopilotDeploymentProfiles"),
    E("device_categories", "Intune Device Categories", "EndpointIntune", "DeviceManagementServiceConfig.Read.All", "/deviceManagement/deviceCategories"),
    E("terms_conditions", "Intune Terms and Conditions", "EndpointIntune", "DeviceManagementServiceConfig.Read.All", "/deviceManagement/termsAndConditions"),
    E("notification_templates", "Intune Notification Templates", "EndpointIntune", "DeviceManagementServiceConfig.Read.All", "/deviceManagement/notificationMessageTemplates"),
    E("security_connectors", "Intune Security Connectors", "EndpointIntune", "DeviceManagementServiceConfig.Read.All", "/deviceManagement/mobileThreatDefenseConnectors"),

    # Global Secure Access (currently beta-only).
    E("gsa_tenant_status", "Global Secure Access Tenant Status", "GlobalSecureAccess", "NetworkAccess.Read.All", "/networkAccess/tenantStatus", api="beta", pagination=False),
    E("gsa_forwarding_profiles", "Global Secure Access Forwarding Profiles", "GlobalSecureAccess", "NetworkAccess.Read.All", "/networkAccess/forwardingProfiles", api="beta"),
    E("gsa_forwarding_policies", "Global Secure Access Forwarding Policies", "GlobalSecureAccess", "NetworkAccess.Read.All", "/networkAccess/forwardingPolicies", api="beta"),
    E("gsa_filtering_policies", "Global Secure Access Filtering Policies", "GlobalSecureAccess", "NetworkAccess.Read.All", "/networkAccess/filteringPolicies", api="beta"),
    E("gsa_tls_policies", "Global Secure Access TLS Inspection Policies", "GlobalSecureAccess", "NetworkAccess.Read.All", "/networkAccess/tlsInspectionPolicies", api="beta"),
    E("gsa_branches", "Global Secure Access Branches", "GlobalSecureAccess", "NetworkAccess.Read.All", "/networkAccess/connectivity/branches", api="beta"),
    E("gsa_connectors", "Global Secure Access Connectors", "GlobalSecureAccess", "NetworkAccess.Read.All", "/networkAccess/connectivity/connectors", api="beta"),
    E("gsa_policy_assignments", "Global Secure Access Policy Assignments", "GlobalSecureAccess", "NetworkAccess.Read.All", "/networkAccess/policyAssignments", api="beta"),

    # Defender workloads and a versioned, fixed Advanced Hunting pack.
    E("defender_identity_sensors", "Defender for Identity Sensors", "DefenderHunting", "SecurityIdentitiesSensors.Read.All", "/security/identities/sensors", api="beta"),
    E("defender_identity_health", "Defender for Identity Health Issues", "DefenderHunting", "SecurityIdentitiesHealth.Read.All", "/security/identities/healthIssues", api="beta"),
    E("security_incidents", "Microsoft Security Incidents", "DefenderHunting", "SecurityIncident.Read.All", "/security/incidents?$filter=createdDateTime ge {start}"),
]


HUNTING_QUERY_PACK = {
    "version": "1.0",
    "published": "2026-08-04",
    "queries": [
        {"id": "privileged_signins", "title": "Suspicious privileged sign-ins", "query": "IdentityLogonEvents | where Timestamp >= ago(30d) | where AccountUpn != '' | where LogonType has_any ('Remote interactive','Network') | where ActionType != 'LogonSuccess'"},
        {"id": "identity_recon", "title": "Identity reconnaissance", "query": "IdentityQueryEvents | where Timestamp >= ago(30d) | where QueryType has_any ('SAMR query','LDAP query')"},
        {"id": "credential_theft", "title": "Credential theft process indicators", "query": "DeviceProcessEvents | where Timestamp >= ago(30d) | where ProcessCommandLine has_any ('lsass','sekurlsa','comsvcs.dll')"},
        {"id": "remote_logon", "title": "Remote logon anomalies", "query": "DeviceLogonEvents | where Timestamp >= ago(30d) | where LogonType in ('RemoteInteractive','Network') | where IsLocalAdmin == true"},
        {"id": "privileged_cloud_changes", "title": "Privileged cloud changes", "query": "CloudAppEvents | where Timestamp >= ago(30d) | where ActionType has_any ('Add member to role','Add eligible member to role','Consent to application')"},
    ],
}

for query in HUNTING_QUERY_PACK["queries"]:
    GRAPH_ENDPOINTS.append(E(
        f"hunting_{query['id']}", f"Defender Hunting: {query['title']}",
        "DefenderHunting", "ThreatHunting.Read.All", "/security/runHuntingQuery",
        api="v1.0", method="POST", pagination=False, mode="hunting",
        body={"Query": query["query"]}, records_field="results",
    ))


def validate_registry(endpoints: Iterable[Mapping] = GRAPH_ENDPOINTS) -> None:
    """Raise for unstable identities, unsafe methods or unlabelled API channels."""
    seen = set()
    for endpoint in endpoints:
        missing = {"id", "name", "profile", "permission", "permissions", "api", "method", "path", "pagination", "output", "licence"} - set(endpoint)
        if missing:
            raise ValueError(f"Graph endpoint missing fields: {sorted(missing)}")
        if endpoint["id"] in seen:
            raise ValueError(f"Duplicate Graph endpoint ID: {endpoint['id']}")
        seen.add(endpoint["id"])
        if endpoint["api"] not in {"v1.0", "beta"}:
            raise ValueError(f"Unsupported Graph API channel: {endpoint['api']}")
        if endpoint["method"] not in {"GET", "POST"}:
            raise ValueError("Graph collection endpoints must be read-only GET or query POST")
        if not endpoint["permissions"] or endpoint["permission"] != endpoint["permissions"][0]:
            raise ValueError("Graph endpoint permission compatibility field is invalid")
        if endpoint.get("response_format", "json") not in {"json", "csv"}:
            raise ValueError("Graph endpoint response format must be json or csv")
        if "getKey" in endpoint["path"] or "recoveryKey" in str(endpoint.get("body", {})):
            raise ValueError("BitLocker recovery key material must never be requested")


validate_registry()
