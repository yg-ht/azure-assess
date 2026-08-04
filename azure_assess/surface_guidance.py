#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Versioned Microsoft guidance for additional collection-surface findings."""


def _requirement(identifier, source_url, expected_state, eligibility, threshold,
                 finding_titles):
    return {
        "id": identifier,
        "source_url": source_url,
        "retrieved": "2026-08-04",
        "expected_state": expected_state,
        "eligibility": eligibility,
        "threshold": threshold,
        "finding_titles": list(finding_titles),
    }


SURFACE_GUIDANCE_BASELINE = {
    "schema_version": "1.0",
    "baseline_version": "2026-08-04",
    "publisher": "Microsoft",
    "requirements": [
        _requirement(
            "defender_cloud_alerts",
            "https://learn.microsoft.com/azure/defender-for-cloud/managing-and-responding-alerts",
            "Significant Defender for Cloud alerts are promptly investigated and resolved.",
            "Defender for Cloud alert inventory is available.",
            "No unresolved medium, high or critical alert remains.",
            ["Unresolved significant Defender for Cloud alerts"],
        ),
        _requirement(
            "security_sensitive_activity",
            "https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log",
            "Security-sensitive administrative changes are reviewed and authorised.",
            "The applicable activity-log inventory is available.",
            "Every observed privileged or control-weakening change is reviewed.",
            ["Security-sensitive Azure control-plane changes"],
        ),
        _requirement(
            "application_gateway_waf",
            "https://learn.microsoft.com/azure/networking/security/zero-trust-application-gateway-waf",
            "Application Gateway WAF operates in Prevention mode without unjustified exclusions.",
            "Application Gateway WAF is applicable and its configuration is collected.",
            "WAF is enabled in Prevention mode and managed-rule exclusions are reviewed.",
            [
                "Application Gateway WAF is disabled or not enforcing full prevention",
                "Unattached Application Gateway WAF policies are not enforcing full prevention",
            ],
        ),
        _requirement(
            "application_gateway_https",
            "https://learn.microsoft.com/azure/application-gateway/ssl-overview",
            "Application Gateway front-end traffic uses HTTPS.",
            "Application Gateway listener inventory is complete.",
            "No listener is explicitly configured for plaintext HTTP unless accepted.",
            ["Application Gateway exposes plaintext HTTP listeners"],
        ),
        _requirement(
            "app_configuration_security",
            "https://learn.microsoft.com/azure/azure-app-configuration/secure-azure-app-configuration",
            "App Configuration uses private access and Microsoft Entra authentication.",
            "App Configuration store inventory is complete.",
            "Public access and local access-key authentication are disabled.",
            [
                "Azure App Configuration permits public network access",
                "Azure App Configuration permits local access-key authentication",
            ],
        ),
        _requirement(
            "azure_monitor_network_access",
            "https://learn.microsoft.com/azure/azure-monitor/fundamentals/policy-reference",
            "Azure Monitor query and ingestion endpoints use restricted network access where applicable.",
            "The workspace or component network configuration is collected.",
            "Public query and ingestion are not explicitly enabled without acceptance.",
            [
                "Log Analytics workspaces permit public query or ingestion",
                "Application Insights permits public query or ingestion",
            ],
        ),
        _requirement(
            "trusted_launch",
            "https://learn.microsoft.com/azure/virtual-machines/trusted-launch-existing-vm",
            "Trusted Launch virtual machines enable Secure Boot and vTPM.",
            "The VM explicitly uses Trusted Launch or Confidential VM security type.",
            "Secure Boot and vTPM are not explicitly disabled.",
            ["Trusted Launch virtual machines disable Secure Boot or vTPM"],
        ),
        _requirement(
            "disk_network_access",
            "https://learn.microsoft.com/azure/virtual-machines/disks-enable-private-links-for-import-export-portal",
            "Managed disk and snapshot import/export is network restricted.",
            "Disk or snapshot network-access properties are collected.",
            "Network access policy is not AllowAll and public network access is not enabled.",
            ["Managed disks or snapshots permit unrestricted network export"],
        ),
        _requirement(
            "monitor_alert_actions",
            "https://learn.microsoft.com/azure/azure-monitor/alerts/action-groups",
            "Operational security alerts notify an effective action group.",
            "Alert rule action configuration is collected.",
            "No enabled alert rule has an explicitly empty action-group collection.",
            ["Azure Monitor alert rules have no effective action group"],
        ),
        _requirement(
            "api_management_security",
            "https://learn.microsoft.com/security/benchmark/azure/baselines/api-management-security-baseline",
            "API Management uses modern TLS and managed identities.",
            "API Management service configuration is collected.",
            "TLS 1.0/1.1 are disabled and a managed identity is configured.",
            [
                "API Management permits deprecated TLS protocols",
                "API Management services lack a managed identity",
            ],
        ),
        _requirement(
            "messaging_service_security",
            "https://learn.microsoft.com/security/benchmark/azure/baselines/service-bus-security-baseline",
            "Messaging services use Microsoft Entra authentication, restricted networking and TLS 1.2 or later.",
            "The applicable namespace or service configuration is collected.",
            "Local authentication and unrestricted public access are disabled and minimum TLS is at least 1.2.",
            [
                "Azure messaging services permit local authentication",
                "Azure messaging services permit unrestricted public network access",
                "Azure messaging services permit deprecated TLS versions",
            ],
        ),
        _requirement(
            "custom_role_least_privilege",
            "https://learn.microsoft.com/azure/role-based-access-control/best-practices",
            "Assigned custom roles follow least privilege.",
            "Custom role definitions and assignments are completely collected.",
            "No assigned custom role grants wildcard control-plane or data-plane permissions.",
            ["Assigned custom Azure roles contain wildcard permissions"],
        ),
    ],
}


GUIDANCE_BY_TITLE = {
    title: requirement
    for requirement in SURFACE_GUIDANCE_BASELINE["requirements"]
    for title in requirement["finding_titles"]
}
