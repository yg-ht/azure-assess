#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Versioned Microsoft public-guidance expectations for Graph assessment checks."""


def _requirement(identifier, source_url, expected_state, eligibility, threshold,
                 finding_titles, **parameters):
    return {
        "id": identifier,
        "source_url": source_url,
        "retrieved": "2026-08-04",
        "expected_state": expected_state,
        "eligibility": eligibility,
        "threshold": threshold,
        "finding_titles": list(finding_titles),
        "parameters": parameters,
    }


GRAPH_GUIDANCE_BASELINE = {
    "schema_version": "1.0",
    "baseline_version": "2026-08-04",
    "publisher": "Microsoft",
    "requirements": [
        _requirement(
            "identity_risk",
            "https://learn.microsoft.com/entra/id-protection/howto-identity-protection-remediate-unblock",
            "Active identity risks are investigated and remediated.",
            "Identity Protection is licensed and the risk inventory is complete.",
            "No at-risk or confirmed-compromised detection remains active.",
            ["Active Microsoft Entra risk detections"],
            active_states=["atrisk", "confirmedcompromised"],
        ),
        _requirement(
            "directory_recommendations",
            "https://learn.microsoft.com/entra/identity/monitoring-health/overview-recommendations",
            "Applicable Microsoft Entra recommendations are resolved or dismissed after review.",
            "The recommendations inventory is licensed and complete.",
            "No active recommendation remains unresolved.",
            ["Unresolved Microsoft Entra recommendations"],
            resolved_states=["completed", "completedbyuser", "dismissed", "resolved"],
        ),
        _requirement(
            "synchronisation_and_provisioning",
            "https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-health-operations",
            "Directory synchronisation and provisioning complete without unresolved failures.",
            "The applicable synchronisation or provisioning inventory is complete.",
            "No failed or unhealthy state is reported.",
            [
                "Unhealthy on-premises directory synchronisation",
                "Unhealthy Microsoft Entra provisioning activity",
            ],
            unhealthy_states=["error", "failed", "failure", "unhealthy"],
        ),
        _requirement(
            "authentication_methods",
            "https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strength-how-it-works",
            "Privileged users use phishing-resistant authentication methods.",
            "Complete privileged-role, user and authentication-method inventories are available.",
            "Every active privileged user has FIDO2/passkey, Windows Hello, platform credential or certificate authentication.",
            ["Weak or missing privileged authentication methods"],
            strong_method_types=[
                "#microsoft.graph.fido2authenticationmethod",
                "#microsoft.graph.platformcredentialauthenticationmethod",
                "#microsoft.graph.windowshelloforbusinessauthenticationmethod",
                "#microsoft.graph.x509certificateauthenticationmethod",
            ],
        ),
        _requirement(
            "entitlement_management",
            "https://learn.microsoft.com/entra/id-governance/entitlement-management-access-package-lifecycle-policy",
            "Access-package assignments expire or are reviewed according to policy.",
            "Entitlement assignment and policy inventories are complete.",
            "No policy or active assignment explicitly uses no expiration without review.",
            ["Unsafe entitlement-management assignments or policies"],
        ),
        _requirement(
            "pim_eligible_assignments",
            "https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure",
            "Privileged access uses eligible, time-bound activation where supported.",
            "The applicable active PIM schedule inventory is licensed and complete.",
            "No active schedule explicitly has no expiration.",
            [
                "Permanent privileged directory assignments",
                "Permanent privileged group assignments",
                "Permanent privileged Azure-resource assignments",
                "Active privileged identity management alerts",
            ],
        ),
        _requirement(
            "sharepoint_sharing",
            "https://learn.microsoft.com/sharepoint/turn-external-sharing-on-or-off",
            "Anonymous SharePoint and OneDrive sharing is disabled unless explicitly accepted.",
            "SharePoint tenant settings are licensed and completely collected.",
            "Anonymous/Anyone sharing and anonymous default links are not enabled.",
            ["Unsafe Microsoft 365 sharing or tenant settings"],
        ),
        _requirement(
            "intune_compliance",
            "https://learn.microsoft.com/intune/intune-service/protect/device-compliance-get-started",
            "Applicable managed devices are current and governed by compliance and enrolment controls.",
            "Intune is licensed and the relevant inventories are complete.",
            "No non-compliant device is observed, device sync is no older than 30 days, and applicable policy inventories are non-empty.",
            [
                "Non-compliant or stale Intune managed devices",
                "Intune estate lacks compliance or enrolment controls",
                "Applicable Intune estate has no compliance policy",
                "Applicable Intune estate has no enrolment restriction",
            ],
            stale_after_days=30,
        ),
        _requirement(
            "intune_rbac",
            "https://learn.microsoft.com/intune/intune-service/fundamentals/role-based-access-control",
            "Assigned custom Intune roles grant only required resource actions.",
            "Role-definition and role-assignment inventories are complete.",
            "No assigned custom role contains a wildcard allowed resource action.",
            ["Excessive Intune RBAC assignments"],
        ),
        _requirement(
            "bitlocker_recovery",
            "https://learn.microsoft.com/intune/intune-service/protect/encrypt-devices",
            "Encrypted managed Windows devices have recoverable BitLocker-key metadata in Entra ID.",
            "Managed-device and BitLocker metadata inventories are complete.",
            "Every encrypted device identifier is represented by at least one recovery-key metadata record.",
            ["Managed encrypted devices lack BitLocker recovery-key metadata coverage"],
        ),
        _requirement(
            "global_secure_access",
            "https://learn.microsoft.com/entra/global-secure-access/overview-what-is-global-secure-access",
            "Applicable traffic forwarding, filtering, TLS inspection and policy assignment controls are configured.",
            "Global Secure Access is licensed, enabled and its beta inventories are complete.",
            "An enabled tenant has the applicable non-empty control inventories and no explicitly disabled control.",
            [
                "Global Secure Access forwarding or filtering controls are absent",
                "Applicable Global Secure Access tenant has no forwarding policy",
                "Applicable Global Secure Access tenant has no filtering policy",
                "Applicable Global Secure Access tenant has no TLS inspection policy",
                "Applicable Global Secure Access tenant has no policy assignment",
            ],
        ),
        _requirement(
            "defender_identity_health",
            "https://learn.microsoft.com/defender-for-identity/health-alerts",
            "Defender for Identity sensors have no unresolved health issues.",
            "Defender for Identity is licensed and sensor and health inventories are complete.",
            "Sensors are healthy/online and no active health issue is returned.",
            ["Unhealthy Defender for Identity sensors"],
        ),
        _requirement(
            "security_incidents",
            "https://learn.microsoft.com/defender-xdr/incidents-overview",
            "Significant Microsoft security incidents are resolved or redirected for handling.",
            "The 30-day incident inventory is licensed and complete.",
            "No unresolved medium, high or critical incident remains.",
            ["Unresolved significant Microsoft security incidents"],
        ),
        _requirement(
            "legacy_authentication_activity",
            "https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication",
            "Legacy authentication is blocked.",
            "The 30-day sign-in inventory is complete.",
            "No successful sign-in uses a legacy authentication client.",
            ["Successful Microsoft Entra legacy-authentication sign-ins"],
        ),
        _requirement(
            "directory_security_changes",
            "https://learn.microsoft.com/entra/identity/monitoring-health/concept-audit-logs",
            "Security-sensitive directory changes are reviewed and authorised.",
            "The 30-day directory audit inventory is available.",
            "Every observed privileged, credential or Conditional Access change is reviewed.",
            ["Security-sensitive Microsoft Entra directory changes"],
        ),
        _requirement(
            "m365_security_activity",
            "https://learn.microsoft.com/purview/audit-log-activities",
            "Mailbox delegation, forwarding and external sharing changes are reviewed.",
            "The applicable unified-audit workload inventory is available.",
            "Every observed security-sensitive mailbox or sharing event is reviewed.",
            [
                "Security-sensitive Exchange mailbox forwarding or delegation changes",
                "Anonymous or external SharePoint sharing activity",
            ],
        ),
        _requirement(
            "intune_endpoint_security_policy",
            "https://learn.microsoft.com/intune/intune-service/protect/endpoint-security-policy",
            "Intune endpoint security policies enable applicable core protections.",
            "Device configuration or settings-catalog policy inventory is available.",
            "Firewall, antivirus, real-time protection and encryption are not explicitly disabled.",
            ["Intune policy explicitly disables a core endpoint security control"],
        ),
        _requirement(
            "intune_security_connectors",
            "https://learn.microsoft.com/intune/intune-service/protect/mobile-threat-defense",
            "Configured Intune security-service connectors are enabled and healthy.",
            "The security connector inventory is available.",
            "No configured connector reports disabled, failed or unhealthy state.",
            ["Intune security-service connectors are disabled or unhealthy"],
        ),
        _requirement(
            "global_secure_access_connectivity",
            "https://learn.microsoft.com/entra/global-secure-access/how-to-configure-connectors",
            "Global Secure Access connectivity components are healthy and enabled profiles are associated.",
            "Global Secure Access is licensed and the applicable beta inventory is available.",
            "No branch or connector is unhealthy and no enabled profile has an explicitly empty association list.",
            [
                "Global Secure Access branches or connectors are unhealthy",
                "Enabled Global Secure Access forwarding profiles have no associations",
            ],
        ),
        _requirement(
            "pim_permanent_requests",
            "https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-deployment-plan",
            "Privileged access requests are time-bound where supported.",
            "The applicable PIM request inventory is available.",
            "No non-rejected request explicitly seeks no-expiration privileged access.",
            ["Privileged activation or assignment requests seek permanent access"],
        ),
    ],
}


GUIDANCE_BY_ID = {
    item["id"]: item for item in GRAPH_GUIDANCE_BASELINE["requirements"]
}
GUIDANCE_BY_TITLE = {
    title: item
    for item in GRAPH_GUIDANCE_BASELINE["requirements"]
    for title in item["finding_titles"]
}
