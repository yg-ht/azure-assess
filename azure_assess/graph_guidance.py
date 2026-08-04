#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Versioned Microsoft public-guidance expectations for Graph assessment checks."""


GRAPH_GUIDANCE_BASELINE = {
    "schema_version": "1.0",
    "baseline_version": "2026-08-04",
    "publisher": "Microsoft",
    "requirements": [
        {
            "id": "authentication_methods",
            "source_url": "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strength-how-it-works",
            "retrieved": "2026-08-04",
            "expected_state": "Privileged users use phishing-resistant authentication methods.",
            "eligibility": "A complete privileged-role and authentication-method inventory is available.",
            "threshold": "Every active privileged principal has at least one phishing-resistant method.",
        },
        {
            "id": "pim_eligible_assignments",
            "source_url": "https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure",
            "retrieved": "2026-08-04",
            "expected_state": "Privileged access uses eligible, time-bound activation where supported.",
            "eligibility": "PIM is licensed and all active and eligible schedules were collected.",
            "threshold": "No unjustified permanent privileged assignment is observed.",
        },
        {
            "id": "intune_compliance",
            "source_url": "https://learn.microsoft.com/en-us/intune/device-security/compliance/overview",
            "retrieved": "2026-08-04",
            "expected_state": "Applicable managed devices are governed by compliance policies.",
            "eligibility": "Intune is licensed and device and compliance inventories are complete.",
            "threshold": "At least one applicable compliance policy exists and devices are not stale or non-compliant.",
        },
        {
            "id": "sharepoint_sharing",
            "source_url": "https://learn.microsoft.com/sharepoint/turn-external-sharing-on-or-off",
            "retrieved": "2026-08-04",
            "expected_state": "External sharing is restricted to the organisation's documented need.",
            "eligibility": "SharePoint tenant settings are licensed and completely collected.",
            "threshold": "Anonymous sharing is not enabled unless explicitly accepted by the assessor.",
        },
        {
            "id": "global_secure_access",
            "source_url": "https://learn.microsoft.com/entra/global-secure-access/overview-what-is-global-secure-access",
            "retrieved": "2026-08-04",
            "expected_state": "Applicable traffic forwarding and filtering controls are configured.",
            "eligibility": "Global Secure Access is licensed, enabled and its beta inventories are complete.",
            "threshold": "Enabled workloads have a forwarding profile and applicable filtering policy.",
        },
        {
            "id": "defender_identity_health",
            "source_url": "https://learn.microsoft.com/defender-for-identity/health-alerts",
            "retrieved": "2026-08-04",
            "expected_state": "Defender for Identity sensors have no unresolved health issues.",
            "eligibility": "Defender for Identity is licensed and sensor and health inventories are complete.",
            "threshold": "No active sensor health issue is reported.",
        },
    ],
}
