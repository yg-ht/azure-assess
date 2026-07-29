#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Versioned, conservative expectations used by offline finding correlations."""


PROFILE_SCHEMA_VERSION = "1.0"


# This is intentionally a small baseline rather than an assertion that every Azure
# built-in policy must be assigned. The stable initiative ID is Microsoft's
# published Microsoft cloud security benchmark built-in initiative identifier.
EXPECTED_POLICY_PROFILE = {
    "schema_version": PROFILE_SCHEMA_VERSION,
    "profile_version": "1.0",
    "requirements": [
        {
            "requirement_id": "microsoft_cloud_security_benchmark",
            "definition_ids": ["1f3afdf9-d0c9-4c3d-847f-89da613e70a8"],
            "applicable_scope_types": ["subscription"],
            "display_name": "Microsoft cloud security benchmark",
            "rationale": (
                "The Microsoft cloud security benchmark provides a Microsoft-authored "
                "security configuration baseline through Azure Policy."
            ),
        }
    ],
}


# Only resource types where accidental deletion has a clear security or recovery
# impact are included. Workload-specific criticality still requires analyst review.
CRITICAL_RESOURCE_PROFILE = {
    "schema_version": PROFILE_SCHEMA_VERSION,
    "profile_version": "1.0",
    "resource_types": {
        "microsoft.keyvault/vaults": (
            "Deletion can remove access to security-sensitive keys, certificates, and secrets."
        ),
        "microsoft.storage/storageaccounts": (
            "Deletion can remove security evidence, application data, or recovery material."
        ),
        "microsoft.sql/servers": (
            "Deletion can disrupt databases and their security control plane."
        ),
        "microsoft.documentdb/databaseaccounts": (
            "Deletion can remove application data and database security configuration."
        ),
        "microsoft.containerservice/managedclusters": (
            "Deletion can remove a Kubernetes workload control plane."
        ),
        "microsoft.network/applicationgateways": (
            "Deletion can remove an application ingress and filtering control."
        ),
    },
    "minimum_lock_level": "CanNotDelete",
}
