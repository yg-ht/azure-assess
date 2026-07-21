#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Offline correlation of Azure non-human identities, roles, and credentials."""

from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from azure_findings_correlation import (
    CorrelationResult,
    canonical_object_id,
    canonical_role_definition_id,
    normalise_identifier,
    parse_timestamp,
)
from azure_findings_governance import nested_value
from azure_findings_shared import flatten_permission_actions


PRIVILEGED_ROLE_NAMES = {
    "owner",
    "contributor",
    "user access administrator",
    "role based access control administrator",
}
BROAD_SCOPE_LEVELS = {"tenant", "management_group", "subscription"}


def privileged_action(action: str) -> bool:
    """Identify broad control/data-plane mutation grants, excluding read-only wildcards."""
    if action == "*" or action.endswith("/*"):
        return True
    return action.endswith(("/write", "/delete", "/action"))


def scope_level(value: Any) -> str:
    scope = normalise_identifier(value).rstrip("/")
    if scope in {"", "/"}:
        return "tenant"
    if "/providers/microsoft.management/managementgroups/" in scope:
        return "management_group"
    if scope.startswith("/subscriptions/"):
        parts = [part for part in scope.split("/") if part]
        if len(parts) == 2:
            return "subscription"
        if len(parts) == 4 and parts[2] == "resourcegroups":
            return "resource_group"
        return "resource"
    return "unknown"


def role_definition_index(
    role_definitions: Iterable[Mapping[str, Any]],
) -> Dict[str, Mapping[str, Any]]:
    index = {}
    for definition in role_definitions:
        identifier = canonical_role_definition_id(definition.get("id") or definition.get("name"))
        if identifier:
            index[identifier] = definition
    return index


def role_privilege(assignment: Mapping[str, Any], definition: Mapping[str, Any]) -> Dict[str, Any]:
    role_name = assignment.get("roleDefinitionName") or definition.get("roleName") or definition.get("name")
    normalised_name = normalise_identifier(role_name)
    actions = {
        normalise_identifier(item)
        for item in (
            flatten_permission_actions(definition)
            + flatten_permission_actions(assignment)
        )
    }
    privileged_actions = sorted(
        action
        for action in actions
        if privileged_action(action)
    )
    return {
        "roleName": role_name,
        "privileged": normalised_name in PRIVILEGED_ROLE_NAMES or bool(privileged_actions),
        "privilegedActions": privileged_actions,
    }


def identity_records(
    applications: Iterable[Mapping[str, Any]],
    service_principals: Iterable[Mapping[str, Any]],
    managed_identities: Iterable[Mapping[str, Any]],
    groups: Iterable[Mapping[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """Join identity inventories by object ID while retaining application metadata."""
    applications_by_app_id = {
        normalise_identifier(item.get("appId")): item
        for item in applications
        if normalise_identifier(item.get("appId"))
    }
    records: Dict[str, Dict[str, Any]] = {}
    for principal in service_principals:
        principal_id = canonical_object_id(principal.get("id") or principal.get("objectId"))
        if not principal_id:
            continue
        principal_type = normalise_identifier(principal.get("servicePrincipalType"))
        kind = "managed_identity" if principal_type == "managedidentity" else "service_principal"
        records[principal_id] = {
            "principalId": principal.get("id") or principal.get("objectId"),
            "appId": principal.get("appId"),
            "displayName": principal.get("displayName"),
            "identityKind": kind,
            "servicePrincipal": principal,
            "application": applications_by_app_id.get(normalise_identifier(principal.get("appId"))),
        }
    for identity in managed_identities:
        principal_id = canonical_object_id(
            nested_value(identity, "principalId", ("properties", "principalId"))
        )
        if not principal_id:
            continue
        record = records.setdefault(principal_id, {})
        record.update(
            {
                "principalId": nested_value(identity, "principalId", ("properties", "principalId")),
                "appId": nested_value(identity, "clientId", ("properties", "clientId")),
                "displayName": identity.get("name") or record.get("displayName"),
                "identityKind": "managed_identity",
                "managedIdentity": identity,
            }
        )
    for group in groups:
        principal_id = canonical_object_id(group.get("id") or group.get("objectId"))
        if principal_id:
            records[principal_id] = {
                "principalId": group.get("id") or group.get("objectId"),
                "displayName": group.get("displayName"),
                "identityKind": "group",
                "group": group,
            }
    return records


def analyse_privileged_non_human_identities(
    applications: Iterable[Mapping[str, Any]],
    service_principals: Iterable[Mapping[str, Any]],
    managed_identities: Iterable[Mapping[str, Any]],
    groups: Iterable[Mapping[str, Any]],
    role_assignments: Iterable[Mapping[str, Any]],
    role_definitions: Iterable[Mapping[str, Any]],
    conclusion_support: str,
    source_files: Iterable[str] = (),
    group_conclusion_support: Optional[str] = None,
) -> Tuple[CorrelationResult, CorrelationResult]:
    """Return separate non-human and group privileged broad-scope assignments."""
    identities = identity_records(applications, service_principals, managed_identities, groups)
    definitions = role_definition_index(role_definitions)
    non_human = {}
    group_observations = {}
    non_human_eligible = []
    group_eligible = []
    for assignment in role_assignments:
        principal_id = canonical_object_id(assignment.get("principalId"))
        identity = identities.get(principal_id)
        if not identity:
            continue
        level = scope_level(assignment.get("scope"))
        if level not in BROAD_SCOPE_LEVELS:
            continue
        eligible_asset = {
            "id": identity.get("principalId"),
            "kind": identity.get("identityKind"),
        }
        if identity.get("identityKind") == "group":
            group_eligible.append(eligible_asset)
        else:
            non_human_eligible.append(eligible_asset)
        definition_id = canonical_role_definition_id(assignment.get("roleDefinitionId"))
        privilege = role_privilege(assignment, definitions.get(definition_id, {}))
        if not privilege["privileged"]:
            continue
        observation = {
            "id": identity.get("principalId"),
            "roleAssignmentId": assignment.get("id"),
            "principalId": identity.get("principalId"),
            "appId": identity.get("appId"),
            "displayName": identity.get("displayName"),
            "identityKind": identity.get("identityKind"),
            "roleName": privilege["roleName"],
            "roleDefinitionId": assignment.get("roleDefinitionId"),
            "privilegedActions": privilege["privilegedActions"],
            "scope": assignment.get("scope"),
            "scopeLevel": level,
        }
        assignment_key = (
            normalise_identifier(assignment.get("id")),
            principal_id,
            definition_id,
            normalise_identifier(assignment.get("scope")),
        )
        if identity.get("identityKind") == "group":
            group_observations[assignment_key] = observation
        else:
            non_human[assignment_key] = observation
    common = {"source_files": sorted(set(source_files))}
    return (
        CorrelationResult(
            observations=[non_human[key] for key in sorted(non_human)],
            eligible_assets=list(
                {item["id"]: item for item in non_human_eligible}.values()
            ),
            conclusion_support=conclusion_support,
            **common,
        ),
        CorrelationResult(
            observations=[group_observations[key] for key in sorted(group_observations)],
            eligible_assets=list(
                {item["id"]: item for item in group_eligible}.values()
            ),
            limitations=(
                ["Group membership was not collected, so inherited members cannot be identified"]
                if group_observations
                else []
            ),
            conclusion_support=group_conclusion_support or conclusion_support,
            **common,
        ),
    )


def credential_records(
    identity: Mapping[str, Any],
) -> Iterable[Tuple[str, int, Mapping[str, Any]]]:
    for credential_type, key in (
        ("password", "passwordCredentials"),
        ("certificate", "keyCredentials"),
    ):
        credentials = identity.get(key) or []
        if isinstance(credentials, list):
            for credential_index, credential in enumerate(credentials):
                if isinstance(credential, Mapping):
                    yield credential_type, credential_index, credential


def expiry_bucket(end: Any, reference_time: datetime) -> str:
    parsed = parse_timestamp(end)
    if parsed is None:
        return "no_expiry" if not end else "invalid_timestamp"
    remaining = parsed - reference_time
    if remaining.total_seconds() < 0:
        return "expired"
    if remaining <= timedelta(days=30):
        return "expires_within_30_days"
    if remaining <= timedelta(days=90):
        return "expires_within_90_days"
    return "more_than_90_days"


def analyse_application_credentials(
    applications: Iterable[Mapping[str, Any]],
    service_principals: Iterable[Mapping[str, Any]],
    reference_time: datetime,
    reference_source: str,
    conclusion_support: str,
    source_files: Iterable[str] = (),
) -> CorrelationResult:
    """Find expired, near-expiry, and non-expiring application credentials."""
    observations = []
    eligible = []
    seen = set()
    for identity_kind, identities in (
        ("application", applications),
        ("service_principal", service_principals),
    ):
        for identity in identities:
            identity_id = identity.get("id") or identity.get("objectId") or identity.get("appId")
            if not identity_id:
                continue
            eligible.append({"id": identity_id, "kind": identity_kind})
            for credential_type, credential_index, credential in credential_records(identity):
                end = credential.get("endDateTime") or credential.get("endDate")
                bucket = expiry_bucket(end, reference_time)
                if bucket == "more_than_90_days":
                    continue
                parsed_end = parse_timestamp(end)
                days_until_expiry = (
                    round((parsed_end - reference_time).total_seconds() / 86400, 1)
                    if parsed_end is not None
                    else None
                )
                # Only emit non-secret metadata.  customKeyIdentifier may
                # contain arbitrary caller-supplied bytes, so it is excluded.
                credential_id = credential.get("keyId") or (
                    f"{credential_type}:{credential_index}"
                )
                dedup = (normalise_identifier(identity_id), normalise_identifier(credential_id), bucket)
                if dedup in seen:
                    continue
                seen.add(dedup)
                observations.append(
                    {
                        "id": identity_id,
                        "appId": identity.get("appId"),
                        "displayName": identity.get("displayName"),
                        "identityKind": identity_kind,
                        "credentialType": credential_type,
                        "credentialId": credential_id,
                        "credentialDisplayName": credential.get("displayName"),
                        "startDateTime": credential.get("startDateTime") or credential.get("startDate"),
                        "endDateTime": end,
                        "expiryStatus": bucket,
                        "daysUntilExpiry": days_until_expiry,
                        "referenceTime": reference_time.isoformat(),
                        "referenceTimeSource": reference_source,
                    }
                )
    return CorrelationResult(
        observations=observations,
        eligible_assets=list({item["id"]: item for item in eligible}.values()),
        source_files=sorted(set(source_files)),
        conclusion_support=conclusion_support,
    )
