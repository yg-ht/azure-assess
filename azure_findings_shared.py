# SPDX-License-Identifier: AGPL-3.0-or-later
from datetime import datetime, timezone
import json
import re

VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?")

GLOBAL_ADMIN_ROLE_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"

ADMIN_PORTAL_APPLICATION_IDS = {"microsoftadminportals"}

MANAGEMENT_API_APPLICATION_IDS = {
    "797f4846-ba00-4fd7-ba43-dac1f8f63013",
    "https://management.azure.com/",
}

RISKY_ADMIN_ROLE_NAMES = {
    "owner",
    "contributor",
    "user access administrator",
}

VM_ACCESS_ROLE_NAMES = {
    "owner",
    "contributor",
    "user access administrator",
    "virtual machine contributor",
    "virtual machine administrator login",
    "virtual machine user login",
    "virtual machine local administrator login",
}

APPROVED_VM_IMAGE_PUBLISHERS = {
    "canonical",
    "credativ",
    "debian",
    "microsoft-azure-edgenetwork",
    "microsoft-cbl-mariner",
    "microsoftwindowsdesktop",
    "microsoftwindowsserver",
    "openlogic",
    "oracle",
    "redhat",
    "suse",
}


def get_path(obj, *keys, default=None):
    current = obj
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
    return current

def first_value(obj, *paths):
    for path in paths:
        if not isinstance(path, tuple):
            path = (path,)
        value = get_path(obj, *path, default=None)
        if value is not None:
            return value
    return None

def truthy(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "enabled", "yes"}
    return bool(value)

def normalize_location(value):
    if not value:
        return None
    return str(value).strip().lower().replace(" ", "")

def normalize_text(value):
    if value is None:
        return ""
    return str(value).strip().lower()

def parse_iso_datetime(value):
    if not value:
        return None
    if isinstance(value, (int, float)):
        timestamp = float(value)
        if timestamp > 10_000_000_000:
            timestamp = timestamp / 1000.0
        try:
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None

def extract_version_tuple(value):
    if not value:
        return None
    match = VERSION_RE.search(str(value))
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2) or 0)
    return major, minor

def version_is_older(value, minimum):
    version = extract_version_tuple(value)
    if not version:
        return True
    return version < minimum

def contains_any_keyword(value, keywords):
    text = normalize_text(value)
    return any(keyword in text for keyword in keywords)

def identity_principal_id(record):
    return normalize_text(
        first_value(
            record,
            "principalId",
            ("principalId",),
            ("properties", "principalId"),
            ("identity", "principalId"),
            ("properties", "identity", "principalId"),
        )
    )

def app_setting_value(records, wanted_name):
    for item in records:
        if normalize_text(item.get("name")) == normalize_text(wanted_name):
            return item.get("value")
    return None

def role_assignment_name(assignment):
    return normalize_text(assignment.get("roleDefinitionName") or assignment.get("roleName"))

def registration_detail_maps(registration_details):
    by_id = {}
    by_upn = {}
    for item in registration_details:
        user_id = normalize_text(item.get("id") or item.get("userId"))
        if user_id:
            by_id[user_id] = item
        upn = normalize_text(item.get("userPrincipalName"))
        if upn:
            by_upn[upn] = item
    return by_id, by_upn

def registration_has_mfa(registration):
    if not registration:
        return False
    if first_value(registration, "isMfaRegistered", ("isMfaRegistered",)) is True:
        return True
    if first_value(registration, "isMfaCapable", ("isMfaCapable",)) is True:
        return True
    methods = first_value(registration, "methodsRegistered", ("methodsRegistered",)) or []
    return isinstance(methods, list) and bool(methods)

def build_user_registration_lookup(ad_users, registration_details):
    by_id, by_upn = registration_detail_maps(registration_details)
    lookup = {}
    for user in ad_users:
        user_id = normalize_text(user.get("id"))
        upn = normalize_text(user.get("userPrincipalName"))
        lookup[user_id] = by_id.get(user_id) or by_upn.get(upn)
    return lookup

def assessment_title(assessment):
    return normalize_text(
        first_value(
            assessment,
            "displayName",
            ("properties", "displayName"),
            ("metadata", "displayName"),
            ("properties", "metadata", "displayName"),
            ("name",),
        )
    )

def assessment_status(assessment):
    return normalize_text(first_value(assessment, ("status", "code"), ("properties", "status", "code")))

def assessment_resource_id(assessment):
    value = first_value(
        assessment,
        ("resourceDetails", "id"),
        ("properties", "resourceDetails", "id"),
        "resourceDetails",
        ("properties", "resourceDetails"),
    )
    if isinstance(value, dict):
        return value.get("id")
    return value

def assessment_matches(assessment, all_keywords=(), any_keywords=()):
    title = assessment_title(assessment)
    if all_keywords and not all(keyword in title for keyword in all_keywords):
        return False
    if any_keywords and not any(keyword in title for keyword in any_keywords):
        return False
    return True

def setting_is_enabled(record):
    enabled = normalize_text(first_value(record, "enabled", ("properties", "enabled"), "value", ("properties", "value")))
    return enabled in {"true", "on", "enabled", "standard"}

def conditional_access_requires_mfa(policy):
    controls = {normalize_text(item) for item in first_value(policy, ("grantControls", "builtInControls")) or []}
    if "mfa" in controls:
        return True
    authentication_strength = first_value(
        policy,
        ("grantControls", "authenticationStrength"),
        ("grantControls", "authenticationStrength", "id"),
    )
    return bool(authentication_strength)

def conditional_access_targets_application(policy, target_ids):
    include_apps = {normalize_text(item) for item in first_value(policy, ("conditions", "applications", "includeApplications")) or []}
    exclude_apps = {normalize_text(item) for item in first_value(policy, ("conditions", "applications", "excludeApplications")) or []}
    targets = {normalize_text(item) for item in target_ids}
    if include_apps.intersection(targets):
        return True
    if "all" in include_apps and not exclude_apps.issuperset(targets):
        return True
    return False

def conditional_access_targets_admins(policy):
    include_roles = {normalize_text(item) for item in first_value(policy, ("conditions", "users", "includeRoles")) or []}
    include_users = {normalize_text(item) for item in first_value(policy, ("conditions", "users", "includeUsers")) or []}
    return GLOBAL_ADMIN_ROLE_TEMPLATE_ID in include_roles or "all" in include_users

def first_matching_group_setting(group_settings, display_name):
    wanted = normalize_text(display_name)
    for setting in group_settings:
        if normalize_text(setting.get("displayName")) == wanted:
            return setting
        template = normalize_text(first_value(setting, ("templateId",), ("properties", "templateId")))
        if wanted in template:
            return setting
    return None

def group_setting_value(setting, wanted_name):
    for item in first_value(setting, "values", ("values",), ("properties", "values")) or []:
        if normalize_text(item.get("name")) == normalize_text(wanted_name):
            return item.get("value")
    return None

def app_stack_value(config, stack_name):
    candidates = [
        first_value(config, "linuxFxVersion", ("properties", "linuxFxVersion")),
        first_value(config, "windowsFxVersion", ("properties", "windowsFxVersion")),
        first_value(config, "javaVersion", ("properties", "javaVersion")),
        first_value(config, "phpVersion", ("properties", "phpVersion")),
        first_value(config, "pythonVersion", ("properties", "pythonVersion")),
        first_value(config, "netFrameworkVersion", ("properties", "netFrameworkVersion")),
    ]
    wanted = normalize_text(stack_name)
    for candidate in candidates:
        text = str(candidate or "")
        lowered = text.lower()
        if not lowered:
            continue
        if wanted == "dotnet" and ("dotnet" in lowered or lowered.startswith("v")):
            return candidate
        if wanted in lowered:
            return candidate
    return {
        "java": first_value(config, "javaVersion", ("properties", "javaVersion")),
        "php": first_value(config, "phpVersion", ("properties", "phpVersion")),
        "python": first_value(config, "pythonVersion", ("properties", "pythonVersion")),
        "dotnet": first_value(config, "netFrameworkVersion", ("properties", "netFrameworkVersion")),
    }.get(wanted)

def alert_policy_has_email_notifications(policy):
    admins_enabled = first_value(policy, "emailAccountAdmins", ("properties", "emailAccountAdmins"))
    recipients = first_value(policy, "emailAddresses", ("properties", "emailAddresses"))
    if admins_enabled is True:
        return True
    if isinstance(recipients, list) and recipients:
        return True
    if isinstance(recipients, str) and recipients.strip():
        return True
    return False

def alert_policy_disabled_alerts(policy):
    disabled = first_value(policy, "disabledAlerts", ("properties", "disabledAlerts"))
    if not disabled:
        return []
    if isinstance(disabled, list):
        return disabled
    if isinstance(disabled, str):
        return [item.strip() for item in disabled.split(",") if item.strip()]
    return [disabled]

def resource_brief(resource):
    return {
        "id": resource.get("id"),
        "name": resource.get("name"),
        "resourceGroup": resource.get("resourceGroup"),
        "location": resource.get("location"),
        "type": resource.get("type"),
    }

def collection_parameters(record):
    return get_path(record, "_collectionContext", "parameters", default={}) or {}

def flatten_permission_actions(role_definition):
    actions = []
    for permission in role_definition.get("permissions", []):
        if not isinstance(permission, dict):
            continue
        actions.extend(permission.get("actions", []) or [])
        actions.extend(permission.get("dataActions", []) or [])
    return [str(action) for action in actions]

def compact_dict(resource, **extra):
    item = resource_brief(resource)
    item.update(extra)
    return item

def resource_key(name=None, resource_group=None, identifier=None):
    if identifier:
        return normalize_text(identifier)
    return f"{normalize_text(resource_group)}::{normalize_text(name)}"

def record_key(record):
    return resource_key(
        name=record.get("name"),
        resource_group=record.get("resourceGroup"),
        identifier=record.get("id"),
    )

def collection_key(record):
    params = collection_parameters(record)
    return resource_key(
        name=params.get("name"),
        resource_group=params.get("resourceGroup"),
        identifier=params.get("id"),
    )

def parameterised_record_keys(records):
    keys = set()
    for record in records:
        key = collection_key(record)
        if key and key != "::":
            keys.add(key)
    return keys

def map_by_name(records):
    mapped = {}
    for record in records:
        for key in ("id", "name"):
            value = record.get(key)
            if value:
                mapped[str(value).lower()] = record
    return mapped

def alert_text(record):
    return " ".join(
        normalize_text(value)
        for value in (
            record.get("name"),
            record.get("description"),
            json.dumps(record.get("condition", {}), sort_keys=True),
            json.dumps(record.get("actions", []), sort_keys=True),
            json.dumps(record, sort_keys=True),
        )
    )

def build_parameter_map(parameter_records):
    result_map = {}
    for record in parameter_records:
        key = collection_key(record)
        if not key or key == "::":
            continue
        result_map.setdefault(key, {})[normalize_text(record.get("name"))] = record
    return result_map

def parameter_value(parameter_map, resource, *parameter_names):
    entries = parameter_map.get(record_key(resource), {})
    for name in parameter_names:
        record = entries.get(normalize_text(name))
        if record is not None:
            return record.get("value")
    return None

def unsupported(title, severity, reason):
    normalized_reason = normalize_text(reason)
    no_data_markers = (
        "dataset was found",
        "dataset is required",
        "datasets are required",
        "inventory is required",
        "is required",
        "are required",
    )
    return {
        "title": title,
        "severity": severity,
        "status": (
            "no_data_to_assess"
            if normalized_reason.startswith("no ") or any(marker in normalized_reason for marker in no_data_markers)
            else "not_implemented"
        ),
        "reason": reason,
        "evidence_count": 0,
        "evidence": [],
    }

def result(title, severity, reason, evidence):
    return {
        "title": title,
        "severity": severity,
        "status": "found" if evidence else "not_found",
        "reason": reason,
        "evidence_count": len(evidence),
        "evidence": evidence,
    }

def is_any_source(rule):
    values = []
    for field in ("sourceAddressPrefix", "sourceAddressPrefixes"):
        value = rule.get(field)
        if isinstance(value, list):
            values.extend(value)
        elif value is not None:
            values.append(value)
    lowered = {normalize_text(value) for value in values}
    return bool(lowered.intersection({"*", "0.0.0.0/0", "internet"}))

def rule_port_values(rule):
    values = []
    for field in ("destinationPortRange", "destinationPortRanges"):
        value = rule.get(field)
        if isinstance(value, list):
            values.extend(value)
        elif value is not None:
            values.append(value)
    return [str(value) for value in values]

def ports_match(port_values, exact_ports):
    for port_value in port_values:
        if port_value == "*":
            return True
        if port_value in exact_ports:
            return True
    return False
