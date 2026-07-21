# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build compact Azure and engagement context for report-facing findings."""

from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from azure_findings_reporting import collection_manifest


CONTEXT_SCHEMA_VERSION = "1.0"
SCOPE_LEVELS = {"tenant", "subscription", "resource", "mixed", "unknown"}
MAX_CONTEXT_VALUE_LENGTH = 4096
MAX_ATTRIBUTE_VALUES = 100
MAX_OBSERVATION_NODES = 50_000
MAX_OBSERVATION_DEPTH = 20


FAMILY_DEFINITIONS = {
    "Identity and access management": {
        "id": "identity_access",
        "label": "Identity and access management",
        "control_plane": "microsoft_graph",
        "default_scope": "tenant",
    },
    "Network security": {
        "id": "network_security",
        "label": "Network security",
        "control_plane": "azure_resource_manager",
        "default_scope": "resource",
    },
    "Storage security": {
        "id": "storage_security",
        "label": "Storage security",
        "control_plane": "azure_resource_manager",
        "default_scope": "resource",
    },
    "Secrets and key management": {
        "id": "secrets_key_management",
        "label": "Secrets and key management",
        "control_plane": "azure_resource_manager",
        "default_scope": "resource",
    },
    "Logging and monitoring": {
        "id": "logging_monitoring",
        "label": "Logging and monitoring",
        "control_plane": "azure_resource_manager",
        "default_scope": "subscription",
    },
    "Security posture management": {
        "id": "security_posture",
        "label": "Security posture management",
        "control_plane": "azure_resource_manager",
        "default_scope": "subscription",
    },
    "Containers and Kubernetes": {
        "id": "containers_kubernetes",
        "label": "Containers and Kubernetes",
        "control_plane": "azure_resource_manager",
        "default_scope": "resource",
    },
    "Application and platform services": {
        "id": "application_platform",
        "label": "Application and platform services",
        "control_plane": "azure_resource_manager",
        "default_scope": "resource",
    },
    "Compute and analytics": {
        "id": "compute_analytics",
        "label": "Compute and analytics",
        "control_plane": "azure_resource_manager",
        "default_scope": "resource",
    },
    "Database security": {
        "id": "database_security",
        "label": "Database security",
        "control_plane": "azure_resource_manager",
        "default_scope": "resource",
    },
    "Integration and messaging": {
        "id": "integration_messaging",
        "label": "Integration and messaging",
        "control_plane": "azure_resource_manager",
        "default_scope": "resource",
    },
}


SERVICE_DEFINITIONS = {
    "machine_learning_": ("machine_learning", "Azure Machine Learning", "workspace"),
    "containerregistry_": ("container_registry", "Azure Container Registry", "registry"),
    "appinsights_": ("application_insights", "Application Insights", "component"),
    "postgresql_": ("postgresql", "Azure Database for PostgreSQL", "server"),
    "sqlserver_": ("sql_server", "Azure SQL", "server"),
    "kubernetes_": ("kubernetes", "Kubernetes", "cluster"),
    "databricks_": ("databricks", "Azure Databricks", "workspace"),
    "servicebus_": ("service_bus", "Azure Service Bus", "namespace"),
    "eventgrid_": ("event_grid", "Azure Event Grid", "topic or domain"),
    "cognitive_": ("ai_services", "Azure AI services", "account"),
    "keyvault_": ("key_vault", "Azure Key Vault", "vault"),
    "hdinsight_": ("hdinsight", "Azure HDInsight", "cluster"),
    "defender_": ("defender_for_cloud", "Microsoft Defender for Cloud", "subscription plan"),
    "monitor_": ("azure_monitor", "Azure Monitor", "monitored scope"),
    "storage_": ("storage", "Azure Storage", "storage account or data service"),
    "network_": ("networking", "Azure networking", "network resource"),
    "aisearch_": ("ai_search", "Azure AI Search", "search service"),
    "synapse_": ("synapse", "Azure Synapse Analytics", "workspace"),
    "cosmosdb_": ("cosmos_db", "Azure Cosmos DB", "account"),
    "signalr_": ("signalr", "Azure SignalR Service", "service"),
    "apim_": ("api_management", "Azure API Management", "service"),
    "mysql_": ("mysql", "Azure Database for MySQL", "server"),
    "redis_": ("redis", "Azure Cache for Redis", "cache"),
    "search_": ("ai_search", "Azure AI Search", "search service"),
    "entra_": ("entra_id", "Microsoft Entra ID", "tenant identity or policy"),
    "iam_": ("azure_rbac", "Azure role-based access control", "role or assignment"),
    "aks_": ("aks", "Azure Kubernetes Service", "cluster"),
    "sql_": ("sql_database", "Azure SQL", "database or server"),
    "app_": ("app_service", "Azure App Service", "application"),
    "vm_": ("virtual_machines", "Azure Virtual Machines", "virtual machine"),
    "iot_": ("iot", "Azure IoT", "IoT service"),
}


FAMILY_ATTRIBUTE_FIELDS = {
    "identity_access": {
        "principal_types": {"principaltype", "usertype"},
        "principal_names": {"userprincipalname", "principalname"},
        "role_names": {"rolename", "roledefinitionname"},
        "authentication_requirements": {"authenticationrequirement"},
    },
    "network_security": {
        "directions": {"direction"},
        "access_actions": {"access"},
        "protocols": {"protocol"},
        "source_addresses": {"sourceaddressprefix", "sourceaddressprefixes"},
        "destination_addresses": {"destinationaddressprefix", "destinationaddressprefixes"},
        "destination_ports": {"destinationportrange", "destinationportranges"},
    },
    "storage_security": {
        "account_kinds": {"kind"},
        "access_tiers": {"accesstier"},
        "public_access_levels": {"publicaccess"},
        "minimum_tls_versions": {"minimumtlsversion", "mintlsversion"},
        "network_default_actions": {"defaultaction"},
    },
    "secrets_key_management": {
        "vault_names": {"vaultname"},
        "object_types": {"objecttype"},
        "key_types": {"keytype", "kty"},
        "network_default_actions": {"defaultaction"},
    },
    "logging_monitoring": {
        "log_categories": {"category", "categories"},
        "retention_days": {"retentiondays", "retentionpolicydays"},
        "workspace_ids": {"workspaceid"},
        "storage_account_ids": {"storageaccountid"},
    },
    "security_posture": {
        "resource_types": {"resourcetype"},
        "pricing_tiers": {"pricingtier"},
        "subplans": {"subplan"},
    },
    "containers_kubernetes": {
        "kubernetes_versions": {"kubernetesversion"},
        "network_plugins": {"networkplugin"},
        "network_policies": {"networkpolicy"},
        "sku_names": {"skuname"},
    },
    "application_platform": {
        "runtime_versions": {
            "linuxfxversion",
            "windowsfxversion",
            "netframeworkversion",
            "nodeversion",
            "pythonversion",
            "javaversion",
            "phpversion",
        },
        "minimum_tls_versions": {"minimumtlsversion", "mintlsversion"},
        "public_network_access": {"publicnetworkaccess"},
        "authentication_enabled": {"authenticationenabled"},
    },
    "compute_analytics": {
        "vm_sizes": {"vmsize"},
        "os_types": {"ostype"},
        "encryption_types": {"encryptiontype"},
        "extension_types": {"extensiontype", "typehandler", "publisher"},
    },
    "database_security": {
        "server_versions": {"serverversion", "version"},
        "minimum_tls_versions": {"minimumtlsversion", "mintlsversion"},
        "public_network_access": {"publicnetworkaccess"},
        "administrator_types": {"administratortype"},
    },
    "integration_messaging": {
        "sku_names": {"skuname"},
        "public_network_access": {"publicnetworkaccess"},
        "minimum_tls_versions": {"minimumtlsversion", "mintlsversion"},
    },
}


def payload_records(payload: Any) -> List[Any]:
    """Return records from the common top-level Azure CLI payload shapes."""
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, Mapping) and isinstance(payload.get("value"), list):
        return payload["value"]
    return [payload]


def context_text(value: Any) -> Optional[str]:
    """Return a bounded scalar string suitable for compact report context."""
    if value is None or isinstance(value, (Mapping, list, tuple, set)):
        return None
    text = str(value).strip()
    if not text or len(text) > MAX_CONTEXT_VALUE_LENGTH:
        return None
    return text


def unique_text(values: Iterable[Any]) -> List[str]:
    """Return deterministic case-insensitive unique non-empty strings."""
    retained = {}
    for value in values:
        text = context_text(value)
        if text is not None:
            retained.setdefault(text.casefold(), text)
    return sorted(retained.values(), key=lambda item: item.casefold())


def subscription_inventory(catalog: Optional[Mapping[str, Any]]) -> List[Mapping[str, Any]]:
    """Return collected subscription records without matching location datasets."""
    item = (catalog or {}).get("az_account_list")
    if not isinstance(item, Mapping) or item.get("error") or item.get("data") is None:
        return []
    return [record for record in payload_records(item.get("data")) if isinstance(record, Mapping)]


def subscription_inventory_available(catalog: Optional[Mapping[str, Any]]) -> bool:
    """Return whether a successfully loaded subscription dataset was supplied."""
    item = (catalog or {}).get("az_account_list")
    return bool(
        isinstance(item, Mapping)
        and not item.get("error")
        and item.get("data") is not None
    )


def engagement_context(
    finding: Mapping[str, Any],
    catalog: Optional[Mapping[str, Any]],
) -> Tuple[Dict[str, Any], List[str]]:
    """Build assessment identity and collection scope from trusted collected metadata."""
    manifest, _ = collection_manifest(catalog)
    manifest_context = manifest.get("context", {}) if isinstance(manifest, Mapping) else {}
    if not isinstance(manifest_context, Mapping):
        manifest_context = {}
    collection_run = finding.get("reporting", {}).get("provenance", {}).get("collection_run")
    collection_run = collection_run if isinstance(collection_run, Mapping) else {}
    manifest_available = manifest is not None or bool(collection_run)
    inventory_available = subscription_inventory_available(catalog)
    selected_subscription_id = context_text(
        manifest_context.get("subscription_id") or collection_run.get("subscription_id")
    )
    selected_tenant_id = context_text(
        manifest_context.get("tenant_id") or collection_run.get("tenant_id")
    )

    subscriptions_by_id: Dict[str, Dict[str, Any]] = {}
    inventory = subscription_inventory(catalog)
    for record in inventory:
        subscription_id = context_text(record.get("id") or record.get("subscriptionId"))
        if subscription_id is None:
            continue
        subscriptions_by_id[subscription_id.casefold()] = {
            "subscription_id": subscription_id,
            "name": context_text(record.get("name") or record.get("subscriptionName")),
            "tenant_id": context_text(record.get("tenantId")),
            "state": context_text(record.get("state")),
            "is_default": record.get("isDefault") if isinstance(record.get("isDefault"), bool) else None,
        }
    if selected_subscription_id and selected_subscription_id.casefold() not in subscriptions_by_id:
        subscriptions_by_id[selected_subscription_id.casefold()] = {
            "subscription_id": selected_subscription_id,
            "name": None,
            "tenant_id": selected_tenant_id,
            "state": None,
            "is_default": None,
        }

    subscriptions = sorted(
        subscriptions_by_id.values(),
        key=lambda item: item["subscription_id"].casefold(),
    )
    tenant_ids = unique_text(
        [selected_tenant_id] + [item.get("tenant_id") for item in subscriptions]
    )
    limitations = []
    if not manifest_available:
        limitations.append("No collection manifest was available for engagement context")
    if not tenant_ids:
        limitations.append("No tenant identity was available in collected engagement context")
    if not subscriptions:
        limitations.append("No subscription identity was available in collected engagement context")
    elif not inventory_available:
        limitations.append(
            "No subscription inventory was available; selected subscription metadata may be incomplete"
        )

    return (
        {
            "tenant_ids": tenant_ids,
            "selected_subscription_id": selected_subscription_id,
            "subscriptions": subscriptions,
            "collection": {
                "run_id": context_text(collection_run.get("run_id")),
                "status": context_text(collection_run.get("status")),
                "started_at": context_text(collection_run.get("started_at")),
                "completed_at": context_text(collection_run.get("completed_at")),
            },
            "sources": {
                "collection_manifest": manifest_available,
                "subscription_inventory": inventory_available,
            },
        },
        limitations,
    )


def family_context(finding: Mapping[str, Any]) -> Dict[str, Any]:
    """Resolve stable category and Azure service-family labels from the finding ID."""
    definition = finding.get("definition", {})
    category = definition.get("category")
    family = dict(
        FAMILY_DEFINITIONS.get(
            category,
            {
                "id": "azure_configuration",
                "label": str(category or "Azure configuration"),
                "control_plane": "azure_resource_manager",
                "default_scope": "unknown",
            },
        )
    )
    finding_id = str(finding.get("finding_id") or "")
    service = ("azure", "Azure", "Azure configuration item")
    for prefix in sorted(SERVICE_DEFINITIONS, key=len, reverse=True):
        if finding_id.startswith(prefix):
            service = SERVICE_DEFINITIONS[prefix]
            break
    family.update(
        {
            "service_id": service[0],
            "service_label": service[1],
            "primary_subject": service[2],
        }
    )
    return family


def azure_path_parts(identifier: Any) -> Dict[str, Optional[str]]:
    """Extract subscription, resource group, and resource type from an Azure ID."""
    text = context_text(identifier)
    if text is None or not text.startswith("/"):
        return {"subscription_id": None, "resource_group": None, "resource_type": None}
    parts = [part for part in text.split("/") if part]
    lowered = [part.casefold() for part in parts]

    def following(segment: str) -> Optional[str]:
        try:
            index = lowered.index(segment)
        except ValueError:
            return None
        return parts[index + 1] if index + 1 < len(parts) else None

    resource_type = None
    provider_indexes = [
        index for index, part in enumerate(lowered) if part == "providers"
    ]
    provider_index = provider_indexes[-1] if provider_indexes else -1
    if provider_index >= 0 and provider_index + 2 < len(parts):
        provider = parts[provider_index + 1]
        type_segments = parts[provider_index + 2 :: 2]
        resource_type = "/".join([provider] + type_segments)
    return {
        "subscription_id": following("subscriptions"),
        "resource_group": following("resourcegroups"),
        "resource_type": resource_type,
    }


def named_observation_values(
    observations: Iterable[Mapping[str, Any]],
    selected_names: Set[str],
) -> Tuple[Dict[str, List[Any]], bool]:
    """Index only allow-listed scalar values by case-insensitive field name."""
    indexed: Dict[str, List[Any]] = {}
    visited = 0
    truncated = False

    def walk(value: Any, depth: int) -> None:
        nonlocal visited, truncated
        if truncated:
            return
        visited += 1
        if visited > MAX_OBSERVATION_NODES or depth > MAX_OBSERVATION_DEPTH:
            truncated = True
            return
        if isinstance(value, Mapping):
            for key, child in value.items():
                key_name = str(key).casefold()
                if key_name not in selected_names:
                    walk(child, depth + 1)
                    continue
                if isinstance(child, (list, tuple, set)):
                    scalars = [item for item in child if not isinstance(item, (Mapping, list, tuple, set))]
                    indexed.setdefault(key_name, []).extend(scalars)
                elif not isinstance(child, Mapping):
                    indexed.setdefault(key_name, []).append(child)
                walk(child, depth + 1)
        elif isinstance(value, (list, tuple)):
            for child in value:
                walk(child, depth + 1)

    for observation in observations:
        walk(observation.get("data", {}), 0)
    return indexed, truncated


def finding_scope_context(
    finding: Mapping[str, Any],
    family: Mapping[str, Any],
    engagement: Mapping[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, List[str]], List[str]]:
    """Summarise affected scope and selected family-specific evidence fields."""
    reporting = finding.get("reporting", {})
    assets = reporting.get("assets", []) if isinstance(reporting, Mapping) else []
    observations = reporting.get("observations", []) if isinstance(reporting, Mapping) else []
    concrete_assets = [asset for asset in assets if asset.get("kind") != "assessment_scope"]
    subscription_ids: List[Any] = []
    resource_groups: List[Any] = []
    resource_types: List[Any] = []
    asset_names: List[Any] = []
    asset_kinds: List[Any] = []
    has_resource = False
    has_subscription = False
    for asset in concrete_assets:
        path = azure_path_parts(asset.get("identifier"))
        subscription_ids.extend([asset.get("subscription_id"), path["subscription_id"]])
        resource_groups.extend([asset.get("resource_group"), path["resource_group"]])
        resource_types.extend([asset.get("resource_type"), path["resource_type"]])
        asset_names.append(asset.get("name"))
        asset_kinds.append(asset.get("kind"))
        has_resource = has_resource or asset.get("kind") in {"azure_resource", "azure_named_resource"}
        has_subscription = has_subscription or asset.get("kind") == "azure_subscription"

    # Resource scope is the most specific scope even when evidence also names
    # its parent subscription. This avoids presenting ancestry as mixed scope.
    if has_resource:
        scope_level = "resource"
    elif has_subscription:
        scope_level = "subscription"
    else:
        scope_level = family["default_scope"]

    if scope_level == "subscription" and not unique_text(subscription_ids):
        subscription_ids.append(engagement.get("selected_subscription_id"))

    configured_fields = FAMILY_ATTRIBUTE_FIELDS.get(family["id"], {})
    selected_names = {
        "location",
        "region",
        "primarylocation",
    }.union(
        source_name
        for source_names in configured_fields.values()
        for source_name in source_names
    )
    indexed, traversal_truncated = named_observation_values(
        observations,
        selected_names,
    )
    locations = unique_text(
        indexed.get("location", [])
        + indexed.get("region", [])
        + indexed.get("primarylocation", [])
    )
    attributes = {}
    limitations = []
    for output_name, source_names in configured_fields.items():
        values = unique_text(
            value
            for source_name in source_names
            for value in indexed.get(source_name, [])
        )
        if len(values) > MAX_ATTRIBUTE_VALUES:
            values = values[:MAX_ATTRIBUTE_VALUES]
            limitations.append(
                f"Family context field {output_name} was limited to {MAX_ATTRIBUTE_VALUES} values"
            )
        if values:
            attributes[output_name] = values
    if traversal_truncated:
        limitations.append("Observation traversal was bounded while deriving finding context")
    if finding.get("status") == "found" and not concrete_assets:
        limitations.append("Finding evidence did not identify a concrete affected asset")

    scope = {
        "level": scope_level,
        "affected_asset_count": len(concrete_assets),
        "observation_count": int(finding.get("evidence_count") or 0),
        "asset_kinds": unique_text(asset_kinds),
        "asset_names": unique_text(asset_names),
        "subscription_ids": unique_text(subscription_ids),
        "resource_groups": unique_text(resource_groups),
        "resource_types": unique_text(resource_types),
        "locations": locations,
    }
    return scope, attributes, limitations


def normalise_finding_context(
    finding: Dict[str, Any],
    catalog: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Attach validated engagement and service-family context to one finding."""
    engagement, engagement_limitations = engagement_context(finding, catalog)
    family = family_context(finding)
    scope, attributes, scope_limitations = finding_scope_context(
        finding,
        family,
        engagement,
    )
    finding["context"] = {
        "schema_version": CONTEXT_SCHEMA_VERSION,
        "engagement": engagement,
        "family": {
            key: family[key]
            for key in (
                "id",
                "label",
                "control_plane",
                "service_id",
                "service_label",
                "primary_subject",
            )
        },
        "scope": scope,
        "attributes": attributes,
        "limitations": sorted(set(engagement_limitations + scope_limitations)),
    }
    validate_finding_context(finding)
    return finding


def validate_string_list(value: Any, field_name: str) -> None:
    """Require unique bounded strings for deterministic context lists."""
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"Finding context {field_name} must be a list of strings")
    if any(not item or len(item) > MAX_CONTEXT_VALUE_LENGTH for item in value):
        raise ValueError(f"Finding context {field_name} contains an invalid string")
    if len({item.casefold() for item in value}) != len(value):
        raise ValueError(f"Finding context {field_name} contains duplicates")


def validate_optional_string(value: Any, field_name: str) -> None:
    """Require a bounded string or null for optional context metadata."""
    if value is not None and (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_CONTEXT_VALUE_LENGTH
    ):
        raise ValueError(f"Finding context {field_name} must be a bounded string or null")


def validate_finding_context(finding: Mapping[str, Any]) -> None:
    """Reject malformed or internally inconsistent report context."""
    context = finding.get("context") or {}
    if context.get("schema_version") != CONTEXT_SCHEMA_VERSION:
        raise ValueError("Unsupported finding context schema")
    engagement = context.get("engagement")
    family = context.get("family")
    scope = context.get("scope")
    attributes = context.get("attributes")
    if not all(isinstance(item, Mapping) for item in (engagement, family, scope, attributes)):
        raise ValueError("Finding context sections must be objects")

    validate_string_list(engagement.get("tenant_ids"), "tenant_ids")
    validate_optional_string(
        engagement.get("selected_subscription_id"),
        "selected_subscription_id",
    )
    subscriptions = engagement.get("subscriptions")
    if not isinstance(subscriptions, list) or any(not isinstance(item, Mapping) for item in subscriptions):
        raise ValueError("Finding context subscriptions must be a list of objects")
    subscription_ids = [item.get("subscription_id") for item in subscriptions]
    if any(
        not isinstance(item, str)
        or not item
        or len(item) > MAX_CONTEXT_VALUE_LENGTH
        for item in subscription_ids
    ):
        raise ValueError("Finding context subscriptions require subscription IDs")
    if len({item.casefold() for item in subscription_ids}) != len(subscription_ids):
        raise ValueError("Finding context contains duplicate subscriptions")
    selected_subscription_id = engagement.get("selected_subscription_id")
    if selected_subscription_id and selected_subscription_id.casefold() not in {
        item.casefold() for item in subscription_ids
    }:
        raise ValueError("Finding context selected subscription is absent from subscriptions")
    for subscription in subscriptions:
        for key in ("name", "tenant_id", "state"):
            validate_optional_string(subscription.get(key), f"subscription {key}")
        if subscription.get("is_default") is not None and not isinstance(
            subscription.get("is_default"), bool
        ):
            raise ValueError("Finding context subscription is_default must be boolean or null")
    collection = engagement.get("collection")
    sources = engagement.get("sources")
    if not isinstance(collection, Mapping) or not isinstance(sources, Mapping):
        raise ValueError("Finding context collection and source metadata must be objects")
    for key in ("run_id", "status", "started_at", "completed_at"):
        validate_optional_string(collection.get(key), f"collection {key}")
    if any(not isinstance(sources.get(key), bool) for key in ("collection_manifest", "subscription_inventory")):
        raise ValueError("Finding context source flags must be booleans")

    required_family_fields = {
        "id",
        "label",
        "control_plane",
        "service_id",
        "service_label",
        "primary_subject",
    }
    if any(
        not isinstance(family.get(key), str) or not context_text(family.get(key))
        for key in required_family_fields
    ):
        raise ValueError("Finding context family metadata is incomplete")
    expected_family = family_context(finding)
    if any(
        family.get(key) != expected_family.get(key)
        for key in required_family_fields
    ):
        raise ValueError("Finding context family metadata conflicts with its definition")
    if scope.get("level") not in SCOPE_LEVELS:
        raise ValueError("Finding context scope level is invalid")
    for key in (
        "asset_kinds",
        "asset_names",
        "subscription_ids",
        "resource_groups",
        "resource_types",
        "locations",
    ):
        validate_string_list(scope.get(key), key)
    affected_asset_count = scope.get("affected_asset_count")
    observation_count = scope.get("observation_count")
    if isinstance(affected_asset_count, bool) or not isinstance(affected_asset_count, int) or affected_asset_count < 0:
        raise ValueError("Finding context affected asset count is invalid")
    if observation_count != int(finding.get("evidence_count") or 0):
        raise ValueError("Finding context observation count does not match evidence count")
    reporting_assets = finding.get("reporting", {}).get("assets", [])
    expected_assets = sum(1 for asset in reporting_assets if asset.get("kind") != "assessment_scope")
    if affected_asset_count != expected_assets:
        raise ValueError("Finding context affected asset count does not match reporting assets")
    for key, values in attributes.items():
        if key not in FAMILY_ATTRIBUTE_FIELDS.get(family["id"], {}):
            raise ValueError("Finding context contains an unsupported family attribute")
        validate_string_list(values, f"attribute {key}")
        if len(values) > MAX_ATTRIBUTE_VALUES:
            raise ValueError("Finding context family attribute contains too many values")
    validate_string_list(context.get("limitations"), "limitations")
