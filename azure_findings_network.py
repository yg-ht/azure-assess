#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Offline Azure network posture and ingress-path correlations."""

import ipaddress
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from azure_findings_correlation import CorrelationResult, canonical_arm_id, normalise_identifier
from azure_findings_governance import nested_value
from azure_findings_shared import collection_parameters


APPROVED_CONNECTION_STATES = {"approved"}
SUCCESSFUL_PROVISIONING_STATES = {"", "succeeded", "success"}
INTERNET_SOURCE_TAGS = {"*", "any", "internet"}


@dataclass(frozen=True)
class PrivateLinkAdapter:
    service: str
    expected_resource_types: Tuple[str, ...]
    expected_group_ids: Tuple[str, ...] = ()


PRIVATE_LINK_ADAPTERS = {
    "storage": PrivateLinkAdapter(
        "Azure Storage",
        ("microsoft.storage/storageaccounts",),
        ("blob", "file", "queue", "table", "web", "dfs"),
    ),
    "key_vault": PrivateLinkAdapter(
        "Azure Key Vault", ("microsoft.keyvault/vaults",), ("vault",)
    ),
    "container_registry": PrivateLinkAdapter(
        "Azure Container Registry",
        ("microsoft.containerregistry/registries",),
        ("registry",),
    ),
    "web": PrivateLinkAdapter(
        "Azure App Service",
        ("microsoft.web/sites",),
        ("sites",),
    ),
    "app_configuration": PrivateLinkAdapter(
        "Azure App Configuration",
        ("microsoft.appconfiguration/configurationstores",),
        ("configurationstores",),
    ),
    "application_gateway": PrivateLinkAdapter(
        "Azure Application Gateway",
        ("microsoft.network/applicationgateways",),
        ("applicationgateways",),
    ),
    "cosmos_db": PrivateLinkAdapter(
        "Azure Cosmos DB",
        ("microsoft.documentdb/databaseaccounts",),
        ("sql", "mongodb", "cassandra", "gremlin", "table"),
    ),
    "machine_learning": PrivateLinkAdapter(
        "Azure Machine Learning",
        ("microsoft.machinelearningservices/workspaces",),
        ("amlworkspace",),
    ),
    "search": PrivateLinkAdapter(
        "Azure AI Search",
        ("microsoft.search/searchservices",),
        ("searchservice",),
    ),
}


def resource_type_from_id(value: Any) -> str:
    resource_id = canonical_arm_id(value)
    marker = "/providers/"
    if marker not in resource_id:
        return ""
    parts = resource_id.split(marker, 1)[1].split("/")
    return "/".join(parts[:2]) if len(parts) >= 2 else ""


def public_network_state(resource: Mapping[str, Any]) -> str:
    public_access = normalise_identifier(
        nested_value(resource, "publicNetworkAccess", ("properties", "publicNetworkAccess"))
    )
    default_action = normalise_identifier(
        nested_value(
            resource,
            ("networkRuleSet", "defaultAction"),
            ("properties", "networkRuleSet", "defaultAction"),
            ("networkAcls", "defaultAction"),
            ("properties", "networkAcls", "defaultAction"),
        )
    )
    if public_access == "disabled":
        return "disabled"
    if public_access == "enabled":
        return "enabled_restricted" if default_action == "deny" else "enabled"
    if default_action == "deny":
        return "enabled_restricted"
    if default_action == "allow":
        return "enabled"
    frontends = nested_value(
        resource,
        "frontendIPConfigurations",
        ("properties", "frontendIPConfigurations"),
    ) or []
    if any(
        canonical_arm_id(
            nested_value(
                frontend,
                ("publicIPAddress", "id"),
                ("properties", "publicIPAddress", "id"),
            )
        )
        for frontend in frontends
        if isinstance(frontend, Mapping)
    ):
        return "enabled"
    return "unknown"


def target_resource_from_connection_id(value: Any) -> str:
    connection_id = canonical_arm_id(value)
    marker = "/privateendpointconnections/"
    return connection_id.split(marker, 1)[0] if marker in connection_id else ""


def normalise_private_connections(
    records: Iterable[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    """Normalise dedicated connection records and generic private endpoint records."""
    connections = []
    for record in records:
        embedded_connections = nested_value(
            record,
            "privateEndpointConnections",
            ("properties", "privateEndpointConnections"),
        )
        if isinstance(embedded_connections, list):
            connections.extend(normalise_private_connections(embedded_connections))
            continue
        service_connections = nested_value(
            record,
            "privateLinkServiceConnections",
            ("properties", "privateLinkServiceConnections"),
            "manualPrivateLinkServiceConnections",
            ("properties", "manualPrivateLinkServiceConnections"),
        )
        if isinstance(service_connections, list):
            for item in service_connections:
                properties = item.get("properties", item) if isinstance(item, Mapping) else {}
                state = properties.get("privateLinkServiceConnectionState") or {}
                connections.append(
                    {
                        "privateEndpointId": record.get("id"),
                        "targetResourceId": properties.get("privateLinkServiceId"),
                        "groupIds": list(properties.get("groupIds") or []),
                        "connectionStatus": state.get("status"),
                        "provisioningState": properties.get("provisioningState")
                        or nested_value(record, "provisioningState", ("properties", "provisioningState")),
                    }
                )
            continue
        state = nested_value(
            record,
            "privateLinkServiceConnectionState",
            ("properties", "privateLinkServiceConnectionState"),
        )
        state = state if isinstance(state, Mapping) else {}
        connections.append(
            {
                "privateEndpointId": nested_value(
                    record,
                    ("privateEndpoint", "id"),
                    ("properties", "privateEndpoint", "id"),
                ),
                "targetResourceId": target_resource_from_connection_id(record.get("id")),
                "groupIds": list(
                    nested_value(record, "groupIds", ("properties", "groupIds")) or []
                ),
                "connectionStatus": state.get("status"),
                "provisioningState": nested_value(
                    record, "provisioningState", ("properties", "provisioningState")
                ),
                "parameters": collection_parameters(record),
            }
        )
    return connections


def connection_is_effective(connection: Mapping[str, Any], adapter: PrivateLinkAdapter) -> bool:
    status = normalise_identifier(connection.get("connectionStatus"))
    provisioning = normalise_identifier(connection.get("provisioningState"))
    groups = {normalise_identifier(item) for item in connection.get("groupIds", [])}
    groups_match = not adapter.expected_group_ids or not groups or bool(
        groups.intersection(adapter.expected_group_ids)
    )
    return (
        status in APPROVED_CONNECTION_STATES
        and provisioning in SUCCESSFUL_PROVISIONING_STATES
        and groups_match
    )


def analyse_private_link_posture(
    resources: Iterable[Mapping[str, Any]],
    connection_records: Iterable[Mapping[str, Any]],
    adapter: PrivateLinkAdapter,
    conclusion_support: str,
    source_files: Iterable[str] = (),
) -> CorrelationResult:
    """Find resources where approved private connectivity leaves public access enabled."""
    connections_by_target: Dict[str, List[Dict[str, Any]]] = {}
    for connection in normalise_private_connections(connection_records):
        target_id = canonical_arm_id(connection.get("targetResourceId"))
        if target_id:
            connections_by_target.setdefault(target_id, []).append(connection)
    observations_by_id = {}
    eligible_assets_by_id = {}
    limitations = []
    for resource in resources:
        resource_id = canonical_arm_id(resource.get("id"))
        if not resource_id or resource_type_from_id(resource_id) not in adapter.expected_resource_types:
            continue
        eligible_assets_by_id[resource_id] = {
            "id": resource.get("id"),
            "name": resource.get("name"),
            "kind": adapter.service,
        }
        public_state = public_network_state(resource)
        candidates = connections_by_target.get(resource_id, [])
        effective = [item for item in candidates if connection_is_effective(item, adapter)]
        if public_state.startswith("enabled") and effective:
            posture = "public_and_private"
        elif public_state.startswith("enabled"):
            posture = "public_only"
        elif public_state == "disabled" and effective:
            posture = "private_only"
        elif public_state == "disabled":
            posture = "private_path_unverified"
        else:
            posture = "unknown"
        if posture == "unknown":
            limitations.append(
                f"Public network state could not be determined for {resource.get('id')}"
            )
        if posture != "public_and_private":
            continue
        observations_by_id[resource_id] = {
            "id": resource.get("id"),
            "name": resource.get("name"),
            "service": adapter.service,
            "publicNetworkState": public_state,
            "privateEndpointPosture": posture,
            "approvedPrivateEndpointIds": sorted(
                {
                    item.get("privateEndpointId")
                    for item in effective
                    if item.get("privateEndpointId")
                }
            ),
            "approvedGroupIds": sorted(
                {
                    group
                    for item in effective
                    for group in item.get("groupIds", [])
                }
            ),
        }
    return CorrelationResult(
        observations=[observations_by_id[key] for key in sorted(observations_by_id)],
        eligible_assets=[eligible_assets_by_id[key] for key in sorted(eligible_assets_by_id)],
        source_files=sorted(set(source_files)),
        limitations=list(dict.fromkeys(limitations)),
        conclusion_support=conclusion_support,
    )


def values(record: Mapping[str, Any], singular: str, plural: str) -> List[Any]:
    plural_value = nested_value(record, plural, ("properties", plural))
    if isinstance(plural_value, list):
        return plural_value
    singular_value = nested_value(record, singular, ("properties", singular))
    return [singular_value] if singular_value is not None else []


def port_intervals(rule: Mapping[str, Any]) -> List[Tuple[int, int]]:
    intervals = []
    for value in values(rule, "destinationPortRange", "destinationPortRanges"):
        text = str(value).strip()
        if text == "*":
            intervals.append((1, 65535))
            continue
        try:
            if "-" in text:
                start, end = text.split("-", 1)
                start_port, end_port = int(start), int(end)
            else:
                start_port = end_port = int(text)
        except ValueError:
            continue
        if 1 <= start_port <= end_port <= 65535:
            intervals.append((start_port, end_port))
    return intervals


def rule_priority(rule: Mapping[str, Any]) -> int:
    try:
        return int(
            nested_value(rule, "priority", ("properties", "priority")) or 65535
        )
    except (TypeError, ValueError):
        return 65535


def collapse_networks(networks: Iterable[Any]) -> Tuple[Any, ...]:
    """Collapse IPv4 and IPv6 networks without mixing address families."""
    collapsed = []
    for version in (4, 6):
        family = [network for network in networks if network.version == version]
        collapsed.extend(ipaddress.collapse_addresses(family))
    return tuple(collapsed)


@dataclass(frozen=True)
class ExternalSourceSpace:
    """A set of candidate source addresses used for exact NSG first-match logic."""

    networks: Tuple[Any, ...] = ()

    @classmethod
    def empty(cls):
        return cls(())

    @classmethod
    def internet(cls, version: Optional[int] = None):
        # The numeric universes permit exact CIDR subtraction.  Reachability is
        # decided separately with ``is_global`` so private-only remnants do not
        # become external attack paths.
        networks = []
        if version in {None, 4}:
            networks.append(ipaddress.ip_network("0.0.0.0/0"))
        if version in {None, 6}:
            networks.append(ipaddress.ip_network("::/0"))
        return cls(tuple(networks))

    @classmethod
    def from_networks(cls, networks: Iterable[Any]):
        return cls(collapse_networks(networks))

    def union(self, other: "ExternalSourceSpace") -> "ExternalSourceSpace":
        return ExternalSourceSpace.from_networks(self.networks + other.networks)

    def intersection(self, other: "ExternalSourceSpace") -> "ExternalSourceSpace":
        intersections = []
        for left in self.networks:
            for right in other.networks:
                if left.version != right.version or not left.overlaps(right):
                    continue
                intersections.append(left if left.subnet_of(right) else right)
        return ExternalSourceSpace.from_networks(intersections)

    def difference(self, other: "ExternalSourceSpace") -> "ExternalSourceSpace":
        remaining = list(self.networks)
        for removal in other.networks:
            updated = []
            for candidate in remaining:
                if candidate.version != removal.version or not candidate.overlaps(removal):
                    updated.append(candidate)
                elif candidate.subnet_of(removal):
                    continue
                elif removal.subnet_of(candidate):
                    updated.extend(candidate.address_exclude(removal))
            remaining = updated
        return ExternalSourceSpace.from_networks(remaining)

    def has_external_address(self) -> bool:
        return any(network_has_global_address(network) for network in self.networks)


def network_has_global_address(network: Any) -> bool:
    """Return whether a CIDR contains at least one globally routable address."""
    # ipaddress treats a zero-prefix network as non-global because it also
    # contains special ranges, but it necessarily contains global addresses.
    if network.prefixlen == 0:
        return True
    # For narrower CIDRs the stdlib classification handles private, shared,
    # documentation, loopback, multicast, reserved, and globally routed ranges
    # without recursive address enumeration.
    return network.is_global


def external_source_scope(space: ExternalSourceSpace) -> Optional[str]:
    if not space.has_external_address():
        return None
    if any(network.prefixlen == 0 for network in space.networks):
        return "internet"
    return "restricted_public"


def address_version(value: Any) -> Optional[int]:
    try:
        return ipaddress.ip_address(str(value).strip()).version
    except ValueError:
        return None


def address_space(values_to_parse: Iterable[Any]) -> Tuple[ExternalSourceSpace, List[str]]:
    """Parse supported NSG prefixes and return unresolved values separately."""
    values_to_parse = list(values_to_parse)
    if not values_to_parse:
        return ExternalSourceSpace.empty(), ["<missing>"]
    networks = []
    unresolved = []
    for value in values_to_parse:
        text = normalise_identifier(value)
        if text in INTERNET_SOURCE_TAGS:
            networks.extend(ExternalSourceSpace.internet().networks)
            continue
        try:
            networks.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            unresolved.append(str(value))
    return ExternalSourceSpace.from_networks(networks), unresolved


def destination_match(rule: Mapping[str, Any], destination_ip: Any = None) -> Optional[bool]:
    """Match a rule destination to the translated backend address."""
    if values(
        rule,
        "destinationApplicationSecurityGroup",
        "destinationApplicationSecurityGroups",
    ):
        return None
    prefixes = values(rule, "destinationAddressPrefix", "destinationAddressPrefixes")
    # Azure rules require a destination, but legacy and synthetic datasets may
    # omit it.  Preserve their established wildcard interpretation.
    if not prefixes:
        return True
    parsed_destination = None
    if destination_ip:
        try:
            parsed_destination = ipaddress.ip_address(str(destination_ip).strip())
        except ValueError:
            return None
    unresolved = False
    for value in prefixes:
        text = normalise_identifier(value)
        if text in {"*", "any"}:
            return True
        if text == "virtualnetwork":
            if parsed_destination is None:
                unresolved = True
            elif parsed_destination.is_private:
                return True
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            unresolved = True
            continue
        if parsed_destination is None:
            unresolved = True
        elif parsed_destination.version == network.version and parsed_destination in network:
            return True
    return None if unresolved else False


def base_rule_matches(rule: Mapping[str, Any], protocol: str, port: int) -> bool:
    if normalise_identifier(
        nested_value(rule, "direction", ("properties", "direction"))
    ) != "inbound":
        return False
    rule_protocol = normalise_identifier(
        nested_value(rule, "protocol", ("properties", "protocol"))
    )
    if rule_protocol not in {"*", "any", normalise_identifier(protocol)}:
        return False
    return any(start <= port <= end for start, end in port_intervals(rule))


def nsg_decision(
    rules: Iterable[Mapping[str, Any]],
    protocol: str,
    port: int,
    destination_ip: Any = None,
    source_version: Optional[int] = None,
) -> Dict[str, Any]:
    """Apply Azure first-match semantics across external source address sets."""
    ordered_rules = sorted(
        (rule for rule in rules if base_rule_matches(rule, protocol, port)),
        key=lambda rule: (
            rule_priority(rule),
            str(rule.get("name") or ""),
        ),
    )
    unclassified = ExternalSourceSpace.internet(source_version)
    allowed = ExternalSourceSpace.empty()
    selected_rule = None
    exclusions = []
    limitations = []
    unresolved_deny = False
    for rule in ordered_rules:
        destination = destination_match(rule, destination_ip)
        access = normalise_identifier(
            nested_value(rule, "access", ("properties", "access"))
        )
        if destination is False:
            continue
        if destination is None:
            limitations.append(
                f"Could not resolve the destination of NSG rule {rule.get('name') or '<unnamed>'}"
            )
            if access == "deny":
                unresolved_deny = True
                unclassified = ExternalSourceSpace.empty()
            continue
        sources, unresolved_sources = address_space(
            values(rule, "sourceAddressPrefix", "sourceAddressPrefixes")
        )
        if unresolved_sources:
            limitations.append(
                f"Could not resolve source prefixes for NSG rule {rule.get('name') or '<unnamed>'}: "
                f"{', '.join(sorted(unresolved_sources))}"
            )
            if access == "deny":
                unresolved_deny = True
        matched = unclassified.intersection(sources)
        if not matched.networks:
            if unresolved_sources and access == "deny":
                unclassified = ExternalSourceSpace.empty()
            continue
        if access == "allow":
            allowed = allowed.union(matched)
            if selected_rule is None and matched.has_external_address():
                selected_rule = rule
        elif access == "deny":
            exclusions.extend(
                str(value)
                for value in values(
                    rule, "sourceAddressPrefix", "sourceAddressPrefixes"
                )
            )
        else:
            limitations.append(
                f"Unsupported access value on NSG rule {rule.get('name') or '<unnamed>'}"
            )
            unresolved_deny = True
            unclassified = ExternalSourceSpace.empty()
            continue
        unclassified = unclassified.difference(matched)
        if unresolved_sources and access == "deny":
            # An unresolved higher-priority deny may cover every still
            # unclassified source. Earlier allows remain authoritative.
            unclassified = ExternalSourceSpace.empty()

    if allowed.has_external_address():
        decision = "allow"
    elif unresolved_deny:
        decision = "unknown"
    else:
        # Any unclassified traffic is blocked by Azure's default DenyAllInbound.
        decision = "deny"
    return {
        "decision": decision,
        "rule": selected_rule,
        "allowed_source_space": allowed,
        "allowedSourceScope": external_source_scope(allowed),
        "excludedSourcePrefixes": sorted(set(exclusions)),
        "limitations": limitations,
    }


def public_ip_index(public_ips: Iterable[Mapping[str, Any]]) -> Dict[str, Mapping[str, Any]]:
    return {
        canonical_arm_id(item.get("id")): item
        for item in public_ips
        if canonical_arm_id(item.get("id"))
        and nested_value(item, "ipAddress", ("properties", "ipAddress"))
    }


def nsg_index(nsgs: Iterable[Mapping[str, Any]]) -> Dict[str, Mapping[str, Any]]:
    return {
        canonical_arm_id(item.get("id")): item
        for item in nsgs
        if canonical_arm_id(item.get("id"))
    }


def nic_nsg_rules(
    nic: Mapping[str, Any], nsgs_by_id: Mapping[str, Mapping[str, Any]]
) -> Tuple[bool, Optional[List[Mapping[str, Any]]]]:
    """Return whether a NIC NSG is attached and all of its inbound rule data."""
    nsg_id = canonical_arm_id(
        nested_value(nic, ("networkSecurityGroup", "id"), ("properties", "networkSecurityGroup", "id"))
    )
    if not nsg_id:
        return False, None
    nsg = nsgs_by_id.get(nsg_id)
    if nsg is None:
        return True, None
    rules = list(
        nested_value(nsg, "securityRules", ("properties", "securityRules")) or []
    )
    rules.extend(
        nested_value(
            nsg, "defaultSecurityRules", ("properties", "defaultSecurityRules")
        )
        or []
    )
    return True, [rule for rule in rules if isinstance(rule, Mapping)]


def parameter_record_id(record: Mapping[str, Any]) -> str:
    parameters = collection_parameters(record)
    return canonical_arm_id(parameters.get("id"))


def parameterised_records(
    records: Iterable[Mapping[str, Any]],
) -> Iterable[Tuple[str, Mapping[str, Any]]]:
    """Expand Azure ``value`` wrappers without losing the requested NIC ID."""
    for record in records:
        nic_id = parameter_record_id(record)
        value = record.get("value")
        if isinstance(value, list):
            for item in value:
                if isinstance(item, Mapping):
                    yield nic_id, item
            continue
        yield nic_id, record


def effective_rules_index(
    records: Iterable[Mapping[str, Any]],
) -> Dict[str, List[List[Mapping[str, Any]]]]:
    """Index effective rules as separate NIC/subnet enforcement layers."""
    index: Dict[str, List[List[Mapping[str, Any]]]] = {}
    for nic_id, record in parameterised_records(records):
        if not nic_id:
            continue
        rules = nested_value(
            record,
            "effectiveSecurityRules",
            "securityRules",
            ("properties", "effectiveSecurityRules"),
            ("properties", "securityRules"),
        ) or []
        if isinstance(rules, list):
            rule_group = [rule for rule in rules if isinstance(rule, Mapping)]
            if rule_group:
                # Azure returns NIC and subnet associations independently.  A
                # packet must pass every associated NSG, so groups stay apart.
                index.setdefault(nic_id, []).append(rule_group)
    return index


def route_index(records: Iterable[Mapping[str, Any]]) -> Dict[str, List[Mapping[str, Any]]]:
    index: Dict[str, List[Mapping[str, Any]]] = {}
    for nic_id, record in parameterised_records(records):
        if nic_id:
            index.setdefault(nic_id, []).append(record)
    return index


def nic_ip_configuration_index(
    nics: Iterable[Mapping[str, Any]],
) -> Tuple[
    Dict[str, Tuple[Mapping[str, Any], Mapping[str, Any]]],
    Dict[str, List[Tuple[Mapping[str, Any], Mapping[str, Any]]]],
]:
    by_id = {}
    pool_backends: Dict[
        str, List[Tuple[Mapping[str, Any], Mapping[str, Any]]]
    ] = {}
    for nic in nics:
        configurations = nested_value(nic, "ipConfigurations", ("properties", "ipConfigurations")) or []
        for configuration in configurations:
            configuration_id = canonical_arm_id(configuration.get("id"))
            if configuration_id:
                by_id[configuration_id] = (nic, configuration)
            for pool in nested_value(
                configuration,
                "loadBalancerBackendAddressPools",
                ("properties", "loadBalancerBackendAddressPools"),
                "applicationGatewayBackendAddressPools",
                ("properties", "applicationGatewayBackendAddressPools"),
            ) or []:
                pool_id = canonical_arm_id(pool.get("id")) if isinstance(pool, Mapping) else ""
                if pool_id:
                    pool_backends.setdefault(pool_id, []).append((nic, configuration))
    return by_id, pool_backends


def decision_for_nic(
    nic: Mapping[str, Any],
    protocol: str,
    port: int,
    nsgs_by_id: Mapping[str, Mapping[str, Any]],
    effective_by_nic: Mapping[str, List[List[Mapping[str, Any]]]],
    destination_ip: Any = None,
    source_version: Optional[int] = None,
) -> Dict[str, Any]:
    rule_groups = effective_by_nic.get(canonical_arm_id(nic.get("id")))
    if rule_groups:
        group_decisions = [
            nsg_decision(
                rules, protocol, port, destination_ip, source_version
            )
            for rules in rule_groups
        ]
        denied = next(
            (item for item in group_decisions if item["decision"] == "deny"),
            None,
        )
        unknown = next(
            (item for item in group_decisions if item["decision"] != "allow"),
            None,
        )
        decision = dict(denied or unknown or group_decisions[0])
        if denied:
            decision["decision"] = "deny"
        elif unknown:
            decision["decision"] = "unknown"
        else:
            allowed = group_decisions[0]["allowed_source_space"]
            for group_decision in group_decisions[1:]:
                allowed = allowed.intersection(
                    group_decision["allowed_source_space"]
                )
            decision["allowed_source_space"] = allowed
            decision["decision"] = (
                "allow" if allowed.has_external_address() else "deny"
            )
            decision["allowedSourceScope"] = external_source_scope(allowed)
            decision["excludedSourcePrefixes"] = sorted(
                {
                    prefix
                    for item in group_decisions
                    for prefix in item.get("excludedSourcePrefixes", [])
                }
            )
            decision["limitations"] = list(
                dict.fromkeys(
                    limitation
                    for item in group_decisions
                    for limitation in item.get("limitations", [])
                )
            )
        decision["source"] = "effective_nsg"
        return decision

    attached, rules = nic_nsg_rules(nic, nsgs_by_id)
    decision = nsg_decision(
        rules, protocol, port, destination_ip, source_version
    ) if rules is not None else {
        "decision": "unknown",
        "rule": None,
        "allowed_source_space": ExternalSourceSpace.empty(),
        "limitations": (
            ["Attached NIC NSG data was unavailable"]
            if attached
            else ["No effective or attached NIC NSG could be evaluated"]
        ),
    }
    decision["source"] = "raw_nsg" if rules is not None else "unavailable"
    return decision


def allowed_nic_segments(
    nic: Mapping[str, Any],
    nsgs_by_id: Mapping[str, Mapping[str, Any]],
    effective_by_nic: Mapping[str, List[List[Mapping[str, Any]]]],
    destination_ip: Any = None,
    source_version: Optional[int] = None,
    limitations: Optional[List[str]] = None,
) -> List[Tuple[str, int, int, Dict[str, Any]]]:
    """Return exact allowed intervals after every relevant NSG boundary."""
    effective_groups = effective_by_nic.get(canonical_arm_id(nic.get("id")))
    if effective_groups:
        rules = [rule for group in effective_groups for rule in group]
    else:
        attached, raw_rules = nic_nsg_rules(nic, nsgs_by_id)
        if raw_rules is None:
            if limitations is not None:
                limitations.append(
                    "Attached NIC NSG data was unavailable"
                    if attached
                    else "No effective or attached NIC NSG could be evaluated"
                )
            return []
        rules = raw_rules or []
    protocols = set()
    for rule in rules:
        protocol = normalise_identifier(
            nested_value(rule, "protocol", ("properties", "protocol"))
        )
        protocols.update(("tcp", "udp") if protocol in {"*", "any"} else (protocol,))

    segments = []
    for protocol in sorted(item for item in protocols if item):
        boundaries = set()
        for rule in rules:
            rule_protocol = normalise_identifier(
                nested_value(rule, "protocol", ("properties", "protocol"))
            )
            if rule_protocol not in {"*", "any", protocol}:
                continue
            for start, end in port_intervals(rule):
                boundaries.add(max(1, start))
                boundaries.add(min(65536, end + 1))
        ordered = sorted(boundaries)
        for start, next_boundary in zip(ordered, ordered[1:]):
            end = next_boundary - 1
            if start > end:
                continue
            decision = decision_for_nic(
                nic,
                protocol,
                start,
                nsgs_by_id,
                effective_by_nic,
                destination_ip,
                source_version,
            )
            if limitations is not None:
                limitations.extend(decision.get("limitations", []))
            if decision["decision"] == "allow":
                segments.append((protocol, start, end, decision))
    return segments


def direct_nic_paths(
    public_ips: Iterable[Mapping[str, Any]],
    nics: Iterable[Mapping[str, Any]],
    nsgs: Iterable[Mapping[str, Any]],
    effective_nsgs: Iterable[Mapping[str, Any]] = (),
    effective_routes: Iterable[Mapping[str, Any]] = (),
    limitations: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Build direct public-IP to NIC paths with effective raw-NSG decisions."""
    ips = public_ip_index(public_ips)
    nsgs_by_id = nsg_index(nsgs)
    effective_by_nic = effective_rules_index(effective_nsgs)
    routes_by_nic = route_index(effective_routes)
    paths = []
    for nic in nics:
        configurations = nested_value(nic, "ipConfigurations", ("properties", "ipConfigurations")) or []
        for configuration in configurations:
            public_ip_id = canonical_arm_id(
                nested_value(
                    configuration,
                    ("publicIPAddress", "id"),
                    ("properties", "publicIPAddress", "id"),
                )
            )
            public_ip = ips.get(public_ip_id)
            if not public_ip:
                continue
            public_ip_address = nested_value(
                public_ip, "ipAddress", ("properties", "ipAddress")
            )
            backend_private_ip = nested_value(
                configuration,
                "privateIPAddress",
                ("properties", "privateIPAddress"),
            )
            for protocol, start_port, end_port, decision in allowed_nic_segments(
                nic,
                nsgs_by_id,
                effective_by_nic,
                backend_private_ip,
                address_version(public_ip_address),
                limitations,
            ):
                selected_rule = decision["rule"] or {}
                paths.append(
                    {
                        "id": nic.get("id"),
                        "publicIpId": public_ip.get("id"),
                        "publicIpAddress": public_ip_address,
                        "frontendType": "nic",
                        "frontendResourceId": nic.get("id"),
                        "protocol": normalise_identifier(
                            nested_value(selected_rule, "protocol", ("properties", "protocol"))
                        )
                        or protocol,
                        "frontendPort": (
                            start_port if start_port == end_port else f"{start_port}-{end_port}"
                        ),
                        "frontendPortRange": [start_port, end_port],
                        "backendResourceId": nested_value(
                            nic,
                            ("virtualMachine", "id"),
                            ("properties", "virtualMachine", "id"),
                        ),
                        "networkInterfaceId": nic.get("id"),
                        "backendIpConfigurationId": configuration.get("id"),
                        "backendPrivateIpAddress": backend_private_ip,
                        "effectiveNsgRule": selected_rule.get("name"),
                        "effectiveNsgPriority": nested_value(
                            selected_rule, "priority", ("properties", "priority")
                        ),
                        "nsgEvidenceSource": decision.get("source"),
                        "allowedSourceScope": decision.get("allowedSourceScope"),
                        "excludedSourcePrefixes": decision.get(
                            "excludedSourcePrefixes", []
                        ),
                        "effectiveRoutes": [
                            {
                                "addressPrefix": nested_value(
                                    route, "addressPrefix", ("properties", "addressPrefix")
                                ),
                                "nextHopType": nested_value(
                                    route, "nextHopType", ("properties", "nextHopType")
                                ),
                                "state": nested_value(route, "state", ("properties", "state")),
                            }
                            for route in routes_by_nic.get(canonical_arm_id(nic.get("id")), [])
                        ],
                        "pathConfidence": (
                            "confirmed"
                            if decision.get("source") == "effective_nsg"
                            else "probable"
                        ),
                    }
                )
    return paths


def load_balancer_paths(
    public_ips: Iterable[Mapping[str, Any]],
    nics: Iterable[Mapping[str, Any]],
    nsgs: Iterable[Mapping[str, Any]],
    load_balancers: Iterable[Mapping[str, Any]],
    effective_nsgs: Iterable[Mapping[str, Any]] = (),
    effective_routes: Iterable[Mapping[str, Any]] = (),
    limitations: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    ips = public_ip_index(public_ips)
    nics = list(nics)
    ip_configurations, pool_backends = nic_ip_configuration_index(nics)
    nsgs_by_id = nsg_index(nsgs)
    effective_by_nic = effective_rules_index(effective_nsgs)
    routes_by_nic = route_index(effective_routes)
    paths = []
    for balancer in load_balancers:
        frontends = {
            canonical_arm_id(item.get("id")): item
            for item in nested_value(
                balancer, "frontendIPConfigurations", ("properties", "frontendIPConfigurations")
            ) or []
        }
        rules = list(
            nested_value(balancer, "loadBalancingRules", ("properties", "loadBalancingRules"))
            or []
        ) + list(
            nested_value(balancer, "inboundNatRules", ("properties", "inboundNatRules"))
            or []
        )
        for rule in rules:
            frontend_id = canonical_arm_id(
                nested_value(
                    rule,
                    ("frontendIPConfiguration", "id"),
                    ("properties", "frontendIPConfiguration", "id"),
                )
            )
            frontend = frontends.get(frontend_id, {})
            public_ip_id = canonical_arm_id(
                nested_value(
                    frontend,
                    ("publicIPAddress", "id"),
                    ("properties", "publicIPAddress", "id"),
                )
            )
            public_ip = ips.get(public_ip_id)
            if not public_ip:
                continue
            public_ip_address = nested_value(
                public_ip, "ipAddress", ("properties", "ipAddress")
            )
            frontend_port = nested_value(rule, "frontendPort", ("properties", "frontendPort"))
            try:
                port = int(frontend_port)
            except (TypeError, ValueError):
                continue
            backend_port = nested_value(rule, "backendPort", ("properties", "backendPort"))
            try:
                backend_port = int(backend_port)
            except (TypeError, ValueError):
                backend_port = port
            protocol = normalise_identifier(
                nested_value(rule, "protocol", ("properties", "protocol"))
            ) or "tcp"
            pool_id = canonical_arm_id(
                nested_value(
                    rule,
                    ("backendAddressPool", "id"),
                    ("properties", "backendAddressPool", "id"),
                )
            )
            backends = list(pool_backends.get(pool_id, []))
            backend_configuration_id = canonical_arm_id(
                nested_value(
                    rule,
                    ("backendIPConfiguration", "id"),
                    ("properties", "backendIPConfiguration", "id"),
                )
            )
            direct_backend = ip_configurations.get(backend_configuration_id)
            if direct_backend:
                backends.append(direct_backend)
            backends = list(
                {
                    (
                        canonical_arm_id(nic.get("id")),
                        canonical_arm_id(configuration.get("id")),
                    ): (nic, configuration)
                    for nic, configuration in backends
                    if canonical_arm_id(nic.get("id"))
                }.values()
            )
            for nic, configuration in backends:
                backend_private_ip = nested_value(
                    configuration,
                    "privateIPAddress",
                    ("properties", "privateIPAddress"),
                )
                decision = decision_for_nic(
                    nic,
                    protocol,
                    backend_port,
                    nsgs_by_id,
                    effective_by_nic,
                    backend_private_ip,
                    address_version(public_ip_address),
                )
                if limitations is not None:
                    limitations.extend(decision.get("limitations", []))
                if decision["decision"] != "allow":
                    continue
                selected_rule = decision.get("rule") or {}
                paths.append(
                    {
                        "id": balancer.get("id"),
                        "publicIpId": public_ip.get("id"),
                        "publicIpAddress": public_ip_address,
                        "frontendType": "load_balancer",
                        "frontendResourceId": balancer.get("id"),
                        "forwardingRuleId": rule.get("id") or rule.get("name"),
                        "protocol": protocol,
                        "frontendPort": port,
                        "backendPort": backend_port,
                        "backendPoolId": pool_id,
                        "backendResourceId": nested_value(
                            nic,
                            ("virtualMachine", "id"),
                            ("properties", "virtualMachine", "id"),
                        ),
                        "networkInterfaceId": nic.get("id"),
                        "backendIpConfigurationId": configuration.get("id"),
                        "backendPrivateIpAddress": backend_private_ip,
                        "effectiveNsgDecision": decision["decision"],
                        "effectiveNsgRule": selected_rule.get("name"),
                        "nsgEvidenceSource": decision.get("source"),
                        "allowedSourceScope": decision.get("allowedSourceScope"),
                        "excludedSourcePrefixes": decision.get(
                            "excludedSourcePrefixes", []
                        ),
                        "effectiveRoutes": [
                            {
                                "addressPrefix": nested_value(
                                    route,
                                    "addressPrefix",
                                    ("properties", "addressPrefix"),
                                ),
                                "nextHopType": nested_value(
                                    route,
                                    "nextHopType",
                                    ("properties", "nextHopType"),
                                ),
                                "state": nested_value(
                                    route, "state", ("properties", "state")
                                ),
                            }
                            for route in routes_by_nic.get(
                                canonical_arm_id(nic.get("id")), []
                            )
                        ],
                        "pathConfidence": (
                            "confirmed"
                            if decision["decision"] == "allow"
                            and decision.get("source") == "effective_nsg"
                            else "probable"
                        ),
                    }
                )
    return paths


def application_gateway_paths(
    public_ips: Iterable[Mapping[str, Any]],
    gateways: Iterable[Mapping[str, Any]],
    nics: Iterable[Mapping[str, Any]] = (),
    effective_routes: Iterable[Mapping[str, Any]] = (),
) -> List[Dict[str, Any]]:
    ips = public_ip_index(public_ips)
    ip_configurations_by_id, _ = nic_ip_configuration_index(nics)
    routes_by_nic = route_index(effective_routes)
    paths = []
    for gateway in gateways:
        frontends = {
            canonical_arm_id(item.get("id")): item
            for item in nested_value(
                gateway, "frontendIPConfigurations", ("properties", "frontendIPConfigurations")
            ) or []
        }
        frontend_ports = {
            canonical_arm_id(item.get("id")): nested_value(
                item, "port", ("properties", "port")
            )
            for item in nested_value(
                gateway, "frontendPorts", ("properties", "frontendPorts")
            ) or []
        }
        listeners = {
            canonical_arm_id(item.get("id")): item
            for item in nested_value(
                gateway, "httpListeners", ("properties", "httpListeners")
            ) or []
        }
        pools = {
            canonical_arm_id(item.get("id")): item
            for item in nested_value(
                gateway, "backendAddressPools", ("properties", "backendAddressPools")
            ) or []
        }
        backend_settings = {
            canonical_arm_id(item.get("id")): item
            for item in nested_value(
                gateway,
                "backendHttpSettingsCollection",
                ("properties", "backendHttpSettingsCollection"),
            ) or []
        }
        rules = nested_value(
            gateway, "requestRoutingRules", ("properties", "requestRoutingRules")
        ) or []
        for rule in rules:
            listener_id = canonical_arm_id(
                nested_value(
                    rule,
                    ("httpListener", "id"),
                    ("properties", "httpListener", "id"),
                )
            )
            listener = listeners.get(listener_id, {})
            frontend_id = canonical_arm_id(
                nested_value(
                    listener,
                    ("frontendIPConfiguration", "id"),
                    ("properties", "frontendIPConfiguration", "id"),
                )
            )
            frontend = frontends.get(frontend_id, {})
            public_ip_id = canonical_arm_id(
                nested_value(
                    frontend,
                    ("publicIPAddress", "id"),
                    ("properties", "publicIPAddress", "id"),
                )
            )
            public_ip = ips.get(public_ip_id)
            if not public_ip:
                continue
            port_id = canonical_arm_id(
                nested_value(
                    listener,
                    ("frontendPort", "id"),
                    ("properties", "frontendPort", "id"),
                )
            )
            pool_id = canonical_arm_id(
                nested_value(
                    rule,
                    ("backendAddressPool", "id"),
                    ("properties", "backendAddressPool", "id"),
                )
            )
            pool = pools.get(pool_id, {})
            settings_id = canonical_arm_id(
                nested_value(
                    rule,
                    ("backendHttpSettings", "id"),
                    ("properties", "backendHttpSettings", "id"),
                )
            )
            settings = backend_settings.get(settings_id, {})
            addresses = nested_value(
                pool, "backendAddresses", ("properties", "backendAddresses")
            ) or []
            ip_configurations = nested_value(
                pool, "backendIPConfigurations", ("properties", "backendIPConfigurations")
            ) or []
            if not addresses and not ip_configurations:
                continue
            path = {
                "id": gateway.get("id"),
                "publicIpId": public_ip.get("id"),
                "publicIpAddress": nested_value(
                    public_ip, "ipAddress", ("properties", "ipAddress")
                ),
                "frontendType": "application_gateway",
                "frontendResourceId": gateway.get("id"),
                "listenerId": listener.get("id") or listener.get("name"),
                "forwardingRuleId": rule.get("id") or rule.get("name"),
                "protocol": normalise_identifier(
                    nested_value(listener, "protocol", ("properties", "protocol"))
                ),
                "frontendPort": frontend_ports.get(port_id),
                "backendPort": nested_value(
                    settings, "port", ("properties", "port")
                ),
                "backendPoolId": pool_id,
                "backendAddresses": [
                    item.get("ipAddress") or item.get("fqdn")
                    for item in addresses
                    if isinstance(item, Mapping)
                ],
                "backendIpConfigurationIds": [
                    item.get("id")
                    for item in ip_configurations
                    if isinstance(item, Mapping)
                ],
                "pathConfidence": "probable",
            }
            resolved_nics = {
                canonical_arm_id(match[0].get("id")): match[0]
                for item in ip_configurations
                if isinstance(item, Mapping)
                for match in [
                    ip_configurations_by_id.get(canonical_arm_id(item.get("id")))
                ]
                if match and canonical_arm_id(match[0].get("id"))
            }
            if not resolved_nics:
                paths.append(path)
                continue
            for nic_id, nic in sorted(resolved_nics.items()):
                resolved_path = dict(path)
                resolved_path.update(
                    {
                        "networkInterfaceId": nic.get("id"),
                        "backendResourceId": nested_value(
                            nic,
                            ("virtualMachine", "id"),
                            ("properties", "virtualMachine", "id"),
                        ),
                        "effectiveRoutes": [
                            {
                                "addressPrefix": nested_value(
                                    route,
                                    "addressPrefix",
                                    ("properties", "addressPrefix"),
                                ),
                                "nextHopType": nested_value(
                                    route,
                                    "nextHopType",
                                    ("properties", "nextHopType"),
                                ),
                                "state": nested_value(
                                    route, "state", ("properties", "state")
                                ),
                            }
                            for route in routes_by_nic.get(nic_id, [])
                        ],
                    }
                )
                paths.append(resolved_path)
    return paths


def analyse_external_attack_paths(
    public_ips: Iterable[Mapping[str, Any]],
    nics: Iterable[Mapping[str, Any]],
    nsgs: Iterable[Mapping[str, Any]],
    conclusion_support: str,
    source_files: Iterable[str] = (),
    effective_nsgs: Iterable[Mapping[str, Any]] = (),
    effective_routes: Iterable[Mapping[str, Any]] = (),
    load_balancers: Iterable[Mapping[str, Any]] = (),
    application_gateways: Iterable[Mapping[str, Any]] = (),
) -> CorrelationResult:
    """Surface direct, load-balancer, and Application Gateway ingress paths."""
    public_ips = list(public_ips)
    nics = list(nics)
    nsgs = list(nsgs)
    effective_nsgs = list(effective_nsgs)
    limitations = []
    paths = direct_nic_paths(
        public_ips,
        nics,
        nsgs,
        effective_nsgs,
        effective_routes,
        limitations,
    )
    paths.extend(
        load_balancer_paths(
            public_ips,
            nics,
            nsgs,
            load_balancers,
            effective_nsgs,
            effective_routes,
            limitations,
        )
    )
    paths.extend(
        application_gateway_paths(
            public_ips, application_gateways, nics, effective_routes
        )
    )
    deduplicated = {}
    for path in paths:
        key = (
            canonical_arm_id(path.get("publicIpId")),
            canonical_arm_id(path.get("frontendResourceId")),
            normalise_identifier(path.get("forwardingRuleId") or path.get("listenerId")),
            normalise_identifier(path.get("protocol")),
            str(path.get("frontendPort")),
            canonical_arm_id(path.get("networkInterfaceId") or path.get("backendResourceId")),
        )
        deduplicated[key] = path
    eligible = [
        {"id": item.get("id"), "ipAddress": nested_value(item, "ipAddress", ("properties", "ipAddress"))}
        for item in public_ips
        if nested_value(item, "ipAddress", ("properties", "ipAddress"))
    ]
    limitations = list(dict.fromkeys(limitations))
    if limitations and conclusion_support == "positive_and_negative":
        conclusion_support = "positive_only" if deduplicated else "inconclusive"
    return CorrelationResult(
        observations=[deduplicated[key] for key in sorted(deduplicated)],
        eligible_assets=eligible,
        source_files=sorted(set(source_files)),
        limitations=limitations,
        conclusion_support=conclusion_support,
    )
