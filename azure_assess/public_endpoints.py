#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Normalise Azure public endpoint addresses and their configured relationships."""

from __future__ import annotations

import ipaddress
import re
import subprocess
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from .findings_correlation import CorrelationResult, canonical_arm_id, normalise_identifier


TOPOLOGY_SCHEMA_VERSION = "1.0"


def _nested(record: Mapping[str, Any], *paths: Sequence[str] | str) -> Any:
    for path in paths:
        parts = path.split(".") if isinstance(path, str) else path
        value: Any = record
        for part in parts:
            if not isinstance(value, Mapping):
                value = None
                break
            value = value.get(part)
        if value is not None:
            return value
    return None


def _items(value: Any) -> List[Mapping[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _split_addresses(value: Any) -> List[str]:
    if isinstance(value, list):
        candidates = value
    elif isinstance(value, str):
        candidates = re.split(r"[,;\s]+", value)
    else:
        candidates = []
    return list(dict.fromkeys(str(item).strip() for item in candidates if str(item).strip()))


def _public_ip(value: Any) -> Optional[str]:
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    return str(address) if address.is_global else None


def _hostname(value: Any) -> Optional[str]:
    text = str(value or "").strip()
    if not text:
        return None
    parsed = urllib.parse.urlparse(text if "://" in text else f"//{text}")
    hostname = parsed.hostname
    if not hostname or "." not in hostname or len(hostname) > 253:
        return None
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        return None
    return hostname.rstrip(".").casefold()


def _resource_parent(child_id: Any) -> str:
    resource_id = canonical_arm_id(child_id)
    markers = (
        "/ipconfigurations/",
        "/frontendipconfigurations/",
        "/instances/",
    )
    for marker in markers:
        if marker in resource_id:
            return resource_id.split(marker, 1)[0]
    return resource_id


def _resource_type(resource_id: Any) -> str:
    parts = canonical_arm_id(resource_id).strip("/").split("/")
    try:
        provider_index = parts.index("providers")
    except ValueError:
        return ""
    provider_parts = parts[provider_index + 1 :]
    if len(provider_parts) < 2:
        return ""
    return "/".join(provider_parts[:2])


def _reference_ids(record: Mapping[str, Any], *paths: Sequence[str] | str) -> List[str]:
    result: List[str] = []
    for path in paths:
        value = _nested(record, path)
        values = value if isinstance(value, list) else [value]
        for item in values:
            identifier = item.get("id") if isinstance(item, Mapping) else item
            canonical = canonical_arm_id(identifier)
            if canonical:
                result.append(canonical)
    return list(dict.fromkeys(result))


def _context(record: Mapping[str, Any]) -> Mapping[str, Any]:
    value = record.get("_collectionContext")
    return value if isinstance(value, Mapping) else {}


def _source_ids(record: Mapping[str, Any], *defaults: str) -> Tuple[str, ...]:
    source = str(record.get("_topologySourceEndpointId") or "").strip()
    return (source,) if source else tuple(item for item in defaults if item)


def _walk_mappings(value: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        yield value
        for child in value.values():
            yield from _walk_mappings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_mappings(child)


def _endpoint_strings(value: Any) -> Iterable[str]:
    """Yield hostname-like strings from a declared endpoint property."""

    if isinstance(value, str):
        if _hostname(value):
            yield value
    elif isinstance(value, Mapping):
        for child in value.values():
            yield from _endpoint_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _endpoint_strings(child)


def _owner_id(record: Mapping[str, Any]) -> str:
    identifier = canonical_arm_id(record.get("id"))
    if identifier:
        return identifier
    parameters = _context(record).get("parameters")
    if isinstance(parameters, Mapping):
        resource_group = parameters.get("resourceGroup") or parameters.get("resource_group")
        name = parameters.get("name")
        if resource_group and name:
            return f"resource-group:{str(resource_group).casefold()}/{str(name).casefold()}"
        if name:
            endpoint = str(_context(record).get("endpoint") or "resource")
            return f"collected:{endpoint.casefold()}:{str(name).casefold()}"
    return ""


def build_public_endpoint_topology(
    datasets: Mapping[str, Iterable[Mapping[str, Any]]],
    collected_at: Optional[str] = None,
    dns_resolver: Optional[Callable[[str], Iterable[str]]] = None,
    dns_diagnostics: Optional[List[Dict[str, Any]]] = None,
    dns_progress: Optional[Callable[[str, Mapping[str, Any]], None]] = None,
) -> List[Dict[str, Any]]:
    """Return one deterministic record per configured public address relationship.

    DNS resolution is opt-in. A resolved address is a point-in-time observation,
    never proof that a shared platform address belongs exclusively to the tenant.
    """

    timestamp = collected_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    records: Dict[Tuple[str, ...], Dict[str, Any]] = {}
    fqdns: List[Tuple[str, str, str, str, List[str], List[int], List[str]]] = []

    def add(
        *,
        address: Optional[str] = None,
        address_prefix: Optional[str] = None,
        fqdn: Optional[str] = None,
        direction: str,
        owner_id: Any,
        attachment_id: Any = None,
        connected_ids: Iterable[Any] = (),
        association: str,
        confidence: str = "configured",
        source_ids: Iterable[str] = (),
        ports: Iterable[Any] = (),
        protocols: Iterable[Any] = (),
        address_origin: str = "control_plane",
        access_state: str = "unknown",
        relationship_id: Any = None,
        relationship_type: Optional[str] = None,
        connection_path: Iterable[Any] = (),
        public_ip_resource_id: Any = None,
    ) -> None:
        public_address = _public_ip(address) if address else None
        public_prefix = None
        if address_prefix:
            try:
                network = ipaddress.ip_network(str(address_prefix).strip(), strict=False)
                public_prefix = str(network) if network.network_address.is_global else None
            except ValueError:
                public_prefix = None
        hostname = _hostname(fqdn)
        if address and not public_address:
            return
        if not public_address and not public_prefix and not hostname:
            return
        owner_text = str(owner_id or "").strip()
        owner = (
            canonical_arm_id(owner_text)
            if owner_text.startswith("/")
            else owner_text.casefold()
        )
        attachment_text = str(attachment_id or "").strip()
        attachment = (
            canonical_arm_id(attachment_text)
            if attachment_text.startswith("/")
            else attachment_text.casefold()
        )
        connected_resources = sorted(
            {
                canonical_arm_id(item)
                for item in connected_ids
                if str(item or "").strip().startswith("/")
                and canonical_arm_id(item)
            }
        )
        connected_targets = sorted(
            {
                str(item).strip().casefold()
                for item in connected_ids
                if item and not str(item).strip().startswith("/")
            }
        )
        port_values = sorted({int(item) for item in ports if str(item).isdigit()})
        protocol_values = sorted({normalise_identifier(item) for item in protocols if item})
        relationship = canonical_arm_id(relationship_id)
        public_ip_resource = canonical_arm_id(public_ip_resource_id)
        path_values = [
            canonical_arm_id(item) if str(item or "").strip().startswith("/") else str(item).strip().casefold()
            for item in connection_path
            if str(item or "").strip()
        ]
        key = (
            public_address or "",
            public_prefix or "",
            hostname or "",
            direction,
            owner,
            attachment,
            association,
            ",".join(connected_resources),
            ",".join(connected_targets),
            ",".join(str(item) for item in port_values),
            ",".join(protocol_values),
            relationship,
            normalise_identifier(relationship_type),
            ",".join(path_values),
            address_origin,
            access_state,
            public_ip_resource,
        )
        source_endpoint_ids = sorted(set(source_ids))
        existing = records.get(key)
        if existing:
            source_endpoint_ids = sorted(set(
                source_endpoint_ids + list(existing.get("sourceEndpointIds") or [])
            ))
        records[key] = {
            "schemaVersion": TOPOLOGY_SCHEMA_VERSION,
            "address": public_address,
            "addressPrefix": public_prefix,
            "addressFamily": (
                f"IPv{ipaddress.ip_address(public_address).version}"
                if public_address
                else f"IPv{ipaddress.ip_network(public_prefix).version}"
                if public_prefix
                else None
            ),
            "fqdn": hostname,
            "direction": direction,
            "ownerResourceId": owner or None,
            "ownerResourceType": _resource_type(owner) or None,
            "publicIpResourceId": public_ip_resource or None,
            "attachmentResourceId": attachment or None,
            "connectedResourceIds": connected_resources,
            "connectedTargets": connected_targets,
            "candidateConnectedResourceIds": [],
            "associationType": association,
            "confidence": confidence,
            "addressOrigin": address_origin,
            "accessState": access_state,
            "ports": port_values,
            "protocols": protocol_values,
            "relationshipId": relationship or None,
            "relationshipType": normalise_identifier(relationship_type) or None,
            "connectionPath": path_values,
            "sourceEndpointIds": source_endpoint_ids,
            "_collectionContext": {
                "derived": True,
                "generatedAt": timestamp,
                "pointInTimeDns": address_origin == "dns_snapshot",
            },
        }
        if hostname and not public_address:
            fqdns.append(
                (
                    hostname,
                    owner,
                    direction,
                    association,
                    connected_resources + connected_targets,
                    port_values,
                    source_endpoint_ids,
                )
            )

    public_ips = list(datasets.get("public_ips", ()))
    nics = list(datasets.get("nics", ()))
    load_balancers = list(datasets.get("load_balancers", ()))
    application_gateways = list(datasets.get("application_gateways", ()))

    for record_set in datasets.get("public_dns_records", ()):
        context = _context(record_set).get("parameters") or {}
        zone_name = str(context.get("name") or "").strip().rstrip(".")
        relative_name = str(record_set.get("name") or "").strip().rstrip(".")
        fqdn = _nested(record_set, "fqdn", "properties.fqdn")
        if not fqdn and zone_name:
            fqdn = zone_name if relative_name in {"", "@"} else f"{relative_name}.{zone_name}"
        targets = _reference_ids(
            record_set,
            "targetResource",
            "properties.targetResource",
        )
        cname = _nested(
            record_set,
            "cnameRecord.cname",
            "properties.CNAMERecord.cname",
            "properties.cnameRecord.cname",
        )
        if cname:
            targets.append(str(cname))
        addresses = [
            value
            for field, key in (("aRecords", "ipv4Address"), ("aaaaRecords", "ipv6Address"))
            for item in _items(_nested(record_set, field, f"properties.{field}"))
            for value in (item.get(key),)
            if value
        ]
        if not addresses and not cname and not targets:
            continue
        if addresses:
            for address in addresses:
                add(
                    address=address,
                    fqdn=fqdn,
                    direction="inbound",
                    owner_id=_owner_id(record_set),
                    connected_ids=targets,
                    association="public_dns_record",
                    source_ids=_source_ids(
                        record_set,
                        "az_network_dns_record-set_list_--zone-name_name_--resource-group_resourcegroup",
                    ),
                    relationship_id=record_set.get("id"),
                    relationship_type="dns_address_record",
                )
        elif fqdn:
            add(
                fqdn=fqdn,
                direction="inbound",
                owner_id=_owner_id(record_set),
                connected_ids=targets,
                association="public_dns_record",
                source_ids=_source_ids(
                    record_set,
                    "az_network_dns_record-set_list_--zone-name_name_--resource-group_resourcegroup",
                ),
                relationship_id=record_set.get("id"),
                relationship_type="dns_alias_record",
            )

    reverse_attachments: Dict[str, List[Dict[str, Any]]] = {}
    nic_ip_connections: Dict[str, List[str]] = {}

    def register_reverse_attachment(public_id: str, **relationship: Any) -> None:
        if public_id:
            reverse_attachments.setdefault(public_id, []).append(relationship)

    for nic in nics:
        owner = _owner_id(nic)
        connected = _reference_ids(nic, "virtualMachine", "properties.virtualMachine")
        for config in _items(_nested(nic, "ipConfigurations", "properties.ipConfigurations")):
            config_id = canonical_arm_id(config.get("id"))
            if config_id:
                nic_ip_connections[config_id] = list(
                    dict.fromkeys([owner] + connected)
                )
            for public_id in _reference_ids(config, "publicIPAddress", "properties.publicIPAddress"):
                register_reverse_attachment(
                    public_id,
                    owner=owner,
                    association="nic",
                    connected=connected,
                    ports=[],
                    protocols=[],
                    sources=_source_ids(nic, "az_network_nic_list"),
                    attachment_id=config.get("id"),
                    relationship_id=config.get("id"),
                    relationship_type="ip_configuration",
                    connection_path=(owner, config.get("id"), *connected),
                    direction="both",
                )

    for balancer in load_balancers:
        owner = _owner_id(balancer)
        frontends = {
            canonical_arm_id(item.get("id")): item
            for item in _items(_nested(balancer, "frontendIPConfigurations", "properties.frontendIPConfigurations"))
        }
        pool_targets: Dict[str, List[str]] = {}
        for pool in _items(_nested(balancer, "backendAddressPools", "properties.backendAddressPools")):
            pool_id = canonical_arm_id(pool.get("id"))
            targets = _reference_ids(
                pool,
                "backendIPConfigurations",
                "properties.backendIPConfigurations",
            )
            for backend in _items(
                _nested(pool, "loadBalancerBackendAddresses", "properties.loadBalancerBackendAddresses")
            ):
                targets += _reference_ids(
                    backend,
                    "networkInterfaceIPConfiguration",
                    "properties.networkInterfaceIPConfiguration",
                )
                target = _nested(backend, "ipAddress", "properties.ipAddress")
                if target:
                    targets.append(str(target))
            for target in list(targets):
                targets += nic_ip_connections.get(canonical_arm_id(target), [])
            if pool_id:
                pool_targets[pool_id] = list(dict.fromkeys(targets))
        rules = [
            (item, "load_balancing_rule", "inbound")
            for item in _items(_nested(balancer, "loadBalancingRules", "properties.loadBalancingRules"))
        ]
        rules += [
            (item, "inbound_nat_rule", "inbound")
            for item in _items(_nested(balancer, "inboundNatRules", "properties.inboundNatRules"))
        ]
        rules += [
            (item, "inbound_nat_pool", "inbound")
            for item in _items(_nested(balancer, "inboundNatPools", "properties.inboundNatPools"))
        ]
        rules += [
            (item, "outbound_rule", "outbound")
            for item in _items(_nested(balancer, "outboundRules", "properties.outboundRules"))
        ]
        for frontend_id, frontend in frontends.items():
            public_ids = _reference_ids(
                frontend, "publicIPAddress", "properties.publicIPAddress"
            )
            matched = False
            for rule, relationship_type, direction in rules:
                if frontend_id not in _reference_ids(rule, "frontendIPConfiguration", "properties.frontendIPConfiguration"):
                    continue
                matched = True
                pool_ids = _reference_ids(
                    rule, "backendAddressPool", "properties.backendAddressPool"
                )
                connected = list(pool_ids)
                for pool_id in pool_ids:
                    connected += pool_targets.get(pool_id, [])
                connected += _reference_ids(
                    rule,
                    "backendIPConfiguration",
                    "properties.backendIPConfiguration",
                )
                port = _nested(rule, "frontendPort", "properties.frontendPort")
                protocol = _nested(rule, "protocol", "properties.protocol")
                rule_id = rule.get("id")
                for public_id in public_ids:
                    register_reverse_attachment(
                        public_id,
                        owner=owner,
                        association="load_balancer",
                        connected=connected,
                        ports=[port] if str(port).isdigit() else [],
                        protocols=[protocol] if protocol else [],
                        sources=_source_ids(balancer, "az_network_lb_list"),
                        attachment_id=frontend_id,
                        relationship_id=rule_id,
                        relationship_type=relationship_type,
                        connection_path=(frontend_id, rule_id, *pool_ids, *connected),
                        direction=direction,
                    )
            if not matched:
                for public_id in public_ids:
                    register_reverse_attachment(
                        public_id,
                        owner=owner,
                        association="load_balancer",
                        connected=[],
                        ports=[],
                        protocols=[],
                        sources=_source_ids(balancer, "az_network_lb_list"),
                        attachment_id=frontend_id,
                        relationship_id=frontend_id,
                        relationship_type="frontend",
                        connection_path=(frontend_id,),
                        direction="inbound",
                    )

    for gateway in application_gateways:
        owner = _owner_id(gateway)
        frontends = _items(_nested(gateway, "frontendIPConfigurations", "properties.frontendIPConfigurations"))
        pools = _items(_nested(gateway, "backendAddressPools", "properties.backendAddressPools"))
        pool_targets = {}
        for pool in pools:
            pool_id = canonical_arm_id(pool.get("id"))
            targets = _reference_ids(
                pool, "backendIPConfigurations", "properties.backendIPConfigurations"
            )
            targets += [
                str(value)
                for item in _items(_nested(pool, "backendAddresses", "properties.backendAddresses"))
                for value in (item.get("ipAddress"), item.get("fqdn"))
                if value
            ]
            for target in list(targets):
                targets += nic_ip_connections.get(canonical_arm_id(target), [])
            if pool_id:
                pool_targets[pool_id] = list(dict.fromkeys(targets))
        frontend_public_ids = {
            canonical_arm_id(frontend.get("id")): _reference_ids(
                frontend, "publicIPAddress", "properties.publicIPAddress"
            )
            for frontend in frontends
        }
        frontend_ports = {
            canonical_arm_id(item.get("id")): _nested(item, "port", "properties.port")
            for item in _items(_nested(gateway, "frontendPorts", "properties.frontendPorts"))
        }
        listeners = {
            canonical_arm_id(item.get("id")): item
            for item in _items(_nested(gateway, "httpListeners", "properties.httpListeners"))
        }
        path_maps = {
            canonical_arm_id(item.get("id")): item
            for item in _items(_nested(gateway, "urlPathMaps", "properties.urlPathMaps"))
        }
        redirect_configurations = {
            canonical_arm_id(item.get("id")): item
            for item in _items(
                _nested(gateway, "redirectConfigurations", "properties.redirectConfigurations")
            )
        }

        def register_gateway_route(
            listener_id: str,
            pool_id: str,
            relationship_id: Any,
            relationship_type: str,
            path: Iterable[Any],
            extra_connected: Iterable[Any] = (),
        ) -> None:
            listener = listeners.get(listener_id, {})
            frontend_ids = _reference_ids(
                listener, "frontendIPConfiguration", "properties.frontendIPConfiguration"
            )
            port_ids = _reference_ids(listener, "frontendPort", "properties.frontendPort")
            ports = [frontend_ports[item] for item in port_ids if frontend_ports.get(item) is not None]
            protocol = _nested(listener, "protocol", "properties.protocol")
            connected = (
                ([pool_id] if pool_id else [])
                + pool_targets.get(pool_id, [])
                + list(extra_connected)
            )
            for frontend_id in frontend_ids:
                for public_id in frontend_public_ids.get(frontend_id, ()):
                    register_reverse_attachment(
                        public_id,
                        owner=owner,
                        association="application_gateway",
                        connected=connected,
                        ports=ports,
                        protocols=[protocol] if protocol else [],
                        sources=_source_ids(
                            gateway,
                            "az_network_application-gateway_list",
                            "az_network_application-gateway_show_--name_name_--resource-group_resourcegroup",
                        ),
                        attachment_id=frontend_id,
                        relationship_id=relationship_id,
                        relationship_type=relationship_type,
                        connection_path=(frontend_id, listener_id, *path, pool_id, *connected),
                        direction="inbound",
                    )

        matched_frontends = set()
        for rule in _items(_nested(gateway, "requestRoutingRules", "properties.requestRoutingRules")):
            rule_id = canonical_arm_id(rule.get("id"))
            listener_ids = _reference_ids(rule, "httpListener", "properties.httpListener")
            pool_ids = _reference_ids(rule, "backendAddressPool", "properties.backendAddressPool")
            path_map_ids = _reference_ids(rule, "urlPathMap", "properties.urlPathMap")
            redirect_ids = _reference_ids(
                rule, "redirectConfiguration", "properties.redirectConfiguration"
            )
            for listener_id in listener_ids:
                listener = listeners.get(listener_id, {})
                matched_frontends.update(
                    _reference_ids(listener, "frontendIPConfiguration", "properties.frontendIPConfiguration")
                )
                for pool_id in pool_ids:
                    register_gateway_route(
                        listener_id, pool_id, rule_id, "request_routing_rule", (rule_id,)
                    )
                for path_map_id in path_map_ids:
                    path_map = path_maps.get(path_map_id, {})
                    default_pools = _reference_ids(
                        path_map,
                        "defaultBackendAddressPool",
                        "properties.defaultBackendAddressPool",
                    )
                    for pool_id in default_pools:
                        register_gateway_route(
                            listener_id,
                            pool_id,
                            path_map_id,
                            "url_path_map_default",
                            (rule_id, path_map_id),
                        )
                    for path_rule in _items(
                        _nested(path_map, "pathRules", "properties.pathRules")
                    ):
                        for pool_id in _reference_ids(
                            path_rule,
                            "backendAddressPool",
                            "properties.backendAddressPool",
                        ):
                            register_gateway_route(
                                listener_id,
                                pool_id,
                                path_rule.get("id"),
                                "url_path_rule",
                                (rule_id, path_map_id, path_rule.get("id")),
                            )
                redirect_targets: List[str] = list(redirect_ids)
                for redirect_id in redirect_ids:
                    redirect = redirect_configurations.get(redirect_id, {})
                    redirect_targets += _reference_ids(
                        redirect,
                        "targetListener",
                        "properties.targetListener",
                    )
                    target_url = _nested(
                        redirect, "targetUrl", "properties.targetUrl"
                    )
                    if target_url:
                        redirect_targets.append(str(target_url))
                if not pool_ids and not path_map_ids:
                    register_gateway_route(
                        listener_id,
                        "",
                        rule_id,
                        "request_routing_rule",
                        (rule_id,),
                        redirect_targets,
                    )
        for frontend_id, public_ids in frontend_public_ids.items():
            if frontend_id in matched_frontends:
                continue
            for public_id in public_ids:
                register_reverse_attachment(
                    public_id,
                    owner=owner,
                    association="application_gateway",
                    connected=[],
                    ports=[],
                    protocols=[],
                    sources=_source_ids(
                        gateway,
                        "az_network_application-gateway_list",
                        "az_network_application-gateway_show_--name_name_--resource-group_resourcegroup",
                    ),
                    attachment_id=frontend_id,
                    relationship_id=frontend_id,
                    relationship_type="frontend",
                    connection_path=(frontend_id,),
                    direction="inbound",
                )

    for public_ip in public_ips:
        public_id = canonical_arm_id(public_ip.get("id"))
        address = _nested(public_ip, "ipAddress", "properties.ipAddress")
        attachment = _nested(public_ip, "ipConfiguration.id", "properties.ipConfiguration.id")
        nat_gateway = _nested(public_ip, "natGateway.id", "properties.natGateway.id")
        linked_public_ip = _nested(
            public_ip,
            "linkedPublicIPAddress.id",
            "properties.linkedPublicIPAddress.id",
            "servicePublicIPAddress.id",
            "properties.servicePublicIPAddress.id",
        )
        reverse = reverse_attachments.get(public_id, [])
        relationship_source = None
        if reverse:
            for relationship in reverse:
                add(
                    address=address,
                    fqdn=_nested(public_ip, "dnsSettings.fqdn", "properties.dnsSettings.fqdn"),
                    direction=relationship.get("direction", "both"),
                    owner_id=relationship["owner"],
                    attachment_id=attachment or relationship.get("attachment_id"),
                    connected_ids=relationship["connected"],
                    association=relationship["association"],
                    source_ids=tuple(dict.fromkeys(
                        _source_ids(public_ip, "az_network_public-ip_list")
                        + tuple(relationship["sources"])
                    )),
                    ports=relationship["ports"],
                    protocols=relationship["protocols"],
                    relationship_id=relationship.get("relationship_id"),
                    relationship_type=relationship.get("relationship_type"),
                    connection_path=relationship.get("connection_path", ()),
                    public_ip_resource_id=public_id,
                )
            continue
        elif nat_gateway:
            owner, association, connected, ports, protocols = nat_gateway, "nat_gateway", [], [], []
        elif linked_public_ip:
            owner, association, connected, ports, protocols = public_id, "linked_public_ip", [linked_public_ip], [], []
        elif attachment:
            owner = _resource_parent(attachment)
            association = _resource_type(owner).split("/")[-1] or "ip_configuration"
            connected, ports, protocols = [], [], []
        else:
            owner, association, connected, ports, protocols = public_id, "unassociated", [], [], []
        add(
            address=address,
            fqdn=_nested(public_ip, "dnsSettings.fqdn", "properties.dnsSettings.fqdn"),
            direction="both",
            owner_id=owner,
            attachment_id=attachment,
            connected_ids=connected,
            association=association,
            source_ids=tuple(dict.fromkeys(
                _source_ids(public_ip, "az_network_public-ip_list")
                + ((relationship_source,) if relationship_source else ())
            )),
            ports=ports,
            protocols=protocols,
            public_ip_resource_id=public_id,
        )

    for vm_record in datasets.get("vm_ip_addresses", ()):
        vm = vm_record.get("virtualMachine")
        if not isinstance(vm, Mapping):
            vm = vm_record
        owner = canonical_arm_id(vm.get("id")) or _owner_id(vm_record)
        network = vm.get("network") if isinstance(vm.get("network"), Mapping) else {}
        for public in _items(network.get("publicIpAddresses")):
            add(
                address=public.get("ipAddress"),
                fqdn=public.get("fqdn"),
                direction="both",
                owner_id=owner,
                attachment_id=public.get("id"),
                association="virtual_machine",
                source_ids=_source_ids(vm_record, "az_vm_list-ip-addresses"),
                public_ip_resource_id=public.get("id"),
            )

    resource_sources = (
        ("nat_gateways", "az_network_nat_gateway_list", "outbound", "nat_gateway"),
        ("bastion_hosts", "az_network_bastion_list", "management", "bastion"),
        ("firewalls", "az_network_firewall_list", "both", "azure_firewall"),
        ("virtual_network_gateways", "az_network_vnet-gateway_list", "both", "virtual_network_gateway"),
    )
    public_by_id = {canonical_arm_id(item.get("id")): item for item in public_ips}
    prefix_records = list(datasets.get("public_ip_prefixes", ()))
    prefix_consumers: Dict[str, List[str]] = {}
    firewall_policy_targets: Dict[str, List[str]] = {}
    for group in datasets.get("firewall_policy_rule_groups", ()):
        group_id = canonical_arm_id(group.get("id"))
        policy_id = group_id.split("/rulecollectiongroups/", 1)[0]
        if not policy_id:
            continue
        for rule in _walk_mappings(group):
            rule_type = normalise_identifier(rule.get("ruleType") or rule.get("rule_type"))
            if "nat" not in rule_type and not any(
                key in rule for key in ("translatedAddress", "translatedFqdn", "translatedPort")
            ):
                continue
            for field in ("translatedAddress", "translatedFqdn"):
                target = rule.get(field)
                if target:
                    firewall_policy_targets.setdefault(policy_id, []).append(str(target))
    gateway_connections: Dict[str, List[str]] = {}
    for connection in datasets.get("virtual_network_connections", ()):
        connection_id = _owner_id(connection)
        gateway_ids = _reference_ids(
            connection,
            "virtualNetworkGateway1",
            "properties.virtualNetworkGateway1",
            "virtualNetworkGateway2",
            "properties.virtualNetworkGateway2",
        )
        peers = _reference_ids(
            connection,
            "localNetworkGateway2",
            "properties.localNetworkGateway2",
            "peer",
            "properties.peer",
        )
        for gateway_id in gateway_ids:
            gateway_connections.setdefault(gateway_id, []).extend(
                [connection_id] + peers
            )
    for dataset_name, source_id, direction, association in resource_sources:
        for resource in datasets.get(dataset_name, ()):
            owner = _owner_id(resource)
            references = _reference_ids(
                resource,
                "publicIpAddresses",
                "properties.publicIpAddresses",
            )
            prefix_references = _reference_ids(
                resource,
                "publicIpPrefixes",
                "properties.publicIpPrefixes",
            )
            connected = _reference_ids(resource, "subnets", "properties.subnets", "firewallPolicy", "properties.firewallPolicy")
            for config in _items(_nested(resource, "ipConfigurations", "properties.ipConfigurations")):
                references += _reference_ids(config, "publicIPAddress", "properties.publicIPAddress")
                connected += _reference_ids(config, "subnet", "properties.subnet")
            policy_ids = _reference_ids(resource, "firewallPolicy", "properties.firewallPolicy")
            for policy_id in policy_ids:
                connected += firewall_policy_targets.get(policy_id, [])
            if association == "azure_firewall":
                for rule in _walk_mappings(resource):
                    if not any(
                        key in rule
                        for key in ("translatedAddress", "translatedFqdn", "translatedPort")
                    ):
                        continue
                    connected += [
                        str(rule[field])
                        for field in ("translatedAddress", "translatedFqdn")
                        if rule.get(field)
                    ]
            if association == "virtual_network_gateway":
                connected += gateway_connections.get(owner, [])
            for public_id in dict.fromkeys(references):
                public_ip = public_by_id.get(public_id, {})
                add(
                    address=_nested(public_ip, "ipAddress", "properties.ipAddress"),
                    fqdn=_nested(public_ip, "dnsSettings.fqdn", "properties.dnsSettings.fqdn"),
                    direction=direction,
                    owner_id=owner,
                    attachment_id=public_id,
                    connected_ids=connected,
                    association=association,
                    source_ids=tuple(dict.fromkeys(
                        _source_ids(resource, source_id)
                        + _source_ids(public_ip, "az_network_public-ip_list")
                    )),
                    public_ip_resource_id=public_id,
                )
            for prefix_id in prefix_references:
                prefix_consumers.setdefault(prefix_id, []).append(owner)

    for prefix in prefix_records:
        prefix_id = canonical_arm_id(prefix.get("id"))
        add(
            address_prefix=_nested(prefix, "ipPrefix", "properties.ipPrefix"),
            direction="outbound",
            owner_id=prefix_id,
            connected_ids=prefix_consumers.get(prefix_id, ()),
            association="public_ip_prefix",
            source_ids=_source_ids(prefix, "az_network_public-ip_prefix_list"),
        )

    for item in datasets.get("vmss_instance_public_ips", ()):
        context = _context(item).get("parameters") or {}
        owner = item.get("virtualMachineScaleSetId") or item.get("id") or f"vmss:{context.get('resourceGroup')}/{context.get('name')}"
        add(
            address=_nested(item, "ipAddress", "properties.ipAddress"),
            fqdn=_nested(item, "dnsSettings.fqdn", "properties.dnsSettings.fqdn"),
            direction="both",
            owner_id=_resource_parent(owner),
            attachment_id=item.get("id"),
            association="vm_scale_set_instance",
            source_ids=_source_ids(
                item,
                "az_vmss_list-instance-public-ips_--name_name_--resource-group_resourcegroup",
            ),
            public_ip_resource_id=item.get("id"),
        )

    service_specs = (
        ("apim_services", "az_apim_show_--name_name_--resource-group_resourcegroup", ("publicIPAddresses", "properties.publicIPAddresses"), ("gatewayUrl", "developerPortalUrl", "managementApiUrl", "portalUrl", "scmUrl"), "both", "api_management"),
        ("web_apps", "az_webapp_list", ("inboundIpAddress", "possibleInboundIpAddresses"), ("defaultHostName", "hostNames", "enabledHostNames"), "inbound", "app_service"),
        ("function_apps", "az_functionapp_list", ("inboundIpAddress", "possibleInboundIpAddresses"), ("defaultHostName", "hostNames", "enabledHostNames"), "inbound", "function_app"),
        ("web_apps", "az_webapp_list", ("outboundIpAddresses", "possibleOutboundIpAddresses"), (), "outbound", "app_service"),
        ("function_apps", "az_functionapp_list", ("outboundIpAddresses", "possibleOutboundIpAddresses"), (), "outbound", "function_app"),
        ("web_app_slots", "az_webapp_deployment_slot_list_--name_name_--resource-group_resourcegroup", ("inboundIpAddress", "possibleInboundIpAddresses"), ("defaultHostName", "hostNames", "enabledHostNames"), "inbound", "app_service_slot"),
        ("web_app_slots", "az_webapp_deployment_slot_list_--name_name_--resource-group_resourcegroup", ("outboundIpAddresses", "possibleOutboundIpAddresses"), (), "outbound", "app_service_slot"),
        ("function_app_slots", "az_functionapp_deployment_slot_list_--name_name_--resource-group_resourcegroup", ("inboundIpAddress", "possibleInboundIpAddresses"), ("defaultHostName", "hostNames", "enabledHostNames"), "inbound", "function_app_slot"),
        ("function_app_slots", "az_functionapp_deployment_slot_list_--name_name_--resource-group_resourcegroup", ("outboundIpAddresses", "possibleOutboundIpAddresses"), (), "outbound", "function_app_slot"),
        ("app_service_environment_addresses", "az_appservice_ase_list-addresses_--name_name", ("inboundIpAddress", "outboundIpAddresses", "vipAddress"), (), "both", "app_service_environment"),
    )
    for dataset_name, source_id, address_fields, fqdn_fields, direction, association in service_specs:
        for resource in datasets.get(dataset_name, ()):
            owner = _owner_id(resource)
            access_state = normalise_identifier(
                _nested(resource, "publicNetworkAccess", "properties.publicNetworkAccess")
            ) or "unknown"
            for field in address_fields:
                for address in _split_addresses(_nested(resource, field, f"properties.{field}")):
                    add(address=address, direction=direction, owner_id=owner, association=association, source_ids=_source_ids(resource, source_id), access_state=access_state)
            for field in fqdn_fields:
                value = _nested(resource, field, f"properties.{field}")
                candidates = value if isinstance(value, list) else (value,)
                for fqdn in candidates:
                    if fqdn:
                        add(fqdn=fqdn, direction=direction, owner_id=owner, association=association, source_ids=_source_ids(resource, source_id), access_state=access_state)

            if association == "api_management":
                for location in _items(_nested(resource, "additionalLocations", "properties.additionalLocations")):
                    for address in _split_addresses(
                        _nested(location, "publicIPAddresses", "properties.publicIPAddresses")
                    ):
                        add(address=address, direction=direction, owner_id=owner, association=association, source_ids=_source_ids(resource, source_id), access_state=access_state)

    managed_service_specs = (
        ("storage_accounts", "az_storage_account_list", "storage_account", ("primaryEndpoints", "properties.primaryEndpoints")),
        ("key_vaults", "az_keyvault_list", "key_vault", ("properties.vaultUri", "vaultUri")),
        ("container_registries", "az_acr_list", "container_registry", ("loginServer", "properties.loginServer")),
        ("cosmos_accounts", "az_cosmosdb_list", "cosmos_db", ("documentEndpoint", "properties.documentEndpoint")),
        ("sql_servers", "az_sql_server_list", "sql_server", ("fullyQualifiedDomainName", "properties.fullyQualifiedDomainName")),
        ("postgres_servers", "az_postgres_flexible-server_list", "postgresql", ("fullyQualifiedDomainName", "properties.fullyQualifiedDomainName")),
        ("mysql_servers", "az_mysql_flexible-server_list", "mysql", ("fullyQualifiedDomainName", "properties.fullyQualifiedDomainName")),
        ("redis_caches", "az_redis_list", "redis", ("hostName", "properties.hostName")),
        ("search_services", "az_search_service_list", "azure_ai_search", ("endpoint", "properties.endpoint")),
        ("cognitive_accounts", "az_cognitiveservices_account_list", "azure_ai", ("properties.endpoint", "endpoint")),
        ("event_grid_topics", "az_eventgrid_topic_list", "event_grid_topic", ("endpoint", "properties.endpoint")),
        ("event_grid_domains", "az_eventgrid_domain_list", "event_grid_domain", ("endpoint", "properties.endpoint")),
        ("event_hubs", "az_eventhubs_namespace_list", "event_hubs", ("serviceBusEndpoint", "properties.serviceBusEndpoint")),
        ("service_bus", "az_servicebus_namespace_list", "service_bus", ("serviceBusEndpoint", "properties.serviceBusEndpoint")),
        ("relay_namespaces", "az_relay_namespace_list", "relay", ("serviceBusEndpoint", "properties.serviceBusEndpoint")),
        ("signalr_services", "az_signalr_show_--name_name_--resource-group_resourcegroup", "signalr", ("hostName", "properties.hostName")),
        ("iot_hubs", "az_iot_hub_list", "iot_hub", ("properties.hostName", "hostName")),
        ("iot_dps", "az_iot_dps_list", "iot_dps", ("properties.serviceOperationsHostName", "serviceOperationsHostName")),
        ("databricks_workspaces", "az_databricks_workspace_list", "databricks", ("workspaceUrl", "properties.workspaceUrl")),
        ("machine_learning_workspaces", "az_ml_workspace_list", "machine_learning", ("discoveryUrl", "properties.discoveryUrl")),
        ("batch_accounts", "az_batch_account_list", "batch", ("accountEndpoint", "properties.accountEndpoint")),
        ("app_configuration", "az_appconfig_list", "app_configuration", ("endpoint", "properties.endpoint")),
        ("synapse_workspaces", "az_synapse_workspace_list", "synapse", ("connectivityEndpoints", "properties.connectivityEndpoints")),
        ("aro_clusters", "az_aro_list", "red_hat_openshift", ("apiserverProfile.url", "consoleProfile.url", "properties.apiserverProfile.url", "properties.consoleProfile.url")),
        ("purview_accounts", "az_purview_account_list", "purview", ("endpoints", "properties.endpoints")),
        ("logic_apps", "az_logicapp_list", "logic_app", ("accessEndpoint", "properties.accessEndpoint")),
        ("hdinsight_clusters", "az_hdinsight_show_--name_name_--resource-group_resourcegroup", "hdinsight", ("connectivityEndpoints", "properties.connectivityEndpoints")),
    )
    for dataset_name, source_id, association, field_paths in managed_service_specs:
        for resource in datasets.get(dataset_name, ()):
            access_state = normalise_identifier(
                _nested(resource, "publicNetworkAccess", "properties.publicNetworkAccess")
            ) or "unknown"
            owner = _owner_id(resource)
            for field_path in field_paths:
                value = _nested(resource, field_path)
                for candidate in _endpoint_strings(value):
                    add(fqdn=candidate, direction="inbound", owner_id=owner, association=association, source_ids=_source_ids(resource, source_id), access_state=access_state)

    afd_routes_by_endpoint: Dict[str, List[Dict[str, Any]]] = {}
    origins_by_group: Dict[str, List[str]] = {}
    afd_origin_targets: Dict[str, List[str]] = {}
    afd_origin_sources: Dict[str, Tuple[str, ...]] = {}
    for origin in datasets.get("afd_origins", ()):
        origin_id = canonical_arm_id(origin.get("id"))
        group_id = origin_id.split("/origins/", 1)[0] if "/origins/" in origin_id else ""
        targets = _reference_ids(
            origin,
            "sharedPrivateLinkResource.privateLink",
            "properties.sharedPrivateLinkResource.privateLink",
        )
        for field in (
            "hostName",
            "properties.hostName",
            "originHostHeader",
            "properties.originHostHeader",
        ):
            target = _nested(origin, field)
            if target:
                targets.append(str(target))
        if origin_id:
            afd_origin_targets[origin_id] = list(dict.fromkeys(targets))
            afd_origin_sources[origin_id] = _source_ids(
                origin,
                "arm_afd_origins",
            )
        if group_id:
            origins_by_group.setdefault(group_id, []).append(origin_id)
    for route in datasets.get("afd_routes", ()):
        route_id = canonical_arm_id(route.get("id"))
        endpoint_id = route_id.split("/routes/", 1)[0] if "/routes/" in route_id else ""
        connections = _reference_ids(route, "originGroup", "properties.originGroup")
        connections += [
            origin_id
            for group_id in list(connections)
            for origin_id in origins_by_group.get(group_id, ())
        ]
        connections += [
            target
            for origin_id in list(connections)
            for target in afd_origin_targets.get(origin_id, ())
        ]
        connections += _reference_ids(route, "customDomains", "properties.customDomains")
        if endpoint_id:
            protocols = _nested(
                route,
                "supportedProtocols",
                "properties.supportedProtocols",
            )
            if not isinstance(protocols, list):
                protocols = ["Http", "Https"]
            protocol_names = [
                normalise_identifier(protocol)
                for protocol in protocols
                if normalise_identifier(protocol) in {"http", "https"}
            ]
            source_ids = list(_source_ids(route, "arm_afd_routes"))
            for origin_id in connections:
                source_ids.extend(afd_origin_sources.get(origin_id, ()))
            afd_routes_by_endpoint.setdefault(endpoint_id, []).append({
                "id": route_id,
                "connections": list(dict.fromkeys(connections)),
                "protocols": list(dict.fromkeys(protocol_names)),
                "ports": [
                    port
                    for protocol, port in (("http", 80), ("https", 443))
                    if protocol in protocol_names
                ],
                "accessState": normalise_identifier(
                    _nested(route, "enabledState", "properties.enabledState")
                ) or "unknown",
                "sourceEndpointIds": list(dict.fromkeys(source_ids)),
            })

    for dataset_name, source_id, association in (
        ("container_instances", "az_container_list", "container_instance"),
        ("container_apps", "az_containerapp_list", "container_app"),
    ):
        for resource in datasets.get(dataset_name, ()):
            ip_config = _nested(resource, "ipAddress", "properties.ipAddress") or {}
            ingress = _nested(resource, "configuration.ingress", "properties.configuration.ingress") or {}
            if not isinstance(ip_config, Mapping):
                ip_config = {}
            if not isinstance(ingress, Mapping):
                ingress = {}
            is_public = normalise_identifier(ip_config.get("type")) == "public" or ingress.get("external") is True
            if not is_public:
                continue
            ports = [item.get("port") for item in _items(ip_config.get("ports"))]
            add(address=ip_config.get("ip"), fqdn=ip_config.get("fqdn") or ingress.get("fqdn"), direction="inbound", owner_id=_owner_id(resource), association=association, source_ids=_source_ids(resource, source_id), ports=ports)
            for address in _split_addresses(_nested(resource, "outboundIpAddresses", "properties.outboundIpAddresses")):
                add(address=address, direction="outbound", owner_id=_owner_id(resource), association=association, source_ids=_source_ids(resource, source_id))

    for cluster in datasets.get("aks_clusters", ()):
        if _nested(cluster, "apiServerAccessProfile.enablePrivateCluster", "properties.apiServerAccessProfile.enablePrivateCluster") is True:
            continue
        fqdn = _nested(cluster, "fqdn", "properties.fqdn")
        if fqdn:
            add(fqdn=fqdn, direction="management", owner_id=_owner_id(cluster), association="aks_api_server", source_ids=_source_ids(cluster, "az_aks_list"), ports=(443,), protocols=("https",))

    for endpoint in datasets.get("afd_endpoints", ()):
        fqdn = _nested(endpoint, "hostName", "properties.hostName")
        if not fqdn:
            continue
        owner = _owner_id(endpoint)
        endpoint_sources = _source_ids(endpoint, "arm_afd_endpoints")
        routes = afd_routes_by_endpoint.get(owner, ())
        if not routes:
            add(
                fqdn=fqdn,
                direction="inbound",
                owner_id=owner,
                association="front_door_endpoint",
                source_ids=endpoint_sources,
            )
            continue
        for route in routes:
            add(
                fqdn=fqdn,
                direction="inbound",
                owner_id=owner,
                connected_ids=route["connections"],
                association="front_door_endpoint",
                source_ids=tuple(dict.fromkeys(
                    endpoint_sources + tuple(route["sourceEndpointIds"])
                )),
                ports=route["ports"],
                protocols=route["protocols"],
                access_state=route["accessState"],
                relationship_id=route["id"],
                relationship_type="front_door_route",
                connection_path=(route["id"], *route["connections"]),
            )

    for endpoint in datasets.get("cdn_endpoints", ()):
        fqdn = _nested(endpoint, "hostName", "properties.hostName")
        if not fqdn:
            continue
        connected = _reference_ids(endpoint, "origins", "properties.origins")
        for origin in _items(_nested(endpoint, "origins", "properties.origins")):
            target = _nested(origin, "hostName", "properties.hostName")
            if target:
                connected.append(str(target))
        http_allowed = _nested(endpoint, "isHttpAllowed", "properties.isHttpAllowed")
        https_allowed = _nested(endpoint, "isHttpsAllowed", "properties.isHttpsAllowed")
        protocols = [
            protocol
            for protocol, allowed in (("http", http_allowed), ("https", https_allowed))
            if allowed is not False
        ]
        add(
            fqdn=fqdn,
            direction="inbound",
            owner_id=_owner_id(endpoint),
            connected_ids=connected,
            association="cdn_endpoint",
            source_ids=_source_ids(endpoint, "arm_cdn_endpoints"),
            ports=(80 if "http" in protocols else None, 443 if "https" in protocols else None),
            protocols=protocols,
            access_state=normalise_identifier(
                _nested(endpoint, "resourceState", "properties.resourceState")
            ) or "unknown",
        )

    for profile in datasets.get("traffic_manager_profiles", ()):
        fqdn = _nested(profile, "dnsConfig.fqdn", "properties.dnsConfig.fqdn")
        if not fqdn:
            continue
        owner = _owner_id(profile)
        profile_sources = _source_ids(
            profile,
            "az_network_traffic-manager_profile_list",
        )
        endpoints = _items(_nested(profile, "endpoints", "properties.endpoints"))
        if not endpoints:
            add(
                fqdn=fqdn,
                direction="inbound",
                owner_id=owner,
                association="traffic_manager",
                source_ids=profile_sources,
            )
            continue
        for endpoint in endpoints:
            connected = _reference_ids(
                endpoint,
                "targetResourceId",
                "properties.targetResourceId",
            )
            target = _nested(endpoint, "target", "properties.target")
            if target:
                connected.append(str(target))
            endpoint_id = endpoint.get("id")
            add(
                fqdn=fqdn,
                direction="inbound",
                owner_id=owner,
                connected_ids=connected,
                association="traffic_manager",
                source_ids=profile_sources,
                access_state=normalise_identifier(
                    _nested(endpoint, "endpointStatus", "properties.endpointStatus")
                ) or "unknown",
                relationship_id=endpoint_id,
                relationship_type="traffic_manager_endpoint",
                connection_path=(endpoint_id, *connected),
            )

    if dns_resolver:
        unique_fqdns = {
            (hostname, owner, direction, association): (
                connected,
                ports,
                source_ids,
            )
            for hostname, owner, direction, association, connected, ports, source_ids in fqdns
        }
        resolved_by_key: Dict[Tuple[str, str, str, str], List[str]] = {}
        total_fqdns = len(unique_fqdns)
        if dns_progress:
            dns_progress("started", {"total": total_fqdns})
        completed_fqdns = 0
        failed_fqdns = 0
        with ThreadPoolExecutor(max_workers=min(8, max(1, len(unique_fqdns)))) as executor:
            futures = {
                executor.submit(dns_resolver, key[0]): key for key in unique_fqdns
            }
            for future in as_completed(futures):
                key = futures[future]
                hostname = key[0]
                try:
                    returned = list(future.result())
                    public_addresses = sorted(
                        {
                            address
                            for value in returned
                            for address in (_public_ip(value),)
                            if address
                        }
                    )
                    resolved_by_key[key] = public_addresses
                    status = "resolved" if public_addresses else "no_public_answer"
                    diagnostic = {
                        "hostname": hostname,
                        "status": status,
                        "returnedAddressCount": len(returned),
                        "publicAddressCount": len(public_addresses),
                    }
                except (OSError, ValueError, TypeError, subprocess.SubprocessError) as exc:
                    resolved_by_key[key] = []
                    failed_fqdns += 1
                    diagnostic = {
                        "hostname": hostname,
                        "status": "failed",
                        "returnedAddressCount": 0,
                        "publicAddressCount": 0,
                        "errorType": type(exc).__name__,
                    }
                if dns_diagnostics is not None:
                    dns_diagnostics.append(diagnostic)
                completed_fqdns += 1
                if dns_progress:
                    dns_progress(
                        "progress",
                        {
                            "completed": completed_fqdns,
                            "total": total_fqdns,
                            "failed": failed_fqdns,
                        },
                    )
        for key, resolved in resolved_by_key.items():
            hostname, owner, direction, association = key
            connected, ports, source_ids = unique_fqdns[key]
            for address in resolved:
                add(address=address, fqdn=hostname, direction=direction, owner_id=owner, connected_ids=connected, association=association, confidence="observed", source_ids=source_ids, ports=ports, address_origin="dns_snapshot")

    owners_by_address: Dict[str, Set[str]] = {}
    owners_by_fqdn: Dict[str, Set[str]] = {}
    for record in records.values():
        owner = str(record.get("ownerResourceId") or "")
        if not owner:
            continue
        if record.get("address") and record.get("addressOrigin") == "control_plane":
            address_owners = owners_by_address.setdefault(
                str(record["address"]),
                set(),
            )
            address_owners.add(owner)
            public_ip_id = str(record.get("publicIpResourceId") or "")
            if public_ip_id:
                address_owners.add(public_ip_id)
        if record.get("fqdn"):
            owners_by_fqdn.setdefault(str(record["fqdn"]).casefold(), set()).add(owner)
    for record in records.values():
        owner = str(record.get("ownerResourceId") or "")
        candidates = set()
        if record.get("address"):
            candidates.update(owners_by_address.get(str(record["address"]), ()))
        for target in record.get("connectedTargets") or []:
            target_ip = _public_ip(target)
            if target_ip:
                candidates.update(owners_by_address.get(target_ip, ()))
            target_hostname = _hostname(target)
            if target_hostname:
                candidates.update(owners_by_fqdn.get(target_hostname, ()))
        candidates.discard(owner)
        record["candidateConnectedResourceIds"] = sorted(candidates)

    return [records[key] for key in sorted(records)]


def resolve_public_fqdns(hostname: str) -> Iterable[str]:
    """Resolve A/AAAA addresses with a per-name timeout and no shell expansion."""

    completed = subprocess.run(
        ["getent", "ahosts", hostname],
        capture_output=True,
        check=False,
        text=True,
        timeout=5,
    )
    if completed.returncode != 0:
        return ()
    return {
        line.split()[0]
        for line in completed.stdout.splitlines()
        if line.split() and _public_ip(line.split()[0])
    }


def analyse_unassociated_public_addresses(
    topology: Iterable[Mapping[str, Any]],
    conclusion_support: str,
    source_files: Iterable[str] = (),
) -> CorrelationResult:
    """Identify allocated Public IP resources without an attributable attachment."""

    topology = list(topology)
    eligible_by_public_ip = {}
    for item in topology:
        if "az_network_public-ip_list" not in (item.get("sourceEndpointIds") or []):
            continue
        if not (item.get("address") or item.get("addressPrefix")):
            continue
        public_ip_id = item.get("publicIpResourceId") or (
            item.get("ownerResourceId")
            if item.get("associationType") == "unassociated"
            else None
        )
        key = str(public_ip_id or item.get("address") or item.get("addressPrefix"))
        eligible_by_public_ip.setdefault(
            key,
            {
                "id": public_ip_id or key,
                "publicIpResourceId": public_ip_id,
                "ownerResourceId": public_ip_id,
                "address": item.get("address"),
                "addressPrefix": item.get("addressPrefix"),
            },
        )
    eligible = list(eligible_by_public_ip.values())
    observations = [
        dict(item)
        for item in topology
        if item.get("associationType") == "unassociated" and item.get("address")
    ]
    return CorrelationResult(
        observations=observations,
        eligible_assets=eligible,
        source_files=sorted(set(source_files)),
        required_endpoint_ids=["az_network_public-ip_list"],
        limitations=[],
        conclusion_support=conclusion_support,
    )
