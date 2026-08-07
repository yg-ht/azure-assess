import importlib.util
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from azure_assess.public_endpoints import (
    analyse_unassociated_public_addresses,
    build_public_endpoint_topology,
)


SUB = "/subscriptions/sub/resourceGroups/rg/providers"
PIP = f"{SUB}/Microsoft.Network/publicIPAddresses/pip-one"
NIC = f"{SUB}/Microsoft.Network/networkInterfaces/nic-one"
VM = f"{SUB}/Microsoft.Compute/virtualMachines/vm-one"


class PublicEndpointTopologyTests(unittest.TestCase):
    def test_public_ip_is_joined_to_nic_and_virtual_machine(self):
        topology = build_public_endpoint_topology(
            {
                "public_ips": [{"id": PIP, "ipAddress": "8.8.8.8"}],
                "nics": [{
                    "id": NIC,
                    "virtualMachine": {"id": VM},
                    "ipConfigurations": [{"publicIPAddress": {"id": PIP}}],
                }],
            },
            collected_at="2026-08-07T12:00:00Z",
        )

        self.assertEqual(len(topology), 1)
        self.assertEqual(topology[0]["associationType"], "nic")
        self.assertEqual(topology[0]["ownerResourceId"], NIC.lower())
        self.assertEqual(topology[0]["connectedResourceIds"], [VM.lower()])
        self.assertEqual(
            topology[0]["_collectionContext"]["generatedAt"],
            "2026-08-07T12:00:00Z",
        )

    def test_public_ip_embedded_attachment_is_not_reported_as_unassociated(self):
        firewall = f"{SUB}/Microsoft.Network/azureFirewalls/firewall-one"
        topology = build_public_endpoint_topology({
            "public_ips": [{
                "id": PIP,
                "ipAddress": "1.1.1.1",
                "ipConfiguration": {"id": f"{firewall}/ipConfigurations/config-one"},
            }]
        })

        self.assertEqual(topology[0]["associationType"], "azurefirewalls")
        self.assertEqual(topology[0]["ownerResourceId"], firewall.lower())

    def test_nat_gateway_public_prefix_is_retained_without_expansion(self):
        nat = f"{SUB}/Microsoft.Network/natGateways/nat-one"
        prefix = f"{SUB}/Microsoft.Network/publicIPPrefixes/prefix-one"
        topology = build_public_endpoint_topology({
            "public_ip_prefixes": [{"id": prefix, "ipPrefix": "8.8.8.0/29"}],
            "nat_gateways": [{"id": nat, "publicIpPrefixes": [{"id": prefix}]}],
        })

        self.assertEqual(len(topology), 1)
        self.assertEqual(topology[0]["addressPrefix"], "8.8.8.0/29")
        self.assertEqual(topology[0]["connectedResourceIds"], [nat.lower()])

    def test_service_managed_addresses_and_fqdns_are_attributed(self):
        app = f"{SUB}/Microsoft.Web/sites/app-one"
        topology = build_public_endpoint_topology({
            "web_apps": [{
                "id": app,
                "inboundIpAddress": "8.8.4.4",
                "outboundIpAddresses": "1.1.1.1,9.9.9.9",
                "defaultHostName": "app-one.azurewebsites.net",
            }]
        })

        self.assertEqual({item["direction"] for item in topology}, {"inbound", "outbound"})
        self.assertEqual({item["ownerResourceId"] for item in topology}, {app.lower()})
        self.assertIn("app-one.azurewebsites.net", {item["fqdn"] for item in topology})

    def test_private_and_documentation_addresses_are_not_treated_as_public(self):
        topology = build_public_endpoint_topology({
            "public_ips": [
                {"id": PIP, "ipAddress": "10.0.0.4"},
                {"id": PIP + "-doc", "ipAddress": "192.0.2.10"},
            ]
        })
        self.assertEqual(topology, [])

    def test_dns_snapshot_is_explicit_and_point_in_time(self):
        diagnostics = []
        topology = build_public_endpoint_topology(
            {"aks_clusters": [{"id": f"{SUB}/Microsoft.ContainerService/managedClusters/aks", "fqdn": "api.example.test"}]},
            dns_resolver=lambda _hostname: ["8.8.8.8", "10.0.0.1"],
            dns_diagnostics=diagnostics,
        )
        observed = [item for item in topology if item["addressOrigin"] == "dns_snapshot"]
        self.assertEqual(len(observed), 1)
        self.assertTrue(observed[0]["_collectionContext"]["pointInTimeDns"])
        self.assertEqual(diagnostics[0]["status"], "resolved")
        self.assertEqual(diagnostics[0]["publicAddressCount"], 1)

    def test_dns_failure_is_recorded_without_losing_configured_fqdn(self):
        diagnostics = []

        def unavailable(_hostname):
            raise OSError("resolver unavailable")

        topology = build_public_endpoint_topology(
            {"web_apps": [{"id": "web", "defaultHostName": "app.example.test"}]},
            dns_resolver=unavailable,
            dns_diagnostics=diagnostics,
        )

        self.assertEqual(len(topology), 1)
        self.assertEqual(topology[0]["fqdn"], "app.example.test")
        self.assertEqual(diagnostics[0]["status"], "failed")
        self.assertEqual(diagnostics[0]["errorType"], "OSError")

    def test_load_balancer_routes_retain_backend_members_and_port_alignment(self):
        load_balancer = f"{SUB}/Microsoft.Network/loadBalancers/lb-one"
        frontend = f"{load_balancer}/frontendIPConfigurations/front"
        pool_web = f"{load_balancer}/backendAddressPools/web"
        pool_admin = f"{load_balancer}/backendAddressPools/admin"
        web_nic = f"{SUB}/Microsoft.Network/networkInterfaces/web/ipConfigurations/ip"
        admin_nic = f"{SUB}/Microsoft.Network/networkInterfaces/admin/ipConfigurations/ip"
        web_vm = f"{SUB}/Microsoft.Compute/virtualMachines/web"
        admin_vm = f"{SUB}/Microsoft.Compute/virtualMachines/admin"
        topology = build_public_endpoint_topology({
            "public_ips": [{"id": PIP, "ipAddress": "8.8.8.8"}],
            "nics": [
                {
                    "id": web_nic.split("/ipConfigurations/", 1)[0],
                    "virtualMachine": {"id": web_vm},
                    "ipConfigurations": [{"id": web_nic}],
                },
                {
                    "id": admin_nic.split("/ipConfigurations/", 1)[0],
                    "virtualMachine": {"id": admin_vm},
                    "ipConfigurations": [{"id": admin_nic}],
                },
            ],
            "load_balancers": [{
                "id": load_balancer,
                "frontendIPConfigurations": [{
                    "id": frontend,
                    "publicIPAddress": {"id": PIP},
                }],
                "backendAddressPools": [
                    {"id": pool_web, "backendIPConfigurations": [{"id": web_nic}]},
                    {"id": pool_admin, "backendIPConfigurations": [{"id": admin_nic}]},
                ],
                "loadBalancingRules": [
                    {
                        "id": f"{load_balancer}/loadBalancingRules/web",
                        "frontendIPConfiguration": {"id": frontend},
                        "backendAddressPool": {"id": pool_web},
                        "frontendPort": 443,
                        "protocol": "Tcp",
                    },
                    {
                        "id": f"{load_balancer}/loadBalancingRules/admin",
                        "frontendIPConfiguration": {"id": frontend},
                        "backendAddressPool": {"id": pool_admin},
                        "frontendPort": 8443,
                        "protocol": "Tcp",
                    },
                ],
            }],
        })

        routes = {item["ports"][0]: item for item in topology}
        self.assertEqual(set(routes), {443, 8443})
        self.assertIn(web_nic.lower(), routes[443]["connectedResourceIds"])
        self.assertIn(web_vm.lower(), routes[443]["connectedResourceIds"])
        self.assertNotIn(admin_nic.lower(), routes[443]["connectedResourceIds"])
        self.assertNotIn(admin_vm.lower(), routes[443]["connectedResourceIds"])
        self.assertIn(admin_nic.lower(), routes[8443]["connectedResourceIds"])
        self.assertIn(admin_vm.lower(), routes[8443]["connectedResourceIds"])
        self.assertEqual(routes[443]["relationshipType"], "load_balancing_rule")

    def test_application_gateway_routes_follow_listener_and_path_map(self):
        gateway = f"{SUB}/Microsoft.Network/applicationGateways/ag-one"
        frontend = f"{gateway}/frontendIPConfigurations/public"
        listener = f"{gateway}/httpListeners/https"
        frontend_port = f"{gateway}/frontendPorts/https"
        pool = f"{gateway}/backendAddressPools/web"
        path_map = f"{gateway}/urlPathMaps/map"
        path_rule = f"{path_map}/pathRules/api"
        topology = build_public_endpoint_topology({
            "public_ips": [{"id": PIP, "ipAddress": "8.8.4.4"}],
            "application_gateways": [{
                "id": gateway,
                "frontendIPConfigurations": [{"id": frontend, "publicIPAddress": {"id": PIP}}],
                "frontendPorts": [{"id": frontend_port, "port": 443}],
                "httpListeners": [{
                    "id": listener,
                    "frontendIPConfiguration": {"id": frontend},
                    "frontendPort": {"id": frontend_port},
                    "protocol": "Https",
                }],
                "backendAddressPools": [{
                    "id": pool,
                    "backendAddresses": [{"fqdn": "api.internal.example"}],
                }],
                "urlPathMaps": [{
                    "id": path_map,
                    "pathRules": [{"id": path_rule, "backendAddressPool": {"id": pool}}],
                }],
                "requestRoutingRules": [{
                    "id": f"{gateway}/requestRoutingRules/rule",
                    "httpListener": {"id": listener},
                    "urlPathMap": {"id": path_map},
                }],
            }],
        })

        self.assertEqual(len(topology), 1)
        self.assertEqual(topology[0]["ports"], [443])
        self.assertEqual(topology[0]["protocols"], ["https"])
        self.assertEqual(topology[0]["relationshipType"], "url_path_rule")
        self.assertIn("api.internal.example", topology[0]["connectedTargets"])

    def test_front_door_route_retains_origin_hostname(self):
        profile = f"{SUB}/Microsoft.Cdn/profiles/front"
        endpoint = f"{profile}/afdEndpoints/edge"
        group = f"{profile}/originGroups/group"
        origin = f"{group}/origins/app"
        topology = build_public_endpoint_topology({
            "afd_endpoints": [{"id": endpoint, "hostName": "edge.azurefd.net"}],
            "afd_routes": [{"id": f"{endpoint}/routes/all", "originGroup": {"id": group}}],
            "afd_origins": [{"id": origin, "hostName": "app.example.com"}],
        })

        self.assertEqual(len(topology), 1)
        self.assertIn(origin.lower(), topology[0]["connectedResourceIds"])
        self.assertIn("app.example.com", topology[0]["connectedTargets"])

    def test_public_dns_and_managed_service_sources_are_normalised(self):
        dns_record = f"{SUB}/Microsoft.Network/dnszones/example.com/A/app"
        signalr = f"{SUB}/Microsoft.SignalRService/SignalR/signalr-one"
        topology = build_public_endpoint_topology({
            "public_ips": [{"id": PIP, "ipAddress": "8.8.8.8"}],
            "public_dns_records": [{
                "id": dns_record,
                "name": "app",
                "aRecords": [{"ipv4Address": "8.8.8.8"}],
                "_collectionContext": {"parameters": {"name": "example.com"}},
            }],
            "signalr_services": [{"id": signalr, "hostName": "signalr.example.com"}],
            "relay_namespaces": [{"id": "relay", "serviceBusEndpoint": "https://relay.example.com:443/"}],
            "hdinsight_clusters": [{
                "id": "hdinsight",
                "connectivityEndpoints": {"https": "https://cluster.example.com"},
            }],
        })

        by_association = {item["associationType"]: item for item in topology}
        self.assertEqual(by_association["public_dns_record"]["fqdn"], "app.example.com")
        self.assertIn(
            PIP.lower(),
            by_association["public_dns_record"]["candidateConnectedResourceIds"],
        )
        self.assertEqual(by_association["signalr"]["fqdn"], "signalr.example.com")
        self.assertEqual(by_association["relay"]["fqdn"], "relay.example.com")
        self.assertEqual(by_association["hdinsight"]["fqdn"], "cluster.example.com")

    def test_unassociated_finding_only_uses_allocated_public_ip_resources(self):
        topology = build_public_endpoint_topology({
            "public_ips": [{"id": PIP, "ipAddress": "8.8.8.8"}],
            "web_apps": [{"id": "web", "inboundIpAddress": "1.1.1.1"}],
        })
        result = analyse_unassociated_public_addresses(
            topology,
            "positive_and_negative",
            ["topology.json"],
        )
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0]["address"], "8.8.8.8")
        self.assertEqual(result.required_endpoint_ids, ["az_network_public-ip_list"])

    def test_duplicate_source_records_do_not_duplicate_relationships(self):
        record = {"id": PIP, "ipAddress": "8.8.8.8"}
        topology = build_public_endpoint_topology({"public_ips": [record, dict(record)]})
        self.assertEqual(len(topology), 1)


class PublicEndpointRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = Path(__file__).resolve().parents[1] / "azure-collect.py"
        spec = importlib.util.spec_from_file_location("azure_collect_public_endpoint_test", script)
        cls.collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.collector)

    def test_missing_public_endpoint_families_are_registered(self):
        names = {item["name"] for item in self.collector.AZURE_CLI_ENDPOINTS}
        self.assertTrue({
            "Azure Firewalls",
            "Azure Firewall Policies",
            "Container Apps",
            "Public IP Prefixes",
            "Traffic Manager Profiles",
            "Virtual Network Gateways",
        }.issubset(names))

        parameter_names = {
            item["name"] for item in self.collector.AZURE_CLI_ENDPOINTS_PARAMS
        }
        self.assertTrue({
            "Public DNS Record Sets",
            "VM Scale Set Instance Public IPs",
            "Azure Firewall Policy Rule Collection Groups",
            "Front Door Endpoints",
            "Front Door Routes",
            "Front Door Origin Groups",
            "Front Door Origins",
            "CDN Endpoints",
        }.issubset(parameter_names))

    def test_derived_datasets_use_the_approved_dns_resolver(self):
        saved = []

        class Manifest:
            @staticmethod
            def endpoint_outcomes(endpoint_id):
                return [{"status": "success"}] if endpoint_id == "az_network_public-ip_list" else []

        def load(prefix):
            if prefix == "az_network_public-ip_list":
                return [{"id": PIP, "ipAddress": "8.8.8.8"}]
            if prefix == "az_webapp_list":
                return [{
                    "id": f"{SUB}/Microsoft.Web/sites/app-one",
                    "defaultHostName": "app-one.azurewebsites.net",
                }]
            return []

        def save(data, filename, **_kwargs):
            saved.append((filename, data))

        resolver = Mock(return_value=["8.8.4.4"])
        with (
            patch.object(self.collector, "COLLECTION_MANIFEST", Manifest()),
            patch.object(
                self.collector,
                "START_TIMESTAMP",
                "20260807-120000",
                create=True,
            ),
            patch.object(self.collector, "load_current_dataset", side_effect=load),
            patch.object(self.collector, "save_json", side_effect=save),
            patch.object(self.collector, "resolve_public_fqdns", resolver),
        ):
            topology = self.collector.save_current_public_endpoint_topology()

        self.assertEqual(len(topology), 3)
        resolver.assert_called_once_with("app-one.azurewebsites.net")
        self.assertEqual(
            [item[0] for item in saved],
            [
                "azure_public_endpoint_topology_20260807-120000.json",
                "azure_public_endpoint_topology_coverage_20260807-120000.json",
            ],
        )
        coverage = saved[1][1]
        dns_coverage = next(
            item for item in coverage if item["logicalInput"] == "dns_snapshot"
        )
        self.assertEqual(dns_coverage["coverageState"], "complete")
        self.assertEqual(dns_coverage["recordCount"], 1)
        self.assertEqual(
            len([item for item in topology if item["addressOrigin"] == "dns_snapshot"]),
            1,
        )

    def test_dns_failure_marks_coverage_failed(self):
        saved = []

        def load(prefix):
            if prefix == "az_webapp_list":
                return [{"id": "web", "defaultHostName": "app.example.test"}]
            return []

        with (
            patch.object(self.collector, "COLLECTION_MANIFEST", None),
            patch.object(self.collector, "START_TIMESTAMP", "20260807-120000", create=True),
            patch.object(self.collector, "load_current_dataset", side_effect=load),
            patch.object(
                self.collector,
                "save_json",
                side_effect=lambda data, filename, **_kwargs: saved.append((filename, data)),
            ),
            patch.object(
                self.collector,
                "resolve_public_fqdns",
                side_effect=OSError("resolver unavailable"),
            ),
        ):
            topology = self.collector.save_current_public_endpoint_topology()

        self.assertEqual(len(topology), 1)
        coverage = saved[1][1]
        dns_coverage = next(
            item for item in coverage if item["logicalInput"] == "dns_snapshot"
        )
        self.assertEqual(dns_coverage["coverageState"], "failed")
        self.assertEqual(dns_coverage["failedCount"], 1)
        self.assertEqual(
            dns_coverage["hostnameOutcomes"],
            [{
                "hostname": "app.example.test",
                "status": "failed",
                "returnedAddressCount": 0,
                "publicAddressCount": 0,
                "errorType": "OSError",
            }],
        )
        self.assertIn("address associations are incomplete", dns_coverage["limitation"])


if __name__ == "__main__":
    unittest.main()
