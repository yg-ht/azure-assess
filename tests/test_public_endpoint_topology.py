import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

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
        topology = build_public_endpoint_topology(
            {"aks_clusters": [{"id": f"{SUB}/Microsoft.ContainerService/managedClusters/aks", "fqdn": "api.example.test"}]},
            dns_resolver=lambda _hostname: ["8.8.8.8", "10.0.0.1"],
        )
        observed = [item for item in topology if item["addressOrigin"] == "dns_snapshot"]
        self.assertEqual(len(observed), 1)
        self.assertTrue(observed[0]["_collectionContext"]["pointInTimeDns"])

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
            "VM Scale Set Instance Public IPs",
            "Azure Firewall Policy Rule Collection Groups",
            "Front Door Endpoints",
            "Front Door Routes",
            "Front Door Origin Groups",
            "Front Door Origins",
            "CDN Endpoints",
        }.issubset(parameter_names))

    def test_derived_datasets_are_saved_without_implicit_dns_resolution(self):
        saved = []

        class Manifest:
            @staticmethod
            def endpoint_outcomes(endpoint_id):
                return [{"status": "success"}] if endpoint_id == "az_network_public-ip_list" else []

        def load(prefix):
            if prefix == "az_network_public-ip_list":
                return [{"id": PIP, "ipAddress": "8.8.8.8"}]
            return []

        def save(data, filename, **_kwargs):
            saved.append((filename, data))

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
            patch.object(
                self.collector,
                "resolve_public_fqdns",
                side_effect=AssertionError("DNS must not be called"),
            ),
        ):
            topology = self.collector.save_current_public_endpoint_topology()

        self.assertEqual(len(topology), 1)
        self.assertEqual(
            [item[0] for item in saved],
            [
                "azure_public_endpoint_topology_20260807-120000.json",
                "azure_public_endpoint_topology_coverage_20260807-120000.json",
            ],
        )


if __name__ == "__main__":
    unittest.main()
