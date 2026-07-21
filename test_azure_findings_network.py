import unittest

from azure_findings_network import (
    PRIVATE_LINK_ADAPTERS,
    analyse_external_attack_paths,
    analyse_private_link_posture,
    nsg_decision,
)


RESOURCE_ID = (
    "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
    "Microsoft.Storage/storageAccounts/account-one"
)
PUBLIC_IP_ID = (
    "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
    "Microsoft.Network/publicIPAddresses/ip-one"
)
NIC_ID = (
    "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
    "Microsoft.Network/networkInterfaces/nic-one"
)
NSG_ID = (
    "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
    "Microsoft.Network/networkSecurityGroups/nsg-one"
)


class PrivateLinkPostureTests(unittest.TestCase):
    def resource(self, public="Enabled"):
        return {"id": RESOURCE_ID, "name": "account-one", "publicNetworkAccess": public}

    def endpoint(self, status="Approved", target=RESOURCE_ID, provisioning="Succeeded"):
        return {
            "id": "/subscriptions/sub-one/resourceGroups/rg-one/providers/Microsoft.Network/privateEndpoints/pe-one",
            "privateLinkServiceConnections": [
                {
                    "properties": {
                        "privateLinkServiceId": target,
                        "groupIds": ["blob"],
                        "privateLinkServiceConnectionState": {"status": status},
                        "provisioningState": provisioning,
                    }
                }
            ],
        }

    def test_public_access_with_approved_endpoint_is_reported(self):
        result = analyse_private_link_posture(
            [self.resource()],
            [self.endpoint()],
            PRIVATE_LINK_ADAPTERS["storage"],
            "positive_and_negative",
        )
        self.assertEqual(result.observations[0]["privateEndpointPosture"], "public_and_private")

    def test_disabled_public_access_with_endpoint_is_not_reported(self):
        result = analyse_private_link_posture(
            [self.resource("Disabled")],
            [self.endpoint()],
            PRIVATE_LINK_ADAPTERS["storage"],
            "positive_and_negative",
        )
        self.assertEqual(result.observations, [])

    def test_pending_or_wrong_target_endpoint_does_not_count(self):
        result = analyse_private_link_posture(
            [self.resource()],
            [self.endpoint("Pending"), self.endpoint(target=RESOURCE_ID.replace("account-one", "other"))],
            PRIVATE_LINK_ADAPTERS["storage"],
            "positive_and_negative",
        )
        self.assertEqual(result.observations, [])

    def test_embedded_private_endpoint_connection_is_correlated(self):
        resource = self.resource()
        resource["privateEndpointConnections"] = [
            {
                "id": f"{RESOURCE_ID}/privateEndpointConnections/connection-one",
                "privateEndpoint": {"id": "/subscriptions/sub-one/resourceGroups/rg-one/providers/Microsoft.Network/privateEndpoints/pe-one"},
                "privateLinkServiceConnectionState": {"status": "Approved"},
                "groupIds": ["blob"],
                "provisioningState": "Succeeded",
            }
        ]
        result = analyse_private_link_posture(
            [resource],
            [resource],
            PRIVATE_LINK_ADAPTERS["storage"],
            "positive_and_negative",
        )
        self.assertEqual(result.observations[0]["privateEndpointPosture"], "public_and_private")


class NsgDecisionTests(unittest.TestCase):
    def rule(
        self,
        priority,
        access,
        port="22",
        source="Internet",
        protocol="Tcp",
        destination="*",
    ):
        return {
            "name": f"{access}-{priority}",
            "priority": priority,
            "direction": "Inbound",
            "access": access,
            "protocol": protocol,
            "sourceAddressPrefix": source,
            "destinationAddressPrefix": destination,
            "destinationPortRange": port,
        }

    def test_higher_priority_deny_wins(self):
        decision = nsg_decision(
            [self.rule(200, "Allow"), self.rule(100, "Deny")], "tcp", 22
        )
        self.assertEqual(decision["decision"], "deny")

    def test_port_ranges_and_protocol_are_enforced(self):
        decision = nsg_decision(
            [self.rule(100, "Allow", "8000-9000", protocol="Tcp")], "tcp", 8443
        )
        self.assertEqual(decision["decision"], "allow")
        self.assertEqual(
            nsg_decision([self.rule(100, "Allow", "8000-9000")], "udp", 8443)["decision"],
            "deny",
        )

    def test_private_source_is_not_treated_as_internet(self):
        decision = nsg_decision(
            [self.rule(100, "Allow", source="10.0.0.0/8")], "tcp", 22
        )
        self.assertEqual(decision["decision"], "deny")
        shared = nsg_decision(
            [self.rule(100, "Allow", source="100.64.0.0/10")], "tcp", 22
        )
        self.assertEqual(shared["decision"], "deny")

    def test_public_allow_list_is_still_external(self):
        decision = nsg_decision(
            [self.rule(100, "Allow", source="8.8.8.0/24")], "tcp", 22
        )
        self.assertEqual(decision["decision"], "allow")

    def test_narrow_deny_does_not_suppress_the_remaining_internet(self):
        decision = nsg_decision(
            [
                self.rule(100, "Deny", source="8.8.8.8/32"),
                self.rule(200, "Allow", source="Internet"),
            ],
            "tcp",
            22,
        )
        self.assertEqual(decision["decision"], "allow")
        self.assertEqual(decision["excludedSourcePrefixes"], ["8.8.8.8/32"])

    def test_universal_deny_suppresses_a_later_allow(self):
        decision = nsg_decision(
            [self.rule(100, "Deny"), self.rule(200, "Allow")],
            "tcp",
            22,
        )
        self.assertEqual(decision["decision"], "deny")

    def test_destination_must_match_the_backend_address(self):
        rule = self.rule(100, "Allow", destination="10.0.0.5/32")
        self.assertEqual(
            nsg_decision([rule], "tcp", 22, "10.0.0.4")["decision"],
            "deny",
        )
        self.assertEqual(
            nsg_decision([rule], "tcp", 22, "10.0.0.5")["decision"],
            "allow",
        )

    def test_public_frontend_family_limits_the_source_universe(self):
        decision = nsg_decision(
            [
                self.rule(100, "Deny", source="0.0.0.0/0"),
                self.rule(200, "Allow", source="Internet"),
            ],
            "tcp",
            22,
            source_version=4,
        )
        self.assertEqual(decision["decision"], "deny")

    def test_unresolved_higher_priority_deny_prevents_an_allow_conclusion(self):
        decision = nsg_decision(
            [
                self.rule(100, "Deny", source="UnresolvedServiceTag"),
                self.rule(200, "Allow", source="Internet"),
            ],
            "tcp",
            22,
        )
        self.assertEqual(decision["decision"], "unknown")
        self.assertTrue(decision["limitations"])


class AttackPathTests(unittest.TestCase):
    def test_direct_public_nic_with_raw_nsg_allow_is_probable(self):
        public_ips = [{"id": PUBLIC_IP_ID, "ipAddress": "203.0.113.10"}]
        nics = [
            {
                "id": NIC_ID,
                "networkSecurityGroup": {"id": NSG_ID},
                "virtualMachine": {"id": "/subscriptions/sub-one/resourceGroups/rg-one/providers/Microsoft.Compute/virtualMachines/vm-one"},
                "ipConfigurations": [
                    {"name": "primary", "publicIPAddress": {"id": PUBLIC_IP_ID}}
                ],
            }
        ]
        nsgs = [
            {
                "id": NSG_ID,
                "securityRules": [
                    {
                        "name": "allow-ssh",
                        "priority": 100,
                        "direction": "Inbound",
                        "access": "Allow",
                        "protocol": "Tcp",
                        "sourceAddressPrefix": "Internet",
                        "destinationPortRange": "22",
                    }
                ],
            }
        ]
        result = analyse_external_attack_paths(
            public_ips, nics, nsgs, "positive_and_negative"
        )
        self.assertEqual(result.observations[0]["frontendPort"], 22)
        self.assertEqual(result.observations[0]["pathConfidence"], "probable")

    def test_unattached_public_ip_does_not_create_attack_path(self):
        result = analyse_external_attack_paths(
            [{"id": PUBLIC_IP_ID, "ipAddress": "203.0.113.10"}],
            [],
            [],
            "positive_and_negative",
        )
        self.assertEqual(result.observations, [])
        self.assertEqual(len(result.eligible_assets), 1)

    def test_effective_nic_and_subnet_nsgs_must_both_allow_the_path(self):
        public_ips = [{"id": PUBLIC_IP_ID, "ipAddress": "203.0.113.10"}]
        nics = [
            {
                "id": NIC_ID,
                "networkSecurityGroup": {"id": NSG_ID},
                "ipConfigurations": [{"publicIPAddress": {"id": PUBLIC_IP_ID}}],
            }
        ]
        context = {"parameters": {"id": NIC_ID}}
        effective_nsgs = [
            {
                "effectiveSecurityRules": [
                    {
                        "name": "allow-ssh-at-nic",
                        "priority": 100,
                        "direction": "Inbound",
                        "access": "Allow",
                        "protocol": "Tcp",
                        "sourceAddressPrefix": "Internet",
                        "destinationPortRange": "22",
                    }
                ],
                "_collectionContext": context,
            },
            {
                "effectiveSecurityRules": [
                    {
                        "name": "deny-ssh-at-subnet",
                        "priority": 100,
                        "direction": "Inbound",
                        "access": "Deny",
                        "protocol": "Tcp",
                        "sourceAddressPrefix": "Internet",
                        "destinationPortRange": "22",
                    }
                ],
                "_collectionContext": context,
            },
        ]
        result = analyse_external_attack_paths(
            public_ips,
            nics,
            [],
            "positive_and_negative",
            effective_nsgs=effective_nsgs,
        )
        self.assertEqual(result.observations, [])

        allowed = analyse_external_attack_paths(
            public_ips,
            nics,
            [],
            "positive_and_negative",
            effective_nsgs=effective_nsgs[:1],
        )
        self.assertEqual(allowed.observations[0]["pathConfidence"], "confirmed")

    def test_effective_layers_require_a_common_external_source(self):
        nic = {
            "id": NIC_ID,
            "ipConfigurations": [
                {
                    "publicIPAddress": {"id": PUBLIC_IP_ID},
                    "privateIPAddress": "10.0.0.4",
                }
            ],
        }
        context = {"parameters": {"id": NIC_ID}}

        def effective_allow(name, source):
            return {
                "effectiveSecurityRules": [
                    {
                        "name": name,
                        "priority": 100,
                        "direction": "Inbound",
                        "access": "Allow",
                        "protocol": "Tcp",
                        "sourceAddressPrefix": source,
                        "destinationAddressPrefix": "10.0.0.4/32",
                        "destinationPortRange": "22",
                    }
                ],
                "_collectionContext": context,
            }

        result = analyse_external_attack_paths(
            [{"id": PUBLIC_IP_ID, "ipAddress": "203.0.113.10"}],
            [nic],
            [],
            "positive_and_negative",
            effective_nsgs=[
                effective_allow("allow-google", "8.8.8.8/32"),
                effective_allow("allow-cloudflare", "1.1.1.1/32"),
            ],
        )
        self.assertEqual(result.observations, [])

    def test_direct_path_requires_the_rule_destination_to_match(self):
        nic = {
            "id": NIC_ID,
            "networkSecurityGroup": {"id": NSG_ID},
            "ipConfigurations": [
                {
                    "publicIPAddress": {"id": PUBLIC_IP_ID},
                    "privateIPAddress": "10.0.0.4",
                }
            ],
        }
        rule = {
            "name": "allow-other-host",
            "priority": 100,
            "direction": "Inbound",
            "access": "Allow",
            "protocol": "Tcp",
            "sourceAddressPrefix": "Internet",
            "destinationAddressPrefix": "10.0.0.5/32",
            "destinationPortRange": "22",
        }
        public_ips = [{"id": PUBLIC_IP_ID, "ipAddress": "203.0.113.10"}]
        result = analyse_external_attack_paths(
            public_ips,
            [nic],
            [{"id": NSG_ID, "securityRules": [rule]}],
            "positive_and_negative",
        )
        self.assertEqual(result.observations, [])

        rule["destinationAddressPrefix"] = "10.0.0.0/24"
        result = analyse_external_attack_paths(
            public_ips,
            [nic],
            [{"id": NSG_ID, "securityRules": [rule]}],
            "positive_and_negative",
        )
        self.assertEqual(result.observations[0]["backendPrivateIpAddress"], "10.0.0.4")

    def test_direct_nic_preserves_an_exposed_port_range(self):
        public_ips = [{"id": PUBLIC_IP_ID, "ipAddress": "203.0.113.10"}]
        nics = [
            {
                "id": NIC_ID,
                "networkSecurityGroup": {"id": NSG_ID},
                "ipConfigurations": [{"publicIPAddress": {"id": PUBLIC_IP_ID}}],
            }
        ]
        nsgs = [
            {
                "id": NSG_ID,
                "securityRules": [
                    {
                        "name": "allow-app-range",
                        "priority": 100,
                        "direction": "Inbound",
                        "access": "Allow",
                        "protocol": "Tcp",
                        "sourceAddressPrefix": "Internet",
                        "destinationPortRange": "8000-9000",
                    }
                ],
            }
        ]
        result = analyse_external_attack_paths(
            public_ips, nics, nsgs, "positive_and_negative"
        )
        self.assertEqual(result.observations[0]["frontendPort"], "8000-9000")
        self.assertEqual(result.observations[0]["frontendPortRange"], [8000, 9000])

    def test_higher_priority_deny_splits_a_broad_allow_range(self):
        nic = {
            "id": NIC_ID,
            "networkSecurityGroup": {"id": NSG_ID},
            "ipConfigurations": [{"publicIPAddress": {"id": PUBLIC_IP_ID}}],
        }
        rules = [
            {
                "name": "deny-admin",
                "priority": 100,
                "direction": "Inbound",
                "access": "Deny",
                "protocol": "Tcp",
                "sourceAddressPrefix": "Internet",
                "destinationPortRange": "8080",
            },
            {
                "name": "allow-apps",
                "priority": 200,
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "sourceAddressPrefix": "Internet",
                "destinationPortRange": "8000-9000",
            },
        ]
        result = analyse_external_attack_paths(
            [{"id": PUBLIC_IP_ID, "ipAddress": "203.0.113.10"}],
            [nic],
            [{"id": NSG_ID, "securityRules": rules}],
            "positive_and_negative",
        )
        self.assertEqual(
            [item["frontendPort"] for item in result.observations],
            ["8000-8079", "8081-9000"],
        )

    def test_load_balancer_rule_resolves_to_backend_nic(self):
        pool_id = "/subscriptions/sub-one/resourceGroups/rg-one/providers/Microsoft.Network/loadBalancers/lb-one/backendAddressPools/pool-one"
        frontend_id = "/subscriptions/sub-one/resourceGroups/rg-one/providers/Microsoft.Network/loadBalancers/lb-one/frontendIPConfigurations/public"
        nic = {
            "id": NIC_ID,
            "networkSecurityGroup": {"id": NSG_ID},
            "ipConfigurations": [
                {
                    "id": f"{NIC_ID}/ipConfigurations/primary",
                    "loadBalancerBackendAddressPools": [{"id": pool_id}],
                }
            ],
        }
        nsg = {
            "id": NSG_ID,
            "securityRules": [
                {
                    "name": "allow-https",
                    "priority": 100,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddressPrefix": "Internet",
                    "destinationPortRange": "8443",
                },
                {
                    "name": "allow-ssh-nat",
                    "priority": 110,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddressPrefix": "Internet",
                    "destinationPortRange": "22",
                }
            ],
        }
        load_balancer = {
            "id": frontend_id.split("/frontendIPConfigurations/", 1)[0],
            "frontendIPConfigurations": [
                {"id": frontend_id, "publicIPAddress": {"id": PUBLIC_IP_ID}}
            ],
            "loadBalancingRules": [
                {
                    "id": "rule-one",
                    "frontendIPConfiguration": {"id": frontend_id},
                    "backendAddressPool": {"id": pool_id},
                    "frontendPort": 443,
                    "backendPort": 8443,
                    "protocol": "Tcp",
                }
            ],
            "inboundNatRules": [
                {
                    "id": "nat-one",
                    "frontendIPConfiguration": {"id": frontend_id},
                    "backendIPConfiguration": {
                        "id": f"{NIC_ID}/ipConfigurations/primary"
                    },
                    "frontendPort": 2222,
                    "backendPort": 22,
                    "protocol": "Tcp",
                }
            ],
        }
        result = analyse_external_attack_paths(
            [{"id": PUBLIC_IP_ID, "ipAddress": "203.0.113.10"}],
            [nic],
            [nsg],
            "positive_and_negative",
            load_balancers=[load_balancer],
            effective_routes=[
                {
                    "value": [
                        {
                            "addressPrefix": "0.0.0.0/0",
                            "nextHopType": "Internet",
                            "state": "Active",
                        }
                    ],
                    "_collectionContext": {"parameters": {"id": NIC_ID}},
                }
            ],
        )
        by_rule = {
            item["forwardingRuleId"]: item for item in result.observations
        }
        self.assertEqual(by_rule["rule-one"]["frontendType"], "load_balancer")
        self.assertEqual(by_rule["rule-one"]["backendPort"], 8443)
        self.assertEqual(by_rule["rule-one"]["pathConfidence"], "probable")
        self.assertEqual(by_rule["nat-one"]["backendPort"], 22)
        self.assertEqual(by_rule["nat-one"]["networkInterfaceId"], NIC_ID)
        self.assertEqual(
            by_rule["rule-one"]["effectiveRoutes"][0]["nextHopType"],
            "Internet",
        )

    def test_load_balancer_unknown_or_default_denied_nsg_is_not_reachable(self):
        pool_id = (
            "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
            "Microsoft.Network/loadBalancers/lb-one/backendAddressPools/pool-one"
        )
        frontend_id = (
            "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
            "Microsoft.Network/loadBalancers/lb-one/frontendIPConfigurations/public"
        )
        nic = {
            "id": NIC_ID,
            "networkSecurityGroup": {"id": NSG_ID},
            "ipConfigurations": [
                {
                    "id": f"{NIC_ID}/ipConfigurations/primary",
                    "privateIPAddress": "10.0.0.4",
                    "loadBalancerBackendAddressPools": [{"id": pool_id}],
                }
            ],
        }
        load_balancer = {
            "id": frontend_id.split("/frontendIPConfigurations/", 1)[0],
            "frontendIPConfigurations": [
                {"id": frontend_id, "publicIPAddress": {"id": PUBLIC_IP_ID}}
            ],
            "loadBalancingRules": [
                {
                    "id": "rule-one",
                    "frontendIPConfiguration": {"id": frontend_id},
                    "backendAddressPool": {"id": pool_id},
                    "frontendPort": 443,
                    "backendPort": 8443,
                    "protocol": "Tcp",
                }
            ],
        }
        result = analyse_external_attack_paths(
            [{"id": PUBLIC_IP_ID, "ipAddress": "203.0.113.10"}],
            [nic],
            [{"id": NSG_ID, "securityRules": []}],
            "positive_and_negative",
            load_balancers=[load_balancer],
        )
        self.assertEqual(result.observations, [])

        destination_rule = {
            "name": "allow-another-backend",
            "priority": 100,
            "direction": "Inbound",
            "access": "Allow",
            "protocol": "Tcp",
            "sourceAddressPrefix": "Internet",
            "destinationAddressPrefix": "10.0.0.5/32",
            "destinationPortRange": "8443",
        }
        mismatched = analyse_external_attack_paths(
            [{"id": PUBLIC_IP_ID, "ipAddress": "203.0.113.10"}],
            [nic],
            [{"id": NSG_ID, "securityRules": [destination_rule]}],
            "positive_and_negative",
            load_balancers=[load_balancer],
        )
        self.assertEqual(mismatched.observations, [])

        destination_rule["destinationAddressPrefix"] = "10.0.0.4/32"
        matched = analyse_external_attack_paths(
            [{"id": PUBLIC_IP_ID, "ipAddress": "203.0.113.10"}],
            [nic],
            [{"id": NSG_ID, "securityRules": [destination_rule]}],
            "positive_and_negative",
            load_balancers=[load_balancer],
        )
        self.assertEqual(
            matched.observations[0]["backendPrivateIpAddress"], "10.0.0.4"
        )

        nic.pop("networkSecurityGroup")
        unresolved = analyse_external_attack_paths(
            [{"id": PUBLIC_IP_ID, "ipAddress": "203.0.113.10"}],
            [nic],
            [],
            "positive_and_negative",
            load_balancers=[load_balancer],
        )
        self.assertEqual(unresolved.observations, [])
        self.assertEqual(unresolved.conclusion_support, "inconclusive")

    def test_application_gateway_listener_and_backend_are_correlated(self):
        gateway_id = "/subscriptions/sub-one/resourceGroups/rg-one/providers/Microsoft.Network/applicationGateways/ag-one"
        frontend_id = f"{gateway_id}/frontendIPConfigurations/public"
        port_id = f"{gateway_id}/frontendPorts/https"
        listener_id = f"{gateway_id}/httpListeners/listener-one"
        pool_id = f"{gateway_id}/backendAddressPools/pool-one"
        settings_id = f"{gateway_id}/backendHttpSettingsCollection/https"
        backend_ip_configuration_id = f"{NIC_ID}/ipConfigurations/primary"
        gateway = {
            "id": gateway_id,
            "frontendIPConfigurations": [
                {"id": frontend_id, "publicIPAddress": {"id": PUBLIC_IP_ID}}
            ],
            "frontendPorts": [{"id": port_id, "port": 443}],
            "httpListeners": [
                {
                    "id": listener_id,
                    "frontendIPConfiguration": {"id": frontend_id},
                    "frontendPort": {"id": port_id},
                    "protocol": "Https",
                }
            ],
            "backendAddressPools": [
                {
                    "id": pool_id,
                    "backendAddresses": [{"fqdn": "internal.example"}],
                    "backendIPConfigurations": [{"id": backend_ip_configuration_id}],
                }
            ],
            "backendHttpSettingsCollection": [{"id": settings_id, "port": 8443}],
            "requestRoutingRules": [
                {
                    "id": f"{gateway_id}/requestRoutingRules/rule-one",
                    "httpListener": {"id": listener_id},
                    "backendAddressPool": {"id": pool_id},
                    "backendHttpSettings": {"id": settings_id},
                }
            ],
        }
        result = analyse_external_attack_paths(
            [{"id": PUBLIC_IP_ID, "ipAddress": "203.0.113.10"}],
            [
                {
                    "id": NIC_ID,
                    "virtualMachine": {
                        "id": (
                            "/subscriptions/sub-one/resourceGroups/rg-one/providers/"
                            "Microsoft.Compute/virtualMachines/vm-one"
                        )
                    },
                    "ipConfigurations": [{"id": backend_ip_configuration_id}],
                }
            ],
            [],
            "positive_and_negative",
            application_gateways=[gateway],
        )
        self.assertEqual(result.observations[0]["frontendType"], "application_gateway")
        self.assertEqual(result.observations[0]["backendAddresses"], ["internal.example"])
        self.assertEqual(result.observations[0]["backendPort"], 8443)
        self.assertEqual(result.observations[0]["networkInterfaceId"], NIC_ID)


if __name__ == "__main__":
    unittest.main()
