# Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.

import json
import logging
import re
import time

import pytest

from tests.k8st.test_base import NetcatClientTCP, Container, Pod, TestBase
from tests.k8st.utils.utils import DiagsCollector, calicoctl, kubectl, run, retry_until_success, update_ds_env

_log = logging.getLogger(__name__)

@pytest.mark.non_vanilla
class TestExternalNetwork(TestBase):
    def setUp(self):
        super(TestExternalNetwork, self).setUp()

        newEnv = {"FELIX_PolicySyncPathPrefix": "/var/run/nodeagent",
                  "FELIX_EGRESSIPSUPPORT": "EnabledPerNamespaceOrPerPod",
                  "FELIX_EGRESSGATEWAYPOLLINTERVAL": "1",
                  "FELIX_ExternalNetworkSupport": "Enabled"}
        update_ds_env("calico-node", "calico-system", newEnv)

        # After restarting felixes, wait for 20s to ensure Felix is past its route-cleanup grace period.
        time.sleep(20)

    def tearDown(self):
        super(TestExternalNetwork, self).tearDown()

    def _patch_peer_external_net(self, peer, external_network):
        if external_network != "":
            kubectl("patch --type=merge bgppeer %s --patch '{\"spec\": {\"externalNetwork\": \"%s\"}}'" % (peer, external_network))
            self.add_cleanup(lambda: kubectl("patch --type=merge bgppeer %s --type json --patch '[{\"op\": \"remove\", \"path\": \"/spec/externalNetwork\"}]'" % peer, allow_fail=True))
        else:
            kubectl("patch --type=merge bgppeer %s --type json --patch '[{\"op\": \"remove\", \"path\": \"/spec/externalNetwork\"}]'" % peer)

    def _setup_ippools(self, ipv4_encap, egress_pool_cidr, block_size):
        assert ipv4_encap in ["IPIP", "VXLAN", "None"]
        ipip_mode = "Never"
        if ipv4_encap == "IPIP":
            ipip_mode = "Always"
        vxlan_mode = "Never"
        if ipv4_encap == "VXLAN":
            vxlan_mode = "Always"
        # Patch default IPv4 to change IPIP mode depending on encap
        kubectl("patch --type=merge ippool default-ipv4-ippool --patch '{\"spec\": {\"ipipMode\": \"%s\", \"vxlanMode\": \"%s\"}}'" % (ipip_mode, vxlan_mode))

        # Create egress gateway IP pool.
        kubectl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: egress-ippool-1
spec:
  cidr: %s
  blockSize: %s
  nodeSelector: '!all()'
  ipipMode: %s
  vxlanMode: %s
EOF
""" % (egress_pool_cidr, block_size, ipip_mode, vxlan_mode))
        self.add_cleanup(lambda: kubectl("delete ippool egress-ippool-1"))

    def _test_external_net_basic(self, ipv4_encap):
        assert ipv4_encap in ["IPIP", "VXLAN", "None"]
        with DiagsCollector():
            # Create egress gateway IP pool and patch default IP pool
            egress_pool_cidr = "10.10.10.0/29"
            block_size = "29"
            self._setup_ippools(ipv4_encap, egress_pool_cidr, block_size)

            # Create ExternalNetworks
            kubectl("""apply -f - << EOF
kind: ExternalNetwork
apiVersion: projectcalico.org/v3
metadata:
  name: rednet
spec:
  routeTableIndex: 500
EOF
""")
            self.add_cleanup(lambda: kubectl("delete externalnetwork rednet", allow_fail=True))

            kubectl("""apply -f - << EOF
kind: ExternalNetwork
apiVersion: projectcalico.org/v3
metadata:
  name: bluenet
spec:
  routeTableIndex: 600
EOF
""")
            self.add_cleanup(lambda: kubectl("delete externalnetwork bluenet", allow_fail=True))

            kubectl("""apply -f - << EOF
kind: ExternalNetwork
apiVersion: projectcalico.org/v3
metadata:
  name: greennet
spec:
  routeTableIndex: 700
EOF
""")
            self.add_cleanup(lambda: kubectl("delete externalnetwork greennet", allow_fail=True))

            # Assign BGP peers to external networks
            self._patch_peer_external_net("peer-a1", "rednet")
            self._patch_peer_external_net("peer-b1", "bluenet")
            self._patch_peer_external_net("peer-b2", "bluenet")
            self._patch_peer_external_net("peer-c1", "greennet")

            # Create egress gateways
            gw_red = self.create_egress_gateway_pod("kind-worker", "gw-red", egress_pool_cidr, color="red", external_networks="rednet")

            gw_blue = self.create_egress_gateway_pod("kind-worker", "gw-blue", egress_pool_cidr, color="blue", external_networks="bluenet")

            gw_redgreen = self.create_egress_gateway_pod("kind-worker", "gw-redgreen", egress_pool_cidr, color="redgreen", external_networks=["rednet", "greennet"])

            for g in [gw_red, gw_blue, gw_redgreen]:
                g.wait_ready()

            # Create namespace for client pods with egress annotations on red gateway.
            client_ns = "ns-client"
            self.create_namespace(client_ns, annotations={
                "egress.projectcalico.org/selector": "color == 'red'",
                "egress.projectcalico.org/namespaceSelector": "all()",
            })

            # Create client with no annotations.
            client_no_annotations = NetcatClientTCP(client_ns, "test-red", node="kind-worker2")
            self.add_cleanup(client_no_annotations.delete)
            client_no_annotations.wait_ready()

            # Create client with annotation override to use gw-blue.
            client_annotation_override = NetcatClientTCP(client_ns, "test-blue", node="kind-worker", annotations={
                "egress.projectcalico.org/selector": "color == 'blue'",
                "egress.projectcalico.org/namespaceSelector": "all()",
            })
            self.add_cleanup(client_annotation_override.delete)
            client_annotation_override.wait_ready()

            # Create client that will be using gw_redgreeen EGW and running in the same node
            client_redgreen = NetcatClientTCP("default", "test-redgreen", node="kind-worker3", annotations={
                "egress.projectcalico.org/selector": "color == 'redgreen'",
                "egress.projectcalico.org/namespaceSelector": "all()",
            })
            self.add_cleanup(client_redgreen.delete)
            client_redgreen.wait_ready()

            server_A_addr = server_B_addr = "172.31.91.1"
            server_C_addr = "172.31.101.1"

            # Use retry_until_success for connectivity checks because the
            # dataplane may take time to converge after encap mode changes.
            def _retry_connect(client, server_addr, assert_text):
                client.check_connected(server_addr, 80, command="wget")
                self.assertIn(assert_text, client.last_output)

            # Verify that each client reaches the correct expected external server
            retry_until_success(_retry_connect, function_args=[client_no_annotations, server_A_addr, "server A"])

            retry_until_success(_retry_connect, function_args=[client_annotation_override, server_B_addr, "server B"])

            # Verify that a client connected to gw_redgreen can reach both external
            # servers in rednet and greennet correctly
            retry_until_success(_retry_connect, function_args=[client_redgreen, server_A_addr, "server A"])
            retry_until_success(_retry_connect, function_args=[client_redgreen, server_C_addr, "server C"])

            # Create a namespace for the cluster server
            server_ns = "ns-server"
            self.create_namespace(server_ns)

            # Add BGPConfiguration with serviceClusterIP
            kubectl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: BGPConfiguration
metadata:
  name: default
spec:
  serviceClusterIPs:
  - cidr: 10.96.0.0/12
EOF
""")

            # Create a Local type NodePort service with a single replica.
            local_svc = "nginx-local"
            self.deploy("nginx:latest", local_svc, server_ns, 80)
            self.wait_until_exists(local_svc, "svc", server_ns)

            # Get clusterIP.
            local_svc_ip = kubectl("get svc %s -n %s -o json | jq -r .spec.clusterIP" % (local_svc, server_ns)).strip()

            # Wait for the deployment to roll out.
            self.wait_for_deployment(local_svc, server_ns)

            # Create an export BGP filter that rejects the service IP range and
            # add it to bird-b1, bird-b2 and bird-c1
            kubectl("""apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: BGPFilter
metadata:
  name: test-filter-export-1
spec:
  exportV4:
  - cidr: 10.96.0.0/12
    matchOperator: In
    action: Reject
EOF
""")
            kubectl("patch --type=merge bgppeer peer-b1 --patch '{\"spec\": {\"filters\": [\"test-filter-export-1\"]}}'")
            self.add_cleanup(lambda: kubectl("patch --type=merge bgppeer peer-b1 --patch '{\"spec\": {\"filters\": []}}'"))
            kubectl("patch --type=merge bgppeer peer-b2 --patch '{\"spec\": {\"filters\": [\"test-filter-export-1\"]}}'")
            self.add_cleanup(lambda: kubectl("patch --type=merge bgppeer peer-b2 --patch '{\"spec\": {\"filters\": []}}'"))
            kubectl("patch --type=merge bgppeer peer-c1 --patch '{\"spec\": {\"filters\": [\"test-filter-export-1\"]}}'")
            self.add_cleanup(lambda: kubectl("patch --type=merge bgppeer peer-c1 --patch '{\"spec\": {\"filters\": []}}'"))
            self.add_cleanup(lambda: kubectl("delete bgpfilter test-filter-export-1"))

            # Assert that a route to the service IP range is present in bird-a1, which is not filtered
            retry_until_success(lambda: self.assertIn("10.96.0.0/12", run("docker exec bird-a1 ip r")))

            # Assert that a route to the service IP range is not present in the other external networks, which are filtered
            retry_until_success(lambda: self.assertNotIn("10.96.0.0/12", run("docker exec bird-b1 ip r")))
            retry_until_success(lambda: self.assertNotIn("10.96.0.0/12", run("docker exec bird-b2 ip r")))
            retry_until_success(lambda: self.assertNotIn("10.96.0.0/12", run("docker exec bird-c1 ip r")))

            # Assert that nginx service can be accessed from the external network.
            output = run("docker exec bird-a1 docker run --rm --network servernetA  alpine wget %s -O - --timeout 2" % local_svc_ip)
            self.assertIn("Welcome to nginx!", output)

            # Assert that nginx service cannot be accessed from a filtered external network.
            output = run("docker exec bird-b1 docker run --rm --network servernetB  alpine wget %s -O - --timeout 5" % local_svc_ip, allow_fail=True, returnerr=True)
            self.assertIn("wget: download timed out", output)

    def _test_external_net_recovery(self, ipv4_encap):
        assert ipv4_encap in ["IPIP", "VXLAN", "None"]
        with DiagsCollector():
            # Create egress gateway IP pool and patch default IP pool
            egress_pool_cidr = "10.10.10.0/29"
            block_size = "29"
            self._setup_ippools(ipv4_encap, egress_pool_cidr, block_size)

            # Create ExternalNetworks
            kubectl("""apply -f - << EOF
kind: ExternalNetwork
apiVersion: projectcalico.org/v3
metadata:
  name: rednet
spec:
  routeTableIndex: 500
EOF
""")
            self.add_cleanup(lambda: kubectl("delete externalnetwork rednet", allow_fail=True))

            # Assign BGP peers to external networks
            self._patch_peer_external_net("peer-a1", "rednet")

            # Create egress gateways
            gw_red = self.create_egress_gateway_pod("kind-worker", "gw-red", egress_pool_cidr, color="red", external_networks="rednet")

            for g in [gw_red]:
                g.wait_ready()

            # Create client with annotation override to use gw-red
            client_red = NetcatClientTCP("default", "test-red", node="kind-worker2", annotations={
                "egress.projectcalico.org/selector": "color == 'red'",
                "egress.projectcalico.org/namespaceSelector": "all()",
            })
            self.add_cleanup(client_red.delete)
            client_red.wait_ready()

            # Create client with no EGW
            client_no_gw = NetcatClientTCP("default", "test-no-gw", node="kind-worker")
            self.add_cleanup(client_no_gw.delete)
            client_no_gw.wait_ready()

            server_A_addr = server_B_addr = "172.31.91.1"

            # Verify that each client reaches the correct expected external server
            def _retry_connect(client, server_addr, assert_text):
                client.check_connected(server_addr, 80, command="wget")
                self.assertIn(assert_text, client.last_output)

            retry_until_success(_retry_connect, function_args=[client_red, server_A_addr, "server A"])

            retry_until_success(_retry_connect, function_args=[client_no_gw, server_B_addr, "server B"])

            # Verify a route to the server exists in the externalnetwork's route table
            retry_until_success(lambda: self.assertIn("172.31.91.0/24", kubectl("exec -n calico-system %s -- ip route list table 500" % self.get_calico_node_pod("kind-worker"))))

            # Restart Felix by updating log level.
            log_level = self.get_ds_env("calico-node", "calico-system", "FELIX_LOGSEVERITYSCREEN")
            if log_level == "Debug":
                new_log_level = "Info"
            else:
                new_log_level = "Debug"
            _log.info("--- Start restarting calico/node ---")
            oldEnv = {"FELIX_LOGSEVERITYSCREEN": log_level}
            newEnv = {"FELIX_LOGSEVERITYSCREEN": new_log_level}
            update_ds_env("calico-node", "calico-system", newEnv)
            self.add_cleanup(lambda: update_ds_env("calico-node", "calico-system", oldEnv))

            # Verify that each client still reaches the correct expected external server
            retry_until_success(_retry_connect, function_args=[client_red, server_A_addr, "server A"])

            retry_until_success(_retry_connect, function_args=[client_no_gw, server_B_addr, "server B"])

            # Delete the externalnetwork and verify that client_red now reaches server B
            kubectl("delete externalnetwork rednet")
            retry_until_success(_retry_connect, function_args=[client_red, server_A_addr, "server B"])
            # Verify a route to the server exists in the externalnetwork's route table
            retry_until_success(lambda: self.assertIn("172.31.91.0/24", kubectl("exec -n calico-system %s -- ip route list table 500" % self.get_calico_node_pod("kind-worker"))))

            # Recreate the externalnetwork and verify that client_red goes back to reaching server A
            kubectl("""apply -f - << EOF
kind: ExternalNetwork
apiVersion: projectcalico.org/v3
metadata:
  name: rednet
spec:
  routeTableIndex: 500
EOF
""")
            retry_until_success(_retry_connect, function_args=[client_red, server_A_addr, "server A"])
            # Verify a route to the server exists in the externalnetwork's route table
            retry_until_success(lambda: self.assertIn("172.31.91.0/24", kubectl("exec -n calico-system %s -- ip route list table 500" % self.get_calico_node_pod("kind-worker"))))

            # Delete the BGPPeer and verify that client_red cannot connect
            # Remove revision and UID information so we can re-apply cleanly.
            # This used to be done with --export, but that option has been removed from kubectl.
            out = kubectl("get bgppeer peer-a1 -o json")
            peer_a1 = json.loads(out)
            del peer_a1["metadata"]["resourceVersion"]
            del peer_a1["metadata"]["uid"]
            peer_a1_in = json.dumps(peer_a1).replace("'", "\\\"")
            kubectl("delete bgppeer peer-a1")
            self.add_cleanup(lambda:run("echo '%s' | kubectl apply -f -" % peer_a1_in, allow_fail=True))

            client_red.cannot_connect(server_A_addr, 80, command="wget")
            # Verify a route to the server exists in the externalnetwork's route table
            retry_until_success(lambda: self.assertIn("172.31.91.0/24", kubectl("exec -n calico-system %s -- ip route list table 500" % self.get_calico_node_pod("kind-worker"))))

            # Recreate the BGPPeer and verify that client_red can connect again
            run("echo '%s' | kubectl apply -f -" % peer_a1_in)
            retry_until_success(_retry_connect, function_args=[client_red, server_A_addr, "server A"])
            # Verify a route to the server exists in the externalnetwork's route table
            retry_until_success(lambda: self.assertIn("172.31.91.0/24", kubectl("exec -n calico-system %s -- ip route list table 500" % self.get_calico_node_pod("kind-worker"))))

    def _test_external_net_switchover(self, ipv4_encap):
        assert ipv4_encap in ["IPIP", "VXLAN", "None"]
        with DiagsCollector():
            # Connect and peer kind-worker3 to bird-c1
            run("docker network connect --ip=172.31.31.5 --ip6=fd00:0:1234:3333::5 enetC kind-worker3")
            kubectl("label node kind-worker3 egress=true --overwrite")
            nodes_enetC_original = run("docker exec -i bird-c1 sh -c 'cat /etc/bird/nodes-enetC.conf'")
            run("""cat <<EOF | docker exec -i bird-c1 sh -c "cat >> /etc/bird/nodes-enetC.conf"
protocol bgp node2 from nodes {
  neighbor 172.31.31.5 as 64512;
}
EOF
""")
            run("docker exec bird-c1 birdcl configure")
            self.add_cleanup(lambda: run("docker network disconnect enetC kind-worker3", allow_fail=True))
            self.add_cleanup(lambda: kubectl("label node kind-worker3 egress- --overwrite"))
            self.add_cleanup(lambda: run("""cat <<EOF | docker exec -i bird-c1 sh -c "cat >> /etc/bird/nodes-enetC.conf"
%s
EOF
""" % nodes_enetC_original))
            self.add_cleanup(lambda: run("docker exec bird-c1 birdcl configure"))

            # Create egress gateway IP pool and patch default IP pool
            egress_pool_cidr = "10.10.10.0/29"
            block_size = "29"
            self._setup_ippools(ipv4_encap, egress_pool_cidr, block_size)

            # Create ExternalNetwork
            kubectl("""apply -f - << EOF
kind: ExternalNetwork
apiVersion: projectcalico.org/v3
metadata:
  name: rednet
spec:
  routeTableIndex: 500
EOF
""")
            self.add_cleanup(lambda: kubectl("delete externalnetwork rednet", allow_fail=True))

            # Assign BGP peers to external networks
            self._patch_peer_external_net("peer-c1", "rednet")

            # Create 2 egress gateways, one on each egress node
            gw_red = self.create_egress_gateway_pod("kind-worker", "gw-red", egress_pool_cidr, color="red", external_networks="rednet")
            gw_red2 = self.create_egress_gateway_pod("kind-worker3", "gw-red2", egress_pool_cidr, color="red", external_networks="rednet")

            for g in [gw_red, gw_red2]:
                g.wait_ready()

            # Create client with annotation override to use gw-red
            client_red = NetcatClientTCP("default", "test-red", node="kind-worker2", annotations={
                "egress.projectcalico.org/selector": "color == 'red'",
                "egress.projectcalico.org/namespaceSelector": "all()",
            })
            self.add_cleanup(client_red.delete)
            client_red.wait_ready()

            server_C_addr = "172.31.101.1"

            # Verify that the client can reach the external server
            client_red.check_connected(server_C_addr, 80, command="wget")
            self.assertIn("server C", client_red.last_output)

            # Remove one egress gateway and verify that the client can still reach the external server
            gw_red.delete()
            self.cleanups.remove(gw_red.delete)

            client_red.check_connected(server_C_addr, 80, command="wget")
            self.assertIn("server C", client_red.last_output)

            # Recreate egress gateway, remove other, and verify that the client can still reach the external server
            gw_red = self.create_egress_gateway_pod("kind-worker", "gw-red", egress_pool_cidr, color="red", external_networks="rednet")
            gw_red.wait_ready()

            gw_red2.delete()
            self.cleanups.remove(gw_red2.delete)

            client_red.check_connected(server_C_addr, 80, command="wget")
            self.assertIn("server C", client_red.last_output)

            # Remove the other egress gateway and verify that the client cannot reach the external server
            gw_red.delete()
            self.cleanups.remove(gw_red.delete)

            client_red.cannot_connect(server_C_addr, 80, command="wget")

            # Recreate both egress gateways and verify that the client can reach the external server again
            gw_red = self.create_egress_gateway_pod("kind-worker", "gw-red", egress_pool_cidr, color="red", external_networks="rednet")
            gw_red2 = self.create_egress_gateway_pod("kind-worker3", "gw-red2", egress_pool_cidr, color="red", external_networks="rednet")

            for g in [gw_red, gw_red2]:
                g.wait_ready()

            client_red.check_connected(server_C_addr, 80, command="wget")
            self.assertIn("server C", client_red.last_output)

    def _test_external_net_multihop(self, ipv4_encap):
        """Test case for externalnetwork in which the external peer is not
        directly connected to the cluster. In this case, the cluster node
        kind-worker peers with bird-d1 through one hop via node-d1. Check
        that this external network can be reached correctly."""
        assert ipv4_encap in ["IPIP", "VXLAN", "None"]
        with DiagsCollector():
            # Create egress gateway IP pool and patch default IP pool
            block_size = "29"
            egress_pool_cidr = "10.10.10.0/%s" % block_size
            self._setup_ippools(ipv4_encap, egress_pool_cidr, block_size)

            # Create ExternalNetwork
            kubectl("""apply -f - << EOF
kind: ExternalNetwork
apiVersion: projectcalico.org/v3
metadata:
  name: greennet
spec:
  routeTableIndex: 700
EOF
""")
            self.add_cleanup(lambda: kubectl("delete externalnetwork greennet", allow_fail=True))

            # Assign BGP peer to external network
            self._patch_peer_external_net("peer-d1", "greennet")

            # Create egress gateway
            gw_green = self.create_egress_gateway_pod("kind-worker", "gw-green", egress_pool_cidr, color="green", external_networks=["greennet"])
            gw_green.wait_ready()

            # Add bootstrap route to the route table for greennet in the calico-node pod running on kind-worker
            kubectl("exec -n calico-system %s -- ip route add 172.31.51.0/24 via 172.31.41.1 table 700" % self.get_calico_node_pod("kind-worker"))
            self.add_cleanup(lambda: kubectl("exec -n calico-system %s -- ip route del 172.31.51.0/24 via 172.31.41.1 table 700" % self.get_calico_node_pod("kind-worker"), allow_fail=True))

            # Add bootstrap route to the EGW IP pool on node-d1
            run("docker exec node-d1 ip route add %s via 172.31.41.4" % egress_pool_cidr)
            self.add_cleanup(lambda: run("docker exec node-d1 ip route del %s via 172.31.41.4" % egress_pool_cidr))

            # Create a client with annotation overrides to use the egw
            client_green = NetcatClientTCP("default", "test-green", node="kind-worker2", annotations={
                "egress.projectcalico.org/selector": "color == 'green'",
                "egress.projectcalico.org/namespaceSelector": "all()",
            })
            self.add_cleanup(client_green.delete)
            client_green.wait_ready()

            server_D_addr = "172.31.91.1"
            # Verify that the server can be reached
            client_green.check_connected(server_D_addr, 80, command="wget")
            self.assertIn("server D", client_green.last_output)

    def test_external_net_basic_ipip(self):
        self._test_external_net_basic(ipv4_encap="IPIP")

    def test_external_net_basic_no_overlay(self):
        self._test_external_net_basic(ipv4_encap="None")

    def test_external_net_recovery_vxlan(self):
        self._test_external_net_recovery(ipv4_encap="VXLAN")

    def test_external_net_recovery_no_overlay(self):
        self._test_external_net_recovery(ipv4_encap="None")

    def test_external_net_switchover_no_overlay(self):
        self._test_external_net_switchover(ipv4_encap="None")

    def test_external_net_multihop_vxlan(self):
        self._test_external_net_multihop(ipv4_encap="VXLAN")

    def test_external_net_multihop_no_overlay(self):
        self._test_external_net_multihop(ipv4_encap="None")
