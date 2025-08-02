# Copyright 2016-2017 Tigera, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import json
import logging
import re
import subprocess
import time

import yaml
from nose_parameterized import parameterized

from tests.st.test_base import TestBase, HOST_IPV4
from tests.st.utils.docker_host import DockerHost
from tests.st.utils.utils import assert_number_endpoints, apply_cnx_license, ETCD_CA, ETCD_CERT, \
    ETCD_KEY, ETCD_HOSTNAME_SSL, ETCD_SCHEME, get_ip, log_and_run, retry_until_success, \
    wipe_etcd

_log = logging.getLogger(__name__)
_log.setLevel(logging.DEBUG)

POST_DOCKER_COMMANDS = [
    "docker load -i /code/calico-node.tar",
    "docker load -i /code/busybox.tar",
    "docker load -i /code/workload.tar",
]

if ETCD_SCHEME == "https":
    ADDITIONAL_DOCKER_OPTIONS = "--cluster-store=etcd://%s:2379 " \
                                "--cluster-store-opt kv.cacertfile=%s " \
                                "--cluster-store-opt kv.certfile=%s " \
                                "--cluster-store-opt kv.keyfile=%s " % \
                                (ETCD_HOSTNAME_SSL, ETCD_CA, ETCD_CERT,
                                 ETCD_KEY)
else:
    ADDITIONAL_DOCKER_OPTIONS = "--cluster-store=etcd://%s:2379 " % \
                                get_ip()


class TestFelixOnGateway(TestBase):
    hosts = None
    networks = None

    def setUp(self):
        _log.debug("Override the TestBase setUp() method which wipes etcd. Do nothing.")
        # Wipe policies and tiers before each test
        self.delete_all("globalnetworkpolicy")
        self.delete_all("tier")
        self.delete_all("hostEndpoint")

        # Wait for felix to remove the policy and allow traffic through the gateway.
        retry_until_success(self.assert_host_can_curl_ext)

    def tearDown(self):
        # Wipe policies and tiers after each test
        self.delete_all("globalnetworkpolicy")
        self.delete_all("tier")
        self.delete_all("hostEndpoint")
        super(TestFelixOnGateway, self).tearDown()

    def delete_all(self, resource):
        # Grab all objects of a resource type
        objects = yaml.load(self.hosts[0].calicoctl("get %s -o yaml" % resource))
        # and delete them (if there are any)
        if len(objects) > 0:
            _log.info("objects: %s", objects)
            if 'items' in objects:
                # Filter out object(s) representing the default tier.
                objects['items'] = [x for x in objects['items']
                                    if (x.get('kind', '') != 'Tier' or
                                        'metadata' not in x or
                                        x['metadata'].get('name', '') not in ['default', 'adminnetworkpolicy'])]
            if 'items' in objects and len(objects['items']) == 0:
                pass
            else:
                self._delete_data(objects, self.hosts[0])

    def _delete_data(self, data, host):
        _log.debug("Deleting data with calicoctl: %s", data)
        self._use_calicoctl("delete", data, host)

    @staticmethod
    def _use_calicoctl(action, data, host):
        # Delete creationTimestamp fields from the data that we're going to
        # write.
        for obj in data.get('items', []):
            if 'creationTimestamp' in obj['metadata']:
                del obj['metadata']['creationTimestamp']
        if 'metadata' in data and 'creationTimestamp' in data['metadata']:
            del data['metadata']['creationTimestamp']
        # use calicoctl with data
        host.writefile("new_data",
                       yaml.dump(data, default_flow_style=False))
        host.calicoctl("%s -f new_data" % action)

    @staticmethod
    def sleep(length):
        _log.debug("Sleeping for %s" % length)
        time.sleep(length)

    @classmethod
    def setUpClass(cls):
        _log.debug("Wiping etcd")
        wipe_etcd(HOST_IPV4)
        cls.policy_tier_name = "default"
        cls.next_tier_allowed = False

        # We set up an additional docker network to act as the external
        # network.  The Gateway container is connected to both networks.
        # and we configure it as a NAT gateway.
        #
        #  "cali-st-ext" host
        #   container
        #      |
        #  "cali-st-ext" docker
        #    bridge
        #      |
        #  Gateway           Host
        #  container         container
        #         \          /
        #        default docker
        #            bridge

        # First, create the hosts and the gateway.
        cls.hosts = []
        log_and_run("docker rm -f cali-st-gw || true")
        cls.gateway = DockerHost("cali-st-gw",
                                 additional_docker_options=ADDITIONAL_DOCKER_OPTIONS,
                                 post_docker_commands=POST_DOCKER_COMMANDS,
                                 start_calico=False)
        cls.gateway_hostname = cls.gateway.execute("hostname")
        log_and_run("docker rm -f cali-st-host || true")
        cls.host = DockerHost("cali-st-host",
                              additional_docker_options=ADDITIONAL_DOCKER_OPTIONS,
                              post_docker_commands=POST_DOCKER_COMMANDS,
                              start_calico=False)
        cls.host_hostname = cls.host.execute("hostname")
        cls.hosts.append(cls.gateway)
        cls.hosts.append(cls.host)

        # Delete the nginx container if it still exists.  We need to do this
        # before we try to remove the network.
        log_and_run("docker rm -f cali-st-ext-nginx || true")

        # Create the external network.
        log_and_run("docker network rm cali-st-ext || true")
        # Use 172.19.0.0 to avoid clash with normal docker subnet and
        # docker-in-docker subnet
        log_and_run("docker network create --driver bridge --subnet 172.19.0.0/16 cali-st-ext")

        # And an nginx server on the external network only.
        log_and_run("docker run --network=cali-st-ext -d --name=cali-st-ext-nginx nginx")

        # Add a Calico Enterprise license key
        apply_cnx_license(cls.hosts[0])

        for host in cls.hosts:
            host.start_calico_node()

        # Get the internal IP of the gateway.  We do this before we add the second
        # network since it means we don't have to figure out which IP is which.
        int_ip = cls.get_container_ip("cali-st-gw")
        cls.gateway_int_ip = int_ip
        _log.info("Gateway internal IP: %s", cls.gateway_int_ip)

        # Add the gateway to the external network.
        log_and_run("docker network connect cali-st-ext cali-st-gw")
        cls.gateway.execute("ip addr")

        # Get the IP of the external server.
        ext_ip = cls.get_container_ip("cali-st-ext-nginx")
        cls.ext_server_ip = ext_ip
        _log.info("External workload IP: %s", cls.ext_server_ip)

        # Configure the internal host to use the gateway for the external IP.
        cls.host.execute("ip route add %s via %s" %
                         (cls.ext_server_ip, cls.gateway_int_ip))

        # Configure the gateway to forward and NAT.
        cls.gateway.execute("sysctl -w net.ipv4.ip_forward=1")
        cls.gateway.execute("iptables -t nat -A POSTROUTING --destination %s -j MASQUERADE" %
                            cls.ext_server_ip)

        # Create workload networks.
        cls.networks = []
        cls.networks.append(cls.gateway.create_network("testnet2"))
        cls.sleep(10)

        cls.n1_workloads = []
        # Create two workloads on cls.hosts[0] and one on cls.hosts[1] all in network 1.
        cls.n1_workloads.append(cls.host.create_workload("workload_hn1_1",
                                                         image="workload",
                                                         network=cls.networks[0]))
        cls.sleep(2)
        cls.n1_workloads.append(cls.gateway.create_workload("workload_gwn1_1",
                                                            image="workload",
                                                            network=cls.networks[0]))
        # Assert that endpoints are in Calico
        assert_number_endpoints(cls.gateway, 1)
        assert_number_endpoints(cls.host, 1)

    @classmethod
    def get_container_ip(cls, container_name):
        ip = log_and_run(
            "docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' %s" %
            container_name)
        return ip.strip()

    @classmethod
    def tearDownClass(cls):
        # Tidy up
        for host in cls.hosts:
            host.remove_workloads()
        for network in cls.networks:
            network.delete()
        for host in cls.hosts:
            host.cleanup()
            del host
        log_and_run("docker rm -f cali-st-ext-nginx || true")
        _log.debug("Wiping etcd")
        wipe_etcd(HOST_IPV4)

    def test_ingress_policy_can_block_through_traffic(self):
        self.add_admin_tier()
        self.add_policy({
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkPolicy',
            'metadata': {'name': 'admin.port80-int'},
            'spec': {
                'tier': 'admin',
                'order': 10,
                'ingress': [
                    {
                        'protocol': 'TCP',
                        'destination': {'ports': [80]},
                        'action': 'Deny'
                    },
                ],
                'egress': [
                    {'action': 'Deny'},
                ],
                'applyOnForward': True,
                'selector': 'role == "gateway-int"'
            }
        })
        self.add_gateway_internal_iface()
        retry_until_success(self.assert_host_can_not_curl_ext, 3)

    def test_ingress_policy_can_allow_through_traffic(self):
        self.add_admin_tier()
        self.add_policy({
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkPolicy',
            'metadata': {'name': 'admin.port80-int'},
            'spec': {
                'tier': 'admin',
                'order': 10,
                'ingress': [
                    {
                        'protocol': 'TCP',
                        'destination': {'ports': [80]},
                        'action': 'Allow'
                    },
                ],
                'egress': [
                    {'action': 'Deny'},
                ],
                'selector': 'role == "gateway-int"'
            }
        })
        self.add_gateway_internal_iface()
        retry_until_success(self.assert_host_can_curl_ext, 3)

    def test_egress_policy_can_block_through_traffic(self):
        self.add_admin_tier()
        self.add_policy({
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkPolicy',
            'metadata': {'name': 'admin.port80-ext'},
            'spec': {
                'tier': 'admin',
                'order': 10,
                'ingress': [
                    {
                        'action': 'Deny',
                    },
                ],
                'egress': [
                    {
                        'protocol': 'TCP',
                        'destination': {'ports': [80]},
                        'action': 'Deny'
                    },
                ],
                'applyOnForward': True,
                'selector': 'role == "gateway-ext"'
            }
        })
        self.add_gateway_external_iface()
        retry_until_success(self.assert_host_can_not_curl_ext, 3)

    def test_egress_policy_can_allow_through_traffic(self):
        self.add_admin_tier()
        self.add_policy({
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkPolicy',
            'metadata': {'name': 'admin.port80-ext'},
            'spec': {
                'tier': 'admin',
                'order': 10,
                'ingress': [
                    {
                        'action': 'Deny',
                    },
                ],
                'egress': [
                    {
                        'protocol': 'TCP',
                        'destination': {'ports': [80]},
                        'action': 'Allow'
                    },
                ],
                'selector': 'role == "gateway-ext"'
            }
        })
        self.add_gateway_external_iface()
        retry_until_success(self.assert_host_can_curl_ext, 3)

    def test_ingress_and_egress_policy_can_allow_through_traffic(self):
        self.add_admin_tier()
        self.add_gateway_external_iface()
        self.add_gateway_internal_iface()
        self.add_host_iface()

        # Adding the host endpoints should break connectivity until we add policy back in.
        retry_until_success(self.assert_host_can_not_curl_ext, 3)

        # Add in the policy...
        self.add_policy({
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkPolicy',
            'metadata': {'name': 'admin.host-out'},
            'spec': {
                'tier': 'admin',
                'order': 10,
                'selector': 'role == "host"',
                'egress': [{'action': 'Allow'}],
                'ingress': [{'action': 'Allow'}],
            }
        })
        self.add_policy({
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkPolicy',
            'metadata': {'name': 'admin.port80-int'},
            'spec': {
                'tier': 'admin',
                'order': 10,
                'ingress': [
                    {
                        'protocol': 'TCP',
                        'destination': {
                            'ports': [80],
                            'nets': [self.ext_server_ip + "/32"],
                        },
                        'source': {
                            'selector': 'role == "host"',
                        },
                        'action': 'Allow'
                    },
                ],
                'egress': [],
                'selector': 'role == "gateway-int"'
            }
        })
        self.add_policy({
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkPolicy',
            'metadata': {'name': 'admin.port80-ext'},
            'spec': {
                'tier': 'admin',
                'order': 10,
                'ingress': [],
                'egress': [
                    {
                        'protocol': 'TCP',
                        'destination': {
                            'ports': [80],
                            'nets': [self.ext_server_ip + "/32"],
                        },
                        'source': {
                            'selector': 'role == "host"',
                        },
                        'action': 'Allow'
                    },
                ],
                'selector': 'role == "gateway-ext"'
            }
        })
        retry_until_success(self.assert_host_can_curl_ext, 3)

    @parameterized.expand([
        ('Allow', 'Deny'),
        ('Deny', 'Allow')
    ])
    def test_conflicting_ingress_and_egress_policy(self, in_action, out_action):
        # If there is policy on the ingress and egress interface then both should
        # get applied and 'Deny' should win.
        self.add_admin_tier()
        self.add_host_iface()
        self.add_gateway_external_iface()
        self.add_gateway_internal_iface()

        self.add_policy({
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkPolicy',
            'metadata': {'name': 'admin.port80-int'},
            'spec': {
                'tier': 'admin',
                'order': 10,
                'ingress': [
                    {
                        'action': in_action
                    },
                ],
                'egress': [],
                'selector': 'role == "gateway-int"'
            }
        })
        self.add_policy({
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkPolicy',
            'metadata': {'name': 'admin.port80-ext'},
            'spec': {
                'tier': 'admin',
                'order': 10,
                'ingress': [],
                'egress': [
                    {
                        'action': out_action
                    },
                ],
                'selector': 'role == "gateway-ext"'
            }
        })
        retry_until_success(self.assert_host_can_not_curl_ext, 3)

    def add_policy(self, policy_data):
        self._apply_resources(policy_data, self.gateway)

    def add_admin_tier(self):
        tier_data = {
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'Tier',
            'metadata': {'name': 'admin'},
            'spec': {'order': 1}
        }
        self._apply_resources(tier_data, self.gateway)

    def add_gateway_internal_iface(self):
        host_endpoint_data = {
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'HostEndpoint',
            'metadata': {
                'name': 'gw-int',
                'labels': {'role': 'gateway-int'}
            },
            'spec': {
                'node': self.gateway_hostname,
                'interfaceName': 'eth0'
            }
        }
        self._apply_resources(host_endpoint_data, self.gateway)

    def add_gateway_external_iface(self):
        host_endpoint_data = {
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'HostEndpoint',
            'metadata': {
                'name': 'gw-ext',
                'labels': {'role': 'gateway-ext'}
            },
            'spec': {
                'node': self.gateway_hostname,
                'interfaceName': 'eth1'
            }
        }
        self._apply_resources(host_endpoint_data, self.gateway)

    def add_host_iface(self):
        host_endpoint_data = {
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'HostEndpoint',
            'metadata': {
                'name': 'host-int',
                'labels': {'role': 'host'}
            },
            'spec': {
                'node': self.host_hostname,
                'interfaceName': 'eth0',
                'expectedIPs': [self.get_container_ip('cali-st-host')],
            }
        }
        self._apply_resources(host_endpoint_data, self.gateway)

    @classmethod
    def _apply_resources(cls, resources, host):
        cls._exec_calicoctl("apply", resources, host)

    @staticmethod
    def _exec_calicoctl(action, data, host):
        # Delete creationTimestamp fields from the data that we're going to
        # write.
        for obj in data.get('items', []):
            if 'creationTimestamp' in obj['metadata']:
                del obj['metadata']['creationTimestamp']
        if 'metadata' in data and 'creationTimestamp' in data['metadata']:
            del data['metadata']['creationTimestamp']

        # Use calicoctl with the modified data.
        host.writejson("new_data", data)
        host.calicoctl("%s -f new_data" % action)

    def assert_host_can_curl_ext(self):
        try:
            self.host.execute("curl -m 2 %s" % self.ext_server_ip)
        except subprocess.CalledProcessError:
            _log.exception("Internal host failed to curl external server IP: %s",
                           self.ext_server_ip)
            self.fail(
                "Internal host failed to curl external server IP: %s" % self.ext_server_ip)

    def assert_host_can_not_curl_ext(self):
        try:
            self.host.execute("curl -m 1 %s" % self.ext_server_ip)
        except subprocess.CalledProcessError:
            return
        else:
            self.fail("Internal host can curl external server IP: %s" % self.ext_server_ip)


class IpNotFound(Exception):
    pass
