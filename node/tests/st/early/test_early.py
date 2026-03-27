# Copyright (c) 2021 Tigera, Inc. All rights reserved.

import logging
import os
import shutil
import tempfile
import time

from tests.st.test_base import TestBase
from tests.st.utils.docker_host import CHECKOUT_DIR, NODE_CONTAINER_NAME
from tests.st.utils.utils import log_and_run
from tests.k8st.utils.utils import retry_until_success

_log = logging.getLogger(__name__)
_log.setLevel(logging.DEBUG)

class TestEarly(TestBase):

    def setUp(self):
        self.cfgpath = "/code/early_cfg.yaml"
        if os.path.exists(self.cfgpath):
            os.remove(self.cfgpath)

    def tearDown(self):
        log_and_run("docker rm -f calico-early-test", raise_exception_on_failure=False)
        log_and_run("docker rm -f calico-early", raise_exception_on_failure=False)
        log_and_run("docker network rm plane1", raise_exception_on_failure=False)
        log_and_run("docker network rm plane2", raise_exception_on_failure=False)
        if os.path.exists(self.cfgpath):
            os.remove(self.cfgpath)

    def start_early_container(self):
        log_and_run("docker network create --subnet=10.19.11.0/24 --ip-range=10.19.11.0/24 plane1")
        log_and_run("docker network create --subnet=10.19.12.0/24 --ip-range=10.19.12.0/24 plane2")
        log_and_run("docker create --privileged --name calico-early" +
                    " -v " + CHECKOUT_DIR + ":/code" +
                    " -e CALICO_EARLY_NETWORKING=" + self.cfgpath +
                    " --net=plane1 tigera/node:test-build")
        log_and_run("docker network connect plane2 calico-early")
        log_and_run("docker start calico-early")
        retry_until_success(lambda: log_and_run("docker exec calico-early /bin/calico-node -v"),
                            retries=3)

    def early_networking_setup_done(self):
        # Check the container's log.
        logs = log_and_run("docker logs calico-early")
        assert "Early networking set up; now monitoring BIRD" in logs

        # Check that BIRD is running.
        protocols = log_and_run("docker exec calico-early birdcl show protocols")
        assert "tor1" in protocols
        assert "tor2" in protocols
        routes = log_and_run("docker exec calico-early birdcl show route")
        assert "10.19.10.19/32" in routes

    def write_config(self, ips, peer_ip_1='10.19.11.1', peer_ip_2='10.19.12.1'):
        f = open(self.cfgpath, "w")
        f.write("""
kind: EarlyNetworkConfiguration
spec:
  nodes:
    - interfaceAddresses:
        - %s
        - %s
      stableAddress:
        address: 10.19.10.19
      asNumber: 65432
      peerings:
        - peerIP: %s
        - peerIP: %s
""" % (ips[0], ips[1], peer_ip_1, peer_ip_2))
        f.close()
        _log.info("Wrote early networking config to " + self.cfgpath)

    def access_stable_address(self, ips):
        # Create a test container on the same networks.
        log_and_run("docker create --privileged --name calico-early-test" +
                    " --net=plane1 spaster/alpine-sleep")
        log_and_run("docker network connect plane2 calico-early-test")
        log_and_run("docker start calico-early-test")
        retry_until_success(lambda: log_and_run("docker exec calico-early-test ip r"),
                            retries=3)
        log_and_run("docker exec calico-early-test apk update")
        log_and_run("docker exec calico-early-test apk add iproute2 iputils")
        log_and_run("docker exec calico-early-test ip r a 10.19.10.19/32" +
                    " nexthop via " + ips[0] +
                    " nexthop via " + ips[1])
        log_and_run("docker exec calico-early-test ip r")

        # Check that the test container can ping the early container
        # on its stable address.
        pings = log_and_run("docker exec calico-early-test ping -c 7 10.19.10.19")
        assert "7 received, 0% packet loss" in pings

    def test_early(self):
        self.start_early_container()

        # Get IP addresses.
        ips = log_and_run("docker inspect '--format={{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' calico-early").strip().split()
        assert len(ips) == 2, "calico-early container should have two IP addresses"

        # Write early networking config.
        self.write_config(ips)

        # Check setup succeeds.
        retry_until_success(self.early_networking_setup_done, timeout=10)

        # Check access to the stable address from another container.
        self.access_stable_address(ips)

    def test_wrong_ips(self):
        self.start_early_container()

        # Get IP addresses.
        ips = log_and_run("docker inspect '--format={{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' calico-early").strip().split()
        assert len(ips) == 2, "calico-early container should have two IP addresses"

        # Write early networking config with wrong IPs.
        wrong_ips = ['10.24.0.1', '10.25.0.1']
        assert wrong_ips[0] not in ips
        assert wrong_ips[1] not in ips
        self.write_config(wrong_ips)

        # Setup should fail.
        time.sleep(5)
        try:
            self.early_networking_setup_done()
            self.fail("Setup succeeded when expected to fail")
        except Exception:
            pass

        # Now rewrite config with correct IPs.
        self.write_config(ips)
        retry_until_success(self.early_networking_setup_done, timeout=10)

        # Check access to the stable address from another container.
        self.access_stable_address(ips)

    def test_bad_peer_ip(self):
        self.start_early_container()

        # Get IP addresses.
        ips = log_and_run("docker inspect '--format={{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' calico-early").strip().split()
        assert len(ips) == 2, "calico-early container should have two IP addresses"

        # Write early networking config with bad peer IP.
        self.write_config(ips, peer_ip_1="10.24.1.67.8")

        # Setup should fail.
        time.sleep(5)
        try:
            self.early_networking_setup_done()
            self.fail("Setup succeeded when expected to fail")
        except Exception:
            pass

        # Now rewrite config with correct IPs.
        self.write_config(ips)
        # Allow 3s between retries, so as to allow time for 5s overall for
        # listen port checking in the case where sv says the early BIRD started
        # up but it didn't really.
        retry_until_success(self.early_networking_setup_done, timeout=20)

        # Check access to the stable address from another container.
        self.access_stable_address(ips)
