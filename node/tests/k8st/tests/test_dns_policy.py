# Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

import logging

from tests.k8st.test_base import TestBase
from tests.k8st.utils.utils import retry_until_success, kubectl, calicoctl

_log = logging.getLogger(__name__)


class TestDNSPolicy(TestBase):

    def setUp(self):
        super(TestDNSPolicy, self).setUp()

        # Create bgp test namespace
        self.ns = "dns-policy-test"
        self.create_namespace(self.ns)
        self.test1 = "test-1 -n " + self.ns

    def tearDown(self):
        super(TestDNSPolicy, self).tearDown()
        self.delete_and_confirm(self.ns, "ns")

        # Clean up policy.
        calicoctl("delete gnp default.allow-egress-to-domain || true")
        calicoctl("delete gnp default.deny-all-egress-except-dns || true")
        calicoctl("get gnp")

    def deny_all_egress_except_dns(self, selector):
        # Deny egress from selected pods, except for DNS.
        calicoctl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: deny-all-egress-except-dns
spec:
  selector: %s
  types:
  - Egress
  egress:
  - action: Allow
    protocol: UDP
    destination:
      ports:
      - 53
  - action: Deny
EOF
""" % selector)

    def allow_egress_to_domains(self, pod_selector, domains):
        domain_string = """
      domains:"""
        for domain in domains:
            domain_string = domain_string + """
      - %s""" % domain

        calicoctl("""apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-egress-to-domain
spec:
  order: 1
  selector: "%s"
  types:
  - Egress
  egress:
  - action: Allow
    destination:%s
EOF
""" % (pod_selector, domain_string))

    def test_internet_service(self):
        kubectl("""apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-1
  namespace: %s
  labels:
    egress: restricted
spec:
  containers:
  - name: alpine
    image: alpine
    command: ["/bin/sleep"]
    args: ["infinity"]
  terminationGracePeriodSeconds: 0
EOF
""" % self.ns)
        kubectl("wait --for=condition=ready pod/%s" % self.test1)
        kubectl("exec " + self.test1 + " -- apk add --no-cache wget")

        def should_connect():
            kubectl("exec " + self.test1 + " -- " +
                    #
                    # Test connection to microsoft.com, with:
                    #
                    # --max-redirect=0 .. Don't follow redirects; if
                    # we get a redirect, that's already enough to know
                    # that we've contacted the target domain name.
                    #
                    # -U firefox .. Pretend to be Firefox.
                    #
                    # -T 4 .. 4 second timeout for all network
                    # operations, including DNS lookups.
                    #
                    # -t 1 .. Only try connecting once.
                    #
                    # allow_codes=[8] .. 8 is the expected return code
                    # when connection succeeds but the server sends an
                    # HTTP failure response.
                    #
                    "wget --max-redirect=0 -U firefox -T 4 -t 1 microsoft.com",
                    allow_codes=[8])

        def should_not_connect():
            try:
                should_connect()
            except Exception:
                return
            raise Exception("should not have connected")

        # No policy.
        retry_until_success(should_connect, timeout=10)

        # Deny all egress.
        self.deny_all_egress_except_dns("egress == 'restricted'")
        retry_until_success(should_not_connect, timeout=10)

        # DNS policy.
        self.allow_egress_to_domains("egress == 'restricted'",
                                     ["microsoft.com", "www.microsoft.com"])
        retry_until_success(should_connect, timeout=10)


TestDNSPolicy.needs_tsee = True
