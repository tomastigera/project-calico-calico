# Copyright (c) 2018 Tigera, Inc. All rights reserved.
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
import os
import re
import subprocess
import time
from datetime import datetime
from pprint import pformat
from unittest import TestCase

from deepdiff import DeepDiff
from kubernetes import client, config

from utils.utils import retry_until_success, run, kubectl, copy_cnx_pull_secret

logger = logging.getLogger(__name__)


first_log_time = None


class TestBase(TestCase):

    """
    Base class for test-wide methods.
    """

    def setUp(self):
        """
        Set up before every test.
        """
        super(TestBase, self).setUp()
        self.cluster = self.k8s_client()
        self.cleanups = []

        # Log a newline to ensure that the first log appears on its own line.
        logger.info("")

    def tearDown(self):
        errors = []
        for cleanup in reversed(self.cleanups):
            try:
                cleanup()
            except Exception as e:
                errors.append(e)
        super(TestBase, self).tearDown()
        if errors:
            raise Exception("Errors during cleanup: %s" % errors)

    def add_cleanup(self, cleanup):
        self.cleanups.append(cleanup)

    @staticmethod
    def assert_same(thing1, thing2):
        """
        Compares two things.  Debug logs the differences between them before
        asserting that they are the same.
        """
        assert cmp(thing1, thing2) == 0, \
            "Items are not the same.  Difference is:\n %s" % \
            pformat(DeepDiff(thing1, thing2), indent=2)

    @staticmethod
    def writejson(filename, data):
        """
        Converts a python dict to json and outputs to a file.
        :param filename: filename to write
        :param data: dictionary to write out as json
        """
        with open(filename, 'w') as f:
            text = json.dumps(data,
                              sort_keys=True,
                              indent=2,
                              separators=(',', ': '))
            logger.debug("Writing %s: \n%s" % (filename, text))
            f.write(text)

    @staticmethod
    def log_banner(msg, *args, **kwargs):
        global first_log_time
        time_now = time.time()
        if first_log_time is None:
            first_log_time = time_now
        time_now -= first_log_time
        elapsed_hms = "%02d:%02d:%02d " % (time_now / 3600,
                                           (time_now % 3600) / 60,
                                           time_now % 60)

        level = kwargs.pop("level", logging.INFO)
        msg = elapsed_hms + str(msg) % args
        banner = "+" + ("-" * (len(msg) + 2)) + "+"
        logger.log(level, "\n" +
                   banner + "\n"
                            "| " + msg + " |\n" +
                   banner)

    @staticmethod
    def k8s_client():
        config.load_kube_config(os.environ.get('KUBECONFIG'))
        return client.CoreV1Api()

    def check_pod_status(self, ns):
        pods = self.cluster.list_namespaced_pod(ns)

        for pod in pods.items:
            logger.info("%s\t%s\t%s", pod.metadata.name, pod.metadata.namespace, pod.status.phase)
            if pod.status.phase != 'Running':
                kubectl("describe po %s -n %s" % (pod.metadata.name, pod.metadata.namespace))
            assert pod.status.phase == 'Running'

    def create_namespace(self, ns_name, labels=None, annotations=None):
        self.cluster.create_namespace(client.V1Namespace(metadata=client.V1ObjectMeta(name=ns_name, labels=labels, annotations=annotations)))
        self.add_cleanup(lambda: self.delete_and_confirm(ns_name, "ns"))

    def deploy(self, image, name, ns, port, replicas=1, svc_type="NodePort", traffic_policy="Local", cluster_ip=None, ipv6=False):
        """
        Creates a deployment and corresponding service with the given
        parameters.
        """
        # Use a pod anti-affinity so that the scheduler prefers deploying the
        # pods on different nodes. This makes our tests more reliable, since
        # some tests expect pods to be scheduled to different nodes.
        selector = {'matchLabels': {'app': name}}
        terms = [client.V1WeightedPodAffinityTerm(
            pod_affinity_term=client.V1PodAffinityTerm(
                label_selector=selector,
                topology_key="kubernetes.io/hostname"),
            weight=100,
            )]
        anti_aff = client.V1PodAntiAffinity(
                preferred_during_scheduling_ignored_during_execution=terms)

        # Run a deployment with <replicas> copies of <image>, with the
        # pods labelled with "app": <name>.
        deployment = client.V1Deployment(
            api_version="apps/v1",
            kind="Deployment",
            metadata=client.V1ObjectMeta(name=name),
            spec=client.V1DeploymentSpec(
                replicas=replicas,
                selector=selector,
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(labels={"app": name}),
                    spec=client.V1PodSpec(
                        affinity=client.V1Affinity(pod_anti_affinity=anti_aff),
                        containers=[
                          client.V1Container(name=name,
                                             image=image,
                                             ports=[client.V1ContainerPort(container_port=port)]),
                    ]))))

        # Create the deployment.
        api_response = client.AppsV1Api().create_namespaced_deployment(
            body=deployment,
            namespace=ns)
        logger.debug("Deployment created. status='%s'" % str(api_response.status))

        # Create a service called <name> whose endpoints are the pods
        # with "app": <name>; i.e. those just created above.
        self.create_service(name, name, ns, port, svc_type, traffic_policy, ipv6=ipv6)

    def wait_for_deployment(self, name, ns):
        """
        Waits for the given deployment to have the desired number of replicas.
        """
        logger.info("Checking status for deployment %s/%s" % (ns, name))
        kubectl("-n %s rollout status deployment/%s" % (ns, name))
        kubectl("get pods -n %s -o wide" % ns)

    def create_service(self, name, app, ns, port, svc_type="NodePort", traffic_policy="Local", cluster_ip=None, ipv6=False):
        service = client.V1Service(
            metadata=client.V1ObjectMeta(
                name=name,
                labels={"name": name},
            ),
            spec={
                "ports": [{"port": port}],
                "selector": {"app": app},
                "type": svc_type,
            }
        )
        if traffic_policy:
            service.spec["externalTrafficPolicy"] = traffic_policy
        if cluster_ip:
          service.spec["clusterIP"] = cluster_ip
        if ipv6:
          service.spec["ipFamilies"] = ["IPv6"]

        api_response = self.cluster.create_namespaced_service(
            body=service,
            namespace=ns,
        )
        logger.debug("Additional Service created. status='%s'" % str(api_response.status))

    def wait_until_exists(self, name, resource_type, ns="default"):
        retry_until_success(kubectl, function_args=["get %s %s -n%s" %
                                                    (resource_type, name, ns)])

    def delete(self, name, resource_type, ns="default", wait="true"):
        try:
            kubectl("delete %s %s -n %s --wait=%s" % (resource_type, name, ns, wait))
        except subprocess.CalledProcessError:
            pass

    def confirm_deletion(self, name, resource_type, ns="default"):
        def is_it_gone_yet(res_name, res_type):
            try:
                kubectl("get %s %s -n %s" % (res_type, res_name, ns),
                        logerr=False)
                raise self.StillThere
            except subprocess.CalledProcessError:
                # Success
                pass

        retry_until_success(is_it_gone_yet, retries=10, wait_time=10, function_args=[name, resource_type])

    def delete_and_confirm(self, name, resource_type, ns="default", wait="true"):
        self.delete(name, resource_type, ns, wait)
        self.confirm_deletion(name, resource_type, ns)

    class StillThere(Exception):
        pass

    def get_routes(self):
        return run("docker exec kube-node-extra ip r")

    def annotate_resource(self, res_type, res_name, ns, k, v):
        return run("kubectl annotate %s %s -n %s %s=%s" % (res_type, res_name, ns, k, v)).strip()

    def get_node_ips_with_local_pods(self, ns, label_selector):
        config.load_kube_config(os.environ.get('KUBECONFIG'))
        api = client.CoreV1Api(client.ApiClient())
        pods = api.list_namespaced_pod(ns, label_selector=label_selector)
        node_names = map(lambda x: x.spec.node_name, pods.items)
        node_ips = []
        for n in node_names:
            addrs = api.read_node(n).status.addresses
            for a in addrs:
                if a.type == 'InternalIP':
                    node_ips.append(a.address)
        return node_ips

    def get_ds_env(self, ds, ns, key):
        config.load_kube_config(os.environ.get('KUBECONFIG'))
        api = client.AppsV1Api(client.ApiClient())
        node_ds = api.read_namespaced_daemon_set(ds, ns, exact=True, export=False)
        for container in node_ds.spec.template.spec.containers:
            if container.name == ds:
                for env in container.env:
                    if env.name == key:
                        return env.value
        return None

    def scale_deployment(self, deployment, ns, replicas):
        return kubectl("scale deployment %s -n %s --replicas %s" %
                       (deployment, ns, replicas)).strip()

    def create_egress_gateway_pod(self, host, name, egress_pool_cidr, color="red", ns="default", termgraceperiod=0, probe_url="", icmp_probes="", external_networks=""):
        """
        Create egress gateway pod, with an IP from that pool.
        """
        copy_cnx_pull_secret(ns)

        ext_net_annotation = ""
        if external_networks != "":
            ext_net_val = ""
            if isinstance(external_networks, list):
                ext_net_val = "\\\"" + "\\\", \\\"".join(external_networks) + "\\\""
            else:
                ext_net_val = "\\\"" + external_networks + "\\\""
            ext_net_annotation = """egress.projectcalico.org/externalNetworkNames: "[%s]"
""" % ext_net_val

        gateway = Pod(ns, name, image=None, yaml="""
apiVersion: v1
kind: Pod
metadata:
  annotations:
    cni.projectcalico.org/ipv4pools: "[\\\"%s\\\"]"
    %s
  labels:
    color: %s
  name: %s
  namespace: %s
spec:
  imagePullSecrets:
  - name: cnx-pull-secret
  initContainers:
  - name: egress-gateway-init
    image: docker.io/tigera/egress-gateway:latest-amd64
    env:
    - name: EGRESS_POD_IPS
      valueFrom:
        fieldRef:
          fieldPath: status.podIPs
    - name: EGRESS_VXLAN_PORT
      value: "4790"
    - name: EGRESS_VXLAN_VNI
      value: "4097"
    imagePullPolicy: Never
    securityContext:
      privileged: true
    command: ["/init-gateway.sh"]
  containers:
  - name: gateway
    image: docker.io/tigera/egress-gateway:latest-amd64
    env:
    # Optional: comma-delimited list of IP addresses to send ICMP pings to; if all probes fail, the egress
    # gateway will report non-ready.
    - name: ICMP_PROBE_IPS
      value: "%s"
    # Only used if ICMP_PROBE_IPS is non-empty: interval to send probes.
    - name: ICMP_PROBE_INTERVAL
      value: "1s"
    # Only used if ICMP_PROBE_IPS is non-empty: timeout on each probe.
    - name: ICMP_PROBE_TIMEOUT
      value: "3s"
    # Optional HTTP URL to send periodic probes to; if the probe fails that is reflected in
    # the health reported on the health port.
    - name: HTTP_PROBE_URL
      value: "%s"
    # Only used if HTTP_PROBE_URL is non-empty: interval to send probes.
    - name: HTTP_PROBE_INTERVAL
      value: "10s"
    # Only used if HTTP_PROBE_URL is non-empty: timeout before reporting non-ready if there are no successful probes.
    - name: HTTP_PROBE_TIMEOUT
      value: "30s"
    # Port that the egress gateway serves its health reports.  Must match the readiness probe and health
    # port defined below.
    - name: HEALTH_PORT
      value: "8080"
    - name: LOG_SEVERITY
      value: "Info"
    - name: EGRESS_VXLAN_VNI
      value: "4097"
    # Use downward API to tell the pod its own IP address.
    - name: EGRESS_POD_IPS
      valueFrom:
        fieldRef:
          fieldPath: status.podIPs
    imagePullPolicy: Never
    securityContext:
      capabilities:
        add: ["NET_ADMIN"]
    command: ["/start-gateway.sh"]
    volumeMounts:
        - mountPath: /var/run/calico
          name: policysync
    ports:
        - name: health
          containerPort: 8080
    readinessProbe:
        httpGet:
          path: /readiness
          port: 8080
        initialDelaySeconds: 3
        periodSeconds: 3
  nodeName: %s
  terminationGracePeriodSeconds: %d
  volumes:
      - flexVolume:
          driver: nodeagent/uds
        name: policysync
""" % (egress_pool_cidr, ext_net_annotation, color, name, ns, icmp_probes, probe_url, host, termgraceperiod))
        self.add_cleanup(gateway.delete)

        return gateway

    def get_calico_node_pod(self, nodeName):
        """Get the calico-node pod name for a given kind node"""
        def fn():
            calicoPod = kubectl("-n kube-system get pods -o wide | grep calico-node | grep '%s '| cut -d' ' -f1" % nodeName)
            if calicoPod is None:
                raise Exception('calicoPod is None')
            return calicoPod.strip()
        calicoPod = retry_until_success(fn)
        return calicoPod


# Default is for K8ST tests to run vanilla tests, and not to run
# specialized tests (e.g., dual_dor, egress_ip).
# Individual test classes can override this.
TestBase.vanilla = True
TestBase.dual_tor = False
TestBase.egress_ip = False


class Container(object):

    def __init__(self, image, args, flags=""):
        self.id = run("docker run --rm -d --net=kind %s %s %s" % (
            flags,
            image,
            args)).strip().split("\n")[-1].strip()
        self._ip = None

    def kill(self):
        run("docker rm -f %s" % self.id)

    def inspect(self, template):
        return run("docker inspect -f '%s' %s" % (template, self.id))

    def running(self):
        return self.inspect("{{.State.Running}}").strip()

    def assert_running(self):
        assert self.running() == "true"

    def wait_running(self):
        retry_until_success(self.assert_running)

    @property
    def ip(self):
        if not self._ip:
            self._ip = self.inspect(
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
            ).strip()
        return self._ip

    def logs(self):
        return run("docker logs %s 2>&1" % self.id)

    def execute(self, cmd):
        return run("docker exec %s %s" % (self.id, cmd))


class Pod(object):

    def __init__(self, ns, name, node=None, image=None, labels=None, annotations=None, yaml=None, cmd=None):
        if yaml:
            # Caller has provided the complete pod YAML.
            kubectl("""apply -f - <<'EOF'
%s
EOF
""" % yaml)
        else:
            # Build YAML with specified namespace, name and image.
            pod = {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": name,
                    "namespace": ns,
                },
                "spec": {
                    "containers": [
                        {
                            "name": name,
                            "image": image,
                        },
                    ],
                    "terminationGracePeriodSeconds": 0,
                },
            }
            if node:
                pod["spec"]["nodeName"] = node
            if annotations:
                pod["metadata"]["annotations"] = annotations
            if labels:
                pod["metadata"]["labels"] = labels
            if cmd:
                pod["spec"]["containers"][0]["command"] = cmd
            kubectl("""apply -f - <<'EOF'
%s
EOF
""" % json.dumps(pod))

        self.name = name
        self.ns = ns
        self._ip = None
        self._hostip = None
        self._nodename = None

    def delete(self):
        kubectl("delete pod/%s -n %s" % (self.name, self.ns))

    def wait_ready(self):
        kubectl("wait --for=condition=ready pod/%s -n %s --timeout=300s" % (self.name, self.ns))

    def wait_not_ready(self):
        kubectl("wait --for=condition=Ready=false pod/%s -n %s --timeout=300s" % (self.name, self.ns))

    @property
    def ip(self):
        start_time = time.time()
        while not self._ip:
            assert time.time() - start_time < 30, "Pod failed to get IP address within 30s"
            ip = run("kubectl get po %s -n %s -o json | jq '.status.podIP'" % (self.name, self.ns)).strip().strip('"')
            if ip != "null":
                self._ip = ip
                break
            time.sleep(0.1)
        return self._ip

    @property
    def hostip(self):
        if not self._hostip:
            self._hostip = run("kubectl get po %s -n %s -o json | jq '.status.hostIP'" %
                           (self.name, self.ns)).strip().strip('"')
        return self._hostip

    @property
    def nodename(self):
        if not self._nodename:
            # spec.nodeName will be populated for a running pod regardless of being specified or not on pod creation.
            self._nodename = run("kubectl get po %s -n %s -o json | jq '.spec.nodeName'" %
                               (self.name, self.ns)).strip().strip('"')
        return self._nodename

    @property
    def annotations(self):
        return json.loads(run("kubectl get po %s -n %s -o json | jq '.metadata.annotations'" %
                           (self.name, self.ns)).strip().strip('"'))

    def execute(self, cmd, timeout=0):
        return kubectl("exec %s -n %s -- %s" % (self.name, self.ns, cmd), timeout=timeout)


class Container(object):

    def __init__(self, image, args, flags=""):
        self.id = run("docker run --rm -d --net=kind %s %s %s" % (
            flags,
            image,
            args)).strip().split("\n")[-1].strip()
        self._ip = None

    def kill(self):
        run("docker rm -f %s" % self.id)

    def inspect(self, template):
        return run("docker inspect -f '%s' %s" % (template, self.id))

    def running(self):
        return self.inspect("{{.State.Running}}").strip()

    def assert_running(self):
        assert self.running() == "true"

    def wait_running(self):
        retry_until_success(self.assert_running)

    @property
    def ip(self):
        if not self._ip:
            self._ip = self.inspect(
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
            ).strip()
        return self._ip

    def logs(self):
        return run("docker logs %s 2>&1" % self.id)

    def execute(self, cmd):
        return run("docker exec %s %s" % (self.id, cmd))


class Pod(object):

    def __init__(self, ns, name, node=None, image=None, labels=None, annotations=None, yaml=None, cmd=None):
        if yaml:
            # Caller has provided the complete pod YAML.
            kubectl("""apply -f - <<'EOF'
%s
EOF
""" % yaml)
        else:
            # Build YAML with specified namespace, name and image.
            pod = {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": name,
                    "namespace": ns,
                },
                "spec": {
                    "containers": [
                        {
                            "name": name,
                            "image": image,
                        },
                    ],
                    "terminationGracePeriodSeconds": 0,
                },
            }
            if node:
                pod["spec"]["nodeName"] = node
            if annotations:
                pod["metadata"]["annotations"] = annotations
            if labels:
                pod["metadata"]["labels"] = labels
            if cmd:
                pod["spec"]["containers"][0]["command"] = cmd
            kubectl("""apply -f - <<'EOF'
%s
EOF
""" % json.dumps(pod))

        self.name = name
        self.ns = ns
        self._ip = None
        self._ipv6 = None
        self._hostip = None
        self._nodename = None

    def delete(self):
        kubectl("delete pod/%s -n %s" % (self.name, self.ns))

    def wait_ready(self):
        kubectl("wait --for=condition=ready pod/%s -n %s --timeout=300s" % (self.name, self.ns))

    def wait_not_ready(self):
        kubectl("wait --for=condition=Ready=false pod/%s -n %s --timeout=300s" % (self.name, self.ns))

    @property
    def ip(self):
        start_time = time.time()
        while not self._ip:
            assert time.time() - start_time < 30, "Pod failed to get IP address within 30s"
            ip = run("kubectl get po %s -n %s -o json | jq '.status.podIP'" % (self.name, self.ns)).strip().strip('"')
            if ip != "null":
                self._ip = ip
                break
            time.sleep(0.1)
        return self._ip

    @property
    def ipv6(self):
        start_time = time.time()
        while not self._ipv6:
            assert time.time() - start_time < 30, "Pod failed to get IP address within 30s"
            ips = run("kubectl get po %s -n %s -o=jsonpath='{.status.podIPs[*].ip}'" % (self.name, self.ns)).strip().split(" ")
            for ip in ips:
                if ":" in ip:
                    self._ipv6 = ip
                    break
            time.sleep(0.1)
        return self._ipv6

    @property
    def hostip(self):
        if not self._hostip:
            self._hostip = run("kubectl get po %s -n %s -o json | jq '.status.hostIP'" %
                           (self.name, self.ns)).strip().strip('"')
        return self._hostip

    @property
    def nodename(self):
        if not self._nodename:
            # spec.nodeName will be populated for a running pod regardless of being specified or not on pod creation.
            self._nodename = run("kubectl get po %s -n %s -o json | jq '.spec.nodeName'" %
                               (self.name, self.ns)).strip().strip('"')
        return self._nodename

    @property
    def annotations(self):
        return json.loads(run("kubectl get po %s -n %s -o json | jq '.metadata.annotations'" %
                           (self.name, self.ns)).strip().strip('"'))

    def execute(self, cmd, timeout=0):
        return kubectl("exec %s -n %s -- %s" % (self.name, self.ns, cmd), timeout=timeout)

class TestBaseV6(TestBase):

    def get_routes(self):
        return run("docker exec kube-node-extra ip -6 r")

class NetcatServerTCP(Container):

    def __init__(self, port):
        super(NetcatServerTCP, self).__init__("subfuzion/netcat", "-v -l -k -p %d" % port, "--privileged")
        self.port = port

    def get_recent_node(self):
        node = None
        for attempt in range(3):
            for line in self.logs().split('\n'):
                m = re.match(r"Connection from ([a-z]+\-[a-z0-9]+)\.kind [0-9]+ received", line)
                if m:
                    node = m.group(1)
            if node is not None:
                return node
            else:
                time.sleep(1)
        assert False, "Couldn't find a recent node name in the logs."

    def get_recent_client_ip(self):
        ip = None
        for attempt in range(3):
            for line in self.logs().split('\n'):
                m = re.match(r"Connection from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) [0-9]+ received", line)
                if m:
                    ip = m.group(1)
            if ip is not None:
                return ip
            else:
                time.sleep(1)
        assert False, "Couldn't find a recent client IP in the logs."

class NetcatClientTCP(Pod):

    def __init__(self, ns, name, node=None, labels=None, annotations=None):
        cmd = ["sleep", "3600"]
        super(NetcatClientTCP, self).__init__(ns, name, image="alpine", node=node, labels=labels, annotations=annotations, cmd=cmd)
        self.last_output = ""

    def can_connect(self, ip, port, command="nc"):
        run("docker exec %s ip rule" % self.nodename, allow_fail=True)
        run("docker exec %s ip r l table 250" % self.nodename, allow_fail=True)
        run("docker exec %s ip r l table 249" % self.nodename, allow_fail=True)
        try:
            self.check_connected(ip, port, command)
            logger.info("'%s' connected, as expected", self.name)
        except subprocess.CalledProcessError:
            logger.exception("Failed to access server")
            logger.warning("'%s' failed to connect, when connection was expected", self.name)
            raise self.ConnectionError

    def cannot_connect(self, ip, port, command="nc"):
        try:
            self.check_connected(ip, port, command)
            logger.warning("'%s' unexpectedly connected", self.name)
            raise self.ConnectionError
        except subprocess.CalledProcessError:
            logger.info("'%s' failed to connect, as expected", self.name)

    def check_connected(self, ip, port, command="nc"):
        self.last_output = ""
        if command == "nc":
            self.last_output = self.execute("nc -w 2 %s %d </dev/null" % (ip, port), timeout=3)
        elif command == "wget":
            self.last_output = self.execute("wget -T 2 %s:%d -O -" % (ip, port))
        else:
            raise Exception('received invalid command')

    def has_egress_annotations(self, egress_ip, now, termination_grace_period):
        error_margin = 3
        annotations = self.annotations
        gateway_ip = annotations["egress.projectcalico.org/gatewayMaintenanceGatewayIP"]
        if gateway_ip != egress_ip:
            raise Exception('egress.projectcalico.org/gatewayMaintenanceGatewayCIDR annotation expected to be: %s, but was: %s. Annotations were: %s' % (egress_ip, gateway_ip, annotations))
        started_str = annotations["egress.projectcalico.org/gatewayMaintenanceStartedTimestamp"]
        started = datetime.strptime(started_str, "%Y-%m-%dT%H:%M:%SZ")
        if abs((started - now).total_seconds()) > error_margin:
            raise Exception('egress.projectcalico.org/gatewayMaintenanceStartedTimestamp annotation expected to be: within %ds of %s, but was: %s. Annotations were: %s' % (error_margin, now, started_str, annotations))
        finished_str = annotations["egress.projectcalico.org/gatewayMaintenanceFinishedTimestamp"]
        finished = datetime.strptime(finished_str, "%Y-%m-%dT%H:%M:%SZ")
        if abs((finished - started).total_seconds()) > (error_margin + termination_grace_period):
            raise Exception('egress.projectcalico.org/gatewayMaintenanceFinishedTimestamp annotation expected to be: within %ds of %s, but was: %s. Annotations were: %s' % ((error_margin + termination_grace_period), started, finished_str, annotations))

    def get_last_output(self):
        return self.last_output

    class ConnectionError(Exception):
        pass
