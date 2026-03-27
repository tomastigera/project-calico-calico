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

import datetime
import functools
import json
import logging
import os
import random
import string
import subprocess
import time
import traceback


_log = logging.getLogger(__name__)

ROUTER_IMAGE = os.getenv("ROUTER_IMAGE", "calico/bird:latest")
NGINX_IMAGE = os.getenv("NGINX_IMAGE", "nginx:1")


# Helps with printing diags after a test.
class DiagsCollector(object):
    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_value, tb):
        if exc_type is None:
            # Test passed, no need to collect diagnostics.
            return

        # Print out diagnostics for the test. These will go to screen
        # on test failure.
        _log.info("===================================================")
        _log.info("==== TEST IS FAILING, COLLECTING DIAGS FOR TEST ===")
        _log.info("===================================================")
        _log.info("Exception information: %s, %s, %s", exc_type, exc_value, traceback.format_tb(tb))
        kubectl("version")
        kubectl("get deployments,pods,svc,endpoints --all-namespaces -o wide")
        for resource in ["node", "bgpconfig", "bgppeer", "gnp", "felixconfig"]:
            _log.info("")
            calicoctl("get " + resource + " -o yaml")
        nodes, _, _ = node_info()
        for node in nodes:
            _log.info("")
            run("docker exec " + node + " ip r")
            run("docker exec " + node + " ip -6 r")
            run("docker exec " + node + " ip l")
        _log.info("== Resource requests/limits for calico-system pods ==")
        kubectl("get pods -n calico-system -o custom-columns="
                "'NAME:.metadata.name,"
                "CONTAINER:.spec.containers[*].name,"
                "CPU_REQ:.spec.containers[*].resources.requests.cpu,"
                "CPU_LIM:.spec.containers[*].resources.limits.cpu,"
                "MEM_REQ:.spec.containers[*].resources.requests.memory,"
                "MEM_LIM:.spec.containers[*].resources.limits.memory'",
                allow_fail=True)
        for pod_name in calico_node_pod_names():
            _log.info("== CPU throttling stats for %s ==", pod_name)
            kubectl("exec -n calico-system %s -- cat /sys/fs/cgroup/cpu.stat" % pod_name,
                    allow_fail=True)
        kubectl("logs -n calico-system -l k8s-app=calico-node")
        self.print_confd_templates(nodes)
        for pod_name in calico_node_pod_names():
            kubectl("exec -n calico-system %s -- cat /etc/calico/confd/config/bird_aggr.cfg" % pod_name,
                    allow_fail=True)
            kubectl("exec -n calico-system %s -- cat /etc/calico/confd/config/bird_ipam.cfg" % pod_name,
                    allow_fail=True)
            kubectl("logs -n calico-system %s" % pod_name,
                    allow_fail=True)
        _log.info("===================================================")
        _log.info("============= COLLECTED DIAGS FOR TEST ============")
        _log.info("===================================================")

    def print_confd_templates(self, nodes):
        for node in nodes:
            calicoPod = kubectl("-n calico-system get pods -o wide | grep calico-node | grep '%s '| cut -d' ' -f1" % node)
            if calicoPod is None:
                continue
            calicoPod = calicoPod.strip()

            # v4 files.
            kubectl("exec -n calico-system %s -- cat /etc/calico/confd/config/bird.cfg" % calicoPod, allow_fail=True)
            kubectl("exec -n calico-system %s -- cat /etc/calico/confd/config/bird_aggr.cfg" % calicoPod, allow_fail=True)
            kubectl("exec -n calico-system %s -- cat /etc/calico/confd/config/bird_ipam.cfg" % calicoPod, allow_fail=True)

            # And for v6.
            kubectl("exec -n calico-system %s -- cat /etc/calico/confd/config/bird6.cfg" % calicoPod, allow_fail=True)
            kubectl("exec -n calico-system %s -- cat /etc/calico/confd/config/bird6_aggr.cfg" % calicoPod, allow_fail=True)
            kubectl("exec -n calico-system %s -- cat /etc/calico/confd/config/bird6_ipam.cfg" % calicoPod, allow_fail=True)

def log_calico_node(node_ip):
    pod_name = run(" kubectl get pod -n calico-system -o wide | grep calico-node | grep %s | awk '{print $1}'" % node_ip)
    kubectl("logs %s -n calico-system " % pod_name.strip())

def exec_in_calico_node(node, command):
    calicoPod = kubectl("-n calico-system get pods -o wide | grep calico-node | grep '%s '| cut -d' ' -f1" % node)
    if calicoPod is None:
        raise Exception("No calico-node pod found on node %s" % node)
    calicoPod = calicoPod.strip()
    return kubectl("exec -n calico-system %s -- %s" % (calicoPod, command))

def start_external_node_with_bgp(name, bird_peer_config=None, bird6_peer_config=None):
    # Check how much disk space we have.
    run("df -h")

    # Setup external node: use privileged mode for setting routes.
    run("docker run -d --privileged --net=kind --name %s %s" % (name, ROUTER_IMAGE))

    # Check how much space there is inside the container.  We may need
    # to retry this, as it may take a while for the image to download
    # and the container to start running.
    retry_until_success(run, retries=30, wait_time=2, function_args=["docker exec %s df -h" % name])

    # Install curl and iproute2.
    run("docker exec %s apk add --no-cache curl iproute2" % name)

    # Set ECMP hash algorithm to L4 for a proper load balancing between nodes.
    run("docker exec %s sysctl -w net.ipv4.fib_multipath_hash_policy=1" % name)

    # Add "merge paths on" to the BIRD config.
    run("docker exec %s sed -i '/protocol kernel {/a merge paths on;' /etc/bird.conf" % name)
    run("docker exec %s sed -i '/protocol kernel {/a merge paths on;' /etc/bird6.conf" % name)

    if bird_peer_config:
        # Install desired peer config.
        output = run("docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' %s" % name)
        birdy_ip = output.strip()
        with open('peers.conf', 'w') as peerconfig:
            peerconfig.write(bird_peer_config.replace("ip@local", birdy_ip))
        run("docker cp peers.conf %s:/etc/bird/peers.conf" % name)
        run("rm peers.conf")
        run("docker exec %s birdcl configure" % name)

    elif bird6_peer_config:
        # Install desired peer config.
        birdy_ip = "2001:20::20"
        run("docker exec %s sysctl -w net.ipv6.conf.all.disable_ipv6=0" % name)
        run("docker exec %s sysctl -w net.ipv6.conf.all.forwarding=1" % name)

        # Try to set net.ipv6.fib_multipath_hash_policy to get IPv6
        # ECMP load balancing by 5-tuple, but allow it to fail as
        # older kernels (e.g. Semaphore v2) don't have that setting.
        # It doesn't actually matter as we aren't currently testing
        # IPv6 ECMP behaviour in detail.
        run("docker exec %s sysctl -w net.ipv6.fib_multipath_hash_policy=1" % name,
            allow_fail=True)

        run("docker exec %s ip -6 a a %s/64 dev eth0" % (name, birdy_ip))
        with open('peers.conf', 'w') as peerconfig:
            peerconfig.write(bird6_peer_config.replace("ip@local", birdy_ip))
        run("docker cp peers.conf %s:/etc/bird6/peers.conf" % name)
        run("rm peers.conf")
        run("docker exec %s birdcl6 configure" % name)

    return birdy_ip

def retry_until_success(fun,
                        retries=90,
                        wait_time=1,
                        ex_class=None,
                        log_exception=True,
                        function_args=None,
                        function_kwargs=None):
    """
    Retries function until no exception is thrown. If exception continues,
    it is reraised.
    :param fun: the function to be repeatedly called
    :param retries: the maximum number of times to retry the function.  A value
    of 0 will run the function once with no retries.
    :param wait_time: the time to wait between retries (in s)
    :param ex_class: The class of expected exceptions.
    :param log_exception: By default this function logs the exception if the
    function is still failing after max retries.   This log can sometimes be
    superfluous -- if e.g. the calling code is going to make a better log --
    and can be suppressed by setting this parameter to False.
    :param function_args: A list of arguments to pass to function
    :param function_kwargs: A dictionary of keyword arguments to pass to
                            function
    :returns: the value returned by function
    """
    if function_args is None:
        function_args = []
    if function_kwargs is None:
        function_kwargs = {}
    for retry in range(retries + 1):
        try:
            result = fun(*function_args, **function_kwargs)
        except Exception as e:
            if ex_class and e.__class__ is not ex_class:
                _log.exception("Hit unexpected exception in function - "
                               "not retrying.")
                stop_for_debug()
                raise
            if retry < retries:
                _log.debug("Hit exception in function - retrying: %s", e)
                time.sleep(wait_time)
            else:
                if log_exception:
                    _log.exception("Function %s did not succeed before "
                                   "timeout.", fun)
                stop_for_debug()
                raise
        else:
            # Successfully ran the function
            return result

def function_name(f):
    """
    A function that returns the name of the provided function as a string.
    This primarily exists to handle the fact that functools.partial is an
    imperfect wrapper.
    """
    if isinstance(f, functools.partial):
        f = f.func

    try:
        return f.__name__
    except Exception:
        return "<unknown function>"


def run(command, logerr=True, allow_fail=False, allow_codes=[], returnerr=False):
    out = ""
    _log.info("[%s] %s", datetime.datetime.now(), command)

    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    out = out.decode()
    err = err.decode()
    _log.info("Out:\n%s", out)
    _log.info("Err:\n%s", err)

    retcode = process.poll()
    if retcode:
        if logerr:
            _log.info("Failure output:\n%s\nerr:\n%s", out, err)
        if not (allow_fail or retcode in allow_codes):
            raise subprocess.CalledProcessError(retcode, command, output="stdout: " + out + " stderr: " + err)
        if returnerr:
            return err
    return out


def curl(hostname, container="kube-node-extra"):
    if ':' in hostname:
        # It's an IPv6 address.
        hostname = '[' + hostname + ']'

    cmd = "docker exec %s curl --connect-timeout 2 -m 3 %s" % (container,
                                                               hostname)
    return run(cmd)


def kubectl(args, logerr=True, allow_fail=False, allow_codes=[], timeout=0, returnerr=False):
    if timeout == 0:
        cmd = "kubectl "
    else:
        cmd = "timeout %d kubectl " % timeout
    return run(cmd + args,
               logerr=logerr,
               allow_fail=allow_fail,
               allow_codes=allow_codes,
               returnerr=returnerr)

def calicoctl(args, allow_fail=False):
    return kubectl("exec -i -n kube-system calicoctl -- calicoctl --allow-version-mismatch " + args,
                   allow_fail=allow_fail)


def calicoctl_apply_dict(object_dict):
    calicoctl("""apply -f - << EOF
%s
EOF
""" % json.dumps(object_dict))


def generate_unique_id(length, prefix=""):
    random_string = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))
    return "%s-%s" % (prefix, random_string)


# We have to define and use this static map, from each node name to
# its IPv6 address, because Kubernetes does not yet allow for an IPv6
# address field in its host resource.  The mappings here must match
# the code in tests/k8st/deploy_resources_on_kind_cluster.sh that assigns an IPv6
# address to each node.
ipv6_map = {
    "kind-control-plane": "2001:20::8",
    "kind-worker": "2001:20::1",
    "kind-worker2": "2001:20::2",
    "kind-worker3": "2001:20::3",
}


def node_info():
    nodes = []
    ips = []
    ip6s = []

    master_node = kubectl("get node --selector='node-role.kubernetes.io/control-plane' -o jsonpath='{.items[0].metadata.name}'")
    nodes.append(master_node)
    ip6s.append(ipv6_map[master_node])
    master_ip = kubectl("get node --selector='node-role.kubernetes.io/control-plane' -o jsonpath='{.items[0].status.addresses[0].address}'")
    ips.append(master_ip)

    for i in range(3):
        node = kubectl("get node --selector='!node-role.kubernetes.io/control-plane' -o jsonpath='{.items[%d].metadata.name}'" % i)
        nodes.append(node)
        ip6s.append(ipv6_map[node])
        node_ip = kubectl("get node --selector='!node-role.kubernetes.io/control-plane' -o jsonpath='{.items[%d].status.addresses[0].address}'" % i)
        ips.append(node_ip)
    return nodes, ips, ip6s

def stop_for_debug():
    _log.info("stop on file /code/stop")
    while os.path.isfile('/code/stop'):
        os.system("sleep 3")


def calico_node_pod_names():
    return kubectl("get po -n calico-system -l k8s-app=calico-node" +
                   " -o jsonpath='{.items[*].metadata.name}'").split()

def calico_node_pod_name(nodename):
    name = kubectl("get po -n calico-system -l k8s-app=calico-node --field-selector spec.nodeName=%s -o jsonpath='{.items[0].metadata.name}'" % nodename)
    return name

def get_felix_config_field(field):
    """Read a field from the default FelixConfiguration spec.

    Returns the field value, or None if not set.
    """
    out = kubectl("get felixconfiguration default -o json")
    fc = json.loads(out)
    return fc.get("spec", {}).get(field)


def update_felix_config(config_values):
    """Patch FelixConfiguration with the given values.

    Felix picks up FelixConfiguration changes immediately (either hot-reload
    or in-container restart), so no explicit wait is needed.  Callers should
    use retry_until_success on their assertions.

    config_values is a dict of FelixConfiguration spec field names to values,
    e.g. {"egressIPSupport": "EnabledPerNamespaceOrPerPod"}.
    """
    _log.info("Patching FelixConfiguration: %s", config_values)
    patch = json.dumps({"spec": config_values})
    kubectl("patch felixconfiguration default --type=merge -p '%s'" % patch)


def set_encapsulation(encap):
    """Set the cluster's encapsulation mode via the Installation resource.

    Patches the Installation CR so the operator reconciles the IPPool.
    Skips the change if the pool is already in the desired mode.
    """
    encap_to_modes = {
        "IPIP": ("Always", "Never"),
        "VXLAN": ("Never", "Always"),
        "None": ("Never", "Never"),
    }
    if encap not in encap_to_modes:
        allowed = ", ".join(sorted(encap_to_modes.keys()))
        raise ValueError(
            "Invalid encapsulation mode %r. Allowed modes are: %s"
            % (encap, allowed)
        )
    ipip_mode, vxlan_mode = encap_to_modes[encap]

    pool = json.loads(calicoctl("get ippool default-ipv4-ippool -o json"))
    if pool["spec"]["ipipMode"] == ipip_mode and pool["spec"]["vxlanMode"] == vxlan_mode:
        _log.info("Encapsulation already set to %s, skipping", encap)
        return

    _log.info("Setting encapsulation to %s via Installation", encap)
    patch_payload = json.dumps([{
        "op": "add",
        "path": "/spec/calicoNetwork/ipPools/0/encapsulation",
        "value": encap,
    }])
    kubectl("patch installation default --type=json -p '%s'" % patch_payload)

    # Wait for the operator to reconcile the IPPool before restarting pods.
    def pool_reconciled():
        p = json.loads(calicoctl("get ippool default-ipv4-ippool -o json"))
        if p["spec"]["ipipMode"] != ipip_mode or p["spec"]["vxlanMode"] != vxlan_mode:
            raise Exception("IPPool not yet reconciled: ipipMode=%s vxlanMode=%s" %
                            (p["spec"]["ipipMode"], p["spec"]["vxlanMode"]))
    retry_until_success(pool_reconciled, retries=30, wait_time=2)

    # Restart calico-node to cleanly apply the new encapsulation.
    kubectl("delete po -n calico-system -l k8s-app=calico-node")
    kubectl("wait --timeout=2m --for=condition=ready"
            " pods -l k8s-app=calico-node -n calico-system")

def wait_for_calico_node_pods_ready():
    """
    Wait until all calico-node pods are ready.
    """
    _log.info("Waiting for calico-node pods to be ready")
    # kubectl seems to cache the list of pods that it's waiting for throughout
    # one wait call.  Split up the wait into multiple short waits in case the
    # set of pods is changing.
    iterations = 30
    for i in range(iterations):
        try:
            kubectl("wait pod --for=condition=Ready -l k8s-app=calico-node -n calico-system --timeout=10s")
            return
        except subprocess.CalledProcessError:
            if i == iterations-1:
                _log.exception("calico-node pods not ready after 30 attempts, giving up")
                _log.info("Current calico-node pods:")
                kubectl("get pods -n calico-system -l k8s-app=calico-node -o wide")
                kubectl("describe pods -n calico-system -l k8s-app=calico-node")
                raise
            _log.info("calico-node pods not ready yet, retrying (%d/30)", i + 1)
    _log.info("All calico-node pods are ready")

def copy_cnx_pull_secret(ns):
    out = run("kubectl get secret tigera-pull-secret -n tigera-operator -o json")

    # Remove revision and UID information so we can re-apply cleanly.
    # This used to be done with --export, but that option has been removed from kubectl.
    sec = json.loads(out)
    del sec["metadata"]["resourceVersion"]
    del sec["metadata"]["uid"]
    sec["metadata"]["namespace"] = ns
    secIn = json.dumps(sec)

    # Reapply in the new namespace.
    run("echo '%s' | kubectl apply -f -" % secIn)
