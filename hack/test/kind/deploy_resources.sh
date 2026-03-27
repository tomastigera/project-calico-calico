#!/bin/bash -e

# Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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

# deploy_resources.sh sets up a kind cluster with Calico installed
# and ready for testing. It loads images, installs Calico via Helm, and verifies
# basic connectivity.
#
# Required environment variables:
#   REPO_ROOT   - absolute path to the repository root
#   KIND        - path to the kind binary
#   KIND_NAME   - name of the kind cluster
#   KIND_IMAGES - space-separated list of Docker images to load onto the cluster
#
# Optional environment variables:
#   ARCH              - target architecture (default: amd64)
#   GIT_VERSION       - version for chart lookup (default: git describe)
#   CALICO_API_GROUP  - which API group to use
#   CLUSTER_ROUTING   - BIRD (default) or FELIX
#   VALUES_FILE       - path to helm values file (default: infra/values.yaml)

# Clean up background jobs on exit, and collect diagnostics on failure.
set -m
function cleanup() {
  rc=$?
  if [ $rc -ne 0 ]; then
    collect_diags
  fi
  jobs -p | xargs --no-run-if-empty kill
  exit $rc
}
trap 'cleanup' SIGINT SIGHUP SIGTERM EXIT

: ${REPO_ROOT:?REPO_ROOT must be set}
: ${KIND:?KIND must be set}
: ${KIND_NAME:?KIND_NAME must be set}

INFRA_DIR=${REPO_ROOT}/hack/test/kind/infra
ARCH=${ARCH:-amd64}
GIT_VERSION=${GIT_VERSION:-$(git -C "${REPO_ROOT}" describe --tags --dirty --always --abbrev=12)}
HELM=${REPO_ROOT}/bin/helm
CHART=${REPO_ROOT}/bin/tigera-operator-${GIT_VERSION}.tgz
VALUES_FILE=${VALUES_FILE:-${INFRA_DIR}/values.yaml}

: ${kubectl:=${REPO_ROOT}/hack/test/kind/kubectl}

# collect_diags prints detailed cluster diagnostics on failure.
# It collects tigerastatus, tigera-operator logs, and logs from failing pods.
function collect_diags() {
  # Guard against kubectl not being set yet (failure during variable init).
  local kctl="${kubectl:-${REPO_ROOT}/hack/test/kind/kubectl}"

  echo ""
  echo "========================================================================"
  echo "  DIAGNOSTICS: Collecting cluster state after failure"
  echo "========================================================================"

  echo ""
  echo "-------- TigeraStatus Resources (YAML) --------"
  ${kctl} get tigerastatus -o yaml 2>&1 || true

  echo ""
  echo "-------- Tigera Operator Logs --------"
  ${kctl} logs -n tigera-operator -l k8s-app=tigera-operator --tail=200 2>&1 || true

  echo ""
  echo "-------- All Pod Status --------"
  ${kctl} get po -A -o wide 2>&1 || true

  echo ""
  echo "-------- Logs from Non-Running / Non-Ready Pods --------"
  ${kctl} get po -A --no-headers 2>/dev/null | while read -r ns name ready status rest; do
    if [ "$status" != "Running" ] && [ "$status" != "Completed" ] && [ "$status" != "Succeeded" ]; then
      echo ""
      echo "---- Pod ${ns}/${name} (Status: ${status}) ----"
      echo "  -- Description --"
      ${kctl} describe pod -n "${ns}" "${name}" 2>&1 || true
      echo "  -- Logs --"
      ${kctl} logs -n "${ns}" "${name}" --all-containers --tail=200 2>&1 || true
      echo "  -- Previous Logs --"
      ${kctl} logs -n "${ns}" "${name}" --all-containers --previous --tail=200 2>&1 || true
    fi
  done

  # Also check for Running pods that aren't fully ready (e.g., 0/1, 1/2).
  ${kctl} get po -A --no-headers 2>/dev/null | while read -r ns name ready status rest; do
    if [ "$status" = "Running" ]; then
      ready_count="${ready%%/*}"
      total_count="${ready##*/}"
      if [ "$ready_count" != "$total_count" ]; then
        echo ""
        echo "---- Pod ${ns}/${name} (Running but not Ready: ${ready}) ----"
        echo "  -- Description --"
        ${kctl} describe pod -n "${ns}" "${name}" 2>&1 || true
        echo "  -- Logs --"
        ${kctl} logs -n "${ns}" "${name}" --all-containers --tail=200 2>&1 || true
        echo "  -- Previous Logs --"
        ${kctl} logs -n "${ns}" "${name}" --all-containers --previous --tail=200 2>&1 || true
      fi
    fi
  done

  echo ""
  echo "========================================================================"
  echo "  END OF DIAGNOSTICS"
  echo "========================================================================"
  echo ""
}

function wait_pod_ready() {
  args="$@"

  # Start background process, waiting for the pod to be ready.
  (
    # Wait in a loop because the command fails fast if the pod isn't visible yet.
    while ! ${kubectl} wait pod --for=condition=Ready --timeout=30s $args; do
      echo "Waiting for pod $args to be ready..."
      ${kubectl} get po -o wide $args || true
      sleep 1
    done;
    ${kubectl} wait pod --for=condition=Ready --timeout=300s $args
  ) & pid=$!
  # Start a second background process that implements the actual timeout.
  ( sleep 300; kill $pid ) 2>/dev/null & watchdog=$!
  set +e

  wait $pid 2>/dev/null
  rc=$?
  kill $watchdog 2>/dev/null
  wait $watchdog 2>/dev/null

  if [ $rc -ne 0 ]; then
    echo "Pod $args failed to become ready within 300s"
  fi

  set -e
  return $rc
}

# Enterprise-specific environment variables.
: ${GCR_IO_PULL_SECRET:=${HOME}/secrets/docker_cfg.json}
: ${TSEE_TEST_LICENSE:=${HOME}/secrets/license.yaml}

echo "Set ipv6 address on each node"
docker exec kind-control-plane ip -6 addr replace 2001:20::8/64 dev eth0
docker exec kind-worker ip -6 addr replace 2001:20::1/64 dev eth0
docker exec kind-worker2 ip -6 addr replace 2001:20::2/64 dev eth0
docker exec kind-worker3 ip -6 addr replace 2001:20::3/64 dev eth0

echo

echo "Load docker images onto kind cluster"
KIND=${KIND} KIND_NAME=${KIND_NAME} ${REPO_ROOT}/hack/test/kind/load_images.sh ${KIND_IMAGES}

# TODO: Why do this instead of building from the repository?
for image in calico/cni:master calico/pod2daemon-flexvol:master; do
    docker pull ${image}
    rm -f image.tar
    docker save --output image.tar ${image}
    for node in kind-control-plane kind-worker kind-worker2 kind-worker3; do
	docker cp image.tar ${node}:/image.tar
	docker exec -t ${node} ctr -n=k8s.io images import /image.tar
	docker exec -t ${node} rm /image.tar
    done
done

echo "Install additional permissions for BGP password"
${kubectl} apply -f ${INFRA_DIR}/additional-rbac.yaml
echo

# CRDs are already created prior to reaching this script from within lib.Makefile as part
# of kind cluster creation.
echo "Install Calico using the helm chart"
${HELM} install calico ${CHART} -f ${VALUES_FILE} -n tigera-operator --create-namespace

if [[ "$CLUSTER_ROUTING" == "FELIX" ]]; then
  echo "Patching installation resource to Felix cluster routing mode"
  ${kubectl} patch installation default --type='merge' -p '{"spec": {"calicoNetwork": {"clusterRoutingMode":"Felix"}}}'
fi

echo "Install calicoctl as a pod"
${kubectl} apply -f ${INFRA_DIR}/calicoctl.yaml
echo

echo "Install storage class"
# We need to pre-create the local storage directory.
docker exec -t kind-worker mkdir /tigera-elasticsearch
${kubectl} apply -f $INFRA_DIR/storage_class.yaml
echo

echo "Wait for tigera status to be ready"
if ! ( ${kubectl} wait --for=create --timeout=60s tigerastatus/calico &&
       ${kubectl} wait --for=condition=Available --timeout=300s tigerastatus/calico ); then
  echo "TigeraStatus for Calico failed to become Available"
  exit 1
fi

# Wait for the Calico API server to be available, if not using the projectcalico.org/v3 CRDs.
# If using the projectcalico.org/v3 CRDs, there is no Calico API server to wait for.
if [ "$CALICO_API_GROUP" != "projectcalico.org/v3" ]; then
  echo "Wait for the Calico API server to be ready"
  if ! ${kubectl} wait --for=condition=Available --timeout=300s tigerastatus/apiserver; then
    echo "TigeraStatus for API server failed to become Available"
    exit 1
  fi
fi

echo "Wait for Calico to be ready..."
wait_pod_ready -n calico-system -l k8s-app
wait_pod_ready -l k8s-app=kube-dns -n kube-system
wait_pod_ready calicoctl -n kube-system

echo "Calico is running."
echo

# The GCR_IO_PULL_SECRET is not needed to install Calico, as we use locally loaded images. However,
# it is still needed for some tests. Notably the EGW tests rely on this.
${kubectl} get secret tigera-pull-secret -n tigera-operator ||
  ${kubectl} -n tigera-operator create secret generic tigera-pull-secret \
   --from-file=.dockerconfigjson=${GCR_IO_PULL_SECRET} \
   --type=kubernetes.io/dockerconfigjson

# Apply the enterprise license.
${kubectl} exec -i -n kube-system calicoctl -- calicoctl --allow-version-mismatch apply -f - < ${TSEE_TEST_LICENSE}

# Wait for log-storage to be available before waiting for its pods.
echo "Wait for log-storage to be ready..."
if ! ( ${kubectl} wait --for=create --timeout=120s tigerastatus/log-storage &&
       ${kubectl} wait --for=condition=Available --timeout=300s tigerastatus/log-storage ); then
  echo "TigeraStatus for log-storage failed to become Available"
  exit 1
fi

# Wait for the full Calico Enterprise system to be running.
wait_pod_ready -n tigera-fluentd -l k8s-app
wait_pod_ready -n tigera-elasticsearch -l k8s-app
wait_pod_ready -n tigera-elasticsearch -l k8s-app=tigera-linseed

echo "Install MetalLB controller for allocating LoadBalancer IPs"
${kubectl} create ns metallb-system || true
${kubectl} apply -f ${INFRA_DIR}/metallb.yaml
${kubectl} apply -f ${INFRA_DIR}/metallb-config.yaml

echo "Cluster is ready."
echo

# Show all the pods running for diags purposes.
${kubectl} get po --all-namespaces -o wide
${kubectl} get svc
