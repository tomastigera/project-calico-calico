#!/bin/bash

# This script updates the manifests in this directory using helm.
# Values files for the manifests in this directory can be found in
# ../charts/tigera-operator/values.

# Helm binary to use. Default to the one installed by the Makefile.
HELM=${HELM:-../bin/helm}

# yq binary to use for parsing component versions not found in charts. Default to the one installed by the Makefile.
YQ=${YQ:-../bin/yq}

if [[ ! -f $HELM ]]; then
  echo "[ERROR] Helm binary ${HELM} not found."
  exit 1
fi
if [[ ! -f $YQ ]]; then
  echo "[ERROR] yq binary ${YQ} not found."
  exit 1
fi

# Get versions to install.
defaultCalicoVersion=$($YQ '.[0].title' ../calico/_data/versions.yml)
CALICO_VERSION=${CALICO_VERSION:-$defaultCalicoVersion}

defaultRegistry=gcr.io/unique-caldron-775/cnx
REGISTRY=${REGISTRY:-$defaultRegistry}

# Versions retrieved from charts.
defaultOperatorVersion=$($YQ .tigeraOperator.version <../charts/tigera-operator/values.yaml)
OPERATOR_VERSION=${OPERATOR_VERSION:-$defaultOperatorVersion}

defaultOperatorRegistry=$($YQ .tigeraOperator.registry <../charts/tigera-operator/values.yaml)
OPERATOR_REGISTRY=${REGISTRY_OPERATOR:-$defaultOperatorRegistry}

# Images used in manifests that are not rendered by Helm.
NON_HELM_MANIFEST_IMAGES="calico/apiserver calico/windows calico/ctl calico/csi calico/node-driver-registrar calico/mock-node calico/dikastes"
NON_HELM_MANIFEST_IMAGES_ENT="tigera/compliance-reporter tigera/firewall-integration tigera/ingress-collector \
tigera/license-agent tigera/prometheus-operator tigera/prometheus-config-reloader tigera/anomaly_detection_jobs \
tigera/calico-windows tigera/calicoctl"
NON_HELM_MANIFEST_IMAGES+=" $NON_HELM_MANIFEST_IMAGES_ENT"

# Version file used when components in non-helm manifests have unique image versions. Should only be set for hashreleases.
# Defaults to nil, which results in CALICO_VERSION being set as the version for all non-helm manifest images.
VERSIONS_FILE=${VERSIONS_FILE:-}

echo "Generating manifests for Calico=$CALICO_VERSION and tigera-operator=$OPERATOR_VERSION"

##########################################################################
# Build the operator manifest.
##########################################################################
cat <<EOF >tigera-operator.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: tigera-operator
  labels:
    name: tigera-operator
    pod-security.kubernetes.io/enforce: privileged
EOF

# Make sure the subchart exists by creating a dummy, such that helm can build the tigera-operator chart. This is because
# it has a dependency on the subchart in its Chart.yaml.
mkdir -p ../charts/tigera-operator/charts/tigera-prometheus-operator
cp ../charts/tigera-prometheus-operator/Chart.yaml ../charts/tigera-operator/charts/tigera-prometheus-operator/

${HELM} -n tigera-operator template \
  --no-hooks \
  --set installation.enabled=false \
  --set apiServer.enabled=false \
  --set intrusionDetection.enabled=false \
  --set logCollector.enabled=false \
  --set logStorage.enabled=false \
  --set manager.enabled=false \
  --set monitor.enabled=false \
  --set policyRecommendation.enabled=false \
  --set tigeraOperator.version=$OPERATOR_VERSION \
  --set tigeraOperator.registry=$OPERATOR_REGISTRY \
  --set calicoctl.tag=$CALICO_VERSION \
  ../charts/tigera-operator >>tigera-operator.yaml

##########################################################################

# Build other Tigera operator manifests.
#
# To add a new manifest to this directory, define
# a new values file in ../charts/values/
##########################################################################
VALUES_FILES=$(cd ../charts/values && find . -type f -name "*.yaml")

for FILE in $VALUES_FILES; do
  echo "Generating manifest from charts/values/$FILE"
  # Default to using tigera-operator. However, some manifests use other namespaces instead,
  # as indicated by a comment at the top of the values file of the following form:
  # NS: <namespace-to-use>
  ns=$(cat ../charts/values/$FILE | grep -Po '# NS: \K(.*)')
  ${HELM} -n ${ns:-"tigera-operator"} template \
    ../charts/tigera-operator \
    --set policyRecommendation.enabled=false \
    --set tigeraOperator.version=$OPERATOR_VERSION \
    --set tigeraOperator.registry=$OPERATOR_REGISTRY \
    --set calicoctl.tag=$CALICO_VERSION \
    --include-crds \
    --no-hooks \
    -f ../charts/values/$FILE >$FILE
done

##########################################################################
# Build manifest which includes both Calico and Operator CRDs.
##########################################################################
echo "# Tigera Operator and Calico Enterprise CRDs" >operator-crds.yaml
(for file in ../charts/tigera-operator/crds/*.yaml; do
  echo "---"
  echo "# Source: tigera-operator/crds/$(basename $file)"
  cat $file
done) >>operator-crds.yaml
(for file in ../charts/tigera-operator/crds/calico/*.yaml; do
  echo "---"
  echo "# Source: tigera-operator/crds/calico/$(basename $file)"
  cat $file
done) >>operator-crds.yaml

##########################################################################
# Build CRDs files used in docs.
##########################################################################
echo "# ECK operator CRDs." >eck-operator-crds.yaml
(for file in ../charts/tigera-operator/crds/eck/*.yaml; do
  echo "---"
  echo "# Source: tigera-operator/crds/eck/$(basename $file)"
  cat $file
done) >>eck-operator-crds.yaml

echo "# Prometheus operator CRDs." >prometheus-operator-crds.yaml
(for file in ../charts/tigera-prometheus-operator/crds/*.yaml; do
  echo "---"
  echo "# Source: tigera-prometheus-operator/crds/$(basename $file)"
  cat $file
done) >>prometheus-operator-crds.yaml

##########################################################################
# Build tigera-prometheus-operator manifests.
##########################################################################
: >tigera-prometheus-operator.yaml
${HELM} -n tigera-operator template \
  --set policyRecommendation.enabled=false \
  --set imagePullSecrets.tigera-pull-secret="\{}" \
  --set tigeraOperator.version=$OPERATOR_VERSION \
  --set tigeraOperator.registry=$OPERATOR_REGISTRY \
  --set calicoctl.tag=$CALICO_VERSION \
  --include-crds \
  --no-hooks \
  ../charts/tigera-prometheus-operator >>tigera-prometheus-operator.yaml

##########################################################################
# Build tigera-operator manifests for OCP.
#
# OCP requires resources in their own yaml files, so output to a dir.
# Then do a bit of cleanup to reduce the directory depth to 1.
##########################################################################
${HELM} template \
  -n tigera-operator \
  ../charts/tigera-operator/ \
  --output-dir ocp \
  --no-hooks \
  --set installation.kubernetesProvider=OpenShift \
  --set installation.enabled=false \
  --set apiServer.enabled=false \
  --set apiServer.enabled=false \
  --set intrusionDetection.enabled=false \
  --set logCollector.enabled=false \
  --set logStorage.enabled=false \
  --set manager.enabled=false \
  --set monitor.enabled=false \
  --set policyRecommendation.enabled=false \
  --set tigeraOperator.version=$OPERATOR_VERSION \
  --set tigeraOperator.registry=$OPERATOR_REGISTRY \
  --set imagePullSecrets.tigera-pull-secret=SECRET \
  --set calicoctl.image=$REGISTRY/tigera/calicoctl \
  --set calicoctl.tag=$CALICO_VERSION
# The first two lines are a newline and a yaml separator - remove them.
find ocp/tigera-operator -name "*.yaml" | xargs sed -i -e 1,2d
mv $(find ocp/tigera-operator -name "*.yaml") ocp/ && rm -r ocp/tigera-operator

# The rendered pull secret base64 encodes our dummy value - restore it to ensure doc references are valid.
sed -i "s/U0VDUkVU/SECRET/g" ocp/02-pull-secret.yaml

# Generating the upgrade manifest for OCP.
# It excludes the CRs (01-*) and the specific BPF files to maintain compatibility with iptables.
VALUES_FILES=$(ls ocp | grep -v -e '^01-' -e 'cluster-network-operator.yaml' -e '02-configmap-calico-resources.yaml')
rm -f tigera-operator-ocp-upgrade.yaml
for FILE in $VALUES_FILES; do
  cat "ocp/$FILE" >> tigera-operator-ocp-upgrade.yaml
  echo -e "---" >> tigera-operator-ocp-upgrade.yaml  # Add divisor
done
# Remove the last separator (last line)
sed -i -e '$ d' tigera-operator-ocp-upgrade.yaml

##########################################################################
# Replace image versions for "static" Calico manifests.
##########################################################################
if [[ $CALICO_VERSION != master ]]; then
  echo "Replacing image tags for static enterprise manifests"
  for img in $NON_HELM_MANIFEST_IMAGES; do
    echo $img
    if [[ $VERSIONS_FILE ]]; then
      ver=$(cat $VERSIONS_FILE | $YQ '.[0].components.* | select(.image == "'$img'").version')
    else
      ver=$CALICO_VERSION
    fi
    find . -type f -exec sed -i "s;\(quay.io\|gcr.io/unique-caldron-775/cnx\)/$img:[A-Za-z0-9_.-]*;$REGISTRY/$img:$ver;g" {} \;
  done
fi

# Remove the dummy sub chart again.
rm -rf ../charts/tigera-operator/charts
