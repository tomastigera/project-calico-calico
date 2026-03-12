#!/bin/bash

export LC_ALL=C

# This script updates the manifests in this directory using helm.
# Values files for the manifests in this directory can be found in
# ../charts/tigera-operator/values.

# Helm binary to use. Default to the one installed by the Makefile.
HELM=${HELM:-../bin/helm}

# yq binary to use. Default to the one installed by the Makefile.
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
defaultCalicoVersion=$($YQ .calicoctl.tag <../charts/tigera-operator/values.yaml)
CALICO_VERSION=${PRODUCT_VERSION:-$defaultCalicoVersion}

calicoctlImage=$($YQ .calicoctl.image <../charts/tigera-operator/values.yaml)
defaultRegistry=${calicoctlImage%/calicoctl}
REGISTRY=${REGISTRY:-$defaultRegistry}

defaultOperatorVersion=$($YQ .tigeraOperator.version <../charts/tigera-operator/values.yaml)
OPERATOR_VERSION=${OPERATOR_VERSION:-$defaultOperatorVersion}

defaultOperatorRegistry=$($YQ .tigeraOperator.registry <../charts/tigera-operator/values.yaml)
OPERATOR_REGISTRY=${OPERATOR_REGISTRY_OVERRIDE:-$defaultOperatorRegistry}

defaultOperatorImage=$($YQ .tigeraOperator.image <../charts/tigera-operator/values.yaml)
OPERATOR_IMAGE=${OPERATOR_IMAGE_OVERRIDE:-$defaultOperatorImage}

defaultPrometheusImage=$($YQ .prometheusOperator.image <../charts/tigera-prometheus-operator/values.yaml)
PROMETHEUS_OPERATOR_IMAGE=${PROMETHEUS_OPERATOR_IMAGE_OVERRIDE:-$defaultPrometheusImage}

defaultPromConfigReloaderImage=$($YQ .prometheusConfigReloader.image <../charts/tigera-prometheus-operator/values.yaml)
PROMETHEUS_CONFIG_RELOADER_IMAGE=${PROMETHEUS_CONFIG_RELOADER_IMAGE_OVERRIDE:-$defaultPromConfigReloaderImage}

# Images used in manifests that are not rendered by Helm.
NON_HELM_MANIFEST_IMAGES="compliance-reporter firewall-integration ingress-collector \
  license-agent anomaly_detection_jobs \
  calico-windows calicoctl"

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
  --set tigeraOperator.image=$OPERATOR_IMAGE \
  --set tigeraOperator.version=$OPERATOR_VERSION \
  --set tigeraOperator.registry=$OPERATOR_REGISTRY \
  --set calicoctl.image=$REGISTRY/calicoctl \
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
    --set tigeraOperator.image=$OPERATOR_IMAGE \
    --set tigeraOperator.version=$OPERATOR_VERSION \
    --set tigeraOperator.registry=$OPERATOR_REGISTRY \
    --set calicoctl.image=$REGISTRY/calicoctl \
    --set calicoctl.tag=$CALICO_VERSION \
    --no-hooks \
    -f ../charts/values/$FILE >$FILE
done

##########################################################################
# Build manifest which includes both Calico and Operator CRDs.
##########################################################################
echo "# crd.projectcalico.org/v1 and operator.tigera.io/v1 APIs" >v1_crd_projectcalico_org.yaml
(for file in ../charts/crd.projectcalico.org.v1/templates/*.yaml; do
  echo "---"
  echo "# Source: crd.projectcalico.org.v1/templates/$(basename $file)"
  cat $file
done) >>v1_crd_projectcalico_org.yaml
(for file in ../charts/crd.projectcalico.org.v1/templates/calico/*.yaml; do
  echo "---"
  echo "# Source: crd.projectcalico.org.v1/templates/$(basename $file)"
  cat $file
done) >>v1_crd_projectcalico_org.yaml

# Maintain legacy operator-crds.yaml for a while.
cp v1_crd_projectcalico_org.yaml operator-crds.yaml

echo "# projectcalico.org/v3 and operator.tigera.io/v1 APIs" >v3_projectcalico_org.yaml
(for file in ../charts/projectcalico.org.v3/templates/*.yaml; do
  echo "---"
  echo "# Source: projectcalico.org.v3/templates/$(basename $file)"
  cat $file
done) >>v3_projectcalico_org.yaml
(for file in ../charts/projectcalico.org.v3/templates/calico/*.yaml; do
  echo "---"
  echo "# Source: projectcalico.org.v3/templates/calico/$(basename $file)"
  cat $file
done) >>v3_projectcalico_org.yaml
(for file in ../charts/projectcalico.org.v3/templates/admission/*.yaml; do
  echo "---"
  echo "# Source: projectcalico.org.v3/templates/admission/$(basename $file)"
  cat $file
done) >>v3_projectcalico_org.yaml

##########################################################################
# Build CRDs files used in docs.
##########################################################################
echo "# Prometheus operator CRDs." >prometheus-operator-crds.yaml
(for file in ../charts/tigera-prometheus-operator/crds/*.yaml; do
  echo "---"
  echo "# Source: tigera-prometheus-operator/crds/$(basename $file)"
  cat $file
done) >>prometheus-operator-crds.yaml

##########################################################################
# Build tigera-prometheus-operator manifests.
##########################################################################
${HELM} -n tigera-operator template \
  --set imagePullSecrets.tigera-pull-secret="\{}" \
  --set prometheusOperator.image=$PROMETHEUS_OPERATOR_IMAGE \
  --set prometheusOperator.tag=$CALICO_VERSION \
  --set prometheusConfigReloader.image=$PROMETHEUS_CONFIG_RELOADER_IMAGE \
  --set prometheusConfigReloader.tag=$CALICO_VERSION \
  --include-crds \
  --no-hooks \
  ../charts/tigera-prometheus-operator > tigera-prometheus-operator.yaml

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
  --set tigeraOperator.image=$OPERATOR_IMAGE \
  --set tigeraOperator.version=$OPERATOR_VERSION \
  --set tigeraOperator.registry=$OPERATOR_REGISTRY \
  --set imagePullSecrets.tigera-pull-secret=SECRET \
  --set calicoctl.image=$REGISTRY/calicoctl \
  --set calicoctl.tag=$CALICO_VERSION
# The first two lines are a newline and a yaml separator - remove them.
find ocp/tigera-operator -name "*.yaml" | xargs sed -i -e 1,2d
mv $(find ocp/tigera-operator -name "*.yaml") ocp/ && rm -r ocp/tigera-operator

# The rendered pull secret base64 encodes our dummy value - restore it to ensure doc references are valid.
sed -i "s/U0VDUkVU/SECRET/g" ocp/02-pull-secret.yaml

##########################################################################
# Build tigera-prometheus-operator manifests for OCP.
##########################################################################
${HELM} -n tigera-operator template \
  --set imagePullSecrets.tigera-pull-secret="\{}" \
  --set installation.kubernetesProvider=openshift \
  --set prometheusOperator.image=$PROMETHEUS_OPERATOR_IMAGE \
  --set prometheusOperator.tag=$CALICO_VERSION \
  --set prometheusConfigReloader.image=$PROMETHEUS_CONFIG_RELOADER_IMAGE \
  --set prometheusConfigReloader.tag=$CALICO_VERSION \
  --no-hooks \
  ../charts/tigera-prometheus-operator > ocp/tigera-prometheus-operator.yaml

# Generating the upgrade manifest for OCP.
# It excludes the CRs (01-*) and the specific BPF files to maintain compatibility with iptables.
OCP_VALUES_FILES=$(ls ocp | grep -v -e '^01-' -e 'cluster-network-operator.yaml' -e '02-configmap-calico-resources.yaml' -e 'mutatingadmissionpolicy')
rm -f tigera-operator-ocp-upgrade.yaml
for FILE in $OCP_VALUES_FILES; do
  cat "ocp/$FILE" >>tigera-operator-ocp-upgrade.yaml
  echo -e "---" >>tigera-operator-ocp-upgrade.yaml # Add divisor
done
# Remove the last separator (last line)
sed -i -e '$ d' tigera-operator-ocp-upgrade.yaml

##########################################################################
# Replace image registry and/or versions for "static" Calico manifests.
##########################################################################
echo "Replacing image versions for static enterprise manifests"
for img in $NON_HELM_MANIFEST_IMAGES; do
  curr_img=${defaultRegistry}/${img}
  new_img=${REGISTRY}/${img}
  echo "$curr_img:$defaultCalicoVersion --> $new_img:$CALICO_VERSION"
  find . -type f -exec sed -i "s|${curr_img}:[A-Za-z0-9_.-]*|${new_img}:$CALICO_VERSION|g" {} \;
done
# Remove the dummy sub chart again.
rm -rf ../charts/tigera-operator/charts
