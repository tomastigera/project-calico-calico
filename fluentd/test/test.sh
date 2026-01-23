#!/bin/bash

# This script will generate fluentd configs using the image
# ${IMAGE}:${IMAGETAG} based off the environment variables configurations
# below and then compare to previously captured configurations to ensure
# only expected changes have happened.

FAILED=0
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
mkdir -p "$TEST_DIR/tmp"
openssl req -new -newkey rsa:2048  -subj "/C=CA/ST=British Columbia/L=Vancouver/O=Tigera/CN=localhost" -days 365 -nodes -x509 -keyout $TEST_DIR/tmp/tls.key -out $TEST_DIR/tmp/tls.crt

ADDITIONAL_MOUNT=""

function generateAndCollectConfig() {
  ENV_FILE=$1
  OUT_FILE=$2

  docker run -d \
    --name generate-fluentd-config \
    -v $TEST_DIR/tmp/tls.key:/tigera-fluentd-prometheus-tls/tls.key \
    -v $TEST_DIR/tmp/tls.crt:/tigera-fluentd-prometheus-tls/tls.crt \
    $ADDITIONAL_MOUNT \
    --hostname config.generator \
    --env-file "$ENV_FILE" \
    "${IMAGE}:${IMAGETAG}" >/dev/null
  sleep 5

  if ! docker logs generate-fluentd-config | sed -n '/<ROOT>/,/<\/ROOT>/p' | sed -e 's|^.*<ROOT>|<ROOT>|' | sed -e 's/ \+$//' >"$OUT_FILE"; then
    echo "Grabbing config from fluentd container failed"
    exit 1
  fi

  if ! docker stop generate-fluentd-config >/dev/null; then
    echo "Stopping fluentd container failed"
    exit 1
  fi

  if ! docker rm generate-fluentd-config >/dev/null; then
    echo "Removing fluentd container failed"
    exit 1
  fi

  unset ADDITIONAL_MOUNT
}

function checkConfiguration() {
  ENV_FILE=$1
  CFG_NAME=$2
  READABLE_NAME=$3

  EXPECTED=$TEST_DIR/$CFG_NAME.cfg
  UUT=$TEST_DIR/tmp/$CFG_NAME.cfg

  echo "#### Testing configuration of $READABLE_NAME"

  generateAndCollectConfig "$ENV_FILE" "$UUT"

  if ! diff "$EXPECTED" "$UUT" &>/dev/null; then
    echo " XXX configuration is not correct"
    FAILED=1
    diff -u "$EXPECTED" "$UUT"
  else
    echo "  ## configuration is correct"
  fi
}

STANDARD_ENV_VARS=$(
  cat <<EOM
NODENAME=test-node-name
ELASTIC_INDEX_SUFFIX=test-cluster-name
ELASTIC_FLOWS_INDEX_SHARDS=5
ELASTIC_DNS_INDEX_SHARDS=5
ELASTIC_L7_INDEX_SHARDS=5
ELASTIC_RUNTIME_INDEX_SHARDS=5
ELASTIC_WAF_INDEX_SHARDS=5
ELASTIC_POLICY_ACTIVITY_INDEX_SHARDS=5
FLUENTD_FLOW_FILTERS=# not a real filter
FLOW_LOG_FILE=/var/log/calico/flowlogs/flows.log
DNS_LOG_FILE=/var/log/calico/dnslogs/dns.log
L7_LOG_FILE=/var/log/calico/l7logs/l7.log
RUNTIME_LOG_FILE=/var/log/calico/runtime-security/report.log
WAF_LOG_FILE=/var/log/calico/waf/waf.log
POLICY_ACTIVITY_LOG_FILE=/var/log/calico/policy/policy_activity.log
ELASTIC_HOST=elasticsearch-tigera-elasticsearch.calico-monitoring.svc.cluster.local
ELASTIC_PORT=9200
EOM
)

ES_SECURE_VARS=$(
  cat <<EOM
ELASTIC_SSL_VERIFY=true
ELASTIC_USER=es-user
ELASTIC_PASSWORD=es-password
EOM
)

S3_VARS=$(
  cat <<EOM
AWS_KEY_ID=aws-key-id-value
AWS_SECRET_KEY=aws-secret-key-value
S3_STORAGE=true
S3_BUCKET_NAME=dummy-bucket
AWS_REGION=not-real-region
S3_BUCKET_PATH=not-a-bucket
S3_FLUSH_INTERVAL=30
EOM
)

SYSLOG_NO_TLS_VARS=$(
  cat <<EOM
SYSLOG_FLOW_LOG=true
SYSLOG_HOST=169.254.254.254
SYSLOG_PORT=3665
SYSLOG_PROTOCOL=udp
SYSLOG_HOSTNAME=nodename
SYSLOG_FLUSH_INTERVAL=17s
EOM
)

SYSLOG_TLS_VARS=$(
  cat <<EOM
SYSLOG_FLOW_LOG=true
SYSLOG_AUDIT_KUBE_LOG=true
SYSLOG_IDS_EVENT_LOG=true
SYSLOG_HOST=169.254.254.254
SYSLOG_PORT=3665
SYSLOG_PROTOCOL=tcp
SYSLOG_TLS=true
SYSLOG_VERIFY_MODE=\${OPENSSL::SSL::VERIFY_NONE}
SYSLOG_HOSTNAME=nodename
SYSLOG_CA_FILE=/etc/pki/tls/certs/tigera-ca-bundle.crt
EOM
)

SYSLOG_TLS_VARS_ALL_LOG_TYPES=$(
  cat <<EOM
SYSLOG_FLOW_LOG=true
SYSLOG_DNS_LOG=true
SYSLOG_L7_LOG=true
SYSLOG_RUNTIME_LOG=true
SYSLOG_WAF_LOG=true
SYSLOG_AUDIT_EE_LOG=true
SYSLOG_AUDIT_KUBE_LOG=true
SYSLOG_IDS_EVENT_LOG=true
SYSLOG_HOST=169.254.254.254
SYSLOG_PORT=3665
SYSLOG_PROTOCOL=tcp
SYSLOG_TLS=true
SYSLOG_VERIFY_MODE=\${OPENSSL::SSL::VERIFY_NONE}
SYSLOG_HOSTNAME=nodename
SYSLOG_CA_FILE=/etc/pki/tls/certs/tigera-ca-bundle.crt
EOM
)

EKS_VARS=$(
  cat <<EOM
MANAGED_K8S=true
K8S_PLATFORM=eks
EKS_CLOUDWATCH_LOG_GROUP=/aws/eks/eks-audit-test/cluster/
EKS_CLOUDWATCH_LOG_FETCH_INTERVAL=10
EOM
)

LINSEED_VARS=$(
  cat <<EOM
LINSEED_TOKEN=/test/token
LINSEED_CA_PATH=/etc/flu/ca.pem
LINSEED_ENDPOINT=ENDPOINT
LINSEED_CERT_PATH=/etc/flu/crt.pem
LINSEED_KEY_PATH=/etc/flu/key.pem
LINSEED_FLUSH_INTERVAL=5s
EOM
)

# Test with ES not secure
cat >"$TEST_DIR/tmp/es-no-secure.env" <<EOM
$STANDARD_ENV_VARS
FLUENTD_ES_SECURE=false
EOM

checkConfiguration "$TEST_DIR/tmp/es-no-secure.env" es-no-secure "ES unsecure"

# Test with ES secure
cat >"$TEST_DIR/tmp/es-secure.env" <<EOM
$STANDARD_ENV_VARS
FLUENTD_ES_SECURE=true
$ES_SECURE_VARS
EOM

checkConfiguration "$TEST_DIR/tmp/es-secure.env" es-secure "ES secure"

# Test with disabled ES secure (all log types)
cat >"$TEST_DIR/tmp/disable-es-secure.env" <<EOM
$STANDARD_ENV_VARS
FLUENTD_ES_SECURE=true
$ES_SECURE_VARS
DISABLE_ES_FLOW_LOG=true
DISABLE_ES_DNS_LOG=true
DISABLE_ES_L7_LOG=true
DISABLE_ES_RUNTIME_LOG=true
DISABLE_ES_WAF_LOG=true
DISABLE_ES_AUDIT_EE_LOG=true
DISABLE_ES_AUDIT_KUBE_LOG=true
DISABLE_ES_BGP_LOG=true
EOM

checkConfiguration "$TEST_DIR/tmp/disable-es-secure.env" disable-es-secure "Disable ES secure"

# Test with some disabled ES secure
cat >"$TEST_DIR/tmp/disable-some-es-secure.env" <<EOM
$STANDARD_ENV_VARS
FLUENTD_ES_SECURE=true
$ES_SECURE_VARS
DISABLE_ES_AUDIT_EE_LOG=true
DISABLE_ES_AUDIT_KUBE_LOG=true
DISABLE_ES_BGP_LOG=true
EOM

checkConfiguration "$TEST_DIR/tmp/disable-some-es-secure.env" disable-some-es-secure "Disable some ES secure"

# Test with disabled ES unsecure (all log types)
cat >"$TEST_DIR/tmp/disable-es-unsecure.env" <<EOM
$STANDARD_ENV_VARS
FLUENTD_ES_SECURE=false
$ES_SECURE_VARS
DISABLE_ES_FLOW_LOG=true
DISABLE_ES_DNS_LOG=true
DISABLE_ES_L7_LOG=true
DISABLE_ES_RUNTIME_LOG=true
DISABLE_ES_WAF_LOG=true
DISABLE_ES_AUDIT_EE_LOG=true
DISABLE_ES_AUDIT_KUBE_LOG=true
DISABLE_ES_BGP_LOG=true
EOM

checkConfiguration "$TEST_DIR/tmp/disable-es-unsecure.env" disable-es-unsecure "Disable ES unsecure"

# Test with some disabled ES unsecure
cat >"$TEST_DIR/tmp/disable-some-es-unsecure.env" <<EOM
$STANDARD_ENV_VARS
FLUENTD_ES_SECURE=false
$ES_SECURE_VARS
DISABLE_ES_AUDIT_EE_LOG=true
DISABLE_ES_AUDIT_KUBE_LOG=true
DISABLE_ES_BGP_LOG=true
EOM

checkConfiguration "$TEST_DIR/tmp/disable-some-es-unsecure.env" disable-some-es-unsecure "Disable some ES unsecure"

# Test with S3 and ES secure
cat >"$TEST_DIR/tmp/es-secure-with-s3.env" <<EOM
$STANDARD_ENV_VARS
FLUENTD_ES_SECURE=true
FORWARD_CLUSTER_LOGS_TO_S3=true
FORWARD_NON_CLUSTER_LOGS_TO_S3=true
$ES_SECURE_VARS
$S3_VARS
EOM

checkConfiguration "$TEST_DIR/tmp/es-secure-with-s3.env" es-secure-with-s3 "ES secure with S3"

# Test with ES not secure and syslog w/no tls
cat >"$TEST_DIR/tmp/es-no-secure-with-syslog-no-tls.env" <<EOM
$STANDARD_ENV_VARS
FLUENTD_ES_SECURE=false
FORWARD_CLUSTER_LOGS_TO_SYSLOG=true
FORWARD_NON_CLUSTER_LOGS_TO_SYSLOG=true
$SYSLOG_NO_TLS_VARS
EOM

checkConfiguration "$TEST_DIR/tmp/es-no-secure-with-syslog-no-tls.env" es-no-secure-with-syslog-no-tls "ES unsecure with syslog without TLS"

# Test with ES secure and syslog with tls
cat >"$TEST_DIR/tmp/es-secure-with-syslog-with-tls.env" <<EOM
$STANDARD_ENV_VARS
FLUENTD_ES_SECURE=true
FORWARD_CLUSTER_LOGS_TO_SYSLOG=true
FORWARD_NON_CLUSTER_LOGS_TO_SYSLOG=true
$ES_SECURE_VARS
$SYSLOG_TLS_VARS
EOM

TMP=$(mktemp)
ADDITIONAL_MOUNT="-v $TMP:/etc/fluentd/syslog/ca.pem"
checkConfiguration "$TEST_DIR/tmp/es-secure-with-syslog-with-tls.env" es-secure-with-syslog-with-tls "ES secure with syslog with TLS"

# Test with ES secure and syslog with tls with all log types
cat >"$TEST_DIR/tmp/es-secure-with-syslog-with-tls-all-log-types.env" <<EOM
$STANDARD_ENV_VARS
FLUENTD_ES_SECURE=true
FORWARD_CLUSTER_LOGS_TO_SYSLOG=true
FORWARD_NON_CLUSTER_LOGS_TO_SYSLOG=true
$ES_SECURE_VARS
$SYSLOG_TLS_VARS_ALL_LOG_TYPES
EOM

TMP=$(mktemp)
ADDITIONAL_MOUNT="-v $TMP:/etc/fluentd/syslog/ca.pem"
checkConfiguration "$TEST_DIR/tmp/es-secure-with-syslog-with-tls-all-log-types.env" es-secure-with-syslog-with-tls-all-log-types "ES secure with syslog with TLS with all log types"

# Test with ES secure and syslog with tls
cat >"$TEST_DIR/tmp/es-secure-with-syslog-and-s3.env" <<EOM
$STANDARD_ENV_VARS
FLUENTD_ES_SECURE=true
FORWARD_CLUSTER_LOGS_TO_SYSLOG=true
FORWARD_NON_CLUSTER_LOGS_TO_SYSLOG=true
FORWARD_CLUSTER_LOGS_TO_S3=true
FORWARD_NON_CLUSTER_LOGS_TO_S3=true
$ES_SECURE_VARS
$SYSLOG_TLS_VARS
$S3_VARS
EOM

checkConfiguration "$TEST_DIR/tmp/es-secure-with-syslog-and-s3.env" es-secure-with-syslog-and-s3 "ES secure with syslog and S3"

# Test with EKS
cat >"$TEST_DIR/tmp/eks.env" <<EOM
$EKS_VARS
EOM
checkConfiguration "$TEST_DIR/tmp/eks.env" eks "EKS"

# Test with EKS, Log Stream Prefix overwritten
cat >"$TEST_DIR/tmp/eks-log-stream-pfx.env" <<EOM
$EKS_VARS
EKS_CLOUDWATCH_LOG_STREAM_PREFIX=kube-apiserver-audit-overwritten-
EOM
checkConfiguration "$TEST_DIR/tmp/eks-log-stream-pfx.env" eks-log-stream-pfx "EKS - Log Stream Prefix overwritten"

SPLUNK_COMMON_VARS=$(
  cat <<EOM
SPLUNK_HEC_TOKEN=splunk-token
SPLUNK_FLOW_LOG=true
SPLUNK_AUDIT_LOG=true
SPLUNK_HEC_HOST=splunk.eng.tigera.com
SPLUNK_HEC_PORT=8088
SPLUNK_PROTOCOL=https
SPLUNK_FLUSH_INTERVAL=5
NODENAME=test-node-name
EOM
)

# Test with Splunk, normal server with http https
cat >"$TEST_DIR/tmp/splunk-trusted-http-https.env" <<EOM
$SPLUNK_COMMON_VARS
FORWARD_CLUSTER_LOGS_TO_SPLUNK=true
FORWARD_NON_CLUSTER_LOGS_TO_SPLUNK=true
EOM

checkConfiguration "$TEST_DIR/tmp/splunk-trusted-http-https.env" splunk-trusted-http-https "Splunk - with http and https"

# Test with linseed enabled
cat >"$TEST_DIR/tmp/linseed.env" <<EOM
$STANDARD_ENV_VARS
FLUENTD_ES_SECURE=true
LINSEED_ENABLED=true
$ES_SECURE_VARS
$LINSEED_VARS
EOM

TMP=$(mktemp)
checkConfiguration "$TEST_DIR/tmp/linseed.env" linseed "LINSEED API with default params"

# Test with S3 and ES secure, non-cluster only
cat >"$TEST_DIR/tmp/es-secure-with-s3.env" <<EOM
$STANDARD_ENV_VARS
FLUENTD_ES_SECURE=true
FORWARD_CLUSTER_LOGS_TO_S3=false
FORWARD_NON_CLUSTER_LOGS_TO_S3=true
$ES_SECURE_VARS
$S3_VARS
EOM

checkConfiguration "$TEST_DIR/tmp/es-secure-with-s3.env" es-secure-with-s3-nch "ES secure with S3 non-cluster only"

# Test with ES secure and s3 and syslog with tls, non-cluster only
cat >"$TEST_DIR/tmp/es-secure-with-syslog-and-s3.env" <<EOM
$STANDARD_ENV_VARS
FLUENTD_ES_SECURE=true
FORWARD_CLUSTER_LOGS_TO_SYSLOG=false
FORWARD_NON_CLUSTER_LOGS_TO_SYSLOG=true
FORWARD_CLUSTER_LOGS_TO_S3=false
FORWARD_NON_CLUSTER_LOGS_TO_S3=true
$ES_SECURE_VARS
$SYSLOG_TLS_VARS
$S3_VARS
EOM

checkConfiguration "$TEST_DIR/tmp/es-secure-with-syslog-and-s3.env" es-secure-with-syslog-and-s3-nch "ES secure with syslog and S3 non-cluster only"

# Test with ES secure and syslog with tls, non-cluster only
cat >"$TEST_DIR/tmp/es-secure-with-syslog-with-tls.env" <<EOM
$STANDARD_ENV_VARS
FLUENTD_ES_SECURE=true
FORWARD_CLUSTER_LOGS_TO_SYSLOG=false
FORWARD_NON_CLUSTER_LOGS_TO_SYSLOG=true
$ES_SECURE_VARS
$SYSLOG_TLS_VARS
EOM

TMP=$(mktemp)
ADDITIONAL_MOUNT="-v $TMP:/etc/fluentd/syslog/ca.pem"
checkConfiguration "$TEST_DIR/tmp/es-secure-with-syslog-with-tls.env" es-secure-with-syslog-with-tls-nch "ES secure with syslog with TLS non-cluster only"

# Test with ES secure and syslog with tls with all log types, non-cluster only
cat >"$TEST_DIR/tmp/es-secure-with-syslog-with-tls-all-log-types.env" <<EOM
$STANDARD_ENV_VARS
FLUENTD_ES_SECURE=true
FORWARD_CLUSTER_LOGS_TO_SYSLOG=false
FORWARD_NON_CLUSTER_LOGS_TO_SYSLOG=true
$ES_SECURE_VARS
$SYSLOG_TLS_VARS_ALL_LOG_TYPES
EOM

TMP=$(mktemp)
ADDITIONAL_MOUNT="-v $TMP:/etc/fluentd/syslog/ca.pem"
checkConfiguration "$TEST_DIR/tmp/es-secure-with-syslog-with-tls-all-log-types.env" es-secure-with-syslog-with-tls-all-log-types-nch "ES secure with syslog with TLS with all log types non-cluster only"

# Test with Splunk, normal server with http https, non-cluster only
cat >"$TEST_DIR/tmp/splunk-trusted-http-https.env" <<EOM
$SPLUNK_COMMON_VARS
FORWARD_CLUSTER_LOGS_TO_SPLUNK=false
FORWARD_NON_CLUSTER_LOGS_TO_SPLUNK=true
EOM

checkConfiguration "$TEST_DIR/tmp/splunk-trusted-http-https.env" splunk-trusted-http-https-nch "Splunk - with http and https non-cluster only"

rm -f "$TMP"

exit $FAILED
