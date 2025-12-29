#!/bin/sh
set -e

remove_secure_es_conf() {
  if test -f "/fluentd/etc/output_${1}/out-es.conf"; then
    sed -i 's|scheme .*||g' "${ROOT_DIR}/fluentd/etc/output_${1}/out-es.conf"
    sed -i 's|user .*||g' "${ROOT_DIR}/fluentd/etc/output_${1}/out-es.conf"
    sed -i 's|password .*||g' "${ROOT_DIR}/fluentd/etc/output_${1}/out-es.conf"
    sed -i 's|ca_file .*||g' "${ROOT_DIR}/fluentd/etc/output_${1}/out-es.conf"
    sed -i 's|ssl_verify .*||g' "${ROOT_DIR}/fluentd/etc/output_${1}/out-es.conf"
  fi
}

# fluentd tries to watch Docker logs and write everything to screen
# by default: prevent this.
echo >"${ROOT_DIR}/fluentd/etc/fluent.conf"

if [ "${MANAGED_K8S}" == "true" ]; then
  # Managed Kubernetes (only EKS supported for now) needs an additional fluentd instance to
  # scrape kube-apiserver audit logs from CloudWatch.
  # This runs as an additional fluentd instance in the cluster, so it doesn't need to include any
  # of the regular logging that follows this if block.  Those logs are scraped by a separate
  # fluentd instance.

  # source
  if [ "${K8S_PLATFORM}" == "eks" ]; then
    export EKS_CLOUDWATCH_LOG_STREAM_PREFIX=${EKS_CLOUDWATCH_LOG_STREAM_PREFIX:-"kube-apiserver-audit-"}
    cat "${ROOT_DIR}/fluentd/etc/inputs/in-eks.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
  fi

  # filter
  cat "${ROOT_DIR}/fluentd/etc/filters/filter-eks-audit.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
  echo >>"${ROOT_DIR}/fluentd/etc/fluent.conf"

  # match
  if [ -z "${DISABLE_ES_AUDIT_KUBE_LOG}" ] || [ "${DISABLE_ES_AUDIT_KUBE_LOG}" == "false" ]; then
    if [ -z "${LINSEED_ENABLED}" ] || [ "${LINSEED_ENABLED}" == "false" ]; then
      cp "${ROOT_DIR}/fluentd/etc/outputs/out-es-kube-audit.conf" "${ROOT_DIR}/fluentd/etc/output_kube_audit/out-es.conf"
      if [ -z "${FLUENTD_ES_SECURE}" ] || [ "${FLUENTD_ES_SECURE}" == "false" ]; then
        remove_secure_es_conf kube_audit
      fi
    else
      cp "${ROOT_DIR}/fluentd/etc/outputs/out-linseed-kube-audit.conf" "${ROOT_DIR}/fluentd/etc/output_kube_audit/out-linseed-kube-audit.conf"
    fi
  fi
  if [ "${S3_STORAGE}" == "true" ]; then
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-s3-kube-audit.conf" "${ROOT_DIR}/fluentd/etc/output_kube_audit/out-s3.conf"
  fi

  source "${ROOT_DIR}/bin/syslog-environment.sh"
  source "${ROOT_DIR}/bin/syslog-config.sh"

  source "${ROOT_DIR}/bin/splunk-environment.sh"
  source "${ROOT_DIR}/bin/splunk-config.sh"

  cat "${ROOT_DIR}/fluentd/etc/outputs/out-eks-audit-es.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
  echo >>"${ROOT_DIR}/fluentd/etc/fluent.conf"

  # Run fluentd
  "$@"

  # bail earlier
  exit $?
fi

# Set the number of shards and replicas for index tigera_secure_ee_flows
sed -i 's|"number_of_shards": *[0-9]\+|"number_of_shards": '"$ELASTIC_FLOWS_INDEX_SHARDS"'|g' "${ROOT_DIR}/fluentd/etc/elastic_mapping_flows.template"
sed -i 's|"number_of_replicas": *[0-9]\+|"number_of_replicas": '"$ELASTIC_FLOWS_INDEX_REPLICAS"'|g' "${ROOT_DIR}/fluentd/etc/elastic_mapping_flows.template"

# Set the number of shards and replicas for index tigera_secure_ee_dns
sed -i 's|"number_of_shards": *[0-9]\+|"number_of_shards": '"$ELASTIC_DNS_INDEX_SHARDS"'|g' "${ROOT_DIR}/fluentd/etc/elastic_mapping_dns.template"
sed -i 's|"number_of_replicas": *[0-9]\+|"number_of_replicas": '"$ELASTIC_DNS_INDEX_REPLICAS"'|g' "${ROOT_DIR}/fluentd/etc/elastic_mapping_dns.template"

# Set the number of replicas for index tigera_secure_ee_audit
sed -i 's|"number_of_replicas": *[0-9]\+|"number_of_replicas": '"$ELASTIC_AUDIT_INDEX_REPLICAS"'|g' "${ROOT_DIR}/fluentd/etc/elastic_mapping_audits.template"

# Set the number of shards and replicas for index tigera_secure_ee_bgp
sed -i 's|"number_of_shards": *[0-9]\+|"number_of_shards": '"$ELASTIC_BGP_INDEX_SHARDS"'|g' "${ROOT_DIR}/fluentd/etc/elastic_mapping_bgp.template"
sed -i 's|"number_of_replicas": *[0-9]\+|"number_of_replicas": '"$ELASTIC_BGP_INDEX_REPLICAS"'|g' "${ROOT_DIR}/fluentd/etc/elastic_mapping_bgp.template"

# Set the number of shards and replicas for index tigera_secure_ee_waf
sed -i 's|"number_of_shards": *[0-9]\+|"number_of_shards": '"$ELASTIC_WAF_INDEX_SHARDS"'|g' "${ROOT_DIR}/fluentd/etc/elastic_mapping_waf.template"
sed -i 's|"number_of_replicas": *[0-9]\+|"number_of_replicas": '"$ELASTIC_WAF_INDEX_REPLICAS"'|g' "${ROOT_DIR}/fluentd/etc/elastic_mapping_waf.template"

# Set the number of shards and replicas for index tigera_secure_ee_l7
sed -i 's|"number_of_shards": *[0-9]\+|"number_of_shards": '"$ELASTIC_L7_INDEX_SHARDS"'|g' "${ROOT_DIR}/fluentd/etc/elastic_mapping_l7.template"
sed -i 's|"number_of_replicas": *[0-9]\+|"number_of_replicas": '"$ELASTIC_L7_INDEX_REPLICAS"'|g' "${ROOT_DIR}/fluentd/etc/elastic_mapping_l7.template"

# Set the number of shards and replicas for index tigera_secure_ee_runtime
sed -i 's|"number_of_shards": *[0-9]\+|"number_of_shards": '"$ELASTIC_RUNTIME_INDEX_SHARDS"'|g' "${ROOT_DIR}/fluentd/etc/elastic_mapping_runtime.template"
sed -i 's|"number_of_replicas": *[0-9]\+|"number_of_replicas": '"$ELASTIC_RUNTIME_INDEX_REPLICAS"'|g' "${ROOT_DIR}/fluentd/etc/elastic_mapping_runtime.template"

# Build the fluentd configuration file bit by bit, because order is important.
# Add the sources.
cat "${ROOT_DIR}/fluentd/etc/fluent_sources.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
echo >>"${ROOT_DIR}/fluentd/etc/fluent.conf"

# Append additional filter blocks to the fluentd config if provided.
if [ "${FLUENTD_FLOW_FILTERS}" == "true" ]; then
  cat "${ROOT_DIR}/etc/fluentd/flow-filters.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
  echo >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
fi

# Append additional filter blocks to the fluentd config if provided.
if [ "${FLUENTD_DNS_FILTERS}" == "true" ]; then
  cat "${ROOT_DIR}/etc/fluentd/dns-filters.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
  echo >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
fi

# Append additional filter blocks to the fluentd config if provided.
if [ "${FLUENTD_WAF_FILTERS}" == "true" ]; then
  cat "${ROOT_DIR}/etc/fluentd/waf-filters.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
  echo >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
fi

# Append additional filter blocks to the fluentd config if provided.
if [ "${FLUENTD_L7_FILTERS}" == "true" ]; then
  cat "${ROOT_DIR}/etc/fluentd/l7-filters.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
  echo >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
fi

# Append additional filter blocks to the fluentd config if provided.
if [ "${FLUENTD_RUNTIME_FILTERS}" == "true" ]; then
  cat "${ROOT_DIR}/etc/fluentd/runtime-filters.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
  echo >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
fi

# Record transformations to add additional identifiers.
cat "${ROOT_DIR}/fluentd/etc/fluent_transforms.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
echo >>"${ROOT_DIR}/fluentd/etc/fluent.conf"

# Exclude specific ES outputs based on ENV variable flags. Note, if ES output is disabled here for a log type, depending on whether
# another output destination is enabled, we may need to disable the output match directive for the log type completely (see later
# on in this script).
if [ -z "${DISABLE_ES_FLOW_LOG}" ] || [ "${DISABLE_ES_FLOW_LOG}" == "false" ]; then
  if [ -z "${LINSEED_ENABLED}" ] || [ "${LINSEED_ENABLED}" == "false" ]; then
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-es-flows.conf" "${ROOT_DIR}/fluentd/etc/output_flows/out-es.conf"
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-es-flows.conf" "${ROOT_DIR}/fluentd/etc/output_non_cluster_flows/out-es.conf"
  else
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-linseed-flows.conf" "${ROOT_DIR}/fluentd/etc/output_flows/out-linseed-flows.conf"
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-linseed-flows.conf" "${ROOT_DIR}/fluentd/etc/output_non_cluster_flows/out-linseed-flows.conf"
  fi
fi
if [ -z "${DISABLE_ES_DNS_LOG}" ] || [ "${DISABLE_ES_DNS_LOG}" == "false" ]; then
  if [ -z "${LINSEED_ENABLED}" ] || [ "${LINSEED_ENABLED}" == "false" ]; then
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-es-dns.conf" "${ROOT_DIR}/fluentd/etc/output_dns/out-es.conf"
  else
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-linseed-dns.conf" "${ROOT_DIR}/fluentd/etc/output_dns/out-linseed-dns.conf"
  fi
fi
if [ -z "${DISABLE_ES_AUDIT_EE_LOG}" ] || [ "${DISABLE_ES_AUDIT_EE_LOG}" == "false" ]; then
  if [ -z "${LINSEED_ENABLED}" ] || [ "${LINSEED_ENABLED}" == "false" ]; then
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-es-tsee-audit.conf" "${ROOT_DIR}/fluentd/etc/output_tsee_audit/out-es.conf"
  else
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-linseed-ee-audit.conf" "${ROOT_DIR}/fluentd/etc/output_tsee_audit/out-linseed-ee-audit.conf"
  fi
fi
if [ -z "${DISABLE_ES_AUDIT_KUBE_LOG}" ] || [ "${DISABLE_ES_AUDIT_KUBE_LOG}" == "false" ]; then
  if [ -z "${LINSEED_ENABLED}" ] || [ "${LINSEED_ENABLED}" == "false" ]; then
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-es-kube-audit.conf" "${ROOT_DIR}/fluentd/etc/output_kube_audit/out-es.conf"
  else
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-linseed-kube-audit.conf" "${ROOT_DIR}/fluentd/etc/output_kube_audit/out-linseed-kube-audit.conf"
  fi
fi
if [ -z "${DISABLE_ES_BGP_LOG}" ] || [ "${DISABLE_ES_BGP_LOG}" == "false" ]; then
  if [ -z "${LINSEED_ENABLED}" ] || [ "${LINSEED_ENABLED}" == "false" ]; then
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-es-bgp.conf" "${ROOT_DIR}/fluentd/etc/output_bgp/out-es.conf"
  else
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-linseed-bgp.conf" "${ROOT_DIR}/fluentd/etc/output_bgp/out-linseed-bgp.conf"
  fi
fi
if [ -z "${DISABLE_ES_L7_LOG}" ] || [ "${DISABLE_ES_L7_LOG}" == "false" ]; then
  if [ -z "${LINSEED_ENABLED}" ] || [ "${LINSEED_ENABLED}" == "false" ]; then
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-es-l7.conf" "${ROOT_DIR}/fluentd/etc/output_l7/out-es.conf"
  else
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-linseed-l7.conf" "${ROOT_DIR}/fluentd/etc/output_l7/out-linseed-l7.conf"
  fi
fi
if [ -z "${DISABLE_ES_RUNTIME_LOG}" ] || [ "${DISABLE_ES_RUNTIME_LOG}" == "false" ]; then
  if [ -z "${LINSEED_ENABLED}" ] || [ "${LINSEED_ENABLED}" == "false" ]; then
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-es-runtime.conf" "${ROOT_DIR}/fluentd/etc/output_runtime/out-es.conf"
  else
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-linseed-runtime.conf" "${ROOT_DIR}/fluentd/etc/output_runtime/out-linseed-runtime.conf"
  fi
fi
if [ -z "${DISABLE_ES_WAF_LOG}" ] || [ "${DISABLE_ES_WAF_LOG}" == "false" ]; then
  if [ -z "${LINSEED_ENABLED}" ] || [ "${LINSEED_ENABLED}" == "false" ]; then
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-es-waf.conf" "${ROOT_DIR}/fluentd/etc/output_waf/out-es.conf"
  else
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-linseed-waf.conf" "${ROOT_DIR}/fluentd/etc/output_waf/out-linseed-waf.conf"
  fi
fi
if [ -z "${DISABLE_ES_POLICY_ACTIVITY_LOG}" ] || [ "${DISABLE_ES_POLICY_ACTIVITY_LOG}" == "false" ]; then
  cp "${ROOT_DIR}/fluentd/etc/outputs/out-linseed-policy-activity.conf" "${ROOT_DIR}/fluentd/etc/output_policy/out-linseed-policy-activity.conf"
fi
# Check if we should strip out the secure settings from the configuration file.
if [ -z "${FLUENTD_ES_SECURE}" ] || [ "${FLUENTD_ES_SECURE}" == "false" ]; then
  for x in flows dns tsee_audit kube_audit bgp l7 runtime waf; do
    remove_secure_es_conf $x
  done
fi

if [ "${S3_STORAGE}" == "true" ]; then
  if [ "${FORWARD_CLUSTER_LOGS_TO_S3}" == "true" ]; then
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-s3-flows.conf" "${ROOT_DIR}/fluentd/etc/output_flows/out-s3.conf"
  fi
  if [ "${FORWARD_NON_CLUSTER_LOGS_TO_S3}" == "true" ]; then
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-s3-flows.conf" "${ROOT_DIR}/fluentd/etc/output_non_cluster_flows/out-s3.conf"
  fi
  cp "${ROOT_DIR}/fluentd/etc/outputs/out-s3-dns.conf" "${ROOT_DIR}/fluentd/etc/output_dns/out-s3.conf"
  cp "${ROOT_DIR}/fluentd/etc/outputs/out-s3-tsee-audit.conf" "${ROOT_DIR}/fluentd/etc/output_tsee_audit/out-s3.conf"
  cp "${ROOT_DIR}/fluentd/etc/outputs/out-s3-kube-audit.conf" "${ROOT_DIR}/fluentd/etc/output_kube_audit/out-s3.conf"
  cp "${ROOT_DIR}/fluentd/etc/outputs/out-s3-compliance-reports.conf" "${ROOT_DIR}/fluentd/etc/output_compliance_reports/out-s3.conf"
  cp "${ROOT_DIR}/fluentd/etc/outputs/out-s3-l7.conf" "${ROOT_DIR}/fluentd/etc/output_l7/out-s3.conf"
  cp "${ROOT_DIR}/fluentd/etc/outputs/out-s3-runtime.conf" "${ROOT_DIR}/fluentd/etc/output_runtime/out-s3.conf"
fi

source "${ROOT_DIR}/bin/syslog-environment.sh"
source "${ROOT_DIR}/bin/syslog-config.sh"

source "${ROOT_DIR}/bin/splunk-environment.sh"
source "${ROOT_DIR}/bin/splunk-config.sh"

# Determine which output match directives to include.

# Include output destination for flow logs when (1) forwarding to ES is not disabled or (2) one of the other destinations for flows is turned on.
if [ -z "${DISABLE_ES_FLOW_LOG}" ] || [ "${DISABLE_ES_FLOW_LOG}" == "false" ] || [ "${SYSLOG_FLOW_LOG}" == "true" ] || [ "${SPLUNK_FLOW_LOG}" == "true" ] || [ "${SUMO_FLOW_LOG}" == "true" ] || [ "${S3_STORAGE}" == "true" ]; then
  cat "${ROOT_DIR}/fluentd/etc/output_match/flows.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
  cat "${ROOT_DIR}/fluentd/etc/output_match/non-cluster-flows.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
  echo >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
fi

# Include output destination for DNS logs when (1) forwarding to ES is not disabled or (2) one of the other destinations for DNS is turned on.
if [ -z "${DISABLE_ES_DNS_LOG}" ] || [ "${DISABLE_ES_DNS_LOG}" == "false" ] || [ "${SYSLOG_DNS_LOG}" == "true" ] || [ "${SPLUNK_DNS_LOG}" == "true" ] || [ "${SUMO_DNS_LOG}" == "true" ] || [ "${S3_STORAGE}" == "true" ]; then
  cat "${ROOT_DIR}/fluentd/etc/output_match/dns.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
  echo >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
fi

# Include output destination for WAF logs when (1) forwarding to ES is not disabled or (2) one of the other destinations for WAF is turned on.
if [ -z "${DISABLE_ES_WAF_LOG}" ] || [ "${DISABLE_ES_WAF_LOG}" == "false" ] || [ "${SYSLOG_WAF_LOG}" == "true" ] || [ "${SPLUNK_WAF_LOG}" == "true" ] || [ "${SUMO_WAF_LOG}" == "true" ] || [ "${S3_STORAGE}" == "true" ]; then
  cat "${ROOT_DIR}/fluentd/etc/output_match/waf.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
  echo >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
fi

# Include output destination for L7 logs when (1) forwarding to ES is not disabled or (2) one of the other destinations for DNS is turned on.
if [ -z "${DISABLE_ES_L7_LOG}" ] || [ "${DISABLE_ES_L7_LOG}" == "false" ] || [ "${SYSLOG_L7_LOG}" == "true" ] || [ "${SPLUNK_L7_LOG}" == "true" ] || [ "${SUMO_L7_LOG}" == "true" ] || [ "${S3_STORAGE}" == "true" ]; then
  cat "${ROOT_DIR}/fluentd/etc/output_match/l7.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
  echo >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
fi

# Include output destination for EE Audit logs when (1) forwarding to ES is not disabled or (2) one of the other destinations for EE Audit is turned on.
if [ -z "${DISABLE_ES_AUDIT_EE_LOG}" ] || [ "${DISABLE_ES_AUDIT_EE_LOG}" == "false" ] || [ "${SYSLOG_AUDIT_EE_LOG}" == "true" ] || [ "${SPLUNK_AUDIT_TSEE_LOG}" == "true" ] || [ "${SUMO_AUDIT_TSEE_LOG}" == "true" ] || [ "${S3_STORAGE}" == "true" ]; then
  cat "${ROOT_DIR}/fluentd/etc/output_match/audit-ee.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
  echo >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
fi

# Include output destination for Kube Audit logs when (1) forwarding to ES is not disabled or (2) one of the other destinations for Kube Audit is turned on.
if [ -z "${DISABLE_ES_AUDIT_KUBE_LOG}" ] || [ "${DISABLE_ES_AUDIT_KUBE_LOG}" == "false" ] || [ "${SYSLOG_AUDIT_KUBE_LOG}" == "true" ] || [ "${SPLUNK_AUDIT_KUBE_LOG}" == "true" ] || [ "${SUMO_AUDIT_KUBE_LOG}" == "true" ] || [ "${S3_STORAGE}" == "true" ]; then
  cat "${ROOT_DIR}/fluentd/etc/output_match/audit-kube.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
  echo >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
fi

# Include output destination for BGP logs when forwarding to ES is not disabled. Currently, BGP logs do not get forwarded to any other
# destinations other than ES (may change in the future).
if [ -z "${DISABLE_ES_BGP_LOG}" ] || [ "${DISABLE_ES_BGP_LOG}" == "false" ]; then
  cat "${ROOT_DIR}/fluentd/etc/output_match/bgp.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
  echo >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
fi

# Include output destination for runtime security logs when (1) forwarding to ES is not disabled or (2) one of the other destinations for runtime security report logs is turned on.
if [ -z "${DISABLE_ES_RUNTIME_LOG}" ] || [ "${DISABLE_ES_RUNTIME_LOG}" == "false" ] || [ "${SYSLOG_RUNTIME_LOG}" == "true" ] || [ "${SPLUNK_RUNTIME_LOG}" == "true" ] || [ "${SUMO_RUNTIME_LOG}" == "true" ] || [ "${S3_STORAGE}" == "true" ]; then
  cat "${ROOT_DIR}/fluentd/etc/output_match/runtime.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
  echo >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
fi

# Append additional output config (for Compliance reports) when S3 archiving is turned on.
if [ "${S3_STORAGE}" == "true" ]; then
  cat "${ROOT_DIR}/fluentd/etc/output_match/compliance.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
fi
echo >>"${ROOT_DIR}/fluentd/etc/fluent.conf"

# Include output destination for policy activity logs.
cat "${ROOT_DIR}/fluentd/etc/output_match/policy-activity.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
echo >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
# Run fluentd
"$@"
