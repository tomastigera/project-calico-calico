if [[ "${SPLUNK_AUDIT_LOG}" == "true" || "${SPLUNK_AUDIT_TSEE_LOG}" == "true" || "${SPLUNK_AUDIT_KUBE_LOG}" == "true" || "${SPLUNK_FLOW_LOG}" == "true" ]]; then
  # Optional Splunk audit log output
  if [ -z "${SPLUNK_AUDIT_INDEX}" ]; then
    sed -i 's|index .*||g' ${ROOT_DIR}/fluentd/etc/outputs/out-splunk-audit.conf
  fi
  if [ -z "${SPLUNK_AUDIT_SOURCETYPE}" ]; then
    sed -i 's|sourcetype .*||g' ${ROOT_DIR}/fluentd/etc/outputs/out-splunk-audit.conf
  fi
  if [ -z "${SPLUNK_AUDIT_SOURCE}" ]; then
    sed -i 's|source .*||g' ${ROOT_DIR}/fluentd/etc/outputs/out-splunk-audit.conf
  fi
  if [ "${SPLUNK_AUDIT_LOG}" == "true" ]; then
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-audit.conf" "${ROOT_DIR}/fluentd/etc/output_tsee_audit/out-splunk-audit.conf"
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-audit.conf" "${ROOT_DIR}/fluentd/etc/output_kube_audit/out-splunk-audit.conf"
  elif [ "${SPLUNK_AUDIT_TSEE_LOG}" == "true" ]; then
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-audit.conf" "${ROOT_DIR}/fluentd/etc/output_tsee_audit/out-splunk-audit.conf"
  elif [ "${SPLUNK_AUDIT_KUBE_LOG}" == "true" ]; then
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-audit.conf" "${ROOT_DIR}/fluentd/etc/output_kube_audit/out-splunk-audit.conf"
  fi

  # Optional Splunk flow log output
  if [ -z "${SPLUNK_FLOW_INDEX}" ]; then
    sed -i 's|index .*||g' "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-flow.conf"
  fi
  if [ -z "${SPLUNK_FLOW_SOURCETYPE}" ]; then
    sed -i 's|sourcetype .*||g' "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-flow.conf"
  fi
  if [ -z "${SPLUNK_FLOW_SOURCE}" ]; then
    sed -i 's|source .*||g' "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-flow.conf"
  fi
  if [ "${SPLUNK_FLOW_LOG}" == "true" ]; then
      if [ "${FORWARD_CLUSTER_LOGS_TO_SPLUNK}" == "true" ]; then
          cp "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-flow.conf" "${ROOT_DIR}/fluentd/etc/output_flows/out-splunk-flow.conf"
      fi
      if [ "${FORWARD_NON_CLUSTER_LOGS_TO_SPLUNK}" == "true" ]; then
          cp "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-flow.conf" "${ROOT_DIR}/fluentd/etc/output_non_cluster_flows/out-splunk-flow.conf"
      fi
  fi

  # Optional Splunk dns log output
  if [ -z "${SPLUNK_DNS_INDEX}" ]; then
    sed -i 's|index .*||g' "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-dns.conf"
  fi
  if [ -z "${SPLUNK_DNS_SOURCETYPE}" ]; then
    sed -i 's|sourcetype .*||g' "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-dns.conf"
  fi
  if [ -z "${SPLUNK_DNS_SOURCE}" ]; then
    sed -i 's|source .*||g' ${ROOT_DIR}/fluentd/etc/outputs/out-splunk-dns.conf
  fi
  if [ "${SPLUNK_DNS_LOG}" == "true" ]; then
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-dns.conf" "${ROOT_DIR}/fluentd/etc/output_dns/out-splunk-dns.conf"
  fi

  # Optional Splunk l7 log output
  if [ -z "${SPLUNK_L7_INDEX}" ]; then
    sed -i 's|index .*||g' ${ROOT_DIR}/fluentd/etc/outputs/out-splunk-l7.conf
  fi
  if [ -z "${SPLUNK_L7_SOURCETYPE}" ]; then
    sed -i 's|sourcetype .*||g' ${ROOT_DIR}/fluentd/etc/outputs/out-splunk-l7.conf
  fi
  if [ -z "${SPLUNK_L7_SOURCE}" ]; then
    sed -i 's|source .*||g' "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-l7.conf"
  fi
  if [ "${SPLUNK_L7_LOG}" == "true" ]; then
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-l7.conf" "${ROOT_DIR}/fluentd/etc/output_l7/out-splunk-l7.conf"
  fi

  # Optional Splunk WAF log output
  if [ -z "${SPLUNK_WAF_INDEX}" ]; then
    sed -i 's|index .*||g' "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-waf.conf"
  fi
  if [ -z "${SPLUNK_WAF_SOURCETYPE}" ]; then
    sed -i 's|sourcetype .*||g' "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-waf.conf"
  fi
  if [ -z "${SPLUNK_WAF_SOURCE}" ]; then
    sed -i 's|source .*||g' "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-waf.conf"
  fi
  if [ "${SPLUNK_WAF_LOG}" == "true" ]; then
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-waf.conf" "${ROOT_DIR}/fluentd/etc/output_waf/out-splunk-waf.conf"
  fi

  # Optional Splunk runtime security report log output
  if [ -z "${SPLUNK_RUNTIME_INDEX}" ]; then
    sed -i 's|index .*||g' "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-runtime.conf"
  fi
  if [ -z "${SPLUNK_RUNTIME_SOURCETYPE}" ]; then
    sed -i 's|sourcetype .*||g' "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-runtime.conf"
  fi
  if [ -z "${SPLUNK_RUNTIME_SOURCE}" ]; then
    sed -i 's|source .*||g' "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-runtime.conf"
  fi
  if [ "${SPLUNK_RUNTIME_LOG}" == "true" ]; then
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-splunk-runtime.conf" "${ROOT_DIR}/fluentd/etc/output_runtime/out-splunk-runtime.conf"
  fi
fi
