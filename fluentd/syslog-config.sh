if [ -z "${SYSLOG_VERIFY_MODE}" ]; then
  sed -i 's|verify_mode .*||g' "${ROOT_DIR}/fluentd/etc/outputs/out-syslog.conf"
fi
if [ "${SYSLOG_TLS}" == "false" ]; then
  sed -i 's|ca_file .*||g' "${ROOT_DIR}/fluentd/etc/outputs/out-syslog.conf"
fi
if [ "${SYSLOG_FLOW_LOG}" == "true" ]; then
  if [ "${FORWARD_CLUSTER_LOGS_TO_SYSLOG}" == "true" ]; then
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-syslog.conf" "${ROOT_DIR}/fluentd/etc/output_flows/out-syslog.conf"
  fi
  if [ "${FORWARD_NON_CLUSTER_LOGS_TO_SYSLOG}" == "true" ]; then
    cp "${ROOT_DIR}/fluentd/etc/outputs/out-syslog-nch.conf" "${ROOT_DIR}/fluentd/etc/output_non_cluster_flows/out-syslog.conf"
  fi
fi
if [ "${SYSLOG_DNS_LOG}" == "true" ]; then
  cp "${ROOT_DIR}/fluentd/etc/outputs/out-syslog.conf" "${ROOT_DIR}/fluentd/etc/output_dns/out-syslog.conf"
fi
if [ "${SYSLOG_AUDIT_EE_LOG}" == "true" ]; then
  cp "${ROOT_DIR}/fluentd/etc/outputs/out-syslog.conf" "${ROOT_DIR}/fluentd/etc/output_tsee_audit/out-syslog.conf"
fi
if [ "${SYSLOG_AUDIT_KUBE_LOG}" == "true" ]; then
  cp "${ROOT_DIR}/fluentd/etc/outputs/out-syslog.conf" "${ROOT_DIR}/fluentd/etc/output_kube_audit/out-syslog.conf"
fi
if [ "${SYSLOG_IDS_EVENT_LOG}" == "true" ]; then
  cp "${ROOT_DIR}/fluentd/etc/outputs/out-syslog.conf" "${ROOT_DIR}/fluentd/etc/output_ids_events/out-syslog.conf"
fi
if [ "${SYSLOG_L7_LOG}" == "true" ]; then
  cp "${ROOT_DIR}/fluentd/etc/outputs/out-syslog.conf" "${ROOT_DIR}/fluentd/etc/output_l7/out-syslog.conf"
fi
if [ "${SYSLOG_RUNTIME_LOG}" == "true" ]; then
  cp "${ROOT_DIR}/fluentd/etc/outputs/out-syslog.conf" "${ROOT_DIR}/fluentd/etc/output_runtime/out-syslog.conf"
fi
if [ "${SYSLOG_WAF_LOG}" == "true" ]; then
  cp "${ROOT_DIR}/fluentd/etc/outputs/out-syslog.conf" "${ROOT_DIR}/fluentd/etc/output_waf/out-syslog.conf"
fi
if [ "${SYSLOG_POLICY_ACTIVITY_LOG}" == "true" ]; then
  cp "${ROOT_DIR}/fluentd/etc/outputs/out-syslog.conf" "${ROOT_DIR}/fluentd/etc/output_policy/out-syslog.conf"
fi

# Append additional output matcher config (for IDS events) when SYSLOG forwarding is turned on
if [ "${SYSLOG_IDS_EVENT_LOG}" == "true" ]; then
  cat "${ROOT_DIR}/fluentd/etc/output_match/ids-events.conf" >>"${ROOT_DIR}/fluentd/etc/fluent.conf"
fi
