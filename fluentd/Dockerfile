# Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
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

ARG CALICO_BASE
ARG THIRD_PARTY_REGISTRY
ARG THIRD_PARTY_RELEASE_BRANCH

FROM ${THIRD_PARTY_REGISTRY}/fluentd-base:v1.19.2-${THIRD_PARTY_RELEASE_BRANCH} AS fluentd

FROM scratch AS source

ARG TARGETARCH

# Dependent binaries and shared libraries
COPY --from=fluentd /bin/sh /bin/sh
COPY --from=fluentd /usr/bin/awk /usr/bin/awk
COPY --from=fluentd /usr/bin/cat /usr/bin/cat
COPY --from=fluentd /usr/bin/coreutils /usr/bin/coreutils
COPY --from=fluentd /usr/bin/cp /usr/bin/cp
COPY --from=fluentd /usr/bin/curl /usr/bin/curl
COPY --from=fluentd /usr/bin/echo /usr/bin/echo
COPY --from=fluentd /usr/bin/find /usr/bin/find
COPY --from=fluentd /usr/bin/jq /usr/bin/jq
COPY --from=fluentd /usr/bin/ls /usr/bin/ls
COPY --from=fluentd /usr/bin/rm /usr/bin/rm
COPY --from=fluentd /usr/bin/sed /usr/bin/sed
COPY --from=fluentd /usr/bin/sort /usr/bin/sort
COPY --from=fluentd /usr/bin/tar /usr/bin/tar
COPY --from=fluentd /usr/bin/test /usr/bin/test
COPY --from=fluentd /usr/bin/which /usr/bin/which

COPY --from=fluentd /lib64/libacl.so.1 /lib64/libacl.so.1
COPY --from=fluentd /lib64/libattr.so.1 /lib64/libattr.so.1
COPY --from=fluentd /lib64/libcap.so.2 /lib64/libcap.so.2
COPY --from=fluentd /lib64/libcom_err.so.2 /lib64/libcom_err.so.2
COPY --from=fluentd /lib64/libcrypt.so.2 /lib64/libcrypt.so.2
COPY --from=fluentd /lib64/libcrypto.so.3 /lib64/libcrypto.so.3
COPY --from=fluentd /lib64/libcurl.so.4 /lib64/libcurl.so.4
COPY --from=fluentd /lib64/libgmp.so.10 /lib64/libgmp.so.10 
COPY --from=fluentd /lib64/libgssapi_krb5.so.2 /lib64/libgssapi_krb5.so.2
COPY --from=fluentd /lib64/libidn2.so.0 /lib64/libidn2.so.0
COPY --from=fluentd /lib64/libk5crypto.so.3 /lib64/libk5crypto.so.3
COPY --from=fluentd /lib64/libkeyutils.so.1 /lib64/libkeyutils.so.1
COPY --from=fluentd /lib64/libkrb5.so.3 /lib64/libkrb5.so.3
COPY --from=fluentd /lib64/libkrb5support.so.0 /lib64/libkrb5support.so.0
COPY --from=fluentd /lib64/libmpfr.so.6 /lib64/libmpfr.so.6
COPY --from=fluentd /lib64/libnghttp2.so.14 /lib64/libnghttp2.so.14
COPY --from=fluentd /lib64/libpcre2-8.so.0 /lib64/libpcre2-8.so.0
COPY --from=fluentd /lib64/libreadline.so.8 /lib64/libreadline.so.8
COPY --from=fluentd /lib64/libselinux.so.1 /lib64/libselinux.so.1
COPY --from=fluentd /lib64/libssl.so.3 /lib64/libssl.so.3
COPY --from=fluentd /lib64/libtinfo.so.6 /lib64/libtinfo.so.6
COPY --from=fluentd /lib64/libunistring.so.5 /lib64/libunistring.so.5
COPY --from=fluentd /lib64/libz.so.1 /lib64/libz.so.1

# ruby and fluentd
COPY --from=fluentd /usr/bin/gem /usr/bin/gem
COPY --from=fluentd /usr/bin/ruby /usr/bin/ruby

COPY --from=fluentd /lib64/libyaml-0.so.2 /lib64/libyaml-0.so.2
COPY --from=fluentd /usr/lib64/ruby/ /usr/lib64/ruby/

COPY --from=fluentd /fluentd/ /fluentd/
COPY --from=fluentd /usr/bin/fluent-gem /usr/bin/fluent-gem
COPY --from=fluentd /usr/bin/fluentd /usr/bin/fluentd

COPY --from=fluentd /tmp/ /tmp/

# Copy scripts needed by fluentd
COPY ee_entrypoint.sh /bin/ee_entrypoint.sh
COPY liveness.sh /bin/liveness.sh
COPY readiness.sh /bin/readiness.sh
COPY splunk-config.sh /bin/splunk-config.sh
COPY splunk-environment.sh /bin/splunk-environment.sh
COPY syslog-config.sh /bin/syslog-config.sh
COPY syslog-environment.sh /bin/syslog-environment.sh

COPY eks/bin/eks-log-forwarder-startup-${TARGETARCH} /bin/eks-log-forwarder-startup

# Copy scripts and configuration files for fluentd
COPY elastic_mapping_audits.template /fluentd/etc/elastic_mapping_audits.template
COPY elastic_mapping_bgp.template /fluentd/etc/elastic_mapping_bgp.template
COPY elastic_mapping_dns.template /fluentd/etc/elastic_mapping_dns.template
COPY elastic_mapping_flows.template /fluentd/etc/elastic_mapping_flows.template
COPY elastic_mapping_l7.template /fluentd/etc/elastic_mapping_l7.template
COPY elastic_mapping_runtime.template /fluentd/etc/elastic_mapping_runtime.template
COPY elastic_mapping_waf.template /fluentd/etc/elastic_mapping_waf.template
COPY filters/ /fluentd/etc/filters/
COPY fluent_sources.conf /fluentd/etc/fluent_sources.conf
COPY fluent_transforms.conf /fluentd/etc/fluent_transforms.conf
COPY inputs/ /fluentd/etc/inputs/
COPY output_match/ /fluentd/etc/output_match/
COPY outputs/ /fluentd/etc/outputs/

FROM ${CALICO_BASE}

ENV PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Compliance reports logs needs a regex pattern because there will be
# multiple logs (one per report type), e.g. compliance.network-access.reports.log
ENV BIRD6_LOG_FILE=/var/log/calico/bird6/current
ENV BIRD_LOG_FILE=/var/log/calico/bird/current
ENV COMPLIANCE_LOG_FILE=/var/log/calico/compliance/compliance.*.reports.log
ENV DNS_LOG_FILE=/var/log/calico/dnslogs/dns.log
ENV EE_AUDIT_LOG_FILE=/var/log/calico/audit/tsee-audit.log
ENV FLOW_LOG_FILE=/var/log/calico/flowlogs/flows.log
ENV IDS_EVENT_LOG_FILE=/var/log/calico/ids/events.log
ENV L7_LOG_FILE=/var/log/calico/l7logs/l7.log
ENV RUNTIME_LOG_FILE=/var/log/calico/runtime-security/report.log
ENV WAF_LOG_FILE=/var/log/calico/waf/waf.log
ENV POLICY_ACTIVITY_LOG_FILE=/var/log/calico/policy/policy_activity.log

# TLS Settings
ENV CA_CRT_PATH=/etc/pki/tls/certs/tigera-ca-bundle.crt
ENV TLS_CRT_PATH=/tls/tls.crt
ENV TLS_KEY_PATH=/tls/tls.key

ENV POS_DIR=/var/log/calico

ENV ELASTIC_FLUSH_INTERVAL=5s
ENV ELASTIC_HOST=elasticsearch
ENV ELASTIC_PORT=9200

ENV KUBE_AUDIT_LOG=/var/log/calico/audit/kube-audit.log
ENV KUBE_AUDIT_POS=${POS_DIR}/kube-audit.log.pos

ENV S3_FLUSH_INTERVAL=5s
ENV S3_STORAGE=false

ENV ELASTIC_INDEX_SUFFIX=cluster

ENV ELASTIC_AUDIT_INDEX_REPLICAS=0
ENV ELASTIC_BGP_INDEX_REPLICAS=0
ENV ELASTIC_BGP_INDEX_SHARDS=1
ENV ELASTIC_DNS_INDEX_REPLICAS=0
ENV ELASTIC_DNS_INDEX_SHARDS=1
ENV ELASTIC_FLOWS_INDEX_REPLICAS=0
ENV ELASTIC_FLOWS_INDEX_SHARDS=1
ENV ELASTIC_L7_INDEX_REPLICAS=0
ENV ELASTIC_L7_INDEX_SHARDS=1
ENV ELASTIC_RUNTIME_INDEX_REPLICAS=0
ENV ELASTIC_RUNTIME_INDEX_SHARDS=1
ENV ELASTIC_TEMPLATE_OVERWRITE=true
ENV ELASTIC_WAF_INDEX_REPLICAS=0
ENV ELASTIC_WAF_INDEX_SHARDS=1
ENV ELASTIC_POLICY_ACTIVITY_INDEX_REPLICAS=0
ENV ELASTIC_POLICY_ACTIVITY_INDEX_SHARDS=1

ENV SYSLOG_PACKET_SIZE=1024

# Linseed default params
ENV LINSEED_CA_PATH=/etc/flu/ca.pem
ENV LINSEED_CERT_PATH=/etc/flu/crt.pem
ENV LINSEED_ENABLED=false
ENV LINSEED_ENDPOINT=ENDPOINT
ENV LINSEED_FLUSH_INTERVAL=5s
ENV LINSEED_KEY_PATH=/etc/flu/key.pem
ENV LINSEED_TOKEN=/var/run/secrets/kubernetes.io/serviceaccount/token

COPY --from=source / /

EXPOSE 24284

ENTRYPOINT ["/bin/ee_entrypoint.sh"]

CMD ["fluentd", "-c", "/fluentd/etc/fluent.conf", "-p", "/fluentd/plugins"]
