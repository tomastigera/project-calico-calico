# Copyright (c) 2024 Tigera, Inc. All rights reserved.

FROM registry.access.redhat.com/ubi9/ubi

ARG FLUENTD_VERSION
ARG ARCH

RUN dnf upgrade -y && dnf install -y \
       gcc \
       ruby \
       ruby-devel

# From upstream fluentd Dockerfile and update them when upgrading fluentd
# https://github.com/fluent/fluentd-docker-image/blob/master/v1.18/debian/Dockerfile
RUN gem install async -v 1.32.1 && \
       gem install async-http -v 0.64.2 && \
       gem install fluentd -v ${FLUENTD_VERSION} && \
       gem install json -v 2.7.4 && \
       gem install oj -v 3.16.6 && \
       gem install rexml -v 3.3.9

# Calico Enterprise dependencies
RUN gem install elasticsearch-api -v 7.17.11 && \
       gem install elasticsearch-transport -v 7.17.11 && \
       gem install elasticsearch-xpack -v 7.17.11 && \
       gem install elasticsearch -v 7.17.11 && \
       gem install fluent-plugin-cloudwatch-logs -v 0.14.3 && \
       gem install fluent-plugin-elasticsearch -v 5.4.3 && \
       gem install fluent-plugin-prometheus -v 2.2.0 && \
       gem install fluent-plugin-remote_syslog -v 1.1.0 && \
       gem install fluent-plugin-s3 -v 1.8.3 && \
       gem install fluent-plugin-splunk-hec -v 1.3.3 && \
       gem install fluent-plugin-sumologic_output -v 1.10.0

# Download jq 1.8, dnf would get 1.6, which has vulnerabilities.
RUN curl -L https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-linux-$ARCH -o /usr/bin/jq && chmod +x /usr/bin/jq

# cleanup
RUN gem sources --clear-all
RUN rm -fr /tmp/* /usr/local/share/gems/cache/*.gem
RUN rm -fr /usr/local/share/gems/gems/fluentd-${FLUENTD_VERSION}/test/
RUN rm -fr RUN rm -fr cgi-0.2.2.gemspec

RUN mkdir -p /fluentd/etc/output_bgp
RUN mkdir -p /fluentd/etc/output_compliance_reports
RUN mkdir -p /fluentd/etc/output_dns
RUN mkdir -p /fluentd/etc/output_flows
RUN mkdir -p /fluentd/etc/output_non_cluster_flows
RUN mkdir -p /fluentd/etc/output_ids_events
RUN mkdir -p /fluentd/etc/output_kube_audit
RUN mkdir -p /fluentd/etc/output_l7
RUN mkdir -p /fluentd/etc/output_runtime
RUN mkdir -p /fluentd/etc/output_tsee_audit
RUN mkdir -p /fluentd/etc/output_waf
RUN mkdir -p /fluentd/log

COPY rubyplugin/out_http.rb /fluentd/plugins/out_http.rb
