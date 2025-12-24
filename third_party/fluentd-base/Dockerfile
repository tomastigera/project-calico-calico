# Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

FROM registry.access.redhat.com/ubi10/ubi AS builder

ARG FLUENTD_VERSION
ARG JQ_VERSION=1.8.1
ARG RUBY_VERSION=3.4.7
ARG TARGETARCH

RUN dnf upgrade -y && dnf install -y \
       autoconf \
       automake \
       gcc \
       libyaml-devel \
       make \
       openssl-devel \
       zlib-devel

RUN dnf clean all

RUN mkdir -p /ruby-build && \
       curl -sfL https://cache.ruby-lang.org/pub/ruby/3.4/ruby-${RUBY_VERSION}.tar.gz | tar xz --strip-components=1 -C /ruby-build && \
       cd /ruby-build && ./configure --prefix=/usr --disable-install-doc && \
       make -j$(nproc) && make install && \
       rm -rf /ruby-build

# From upstream fluentd Dockerfile and update them when upgrading fluentd
# https://github.com/fluent/fluentd-docker-image/blob/master/v1.19/debian/Dockerfile
RUN gem install async -v 2.24.0 && \
       gem install async-http -v 0.89.0 && \
       gem install fluentd -v ${FLUENTD_VERSION} && \
       gem install json -v 2.13.2 && \
       gem install oj -v 3.16.11 && \
       gem install rexml -v 3.4.2

# Calico Enterprise dependencies
RUN gem install elasticsearch-api -v 8.19.2 && \
       gem install elasticsearch-transport -v 7.17.11 && \
       gem install elasticsearch-xpack -v 7.17.11 && \
       gem install elasticsearch -v 8.19.2 && \
       gem install fluent-plugin-cloudwatch-logs -v 0.15.0 && \
       gem install fluent-plugin-elasticsearch -v 6.0.0 && \
       gem install fluent-plugin-prometheus -v 2.2.1 && \
       gem install fluent-plugin-remote_syslog -v 1.1.0 && \
       gem install fluent-plugin-s3 -v 1.8.3 && \
       gem install fluent-plugin-splunk-hec -v 1.3.3 && \
       gem sources --clear-all


# Cleanup
RUN gem uninstall rexml -v 3.4.0

# Download jq 1.8, dnf would get 1.6, which has vulnerabilities.
RUN curl -L https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/jq-linux-${TARGETARCH} -o /usr/bin/jq && chmod +x /usr/bin/jq

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
RUN mkdir -p /fluentd/etc/output_policy
RUN mkdir -p /fluentd/log

COPY rubyplugin/out_http.rb /fluentd/plugins/out_http.rb

FROM scratch

COPY --from=builder / /
