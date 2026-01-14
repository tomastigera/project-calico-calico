# Copyright (c) 2023-2025 Tigera, Inc. All rights reserved.

ARG CALICO_BASE

FROM alpine:3 AS builder

ARG KUBE_BENCH_VERSION
ARG TARGETARCH

RUN apk add --no-cache curl

# install kube-bench configs
# ref: https://github.com/aquasecurity/kube-bench/blob/main/docs/installation.md
RUN curl -sfL https://github.com/aquasecurity/kube-bench/archive/refs/tags/${KUBE_BENCH_VERSION}.tar.gz -o /tmp/kube-bench.tar.gz && \
	mkdir -p /tmp/kube-bench && tar -xf /tmp/kube-bench.tar.gz --strip-components 1 -C /tmp/kube-bench && \
	mkdir -p /etc/kube-bench && mv /tmp/kube-bench/cfg /etc/kube-bench/

FROM scratch AS source

ARG TARGETARCH

COPY bin/benchmarker-${TARGETARCH} /usr/bin/compliance-benchmarker
COPY bin/kube-bench-${TARGETARCH} /usr/bin/kube-bench
COPY bin/kubectl-${TARGETARCH} /usr/bin/kubectl

COPY --from=builder /etc/kube-bench /etc/kube-bench/

FROM ${CALICO_BASE}

COPY --from=source / /

ENTRYPOINT ["/usr/bin/compliance-benchmarker"]
