# Copyright (c) 2023-2025 Tigera, Inc. All rights reserved.

ARG CALICO_BASE
ARG UBI_IMAGE

FROM ${UBI_IMAGE} AS builder

ARG KUBE_BENCH_VERSION
ARG TARGETARCH

RUN microdnf install -y gzip tar

# install kube-bench configs
# ref: https://github.com/aquasecurity/kube-bench/blob/main/docs/installation.md
RUN mkdir /kube-bench-src && \
	curl -sfL https://github.com/aquasecurity/kube-bench/archive/refs/tags/${KUBE_BENCH_VERSION}.tar.gz | tar xz --strip-components 1 -C /kube-bench-src && \
	mkdir -p /etc/kube-bench && mv /kube-bench-src/cfg/ /etc/kube-bench/

FROM scratch AS source

ARG TARGETARCH

COPY bin/benchmarker-${TARGETARCH} /usr/bin/compliance-benchmarker
COPY bin/kube-bench-${TARGETARCH} /usr/bin/kube-bench
COPY bin/kubectl-${TARGETARCH} /usr/bin/kubectl

COPY --from=builder /etc/kube-bench /etc/kube-bench/

FROM ${CALICO_BASE}

COPY --from=source / /

ENTRYPOINT ["/usr/bin/compliance-benchmarker"]
