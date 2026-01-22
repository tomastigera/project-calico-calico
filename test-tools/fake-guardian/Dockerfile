# Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

ARG CALICO_BASE
ARG UBI_IMAGE

FROM ${UBI_IMAGE} AS builder

ARG CONTROLLER_RUNTIME_VERSION
ARG K8S_VERSION
ARG TARGETARCH

RUN curl -sfL https://github.com/kubernetes-sigs/controller-runtime/releases/download/${CONTROLLER_RUNTIME_VERSION}/setup-envtest-linux-${TARGETARCH} -o /usr/bin/setup-envtest && chmod +x /usr/bin/setup-envtest

# Download etcd, kube-apiserver, and kubectl binaries using setup-envtest
RUN setup-envtest use ${K8S_VERSION} --bin-dir /usr/local/bin

FROM scratch AS source

ARG K8S_VERSION
ARG TARGETARCH

COPY --from=builder /usr/local/bin/k8s/${K8S_VERSION}-linux-${TARGETARCH}/ /usr/share/kubebuilder-envtest/
COPY bin/fake-guardian-${TARGETARCH} /usr/bin/fake-guardian

FROM ${CALICO_BASE}

ARG GIT_VERSION=unknown

# Required labels for certification
LABEL description="Fake Guardian for managed cluster scale testing"
LABEL maintainers="Glendon Ngo (glen@tigera.io), Gordon Cosgrave (gordon@tigera.io)"
LABEL name="Fake Guardian"
LABEL release="1"
LABEL summary="Fake Guardian for managed cluster scale testing"
LABEL vendor="Tigera"
LABEL version=${GIT_VERSION}

COPY --from=source / /

USER 10001:10001

ENTRYPOINT ["/usr/bin/fake-guardian"]
