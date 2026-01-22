# Copyright (c) 2023-2025 Tigera, Inc. All rights reserved.

ARG CALICO_BASE
ARG UBI_IMAGE

FROM ${UBI_IMAGE} AS builder

RUN mkdir -p /etc/ui-apis

FROM scratch AS source

ARG TARGETARCH

COPY bin/dashboard-api-${TARGETARCH} /usr/bin/dashboard-api
COPY bin/ui-apis-${TARGETARCH} /usr/bin/ui-apis

# /etc/ui-apis directory used for storing self-signed certificates
COPY --chown=10001:10001 --from=builder /etc/ui-apis /etc/ui-apis/

FROM ${CALICO_BASE}

COPY --from=source / /

USER 10001:10001

ENTRYPOINT ["/usr/bin/ui-apis"]
