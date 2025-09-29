# Copyright (c) 2025 Tigera, Inc. All rights reserved.

ARG CALICO_BASE=calico/base:latest

FROM scratch AS source

ARG TARGETARCH

COPY bin/waf-http-filter-${TARGETARCH} /waf-http-filter

FROM ${CALICO_BASE}

COPY --from=source / /

USER 10001:10001

ENTRYPOINT ["/waf-http-filter"]
