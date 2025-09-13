# Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

ARG CALICO_BASE

FROM scratch AS source

ARG TARGETARCH

# Copy Dex binary, wrapper, and web UI
COPY dex/bin/dex-${TARGETARCH} /usr/bin/dex
COPY wrapper/bin/dex-wrapper-${TARGETARCH} /usr/bin/dex-wrapper
COPY docker-image/web /srv/dex/web

FROM ${CALICO_BASE}

COPY --from=source / /

ENV DEX_FRONTEND_DIR=/srv/dex/web

USER 10001:10001

ENTRYPOINT ["/usr/bin/dex-wrapper"]
