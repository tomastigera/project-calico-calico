# Copyright (c) 2025 Tigera, Inc. All rights reserved.

FROM scratch 

ARG TARGETARCH

# Copy the ztunnel binary built from patched source
COPY bin/ztunnel-${TARGETARCH} /usr/bin/ztunnel
# Copy license from source
COPY ztunnel/LICENSE /LICENSE
