# Copyright (c) 2023-2025 Tigera, Inc. All rights reserved.

ARG CALICO_BASE

FROM scratch AS source

ARG TARGETARCH

COPY geoip/dbip-asn-lite.mmdb /usr/share/GeoIP/dbip-asn-lite.mmdb
COPY geoip/dbip-city-lite.mmdb /usr/share/GeoIP/dbip-city-lite.mmdb

COPY bin/controller-${TARGETARCH} /usr/bin/intrusion-detection-controller
COPY bin/healthz-${TARGETARCH} /usr/bin/healthz

FROM ${CALICO_BASE}

COPY --from=source / /

# IDS controller syslog forwarding feature requires privileged user and group (0)
# to write event logs into /var/log/calico. The host path is owned by root.
# Tigera operator /operator/pkg/render/intrusion_detection.go controls UID and GID
# for IDS controller container. Setting UID/GID here to non-root as a fallback.
USER 10001:10001

ENTRYPOINT ["/usr/bin/intrusion-detection-controller"]
