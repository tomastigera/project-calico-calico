# Copyright (c) 2023-2025 Tigera, Inc. All rights reserved.

ARG CALICO_BASE
ARG THIRD_PARTY_REGISTRY
ARG THIRD_PARTY_RELEASE_BRANCH

FROM ${THIRD_PARTY_REGISTRY}/snort:v3.10.0.0-${THIRD_PARTY_RELEASE_BRANCH} AS snort

FROM scratch AS source

ARG TARGETARCH

# Copy snort, tar, and library dependencies
COPY --from=snort /usr/bin/snort /usr/bin/snort
COPY --from=snort /usr/bin/tar /usr/bin/tar
COPY --from=snort /lib64/libdaq.so.3 /lib64/libdaq.so.3

COPY --from=snort /lib64/libOpenCL.so.1 /lib64/libOpenCL.so.1
COPY --from=snort /lib64/libacl.so.1 /lib64/libacl.so.1
COPY --from=snort /lib64/libattr.so.1 /lib64/libattr.so.1
COPY --from=snort /lib64/libcap.so.2 /lib64/libcap.so.2
COPY --from=snort /lib64/libcrypto.so.3 /lib64/libcrypto.so.3
COPY --from=snort /lib64/libdnet.so.1 /lib64/libdnet.so.1
COPY --from=snort /lib64/libhwloc.so.15 /lib64/libhwloc.so.15
COPY --from=snort /lib64/libibverbs.so.1 /lib64/libibverbs.so.1
COPY --from=snort /lib64/libluajit-5.1.so.2 /lib64/libluajit-5.1.so.2
COPY --from=snort /lib64/liblzma.so.5 /lib64/liblzma.so.5
COPY --from=snort /lib64/libnl-3.so.200 /lib64/libnl-3.so.200
COPY --from=snort /lib64/libnl-route-3.so.200 /lib64/libnl-route-3.so.200
COPY --from=snort /lib64/libpcap.so.1 /lib64/libpcap.so.1
COPY --from=snort /lib64/libpciaccess.so.0 /lib64/libpciaccess.so.0
COPY --from=snort /lib64/libpcre2-8.so.0 /lib64/libpcre2-8.so.0
COPY --from=snort /lib64/libselinux.so.1 /lib64/libselinux.so.1
COPY --from=snort /lib64/libudev.so.1 /lib64/libudev.so.1
COPY --from=snort /lib64/libuuid.so.1 /lib64/libuuid.so.1
COPY --from=snort /lib64/libxml2.so.2 /lib64/libxml2.so.2
COPY --from=snort /lib64/libz.so.1 /lib64/libz.so.1

# Copy snort scripts and community rules
COPY --from=snort /usr/etc/snort /usr/etc/snort/

# Copy snort log location
COPY --from=snort /var/log/snort /var/log/snort/
COPY --from=snort /var/log/snort-alerts /var/log/snort-alerts/

# Copy the deep-packet-inspection binary
COPY bin/deep-packet-inspection-${TARGETARCH} /usr/bin/deep-packet-inspection

FROM ${CALICO_BASE}

COPY --from=source / /

ENTRYPOINT ["/usr/bin/deep-packet-inspection"]
