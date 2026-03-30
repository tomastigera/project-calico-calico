# Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

ARG CALICO_BASE
ARG UBI_IMAGE

FROM ${UBI_IMAGE} AS ubi

RUN microdnf upgrade -y && microdnf install -y \
    shadow-utils

# Ensure this version matches the version used in quay.io/tigera/envoybinary.
FROM envoyproxy/envoy:v1.37.1 AS envoy

# For updating this version please see
# https://github.com/tigera/operator/blob/master/docs/common_tasks.md#updating-the-bundled-version-of-envoy-gateway
FROM quay.io/tigera/envoybinary:v1.37.1-0a0b20ed98 AS envoybinary

FROM scratch AS source

# dependencies
COPY --from=ubi /bin/sh /bin/sh
COPY --from=ubi /usr/bin/chown /usr/bin/chown
COPY --from=ubi /usr/bin/coreutils /usr/bin/coreutils
COPY --from=ubi /usr/bin/env /usr/bin/env
COPY --from=ubi /usr/bin/id /usr/bin/id
COPY --from=ubi /usr/sbin/groupmod /usr/sbin/groupmod
COPY --from=ubi /usr/sbin/usermod /usr/sbin/usermod

COPY --from=ubi /lib64/libacl.so.1 /lib64/libacl.so.1
COPY --from=ubi /lib64/libattr.so.1 /lib64/libattr.so.1
COPY --from=ubi /lib64/libaudit.so.1 /lib64/libaudit.so.1
COPY --from=ubi /lib64/libbz2.so.1 /lib64/libbz2.so.1
COPY --from=ubi /lib64/libcap-ng.so.0 /lib64/libcap-ng.so.0
COPY --from=ubi /lib64/libcap.so.2 /lib64/libcap.so.2
COPY --from=ubi /lib64/libcrypt.so.2 /lib64/libcrypt.so.2
COPY --from=ubi /lib64/libeconf.so.0 /lib64/libeconf.so.0
COPY --from=ubi /lib64/libpcre2-8.so.0 /lib64/libpcre2-8.so.0
COPY --from=ubi /lib64/libselinux.so.1 /lib64/libselinux.so.1
COPY --from=ubi /lib64/libsemanage.so.2 /lib64/libsemanage.so.2
COPY --from=ubi /lib64/libsepol.so.2 /lib64/libsepol.so.2
COPY --from=ubi /lib64/libtinfo.so.6 /lib64/libtinfo.so.6

# envoy
COPY --from=envoybinary --chmod=755 /usr/local/bin/envoy /usr/bin/envoy

COPY --from=envoy /docker-entrypoint.sh /docker-entrypoint.sh
COPY --from=envoy /usr/local/bin/su-exec /usr/bin/su-exec

COPY --from=envoy /etc/envoy/VERSION.txt /etc/envoy/VERSION.txt
COPY --from=envoy /etc/envoy/envoy.yaml /etc/envoy/envoy.yaml
COPY --from=envoy /etc/group /etc/group
COPY --from=envoy /etc/passwd /etc/passwd

FROM ${CALICO_BASE}

COPY --from=source / /

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["envoy", "-c", "/etc/envoy/envoy.yaml"]
