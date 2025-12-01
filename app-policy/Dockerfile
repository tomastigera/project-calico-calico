# Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG UBI_IMAGE
ARG CALICO_BASE

FROM ${UBI_IMAGE} AS builder

RUN microdnf upgrade -y && microdnf install -y \
    iptables \
    nftables

# Create symlinks to xtables-nft-multi
RUN set -eux; \
    mkdir -p /rootfs/usr/sbin && cd /rootfs/usr/sbin; \
    for link in \
      ip6tables \
      ip6tables-nft \
      ip6tables-nft-restore \
      ip6tables-nft-save \
      ip6tables-restore \
      ip6tables-restore-translate \
      ip6tables-save \
      ip6tables-translate \
      iptables \
      iptables-nft \
      iptables-nft-restore \
      iptables-nft-save \
      iptables-restore \
      iptables-restore-translate \
      iptables-save \
      iptables-translate \
      xtables-monitor; \
    do \
      ln -sf xtables-nft-multi "$link"; \
    done

# Precreate the /var/run/dikastes directory so that we don't need any elevated
# permission to create the directory at runtime.
RUN mkdir -p /rootfs/var/run/dikastes

FROM scratch AS source

ARG BINDIR
ARG TARGETARCH

COPY --from=builder /rootfs/ /

COPY --from=builder /usr/sbin/nft /usr/sbin/nft
COPY --from=builder /usr/sbin/xtables-nft-multi /usr/sbin/xtables-nft-multi

COPY --from=builder /lib64/libgmp.so.10 /lib64/libgmp.so.10
COPY --from=builder /lib64/libjansson.so.4 /lib64/libjansson.so.4
COPY --from=builder /lib64/libmnl.so.0 /lib64/libmnl.so.0
COPY --from=builder /lib64/libnftables.so.1 /lib64/libnftables.so.1
COPY --from=builder /lib64/libnftnl.so.11 /lib64/libnftnl.so.11
COPY --from=builder /lib64/libreadline.so.8 /lib64/libreadline.so.8
COPY --from=builder /lib64/libtinfo.so.6 /lib64/libtinfo.so.6
COPY --from=builder /lib64/libxtables.so.12 /lib64/libxtables.so.12

# xtables modules are expected to be in /usr/lib64/xtables/
COPY --from=builder /usr/lib64/xtables/ /usr/lib64/xtables/

COPY ${BINDIR}/dikastes-${TARGETARCH} /dikastes
COPY geoip/dbip-city-lite.mmdb /opt/geoip/dbip-city-lite.mmdb

FROM ${CALICO_BASE}

ARG GIT_VERSION=unknown

LABEL org.opencontainers.image.description="Calico Dikastes enables Application Layer Policy"
LABEL org.opencontainers.image.authors="maintainers@tigera.io"
LABEL org.opencontainers.image.source="https://github.com/projectcalico/calico"
LABEL org.opencontainers.image.title="Calico Dikastes"
LABEL org.opencontainers.image.vendor="Project Calico"
LABEL org.opencontainers.image.version="${GIT_VERSION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY --from=source / /

ENTRYPOINT ["/dikastes"]
