# Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
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

# Use this build stage to install iptables-legacy from EPEL.
FROM almalinux:9 AS almalinux

# Install iptables-legacy from EPEL (provides xtables-legacy-multi binary).
RUN dnf upgrade -y && dnf install -y epel-release

RUN dnf install -y \
    iptables-legacy

RUN dnf clean all

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest AS ubi

ARG TARGETARCH

# Update base packages to pick up security updates.
RUN microdnf upgrade -y

RUN microdnf install -y \
    # Don't install copious docs.
    --setopt=tsflags=nodocs \
    # Needed for iptables
    libpcap libmnl libnfnetlink libnftnl libnetfilter_conntrack \
    ipset \
    iputils \
    nftables \    
    # Need arp
    net-tools \
    # Need kmod to ensure ip6tables-save works correctly
    kmod \
    # Also needed (provides utilities for browsing procfs like ps)
    procps \
    iproute \
    # Needed for startup script
    which  \
    gawk  \
    # Needed for the cleanup script
    findutils

# Since the ubi repos do not contain all the packages we need (e.g. they're missing conntrack-tools),
# we're using AlmaLinux repos for missing packages.
COPY almalinux.repo /etc/yum.repos.d/almalinux.repo

RUN microdnf --enablerepo=appstream --enablerepo=baseos install -y \
    # Needed for conntrack - from appstream
    libnetfilter_cthelper libnetfilter_cttimeout libnetfilter_queue \
    conntrack-tools \
    # From baseos
    iproute-tc \
    iptables-nft

COPY --from=almalinux /usr/sbin/xtables-legacy-multi /usr/sbin/xtables-legacy-multi

# Set symbolic links for legacy iptables binaries
RUN set -eux; \
    for bin in iptables-legacy iptables-legacy-restore iptables-legacy-save ip6tables-legacy ip6tables-legacy-restore ip6tables-legacy-save; do \
        ln -sf /usr/sbin/xtables-legacy-multi /usr/sbin/${bin} || true; \
    done

# Set alternatives
RUN alternatives --install /usr/sbin/iptables iptables /usr/sbin/iptables-legacy 1 && \
    alternatives --set iptables /usr/sbin/iptables-legacy && \
    alternatives --install /usr/sbin/ip6tables ip6tables /usr/sbin/ip6tables-legacy 1 && \
    alternatives --set ip6tables /usr/sbin/ip6tables-legacy

RUN microdnf clean all

COPY bin/egressd-${TARGETARCH} /egressd

# Add symlink to modprobe where iptables expects it to be.
RUN test -f /sbin/modprobe || ln -s /usr/sbin/modprobe /sbin/modprobe

# Clean out as many files as we can from the filesystem.  We no longer need dnf or the platform python install
# or any of its dependencies.
COPY clean-up-filesystem.sh /clean-up-filesystem.sh
RUN touch /in-the-container && /clean-up-filesystem.sh

# Copy everything into a fresh scratch image so that naive CVE scanners don't pick up binaries and libraries
# that have been removed in our later layers.
FROM scratch

ARG GIT_VERSION=unknown

# Required labels for certification
LABEL description="Calico egress gateway configures networking for egress gateway pod"
LABEL maintainer="maintainers@tigera.io"
LABEL name="Calico egress gateway"
LABEL release="1"
LABEL summary="Calico gateway image for egress traffic"
LABEL vendor="Project Calico"
LABEL version=${GIT_VERSION}

# base ubi image has been cleaned from  clean-up-filesystem.sh of all unnecessary imports
COPY --from=ubi / /

COPY init-gateway.sh /init-gateway.sh
COPY start-gateway.sh /start-gateway.sh
