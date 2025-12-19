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

ARG IPTABLES_VER=1.8.2-16

# Use this build stage to build iptables rpm binaries.
# We need to rebuild the iptables rpm because the prepackaged rpm does not have legacy iptables binaries.
# FIXME(jiawei): Update the base image to AlmaLinux 9.
FROM almalinux:8 AS almalinux

ARG IPTABLES_VER
ARG CENTOS_MIRROR_BASE_URL=http://vault.centos.org/8.1.1911
ARG LIBNFTNL_VER=1.1.1-4
ARG LIBNFTNL_SOURCERPM_URL=${CENTOS_MIRROR_BASE_URL}/BaseOS/Source/SPackages/libnftnl-${LIBNFTNL_VER}.el8.src.rpm
ARG IPTABLES_SOURCERPM_URL=${CENTOS_MIRROR_BASE_URL}/BaseOS/Source/SPackages/iptables-${IPTABLES_VER}.el8.src.rpm
ARG TARGETARCH

# Install build dependencies and security updates.
RUN dnf install -y 'dnf-command(config-manager)' && \
    # Enable PowerTools repo for '-devel' packages
    dnf config-manager --set-enabled powertools && \
    # Install required packages for building rpms. yum-utils is not required but it gives us yum-builddep to easily install build deps.
    yum install -y rpm-build yum-utils make && \
    # Ensure security updates are installed.
    yum -y update-minimal --security --sec-severity=Important --sec-severity=Critical

# In order to rebuild the iptables RPM, we first need to rebuild the libnftnl RPM because building
# iptables requires libnftnl-devel but libnftnl-devel is not available on ubi or CentOS repos.
# (Note: it's not in RHEL8.1 either https://bugzilla.redhat.com/show_bug.cgi?id=1711361).
# Rebuilding libnftnl will give us libnftnl-devel too.
RUN case "${TARGETARCH}" in \
    amd64) export MACHINEARCH=x86_64 ;; \
    arm64) export MACHINEARCH=aarch64 ;; \
    *) export MACHINEARCH=${TARGETARCH} ;; \
    esac && \
    rpm -i ${LIBNFTNL_SOURCERPM_URL} && \
    yum-builddep -y --spec /root/rpmbuild/SPECS/libnftnl.spec && \
    rpmbuild -bb /root/rpmbuild/SPECS/libnftnl.spec && \
    # Now install libnftnl and libnftnl-devel
    rpm -Uv /root/rpmbuild/RPMS/${MACHINEARCH}/libnftnl-${LIBNFTNL_VER}.el8.${MACHINEARCH}.rpm && \
    rpm -Uv /root/rpmbuild/RPMS/${MACHINEARCH}/libnftnl-devel-${LIBNFTNL_VER}.el8.${MACHINEARCH}.rpm && \
    # Install source RPM for iptables and install its build dependencies.
    rpm -i ${IPTABLES_SOURCERPM_URL} && \
    yum-builddep -y --spec /root/rpmbuild/SPECS/iptables.spec

# Patch the iptables build spec so that we keep the legacy iptables binaries.
RUN sed -i '/drop all legacy tools/,/sbindir.*legacy/d' /root/rpmbuild/SPECS/iptables.spec

# Patch the iptables build spec to drop the renaming of nft binaries. Instead of renaming binaries,
# we will use alternatives to set the canonical iptables binaries.
RUN sed -i '/rename nft versions to standard name/,/^done/d' /root/rpmbuild/SPECS/iptables.spec

# Patch the iptables build spec so that legacy and nft iptables binaries are verified to be in the resulting rpm.
RUN sed -i '/%files$/a \
\%\{_sbindir\}\/xtables-legacy-multi \n\
\%\{_sbindir\}\/ip6tables-legacy \n\
\%\{_sbindir\}\/ip6tables-legacy-restore \n\
\%\{_sbindir\}\/ip6tables-legacy-save \n\
\%\{_sbindir\}\/iptables-legacy \n\
\%\{_sbindir\}\/iptables-legacy-restore \n\
\%\{_sbindir\}\/iptables-legacy-save \n\
\%\{_sbindir\}\/ip6tables-nft\n\
\%\{_sbindir\}\/ip6tables-nft-restore\n\
\%\{_sbindir\}\/ip6tables-nft-save\n\
\%\{_sbindir\}\/iptables-nft\n\
\%\{_sbindir\}\/iptables-nft-restore\n\
\%\{_sbindir\}\/iptables-nft-save\n\
' /root/rpmbuild/SPECS/iptables.spec

# Finally rebuild iptables.
RUN rpmbuild -bb /root/rpmbuild/SPECS/iptables.spec

# FIXME(jiawei): Update the base image to UBI 9.
FROM registry.access.redhat.com/ubi8/ubi-minimal:latest AS ubi

ARG IPTABLES_VER
ARG TARGETARCH

# Update base packages to pick up security updates.
RUN microdnf upgrade

# Copy in our rpms
COPY --from=almalinux /root/rpmbuild/RPMS/ /tmp/rpms/

RUN microdnf install \
    # Don't install copious docs.
    --setopt=tsflags=nodocs \
    # Needed for iptables
    libpcap libmnl libnfnetlink libnftnl libnetfilter_conntrack \
    ipset \
    iputils \
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

# Since the ubi repos do not contain all the packages we need (they're missing conntrack-tools),
# we're using AlmaLinux repos for missing packages.
COPY almalinux.repo /etc/yum.repos.d/almalinux.repo

RUN microdnf --enablerepo=baseos install \
    iproute-tc \
    nftables \
    # Needed for conntrack
    libnetfilter_cthelper libnetfilter_cttimeout libnetfilter_queue \
    conntrack-tools

# Install iptables via rpms. The libs must be force installed because the iptables source RPM has the release
# version '1.8.8-6.el8' conflicts with iptables-libs (pulled in by the iputils package) '1.8.5-11.el8_9'.
RUN case "${TARGETARCH}" in \
    amd64) export MACHINEARCH=x86_64 ;; \
    arm64) export MACHINEARCH=aarch64 ;; \
    *) export MACHINEARCH=${TARGETARCH} ;; \
    esac && \
    rpm --force -i /tmp/rpms/${MACHINEARCH}/iptables-libs-${IPTABLES_VER}.el8.${MACHINEARCH}.rpm && \
    rpm -i /tmp/rpms/${MACHINEARCH}/iptables-${IPTABLES_VER}.el8.${MACHINEARCH}.rpm && \
    # Set alternatives
    alternatives --install /usr/sbin/iptables iptables /usr/sbin/iptables-legacy 1 && \
    alternatives --install /usr/sbin/ip6tables ip6tables /usr/sbin/ip6tables-legacy 1

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
