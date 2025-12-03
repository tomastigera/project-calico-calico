# Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

FROM almalinux:9 AS builder

ARG DAQ_VERSION=3.0.22
ARG SNORT3_VERSION

RUN dnf upgrade -y && dnf install -y \
    epel-release

RUN dnf install -y \
    autoconf \
    automake \
    bison \
    cmake \
    flex \
    gcc \
    gcc-c++ \
    hwloc-devel \
    libdnet-devel \
    libtool \
    libuuid-devel \
    luajit-devel \
    openssl-devel \
    pcre2-devel \
    pkg-config \
    xz-devel \
    zlib-devel

RUN dnf --enablerepo=crb install -y \
    libnetfilter_queue-devel \
    libnfnetlink-devel \
    libpcap-devel

RUN dnf clean all

RUN mkdir /build
WORKDIR /build

# Install snort DAQ (Data Acquisition library)
RUN curl -sfL https://github.com/snort3/libdaq/archive/refs/tags/v${DAQ_VERSION}.tar.gz | tar xz -C /build && \
    cd /build/libdaq-${DAQ_VERSION}/ && \
    ./bootstrap && ./configure --prefix=/usr --libdir=/usr/lib64 && \
    make -j$(nproc) && make install

# Build and Install Snort 3
RUN curl -sfL https://github.com/snort3/snort3/archive/refs/tags/${SNORT3_VERSION}.tar.gz | tar xz -C /build && \
    cd /build/snort3-${SNORT3_VERSION}/ && \
    ./configure_cmake.sh --prefix=/usr --build-type=Release --disable-gdb --disable-docs && \
    cd build && \
    make -j$(nproc) && make install

# Clean up build files
RUN rm -fr /build

# Create Snorts Log directory
RUN mkdir /var/log/snort /var/log/snort-alerts

# Copy Snort community rules
COPY snort3-community.rules /usr/etc/snort/rules/snort3-community.rules

# Snort config validation
RUN snort -V && snort -c /usr/etc/snort/snort.lua -R /usr/etc/snort/rules/* -T

FROM scratch

COPY --from=builder / /
