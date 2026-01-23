# Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.

ARG CALICO_BASE
ARG UBI_IMAGE

FROM ${UBI_IMAGE} AS ubi

RUN microdnf upgrade -y

RUN mkdir /prometheus && \
    ln -s /etc/prometheus /prometheus/prometheus

FROM scratch AS source

ARG TARGETARCH

# copy sh and curl used by startup and readiness probes.
COPY --from=ubi /bin/bash /bin/sh
COPY --from=ubi /bin/curl /bin/curl

COPY --from=ubi /lib64/libcom_err.so.2 /lib64/libcom_err.so.2
COPY --from=ubi /lib64/libcrypto.so.3 /lib64/libcrypto.so.3
COPY --from=ubi /lib64/libcurl.so.4 /lib64/libcurl.so.4
COPY --from=ubi /lib64/libgssapi_krb5.so.2 /lib64/libgssapi_krb5.so.2
COPY --from=ubi /lib64/libidn2.so.0 /lib64/libidn2.so.0
COPY --from=ubi /lib64/libk5crypto.so.3 /lib64/libk5crypto.so.3
COPY --from=ubi /lib64/libkeyutils.so.1 /lib64/libkeyutils.so.1
COPY --from=ubi /lib64/libkrb5.so.3 /lib64/libkrb5.so.3
COPY --from=ubi /lib64/libkrb5support.so.0 /lib64/libkrb5support.so.0
COPY --from=ubi /lib64/libnghttp2.so.14 /lib64/libnghttp2.so.14
COPY --from=ubi /lib64/libpcre2-8.so.0 /lib64/libpcre2-8.so.0
COPY --from=ubi /lib64/libselinux.so.1 /lib64/libselinux.so.1
COPY --from=ubi /lib64/libssl.so.3 /lib64/libssl.so.3
COPY --from=ubi /lib64/libtinfo.so.6 /lib64/libtinfo.so.6
COPY --from=ubi /lib64/libunistring.so.5 /lib64/libunistring.so.5
COPY --from=ubi /lib64/libz.so.1 /lib64/libz.so.1

# prometheus files
COPY --from=ubi --chown=10001:10001 /prometheus /prometheus

COPY prometheus/.build/linux-${TARGETARCH}/prometheus /bin/prometheus
COPY prometheus/.build/linux-${TARGETARCH}/promtool /bin/promtool
COPY prometheus/LICENSE /LICENSE
COPY prometheus/NOTICE /NOTICE
COPY prometheus/documentation/examples/prometheus.yml /etc/prometheus/prometheus.yml
COPY prometheus/npm_licenses.tar.bz2 /npm_licenses.tar.bz2

FROM ${CALICO_BASE}

COPY --from=source / /

WORKDIR /prometheus

USER       10001:10001
EXPOSE     9090
VOLUME     [ "/prometheus" ]
ENTRYPOINT [ "/bin/prometheus" ]
CMD        [ "--config.file=/etc/prometheus/prometheus.yml", \
    "--storage.tsdb.path=/prometheus"]
