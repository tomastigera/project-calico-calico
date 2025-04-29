# Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

ARG CALICO_BASE
ARG THIRD_PARTY_REGISTRY

FROM ${THIRD_PARTY_REGISTRY}/elasticsearch:v8.17.4 AS elastic

FROM scratch AS source

ARG TARGETARCH

# binary dependencies
COPY --from=elastic /bin/bash /bin/bash
COPY --from=elastic /bin/sh /bin/sh
COPY --from=elastic /usr/bin/basename /usr/bin/basename
COPY --from=elastic /usr/bin/bash /usr/bin/bash
COPY --from=elastic /usr/bin/cat /usr/bin/cat
COPY --from=elastic /usr/bin/chown /usr/bin/chown
COPY --from=elastic /usr/bin/coreutils /usr/bin/coreutils
COPY --from=elastic /usr/bin/cp /usr/bin/cp
COPY --from=elastic /usr/bin/date /usr/bin/date
COPY --from=elastic /usr/bin/dirname /usr/bin/dirname
COPY --from=elastic /usr/bin/env /usr/bin/env
COPY --from=elastic /usr/bin/grep /usr/bin/grep
COPY --from=elastic /usr/bin/id /usr/bin/id
COPY --from=elastic /usr/bin/ln /usr/bin/ln
COPY --from=elastic /usr/bin/ls /usr/bin/ls
COPY --from=elastic /usr/bin/mkdir /usr/bin/mkdir
COPY --from=elastic /usr/bin/sh /usr/bin/sh
COPY --from=elastic /usr/bin/sleep /usr/bin/sleep
COPY --from=elastic /usr/bin/touch /usr/bin/touch
COPY --from=elastic /usr/bin/uname /usr/bin/uname
COPY --from=elastic /usr/bin/yes /usr/bin/yes
COPY --from=elastic /usr/sbin/chroot /usr/sbin/chroot

COPY --from=elastic /lib64/libacl.so.1 /lib64/libacl.so.1
COPY --from=elastic /lib64/libattr.so.1 /lib64/libattr.so.1
COPY --from=elastic /lib64/libcap.so.2 /lib64/libcap.so.2
COPY --from=elastic /lib64/libdl.so.2 /lib64/libdl.so.2
COPY --from=elastic /lib64/libpcre.so.1 /lib64/libpcre.so.1
COPY --from=elastic /lib64/libpcre2-8.so.0 /lib64/libpcre2-8.so.0
COPY --from=elastic /lib64/librt.so.1 /lib64/librt.so.1
COPY --from=elastic /lib64/libselinux.so.1 /lib64/libselinux.so.1
COPY --from=elastic /lib64/libtinfo.so.6 /lib64/libtinfo.so.6
COPY --from=elastic /lib64/libzstd.so.1 /lib64/libzstd.so.1
COPY --from=elastic /lib64/libstdc++.so.6 /lib64/libstdc++.so.6
COPY --from=elastic /lib64/libgcc_s.so.1 /lib64/libgcc_s.so.1
COPY --from=elastic /lib64/libsystemd.so.0 /lib64/libsystemd.so.0
COPY --from=elastic /lib64/liblzma.so.5 /lib64/liblzma.so.5
COPY --from=elastic /lib64/librt.so.1 /lib64/librt.so.1

COPY --from=elastic /lib64/liblzma.so.5 /lib64/liblzma.so.5
COPY --from=elastic /lib64/liblz4.so.1 /lib64/liblz4.so.1
COPY --from=elastic /lib64/libgcrypt.so.20 /lib64/libgcrypt.so.20
COPY --from=elastic /lib64/libgpg-error.so.0 /lib64/libgpg-error.so.0

COPY --from=elastic /lib64/libmount.so.1 /lib64/libmount.so.1
COPY --from=elastic /lib64/libblkid.so.1 /lib64/libblkid.so.1
COPY --from=elastic /lib64/libuuid.so.1 /lib64/libuuid.so.1

# required by jvm
COPY --from=elastic /lib64/libm.so.6 /lib64/libm.so.6
COPY --from=elastic /lib64/libz.so.1 /lib64/libz.so.1

# user and groups
COPY --from=elastic /etc/group /etc/group
COPY --from=elastic /etc/passwd /etc/passwd
COPY --from=elastic /etc/shadow /etc/shadow

# elasticsearch jars and binaries
COPY --from=elastic /usr/share/elasticsearch /usr/share/elasticsearch/
COPY --from=elastic /usr/bin/tini /usr/bin/tini

# tigera custom elasticsearch readiness-probe
COPY bin/readiness-probe-${TARGETARCH} /usr/bin/readiness-probe

FROM ${CALICO_BASE}

ENV ELASTIC_CONTAINER=true
ENV PATH=/usr/share/elasticsearch/bin:/usr/sbin:/usr/bin:/sbin:/bin

COPY --from=source / /

WORKDIR /usr/share/elasticsearch

EXPOSE 9200 9300

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/share/elasticsearch/bin/docker-entrypoint.sh"]

CMD ["eswrapper"]
