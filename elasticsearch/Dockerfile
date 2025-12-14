# Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

ARG CALICO_BASE
ARG THIRD_PARTY_REGISTRY
ARG THIRD_PARTY_RELEASE_BRANCH

FROM ${THIRD_PARTY_REGISTRY}/elasticsearch:v8.18.8-${THIRD_PARTY_RELEASE_BRANCH} AS elastic

FROM scratch AS source

ARG TARGETARCH

# Binary dependencies
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
COPY --from=elastic /lib64/libpcre2-8.so.0 /lib64/libpcre2-8.so.0
COPY --from=elastic /lib64/libselinux.so.1 /lib64/libselinux.so.1
COPY --from=elastic /lib64/libtinfo.so.6 /lib64/libtinfo.so.6

# Required by jvm
COPY --from=elastic /lib64/libdl.so.2 /lib64/libdl.so.2
COPY --from=elastic /lib64/libm.so.6 /lib64/libm.so.6
COPY --from=elastic /lib64/librt.so.1 /lib64/librt.so.1
COPY --from=elastic /lib64/libz.so.1 /lib64/libz.so.1

# Required by elasticsearch/lib/platform/linux-x64/*.so
COPY --from=elastic /lib64/libgcc_s.so.1 /lib64/libgcc_s.so.1
COPY --from=elastic /lib64/libstdc++.so.6 /lib64/libstdc++.so.6

# User and groups
COPY --from=elastic /etc/group /etc/group
COPY --from=elastic /etc/passwd /etc/passwd
COPY --from=elastic /etc/shadow /etc/shadow

# Elasticsearch jars and binaries
COPY --from=elastic /usr/share/elasticsearch /usr/share/elasticsearch/
COPY --from=elastic /usr/bin/tini /usr/bin/tini

# Tigera custom elasticsearch readiness-probe
COPY bin/readiness-probe-${TARGETARCH} /usr/bin/readiness-probe

FROM ${CALICO_BASE}

ENV ELASTIC_CONTAINER=true
ENV PATH=/usr/share/elasticsearch/bin:/usr/sbin:/usr/bin:/sbin:/bin

COPY --from=source / /

WORKDIR /usr/share/elasticsearch

EXPOSE 9200 9300

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/share/elasticsearch/bin/docker-entrypoint.sh"]

CMD ["eswrapper"]
