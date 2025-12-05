# Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

ARG CALICO_BASE_UBI10
ARG THIRD_PARTY_REGISTRY
ARG THIRD_PARTY_RELEASE_BRANCH

FROM ${THIRD_PARTY_REGISTRY}/kibana-ubi:v8.18.8-${THIRD_PARTY_RELEASE_BRANCH} AS kibana

# the base image runs as the kibana user (1000) so change user
# to root (0) to run setup scripts
USER 0

ARG GTM_INTEGRATION=disabled

COPY create_kibana_config.sh /usr/bin/create_kibana_config.sh
RUN /usr/bin/create_kibana_config.sh /usr/share/kibana/config/kibana.yml

RUN if [ "$GTM_INTEGRATION" != "enabled" ]; then \
        echo "Uninstalling Google Tag Manager plugin..."; \
        /usr/share/kibana/bin/kibana-plugin remove googletagmanager; \
    fi

FROM scratch AS source

# init script binary dependencies
COPY --from=kibana /bin/bash /bin/bash
COPY --from=kibana /bin/sh /bin/sh
COPY --from=kibana /bin/tini /bin/tini
COPY --from=kibana /usr/bin/basename /usr/bin/basename
COPY --from=kibana /usr/bin/cat /usr/bin/cat
COPY --from=kibana /usr/bin/coreutils /usr/bin/coreutils
COPY --from=kibana /usr/bin/cp /usr/bin/cp
COPY --from=kibana /usr/bin/date /usr/bin/date
COPY --from=kibana /usr/bin/dirname /usr/bin/dirname
COPY --from=kibana /usr/bin/echo /usr/bin/echo
COPY --from=kibana /usr/bin/env /usr/bin/env
COPY --from=kibana /usr/bin/grep /usr/bin/grep
COPY --from=kibana /usr/bin/ln /usr/bin/ln
COPY --from=kibana /usr/bin/ls /usr/bin/ls
COPY --from=kibana /usr/bin/touch /usr/bin/touch
COPY --from=kibana /usr/bin/tr /usr/bin/tr
COPY --from=kibana /usr/bin/xargs /usr/bin/xargs
COPY --from=kibana /usr/bin/yes /usr/bin/yes

COPY --from=kibana /lib64/libacl.so.1 /lib64/libacl.so.1
COPY --from=kibana /lib64/libattr.so.1 /lib64/libattr.so.1
COPY --from=kibana /lib64/libcap.so.2 /lib64/libcap.so.2
COPY --from=kibana /lib64/libdl.so.2 /lib64/libdl.so.2
COPY --from=kibana /lib64/libpcre2-8.so.0 /lib64/libpcre2-8.so.0
COPY --from=kibana /lib64/libselinux.so.1 /lib64/libselinux.so.1
COPY --from=kibana /lib64/libtinfo.so.6 /lib64/libtinfo.so.6

# additional node dependencies
COPY --from=kibana /lib64/libgcc_s.so.1 /lib64/libgcc_s.so.1
COPY --from=kibana /lib64/libm.so.6 /lib64/libm.so.6
COPY --from=kibana /lib64/libstdc++.so.6 /lib64/libstdc++.so.6

# kibana node binaries and packages
COPY --from=kibana /usr/local/bin/kibana-docker /usr/local/bin/kibana-docker
COPY --from=kibana /usr/share/fonts /usr/share/fonts/
COPY --from=kibana --chown=1000:0 /usr/share/kibana /usr/share/kibana/

FROM ${CALICO_BASE_UBI10}

ENV ELASTIC_CONTAINER=true
ENV PATH=/usr/share/kibana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

COPY --from=source / /

WORKDIR /usr/share/kibana

USER 1000

ENTRYPOINT ["/bin/tini", "--"]

CMD ["/usr/local/bin/kibana-docker"]
