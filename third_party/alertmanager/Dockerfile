# Copyright (c) 2022-2025 Tigera, Inc. All rights reserved.

ARG CALICO_BASE
ARG UBI_IMAGE

FROM ${UBI_IMAGE} AS builder

RUN mkdir /alertmanager

FROM scratch AS source

ARG TARGETARCH

COPY --from=builder --chown=10001:10001 /alertmanager /alertmanager

COPY alertmanager/examples/ha/alertmanager.yml /etc/alertmanager/alertmanager.yml
COPY bin/alertmanager-${TARGETARCH} /bin/alertmanager
COPY bin/amtool-${TARGETARCH} /bin/amtool

FROM ${CALICO_BASE}

COPY --from=source / /

USER       10001:10001
EXPOSE     9093
VOLUME     [ "/alertmanager" ]
WORKDIR    /alertmanager
ENTRYPOINT [ "/bin/alertmanager" ]
CMD        [ "--config.file=/etc/alertmanager/alertmanager.yml", \
             "--storage.path=/alertmanager" ]
