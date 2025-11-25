ARG KIBANA_VERSION

ARG TARGETARCH

FROM docker.elastic.co/kibana/kibana-ubi:${KIBANA_VERSION}-${TARGETARCH} AS builder

ARG KIBANA_VERSION

USER 0

ENV PATH=/usr/share/kibana/bin:$PATH

WORKDIR /usr/share/kibana

COPY kibana/plugins/tigera/build/tigera-${KIBANA_VERSION}.zip /tmp/tigera-${KIBANA_VERSION}.zip
RUN /usr/share/kibana/bin/kibana-plugin install file:///tmp/tigera-${KIBANA_VERSION}.zip && \
    rm -f /tmp/tigera-${KIBANA_VERSION}.zip

COPY kibana/plugins/googletagmanager/build/googletagmanager-${KIBANA_VERSION}.zip /tmp/googletagmanager-${KIBANA_VERSION}.zip
RUN /usr/share/kibana/bin/kibana-plugin install file:///tmp/googletagmanager-${KIBANA_VERSION}.zip && \ 
    rm -f /tmp/googletagmanager-${KIBANA_VERSION}.zip

FROM scratch

COPY --from=builder / /
