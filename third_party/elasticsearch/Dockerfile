FROM registry.access.redhat.com/ubi10/ubi:latest AS builder

ARG ELASTIC_ARCH
ARG ELASTIC_VERSION
ARG TARGETARCH
ARG TINI_VERSION

RUN dnf upgrade -y && dnf clean all

################################################################################
# Install and config the elasticsearch archive
#
# Recreating the elasticsearch container image by copying essential files from
# UBI. Certain Dockerfile instructions in the scratch stage are extracted from:
# https://github.com/elastic/dockerfiles/blob/vx.y.z/elasticsearch/Dockerfile.
# We need to review and update them when upgrading to a newer version of
# elasticsearch.
################################################################################
COPY build/elasticsearch-${ELASTIC_VERSION}-linux-${ELASTIC_ARCH}.tar.gz /tmp/elasticsearch.tar.gz

RUN mkdir /usr/share/elasticsearch && \
    tar -zxf /tmp/elasticsearch.tar.gz --strip-components=1 -C /usr/share/elasticsearch/ && \
    rm -f /tmp/elasticsearch.tar.gz

COPY build/elasticsearch-${ELASTIC_VERSION}/distribution/docker/src/docker/bin/docker-entrypoint.sh /usr/share/elasticsearch/bin/docker-entrypoint.sh

# `tini` is a tiny but valid init for containers. This is used to cleanly
# control how ES and any child processes are shut down.
RUN curl -sfL https://github.com/krallin/tini/releases/download/v${TINI_VERSION}/tini-${TARGETARCH} -o /usr/bin/tini && \
    chmod 0755 /usr/bin/tini

# Add storage plugin
RUN /usr/share/elasticsearch/bin/elasticsearch-plugin install --batch repository-gcs

# Change /usr/share/elasticsearch folder ownership to elasticsearch user and group.
# Elastic gradle step installs bundle JDK into the /usr/share/elasticsearch/jdk folder.
# The folder permission is 0750 and when we deploy this UBI based container to Openshift,
# which has SELinux enabled by default, elasticsearch user get permissions errors on
# accessing JDK files. This is not an issue on non-SELinux enabled hosts like Ubuntu.
# Changing the folder ownership works on both hosts.
RUN groupadd -g 10001 elasticsearch && \
    adduser --uid 10001 --gid 10001 --home /usr/share/elasticsearch elasticsearch && \
    chown -R 10001:10001 /usr/share/elasticsearch

FROM scratch

COPY --from=builder / /
