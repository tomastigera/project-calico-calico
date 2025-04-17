ARG KINDEST_NODE_VERSION
FROM kindest/node:${KINDEST_NODE_VERSION}

# docker build on gcloud VMs fails when running 'apt-get update' with this error:
# E: Problem executing scripts APT::Update::Post-Invoke 'rm -f /var/cache/apt/archives/*.deb /var/cache/apt/archives/partial/*.deb /var/cache/apt/*.bin || true'
# E: Sub-process returned an error code
# make: Leaving directory '/home/ubuntu/calico/node'
# The command '/bin/sh -c apt-get update' returned a non-zero code: 100
# Removing this file fixes that.
RUN rm /etc/apt/apt.conf.d/docker-clean

RUN apt-get update
RUN apt-get install -y podman

COPY get-ips.sh /
RUN chmod +x /get-ips.sh

COPY tmp/calico-node.tar /
RUN mkdir /calico-early

ARG EARLY_NETWORK_CONFIG_FILE
COPY ${EARLY_NETWORK_CONFIG_FILE} /calico-early/cfg.yaml
