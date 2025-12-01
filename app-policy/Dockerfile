# Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
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

ARG UBI_IMAGE
ARG CALICO_BASE

FROM ${UBI_IMAGE} AS builder

# Update base packages to pick up security updates and embedding iptables
RUN microdnf upgrade -y && microdnf install -y findutils iptables && \
  ldd /sbin/iptables | tr -s '[:blank:]' '\n' | grep '^/' | \
  xargs -I % sh -c 'mkdir -p $(dirname /deps%); cp % /deps%;'

RUN mkdir -p /var/run/dikastes

FROM scratch AS source

ARG BINDIR
ARG TARGETARCH

# Copy default GeoIP MMDB binary files from DB-IP.
COPY geoip/dbip-city-lite.mmdb /opt/geoip/dbip-city-lite.mmdb

# Precreate the /var/run/dikastes directory so that we don't need any elevated
# permission to create the directory at runtime.
COPY --from=builder /var/run/dikastes /var/run/dikastes/
COPY --from=builder /sbin/iptables /sbin/iptables
COPY --from=builder /usr/lib64/xtables /usr/lib64/xtables
COPY --from=builder /deps /

COPY ${BINDIR}/dikastes-${TARGETARCH} /dikastes

FROM ${CALICO_BASE}

ARG GIT_VERSION=unknown

LABEL org.opencontainers.image.description="Calico Dikastes enables Application Layer Policy"
LABEL org.opencontainers.image.authors="maintainers@tigera.io"
LABEL org.opencontainers.image.source="https://github.com/projectcalico/calico"
LABEL org.opencontainers.image.title="Calico Dikastes"
LABEL org.opencontainers.image.vendor="Project Calico"
LABEL org.opencontainers.image.version="${GIT_VERSION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY --from=source / /

ENTRYPOINT ["/dikastes"]
