FROM scratch

ARG TARGETARCH

LABEL maintainer="maintainers@tigera.io"
WORKDIR /gorun/

# Copy binary
COPY bin/dashboard-api-${TARGETARCH} /gorun/dashboard-api

# Configure entrypoint.
ENTRYPOINT ["/gorun/dashboard-api"]
