FROM scratch

ARG TARGETARCH

LABEL maintainer="maintainers@tigera.io"

# Copy binary
COPY bin/dashboard-api-${TARGETARCH} /dashboard-api

# Configure entrypoint.
ENTRYPOINT ["/dashboard-api"]
