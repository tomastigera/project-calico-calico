FROM scratch

LABEL maintainer="maintainers@tigera.io"
WORKDIR /gorun/

# Copy binary
COPY bin/cc-dashboard-query-api /gorun/cc-dashboard-query-api

# Configure entrypoint.
ENTRYPOINT ["/gorun/cc-dashboard-query-api"]
