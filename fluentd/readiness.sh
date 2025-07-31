#!/bin/sh

set -e -o pipefail

# set up any environment variables necessary for our liveness check to run properly
source ${ROOT_DIR}/bin/splunk-environment.sh

# Query fluentd monitor_agent metrics
# curl will return non-zero error code on failure.
output=$(curl -f -s "http://localhost:24220/api/plugins.json")
# Get the current metrics of elasticsearch for flows, dns, l7, audit_ee, audit_kube, bgp.
# the tigera_secure_ee output contains multiple values.
tigera_secure_ee=$(echo "$output" | jq -r '.plugins[] | select(.config.index_name) | select(.config.index_name | startswith("tigera_secure_ee"))')

# Special case: If flow logs has been turned off, then skip the check and return ready.
retry_count=$(echo "$tigera_secure_ee" | jq -r '.retry_count' | awk '{ SUM += $0 } END { print SUM }')
if [ -z "$retry_count" ]; then
    echo "Flow logs to ES is disabled, skip the retry/buffer check"
    exit 0
fi

# Verify if we have enough available buffer space left
# by default, the total buffer size is 512MB in memory or 64GB on disk
# see: https://docs.fluentd.org/configuration/buffer-section#buffering-parameters
# The command below uses awk as an alternative for the `head` command. Head for unknown reasons causes issues with the kubelet.
buffer_avail_ratio=$(echo "$tigera_secure_ee" | jq -r ".buffer_available_buffer_space_ratios" | sort -n | awk 'FNR <= 1')
LOWER_BOUND_PERCENTAGE=5
if [ -n "$buffer_avail_ratio" ] && [ "$buffer_avail_ratio" -lt "$LOWER_BOUND_PERCENTAGE" ]; then
    echo "Remaining buffer is lower than the required percentage: $buffer_avail_ratio < $LOWER_BOUND_PERCENTAGE"
    # remaining buffer is low so we shouldn't accept new requests
    exit 1
fi

exit 0
