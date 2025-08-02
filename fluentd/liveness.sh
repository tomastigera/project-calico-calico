#!/bin/sh

set -e -o pipefail

# set up any environment variables necessary for our liveness check to run properly
source ${ROOT_DIR}/bin/splunk-environment.sh

curl -s http://localhost:24220/api/plugins.json | jq >/tmp/liveness_probe.json
