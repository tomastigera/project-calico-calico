#!/bin/bash

set -e

echo "[INFO] starting prologue for CD"

echo "[INFO] creating local secret files"
createLocalSecret "banzai-google-service-account.json" "${HOME}/secrets/banzai-google-service-account.json"
# Needed for hub cli commands to interact with github as marvin user
export GITHUB_TOKEN="${GITHUB_ACCESS_TOKEN}"

git config --global --add url."git@github.com:".insteadOf "https://github.com/"
git config --global user.email "${GITHUB_USER_EMAIL}"
git config --global user.name "${GITHUB_USER_NAME}"
gcloud auth activate-service-account --key-file="${HOME}/secrets/banzai-google-service-account.json"
gcloud auth configure-docker -q

# wait for docker to be available
if [ ! -z "${DOCKER_HOST}" ]; then
  until docker ps; do sleep 5; done
fi

echo "[INFO] Finished prologue for CD"