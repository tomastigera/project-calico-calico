#!/bin/bash
# Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

#
# This script makes and pushes images for Windows.
# It assumes Windows instances are provisioned with the terraform scripts
# located at github.com/tigera/process/testing/windows-instances.
set -ex -o pipefail

# Build eks log forwarder binaries on the Semaphore VM.
if [[ "$BASE" != "true" ]]; then
  make bin/eks-log-forwarder-startup.exe
fi

# Tar up repo so we can send it to the Windows instances where we will build the docker image.
cd "$HOME"
tar --exclude='.go-pkg-cache' --exclude='.go-build-cache' -czf "$HOME/calico-private.tar.gz" calico-private

GCR_SECRET=$(cat ~/secrets/banzai-google-service-account.json | base64 -w0)
GCR_LOGIN="[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('${GCR_SECRET}')) | docker login -u _json_key --password-stdin https://gcr.io"

# The set of commands we run on each Windows instance:
# - Untar the calico-private repo tarball
# - Login to gcr.io
# - Tell git to ignore permission differences between Linux and Windows systems
# - Build and push images
CMD="powershell -Command \"tar xzf c:\\calico-private.tar.gz -C c:\\; cd c:\\calico-private; ${GCR_LOGIN}; git config core.filemode false;"
if [[ "$BASE" == "true" ]]; then
  CMD="${CMD} make -C third_party/fluentd-base cd CONFIRM=${CONFIRM} SEMAPHORE_GIT_BRANCH=${SEMAPHORE_GIT_BRANCH} SEMAPHORE_GIT_REF_TYPE=${SEMAPHORE_GIT_REF_TYPE}"
else
  CMD="${CMD} make -C fluentd cd BRANCH_NAME=${BRANCH_NAME} CONFIRM=${CONFIRM} SEMAPHORE_GIT_REF_TYPE=${SEMAPHORE_GIT_REF_TYPE}"
fi

# Loop over all host IPs. hosts.txt is created by the Windows host creation
# script and each host IP, one per line.
SSH_ARGS="-i ${PROCESS_REPO}/tf/master_ssh_key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"

while read -r host; do
  LOG_FILE=~/log-${host}.txt

  # Copy over the calico-private tarball.
  scp -vr ${SSH_ARGS} "$HOME/calico-private.tar.gz" "Administrator@${host}:/" </dev/null

  # Kick off cmd in the background, saving the individual logs.
  ssh ${SSH_ARGS} "Administrator@${host}" "${CMD}" </dev/null | tee "${LOG_FILE}" &
done <"${PROCESS_REPO}/hosts.txt"

# Wait until all image pushing is done.
wait

# Upload logs to artifact store.
while read -r host; do
  LOG_FILE=~/log-${host}.txt
  artifact push job --expire-in 2w ${LOG_FILE}
done <"${PROCESS_REPO}/hosts.txt"
