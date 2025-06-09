#!/bin/bash
set -ex

make VALIDARCHES=amd64 image-all

mkdir -p certs
podname=$(kubectl get po -n  "tigera-fluentd" -l k8s-app=fluentd-node --no-headers -o custom-columns=":metadata.name" | tail -1)
kubectl exec -n "tigera-fluentd" "$podname" -- cat /etc/pki/tls/certs/ca.crt > certs/cacert.crt
kubectl exec -n "tigera-fluentd" "$podname" -- cat /tigera-fluentd-prometheus-tls/tls.key > certs/tls.key
kubectl exec -n "tigera-fluentd" "$podname" -- cat /tigera-fluentd-prometheus-tls/tls.crt > certs/tls.crt
kubectl exec -n "tigera-fluentd" "$podname" -- cat /var/run/secrets/tigera.io/linseed/token > certs/token

pkill -9 kubectl
kubectl port-forward -n tigera-guardian svc/tigera-guardian 9443:443 &

docker run --rm -ti --network="host" -v "$(pwd)"/certs:/certs \
  -e RATE=100 \
  -e BATCH_SIZE=200 \
  -e DIRECT_OUTPUT="true" \
  -e FLOW_LOG_FILE="./flows.log" \
  -e LOG_LEVEL="DEBUG" \
  --add-host tigera-linseed.tigera-elasticsearch.svc:127.0.0.1 \
  fake-log-generator:latest-amd64
pkill -9 kubectl
