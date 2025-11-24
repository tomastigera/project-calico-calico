#!/bin/bash -e

docker exec "${APISERVER_NAME}" kubectl apply -f "/go/src/${PACKAGE_NAME}/test/role.yaml"
docker exec "${APISERVER_NAME}" kubectl apply -f "/go/src/${PACKAGE_NAME}/test/token-binding.yaml"

docker exec "${APISERVER_NAME}" kubectl apply -f "/go/src/${PACKAGE_NAME}/test/pip/roles.yaml"
docker exec "${APISERVER_NAME}" kubectl apply -f "/go/src/${PACKAGE_NAME}/test/pip/role-bindings.yaml"

docker exec "${APISERVER_NAME}" kubectl create clusterrole selfsubjectreview \
	--verb=create --resource=selfsubjectaccessreviews.authorization.k8s.io

# Create service accounts for FV tests
docker exec "${APISERVER_NAME}" kubectl create sa fv-cluster-admin --namespace=default || true
docker exec "${APISERVER_NAME}" kubectl create clusterrolebinding fv-cluster-admin --clusterrole=cluster-admin --serviceaccount=default:fv-cluster-admin

# Get current directory to write tokens
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Generate tokens and save to files for test usage (write to host filesystem, not container)
docker exec "${APISERVER_NAME}" kubectl create token fv-cluster-admin --duration=24h > "${SCRIPT_DIR}/ui-apis-token"
