# cc-dashboard-query-api

Calico Cloud Dashboard Query API

## Development

### Run locally

#### Prerequisites

* Set `tigera-linseed` to `::1` or `127.0.0.1` in the hosts file

#### Environment
```
TENANT="" # Set this for multi-tenant
[[ -n "${TENANT}" ]]; && TENANT_NAMESPACE="cc-tenant-${TENANT}"

# Environment variables

export CC_DASHBOARD_QUERY_API_LOG_LEVEL=INFO

# Kubeconfig and open telemetry
export CC_DASHBOARD_QUERY_API_KUBECONFIG=${KUBECONFIG}
export CC_DASHBOARD_QUERY_API_OPEN_TELEMETRY_ENABLED=false

# Tenant
export CC_DASHBOARD_QUERY_API_TENANT_ID=${TENANT}
export CC_DASHBOARD_QUERY_API_TENANT_NAMESPACE=${TENANT_NAMESPACE}

# HTTPS Server
export CC_DASHBOARD_QUERY_API_HTTPS_KEY=${FILES_DIR}/https-server.key
export CC_DASHBOARD_QUERY_API_HTTPS_CERT=${FILES_DIR}/https-server.crt

# Linseed client
export CC_DASHBOARD_QUERY_API_LINSEED_CA=${FILES_DIR}/tigera-ca.crt
export CC_DASHBOARD_QUERY_API_LINSEED_TOKEN=${FILES_DIR}/token
export CC_DASHBOARD_QUERY_API_LINSEED_CLIENT_KEY=${FILES_DIR}/linseed-client.key
export CC_DASHBOARD_QUERY_API_LINSEED_CLIENT_CERT=${FILES_DIR}/linseed-client.crt
export CC_DASHBOARD_QUERY_API_LINSEED_URL=https://tigera-linseed:9443/

# CORS
export CC_DASHBOARD_QUERY_API_CORS_ORIGINS=https://www.dev.calicocloud.io

# OIDC auth
export CC_DASHBOARD_QUERY_API_OIDC_AUTH_ISSUER=
export CC_DASHBOARD_QUERY_API_OIDC_AUTH_JWKSURL=
export CC_DASHBOARD_QUERY_API_OIDC_AUTH_CLIENT_ID=
export CC_DASHBOARD_QUERY_API_OIDC_AUTH_GROUPS_CLAIM=
export CC_DASHBOARD_QUERY_API_OIDC_AUTH_USERNAME_CLAIM=

```

#### Commands

```
TENANT="" # Set this for multi-tenant
[[ -n "${TENANT}" ]]; && TENANT_NAMESPACE="cc-tenant-${TENANT}"

FILES_DIR=/tmp/cc-dashboard-query-api/

mkdir -p ${FILES_DIR}

# HTTPS cert
if [[ ! -f ${FILES_DIR}/https-server.crt ]]; then
	openssl req -x509 -newkey rsa:4096 -keyout ${FILES_DIR}/https-server.key -out ${FILES_DIR}/https-server.crt -sha256 -days 3650 -nodes -subj "/C=IR/ST=Cork/L=Cork/O=Tigera/OU=Engineering/CN=dev.calicocloud.io"
fi

kubectl create token --namespace ${TENANT_NAMESPACE:-cc-dashboard-query-api} cc-dashboard-query-api --duration=1h >${FILES_DIR}/token

if [[ -n "${TENANT}" ]]; then
	kubectl get --namespace ${TENANT_NAMESPACE} secret tigera-ca-private-tenant -o 'jsonpath={.data.tls\.crt}' | base64 -d >${FILES_DIR}/tigera-ca.crt
else
	kubectl get --namespace tigera-operator secret tigera-ca-private -o 'jsonpath={.data.tls\.crt}' | base64 -d >${FILES_DIR}/tigera-ca.crt
fi

kubectl get --namespace ${TENANT_NAMESPACE:-cc-dashboard-query-api} secret cc-dashboard-query-api-linseed-access-cert-pair -o 'jsonpath={.data.tls\.crt}' | base64 -d >${FILES_DIR}/linseed-client.crt
kubectl get --namespace ${TENANT_NAMESPACE:-cc-dashboard-query-api} secret cc-dashboard-query-api-linseed-access-cert-pair -o 'jsonpath={.data.tls\.key}' | base64 -d >${FILES_DIR}/linseed-client.key

# Port forward the tigera-linseed service
kubectl port-forward -n ${TENANT_NAMESPACE:-tigera-elasticsearch} svc/tigera-linseed 9443:443
```