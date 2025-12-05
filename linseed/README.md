# LINSEED

Linseed is a REST API for interacting with Calico Enterprise data primitives like:

- Audit logs (Calico Enterprise and Kubernetes)
- BGP logs
- Compliance Benchmarks, Reports, Snapshots
- DNS flows and DNS logs
- Events
- Flows and Flow logs (L3 logs)
- L7 flows and L7 logs
- BGP logs
- Runtime reports
- Threat Feeds (IPSet and DomainNameSet)
- WAF logs

It also provided additional APIs that extract high level information from the primitives described above.

- processes (extracted from flow logs)
- event statistics

*What defines a log ?*

A log records the raw event that happened when two components interact within a K8S cluster over a period of time.
An example of such interaction can be establishing the connection between a client application and server application.
A log can gather statistics like how much data is being transmitted, who initiated the interaction and if the interaction was successful or not.

Logs have multiple flavours, as they gather raw data at L3-L4 level, L7 level, DNS, K8s Audit Service, BGP etc.

*What defines a flow ?*

A flow is an aggregation of one or multiple logs that describe the interaction between a source and destination over a given period of time.
Flows have direction, as they can be reported by either the source and destination.

## Sample requests

Simulate a request to ingest data from FluentD from a standalone/management cluster

```bash
curl -vvv "https://tigera-linseed.tigera-elasticsearch.svc/api/v1/flows/logs/bulk" \
-X POST \
--data-raw '{}' \
-H "Content-Type: application/x-ndjson" \
-H "Authorization: Bearer $(cat /var/run/secrets/tigera.io/linseed/token)" \
--cert /tigera-fluentd-prometheus-tls/tls.crt \
--key /tigera-fluentd-prometheus-tls/tls.key \
--cacert /etc/pki/tls/certs/ca.crt
```

Simulate a request to read data from the ui-apis backend from a standalone/management cluster

```bash
curl -vvv "https://tigera-linseed.tigera-elasticsearch.svc/api/v1/flows/logs/" \
-H "Content-Type: application/json" \
-H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
--cert /internal-manager-tls/tls.crt \
--key /internal-manager-tls/tls.key \
--cacert /etc/pki/tls/certs/ca.crt
```

## Building and testing

To build this locally, use one of the following commands:

```bash
make image
```

or

```bash
make ci
```

## Local development

To run all tests

```bash
make test
```

In order to run locally, start an elastic server on localhost and k8s server using:

```bash
make run-elastic k8s-setup copy-es-cacert
```

Start Linseed with the following environment variables:

- ELASTIC_SCHEME=http
- ELASTIC_HOST=localhost
- LINSEED_HTTPS_CERT=~/calico-private/linseed/fv/cert/localhost.crt
- LINSEED_HTTPS_KEY=~/calico-private/linseed/fv/cert/localhost.key
- LINSEED_CA=~/calico-private/linseed/fv/cert/RootCA.crt
- KUBERNETES_SERVICE_HOST=127.0.0.1
- KUBERNETES_SERVICE_PORT=6443

Or simply use the following command:

```bash
make run-image
```

Starting with ES 8, we need to create a user and password to connect to Elasticsearch. Credentials will be stored under `/calico-private/.elasticsearch.created.` as part of make run-elasticsearch.

## Clients

In order to call Linseed API, you can make use of the clients provided as part of the API.

An example to make a paginated query to read flow logs from the last 5 minutes is provided below:

```go
// Create linseed client.
config := rest.Config{
	URL:             "https://tigera-linseed.tigera-elasticsearch.svc",
	CACertPath:      "<replace with Linseed CA>",
	ClientKeyPath:   "<replace with Linseed Client Certificate Path>",
	ClientCertPath:  "<replace with Linseed Client Certificate Key>",
}
linseed, err := client.NewClient("<replace with Tenant ID or leave blank>", config, rest.WithTokenPath("<replace with Token path>"))
if err != nil {
	log.WithError(err).Fatal("failed to create linseed client")
}

// Define a context that will be used to make requests to Linseed
ctx, cancel := context.WithTimeout(context.Background(), 5 * time.Second)
defer cancel()

// Define query parameters
params := v1.FlowLogParams{
	QueryParams: v1.QueryParams{
		TimeRange: &lmav1.TimeRange{
			From: time.Now().Add(-5 * time.Second),
			To:   time.Now().Add(5 * time.Second),
		},
		MaxPageSize: 10,
	},
}

// Perform paginated list.
pager := client.NewListPager[v1.FlowLog](&params)
pages, errors := pager.Stream(ctx, linseed.FlowLogs("<replace with managed CLUSTER name or leave blank>").List)

for page := range pages {
	for _, item := range page.Items {
		// Process returned data
		log.Infof("Received item %v", item)
	}
}

if err, ok := <-errors; ok {
	log.WithError(err).Error("failed to read flow logs")
}
```

### mTLS connections

Clients needs to establish an mTLS connection when connecting to Linseed. This means that when performing the TLS
handshake, both server and client need to present a x509 certificate that are signed by a known authority.

All clients certificate are provisioned by tigera-operator as secrets in the namespace of the component that acts as
client. Operator will also configure tigera-ca-bundle in the namespace of the component to contain the CA used to
generate Linseed server certificate.

### Multi Cluster Queries

By default, all requests are made for a single cluster, which is specified in the `X-Cluster-Id` header.

Some components, e.g. the (e.g. `cc-dashboard-query-api`) need to query and aggregate data from multiple clusters.

To do this, the `X-Cluster-Id` header should be set to `v1.QueryMultipleClusters` (`"_MULTI_"`) and in the request body, 
either `all_clusters` should be set to `true` or the `clusters` field should be set to a list of required clusters.

See below for the additional RBAC requirements for querying multiple clusters.

### Tokens

Client needs to present a JWT token on all request for authentication and authorizations.

For components running inside a standalone or a management cluster, no provisioning is needed. These will make use of
Kubernetes service accounts configured on their deployment.
In this setup, tokens will be mounted by Kubernetes at this
location `/var/run/secrets/kubernetes.io/serviceaccount/token` inside the container.

For components running inside a managed cluster, Linseed will provision those tokens as secrets and tigera-operator
running inside the managed cluster will mount them as part of rendering the component.
In this setup, tokens will be mounted by tigera-operator at this location `/var/run/secrets/tigera.io/linseed/token`
inside the container.
Linseed provisions these tokens as secrets ending with suffix `-tigera-linseed-token` in the component namespace when
the managed cluster status changed to connected. Linseed runs an additional controller for token provisioning when
enabling `TOKEN_CONTROLLER_ENABLED` environment variable.
A token is valid for 24 hours. Linseed will initiate a refresh every 16 hours. Linseed keeps an internal list of
components that need to have a token provisioned.

### RBAC

All components are authorized to perform READ/WRITE actions using a special RBAC for API group `linseed.tigera.io`.
ClusterRoles/ClusterRoleBindings are created by operator in a standalone/management cluster by tigera-operator.
The Bearer token is authenticated and the component name is extracted from this token. Linseed expects a Kubernetes
service account or extract a subject claim that contains the namespace and name of the component.

Operator will also create ClusterRoleBindings using the service account of the component.

Sample ClusterRole

```yaml
kind: ClusterRole
metadata:
  name: sample-write-cluster-role
rules:
- apiGroups:
  - linseed.tigera.io
  resources:
  - flowlogs
  - kube_auditlogs
  - ee_auditlogs
  - dnslogs
  - l7logs
  - events
  - bgplogs
  - waflogs
  - runtimereports
  verbs:
  - create
```

The following RBAC can be specified:

| RESOURCE                    | VERB                      |
| --------------------------- | ------------------------- |
| `auditlogs`                 | GET                       |
| `benchmarks`                | GET/CREATE                |
| `bgplogs`                   | GET/CREATE                |
| `compliancereports`         | GET/CREATE                |
| `dnsflows`                  | GET                       |
| `dnslogs`                   | GET/CREATE                |
| `ee_auditlogs`              | CREATE                    |
| `events`                    | GET/CREATE/DISMISS/DELETE |
| `flows`                     | GET                       |
| `flowlogs`                  | GET/CREATE                |
| `kube_auditlogs`            | CREATE                    |
| `l7flows`                   | GET                       |
| `l7logs`                    | GET/CREATE                |
| `processes`                 | GET                       |
| `runtimereports`            | GET/CREATE                |
| `snapshots`                 | GET/CREATE                |
| `threatfeeds_domainnameset` | GET/CREATE/DELETE         |
| `threatfeeds_ipset`         | GET/CREATE/DELETE         |
| `waflogs`                   | GET/CREATE                |

#### Multi Cluster RBAC

The ability to query across multiple clusters requires additional RBAC permissions. 
For each resource used in a multi-cluster query, the following permissions are required:

| RESOURCE                                  | VERB |
| ----------------------------------------- | ---- |
| `auditlogs-multi-cluster`                 | GET  |
| `benchmarks-multi-cluster`                | GET  |
| `bgplogs-multi-cluster`                   | GET  |
| `compliancereports-multi-cluster`         | GET  |
| `dnsflows-multi-cluster`                  | GET  |
| `dnslogs-multi-cluster`                   | GET  |
| `events-multi-cluster`                    | GET  |
| `flows-multi-cluster`                     | GET  |
| `flowlogs-multi-cluster`                  | GET  |
| `l7flows-multi-cluster`                   | GET  |
| `l7logs-multi-cluster`                    | GET  |
| `processes-multi-cluster`                 | GET  |
| `runtimereports-multi-cluster`            | GET  |
| `snapshots-multi-cluster`                 | GET  |
| `threatfeeds_domainnameset-multi-cluster` | GET  |
| `threatfeeds_ipset-multi-cluster`         | GET  |
| `waflogs-multi-cluster`                   | GET  |

### Environment variables

A component running inside a management/standalona cluster will have the following environment variables configured:

```text
LINSEED_URL:                https://tigera-linseed.tigera-elasticsearch.svc
LINSEED_CA:                 /etc/pki/tls/certs/ca.crt
LINSEED_CLIENT_CERT:        /<REPLACE_COMPONENT_NAME>-tls/tls.crt
LINSEED_CLIENT_KEY:         /<REPLACE_COMPONENT_NAME>-tls/tls.key
LINSEED_TOKEN:              /var/run/secrets/kubernetes.io/serviceaccount/token
```

A component running inside a managed cluster will have the following environment variables configured

```text
LINSEED_URL:                https://tigera-linseed.tigera-elasticsearch.svc
LINSEED_CA:                 /etc/pki/tls/certs/ca.crt
LINSEED_CLIENT_CERT:        /<REPLACE_COMPONENT_NAME>-tls/tls.crt
LINSEED_CLIENT_KEY:         /<REPLACE_COMPONENT_NAME>-tls/tls.key
LINSEED_TOKEN:              /var/run/secrets/tigera.io/linseed/token
```

## Configuration and permissions

| ENV                                       |                  Default value                   |                                                                                                                          Description |
| ----------------------------------------- |:------------------------------------------------:| -----------------------------------------------------------------------------------------------------------------------------------: |
| LINSEED_PORT                              |                      `443`                       |                                                                                                      Local Port to start the service |
| LINSEED_HOST                              |                     <empty>                      |                                                                                                                 Host for the service |
| LINSEED_LOG_LEVEL                         |                      `Info`                      |                                                                                                             Log Level across service |
| KUBECONFIG                                |                        -                         |                                                                                                     Path to KubeConfig configuration |
| LINSEED_HTTPS_CERT                        |              `/certs/https/tls.crt`              |                                                                                                                     Path to tls cert |
| LINSEED_HTTPS_KEY                         |              `/certs/https/tls.key`              |                                                                                                                      Path to tls key |
| LINSEED_ENABLE_METRICS                    |                     `false`                      |                                                                                          Enable /metrics endpoint. Enabled for Cloud |
| LINSEED_METRICS_PORT                      |                      `9095`                      |                                                                                       Specify a port to expose the /metrics endpoint |
| LINSEED_METRICS_CERT                      |              `/certs/https/tls.crt`              |                                                                                       Specify x509 certificate for /metrics endpoint |
| LINSEED_METRICS_KEY                       |              `/certs/https/tls.key`              |                                                                                            Specify private key for /metrics endpoint |
| LINSEED_TOKEN_KEY                         |            `/certs/https/tokens.key`             |                                               Provide a path for the private key to be used for token generation for managed cluster |
| LINSEED_CA_CERT                           |            `/certs/https/client.crt`             |                                                                                                                      Path to ca cert |
| LINSEED_EXPECTED_TENANT_ID                |                        -                         |                                                       ExpectedTenantID will be verified against x-tenant-id header for all API calls |
| TENANT_NAMESPACE                          |                        -                         |                                                                         Tenant namespace will populated only in a multi-tenant setup |
| MANAGEMENT_OPERATOR_NS                    |                `tigera-operator`                 |                                                      The namespace in which tigera-operator is running inside the management cluster |
| TOKEN_CONTROLLER_ENABLED                  |                     `false`                      |                                     Enabling Token controller. Will provision tokens for components running inside a managed cluster |
| LINSEED_MULTI_CLUSTER_FORWARDING_ENDPOINT | `https://calico-manager.calico-system.svc:9443`  |                                  Tigera Manager Endpoint used to override K8S API Endpoint to make requests inside a managed cluster |
| LINSEED_MULTI_CLUSTER_FORWARDING_CA       |           `/etc/pki/tls/certs/ca.crt`            |                                                        Path to the CA that trust the certificate provided by tigera manager endpoint |
| LINSEED_HEALTH_PORT                       |                      `8080`                      |                                                                                   Health port used for readiness and liveness probes |
| ELASTIC_HOST                              | `tigera-secure-es-http.tigera-elasticsearch.svc` |                                                                                    Elastic Host; For local development use localhost |
| ELASTIC_PORT                              |                      `9200`                      |                                                                                         Elastic Port; For local development use 9200 |
| ELASTIC_SCHEME                            |                     `https`                      |                                                                                 Defines what protocol is used to sniff Elastic nodes |
| ELASTIC_USERNAME                          |                     <empty>                      |                                                Elastic username; If left empty, communication with Elastic will not be authenticated |
| ELASTIC_PASSWORD                          |                     <empty>                      |                                                Elastic password; If left empty, communication with Elastic will not be authenticated |
| ELASTIC_CA                                |          `/certs/elasticsearch/tls.crt`          |                                                                                                          Elastic ca certificate path |
| ELASTIC_CLIENT_CERT                       |        `/certs/elasticsearch/client.crt`         |                                Elastic client certificate path; It will only be picked up if LINSEED_ELASTIC_MTLS_ENABLED is enabled |
| ELASTIC_CLIENT_KEY                        |        `/certs/elasticsearch/client.key`         |                                        Elastic client key path; It will only be picked up if LINSEED_ELASTIC_MTLS_ENABLED is enabled |
| ELASTIC_MTLS_ENABLED                      |                     `false`                      |                                                                               Enables mTLS communication between Elastic and Linseed |
| ELASTIC_GZIP_ENABLED                      |                     `false`                      |                                                                               Enables gzip communication between Elastic and Linseed |
| ELASTIC_SNIFFING_ENABLED                  |                     `false`                      |                                                                                                   Enabled sniffing for Elastic nodes |
| ELASTIC_REPLICAS                          |                       `0`                        |                                                                                                  Elastic replicas for index creation |
| ELASTIC_SHARDS                            |                       `1`                        |                                                                                                    Elastic shards for index creation |
| ELASTIC_FLOW_REPLICAS                     |                       `0`                        |                                                                                            Elastic replicas for flows index creation |
| ELASTIC_FLOW_SHARDS                       |                       `1`                        |                                                                                              Elastic shards for flows index creation |
| ELASTIC_DNS_REPLICAS                      |                       `0`                        |                                                                                              Elastic replicas for DNS index creation |
| ELASTIC_DNS_SHARDS                        |                       `1`                        |                                                                                                Elastic shards for DNS index creation |
| ELASTIC_AUDIT_REPLICAS                    |                       `0`                        |                                                                                            Elastic replicas for Audit index creation |
| ELASTIC_AUDIT_SHARDS                      |                       `1`                        |                                                                                              Elastic shards for Audit index creation |
| ELASTIC_BGP_REPLICAS                      |                       `0`                        |                                                                                              Elastic replicas for BGP index creation |
| ELASTIC_BGP_SHARDS                        |                       `1`                        |                                                                                                Elastic shards for BGP index creation |
| ELASTIC_WAF_REPLICAS                      |                       `0`                        |                                                                                              Elastic replicas for WAF index creation |
| ELASTIC_WAF_SHARDS                        |                       `1`                        |                                                                                                Elastic shards for WAF index creation |
| ELASTIC_L7_REPLICAS                       |                       `0`                        |                                                                                               Elastic replicas for L7 index creation |
| ELASTIC_L7_SHARDS                         |                       `1`                        |                                                                                                 Elastic shards for L7 index creation |
| ELASTIC_RUNTIME_REPLICAS                  |                       `0`                        |                                                                                          Elastic replicas for runtime index creation |
| ELASTIC_RUNTIME_SHARDS                    |                       `1`                        |                                                                                            Elastic shards for runtime index creation |
| ELASTIC_INDEX_MAX_RESULT_WINDOW           |                     `10000`                      |         Elastic setting that sets the maximum value of from + size for searches. After this limit is hit, deep pagination is enabled |
| BACKEND                                   |              `elastic-multi-index`               | Linseed can either write data into multiple elastic indices (zero and single tenant mode) or into a single index (multi-tenant mode) |

Linseed is deployed in namespace `tigera-elasticsearch` as part of Calico Enterprise installation.
It establishes connections with the following components:

- `tigera-elasticsearch/tigera-elasticsearch-*` pod via service `tigera-secure-es-http.tigera-elasticsearch.svc:9200`

It has the following clients, via service `tigera-linseed.tigera-elasticsearch.svc`

- `ui-apis` container from `tigera-manager/tigera-manager-*` pod, deployment `tigera-manager/tigera-manager`
- `intrusion-detection-controller` container from `tigera-intrusion-detection/intrusion-detection-controller-*` pod,
  deployment `tigera-intrusion-detection/intrusion-detection-controller`
- `fluentd-node` container from `tigera-fluentd/fluentd-node-*` pod, daemonset `tigera-fluentd/fluentd-node`
- `fluentd-node` container from `tigera-fluentd/fluentd-node-windows*` pod,
  daemonset `tigera-fluentd/fluentd-node-windows`
- `tigera-dpi` container from `tigera-dpi/tigera-dpi-*` pod, daemonset `tigera-dpi/tigera-dpi`
- `compliance-benchmarker` container from `tigera-compliance/compliance-benchmarker-*` pod,
  daemonset `tigera-compliance/compliace-benchmarker`
- `compliance-controller` container from `tigera-compliance/compliance-controller-*` pod,
  deployment `tigera-compliance/compliace-controller`
- `compliance-snapshotter` container from `tigera-compliance/compliance-snapshotter-*` pod,
  deployment `tigera-compliance/compliace-snapshotter`
- `compliance-server` container from `tigera-compliance/compliance-server-*` pod,
  deployment `tigera-compliance/compliance-server`
- `policy-recommendation-controller` container from `calico-system/tigera-policy-recommendation-*` pod,
  deployment `calico-system\tigera-policy-recommendation`
- `adjobs` container from `tigera-intrusion-detection/cluster-tigera.io.detector.*` cron jobs
- `api` container from `cc-dashboard-query-api/cc-dashboard-query-api-*` pod, deployment `cc-dashboard-query-api/cc-dashboard-query-api` (Calico Cloud management clusters)

It requires RBAC access for:

- CREATE for authorization.k8s.io.SubjectAccessReview
- CREATE for authentication.k8s.io.TokenReviews.
- LIST,WATCH for projectcalico.org.ManagedClusters

All communication with Linseed requires mTLS. X509 certificates will be mounted inside the pod via operator at `/etc/pki/tls/certs/` and `/tigera-secure-linseed-cert`

## Docs

- [Low level design for changes to the log storage subsystem](https://docs.google.com/document/d/1raHOohq0UWlLD9ygqsvu4vPMNNS9iGeY5xhHKt0O3Hc/edit?usp=sharing)
- [Multi-tenancy Proposal](https://docs.google.com/document/d/1HM0gba3hlR_cdTqHWc-NSqoiGHrVdTc_g1w3k8NmSdM/edit?usp=sharing)
