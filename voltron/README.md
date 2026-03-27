# Voltron
Components for managing multiple clusters through a single management plane. 

There are currently two components: 
* Voltron - a backend server component running in Management Plane
* Guardian - an agent running in each App Cluster that communicates with Voltron and proxies requests to its local Kube API server

## Build and deploy

Build all components:

```
make all
```

Push images
```
make cd CONFIRM=true BRANCH_NAME=branch-name
# or, automatic current branch
make cd CONFIRM=true
```

## Guardian

### Configurations

<!-- until health check restored -->
<!--GUARDIAN_PORT | Environment | 5555 | no-->
<!--GUARDIAN_HOST | Environment | localhost | no-->
Name | Type | Default | Required
--- | --- | --- | ---
GUARDIAN_LOGLEVEL | Environment | DEBUG | no
GUARDIAN_CERT_PATH | Environment | /certs | no
GUARDIAN_VOLTRON_URL | Environment | none | yes
GUARDIAN_KEEP_ALIVE_ENABLE | Environment | true | no
GUARDIAN_KEEP_ALIVE_INTERVAL | Environment | 100 ms | no

### Build and deploy

Build guardian:

```
make guardian
```

Build image:
```
make tigera/guardian
```

Push image
```
make cd CONFIRM=true BRANCH_NAME=branch-name BUILD_IMAGES="tigera/guardian"
# or, automatic current branch
make cd CONFIRM=true BUILD_IMAGES="tigera/guardian"
```

## Voltron

### Configurations

Name | Type | Default
--- | --- | ---
VOLTRON_LOGLEVEL | Environment | DEBUG
VOLTRON_PORT | Environment | 5555
VOLTRON_HOST | Environment | any
VOLTRON_TUNNEL_PORT | Environment | 5566
VOLTRON_TUNNEL_HOST | Environment | any
VOLTRON_TUNNEL_CERT | Environment | /certs/tunnel/cert
VOLTRON_TUNNEL_KEY | Environment | /certs/tunnel/key
VOLTRON_HTTPS_CERT | Environment | /certs/https/cert
VOLTRON_HTTPS_KEY | Environment | /certs/https/key
VOLTRON_INTERNAL_HTTPS_CERT | Environment | /certs/internal/cert
VOLTRON_INTERNAL_HTTPS_KEY | Environment | /certs/internal/key
VOLTRON_PUBLIC_IP | Environment | 127.0.0.1:32453
VOLTRON_K8S_CONFIG_PATH | Environment | <empty string>
VOLTRON_KEEP_ALIVE_ENABLE | Environment | true
VOLTRON_KEEP_ALIVE_INTERVAL | Environment | 100 ms
VOLTRON_K8S_ENDPOINT | Environment | https://kubernetes.default
VOLTRON_COMPLIANCE_ENDPOINT | Environment | https://compliance.calico-monitoring.svc.cluster.local
VOLTRON_COMPLIANCE_BUNDLE_PATH | Environment | /certs/compliance/tls.crt
VOLTRON_COMPLIANCE_INSECURE_TLS | Environment | false
VOLTRON_ENABLE_IMAGE_ASSURANCE | Environment
VOLTRON_IMAGE_ASSURANCE_ENDPOINT | Environment
VOLTRON_IMAGE_ASSURANCE_CA_BUNDLE_PATH | Environment
VOLTRON_UI_BACKEND_ENDPOINT | Environment | https://127.0.0.1:8443
VOLTRON_NGINX_ENDPOINT | Environment | http://127.0.0.1:8080

### Build and deploy

Build voltron:

```
make voltron
```

Build image:
```
make tigera/voltron
```

Push image
```
make cd CONFIRM=true BRANCH_NAME=branch-name BUILD_IMAGES="tigera/voltron"
# or, automatic current branch
make cd CONFIRM=true BUILD_IMAGES="tigera/voltron"
```

# Deploy a demo using bz

![](images/arch1.png)

Please refer to the [bz install guide](https://github.com/tigera/bz-cli) and [helper scripts](https://github.com/tigera/banzai-utils/blob/master/mcm/README.md).
