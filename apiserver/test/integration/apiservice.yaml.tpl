# We register our local tigera-apiserver with our local kube-apiserver by:
# - Setting --enable-aggregator-routing to true, so that kube-apiserver connects to APIServices via Endpoint IP, not Virtual IP
# - Creating a headless service, backed by an EndpointSlice that points to our local tigera-apiserver
# - Creating an APIService that points to our headless service and registers the v3 API
---
apiVersion: v1
kind: Service
metadata:
  name: tigera-apiserver
  namespace: default
spec:
  type: ClusterIP
  clusterIP: None           # Headless service so we can create our own backing EndpointSlice.
  ports:
  - name: https
    port: 443
    targetPort: 5443
    protocol: TCP

---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: tigera-apiserver
  namespace: default
  labels:
    kubernetes.io/service-name: tigera-apiserver
endpoints:
- addresses:
  - ${HOST_IP}          # Loopback IP will fail validation - must be the host IP.
ports:
- name: https
  port: 5443
  protocol: TCP
addressType: IPv4

---
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  name: v3.projectcalico.org
spec:
  group: projectcalico.org
  version: v3
  service:
    name: tigera-apiserver
    namespace: default
    port: 443
  groupPriorityMinimum: 1500
  versionPriority: 200
  insecureSkipTLSVerify: true
