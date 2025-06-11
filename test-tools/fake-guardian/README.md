# Fake Guardian

### Local Setup
You must have a cloud managed and management cluster provisioned prior to starting this procedure.

1. Set NAMESPACE, MANAGED_KUBECONFIG, MANAGEMENT_KUBECONFIG, TENANT_ID variables, example:
```
export NAMESPACE="fake-guardian"
export MANAGED_KUBECONFIG="/home/glen/bzprofiles/touchdew-killer/.local/kubeconfig"
export MANAGEMENT_KUBECONFIG="/home/glen/custom-clusters/calico-cloud-clusters/scale_testing/multi-08/.local/kubeconfig"
export TENANT_ID="vg10a052"
```
2. Change directory to `cmd/create-managed-clusters` and run the `main.go` script"
```shell
cd cmd/create-managed-clusters && go run main.go
```
This will create the managed cluster connection secrets on the managed clusters (default is 10), and the managed cluster resource on the management cluster.

3. Run the shell commands below on the management cluster to get a pull secret used to pull the fake-guardian image from a private repository.

```shell
# NOTE run the next command on the MANAGEMENT cluster to get the gcp pull secret
k -n tigera-manager  get secret tigera-pull-secret -o json | jq -c 'del(.metadata)|.metadata.name="tigera-pull-secret"|.metadata.namespace="fake-guardian"'  > /tmp/tigera-pull-secret.json
```

4. Run the shell commands below on the managed cluster
```shell
# managed cluster
k create ns fake-guardian
k -n tigera-guardian get cm tigera-ca-bundle -o json | jq -c 'del(.metadata)|.metadata.name="tigera-ca-bundle"|.metadata.namespace="fake-guardian"' | kaf -
k apply -f /tmp/tigera-pull-secret.json
```
5. Deploy the fake guardian stateful set and its related resources.
```shell
k apply -f fake-guardian.yaml
```

6. Scale the statefulset up to a desired replica amount (eg.5). You may need to bump up CPU or memory for the node to scale to higher replicas.
```shell
k -n fake-guardian scale statefulset fake-guardian-ss --replicas 5
```

### running locally
```shell

k -n fake-guardian get secret fake-guardian-sa-token -o json | jq -r '.data.token|@base64d' | tr -d '\n' > /tmp/fake-guardian.token
k -n fake-guardian get cm tigera-ca-bundle -o json | jq -rc '.data["ca.crt"]' > /tmp/fake-guardian-ca.crt

cat $KUBECONFIG| yq read - -j | jq '.clusters[0].cluster["certificate-authority-data"]|@base64d' -r > /tmp/real-apiserver.crt
```

See the goland run configuration `.run/fake-guardian.run.xml` for the required environment variables, you will need to change some of these to point at your labs cluster.


### running on labs cluster
Due to the limited resources available in the labs cluster you can only run about 5 fake-guardian instances (all on the one pod)
```shell
k -n fake-guardian scale statefulset fake-guardian-ss --replicas 1
```
