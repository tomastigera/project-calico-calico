## Building and testing

In order to build the API locally, use one of the following commands:

```
LOCAL_BUILD=true make image
```

or

```
make ci cd
```

In order to run local tests, use the following command:

```
make ut
```

Clean the build:

```
make clean
```

Make a local image and push to your GCR repository to test your updates.

```
LOCAL_BUILD=true make image
```

```
docker tag tigera/policy-recommendation:latest-amd64 gcr.io/tigera-dev/<USER_NAME>/tigera/policy-recommendation:latest
```

```
docker push gcr.io/tigera-dev/<USER_NAME>/tigera/policy-recommendation:latest
```

Annotate and edit the tigera-policy-recommendation deployment

```
kubectl annotate deployment -n calico-system tigera-policy-recommendation unsupported.operator.tigera.io/ignore=true
```

```
kubectl patch deployment -n calico-system tigera-policy-recommendation \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"policy-recommendation-controller","image":"gcr.io/tigera-dev/<USER_NAME>/tigera/policy-recommendation:latest","imagePullPolicy":"Always"}]}}}}'
```

## Deployment

The deployment creates a pod within the 'calico-system' namespace, and only within the Standalone or Management cluster. Watchers will be deployed for the ManagedCluster resource within the Management cluster. The Standalone/Management clusters will start a watcher for the PolicyRecommendationScope resource in the cluster and every managed cluster added to the MCM setup.

Enabling/Disabling Policy Recommendations will trigger watchers for the Namespace, NetworkPolicy and StagedNetworkPolicy resources of the cluster.

A recommendation loop associated to each cluster runs on a fixed interval and processes updates to the flow logs for the namespaces that recommendations are generated for.

## RBAC

The tigera-policy-recommendation clusterrole contains the following RBAC:

rules:
- apiGroups:
  - ""
  resources:
  - namespaces
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - projectcalico.org
  resources:
  - tiers
  - policyrecommendationscopes
  - policyrecommendationscopes/status
  - stagednetworkpolicies
  - tier.stagednetworkpolicies
  - networkpolicies
  - tier.networkpolicies
  - globalnetworksets
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - linseed.tigera.io
  resources:
  - flows
  verbs:
  - get
- apiGroups:
  - projectcalico.org
  resources:
  - licensekeys
  - managedclusters
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - crd.projectcalico.org
  resources:
  - licensekeys
  verbs:
  - get
  - list
  - watch
