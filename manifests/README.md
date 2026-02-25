# Calico Enterprise manifests

This directory contains manifests for installing Calico Enterprise on Kubernetes in various ways.

The majority of the manifests in this directory are automatically generated from the helm charts
in the `charts/` directory of this repository, and can be updated by running `make gen-manifests`
in the repository root.

To make changes to the auto-generated manifests:

1. Modify the source content in either `charts/tigera-operator/` or `charts/tigera-prometheus-operator`

2. Re-run code generation from the top level of this repository

```bash
make gen-manifests
```

Some of these manifests are not automatically generated. To edit these, modify the manifests directly and
commit your changes. **The following manifests are not auto generated:**

- aks/custom-resources.yaml
- aks/custom-resources-calico-cni.yaml
- aks/custom-resources-upgrade-from-calico.yaml
- aws/*
- calicoctl.yaml
- compliance-reporter-pod.yaml
- custom-resources.yaml
- custom-resources-upgrade-from-calico.yaml
- eks/*
- fortimanager-device-configmap.yaml
- fortimanager.yaml
- fortinet-device-configmap.yaml
- fortinet.yaml
- ingress/*
- licenseagent.yaml
- ocp/00-namespace-tigera-operator.yaml
- ocp/01-cr-apiserver.yaml
- ocp/01-cr-installation.yaml
- ocp/tigera-enterprise-resources.yaml
- ocp/tigera-prometheus-operator.yaml
- rancher/*
- threatdef/*
- tigera-prometheus-operator.yaml
- ocp-tigera-operator-no-resource-loading.yaml
