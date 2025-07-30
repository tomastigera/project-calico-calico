# Tigera API server

This folder contains the Tigera API server for Kubernetes.

## Building the plugins and running tests

To build the code into a docker image:

```bash
make image
```

The unit tests can be run via `ut` Makefile target:

```bash
make ut
```

The integration tests/functional verification tests can be run via the `fv`/`fv-kdd` Makefile target:

```bash
make fv
```

## Adding resources to apiserver

Add the new resource definitions to tigera/api and associated code in libcalico-go.  Ensure the code auto-generation is run (make gen-files) in both repositories.

The overall approach is largely identical for both namespaced (e.g. network policy) as well as non-namespaced (e.g. globalnetworkset) resources:

1. Add the resource type definitions to `tigera/api`. This is likely comprised of a List `struct` type and an individual resource type. For example:

```go
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LicenseKeyList is a list of LicenseKey objects.
type LicenseKeyList struct {
  metav1.TypeMeta
  metav1.ListMeta

  Items []LicenseKey
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// If your object has a status subresource:
// +kubebuilder:subresource:status

type LicenseKey struct {
  metav1.TypeMeta
  metav1.ObjectMeta

  Spec calico.LicenseKeySpec
  // If your object has a status subresource:
  Status calico.LicenseKeyStatus
}
```

Pay particular attention the `genclient` metadata - the above example is for a non-namespaced resource.

2. Add the k8s-facing resource types to `pkg/apis/projectcalico/v3/types.go`. This will be similar to the types above, except the metadata fields indicate how to pack/unpack json data. The contents will essentially use the Calico v3 resource type. For example:

```go
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LicenseKeyList  is a list of license objects.
type LicenseKeyList struct {
  metav1.TypeMeta `json:",inline"`
  metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

  Items []LicenseKey `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// If your object has a status subresource:
// +kubebuilder:subresource:status

type LicenseKey struct {
  metav1.TypeMeta   `json:",inline"`
  metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

  Spec calico.LicenseKeySpec `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
  // If your object has a status subresource:
  Status calico.LicenseKeyStatus `json:"status,omitempty" protobyf:"bytes,3,opt,name=status"`
}
```

3. Once you have these type declarations, add the resource and resource list types to `api/pkg/apis/projectcalico/v3/register.go`. For example:

```go
...
&LicenseKey{},
&LicenseKeyList{},
...
```

4. Register the field label conversion anonymous function in `addConversionFuncs()` in `pkg/apis/projectcalico/v3/conversion.go`. For example:

```go
err = scheme.AddFieldLabelConversionFunc(schema.GroupVersionKind{"projectcalico.org", "v3", "LicenseKey"},
  func(label, value string) (string, string, error) {
    switch label {
    case "metadata.name":
      return label, value, nil
    default:
      return "", "", fmt.Errorf("field label not supported: %s", label)
    }
  },
)
if err != nil {
  return err
}
```

5. Add backend storage and associated strategies for your resource types. A simple approach is to just copy the two files below into your own package (and associated directory), and then modify the types to point to your resource declarations from the first couple of steps. For example:

* `pkg/registry/projectcalico/licensekey/storage.go`
* `pkg/registry/projectcalico/licensekey/strategy.go`

If your resource has a status subresource, use the following instead:

* `pkg/registry/projectcalico/globalthreatfeed/storage.go`
* `pkg/registry/projectcalico/globalthreatfeed/strategy.go`

6. Add a reference to your storage strategy created in the previous steps to `pkg/registry/projectcalico/rest/storage_calico.go`. This registers a callback for REST API calls for your resource type. For example:

```go
import (
  ...
  calicolicensekey "github.com/tigera/calico-k8sapiserver/pkg/registry/projectcalico/licensekey"
)
...

licenseKeyRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("licensekeys"))
if err != nil {
  return nil, err
}
licenseKeysSetOpts := server.NewOptions(
  etcd.Options{
    RESTOptions:   licenseKeyRESTOptions,
    Capacity:      10,
    ObjectType:    calicolicensekey.EmptyObject(),
    ScopeStrategy: calicolicensekey.NewStrategy(scheme),
    NewListFunc:   calicolicensekey.NewList,
    GetAttrsFunc:  calicolicensekey.GetAttrs,
    Trigger:       nil,
  },
  calicostorage.Options{
    RESTOptions:  licenseKeyRESTOptions,
    LicenseCache: licenseCache,
  },
  p.StorageType,
  authorizer,
)
```

If your resource has a status subresource, also register RESTapi calls for your status subresource:

```go
...
gThreatFeedStatusRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("globalthreatfeeds/status"))
if err != nil {
    return nil, err
}

gThreatFeedStatusOpts := server.NewOptions(
    sharedGlobalThreatFeedEtcdOpts,
    calicostorage.Options{
        RESTOptions:  gThreatFeedStatusRESTOptions,
        LicenseCache: licenseCache,
    },
    p.StorageType,
    authorizer,
    []string{},
)
```

Update the storage map (also in `pkg/registry/projectcalico/rest/storage_calico.go`) for your resource key with the associated REST api type, for example:

```go
...
storage["licensekeys"] = calicolicensekey.NewREST(scheme, *licenseKeysSetOpts)
...
```

If your resource has a status subresource:

```go
...
globalThreatFeedsStorage, globalThreatFeedsStatusStorage := calicogthreatfeed.NewREST(scheme, *gThreatFeedOpts)
storage["globalthreatfeeds"] = globalThreatFeedsStorage
storage["globalthreatfeeds/status"] = globalThreatFeedsStatusStorage
...
```

7. Create a factory function to create a resource storage implementation. Use `pkg/storage/calico/licenseKey_storage.go` as a model for your work - this is basically a copy/paste and then update the resource type declarations.
  
If your resource has a status subresource, also use `pkg/storage/calico/globalThreatFeedStatus_storage.go` as model to create subresource storage implementation.

8. Define how the API is going to be used by defining its behaviour is `hasRestrictionsFn()` If an API is restricted by a license, you need to see if the feature is defined in the [licensing library](https://github.com/tigera/licensing/blob/master/client/features/features.go). A sample of implementing restrictions can be found at `pkg/storage/calico/globalReport_storage.go`

```go
hasRestrictionsFn := func(obj resourceObject) bool {
  return !opts.LicenseMonitor.GetFeatureStatus(features.AlertManagement)
}
```

9. Add your factory function to `NewStorage()` function in `pkg/storage/calico/storage_interface.go`. For example:

```go
func NewStorage(...) {

...

  case "projectcalico.org/licensekeys":
    return NewLicenseKeyStorage(opts)
  // If there is status subresource
  case "projectcalico.org/globalthreatfeeds/status":
      return NewGlobalThreatFeedStatusStorage(opts)
}
```

10. Register your conversion routines in `pkg/storage/calico/converter.go`. For example:

```go
  convertToAAPI() {
    ...
    case *libcalicoapi.LicenseKey:
      lcgLicense := libcalicoObject.(*libcalicoapi.LicenseKey)
      aapiLicenseKey := &aapi.LicenseKey{}
      LicenseKeyConverter{}.convertToAAPI(lcgLicense, aapiLicenseKey)
      return aapiLicenseKey
  }

```

Remember to copy the Status member if your resource has one.

11. Lastly, add a clientset test for functional verification tests to `test/integration/clientset_test.go`. Take a look at the `TestLicenseKeyClient()` and `testLicenseKeyClient()` functions as an example.

* Verify you can view, modify, and create your resource via  `kubectl`, for example:

```bash
kubectl get LicenseKeys
kubectl delete licensekey default
kubectl apply -f artifacts/calico/iwantcake5-license.yaml
```

* Run `make static-checks` before creating a PR to make sure that all the changes can be goimport-ed.

* For an example pull request that contains all these changes (plus all the generated files as well), see: <https://github.com/tigera/calico-private/pull/4214>.

* For one with a status subresource, see: <https://github.com/tigera/calico-k8sapiserver/pull/104> and <https://github.com/tigera/calico-k8sapiserver/pull/106>.
