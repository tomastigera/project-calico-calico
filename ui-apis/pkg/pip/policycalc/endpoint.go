package policycalc

import (
	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	"github.com/projectcalico/calico/lma/pkg/api"
)

// New creates a new EndpointCache.
func NewEndpointCache() *EndpointCache {
	return &EndpointCache{
		endpoints: make(map[string]*EndpointData),
	}
}

// EndpointData encapsulates data about a single or related set of endpoints.
type EndpointData struct {
	// The named ports configured in the endpoint.
	NamedPorts []api.EndpointNamedPort

	// The service account configured in the endpoint. Only valid for Pods.
	ServiceAccount *string

	// The labels configured on the endpoint.
	//TODO(rlb): When using the cached endpoint labels rather than the flow log labels, we should be able to cache the
	//           selector values associated with these labels for the duration of the entire eumeration.
	Labels uniquelabels.Map

	// ---- Internal data ----

	// The resource underpinning this EndpointData. The public values above are calculated from this resource
	// only when the endpoint data is explicitly requested in the cache. After calculating this data, the resource
	// is nilled out (so a non-nil value can be used to indicate the public data needs to be populated).
	resource resources.Resource
}

// EndpointCache is used for caching endpoint data that may not be contained in the flow logs.
type EndpointCache struct {
	endpoints map[string]*EndpointData
}

// Get returns the EndpointData for the requested endpoint.
func (e *EndpointCache) Get(namespace, name string) *EndpointData {
	ed := e.endpoints[namespaceName(namespace, name)]
	if ed == nil {
		// No cache entry, return nil.
		return nil
	}
	// We have a cache entry. If the resource is non-nil then we have not initialized the public endpoint data. Do that
	// first and then nil-out the resource so we don't do it again.
	if ed.resource != nil {
		e.populateEndpointData(ed)
		ed.resource = nil
	}
	return ed
}

// OnUpdates updates the cache from a compliance syncer callback.
func (e *EndpointCache) OnUpdates(updates []syncer.Update) {
	for _, u := range updates {
		if u.Type != syncer.UpdateTypeSet {
			// We only care about sets. We ignore deletes since we want to collect the full set of endpoints within the
			// interval.
			continue
		}

		// Store the current resource settings in the cache. Note that we don't process the resource until it is
		// actually requested in Get(). See populateEndpointData() which explicitly handles each of these resource
		// types.
		switch r := u.Resource.(type) {
		case *corev1.Pod:
			e.addOrUpdate(namespaceName(r.Namespace, r.Name), r)
			if r.GenerateName != "" {
				e.addOrUpdate(namespaceName(r.Namespace, r.GenerateName+"*"), r)
			}
		// Handle both the libcalico and AAPIS version of the Calico resources. We get both depending on the source of
		// the data.
		case *v3.HostEndpoint:
			e.addOrUpdate(namespaceName("", r.Name), r)
		}
	}
}

// OnStatusUpdate called from the replayer to indicate config sync status.
func (e *EndpointCache) OnStatusUpdate(status syncer.StatusUpdate) {
	if status.Type == syncer.StatusTypeFailed {
		// If there is an error during sync, not a lot we can do. PIP will work without the endpoint data, but match
		// ability may be reduced.
		log.WithError(status.Error).Warning("Error populating endpoint cache - policy match capability may be reduced")
	}
}

// addOrUpdate either adds a new EndpointData entry, or updates the resource in the existing entry. We only track the
// most recent settings of each resource.
func (e *EndpointCache) addOrUpdate(key string, r resources.Resource) {
	// Add or update and entry for this resource.
	if ed := e.endpoints[key]; ed == nil {
		log.Infof("Adding resource to endpoint cache: %s", key)
		e.endpoints[key] = &EndpointData{
			resource: r,
		}
	} else {
		log.Debugf("Updating resource in endpoint cache: %s", key)
		ed.resource = r
	}
}

// populateEndpointData populates the public EndpointData value from the cached resource.
func (e *EndpointCache) populateEndpointData(ed *EndpointData) {
	switch r := ed.resource.(type) {
	case *corev1.Pod:
		e.populateEndpointDataPod(r, ed)
	case *v3.HostEndpoint:
		e.populateEndpointDataHEP(&r.ObjectMeta, &r.Spec, ed)
	}

	// If our labels are nil, set them to be an empty map. We use nil to mean "unknown", but in this case we know that
	// the labels are just empty.
	if ed.Labels.IsNil() {
		ed.Labels = uniquelabels.Empty
	}
}

// populateEndpointDataPod populates the calculated endpoint data fields from a pod.
func (e *EndpointCache) populateEndpointDataPod(pod *corev1.Pod, ed *EndpointData) {
	ed.Labels = uniquelabels.Make(pod.Labels)
	ed.NamedPorts = e.getPodPorts(pod)
	ed.ServiceAccount = &pod.Spec.ServiceAccountName
}

// populateEndpointDataHEP populates the calculated endpoint data fields from a HEP.
func (e *EndpointCache) populateEndpointDataHEP(meta *metav1.ObjectMeta, spec *v3.HostEndpointSpec, ed *EndpointData) {
	ed.Labels = uniquelabels.Make(meta.Labels)
	ed.NamedPorts = e.getHEPPorts(spec)
}

// getPodPorts returns the set of endpoint ports scanned from the pod container configuration.
func (e *EndpointCache) getPodPorts(pod *corev1.Pod) []api.EndpointNamedPort {
	enp := make([]api.EndpointNamedPort, 0)
	for _, c := range pod.Spec.Containers {
		for _, kp := range c.Ports {
			if kp.Name == "" || kp.ContainerPort == 0 {
				continue
			}
			protocol := api.ProtoTCP
			if kp.Protocol != "" {
				pfs := numorstring.ProtocolFromString(string(kp.Protocol))
				pnum := api.GetProtocolNumber(&pfs)
				if pnum == nil {
					continue
				}
			}
			enp = append(enp, api.EndpointNamedPort{
				Name:     kp.Name,
				Port:     uint16(kp.ContainerPort),
				Protocol: protocol,
			})
		}
	}
	return enp
}

// getHEPPorts returns the set of endpoint ports scanned from the HEP configuration.
func (e *EndpointCache) getHEPPorts(spec *v3.HostEndpointSpec) []api.EndpointNamedPort {
	enp := make([]api.EndpointNamedPort, 0, len(spec.Ports))
	for _, p := range spec.Ports {
		if proto := api.GetProtocolNumber(&p.Protocol); proto != nil {
			enp = append(enp, api.EndpointNamedPort{
				Name:     p.Name,
				Port:     p.Port,
				Protocol: *proto,
			})
		}
	}
	return enp
}

// namespaceName constructs a key from the namespace and name.
func namespaceName(namespace, name string) string {
	return namespace + "/" + name
}
