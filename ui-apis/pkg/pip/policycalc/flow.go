package policycalc

import (
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/lma/pkg/api"
)

// flowCache contains cached data when calculating the before/after impact of the policies on a flow.
type flowCache struct {
	// Cached source and destination caches.
	source      endpointCache
	destination endpointCache

	// Cached policy actions. Populated by the before flow calculation and used by the after policy calculation to
	// speed up processing and to assist with unknown rule matches.
	policies map[model.ResourceKey]api.ActionFlag
}

type endpointCache struct {
	selectors []MatchType
}
