package policycalc

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/lma/pkg/api"
)

// NewEndpointSelectorHandler creates a new EndpointSelectorHandler used for enumerating Endpoint selectors and
// temporarily caching the result.
func NewEndpointSelectorHandler() *EndpointSelectorHandler {
	return &EndpointSelectorHandler{
		selectorMatchers: make(map[string]EndpointMatcher),
	}
}

// EndpointSelectorHandler is used for enumerating Endpoint selectors and temporarily caching the result.
type EndpointSelectorHandler struct {
	selectorMatchers map[string]EndpointMatcher
}

// InitFlowDataSelectorResults initializes the cached selector results in the flow data.
func (c *EndpointSelectorHandler) CreateSelectorCache() []MatchType {
	return make([]MatchType, len(c.selectorMatchers))
}

// GetSelectorEndpointMatcher returns an Endpoint matcher function for a specific Endpoint selector.
func (c *EndpointSelectorHandler) GetSelectorEndpointMatcher(selStr string) EndpointMatcher {
	if m, ok := c.selectorMatchers[selStr]; ok {
		return m
	}

	// We don't have one, parse the selector string and create the Selector matcher.
	parsedSel, err := selector.Parse(selStr)
	if err != nil {
		// The selector is bad so we don't add it to the label helper.
		log.WithError(err).Errorf("Bad selector found in config: %s", selStr)
		return nil
	}

	// Short-circuit all() selector.
	isAll := selStr == "all()"

	// Create a closure to perform the selector matching and the caching.
	cacheIdx := len(c.selectorMatchers)
	matcher := func(_ *api.Flow, ep *api.FlowEndpointData, _ *flowCache, epCache *endpointCache) MatchType {
		val := epCache.selectors[cacheIdx]
		if val == MatchTypeUnknown {
			if !ep.IsLabelledEndpoint() {
				// This is not a labelled endpoint and therefore does not match a rule using label selectors.
				val = MatchTypeFalse
			} else if isAll {
				// This is an all() selector, so matches all endpoints - in this case it doesn't matter if we don't have
				// the labels, match is true.
				val = MatchTypeTrue
			} else if ep.Labels.IsNil() {
				// We don't have the labels, so match is uncertain.
				val = MatchTypeUncertain
			} else if parsedSel.EvaluateLabels(ep) {
				// Selector matches labels, so match is true.
				val = MatchTypeTrue
			} else {
				// Selector does not match labels, so match is false.
				val = MatchTypeFalse
			}
			epCache.selectors[cacheIdx] = val
		}
		log.Debugf("Endpoint selector: %s = %s", selStr, val)

		return val
	}

	c.selectorMatchers[selStr] = matcher

	return matcher
}
