package pip

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/lma/pkg/api"
	pelastic "github.com/projectcalico/calico/lma/pkg/elastic"
	"github.com/projectcalico/calico/lma/pkg/list"
	pipcfg "github.com/projectcalico/calico/ui-apis/pkg/pip/config"
)

// New returns a new PIP instance.
func New(cfg *pipcfg.Config, listSrc ClusterAwareLister, ls client.Client) PIP {
	p := &pip{
		listSrc:  listSrc,
		lsclient: ls,
		cfg:      cfg,
	}
	return p
}

type ClusterAwareLister interface {
	RetrieveList(clusterID string, kind metav1.TypeMeta) (*list.TimestampedResourceList, error)
}

// pip implements the PIP interface.
type pip struct {
	listSrc  ClusterAwareLister
	lsclient client.Client
	cfg      *pipcfg.Config
}

type FlowLogResults struct {
	pelastic.CompositeAggregationResults `json:",inline"`
	AggregationsPreview                  map[string]any `json:"aggregations_preview"`
}

// GetFlows returns the set of PIP-processed flows based on the request parameters in `params`. The map is
// JSON serializable
func (p *pip) GetFlows(ctxIn context.Context, pager client.ListPager[lapi.L3Flow], params *PolicyImpactParams, rbacHelper pelastic.FlowFilter) (*FlowLogResults, error) {
	// Create a context with timeout to ensure we don't block for too long with this calculation.
	ctx, cancel := context.WithTimeout(ctxIn, p.cfg.MaxCalculationTime)
	defer cancel() // Releases timer resources if the operation completes before the timeout.

	// Get a primed policy calculator.
	calc, err := p.GetPolicyCalculator(ctx, params)
	if err != nil {
		return nil, err
	}

	// Enumerate the aggregation buckets until we have all we need. The channel will be automatically closed.
	var before []*pelastic.CompositeAggregationBucket
	var after []*pelastic.CompositeAggregationBucket
	startTime := time.Now()
	processedFlows, errs := p.SearchAndProcessFlowLogs(ctx, pager, params.ClusterName, calc, params.Limit, params.ImpactedOnly, rbacHelper)
	for processedFlow := range processedFlows {
		before = append(before, processedFlow.Before...)
		after = append(after, processedFlow.After...)
	}
	took := int64(time.Since(startTime) / time.Millisecond)

	// Check for errors.
	// We can use the blocking version of the channel operator since the error channel will have been closed (it
	// is closed alongside the results channel).
	err = <-errs

	// If there was an error, check for a time out. If it timed out just flag this in the response, but return whatever
	// data we already have. Otherwise return the error.
	// For timeouts we have a couple of mechanisms for hitting this:
	// -  We exceed the context deadline.
	// -  The elastic search query returns a timeout.
	var timedOut bool
	if err != nil {
		if ctxIn.Err() == nil && ctx.Err() == context.DeadlineExceeded {
			// The context passed to us has no error, but our context with timeout is indicating it has timed out.
			log.Info("Context deadline exceeded - flag results as timedout")
			timedOut = true
		} else {
			// Just pass the received error up the stack.
			log.WithError(err).Warning("Error response from elasticsearch query")
			return nil, err
		}
	}

	// TODO: This query isn't actually used, it's just needed for the conversion functions below.
	// We need to rework how we make those conversion functions!
	q := &pelastic.CompositeAggregationQuery{
		Name:               api.FlowlogBuckets,
		AggNestedTermInfos: pelastic.FlowAggregatedTerms,
	}

	return &FlowLogResults{
		CompositeAggregationResults: pelastic.CompositeAggregationResults{
			TimedOut:     timedOut,
			Took:         took,
			Aggregations: pelastic.CompositeAggregationBucketsToMap(before, q),
		},
		AggregationsPreview: pelastic.CompositeAggregationBucketsToMap(after, q),
	}, nil
}
