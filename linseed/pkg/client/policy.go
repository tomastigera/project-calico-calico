package client

import (
	"context"
	"fmt"

	"github.com/projectcalico/calico/libcalico-go/lib/json"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

type PolicyActivityInterface interface {
	ListSummary(context.Context, v1.Params) (*v1.List[v1.PolicyActivity], error)
	ListInto(context.Context, v1.Params, v1.Listable) error
	Create(context.Context, []v1.PolicyActivity) (*v1.BulkResponse, error)
}

type PolicyActivityLogs struct {
	restClient rest.RESTClient
	clusterID  string
}

func newPolicyActivityLogs(c Client, cluster string) PolicyActivityInterface {
	return &PolicyActivityLogs{
		restClient: c.RESTClient(),
		clusterID:  cluster,
	}
}

func (p *PolicyActivityLogs) ListSummary(ctx context.Context, params v1.Params) (*v1.List[v1.PolicyActivity], error) {
	logs := v1.List[v1.PolicyActivity]{}
	err := p.ListInto(ctx, params, &logs)
	return &logs, err
}

// ListInto gets the policy activity for the given input params.
func (p *PolicyActivityLogs) ListInto(ctx context.Context, params v1.Params, l v1.Listable) error {
	if l == nil {
		return fmt.Errorf("list cannot be nil")
	}

	err := p.restClient.Post().
		Path("/policy_activity/logs").
		Params(params).
		Cluster(p.clusterID).
		Do(ctx).
		Into(l)
	if err != nil {
		return err
	}

	return nil
}

func (p *PolicyActivityLogs) Create(ctx context.Context, logs []v1.PolicyActivity) (*v1.BulkResponse, error) {
	var err error
	var body []byte
	for _, e := range logs {
		// Add a newline between each. Do it here so that
		// we don't have a newline after the last event.
		if len(body) != 0 {
			body = append(body, []byte("\n")...)
		}

		// Add the item.
		out, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		body = append(body, out...)
	}

	resp := v1.BulkResponse{}
	err = p.restClient.Post().
		Path("/policy_activity/logs/bulk").
		Cluster(p.clusterID).
		BodyJSON(body).
		ContentType(rest.ContentTypeMultilineJSON).
		Do(ctx).
		Into(&resp)
	return &resp, err
}
