package client

import (
	"context"

	"github.com/projectcalico/calico/libcalico-go/lib/json"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

type PolicyActivityInterface interface {
	Create(context.Context, []v1.PolicyActivity) (*v1.BulkResponse, error)
	GetPolicyActivity(context.Context, *v1.PolicyActivityRequest) (*v1.PolicyActivityResponse, error)
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

func (p *PolicyActivityLogs) GetPolicyActivity(ctx context.Context, req *v1.PolicyActivityRequest) (*v1.PolicyActivityResponse, error) {
	resp := v1.PolicyActivityResponse{}
	err := p.restClient.Post().
		Path("/policyactivity").
		Params(req).
		Cluster(p.clusterID).
		Do(ctx).
		Into(&resp)
	return &resp, err
}
