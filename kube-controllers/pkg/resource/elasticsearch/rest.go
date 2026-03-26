// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

// esk8srest provides an implementation of the rest.RESTClient that can handle k8s requests to elasticsearch.k8s.elastic.co
package elasticsearch

import (
	esv1 "github.com/elastic/cloud-on-k8s/v3/pkg/apis/elasticsearch/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

// RESTClient is a wrapper for the rest.RESTClient that can handle requests to the elasticsearch.k8s.elastic.co API group
type RESTClient interface {
	rest.Interface
	CalculateTigeraElasticsearchHash() (string, error)
}

type restClient struct {
	*rest.RESTClient
}

func init() {
	// Register the scheme once.
	if err := esv1.SchemeBuilder.AddToScheme(scheme.Scheme); err != nil {
		panic(err)
	}
}

// NewRESTClient creates a new instance of the RESTClient from the given rest.Config
func NewRESTClient(config *rest.Config) (RESTClient, error) {
	cp := rest.CopyConfig(config)
	cp.APIPath = "/apis"
	cp.GroupVersion = &schema.GroupVersion{Group: "elasticsearch.k8s.elastic.co", Version: "v1"}

	cp.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	cp.UserAgent = rest.DefaultKubernetesUserAgent()

	restCli, err := rest.RESTClientFor(cp)
	if err != nil {
		return nil, err
	}

	return &restClient{RESTClient: restCli}, nil
}
