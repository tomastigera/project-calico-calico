// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package fake

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	esv1 "github.com/elastic/cloud-on-k8s/v3/pkg/apis/elasticsearch/v1"
	"github.com/tigera/api/pkg/client/clientset_generated/clientset/scheme"
	"k8s.io/apimachinery/pkg/runtime/schema"
	restfake "k8s.io/client-go/rest/fake"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/utils"
)

type RESTClient struct {
	esResponse *esv1.Elasticsearch
	*restfake.RESTClient
}

func init() {
	// Register the scheme once.
	if err := esv1.SchemeBuilder.AddToScheme(scheme.Scheme); err != nil {
		panic(err)
	}
}

// NewFakeRESTClient creates a very simple fake elasticsearch.RESTClient, where it always responds with the given
// elasticsearch object, no matter what the request is. You can change the elasticsearch object it responds with (and
// in turn the hash) using the SetElasticsearch function.
//
// Note that at the time this was written the only call made through this rest client would be to grab the singular
// elasticsearch resource, thus there was no need to do anything but return an single elasticsearch response for every
// call through this rest client
func NewFakeRESTClient(esResponse *esv1.Elasticsearch) (*RESTClient, error) {
	cli := &RESTClient{
		esResponse: esResponse,
		RESTClient: &restfake.RESTClient{
			GroupVersion:         schema.GroupVersion{Group: "elasticsearch.k8s.elastic.co", Version: "v1"},
			VersionedAPIPath:     "/apis",
			NegotiatedSerializer: scheme.Codecs.WithoutConversion(),
		}}

	cli.Client = restfake.CreateHTTPClient(func(*http.Request) (*http.Response, error) {
		byts, _ := json.Marshal(cli.esResponse)
		closer := io.NopCloser(bytes.NewReader(byts))
		return &http.Response{
			Status:        "200 OK",
			StatusCode:    200,
			Proto:         "HTTP/2.0",
			ProtoMajor:    2,
			ContentLength: int64(len(byts)),
			Body:          closer,
		}, nil
	})

	return cli, nil
}

func (r *RESTClient) SetElasticsearch(es *esv1.Elasticsearch) {
	r.esResponse = es
}

func (r *RESTClient) CalculateTigeraElasticsearchHash() (string, error) {
	return utils.GenerateTruncatedHash(r.esResponse.CreationTimestamp, 24)
}
