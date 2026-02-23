// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

package elastic

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"time"

	"github.com/olivere/elastic/v7"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/lma/pkg/api"
)

const (
	createIndexMaxRetries    = 3
	createIndexRetryInterval = 1 * time.Second
	applicationName          = "lma"
	DefaultPageSize          = 100
)

type IndexTemplate struct {
	IndexPatterns []string       `json:"index_patterns,omitempty"`
	Settings      map[string]any `json:"settings,omitempty"`
	Mappings      map[string]any `json:"mappings,omitempty"`
}

type IndexSettings struct {
	Replicas  string    `json:"number_of_replicas,omitempty"`
	Shards    string    `json:"number_of_shards,omitempty"`
	LifeCycle LifeCycle `json:"lifecycle"`
}

type LifeCycle struct {
	Name          string `json:"name,omitempty"`
	RolloverAlias string `json:"rollover_alias,omitempty"`
}

type Client interface {
	api.DNSLogReportHandler
	ClusterIndex(string, string) string
	ClusterAlias(string) string
	IndexTemplateName(index string) string
	Backend() *elastic.Client

	SearchCompositeAggregations(
		context.Context, *CompositeAggregationQuery, CompositeAggregationKey,
	) (<-chan *CompositeAggregationBucket, <-chan error)

	Do(ctx context.Context, s *elastic.SearchService) (*elastic.SearchResult, error)
}

// client implements the Client interface.
type client struct {
	*elastic.Client
	indexSuffix   string
	indexSettings IndexSettings
}

func NewWithClient(cli *elastic.Client) Client {
	return &client{
		Client: cli,
	}
}

// doFunc invokes the Do on the search service. This is added to allow us to mock out the client in test code.
func (c *client) Do(ctx context.Context, s *elastic.SearchService) (*elastic.SearchResult, error) {
	return s.Do(ctx)
}

// MustGetElasticClient returns the elastic Client, or panics if it's not possible.
func MustGetElasticClient() Client {
	cfg := MustLoadConfig()
	c, err := NewFromConfig(cfg)
	if err != nil {
		log.Fatalf("Unable to connect to Elasticsearch: %v", err)
	}
	return c
}

// NewFromConfig returns a new elastic Client using the supplied configuration.
func NewFromConfig(cfg *Config) (Client, error) {
	ca, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	h := &http.Client{}
	if cfg.ParsedElasticURL.Scheme == "https" {
		if cfg.ElasticCA != "" {
			cert, err := os.ReadFile(cfg.ElasticCA)
			if err != nil {
				return nil, err
			}
			ok := ca.AppendCertsFromPEM(cert)
			if !ok {
				return nil, fmt.Errorf("invalid Elasticsearch CA in environment variable ELASTIC_CA")
			}
		}

		tlsConfig, err := tls.NewTLSConfig()
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = ca
		h.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}

	indexSuffix := cfg.ElasticIndexSuffix
	if cfg.ElasticIndexMidfix != "" {
		indexSuffix = fmt.Sprintf("%s.%s", cfg.ElasticIndexMidfix, indexSuffix)
	}

	return New(
		h, cfg.ParsedElasticURL, cfg.ElasticUser, cfg.ElasticPassword, indexSuffix,
		cfg.ElasticConnRetries, cfg.ElasticConnRetryInterval, cfg.ParsedLogLevel == log.DebugLevel, cfg.ElasticReplicas,
		cfg.ElasticShards)
}

// New returns a new elastic client using the supplied parameters. This method performs retries if creation of the
// client fails.
func New(
	h *http.Client, url *url.URL, username, password, indexSuffix string,
	retries int, retryInterval time.Duration, trace bool, replicas int, shards int,
) (Client, error) {
	options := []elastic.ClientOptionFunc{
		elastic.SetURL(url.String()),
		elastic.SetHttpClient(h),
		elastic.SetErrorLog(log.StandardLogger()),
		elastic.SetSniff(false),
	}
	if trace {
		options = append(options, elastic.SetTraceLog(log.StandardLogger()))
	}
	if username != "" {
		options = append(options, elastic.SetBasicAuth(username, password))
	}

	var err error
	var c *elastic.Client
	for i := range retries {
		log.Info("Connecting to Elastic")
		if c, err = elastic.NewClient(options...); err == nil {
			log.Info("Successfully connected to Elastic")
			return &client{c, indexSuffix, IndexSettings{strconv.Itoa(replicas), strconv.Itoa(shards), LifeCycle{}}}, nil
		}
		log.WithError(err).WithField("attempts", retries-i).Warning("Elastic connect failed, retrying")
		time.Sleep(retryInterval)
	}
	log.Errorf("Unable to connect to Elastic after %d retries", retries)
	return nil, err
}

func (c *client) ClusterAlias(index string) string {
	return fmt.Sprintf("%s.%s.", index, c.indexSuffix)
}

func (c *client) IndexTemplateName(index string) string {
	return fmt.Sprintf("%s.%s", index, c.indexSuffix)
}

func (c *client) ClusterIndex(index, postfix string) string {
	if postfix != "" {
		return fmt.Sprintf("%s.%s.%s", index, c.indexSuffix, postfix)
	} else {
		return fmt.Sprintf("%s.%s", index, c.indexSuffix)
	}
}

// IndexTemplate populates and returns IndexTemplate object
func (c *client) IndexTemplate(indexAlias, indexPrefix, mapping string, lifecycleEnabled bool) (IndexTemplate, error) {
	var indexSettings map[string]any
	if lifecycleEnabled {
		c.indexSettings.LifeCycle = LifeCycle{Name: fmt.Sprintf("%s_policy", indexPrefix), RolloverAlias: indexAlias}
	}

	// Convert c.indexSettings into map[string]interface{} that can represent:
	// "settings": {
	//   "index": {
	//     "number_of_shards": "<shards>",
	//     "number_of_replicas": "<replicas>"
	//     "lifecycle": {
	//        "name": "<policy name>",
	//        "rollover_alias": "<index alias>"
	//     }
	//   }
	// }
	s, err := json.Marshal(map[string]any{
		"index": c.indexSettings,
	})
	if err != nil {
		return IndexTemplate{}, err
	}
	if err := json.Unmarshal(s, &indexSettings); err != nil {
		return IndexTemplate{}, err
	}

	// Convert mapping to map[string]interface{}
	var indexMappings map[string]any
	if err := json.Unmarshal([]byte(mapping), &indexMappings); err != nil {
		return IndexTemplate{}, err
	}

	return IndexTemplate{
		IndexPatterns: []string{fmt.Sprintf("%s*", indexAlias)},
		Settings:      indexSettings,
		Mappings:      indexMappings,
	}, nil
}

func (c *client) MaybeUpdateIndexMapping(index string, expectedMapping map[string]any) error {
	ctx := context.Background()

	if resp, err := c.GetMapping().Index(index).Do(ctx); err != nil {
		log.WithError(err).Errorf("failed to get index mapping for %s", index)
		return err
	} else {
		// GetMapping() response example:
		// {
		//   "tigera_secure_ee_events.cluster.lma" : {
		//     "mappings" : {
		//       "dynamic" : "false",
		//       "properties" : {
		//         "description" : {
		//           "type" : "keyword"
		//          },
		//        ...
		v, ok := resp[index].(map[string]any)
		if !ok {
			log.Warnf("failed find key=%s from %s index mapping response. index mapping update will be skipped", index, index)
			return nil
		}

		mapping, ok := v["mappings"].(map[string]any)
		if !ok {
			log.Warnf("failed find key=mappings from %s index mapping response. index mapping update will be skipped", index)
			return nil
		}

		if !reflect.DeepEqual(expectedMapping, mapping) {
			if _, err := c.PutMapping().Index(index).BodyJson(expectedMapping).Do(ctx); err != nil {
				log.WithError(err).Errorf("failed to update index mapping for %s", index)
				return err
			}
			log.Infof("successfully updated index mapping for %s", index)
		} else {
			log.Infof("index mapping for %s is up to date", index)
		}
	}
	return nil
}

func (c *client) Backend() *elastic.Client {
	return c.Client
}

// NewMockComplianceClient creates a mock client used for testing.
func NewMockComplianceClient(doFunc func(ctx context.Context, s *elastic.SearchService) (*elastic.SearchResult, error)) Client {
	mc := mockComplianceClient{}
	mc.DoFunc = doFunc
	return &mc
}

type mockComplianceClient struct {
	Client
	DoFunc func(ctx context.Context, s *elastic.SearchService) (*elastic.SearchResult, error)
}

func (m mockComplianceClient) Backend() *elastic.Client {
	return nil
}

func (m mockComplianceClient) ClusterIndex(string, string) string {
	return "fake-index"
}

func (m mockComplianceClient) ClusterAlias(string) string {
	return "fake-index"
}

func (m mockComplianceClient) Do(ctx context.Context, s *elastic.SearchService) (*elastic.SearchResult, error) {
	return m.DoFunc(ctx, s)
}

// NewMockSearchClient creates a mock client used for testing search results.
func NewMockSearchClient(results []any) Client {
	idx := 0

	doFunc := func(_ context.Context, _ *elastic.SearchService) (*elastic.SearchResult, error) {
		if idx >= len(results) {
			return nil, errors.New("enumerated past end of results")
		}
		result := results[idx]
		idx++

		switch rt := result.(type) {
		case *elastic.SearchResult:
			return rt, nil
		case elastic.SearchResult:
			return &rt, nil
		case error:
			return nil, rt
		case string:
			result := new(elastic.SearchResult)
			decoder := &elastic.DefaultDecoder{}
			err := decoder.Decode([]byte(rt), result)
			return result, err
		}

		return nil, errors.New("unexpected result type")
	}

	return NewMockComplianceClient(doFunc)
}
