// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package elasticsearch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/olivere/elastic/v7"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/projectcalico/calico/e2e/pkg/config"
	"github.com/projectcalico/calico/e2e/pkg/utils"
)

const (
	defaultKibanaScheme = "https"
	defaultKibanaHost   = "tigera-secure-kb-http.tigera-kibana.svc"
	elasticNamespace    = "tigera-elasticsearch"
	kibanaNamspace      = "tigera-kibana"
	eckNamespace        = "tigera-eck-operator"

	LogStorageName       = "tigera-secure"
	KibanaCertSecret     = "tigera-secure-kibana-cert"
	EckWebhookSecretName = "elastic-webhook-server-cert"
	CertSecret           = "tigera-secure-elasticsearch-cert"

	ElasticHealthTimeout      = 3 * time.Minute
	ElasticHealthPollInterval = 10 * time.Second

	EndTimeField = "end_time"

	FlowLogIndexPrefix          = "tigera_secure_ee_flows."
	FlowLogIndexPrefixFlowsynth = "tigera_secure_ee_flows.cluster.flowsynth."
	FlowlogsIndex               = "tigera_secure_ee_flows*"
	EventsIndexPrefix           = "tigera_secure_ee_events."
	EventsIndex                 = "tigera_secure_ee_events.*"
)

type TestSpec struct {
	Job      string
	Datafeed string
	Config   TestConfig
}

type TestConfig struct {
	RecordScore int
	NumRecords  int
	NumNodes    int
	PodNetwork  *net.IPNet
	StartTime   time.Time
	EndTime     time.Time
}

// A subset of the flow log structure
type FlowLog struct {
	StartTime int64 `json:"start_time"`
	EndTime   int64 `json:"end_time"`

	Action          string                   `json:"action"`
	SourceName      string                   `json:"source_name"`
	SourceNameAggr  string                   `json:"source_name_aggr"`
	SourceNamespace string                   `json:"source_namespace"`
	SourceLabels    *FlowLogLabelsJSONOutput `json:"source_labels"`

	SourcePort    int64                    `json:"source_port"`
	SourceType    string                   `json:"source_type"`
	DestName      string                   `json:"dest_name"`
	DestNameAggr  string                   `json:"dest_name_aggr"`
	DestNamespace string                   `json:"dest_namespace"`
	DestPort      int64                    `json:"dest_port"`
	DestType      string                   `json:"dest_type"`
	DestLabels    *FlowLogLabelsJSONOutput `json:"dest_labels"`

	Proto             string                     `json:"proto"`
	Reporter          string                     `json:"reporter"`
	Policies          *FlowLogPoliciesJSONOutput `json:"policies"`
	BytesIn           int64                      `json:"bytes_in"`
	BytesOut          int64                      `json:"bytes_out"`
	NumFlows          int64                      `json:"num_flows"`
	NumFlowsStarted   int64                      `json:"num_flows_started"`
	NumFlowsCompleted int64                      `json:"num_flows_completed"`
	PacketsIn         int64                      `json:"packets_in"`
	PacketsOut        int64                      `json:"packets_out"`
	Host              string                     `json:"host"`

	ProcessName     string `json:"process_name"`
	ProcessID       string `json:"process_id"`
	NumProcessNames int    `json:"num_process_names"`
	NumProcessIDs   int    `json:"num_process_ids"`
}

type FlowLogLabelsJSONOutput struct {
	Labels []string `json:"labels"`
}

type FlowLogPoliciesJSONOutput struct {
	AllPolicies      []string `json:"all_policies"`
	EnforcedPolicies []string `json:"enforced_policies"`
	PendingPolicies  []string `json:"pending_policies"`
}

func (c *TestConfig) MarshalYAML() (any, error) {
	v := struct {
		NumNodes   int    `yaml:"NumNodes"`
		PodNetwork string `yaml:"PodNetwork"`
		StartTime  string `yaml:"StartTime"`
		EndTime    string `yaml:"EndTime"`
	}{
		c.NumNodes,
		c.PodNetwork.String(),
		c.StartTime.Format("2006-01-02"),
		c.EndTime.Format("2006-01-02"),
	}
	return &v, nil
}

var elasticClient *elastic.Client

// PortForward sets up port forwarding to the Elasticsearch service in the cluster.
// It returns a function that can be called to stop the port forwarding.
func PortForward() func() {
	stopCh := make(chan time.Time, 1)
	kubectl := utils.Kubectl{}
	kubectl.PortForward("tigera-elasticsearch", "svc/tigera-secure-es-http", "9200", "", stopCh)
	kubectl.PortForward("tigera-manager", "svc/tigera-manager", "9443", "", stopCh)

	return func() {
		stopCh <- time.Now()
		close(stopCh)
	}
}

// InitClient initializes and returns an Elasticsearch client as well as a cleanup function to close the client.
// If a client already exists, it reuses the existing client.
func InitClient(f *framework.Framework) *elastic.Client {
	if elasticClient != nil {
		logrus.Info("Reusing existing elastic client")
		return elasticClient
	}

	elasticCert := getElasticCert(f)
	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:            elasticCert,
			InsecureSkipVerify: true,
		}},
	}

	logger := logrus.StandardLogger()
	options := []elastic.ClientOptionFunc{
		elastic.SetErrorLog(logger),
		elastic.SetInfoLog(logger),
		elastic.SetTraceLog(logger),
		elastic.SetURL(config.ElasticsearchURL()),
		elastic.SetSniff(false),
		elastic.SetHealthcheck(false),
		elastic.SetHttpClient(httpClient),
	}
	if userPwd := getElasticUserSecretPassword(f); userPwd != "" {
		username := GetUserName(f)
		options = append(options, elastic.SetBasicAuth(username, userPwd))
	}

	var err error
	elasticClient, err = elastic.NewClient(options...)
	Expect(err).NotTo(HaveOccurred())
	return elasticClient
}

func GetKibanaStatusURL(f *framework.Framework) string {
	kibanaUri := config.ManagerURL()
	u, err := url.Parse(kibanaUri)
	Expect(err).NotTo(HaveOccurred())

	pass := getElasticUserSecretPassword(f)
	u.User = url.UserPassword(GetUserName(f), pass)
	u.Path = "tigera-kibana/api/status"
	return u.String()
}

func GetUserName(f *framework.Framework) string {
	if f == nil {
		f = utils.NewDefaultFramework("calico-temp")
	}
	return getElasticUserSecretName(f)
}

func GetPassword(f *framework.Framework) string {
	if f == nil {
		f = utils.NewDefaultFramework("calico-temp")
	}
	return getElasticUserSecretPassword(f)
}

func GetElasticNamespace() string {
	return elasticNamespace
}

func GetKibanaNamespace() string {
	return kibanaNamspace
}

func GetEckNamespace() string {
	return eckNamespace
}

func GetPublicCertSecret() string {
	return "tigera-secure-es-http-certs-public"
}

func GetKibanaPublicCertSecret() string {
	return "tigera-secure-kb-http-certs-public"
}

func GetPathToCert(f *framework.Framework) string {
	if f == nil {
		f = utils.NewDefaultFramework("calico-temp")
	}
	tf, err := os.CreateTemp("", "elastic-cert-*.txt")
	Expect(err).NotTo(HaveOccurred())
	defer func() { _ = tf.Close() }()
	cd := getElasticCertData(f)
	_, _ = tf.Write(cd)
	return tf.Name()
}

func LogElasticDiags(c *elastic.Client, _ *framework.Framework) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	ch, err := c.ClusterHealth().Pretty(true).Do(ctx)
	if err != nil {
		logrus.WithError(err).Info("failed to get elasticsearch cluster health")
	} else {
		logrus.Infof("elastic cluster health:\n %v", ch)
	}
	r, err := c.PerformRequest(ctx, elastic.PerformRequestOptions{
		Method: "GET",
		Path:   "/_cat/nodes?v&h=id,disk.total,disk.used_percent,heap.percent,uptime,ram.percent",
	})
	if err != nil {
		logrus.WithError(err).Info("failed to get elasticsearch node info")
	} else {
		logrus.Infof("elastic nodes:\n %v", r)
	}
}

func WaitForElastic(client *elastic.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), ElasticHealthTimeout)
	defer cancel()

	lastError := "context expired before getting health for the first time"
	for {
		select {
		case <-ctx.Done():
			framework.Failf("deadline exceeded for elasticsearch to become healthy, last error was: %s", lastError)
		default:
			r, err := client.ClusterHealth().Do(ctx)
			if err != nil {
				lastError = fmt.Sprintf("failed to get elasticsearch health: %s", err.Error())
				time.Sleep(ElasticHealthPollInterval)
				continue
			}
			// green or yellow means the cluster is healthy enough to test with (yellow just means
			// there aren't enough nodes for proper replication, which will always be true of single
			// node clusters)
			if r.Status != "green" && r.Status != "yellow" {
				lastError = fmt.Sprintf("elasticsearch ClusterHealth.Status %s", r.Status)
				time.Sleep(ElasticHealthPollInterval)
				continue
			}
			return
		}
	}
}

func DeleteIndices(client *elastic.Client, prefix string) {
	ctx := context.Background()

	indexNames, err := client.IndexNames()
	Expect(err).NotTo(HaveOccurred())

	toDelete := []string{}
	for _, indexName := range indexNames {
		if strings.HasPrefix(indexName, prefix) {
			framework.Logf("Will delete ES index %v", indexName)
			toDelete = append(toDelete, indexName)
		}
	}

	if len(toDelete) > 0 {
		resp, err := client.DeleteIndex(toDelete...).Do(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Acknowledged).To(BeTrue())
		framework.Logf("ES indices deleted")
	}
}

func RefreshIndices(client *elastic.Client, indices ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), framework.SingleCallTimeout)
	defer cancel()

	_, err := client.Refresh(indices...).Do(ctx)
	Expect(err).ShouldNot(HaveOccurred())
}

func IndexExists(client *elastic.Client, indices ...string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), framework.SingleCallTimeout)
	defer cancel()

	timeoutInterval := defaultEventuallyTimeout
	pollingInterval := defaultEventuallyPollingInterval

	Eventually(func(g Gomega) bool {
		result, err := client.IndexExists(indices...).
			AllowNoIndices(false).
			Do(ctx)
		g.Expect(err).NotTo(HaveOccurred())
		return result
	}, timeoutInterval, pollingInterval).Should(BeTrue())
	return true
}

// CheckSearchEvents searches for a key and value in the given index in Elasticsearch
var (
	defaultEventuallyTimeout         = 3 * time.Minute
	defaultEventuallyPollingInterval = 10 * time.Second
)

// CheckSearchEvents asserts whether or not the given search key and search value are present
// in the provided ES index.
//
// The assertion is tried periodically until it passes or a timeout occurs.
//
// Both the timeout and polling interval (time.Duration) are configurable as optional arguments:
// The first optional argument is the timeout
// The second optional argument is the polling interval
func CheckSearchEvents(client *elastic.Client, index, searchKey, searchValue string, intervals ...time.Duration) {
	logrus.Infof("CheckSearchEvents: client: %+v index: %v key:%v value:%v", client, index, searchKey, searchValue)

	timeoutInterval := defaultEventuallyTimeout
	pollingInterval := defaultEventuallyPollingInterval
	if len(intervals) > 0 {
		timeoutInterval = intervals[0]
	}
	if len(intervals) > 1 {
		pollingInterval = intervals[1]
	}

	Eventually(func() int {
		IndexExists(client, index)
		RefreshIndices(client, index)
		return checkSearchEventsExist(client, index, searchKey, searchValue)
	}, timeoutInterval, pollingInterval).Should(BeNumerically(">", 0))
}

func checkSearchEventsExist(client *elastic.Client, index, searchKey, searchValue string) int {
	ctx, cancel := context.WithTimeout(context.Background(), framework.SingleCallTimeout)
	defer cancel()
	termQuery := elastic.NewTermQuery(searchKey, searchValue)
	searchResult, err := client.Search().
		Index(index).
		Query(termQuery).
		Pretty(true).
		Do(ctx)

	Expect(err).ToNot(HaveOccurred())

	if int(searchResult.Hits.TotalHits.Value) > 0 {
		logrus.Infof("Found %s: %s in a total of %d record(s)\n", searchKey, searchValue, searchResult.Hits.TotalHits.Value)
	}
	return int(searchResult.Hits.TotalHits.Value)
}

func SearchEventsResult(client *elastic.Client, index, searchKey, searchValue string) []*elastic.SearchHit {
	ctx, cancel := context.WithTimeout(context.Background(), framework.SingleCallTimeout)
	defer cancel()
	termQuery := elastic.NewTermQuery(searchKey, searchValue)
	searchResult, err := client.Search().
		Index(index).
		Query(termQuery).
		Pretty(true).
		Do(ctx)

	Expect(err).ToNot(HaveOccurred())

	return searchResult.Hits.Hits
}

func getElasticUserSecrets(f *framework.Framework) map[string][]byte {
	elasticUserSecret := "tigera-secure-es-elastic-user"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := f.ClientSet.CoreV1().Secrets(GetElasticNamespace()).Get(ctx, elasticUserSecret, metav1.GetOptions{})
	Expect(err).To(Not(HaveOccurred()))
	return s.Data
}

func getElasticUserSecretName(f *framework.Framework) string {
	secretMap := getElasticUserSecrets(f)
	elasticUserSecretNames := []string{}
	for user := range secretMap {
		elasticUserSecretNames = append(elasticUserSecretNames, user)
	}
	Expect(elasticUserSecretNames).To(Not(BeEmpty()))
	return elasticUserSecretNames[0]
}

func getElasticUserSecretPassword(f *framework.Framework) string {
	secretMap := getElasticUserSecrets(f)
	elasticUserName := getElasticUserSecretName(f)
	un, exists := secretMap[elasticUserName]
	if !exists {
		framework.Failf("Failed to find elastic user credentials %s in namespace %s", elasticUserName, GetElasticNamespace())
	}
	return string(un)
}

func getElasticCertData(f *framework.Framework) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := f.ClientSet.CoreV1().Secrets(GetElasticNamespace()).Get(ctx, GetPublicCertSecret(), metav1.GetOptions{})
	Expect(err).To(Not(HaveOccurred()))
	rootPEM, exists := s.Data["tls.crt"]
	if !exists {
		framework.Failf("Couldn't find tls.crt in Elasticsearch secret %s to create Elasticsearch client", GetPublicCertSecret())
	}
	return rootPEM
}

func getElasticCert(f *framework.Framework) *x509.CertPool {
	rootPEM := getElasticCertData(f)
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(rootPEM)
	if !ok {
		framework.Failf("Failed to parse root certificate for Elasticsearch client")
	}
	return roots
}

func SearchInEs(esclient *elastic.Client, query *elastic.BoolQuery, esIndex string) *elastic.SearchResult {
	searchResult, err := esclient.Search().
		Index(esIndex).
		Query(query).
		Size(10).
		Sort("start_time", false).
		Pretty(true).
		Do(context.Background())
	Expect(err).NotTo(HaveOccurred(), "Failed to search: %v", err)
	logrus.Debugf("result from elastic +%v", searchResult)

	return searchResult
}

func SearchInESWithoutOrder(esclient *elastic.Client, query *elastic.BoolQuery, esIndex string) *elastic.SearchResult {
	var searchResult *elastic.SearchResult
	var err error
	if IndexExists(esclient, esIndex) {
		searchResult, err = esclient.Search().
			Index(esIndex).
			Query(query).
			Size(10).
			Pretty(true).
			Do(context.Background())
		Expect(err).NotTo(HaveOccurred(), "Failed to search: %v", err)
		logrus.Debugf("result from elastic +%v", searchResult)
	}

	return searchResult
}

func GetFlowlogsFromESSearchResult(res *elastic.SearchResult) []FlowLog {
	var flog FlowLog
	var flowlogs []FlowLog

	for _, item := range res.Each(reflect.TypeOf(flog)) {
		if f, ok := item.(FlowLog); ok {
			logrus.Debugf("Flowlog: %#v\n", f)
			flowlogs = append(flowlogs, f)
		}
	}
	return flowlogs
}

func BuildElasticQueryWithinTimeRange(start, end *time.Time, tq ...elastic.Query) *elastic.BoolQuery {
	return BuildElasticQueryWithinTimeRangeOnField(EndTimeField, start, end, tq...)
}

func BuildElasticQueryWithinTimeRangeOnField(timeField string, start, end *time.Time, tq ...elastic.Query) *elastic.BoolQuery {
	query := elastic.NewBoolQuery()
	withinTimeRange := elastic.NewRangeQuery(timeField)
	withinTimeRange = withinTimeRange.From((*start).Unix())
	withinTimeRange = withinTimeRange.To((*end).Unix())
	withinTimeRange = withinTimeRange.Format("epoch_second")

	innerQuery := elastic.NewBoolQuery()
	innerQuery = innerQuery.Should(tq...)

	return query.Must(withinTimeRange, innerQuery)
}

func BuildElasticQueryWithTerms(tq ...elastic.Query) *elastic.BoolQuery {
	query := elastic.NewBoolQuery()
	innerQuery := elastic.NewBoolQuery()
	innerQuery = innerQuery.Must(tq...)
	return query.Must(innerQuery)
}
