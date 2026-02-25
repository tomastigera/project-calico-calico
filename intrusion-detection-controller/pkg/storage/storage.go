// Copyright 2019 Tigera Inc. All rights reserved.

package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	geodb "github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/geodb"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/util"
	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	lmaAPI "github.com/projectcalico/calico/lma/pkg/api"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

const (
	// maxPageSize is the maximum number of results to include in each page returned from Linseed.
	maxPageSize = 1000

	MaxClauseCount = 1024

	// forwarderConfigIndexName is the name of the configmap used to store forwarder configuration.
	forwarderConfigConfigMapName = "forwarder-config"
	forwarderConfigMapNamespace  = "tigera-intrusion-detection"
)

type Service struct {
	lsClient                      client.Client
	client                        ctrlclient.WithWatch
	clusterName                   string
	forwarderConfigMappingCreated chan struct{}
	cancel                        context.CancelFunc
	maxLinseedTimeSkew            time.Duration
}

func NewService(lsClient client.Client, k8scli ctrlclient.WithWatch, clusterName string, maxLinseedTimeSkew time.Duration) *Service {
	return &Service{
		lsClient:                      lsClient,
		client:                        k8scli,
		clusterName:                   clusterName,
		forwarderConfigMappingCreated: make(chan struct{}),
		maxLinseedTimeSkew:            maxLinseedTimeSkew,
	}
}

func (e *Service) Run(ctx context.Context) {
	// This function is a no-op, but it is required to implement the controller.Controller interface.
}

func (e *Service) Close() {
	if e.cancel != nil {
		e.cancel()
	}
}

func (e *Service) ListIPSets(ctx context.Context) ([]Meta, error) {
	pager := client.NewListPager[lsv1.IPSetThreatFeed](&lsv1.IPSetThreatFeedParams{})
	pages, errs := pager.Stream(ctx, e.lsClient.ThreatFeeds(e.clusterName).IPSet().List)

	var ids []Meta
	for page := range pages {
		for _, item := range page.Items {
			ids = append(ids, Meta{
				Name:        item.ID,
				SeqNo:       item.SeqNumber,
				PrimaryTerm: item.PrimaryTerm,
			})
		}
	}

	if err, ok := <-errs; ok {
		log.WithError(err).Error("failed to read threat feeds")
		return nil, err
	}

	return ids, nil
}

func (e *Service) ListDomainNameSets(ctx context.Context) ([]Meta, error) {
	pager := client.NewListPager[lsv1.DomainNameSetThreatFeed](&lsv1.DomainNameSetThreatFeedParams{})
	pages, errs := pager.Stream(ctx, e.lsClient.ThreatFeeds(e.clusterName).DomainNameSet().List)

	var ids []Meta
	for page := range pages {
		for _, item := range page.Items {
			ids = append(ids, Meta{
				Name:        item.ID,
				SeqNo:       item.SeqNumber,
				PrimaryTerm: item.PrimaryTerm,
			})
		}
	}

	if err, ok := <-errs; ok {
		log.WithError(err).Error("failed to read threat feeds")
		return nil, err
	}

	return ids, nil
}

func (e *Service) PutIPSet(ctx context.Context, name string, set IPSetSpec) error {
	feed := lsv1.IPSetThreatFeed{
		ID: name,
		Data: &lsv1.IPSetThreatFeedData{
			CreatedAt: time.Now().UTC(),
			IPs:       set,
		},
	}

	response, err := e.lsClient.ThreatFeeds(e.clusterName).IPSet().Create(ctx, []lsv1.IPSetThreatFeed{feed})
	bulkErr := e.checkBulkError(err, response)
	if bulkErr != nil {
		return bulkErr
	}

	return nil
}

func (e *Service) checkBulkError(err error, response *lsv1.BulkResponse) error {
	if err != nil {
		return err
	}
	if response.Failed != 0 {
		var errorMsg []string
		for _, msg := range response.Errors {
			errorMsg = append(errorMsg, msg.Error())
		}

		return errors.New(strings.Join(errorMsg, " and "))
	}
	return nil
}

func (e *Service) PutDomainNameSet(ctx context.Context, name string, set DomainNameSetSpec) error {
	feed := lsv1.DomainNameSetThreatFeed{
		ID: name,
		Data: &lsv1.DomainNameSetThreatFeedData{
			CreatedAt: time.Now(),
			Domains:   set,
		},
	}

	response, err := e.lsClient.ThreatFeeds(e.clusterName).DomainNameSet().Create(ctx, []lsv1.DomainNameSetThreatFeed{feed})
	bulkErr := e.checkBulkError(err, response)
	if bulkErr != nil {
		return bulkErr
	}

	return nil
}

func (e *Service) GetIPSet(ctx context.Context, name string) (IPSetSpec, error) {
	params := lsv1.IPSetThreatFeedParams{
		ID: name,
	}

	response, err := e.lsClient.ThreatFeeds(e.clusterName).IPSet().List(ctx, &params)
	if err != nil {
		return nil, err
	}

	var data []string
	for _, item := range response.Items {
		if item.Data != nil {
			data = append(data, item.Data.IPs...)
		}
	}

	return data, nil
}

func (e *Service) GetDomainNameSet(ctx context.Context, name string) (DomainNameSetSpec, error) {
	params := lsv1.DomainNameSetThreatFeedParams{
		ID: name,
	}

	response, err := e.lsClient.ThreatFeeds(e.clusterName).DomainNameSet().List(ctx, &params)
	if err != nil {
		return nil, err
	}

	var data []string
	for _, item := range response.Items {
		if item.Data != nil {
			data = append(data, item.Data.Domains...)
		}
	}

	return data, nil
}

func (e *Service) GetIPSetModified(ctx context.Context, name string) (time.Time, error) {
	params := lsv1.IPSetThreatFeedParams{
		ID: name,
	}
	response, err := e.lsClient.ThreatFeeds(e.clusterName).IPSet().List(ctx, &params)
	if err != nil {
		return time.Time{}, err
	}

	if response.TotalHits != 1 {
		return time.Time{}, fmt.Errorf("multiple feeds returned for name")
	}

	if response.Items[0].Data != nil {
		createdAt := response.Items[0].Data.CreatedAt
		return createdAt, nil
	}

	return time.Time{}, fmt.Errorf("missing created time field")
}

func (e *Service) GetDomainNameSetModified(ctx context.Context, name string) (time.Time, error) {
	params := lsv1.DomainNameSetThreatFeedParams{
		ID: name,
	}

	response, err := e.lsClient.ThreatFeeds(e.clusterName).DomainNameSet().List(ctx, &params)
	if err != nil {
		return time.Time{}, err
	}

	if response.TotalHits != 1 {
		return time.Time{}, fmt.Errorf("multiple feeds returned for name")
	}

	if response.Items[0].Data != nil {
		createdAt := response.Items[0].Data.CreatedAt
		return createdAt, nil
	}

	return time.Time{}, fmt.Errorf("missing created time field")
}

func (e *Service) DeleteIPSet(ctx context.Context, m Meta) error {
	feed := lsv1.IPSetThreatFeed{
		ID:          m.Name,
		SeqNumber:   m.SeqNo,
		PrimaryTerm: m.PrimaryTerm,
	}

	response, err := e.lsClient.ThreatFeeds(e.clusterName).IPSet().Delete(ctx, []lsv1.IPSetThreatFeed{feed})
	bulkErr := e.checkBulkError(err, response)
	if bulkErr != nil {
		return bulkErr
	}

	return nil
}

func (e *Service) DeleteDomainNameSet(ctx context.Context, m Meta) error {
	feed := lsv1.DomainNameSetThreatFeed{
		ID:          m.Name,
		SeqNumber:   m.SeqNo,
		PrimaryTerm: m.PrimaryTerm,
	}

	response, err := e.lsClient.ThreatFeeds(e.clusterName).DomainNameSet().Delete(ctx, []lsv1.DomainNameSetThreatFeed{feed})
	bulkErr := e.checkBulkError(err, response)
	if bulkErr != nil {
		return bulkErr
	}

	return nil
}

type SetQuerier interface {
	// QueryIPSet queries the flow log by IPs specified in the feed's IPSet.
	// It returns a queryIterator, the latest IPSet hash, and error if any happens during the querying
	QueryIPSet(ctx context.Context, geoDB geodb.GeoDatabase, feed *apiv3.GlobalThreatFeed) (queryIterator Iterator[lsv1.FlowLog], newSetHash string, err error)
	// QueryDomainNameSet queries the DNS log by domain names specified in the feed's DomainNameSet.
	// It returns a queryIterator, the latest DomainNameSet hash, and error if any happens during the querying
	QueryDomainNameSet(ctx context.Context, set DomainNameSetSpec, feed *apiv3.GlobalThreatFeed) (queryIterator Iterator[lsv1.DNSLog], newSetHash string, err error)
	// GetDomainNameSet queries and outputs all the domain names specified in the feed's DomainNameSet.
	GetDomainNameSet(ctx context.Context, name string) (DomainNameSetSpec, error)
}

func (e *Service) QueryIPSet(ctx context.Context, geoDB geodb.GeoDatabase, feed *apiv3.GlobalThreatFeed) (Iterator[lsv1.FlowLog], string, error) {
	ipset, err := e.GetIPSet(ctx, feed.Name)
	if err != nil {
		return nil, "", err
	}

	newIpSetHash := util.ComputeSha256Hash(ipset)
	fromTimestamp := time.Now()
	currentIpSetHash := feed.Annotations[IpSetHashKey]
	// If the ipSet has changed we need to query from the beginning of time, otherwise query from the last successful time
	if feed.Status.LastSuccessfulSearch != nil && strings.Compare(newIpSetHash, currentIpSetHash) == 0 {
		fromTimestamp = feed.Status.LastSuccessfulSearch.Time
	}

	// Create the list pager for flow logs
	var tr lmav1.TimeRange
	tr.From = fromTimestamp.Add(-e.maxLinseedTimeSkew)
	tr.To = time.Now()
	tr.Field = "generated_time"

	queryTerms := splitIPSet(ipset)
	var queries []queryEntry[lsv1.FlowLog, lsv1.FlowLogParams]

	for _, t := range queryTerms {
		matchSource := flowParams(tr, lsv1.MatchTypeSource, t)
		queries = append(queries, queryEntry[lsv1.FlowLog, lsv1.FlowLogParams]{
			key:         QueryKeyFlowLogSourceIP,
			queryParams: matchSource,
			listPager:   client.NewListPager[lsv1.FlowLog](&matchSource),
			listFn:      e.lsClient.FlowLogs(e.clusterName).List,
		})

		matchDestination := flowParams(tr, lsv1.MatchTypeDest, t)
		queries = append(queries, queryEntry[lsv1.FlowLog, lsv1.FlowLogParams]{
			key:         QueryKeyFlowLogDestIP,
			queryParams: matchDestination,
			listPager:   client.NewListPager[lsv1.FlowLog](&matchDestination),
			listFn:      e.lsClient.FlowLogs(e.clusterName).List,
		})
	}

	return newQueryIterator(ctx, queries, feed.Name), newIpSetHash, nil
}

func flowParams(tr lmav1.TimeRange, matchType lsv1.MatchType, t []string) lsv1.FlowLogParams {
	matchSource := lsv1.FlowLogParams{QueryParams: lsv1.QueryParams{TimeRange: &tr}}
	matchSource.IPMatches = []lsv1.IPMatch{
		{
			Type: matchType,
			IPs:  t,
		},
	}
	matchSource.SetMaxPageSize(maxPageSize)
	return matchSource
}

func (e *Service) QueryDomainNameSet(ctx context.Context, domainNameSet DomainNameSetSpec, feed *apiv3.GlobalThreatFeed) (Iterator[lsv1.DNSLog], string, error) {
	newDomainNameSetHash := util.ComputeSha256Hash(domainNameSet)
	fromTimestamp := time.Now()
	currentDomainNameSetHash := feed.Annotations[DomainNameSetHashKey]
	// If the domainNameSet has changed we need to query from the beginning of time, otherwise query from the last successful time
	if feed.Status.LastSuccessfulSearch != nil && strings.Compare(newDomainNameSetHash, currentDomainNameSetHash) == 0 {
		fromTimestamp = feed.Status.LastSuccessfulSearch.Time
	}

	queryTerms := splitDomainNameSet(domainNameSet)

	// Ordering is important for the queries, so that we get more relevant results earlier. The caller
	// wants to de-duplicate events that point to the same DNS query. For example, a DNS query for www.example.com
	// will create a DNS log with www.example.com in both the qname and one of the rrsets.name. We only want to emit
	// one security event in this case, and the most relevant one is the one that says a pod queried directly for
	// for a name on our threat list.

	// Create the list pager for flow logs
	var tr lmav1.TimeRange
	tr.From = fromTimestamp.Add(-e.maxLinseedTimeSkew)
	tr.To = time.Now()
	tr.Field = "generated_time"

	var queries []queryEntry[lsv1.DNSLog, lsv1.DNSLogParams]
	for _, t := range queryTerms {
		matchQname := dnsLogParams(tr, lsv1.DomainMatchQname, t)
		queries = append(queries, queryEntry[lsv1.DNSLog, lsv1.DNSLogParams]{
			key:         QueryKeyDNSLogQName,
			queryParams: matchQname,
			listPager:   client.NewListPager[lsv1.DNSLog](&matchQname), listFn: e.lsClient.DNSLogs(e.clusterName).List,
		})
		matchRRSet := dnsLogParams(tr, lsv1.DomainMatchRRSet, t)
		queries = append(queries, queryEntry[lsv1.DNSLog, lsv1.DNSLogParams]{
			key:       QueryKeyDNSLogRRSetsName,
			listPager: client.NewListPager[lsv1.DNSLog](&matchRRSet), listFn: e.lsClient.DNSLogs(e.clusterName).List,
		})
		matchRRData := dnsLogParams(tr, lsv1.DomainMatchRRData, t)
		queries = append(queries, queryEntry[lsv1.DNSLog, lsv1.DNSLogParams]{
			key:       QueryKeyDNSLogRRSetsRData,
			listPager: client.NewListPager[lsv1.DNSLog](&matchRRData), listFn: e.lsClient.DNSLogs(e.clusterName).List,
		})
	}

	return newQueryIterator(ctx, queries, feed.Name), newDomainNameSetHash, nil
}

func dnsLogParams(tr lmav1.TimeRange, matchType lsv1.DomainMatchType, domainNameSet DomainNameSetSpec) lsv1.DNSLogParams {
	matchQname := lsv1.DNSLogParams{QueryParams: lsv1.QueryParams{TimeRange: &tr}}
	matchQname.DomainMatches = []lsv1.DomainMatch{
		{
			Type:    matchType,
			Domains: domainNameSet,
		},
	}
	matchQname.SetMaxPageSize(maxPageSize)
	return matchQname
}

func splitIPSet(ipset IPSetSpec) [][]string {
	return splitStringSlice(ipset)
}

func splitDomainNameSet(set DomainNameSetSpec) [][]string {
	return splitStringSlice(set)
}

func splitStringSlice(set []string) [][]string {
	terms := make([][]string, 1)
	for _, t := range set {
		if len(terms[len(terms)-1]) >= MaxClauseCount {
			terms = append(terms, []string{t})
		} else {
			terms[len(terms)-1] = append(terms[len(terms)-1], t)
		}
	}
	return terms
}

func (e *Service) PutSecurityEventWithID(ctx context.Context, f []lsv1.Event) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if len(f) == 0 {
		return nil
	}
	_, err := e.lsClient.Events(e.clusterName).Create(ctx, f)
	return err
}

// GetSecurityEvents retrieves a listing of security events sorted in ascending order,
// where each events time falls within the range given by start and end time.
func (e *Service) GetSecurityEvents(ctx context.Context, pager client.ListPager[lsv1.Event]) <-chan *lmaAPI.EventResult {
	results := make(chan *lmaAPI.EventResult)

	// Fire off a query to Linseed to get security events. We'll funnel the resuls into the channel.
	go func() {
		defer close(results)

		pages, errs := pager.Stream(ctx, e.lsClient.Events(e.clusterName).List)

		for page := range pages {
			for _, item := range page.Items {
				results <- &lmaAPI.EventResult{
					ID: item.ID,

					// Copy the Linseed representation into the LMA representation.
					// Eventually, we should remove the LMA representation and use the Linseed representation directly.
					EventsData: &lmaAPI.EventsData{
						Description:     item.Description,
						Origin:          item.Origin,
						Severity:        item.Severity,
						Time:            item.Time.GetTime().Unix(),
						Type:            item.Type,
						DestIP:          item.DestIP,
						DestName:        item.DestName,
						DestNameAggr:    item.DestNameAggr,
						DestNamespace:   item.DestNamespace,
						DestPort:        item.DestPort,
						Dismissed:       item.Dismissed,
						Host:            item.Host,
						SourceIP:        item.SourceIP,
						SourceName:      item.SourceName,
						SourceNameAggr:  item.SourceNameAggr,
						SourceNamespace: item.SourceNamespace,
						SourcePort:      item.SourcePort,
						Record:          item.Record,
					},
				}
			}
		}

		if err, ok := <-errs; ok {
			results <- &lmaAPI.EventResult{Err: err}
		}
	}()

	return results
}

// PutForwarderConfig saves the given ForwarderConfig object as a ConfigMap.
func (e *Service) PutForwarderConfig(ctx context.Context, f *ForwarderConfig) error {
	cm := &v1.ConfigMap{}

	// Get the existing configmap, if it exists. If it doesn't, we'll create it.
	err := e.client.Get(ctx, types.NamespacedName{Name: forwarderConfigConfigMapName, Namespace: forwarderConfigMapNamespace}, cm)
	if err != nil && !k8serrors.IsNotFound(err) {
		return err
	}

	// Set the fields on the configmap.
	bs, err := json.Marshal(f)
	if err != nil {
		return err
	}
	cm.Data = map[string]string{
		"config": string(bs),
	}

	// Create the configmap if it doesn't exist, otherwise update it.
	if cm.ResourceVersion == "" {
		cm.Name = forwarderConfigConfigMapName
		cm.Namespace = forwarderConfigMapNamespace
		return e.client.Create(ctx, cm)
	}
	return e.client.Update(ctx, cm)
}

// GetForwarderConfig retrieves the forwarder config (which will be a singleton).
func (e *Service) GetForwarderConfig(ctx context.Context) (*ForwarderConfig, error) {
	cm := &v1.ConfigMap{}
	err := e.client.Get(ctx, types.NamespacedName{Name: forwarderConfigConfigMapName, Namespace: forwarderConfigMapNamespace}, cm)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	var config ForwarderConfig
	if err = json.Unmarshal([]byte(cm.Data["config"]), &config); err != nil {
		return nil, err
	}
	return &config, nil
}
