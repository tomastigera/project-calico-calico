// Copyright (c) 2023 Tigera All rights reserved.

package api

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	auditv1 "k8s.io/apiserver/pkg/apis/audit"

	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	lma "github.com/projectcalico/calico/lma/pkg/api"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/projectcalico/calico/lma/pkg/list"
)

const (
	DefaultPageSize       = 100
	defaultLinseedTimeout = 60 * time.Second
)

type StoreFactory interface {
	NewStore(cluster string) ComplianceStore
}

func NewStoreFactory(c client.Client) StoreFactory {
	return &storeFactory{c}
}

type storeFactory struct {
	c client.Client
}

func (f *storeFactory) NewStore(cluster string) ComplianceStore {
	return NewComplianceStore(f.c, cluster)
}

// ComplianceStore is an interface for the reporter to use when interacting with the data store.
type ComplianceStore interface {
	ListDestination
	ReportEventFetcher
	AuditLogReportHandler
	FlowLogReportHandler
	ReportStorer
	BenchmarksQuery
	ReportRetriever
	BenchmarksStore
}

func NewComplianceStore(lsc client.Client, cluster string) ComplianceStore {
	return &complianceStore{
		c:     lsc.Compliance(cluster),
		audit: lsc.AuditLogs(cluster),
		flows: lsc.L3Flows(cluster),
	}
}

type complianceStore struct {
	c     client.ComplianceInterface
	audit client.AuditLogsInterface
	flows client.L3FlowsInterface
}

func (r *complianceStore) RetrieveList(kind metav1.TypeMeta, from *time.Time, to *time.Time, sortAscendingTime bool) (*list.TimestampedResourceList, error) {
	params := v1.SnapshotParams{}
	if from != nil || to != nil {
		params.TimeRange = &lmav1.TimeRange{}
		if from != nil {
			params.TimeRange.From = *from
		}
		if to != nil {
			params.TimeRange.To = *to
		} else {
			params.TimeRange.To = time.Now()
		}
	}
	params.TypeMatch = &kind
	params.Sort = []v1.SearchRequestSortBy{{Field: "requestCompletedTimestamp", Descending: !sortAscendingTime}}

	// We only want to retrieve a single item.
	params.MaxPageSize = 1

	ctx, cancel := context.WithTimeout(context.Background(), defaultLinseedTimeout)
	defer cancel()

	// Perform the query.
	items, err := r.c.Snapshots().List(ctx, &params)
	if err != nil {
		return nil, err
	} else if num := len(items.Items); num == 0 {
		return nil, cerrors.ErrorResourceDoesNotExist{Err: fmt.Errorf("no snapshot found"), Identifier: kind}
	} else if num != 1 {
		return nil, fmt.Errorf("unexpected number of results (%d)", num)
	}
	return &items.Items[0].ResourceList, nil
}

func (r *complianceStore) StoreList(_ metav1.TypeMeta, l *list.TimestampedResourceList) error {
	if l == nil {
		logrus.Warn("BUG: nil *list.TimestampedResourceList provided")
		return nil
	}
	s := v1.Snapshot{
		ID:           l.String(),
		ResourceList: *l,
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultLinseedTimeout)
	defer cancel()
	snaps := r.c.Snapshots()
	resp, err := snaps.Create(ctx, []v1.Snapshot{s})
	if err != nil {
		return err
	}
	if resp.Succeeded != 1 || resp.Failed != 0 {
		return fmt.Errorf("error storing snapshot: %#v", resp)
	}
	logrus.WithFields(logrus.Fields{"id": s.ID, "kind": s.ResourceList.GetObjectKind()}).Info("successfully stored list")
	return nil
}

func (r *complianceStore) GetAuditEvents(ctx context.Context, start *time.Time, end *time.Time) <-chan *AuditEventResult {
	return r.SearchAuditEvents(ctx, nil, start, end)
}

func (r *complianceStore) SearchAuditEvents(ctx context.Context, filter *apiv3.AuditEventsSelection, start *time.Time, end *time.Time) <-chan *AuditEventResult {
	ch := make(chan *AuditEventResult, DefaultPageSize)

	go func() {
		defer func() {
			logrus.Infof("completed audit events query")
			close(ch)
		}()

		params := constructAuditEventsQuery(filter, start, end)
		lp := client.NewListPager[v1.AuditLog](params)
		pages, errors := lp.Stream(ctx, r.audit.List)
		for page := range pages {
			for _, item := range page.Items {
				ch <- &AuditEventResult{Event: &item.Event}
			}
		}
		if err, ok := <-errors; ok {
			ch <- &AuditEventResult{Err: err}
		}
	}()

	return ch
}

// Issue a query to Linseed that matches flow logs that are
// generated or received by the specified namespaces and occurred within the
// start and end time range. We do not filter flow logs using endpoint based
// queries due to potentially large number of in-scope endpoints that may
// have to be specified in the query.
func (r *complianceStore) SearchFlows(ctx context.Context, namespaces []string, start *time.Time, end *time.Time) <-chan *lma.FlowLogResult {
	logrus.Debugf("Searching across namespaces %+v", namespaces)
	ch := make(chan *lma.FlowLogResult, DefaultPageSize)

	go func() {
		// Linseed doesn't aggregate across reporter and action, but for the purposes of Compliance we don't care about
		// those distinctions. So, keep track of which flows we have sent and skip any that are duplicates.
		sent := map[apiv3.EndpointsReportFlow]struct{}{}
		defer func() {
			logrus.WithField("namespaces", namespaces).WithField("found", len(sent)).Infof("completed flow query")
			close(ch)
		}()

		params := buildFlowQuery(start, end, namespaces)
		lp := client.NewListPager[v1.L3Flow](params)
		pages, errors := lp.Stream(ctx, r.flows.List)
		for page := range pages {
			for _, item := range page.Items {
				sname, sIsAggregated := getFlowEndpointName(item.Key.Source.Name, item.Key.Source.AggregatedName)
				dname, dIsAggregated := getFlowEndpointName(item.Key.Destination.Name, item.Key.Destination.AggregatedName)
				stype := getFlowEndpointType(item.Key.Source.Type, sname)
				dtype := getFlowEndpointType(item.Key.Destination.Type, dname)
				reportFlow := apiv3.EndpointsReportFlow{
					Source: apiv3.FlowEndpoint{
						Name:                    sname,
						Namespace:               item.Key.Source.Namespace,
						Kind:                    stype,
						NameIsAggregationPrefix: sIsAggregated,
					},
					Destination: apiv3.FlowEndpoint{
						Name:                    dname,
						Namespace:               item.Key.Destination.Namespace,
						Kind:                    dtype,
						NameIsAggregationPrefix: dIsAggregated,
					},
				}
				if _, ok := sent[reportFlow]; !ok {
					ch <- &lma.FlowLogResult{EndpointsReportFlow: &reportFlow}
					sent[reportFlow] = struct{}{}
				}
			}
		}
		if err, ok := <-errors; ok {
			ch <- &lma.FlowLogResult{Err: err}
		}
	}()

	return ch
}

func (r *complianceStore) StoreArchivedReport(d *v1.ReportData) error {
	if d == nil {
		logrus.Warn("BUG: nil *v1.ReportData provided")
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultLinseedTimeout)
	defer cancel()
	_, err := r.c.ReportData().Create(ctx, []v1.ReportData{*d})
	logrus.WithFields(logrus.Fields{"id": d.UID()}).Info("successfully stored report")
	return err
}

// RetrieveLatestBenchmarks returns the set of BenchmarkSetIDs within the time interval.
func (r *complianceStore) RetrieveLatestBenchmarks(ctx context.Context, ct v1.BenchmarkType, filters []v1.BenchmarksFilter, start time.Time, end time.Time) <-chan BenchmarksResult {
	params := v1.BenchmarksParams{}
	params.TimeRange = &lmav1.TimeRange{}
	params.TimeRange.From = start
	params.TimeRange.To = end
	params.Type = ct
	params.Filters = filters

	ch := make(chan BenchmarksResult, DefaultPageSize)
	seen := make(map[string]*v1.Benchmarks)

	go func() {
		defer func() {
			logrus.Infof("completed benchmarks query")
			close(ch)
		}()

		lp := client.NewListPager[v1.Benchmarks](&params)
		pages, errors := lp.Stream(ctx, r.c.Benchmarks().List)
		for page := range pages {
			for _, benchmarks := range page.Items {
				// Make a copy, since we're potentially sending a pointer over the channel.
				bms := benchmarks

				if prev, ok := seen[bms.NodeName]; ok {
					f := logrus.Fields{"node": bms.NodeName, "previousTime": prev.Timestamp, "thisTime": bms.Timestamp}
					logrus.WithFields(f).Debug("Found an earlier benchmark set for this node")
					if prev.Error == "" || bms.Error != "" {
						// Either the previous entry did not indicate error, or this entry does indicate an error
						// in either case continue processing entries.
						continue
					}
				}

				// Either this is a new node, or this is the first non-errored entry for that node. Update our seen map
				// and if not errored send the update now.
				seen[bms.NodeName] = &bms
				if bms.Error == "" {
					logrus.WithFields(
						logrus.Fields{
							"node": bms.NodeName,
							"time": bms.Timestamp,
						}).Debug("Found latest successful benchmark set for this node")
					ch <- BenchmarksResult{Benchmarks: &bms}
				}

			}

			// We have iterated through all sets. Any that contain an error, send those now since we were previously holding
			// off in case we found a non-errored set.
			for _, benchmarks := range seen {
				if benchmarks.Error != "" {
					logrus.WithFields(
						logrus.Fields{
							"node": benchmarks.NodeName,
							"time": benchmarks.Timestamp,
						}).Debug("Sending errored benchmark set for this node")
					ch <- BenchmarksResult{Benchmarks: benchmarks}
				}
			}
		}
		if err, ok := <-errors; ok {
			ch <- BenchmarksResult{Err: err}
		}
	}()

	return ch
}

// RetrieveArchivedReport implements the api.ReportRetriever interface
func (c *complianceStore) RetrieveArchivedReportTypeAndNames(ctx context.Context, q ReportQueryParams) ([]ReportTypeAndName, error) {
	reports, err := c.RetrieveArchivedReportSummaries(ctx, q)
	if err != nil {
		return nil, err
	}
	res := []ReportTypeAndName{}
	for _, report := range reports.Reports {
		res = append(res, ReportTypeAndName{
			ReportName:     report.ReportName,
			ReportTypeName: report.ReportTypeName,
		})
	}

	return res, nil
}

// RetrieveArchivedReport implements the api.ReportRetriever interface
func (c *complianceStore) RetrieveArchivedReportSummaries(ctx context.Context, q ReportQueryParams) (*ArchivedReportSummaries, error) {
	params := v1.ReportDataParams{}
	for _, s := range q.SortBy {
		params.Sort = append(params.Sort, v1.SearchRequestSortBy{
			Field: s.Field, Descending: !s.Ascending,
		})
	}
	if q.FromTime != "" || q.ToTime != "" {
		params.TimeRange = &lmav1.TimeRange{}
		if q.FromTime != "" {
			t, err := time.Parse(time.RFC3339, q.FromTime)
			if err != nil {
				panic(err)
			}
			params.TimeRange.From = t
		}
		if q.ToTime != "" {
			t, err := time.Parse(time.RFC3339, q.ToTime)
			if err != nil {
				panic(err)
			}
			params.TimeRange.To = t
		} else {
			params.TimeRange.To = time.Now()
		}
	}
	for _, r := range q.Reports {
		params.ReportMatches = append(params.ReportMatches, v1.ReportMatch{
			ReportName:     r.ReportName,
			ReportTypeName: r.ReportTypeName,
		})
	}

	// Set the default page size
	params.SetMaxPageSize(DefaultPageSize)

	if q.Page > 0 {
		actualPageSize := params.GetMaxPageSize()
		if q.MaxItems != nil && *q.MaxItems != 0 {
			actualPageSize = int(math.Min(float64(params.GetMaxPageSize()), float64(*q.MaxItems)))
		}
		params.SetAfterKey(map[string]any{
			"startFrom": q.Page * actualPageSize,
		})
	}

	opts := []client.ListPagerOption[v1.ReportData]{}
	if q.MaxItems != nil {
		opts = append(opts, client.WithMaxResults[v1.ReportData](*q.MaxItems))

		// If the maximum items we've been request to return is less than a single page,
		// we should reduce the page size to match.
		if *q.MaxItems < params.GetMaxPageSize() {
			params.MaxPageSize = *q.MaxItems
		}
	}

	lp := client.NewListPager(&params, opts...)
	pages, errors := lp.Stream(ctx, c.c.ReportData().List)

	summary := ArchivedReportSummaries{}
	for page := range pages {
		// TotalHits is actually the total items returned from Elastic and not the page size.
		summary.Count = int(page.TotalHits)
		for _, report := range page.Items {
			summary.Reports = append(summary.Reports, reportToSummary(&report))
		}
	}
	if err, ok := <-errors; ok {
		return nil, err
	}
	return &summary, nil
}

// Summarize the report. Only a subet of fields are included in a report summary.
func reportToSummary(report *v1.ReportData) *v1.ReportData {
	rd := apiv3.ReportData{}
	rd.ReportName = report.ReportName
	rd.ReportTypeName = report.ReportTypeName
	rd.ReportSpec = report.ReportSpec
	rd.ReportTypeSpec = report.ReportTypeSpec
	rd.StartTime = report.StartTime
	rd.EndTime = report.EndTime
	rd.GenerationTime = report.GenerationTime
	rd.EndpointsSummary = report.EndpointsSummary
	rd.NamespacesSummary = report.NamespacesSummary
	rd.ServicesSummary = report.ServicesSummary
	rd.AuditSummary = report.AuditSummary
	return &v1.ReportData{ReportData: &rd, UISummary: report.UISummary}
}

// RetrieveArchivedReport implements the api.ReportRetriever interface
func (c *complianceStore) RetrieveLastArchivedReportSummary(ctx context.Context, reportName string) (*v1.ReportData, error) {
	params := v1.ReportDataParams{}
	params.MaxPageSize = 1

	// Query in descending time order. The first entry in the array will be
	// the latest report.
	params.Sort = append(params.Sort, v1.SearchRequestSortBy{
		Field: "endTime", Descending: true,
	})

	res, err := c.c.ReportData().List(ctx, &params)
	if err != nil {
		return nil, err
	}
	if len(res.Items) == 0 {
		return nil, cerrors.ErrorResourceDoesNotExist{
			Identifier: reportName,
			Err:        errors.New("no reports exist with the requested ID"),
		}
	} else if len(res.Items) > 1 {
		logrus.Warnf("More than one report with the given name: %s", reportName)
	}
	return reportToSummary(&res.Items[0]), nil
}

// RetrieveArchivedReport implements the api.ReportRetriever interface
func (c *complianceStore) RetrieveArchivedReport(ctx context.Context, id string) (*v1.ReportData, error) {
	params := v1.ReportDataParams{ID: id}
	res, err := c.c.ReportData().List(ctx, &params)
	if err != nil {
		return nil, err
	}
	if len(res.Items) == 0 {
		return nil, cerrors.ErrorResourceDoesNotExist{
			Identifier: id,
			Err:        errors.New("no report archives exist with the requested ID"),
		}
	} else if len(res.Items) > 1 {
		logrus.Warnf("More than one report archive with the given ID: %s", id)
	}
	return &res.Items[0], nil
}

func (r *complianceStore) GetBenchmarks(cxt context.Context, id string) (*v1.Benchmarks, error) {
	params := v1.BenchmarksParams{}
	params.ID = id

	ctx, cancel := context.WithTimeout(context.Background(), defaultLinseedTimeout)
	defer cancel()
	res, err := r.c.Benchmarks().List(ctx, &params)
	if err != nil {
		return nil, err
	}

	if len(res.Items) == 0 {
		return nil, cerrors.ErrorResourceDoesNotExist{
			Identifier: id,
			Err:        errors.New("no benchmarks exist with the requested ID"),
		}
	} else if len(res.Items) > 1 {
		logrus.Warnf("More than one benchmark with the given ID: %s", id)
	}
	return &res.Items[0], nil
}

// StoreBenchmarks stores the supplied benchmarks.
func (r *complianceStore) StoreBenchmarks(ctx context.Context, b *v1.Benchmarks) error {
	if b == nil {
		logrus.Warn("BUG: nil *v1.Benchmarks provided")
		return nil
	}
	_, err := r.c.Benchmarks().Create(ctx, []v1.Benchmarks{*b})
	return err
}

func constructAuditEventsQuery(filter *apiv3.AuditEventsSelection, start, end *time.Time) *v1.AuditLogParams {
	params := v1.AuditLogParams{}
	params.MaxPageSize = DefaultPageSize
	params.Type = v1.AuditLogTypeAny

	// Limit query to include ResponseComplete stage only since that has that has the most information, and only
	// to the configuration event verb types.
	params.Stages = []auditv1.Stage{auditv1.StageResponseComplete}
	params.Verbs = EventConfigurationVerbs

	// Query by filter if specified.
	if filter != nil {
		for _, r := range filter.Resources {
			params.ObjectRefs = append(params.ObjectRefs, v1.ObjectReference{
				Name:       r.Name,
				Namespace:  r.Namespace,
				APIGroup:   r.APIGroup,
				APIVersion: r.APIVersion,
				Resource:   r.Resource,
			})
		}
	}

	// Query by from/to if specified.
	if start != nil || end != nil {
		params.TimeRange = &lmav1.TimeRange{}
		if start != nil {
			params.TimeRange.From = *start
		}
		if end != nil {
			params.TimeRange.To = *end
		}
	}
	return &params
}

// buildFlowQuery returns the flow queries to perform, given the input. This may return more than one
// query if needed in order to satisfy the request.
func buildFlowQuery(start, end *time.Time, namespaces []string) *v1.L3FlowParams {
	// Build base params for each type of query.
	params := v1.L3FlowParams{}
	params.MaxPageSize = DefaultPageSize
	if start != nil || end != nil {
		params.TimeRange = &lmav1.TimeRange{}
		if start != nil {
			params.TimeRange.From = *start
		}
		if end != nil {
			params.TimeRange.To = *end
		}
	}

	if len(namespaces) != 0 {
		params.NamespaceMatches = append(params.NamespaceMatches, v1.NamespaceMatch{
			Type:       v1.MatchTypeAny,
			Namespaces: namespaces,
		})
	}

	return &params
}

func getFlowEndpointType(flowLogEndpointType v1.EndpointType, endpointName string) (flowEndpointType string) {
	switch flowLogEndpointType {
	case v1.HEP:
		flowEndpointType = resources.TypeCalicoHostEndpoints.Kind
	case v1.WEP:
		flowEndpointType = resources.TypeK8sPods.Kind
	case v1.NetworkSet:
		flowEndpointType = resources.TypeCalicoGlobalNetworkSets.Kind
	case v1.Network:
		switch endpointName {
		case lma.FlowLogNetworkPublic:
			flowEndpointType = apiv3.KindFlowPublic
		case lma.FlowLogNetworkPrivate:
			flowEndpointType = apiv3.KindFlowPrivate
		default:
			logrus.WithFields(logrus.Fields{
				"type": flowLogEndpointType,
				"name": endpointName,
			}).Error("Unknown endpoint type")
		}
	default:
		logrus.WithField("endpoint-type", flowLogEndpointType).Error("Unknown endpoint type")
	}
	return
}

func getFlowEndpointName(name, nameAggr string) (flowName string, isAggregated bool) {
	flowName = name
	if name == "-" || name == "" {
		flowName = nameAggr
		isAggregated = true
	}
	return
}
