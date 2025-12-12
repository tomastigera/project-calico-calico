// Copyright (c) 2019-2022 Tigera, Inc. All rights reserved.
package report

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	capi "github.com/projectcalico/calico/compliance/pkg/api"
	"github.com/projectcalico/calico/compliance/pkg/archive"
	"github.com/projectcalico/calico/compliance/pkg/config"
	"github.com/projectcalico/calico/compliance/pkg/event"
	"github.com/projectcalico/calico/compliance/pkg/flow"
	"github.com/projectcalico/calico/compliance/pkg/replay"
	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/compliance/pkg/xrefcache"
	"github.com/projectcalico/calico/libcalico-go/lib/compliance"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

const (
	// A zero-trust exposure is indicated when any of these flags are *set* in the endpoint cache entry.
	ZeroTrustWhenEndpointFlagsSet = xrefcache.CacheEntryInternetExposedIngress |
		xrefcache.CacheEntryInternetExposedEgress |
		xrefcache.CacheEntryOtherNamespaceExposedIngress |
		xrefcache.CacheEntryOtherNamespaceExposedEgress

	// A zero-trust exposure is indicated when any of these flags are *unset* in the endpoint cache entry.
	ZeroTrustWhenEndpointFlagsUnset = xrefcache.CacheEntryProtectedIngress |
		xrefcache.CacheEntryProtectedEgress |
		xrefcache.CacheEntryEnvoyEnabled

	// The full set of zero-trust flags for an endpoint.
	ZeroTrustFlags = ZeroTrustWhenEndpointFlagsSet | ZeroTrustWhenEndpointFlagsUnset

	// Compliance report logs need to be written to separate log files (one per report type), in order
	// to avoid write conflicts when report jobs run concurrently.
	// The pattern will be ReportLogFilenamePrefix + Report Type + ReportLogFilenameSuffix
	//			e.g. compliance.network-access.reports.log
	ReportLogFilenamePrefix = "compliance"
	ReportLogFilenameSuffix = "reports.log"
)

// Run is the entrypoint to start running the reporter.
func Run(ctx context.Context, cfg *config.Config, healthy func(), store capi.ComplianceStore) error {
	log.Info("Running reporter")

	// Inidicate healthy.
	healthy()

	// Get the report config.
	reportCfg := MustLoadReportConfig(cfg)

	// Create the cross-reference cache that we use to monitor for changes in the relevant data.
	xc := xrefcache.NewXrefCache(cfg, healthy)
	replayer := replay.New(cfg.ParsedReportStart, cfg.ParsedReportEnd, store, store, xc)

	var longTermArchiver archive.LogDispatcher
	if reportCfg.ArchiveLogsEnabled {
		log.WithFields(log.Fields{
			"directory": reportCfg.ArchiveLogsDirectory,
			"max_size":  reportCfg.ArchiveLogsMaxFileSizeMB,
			"max_files": reportCfg.ArchiveLogsMaxFiles,
		}).Info("Creating Archive Logs FileDispatcher")
		longTermArchiver = archive.NewFileDispatcher(
			reportCfg.ArchiveLogsDirectory,
			fmt.Sprintf("%s.%s.%s", ReportLogFilenamePrefix, reportCfg.ReportType.Name, ReportLogFilenameSuffix),
			reportCfg.ArchiveLogsMaxFileSizeMB,
			reportCfg.ArchiveLogsMaxFiles,
		)
	}

	r := &reporter{
		ctx: ctx,
		cfg: reportCfg,
		clog: log.WithFields(log.Fields{
			"name":  reportCfg.Report.Name,
			"type":  reportCfg.ReportType.Name,
			"start": cfg.ParsedReportStart.Format(time.RFC3339),
			"end":   cfg.ParsedReportEnd.Format(time.RFC3339),
		}),
		auditer:          store,
		flowlogger:       store,
		archiver:         store,
		xc:               xc,
		replayer:         replayer,
		benchmarker:      store,
		healthy:          healthy,
		inScopeEndpoints: make(map[apiv3.ResourceID]*reportEndpoint),
		services:         make(map[apiv3.ResourceID]xrefcache.CacheEntryFlags),
		namespaces:       make(map[apiv3.ResourceID]xrefcache.CacheEntryFlags),
		serviceAccounts:  set.New[apiv3.ResourceID](),
		policies:         set.New[apiv3.ResourceID](),
		data: &apiv3.ReportData{
			ReportName:     reportCfg.Report.Name,
			ReportTypeName: reportCfg.ReportType.Name,
			ReportSpec:     reportCfg.Report.Spec,
			ReportTypeSpec: reportCfg.ReportType.Spec,
			StartTime:      metav1.Time{Time: cfg.ParsedReportStart},
			EndTime:        metav1.Time{Time: cfg.ParsedReportEnd},
		},
		flowLogFilter:    flow.NewFlowLogFilter(),
		longTermArchiver: longTermArchiver,
	}

	return r.run()
}

type reporter struct {
	ctx         context.Context
	cfg         *Config
	clog        *log.Entry
	xc          xrefcache.XrefCache
	replayer    syncer.Starter
	auditer     capi.AuditLogReportHandler
	benchmarker capi.BenchmarksQuery
	flowlogger  capi.FlowLogReportHandler
	archiver    capi.ReportStorer
	healthy     func()

	// Consolidate the tracked in-scope endpoint events into a local cache, which will get converted and copied into
	// the report data structure.
	inScopeEndpoints map[apiv3.ResourceID]*reportEndpoint
	services         map[apiv3.ResourceID]xrefcache.CacheEntryFlags
	namespaces       map[apiv3.ResourceID]xrefcache.CacheEntryFlags
	serviceAccounts  set.Typed[apiv3.ResourceID]
	policies         set.Typed[apiv3.ResourceID]
	data             *apiv3.ReportData

	// Flow logs tracking information.
	flowLogFilter *flow.FlowLogFilter

	// Archive reports for long-term storage in secondary store (e.g. S3)
	longTermArchiver archive.LogDispatcher
}

type reportEndpoint struct {
	zeroTrustFlags xrefcache.CacheEntryFlags
	policies       set.Typed[apiv3.ResourceID]
	services       set.Typed[apiv3.ResourceID]
	flowAggrName   string
}

func (r *reporter) run() error {
	r.clog.Info("Reporter run started")

	// Report healthy.
	r.healthy()

	// Include endpoint data if required.
	if r.cfg.ReportType.Spec.IncludeEndpointData ||
		(r.cfg.ReportType.Spec.AuditEventsSelection != nil && r.cfg.Report.Spec.Endpoints != nil) {
		// We either want endpoint data in the report, or we are gathering audit logs and have specified an in-scope
		// endpoints filter with which we will filter in-scope resources.
		r.clog.Info("Including endpoint data in report, or require endpoints for filtering")

		// Register the endpoint selectors to specify which endpoints we will receive notification for.
		if err := r.xc.RegisterInScopeEndpoints(r.cfg.Report.Spec.Endpoints); err != nil {
			r.clog.WithError(err).Error("Unable to register inscope endpoints selection")
			return nil
		}

		// Configure the x-ref cache to spit out the events that we care about (which is basically all the endpoints
		// flagged as "in-scope".
		for _, k := range xrefcache.KindsEndpoint {
			r.xc.RegisterOnUpdateHandler(k, xrefcache.EventInScope, r.onUpdate)
		}

		// Register for status updates.
		r.xc.RegisterOnStatusUpdateHandler(r.onStatusUpdate)

		// Populate the report data from the replayer.
		r.replayer.Start(r.ctx)

		// Create the initial ReportData structure
		if r.cfg.ReportType.Spec.IncludeEndpointData {
			r.clog.Info("Including endpoint data in report")
			r.transferAggregatedData()
		}

		// Include flow logs if required.
		if r.cfg.ReportType.Spec.IncludeEndpointFlowLogData {
			// We also need to include flow logs data for the in-scope endpoints.
			r.clog.Info("Including flow log data in report")
			r.addFlowLogEntries()
		}
		r.flowLogFilter = nil
	}

	// Indicate we are healthy.
	r.healthy()

	// Include audit data if required.
	if r.cfg.ReportType.Spec.AuditEventsSelection != nil {
		// We need to include audit log data in the report.
		r.clog.Info("Including audit event data in report")
		if err := r.addAuditEvents(); err != nil {
			r.clog.WithError(err).Error("Hit error gathering audit logs")
			return err
		}
	}

	// Indicate we are healthy.
	r.healthy()

	// Include benchmarks if required.
	if r.cfg.ReportType.Spec.IncludeCISBenchmarkData {
		// We need to include benchmarks in the report.
		r.clog.Info("Including benchmarks in report")
		if err := r.addBenchmarks(); err != nil {
			r.clog.WithError(err).Error("Hit error gathering benchmarks")
			return err
		}
	}

	// Indicate we are healthy.
	r.healthy()

	r.clog.Info("Rendering report data based on template")
	summary, err := compliance.RenderTemplate(r.cfg.ReportType.Spec.UISummaryTemplate.Template, r.data)
	if err != nil {
		r.clog.WithError(err).Error("Error rendering data into summary")
	}

	// Indicate we are healthy.
	r.healthy()

	// Set the generation time and store the report data.
	r.clog.Info("Storing report into archiver")
	r.data.GenerationTime = metav1.Now()
	_ = r.archiver.StoreArchivedReport(&v1.ReportData{
		ReportData: r.data,
		UISummary:  summary,
	})

	// Indicate we are healthy.
	r.healthy()

	// Set the generation time and store the report data.
	r.clog.Info("Initializing long-term storage")
	if err = r.longTermArchiver.Initialize(); err != nil {
		r.clog.WithError(err).Error("Long-term storage file dispatcher unable to initialize")
		return err
	}

	r.clog.Info("Sending report to long-term storage")
	if err = r.longTermArchiver.Dispatch(v1.ReportData{
		ReportData: r.data,
		UISummary:  summary,
	}); err != nil {
		r.clog.WithError(err).Error("Error sending report to long-term storage")
		return err
	}

	// Indicate we are healthy.
	r.healthy()

	r.clog.Info("Report is successfully executed")

	return nil
}

func (r *reporter) onUpdate(update syncer.Update) {
	if update.Type&xrefcache.EventResourceDeleted != 0 {
		// We don't need to track deleted endpoints because we are getting the superset of resources managed within the
		// timeframe.
		return
	}
	xref := update.Resource.(*xrefcache.CacheEntryEndpoint)
	ep := r.getEndpoint(update.ResourceID)
	zeroTrustFlags, _ := zeroTrustFlags(update.Type, xref.Flags)

	// Update the endpoint and namespaces policies and services
	// TODO(rlb): Performance improvement here - we only need to update what has actually changed in particular no
	//           need to update policies or services set if not changed. However, I have not UTd that the correct
	//           update flags are returned, so let's not trust to luck.
	ep.zeroTrustFlags |= zeroTrustFlags
	ep.policies.AddSet(xref.AppliedPolicies)
	ep.services.AddSet(xref.Services)

	// Track the full set of Policies and ServiceAccounts for all our in-scope endpoints.
	r.policies.AddSet(xref.AppliedPolicies)
	if xref.ServiceAccount != nil {
		r.serviceAccounts.Add(*xref.ServiceAccount)
	}

	// Loop through and update the flags on the services.
	for item := range ep.services.All() {
		r.services[item] |= zeroTrustFlags
	}

	ep.flowAggrName = xref.GetFlowLogAggregationName()

	// Update the namespace flags.
	if update.ResourceID.Namespace != "" {
		r.namespaces[toNamespace(update.ResourceID.Namespace)] |= zeroTrustFlags
	}
}

func (r *reporter) getEndpoint(id apiv3.ResourceID) *reportEndpoint {
	re := r.inScopeEndpoints[id]
	if re == nil {
		re = &reportEndpoint{
			policies: set.New[apiv3.ResourceID](),
			services: set.New[apiv3.ResourceID](),
		}
		r.inScopeEndpoints[id] = re
	}
	return re
}

func (r *reporter) onStatusUpdate(status syncer.StatusUpdate) {
	switch status.Type {
	case syncer.StatusTypeFailed:
		r.clog.Fatalf("Unable to generate report: %v", status.Error)
	case syncer.StatusTypeComplete:
		r.clog.Info("All data has been processed")
	}
}

// addFlowLogEntries adds flows matching the FlowLogFilter to the ReportData.
// Aggregated flow logs are searched using the namespaces specified
// in the FlowLogFilter. Results are further filtered using the endpoint names
// and aggregated endpoint names tracked in the FlowLogFilter.
func (r *reporter) addFlowLogEntries() {
	namespaces := make([]string, 0, len(r.flowLogFilter.Namespaces))
	for ns := range r.flowLogFilter.Namespaces {
		namespaces = append(namespaces, ns)
	}

	r.clog.Debug("Processing flow results")
	for epFlow := range r.flowlogger.SearchFlows(r.ctx, namespaces, &r.cfg.ParsedReportStart, &r.cfg.ParsedReportEnd) {
		// On error, skip processing this flow and continue processing the next one.
		if epFlow.Err != nil {
			r.clog.WithError(epFlow.Err).Error("Error processing flow log entry")
			continue
		}
		if r.flowLogFilter.FilterInFlow(epFlow.EndpointsReportFlow) {
			r.data.Flows = append(r.data.Flows, *epFlow.EndpointsReportFlow)
		}
	}
}

// addAuditEvents reads audit logs from storage, filters them based on the resources specified in
// `filter`. Blank fields in the filter ResourceIDs are regarded as wildcard matches for that
// parameter.  Fields within a ResourceID are ANDed, different ResourceIDs are ORed. For example:
//   - an empty filter would include no audit events
//   - a filter containing a blank ResourceID would contain all audit events
//   - a filter containing two ResourceIDs, one with Kind set to "NetworkPolicy", the other with kind
//     set to "GlobalNetworkPolicy" would include all Kubernetes and Calico NetworkPolicy and
//     all Calico GlobalNetworkPolicy audit events.
func (r *reporter) addAuditEvents() error {
	for e := range r.auditer.SearchAuditEvents(r.ctx, r.cfg.ReportType.Spec.AuditEventsSelection,
		&r.cfg.ParsedReportStart, &r.cfg.ParsedReportEnd) {
		// If we received an error then log and exit.
		if e.Err != nil {
			r.clog.WithError(e.Err).Error("Error querying audit logs from store")
			return e.Err
		}

		// If we were filtering endpoints, then check to see if the audit event is associated with any of our in-scope
		// types, otherwise we aren't filtering at all.
		if r.cfg.Report.Spec.Endpoints != nil {
			// Normalize the resource kind in the event log.
			if res, err := event.ExtractResourceFromAuditEvent(e.Event); err != nil {
				r.clog.WithError(err).Error("Unable to extract resource from audit event")
				continue
			} else if res == nil {
				r.clog.Info("Filtering out unhandled event type")
				continue
			} else if id := resources.GetResourceID(res); !r.isInScope(id) {
				r.clog.Infof("Filtering out not-in-scope resource from audit events: %s", id)
				continue
			}
		}

		// The audit event is being included. Update the stats and append the event log.
		switch e.Verb {
		case string(v1.Create):
			r.data.AuditSummary.NumCreate++
		case string(v1.Patch), string(v1.Update):
			r.data.AuditSummary.NumModify++
		case string(v1.Delete):
			r.data.AuditSummary.NumDelete++
		}
		r.data.AuditEvents = append(r.data.AuditEvents, *e.Event)
		r.data.AuditSummary.NumTotal++
	}

	return nil
}

// isInScope returns true if the specified id is in our in-scope data.
func (r *reporter) isInScope(id apiv3.ResourceID) bool {
	switch id.TypeMeta {
	case resources.TypeK8sNamespaces:
		_, ok := r.namespaces[id]
		return ok
	case resources.TypeK8sServiceAccounts:
		return r.serviceAccounts.Contains(id)
	case resources.TypeK8sPods, resources.TypeCalicoHostEndpoints:
		_, ok := r.inScopeEndpoints[id]
		return ok
	case resources.TypeCalicoNetworkPolicies, resources.TypeCalicoGlobalNetworkPolicies, resources.TypeK8sNetworkPolicies:
		return r.policies.Contains(id)
	case resources.TypeK8sServices:
		_, ok := r.services[id]
		return ok
	case resources.TypeK8sEndpoints:
		nid := apiv3.ResourceID{
			TypeMeta:  resources.TypeK8sServices,
			Name:      id.Name,
			Namespace: id.Namespace,
		}
		_, ok := r.services[nid]
		return ok
	case resources.TypeCalicoGlobalNetworkSets, resources.TypeCalicoNetworkSets:
		return false
	default:
		return false
	}
}

func (r *reporter) transferAggregatedData() {
	// Create the endpoints slice up-front because it's likely to be large.
	r.data.Endpoints = make([]apiv3.EndpointsReportEndpoint, 0, len(r.inScopeEndpoints))

	// Transfer the aggregated data to the ReportData structure. Start with endpoints.
	for id, ep := range r.inScopeEndpoints {
		r.data.Endpoints = append(r.data.Endpoints, apiv3.EndpointsReportEndpoint{
			Endpoint:                  id,
			IngressProtected:          ep.zeroTrustFlags&xrefcache.CacheEntryProtectedIngress == 0, // We reversed this for zero-trust
			EgressProtected:           ep.zeroTrustFlags&xrefcache.CacheEntryProtectedEgress == 0,  // We reversed this for zero-trust
			IngressFromInternet:       ep.zeroTrustFlags&xrefcache.CacheEntryInternetExposedIngress != 0,
			EgressToInternet:          ep.zeroTrustFlags&xrefcache.CacheEntryInternetExposedEgress != 0,
			IngressFromOtherNamespace: ep.zeroTrustFlags&xrefcache.CacheEntryOtherNamespaceExposedIngress != 0,
			EgressToOtherNamespace:    ep.zeroTrustFlags&xrefcache.CacheEntryOtherNamespaceExposedEgress != 0,
			EnvoyEnabled:              ep.zeroTrustFlags&xrefcache.CacheEntryEnvoyEnabled == 0, // We reversed this for zero-trust
			AppliedPolicies:           ep.policies.Slice(),
			Services:                  ep.services.Slice(),
			FlowLogAggregationName:    ep.flowAggrName,
		})

		// Track for filter flow logs at a later stage.
		r.flowLogFilter.TrackNamespaceAndEndpoint(id.Namespace, id.Name, ep.flowAggrName)

		// Update the summary stats.
		updateSummary(ep.zeroTrustFlags, &r.data.EndpointsSummary, true)

		// Fill in the service account stat which is not handled by zero trust.
		r.data.EndpointsSummary.NumServiceAccounts = r.serviceAccounts.Len()

		// Delete from our dictionary now.
		delete(r.inScopeEndpoints, id)
	}

	// We can delete the dictionary now.
	r.inScopeEndpoints = nil

	// Now handle namespaces.
	for ns, zeroTrustFlags := range r.namespaces {
		r.data.Namespaces = append(r.data.Namespaces, apiv3.EndpointsReportNamespace{
			Namespace: apiv3.ResourceID{
				TypeMeta: resources.TypeK8sNamespaces,
				Name:     ns.Name,
			},
			IngressProtected:          zeroTrustFlags&xrefcache.CacheEntryProtectedIngress == 0, // We reversed this for zero-trust
			EgressProtected:           zeroTrustFlags&xrefcache.CacheEntryProtectedEgress == 0,  // We reversed this for zero-trust
			IngressFromInternet:       zeroTrustFlags&xrefcache.CacheEntryInternetExposedIngress != 0,
			EgressToInternet:          zeroTrustFlags&xrefcache.CacheEntryInternetExposedEgress != 0,
			IngressFromOtherNamespace: zeroTrustFlags&xrefcache.CacheEntryOtherNamespaceExposedIngress != 0,
			EgressToOtherNamespace:    zeroTrustFlags&xrefcache.CacheEntryOtherNamespaceExposedEgress != 0,
			EnvoyEnabled:              zeroTrustFlags&xrefcache.CacheEntryEnvoyEnabled == 0, // We reversed this for zero-trust
		})

		// Delete from our dictionary now.
		delete(r.namespaces, ns)

		// Update the summary stats.
		updateSummary(zeroTrustFlags, &r.data.NamespacesSummary, true)
	}

	// We can delete the dictionary now.
	r.namespaces = nil

	// Now handle services.
	for id, zeroTrustFlags := range r.services {
		r.data.Services = append(r.data.Services, apiv3.EndpointsReportService{
			Service:                   id,
			IngressProtected:          zeroTrustFlags&xrefcache.CacheEntryProtectedIngress == 0, // We reversed this for zero-trust
			IngressFromInternet:       zeroTrustFlags&xrefcache.CacheEntryInternetExposedIngress != 0,
			IngressFromOtherNamespace: zeroTrustFlags&xrefcache.CacheEntryOtherNamespaceExposedIngress != 0,
			EnvoyEnabled:              zeroTrustFlags&xrefcache.CacheEntryEnvoyEnabled == 0, // We reversed this for zero-trust
		})

		// Delete from our dictionary now.
		delete(r.services, id)

		// Update the summary stats.
		updateSummary(zeroTrustFlags, &r.data.ServicesSummary, false)
	}

	// We can delete the dictionary now.
	r.services = nil
}

func updateSummary(zeroTrustFlags xrefcache.CacheEntryFlags, summary *apiv3.EndpointsSummary, includeEgress bool) {
	summary.NumTotal++
	if zeroTrustFlags&xrefcache.CacheEntryProtectedIngress == 0 {
		summary.NumIngressProtected++ // We reversed this for zero-trust
	}
	if zeroTrustFlags&xrefcache.CacheEntryInternetExposedIngress != 0 {
		summary.NumIngressFromInternet++
	}
	if zeroTrustFlags&xrefcache.CacheEntryOtherNamespaceExposedIngress != 0 {
		summary.NumIngressFromOtherNamespace++
	}
	if zeroTrustFlags&xrefcache.CacheEntryEnvoyEnabled == 0 {
		summary.NumEnvoyEnabled++
	}
	if includeEgress {
		if zeroTrustFlags&xrefcache.CacheEntryProtectedEgress == 0 {
			summary.NumEgressProtected++ // We reversed this for zero-trust
		}
		if zeroTrustFlags&xrefcache.CacheEntryInternetExposedEgress != 0 {
			summary.NumEgressToInternet++
		}
		if zeroTrustFlags&xrefcache.CacheEntryOtherNamespaceExposedEgress != 0 {
			summary.NumEgressToOtherNamespace++
		}
	}
}

// zeroTrustFlags converts the flags and updates into a set of zero-trust flags and changed zero-trust flags.
// The zero trust flags map on to the cache entry flags, but reverse the bit for the flags whose "unset" value indicates
// zero trust.
func zeroTrustFlags(updateType syncer.UpdateType, flags xrefcache.CacheEntryFlags) (allZeroTrust, changedZeroTrust xrefcache.CacheEntryFlags) {
	// The updateType flags correspond directly with the cache entry flags so we can perform bitwise manipulation on them
	// to check for updates.

	// Get the set of changed flags (update masked with the flags of interest). One alteration though, for an add we need
	// to treat as if all fields changed.
	changedFlags := xrefcache.CacheEntryFlags(updateType) & ZeroTrustFlags
	if updateType&xrefcache.EventResourceAdded != 0 {
		changedFlags = ZeroTrustFlags
	}

	// Calculate the corresponding set of flags that indicate a zero-trust exposure.
	zeroTrust := (flags ^ ZeroTrustWhenEndpointFlagsUnset) & ZeroTrustFlags

	return zeroTrust, zeroTrust & changedFlags
}

// toNamespace converts a namespace name to the equivalent ResourceID.
func toNamespace(ns string) apiv3.ResourceID {
	return apiv3.ResourceID{
		TypeMeta: resources.TypeK8sNamespaces,
		Name:     ns,
	}
}
