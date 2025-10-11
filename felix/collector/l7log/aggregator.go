// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

package l7log

import (
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/config"
)

// TODO: If named aggregation levels works better, refactor all these levels to only be strings
// Aggregation variables
type HTTPHeaderAggregationKind int
type HTTPMethodAggregationKind int
type ServiceAggregationKind int
type DestinationAggregationKind int
type SourceAggregationKind int
type URLAggregationKind int
type ResponseCodeAggregationKind int

const (
	HTTPHeaderInfo HTTPHeaderAggregationKind = iota
	HTTPHeaderInfoNone
)

const (
	HTTPMethod HTTPMethodAggregationKind = iota
	HTTPMethodNone
)

const (
	ServiceInfo ServiceAggregationKind = iota
	ServiceInfoNone
)

const (
	DestinationInfo DestinationAggregationKind = iota
	DestinationInfoNone
)

const (
	SourceInfo SourceAggregationKind = iota
	SourceInfoNoPort
	SourceInfoNone
)

const (
	FullURL URLAggregationKind = iota
	URLWithoutQuery
	BaseURL
	URLNone
)

const (
	ResponseCode ResponseCodeAggregationKind = iota
	ResponseCodeNone
)

var aggregationKindTypeMap map[string]int = map[string]int{
	"ExcludeL7HTTPHeaderInfo":   int(HTTPHeaderInfoNone),
	"IncludeL7HTTPHeaderInfo":   int(HTTPHeaderInfo),
	"ExcludeL7HTTPMethod":       int(HTTPMethodNone),
	"IncludeL7HTTPMethod":       int(HTTPMethod),
	"ExcludeL7ServiceInfo":      int(ServiceInfoNone),
	"IncludeL7ServiceInfo":      int(ServiceInfo),
	"ExcludeL7DestinationInfo":  int(DestinationInfoNone),
	"IncludeL7DestinationInfo":  int(DestinationInfo),
	"ExcludeL7SourceInfo":       int(SourceInfoNone),
	"IncludeL7SourceInfoNoPort": int(SourceInfoNoPort),
	"IncludeL7SourceInfo":       int(SourceInfo),
	"ExcludeL7URL":              int(URLNone),
	"TrimURLQuery":              int(URLWithoutQuery),
	"TrimURLQueryAndPath":       int(BaseURL),
	"IncludeL7FullURL":          int(FullURL),
	"ExcludeL7ResponseCode":     int(ResponseCodeNone),
	"IncludeL7ResponseCode":     int(ResponseCode),
}

// AggregationKind is a collection of all the different types of aggregation
// values that make up L7 aggregation.
type AggregationKind struct {
	HTTPHeader      HTTPHeaderAggregationKind
	HTTPMethod      HTTPMethodAggregationKind
	Service         ServiceAggregationKind
	Destination     DestinationAggregationKind
	Source          SourceAggregationKind
	TrimURL         URLAggregationKind
	ResponseCode    ResponseCodeAggregationKind
	NumURLPathParts int
	URLCharLimit    int
}

// Sets the default L7 Aggregation levels. By default, everything is allowed
// except for the Src/Dst details and the extra HTTP header fields.
func DefaultAggregationKind() AggregationKind {
	return AggregationKind{
		HTTPHeader:      HTTPHeaderInfoNone,
		HTTPMethod:      HTTPMethod,
		Service:         ServiceInfo,
		Destination:     DestinationInfo,
		Source:          SourceInfoNoPort,
		TrimURL:         FullURL,
		ResponseCode:    ResponseCode,
		NumURLPathParts: 5,
		URLCharLimit:    250,
	}
}

// Aggregator is responsible for creating, aggregating, and
// storing the aggregated L7 logs until they are exported.
type Aggregator struct {
	kind                 AggregationKind
	l7Store              map[L7Meta]L7Spec
	l7OverflowStore      map[L7Meta]L7Spec
	l7Mutex              sync.Mutex
	aggregationStartTime time.Time
	perNodeLimit         int
	numUnLoggedUpdates   int
}

// NewAggregator constructs an Aggregator
func NewAggregator() *Aggregator {
	return &Aggregator{
		kind:                 DefaultAggregationKind(),
		l7Store:              make(map[L7Meta]L7Spec),
		l7OverflowStore:      make(map[L7Meta]L7Spec),
		aggregationStartTime: time.Now(),
	}
}

func (a *Aggregator) AggregateOver(ak AggregationKind) *Aggregator {
	a.kind = ak
	return a
}

func (a *Aggregator) PerNodeLimit(l int) *Aggregator {
	a.perNodeLimit = l
	return a
}

func (a *Aggregator) FeedUpdate(update Update) error {
	isOverflow := update.Type == ""
	meta, spec, err := newMetaSpecFromUpdate(update, a.kind)
	if err != nil {
		return err
	}

	// Ensure that we cannot add or aggregate new logs into the store at
	// the same time that existing logs are being flushed out.
	a.l7Mutex.Lock()
	defer a.l7Mutex.Unlock()

	if _, ok := a.l7Store[meta]; ok {
		existing := a.l7Store[meta]
		existing.Merge(spec)
		a.l7Store[meta] = existing
	} else if _, ok := a.l7OverflowStore[meta]; ok {
		existing := a.l7OverflowStore[meta]
		existing.Merge(spec)
		a.l7OverflowStore[meta] = existing
	} else if (a.perNodeLimit == 0) || (len(a.l7Store) < a.perNodeLimit) {
		// Since we expect there to be too many L7 logs, trim out
		// overflow logs since we do not want to use up our log limit
		// to record them since they have less data. Overflow logs will
		// not have a type.
		if !isOverflow {
			a.l7Store[meta] = spec
		} else if len(a.l7OverflowStore) < a.perNodeLimit {
			a.l7OverflowStore[meta] = spec
		} else {
			a.numUnLoggedUpdates++
		}
	} else {
		a.numUnLoggedUpdates++
	}

	return nil
}

func (a *Aggregator) Get() []*L7Log {
	var l7Logs []*L7Log
	aggregationEndTime := time.Now()

	// Ensure that we can't add or aggregate new logs into the store at the
	// same time as existing logs are being flushed out.
	a.l7Mutex.Lock()
	defer a.l7Mutex.Unlock()

	for meta, spec := range a.l7Store {
		l7Data := L7Data{meta, spec}
		l7Logs = append(l7Logs, l7Data.ToL7Log(
			a.aggregationStartTime,
			aggregationEndTime,
		))
	}

	// If logs with real data (not overflow) do not reach the per node
	// limit, add any overflow logs until the per node limit is reached.
	if len(l7Logs) <= a.perNodeLimit {
		remainder := a.perNodeLimit - len(l7Logs)
		i := 0
		for meta, spec := range a.l7OverflowStore {
			if i >= remainder {
				a.numUnLoggedUpdates = a.numUnLoggedUpdates + len(a.l7OverflowStore) - i
				break
			}
			l7Data := L7Data{meta, spec}
			l7Logs = append(l7Logs, l7Data.ToL7Log(
				a.aggregationStartTime,
				aggregationEndTime,
			))
			i++
		}
	}

	if a.numUnLoggedUpdates > 0 {
		log.Warningf(
			"%v L7 logs were not logged, because of perNodeLimit being set to %v",
			a.numUnLoggedUpdates,
			a.perNodeLimit,
		)
		// Emit an Elastic log to alert about the un logged updates.  This log has no content
		// except for the time period and the number of updates that could not be fully
		// logged.
		excessLog := &L7Log{
			StartTime: a.aggregationStartTime.Unix(),
			EndTime:   aggregationEndTime.Unix(),
			Count:     a.numUnLoggedUpdates,
			Type:      L7LogTypeUnLogged, // Type is otherwise the protocol tcp, tls, http1.1 etc
		}
		l7Logs = append(l7Logs, excessLog)
	}

	a.l7Store = make(map[L7Meta]L7Spec)
	a.l7OverflowStore = make(map[L7Meta]L7Spec)
	a.aggregationStartTime = aggregationEndTime
	return l7Logs
}

func translateAggregationKind(aggStr string) (int, error) {
	val, ok := aggregationKindTypeMap[aggStr]
	if !ok {
		// Unrecognized aggregation level string provided.
		return val, fmt.Errorf("invalid aggregation kind provided: %s", aggStr)
	}
	return val, nil
}

func AggregationKindFromConfigParams(cfg *config.Config) AggregationKind {
	agg := DefaultAggregationKind()
	headerInfoLevel, err := translateAggregationKind(cfg.L7LogsFileAggregationHTTPHeaderInfo)
	if err != nil {
		log.Errorf("Unrecognized L7 aggregation parameter for header info: %s", cfg.L7LogsFileAggregationHTTPHeaderInfo)
	} else {
		agg.HTTPHeader = HTTPHeaderAggregationKind(headerInfoLevel)
	}
	methodLevel, err := translateAggregationKind(cfg.L7LogsFileAggregationHTTPMethod)
	if err != nil {
		log.Errorf("Unrecognized L7 aggregation parameter for method: %s", cfg.L7LogsFileAggregationHTTPMethod)
	} else {
		agg.HTTPMethod = HTTPMethodAggregationKind(methodLevel)
	}
	serviceLevel, err := translateAggregationKind(cfg.L7LogsFileAggregationServiceInfo)
	if err != nil {
		log.Errorf("Unrecognized L7 aggregation parameter for service info: %s", cfg.L7LogsFileAggregationServiceInfo)
	} else {
		agg.Service = ServiceAggregationKind(serviceLevel)
	}
	destLevel, err := translateAggregationKind(cfg.L7LogsFileAggregationDestinationInfo)
	if err != nil {
		log.Errorf("Unrecognized L7 aggregation parameter for destination info: %s", cfg.L7LogsFileAggregationDestinationInfo)
	} else {
		agg.Destination = DestinationAggregationKind(destLevel)
	}
	srcLevel, err := translateAggregationKind(cfg.L7LogsFileAggregationSourceInfo)
	if err != nil {
		log.Errorf("Unrecognized L7 aggregation parameter for source info: %s", cfg.L7LogsFileAggregationSourceInfo)
	} else {
		agg.Source = SourceAggregationKind(srcLevel)
	}
	rcLevel, err := translateAggregationKind(cfg.L7LogsFileAggregationResponseCode)
	if err != nil {
		log.Errorf("Unrecognized L7 aggregation parameter for response code: %s", cfg.L7LogsFileAggregationResponseCode)
	} else {
		agg.ResponseCode = ResponseCodeAggregationKind(rcLevel)
	}
	urlLevel, err := translateAggregationKind(cfg.L7LogsFileAggregationTrimURL)
	if err != nil {
		log.Errorf("Unrecognized L7 aggregation parameter for URL: %s", cfg.L7LogsFileAggregationTrimURL)
	} else {
		agg.TrimURL = URLAggregationKind(urlLevel)
	}
	agg.NumURLPathParts = cfg.L7LogsFileAggregationNumURLPath
	agg.URLCharLimit = cfg.L7LogsFileAggregationURLCharLimit

	return agg
}
