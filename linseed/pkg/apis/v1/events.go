// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package v1

import (
	"encoding/json"
	"fmt"
	"time"
)

// EventParams define querying parameters to retrieve events
type EventParams struct {
	QueryParams        `json:",inline" validate:"required"`
	QuerySortParams    `json:",inline"`
	LogSelectionParams `json:",inline"`

	ID string `json:"id,omitempty"`
}

type TimestampOrDate struct {
	intVal  *int64
	timeVal *time.Time
}

// EventStatistics capture the result of event statistics requests.
// It contains the values that are requested by EventStatisticsParams.
// Event statistics are designed to be modular to enable a client (e.g. UI)
// to either query everything it needs in one request (and render a full page
// of statistics with the result) or use multiple smaller requests
// (one per widget/table to display).
// Smaller requests can also be used in different use cases (e.g. populate list
// of distinct values for a filter).
type EventStatistics struct {
	FieldValues        *FieldValues                 `json:"field_values,omitempty"`
	SeverityHistograms map[string][]HistogramBucket `json:"severity_histograms,omitempty"`
}

// EventStatisticsParams is used to define required statistics for a request.
// For an ES backend, this would correspond to various aggregations parameters/queries.
type EventStatisticsParams struct {
	// EventParams inherits all the normal events selection parameters.
	// However Sort by time is not supported for statistics.
	// Used to specify the subset of events we want to consider when computing statistics.
	EventParams `json:",inline"`

	// FieldValues defines the event fields we want to compute field values statistics for.
	FieldValues *FieldValuesParam `json:"field_values,omitempty"`

	// SeverityHistograms defines parameters of the severity histograms we want to compute (name and selector for severity range).
	SeverityHistograms []SeverityHistogramParam `json:"severity_histograms,omitempty"`
}

// FieldValuesParam contains optional values we want to compute FieldValues for.
// These parameters are captured in FieldValueParam.
type FieldValuesParam struct {
	TypeValues            *FieldValueParam `json:"type,omitempty"`
	NameValues            *FieldValueParam `json:"name,omitempty"`
	SeverityValues        *FieldValueParam `json:"severity,omitempty"`
	SourceNamespaceValues *FieldValueParam `json:"source_namespace,omitempty"`
	DestNamespaceValues   *FieldValueParam `json:"dest_namespace,omitempty"`
	SourceNameValues      *FieldValueParam `json:"source_name,omitempty"`
	DestNameValues        *FieldValueParam `json:"dest_name,omitempty"`
	AttackVectorValues    *FieldValueParam `json:"attack_vector,omitempty"`
	MitreTacticValues     *FieldValueParam `json:"mitre_tactic,omitempty"`
	MitreIDsValues        *FieldValueParam `json:"mitre_ids,omitempty"`
}

// FieldValueParam described what processing/aggregation we want to perform for a given field.
// If Count is true, we will list the number of distinct values and count the number of matching events.
// GroupBySeverity is true, The count will be broken down per distinct severity values.
type FieldValueParam struct {
	Count           bool `json:"count,omitempty"`
	GroupBySeverity bool `json:"group_by_severity,omitempty"`
}

// FieldValues contains results of processing/aggregation that was defined by FieldValuesParam
// For each field, we provide a list of FieldValue.
type FieldValues struct {
	TypeValues            []FieldValue    `json:"type,omitempty"`
	NameValues            []FieldValue    `json:"name,omitempty"`
	SeverityValues        []SeverityValue `json:"severity,omitempty"`
	SourceNamespaceValues []FieldValue    `json:"source_namespace,omitempty"`
	DestNamespaceValues   []FieldValue    `json:"dest_namespace,omitempty"`
	SourceNameValues      []FieldValue    `json:"source_name,omitempty"`
	DestNameValues        []FieldValue    `json:"dest_name,omitempty"`
	AttackVectorValues    []FieldValue    `json:"attack_vector,omitempty"`
	MitreTacticValues     []FieldValue    `json:"mitre_tactic,omitempty"`
	MitreIDsValues        []FieldValue    `json:"mitre_ids,omitempty"`
}

// FieldValue captures a distinct unique value for a given field (in Value) and the number of
// matching events (in Count). If requested, BySeverity contains a list of SeverityValue(s).
type FieldValue struct {
	Value      string          `json:"value"`
	Count      int64           `json:"count"`
	BySeverity []SeverityValue `json:"by_severity,omitempty"`
}

// SeverityValue captures a distinct unique severity value for a subset of events (in Value) and the number of
// matching events (in Count).
type SeverityValue struct {
	Value int   `json:"value"`
	Count int64 `json:"count"`
}

// SeverityHistogramParams define the required severity histograms we want to include in the statistics.
// This is typically used to compute a stacked-histogram of number of events per day
// grouped by severity range (e.g. critical, high, low/medium) where each range would be
// one histogram, defined by a SeverityHistogramParam.
type SeverityHistogramParam struct {
	// Name of the SeverityHistogramParam being computed (e.g. "high-severity").
	// Each SeverityHistogramParam will result in []HistogramBucket.
	Name string `json:"name"`
	// Selector is an optional parameter used to define a selector that's combined with overall
	// LogSelectionParams.Selector value (logical AND) in order to specify a subset of events
	// that should be considered when computing the desired DateHistogram as part of the statistics request.
	// A typical example would be "severity > 0 AND severity <= 70" in order to isolate the range
	// required for a SeverityHistogram that will be part of a stacked-histogram with other severity ranges.
	Selector string `json:"selector,omitempty"`
}

// HistogramBucket represents the data for a single bar of a SeverityHistogram.
// Time capture the date as a unix timestamp in milliseconds and Value the number of matching events for that day.
type HistogramBucket struct {
	Time  float64 `json:"time"`
	Value int64   `json:"value"`
}

// ISO8601Format is the format Anomaly Detection
// alerts use for field "Time". Example: 2023-04-28T19:38:14+00:00
// Anomaly detection makes use of `isoformat` method available in python libraries.
// This format is similar to RFC3339, but it has some small differences.
// RFC 3339 uses HH:mm:ssZ to mark a timestamp is on GMT timezone,
// while this format will render this infomation like +00:00
const ISO8601Format = "2006-01-02T15:04:05-07:00"

type IPGeoInfo struct {
	CityName    string `json:"city_name,omitempty"`
	CountryName string `json:"country_name,omitempty"`
	ISO         string `json:"iso,omitempty"`
	ASN         string `json:"asn,omitempty"`
}

type Event struct {
	ID              string          `json:"id"`
	Time            TimestampOrDate `json:"time" validate:"required"`
	Description     string          `json:"description" validate:"required"`
	Origin          string          `json:"origin" validate:"required"`
	Severity        int             `json:"severity" validate:"required"`
	Type            string          `json:"type" validate:"required"`
	DestIP          *string         `json:"dest_ip,omitempty"`
	DestName        string          `json:"dest_name,omitempty"`
	DestNameAggr    string          `json:"dest_name_aggr,omitempty"`
	DestNamespace   string          `json:"dest_namespace,omitempty"`
	DestPort        *int64          `json:"dest_port,omitempty"`
	Protocol        string          `json:"protocol,omitempty"`
	Dismissed       bool            `json:"dismissed,omitempty"`
	Host            string          `json:"host,omitempty"`
	SourceIP        *string         `json:"source_ip,omitempty"`
	SourceName      string          `json:"source_name,omitempty"`
	SourceNameAggr  string          `json:"source_name_aggr,omitempty"`
	SourceNamespace string          `json:"source_namespace,omitempty"`
	SourcePort      *int64          `json:"source_port,omitempty"`
	Name            string          `json:"name,omitempty"`
	AttackVector    string          `json:"attack_vector,omitempty"`
	MitreTactic     string          `json:"mitre_tactic,omitempty"`
	MitreIDs        *[]string       `json:"mitre_ids,omitempty"`
	Mitigations     *[]string       `json:"mitigations,omitempty"`
	Record          any             `json:"record,omitempty"`
	GeoInfo         IPGeoInfo       `json:"geo_info"`

	// Cluster is populated by linseed from the request context.
	Cluster string `json:"cluster,omitempty"`
	// GeneratedTime is populated by Linseed when ingesting data to Elasticsearch
	GeneratedTime *time.Time `json:"generated_time,omitempty"`
}

// Events can take records of numerous forms. GetRecord extracts the record
// on the event into the given object.
func (e *Event) GetRecord(into any) error {
	bs, err := json.Marshal(e.Record)
	if err != nil {
		return err
	}
	return json.Unmarshal(bs, into)
}

// RawRecordData is a generic record with arbitrary fields.
type RawRecordData map[string]any

type EventRecord struct {
	// Structured fields
	ResponseObjectKind string `json:"responseObject.kind,omitempty"`
	ObjectRefResource  string `json:"objectRef.resource,omitempty"`
	ObjectRefNamespace string `json:"objectRef.namespace,omitempty"`
	ObjectRefName      string `json:"objectRef.name,omitempty"`
	ClientNamespace    string `json:"client_namespace,omitempty"`
	ClientName         string `json:"client_name,omitempty"`
	ClientNameAggr     string `json:"client_name_aggr,omitempty"`
	SourceType         string `json:"source_type,omitempty"`
	SourceNamespace    string `json:"source_namespace,omitempty"`
	SourceNameAggr     string `json:"source_name_aggr,omitempty"`
	SourceName         string `json:"source_name,omitempty"`
	DestType           string `json:"dest_type,omitempty"`
	DestNamespace      string `json:"dest_namespace,omitempty"`
	DestNameAggr       string `json:"dest_name_aggr,omitempty"`
	DestName           string `json:"dest_name,omitempty"`
	DestPort           int    `json:"dest_port,omitempty"`
	Protocol           string `json:"proto,omitempty"`
}

type SuspiciousDomainEventRecord struct {
	DNSLogID          string   `json:"dns_log_id"`
	Feeds             []string `json:"feeds,omitempty"`
	SuspiciousDomains []string `json:"suspicious_domains"`
}

type SuspiciousIPEventRecord struct {
	FlowAction       string   `json:"flow_action"`
	FlowLogID        string   `json:"flow_log_id"`
	Protocol         string   `json:"protocol"`
	Feeds            []string `json:"feeds,omitempty"`
	SuspiciousPrefix *string  `json:"suspicious_prefix"`
}

type DPIRecord struct {
	SnortSignatureID       string `json:"snort_signature_id"`
	SnortSignatureRevision string `json:"snort_signature_revision"`
	SnortAlert             string `json:"snort_alert"`
}

// NewEventTimestamp will create a new TimestampOrDate
// that has only the timestamp field populated with a value
// that represents unix time in seconds
func NewEventTimestamp(val int64) TimestampOrDate {
	return TimestampOrDate{
		intVal: &val,
	}
}

// NewEventDate will create a new TimestampOrDate
// that has only the date field populated with a value
// that represents a time in RFC ISO format
func NewEventDate(val time.Time) TimestampOrDate {
	return TimestampOrDate{
		timeVal: &val,
	}
}

func (t *TimestampOrDate) UnmarshalJSON(data []byte) error {
	if t == nil {
		return fmt.Errorf("cannot unmarshal nil value from JSON")
	}

	if len(data) == 0 {
		return nil
	}

	if data[0] == '"' {
		return json.Unmarshal(data, &t.timeVal)
	}

	return json.Unmarshal(data, &t.intVal)
}

func (t TimestampOrDate) MarshalJSON() ([]byte, error) {
	if t.intVal != nil && t.timeVal != nil {
		return nil, fmt.Errorf("time should either be as unix timestamp or ISO8601 time format")
	}

	if t.intVal != nil {
		return json.Marshal(*t.intVal)
	}

	if t.timeVal != nil {
		return json.Marshal(t.timeVal.Format(ISO8601Format))
	}

	if t.timeVal == nil && t.intVal == nil {
		zero := 0
		return json.Marshal(&zero)
	}

	return nil, nil
}

func (t *TimestampOrDate) GetTime() time.Time {
	if t.intVal != nil {
		return time.Unix(*t.intVal, 0)
	}

	if t.timeVal != nil {
		return *t.timeVal
	}

	return time.Time{}
}
