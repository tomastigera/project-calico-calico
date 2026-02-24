// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package v1

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lma/pkg/httputils"
	"github.com/projectcalico/calico/lma/pkg/timeutils"
)

type TimeField string

const (
	FieldDefault       TimeField = ""
	FieldStartTime     TimeField = "start_time"
	FieldGeneratedTime TimeField = "generated_time"
)

type TimeRange struct {
	// The from->to time ranges parsed from the request.
	From time.Time `json:"from"`
	To   time.Time `json:"to"`

	// The time field to match against.  When this field is not specified, the chosen time field
	// is as determined by the "query helper" for each index, on a per-index basis.
	Field TimeField `json:"field,omitempty"`

	// If the from and to are relative to "now", then the now time is also filled in - this allows relative times
	// to be reverse engineered (useful for the cache which keeps data for relative times updated in the background).
	Now *time.Time `json:"-"`
}

type timeRangeInternal struct {
	From  *string   `json:"from"`
	To    *string   `json:"to"`
	Field TimeField `json:"field,omitempty"`
}

// UnmarshalJSON implements the unmarshalling interface for JSON.
func (t *TimeRange) UnmarshalJSON(b []byte) error {
	var err error

	// Just extract the timestamp and kind fields from the blob.
	s := new(timeRangeInternal)
	if err = json.Unmarshal(b, s); err != nil {
		log.WithError(err).Debug("Unable to unmarshal time")
		return err
	}

	if s.From == nil && s.To == nil {
		return httputils.NewHttpStatusErrorBadRequest(
			"Request body contains an invalid value for the time range: missing `to` and `from` fields", nil,
		)
	}

	if s.From != nil && strings.TrimSpace(*s.From) == "" {
		return httputils.NewHttpStatusErrorBadRequest(
			"Request body contains an invalid value for the time range: missing `from` field", nil,
		)
	}
	if s.To != nil && strings.TrimSpace(*s.To) == "" {
		return httputils.NewHttpStatusErrorBadRequest(
			"Request body contains an invalid value for the time range: missing `to` field", nil,
		)
	}

	now := time.Now().UTC()
	if from, fromQp, err := timeutils.ParseTime(now, s.From); err != nil {
		log.WithError(err).Debug("Unable to parse 'from' time")
		return httputils.NewHttpStatusErrorBadRequest(
			fmt.Sprintf("Request body contains an invalid value for the time range 'from' field: %s", *s.From), err,
		)
	} else if to, toQp, err := timeutils.ParseTime(now, s.To); err != nil {
		return httputils.NewHttpStatusErrorBadRequest(
			fmt.Sprintf("Request body contains an invalid value for the time range 'to' field: %s", *s.To), err,
		)
	} else if isstring(fromQp) != isstring(toQp) {
		log.Debug("time range is specified as a mixture of explicit time and relative time")
		return httputils.NewHttpStatusErrorBadRequest(
			"Request body contains an invalid time range: values must either both be explicit times or both be relative to now", nil,
		)
	} else if from != nil && to != nil && from.After(*to) {
		log.Debug("From is after To")
		return httputils.NewHttpStatusErrorBadRequest(
			fmt.Sprintf("Request body contains an invalid time range: from (%s) is after to (%s)", *s.From, *s.To), nil,
		)
	} else {
		if from != nil {
			t.From = *from
		}
		if to != nil {
			t.To = *to
		}

		if isstring(fromQp) {
			// Since these times are relative to now, also store the now time.
			t.Now = &now
		}
	}

	switch s.Field {
	case FieldDefault, FieldGeneratedTime, FieldStartTime:
		t.Field = s.Field
	default:
		return httputils.NewHttpStatusErrorBadRequest(
			fmt.Sprintf("Request body contains an invalid time range: unsupported time field (%s)", s.Field), nil,
		)
	}

	return nil
}

// MarshalJSON implements the marshalling interface for JSON. We need to implement this explicitly because the default
// implementation doesn't honor the "inline" directive when the parameter is an interface type.
func (t TimeRange) MarshalJSON() ([]byte, error) {
	// Just extract the timestamp and kind fields from the blob.
	from := t.From.UTC().Format(time.RFC3339)
	to := t.To.UTC().Format(time.RFC3339)
	s := timeRangeInternal{
		From:  &from,
		To:    &to,
		Field: t.Field,
	}
	return json.Marshal(s)
}

func (t TimeRange) String() string {
	tr := fmt.Sprintf("%s -> %s", t.From.UTC().Format(time.RFC3339), t.To.UTC().Format(time.RFC3339))
	if t.Field != "" {
		return string(t.Field) + ": " + tr
	}
	return tr
}

func (t TimeRange) Duration() time.Duration {
	return t.To.Sub(t.From)
}

func (t TimeRange) InRange(t1 time.Time) bool {
	//nolint:staticcheck // Ignore QF1001: could apply De Morgan's law
	return !(t1.Before(t.From) || t1.After(t.To))
}

func (t TimeRange) Overlaps(from, to time.Time) bool {
	//nolint:staticcheck // Ignore QF1001: could apply De Morgan's law
	return !(to.Before(t.From) || from.After(t.To))
}

func isstring(a any) bool {
	_, ok := a.(string)
	return ok
}
