// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package index

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/olivere/elastic/v7"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/validator/v3/query"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/projectcalico/calico/lma/pkg/httputils"
)

// alertsIndexHelper implements the Helper interface for events.
type alertsIndexHelper struct {
	singleIndex bool
}

func MultiIndexAlerts() Helper {
	return alertsIndexHelper{}
}

func SingleIndexAlerts() Helper {
	return alertsIndexHelper{singleIndex: true}
}

// NewAlertsConverter returns a Converter instance defined for alerts.
func NewAlertsConverter() converter {
	return converter{basicAtomToElastic, basicSetOpTermToElastic}
}

// Helper.

func (h alertsIndexHelper) BaseQuery(i bapi.ClusterInfo, params v1.Params) (*elastic.BoolQuery, error) {
	return defaultBaseQuery(i, h.singleIndex, params)
}

func (h alertsIndexHelper) NewSelectorQuery(selector string) (elastic.Query, error) {
	q, err := query.ParseQuery(selector)
	if err != nil {
		return nil, &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Err:    err,
			Msg:    fmt.Sprintf("Invalid selector (%s) in request: %v", selector, err),
		}
	} else if err := query.Validate(q, query.IsValidEventsKeysAtom); err != nil {
		return nil, &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Err:    err,
			Msg:    fmt.Sprintf("Invalid selector (%s) in request: %v", selector, err),
		}
	}
	converter := NewAlertsConverter()
	return JsonObjectElasticQuery(converter.Convert(q)), nil
}

func (h alertsIndexHelper) NewRBACQuery(resources []apiv3.AuthorizedResourceVerbs) (elastic.Query, error) {
	return nil, nil
}

func (h alertsIndexHelper) NewTimeRangeQuery(r *lmav1.TimeRange) elastic.Query {
	timeField := GetTimeFieldForQuery(h, r)
	timeRangeQuery := elastic.NewRangeQuery(timeField)
	switch timeField {
	case "generated_time":
		return processGeneratedField(r, timeRangeQuery)
	default:
		// Any query that targets the default field requires further processing
		// and assumes we have defaults for both start and end of the interval.
		// This query will target any value that is higher that the start, but lower or
		// equal to the end of the interval
		from := strconv.FormatInt(r.From.Unix(), 10)
		to := strconv.FormatInt(r.To.Unix(), 10)
		return timeRangeQuery.Gt(from).Lte(to)
	}
}

func (h alertsIndexHelper) GetTimeField() string {
	return "time"
}
