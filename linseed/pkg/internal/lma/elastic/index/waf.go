// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package index

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/olivere/elastic/v7"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/validator/v3/query"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/projectcalico/calico/lma/pkg/httputils"
)

// wafLogsIndexHelper implements the Helper interface for waf logs.
type wafLogsIndexHelper struct {
	singleIndex bool
}

// MultiIndexWAFLogs returns an instance of the waf logs index helper.
func MultiIndexWAFLogs() Helper {
	return wafLogsIndexHelper{}
}

// SingleIndexWAFLogs returns an instance of the waf logs index helper.
func SingleIndexWAFLogs() Helper {
	return wafLogsIndexHelper{singleIndex: true}
}

// NewWAFLogsConverter returns a Converter instance defined for waf logs.
func NewWAFLogsConverter() converter {
	return converter{wafAtomToElastic, wafSetOpTermToElastic}
}

// wafAtomToElastic returns a waf log atom as an elastic JsonObject.
func wafAtomToElastic(a *query.Atom) JsonObject {
	return wafQueryObjectToElastic(a, a.Key, basicAtomToElastic)
}

// wafSetOpTermToElastic returns a waf log setOpTerm as an elastic JsonObject.
func wafSetOpTermToElastic(t *query.SetOpTerm) JsonObject {
	return wafQueryObjectToElastic(t, t.Key, basicSetOpTermToElastic)
}

// wafQueryObjectToElastic returns a waf log queryObject object as an elastic JsonObject.
func wafQueryObjectToElastic[E queryObject](o E, key string, basicConverter converterFunc[E]) JsonObject {
	switch key {
	case "rules.id", "rules.message", "rules.severity", "rules.file", "rules.disruptive", "rules.line":

		path := key[:strings.Index(key, ".")]
		return JsonObject{
			"nested": JsonObject{
				"path":  path,
				"query": basicConverter(o),
			},
		}
	}

	return basicConverter(o)
}

func (h wafLogsIndexHelper) BaseQuery(i bapi.ClusterInfo, params v1.Params) (*elastic.BoolQuery, error) {
	return defaultBaseQuery(i, h.singleIndex, params)
}

func (h wafLogsIndexHelper) NewSelectorQuery(selector string) (elastic.Query, error) {
	q, err := query.ParseQuery(selector)
	if err != nil {
		return nil, &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Err:    err,
			Msg:    fmt.Sprintf("Invalid selector (%s) in request: %v", selector, err),
		}
	} else if err := query.Validate(q, query.IsValidWAFAtom); err != nil {
		return nil, &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Err:    err,
			Msg:    fmt.Sprintf("Invalid selector (%s) in request: %v", selector, err),
		}
	}
	converter := NewWAFLogsConverter()
	return JsonObjectElasticQuery(converter.Convert(q)), nil
}

func (h wafLogsIndexHelper) NewRBACQuery(
	resources []apiv3.AuthorizedResourceVerbs,
) (elastic.Query, error) {
	return nil, fmt.Errorf("not implemented")
}

func (h wafLogsIndexHelper) NewTimeRangeQuery(r *lmav1.TimeRange) elastic.Query {
	timeField := GetTimeFieldForQuery(h, r)
	timeRangeQuery := elastic.NewRangeQuery(timeField)
	switch timeField {
	case "generated_time":
		return processGeneratedField(r, timeRangeQuery)
	default:
		// Any query that targets the default field assumes we have defaults for both start and end of the interval.
		// This query will target any value that is higher that the start, but lower or
		// equal to the end of the interval
		return timeRangeQuery.Gt(r.From).Lte(r.To)
	}
}

func (h wafLogsIndexHelper) GetTimeField() string {
	return "@timestamp"
}
