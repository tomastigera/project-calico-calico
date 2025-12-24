// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

// PolicyActivityIndexHelper implements the Helper interface for policy activity logs.
type PolicyActivityIndexHelper struct {
	singleIndex bool
}

// MultiIndexPolicyActivity returns an instance of the policy activity logs index helper.
func MultiIndexPolicyActivity() Helper {
	return PolicyActivityIndexHelper{}
}

// SingleIndexPolicyActivity returns an instance of the policy activity logs index helper.
func SingleIndexPolicyActivity() Helper {
	return PolicyActivityIndexHelper{singleIndex: true}
}

// NewPolicyActivityConverter returns a Converter instance defined for policy activity logs.
func NewPolicyActivityConverter() converter {
	return converter{atomToElastic: PolicyActivityAtomToElastic, setOpTermToElastic: PolicyActivitySetOpTermToElastic}
}

// PolicyActivityAtomToElastic returns policy activity log atom as an elastic JsonObject.
func PolicyActivityAtomToElastic(a *query.Atom) JsonObject {
	return PolicyActivityQueryObjectToElastic(a, a.Key, basicAtomToElastic)
}

// PolicyActivitySetOpTermToElastic returns policy activity log setOpTerm as an elastic JsonObject.
func PolicyActivitySetOpTermToElastic(t *query.SetOpTerm) JsonObject {
	return PolicyActivityQueryObjectToElastic(t, t.Key, basicSetOpTermToElastic)
}

// PolicyActivityQueryObjectToElastic returns policy activity log queryObject object as an elastic JsonObject.
func PolicyActivityQueryObjectToElastic[E queryObject](o E, key string, basicConverter converterFunc[E]) JsonObject {
	switch key {
	case "policy", "rule", "last_evaluated":
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

func (h PolicyActivityIndexHelper) BaseQuery(i bapi.ClusterInfo, params v1.Params) (*elastic.BoolQuery, error) {
	return defaultBaseQuery(i, h.singleIndex, params)
}

func (h PolicyActivityIndexHelper) NewSelectorQuery(selector string) (elastic.Query, error) {
	q, err := query.ParseQuery(selector)
	if err != nil {
		return nil, &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Err:    err,
			Msg:    fmt.Sprintf("Invalid selector %q in request: %v", selector, err),
		}
	}
	if err := query.Validate(q, query.IsValidPolicyActivityAtom); err != nil {
		return nil, &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Err:    err,
			Msg:    fmt.Sprintf("Invalid selector %q in request: %v", selector, err),
		}
	}
	converter := NewPolicyActivityConverter()
	return JsonObjectElasticQuery(converter.Convert(q)), nil
}

func (h PolicyActivityIndexHelper) NewRBACQuery(
	resources []apiv3.AuthorizedResourceVerbs,
) (elastic.Query, error) {
	return nil, fmt.Errorf("not implemented")
}

func (h PolicyActivityIndexHelper) NewTimeRangeQuery(r *lmav1.TimeRange) elastic.Query {
	timeField := GetTimeFieldForQuery(h, r)
	timeRangeQuery := elastic.NewRangeQuery(timeField)
	switch timeField {
	case "generated_time":
		return processGeneratedField(r, timeRangeQuery)
	default:
		// Any query that targets the default field assumes we have defaults for both start and end of the interval.
		// This query will target any value that is higher that the start, but lower or
		// equal to the end of the interval.
		return timeRangeQuery.Gt(r.From).Lte(r.To)
	}
}

func (h PolicyActivityIndexHelper) GetTimeField() string {
	return "last_evaluated"
}
