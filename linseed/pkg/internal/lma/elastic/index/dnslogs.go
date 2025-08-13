// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package index

import (
	"errors"
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

// dnsLogsIndexHelper implements the Helper interface for dns logs.
type dnsLogsIndexHelper struct {
	singleIndex bool
}

func MultiIndexDNSLogs() Helper {
	return dnsLogsIndexHelper{}
}

func SingleIndexDNSLogs() Helper {
	return dnsLogsIndexHelper{singleIndex: true}
}

func (h dnsLogsIndexHelper) BaseQuery(i bapi.ClusterInfo, params v1.Params) (*elastic.BoolQuery, error) {
	return defaultBaseQuery(i, h.singleIndex, params)
}

// NewDnsLogsConverter returns a Converter instance defined for dns logs.
func NewDnsLogsConverter() converter {
	return converter{atomToElastic: dnsAtomToElastic, setOpTermToElastic: dnsSetOpTermToElastic}
}

// dnsAtomToElastic returns a dns log atom as an elastic JsonObject.
func dnsAtomToElastic(a *query.Atom) JsonObject {
	return dnsQueryObjectToElastic(a, a.Key, basicAtomToElastic)
}

// dnsSetOpTermToElastic returns a flow log setOpTerm as an elastic JsonObject.
func dnsSetOpTermToElastic(t *query.SetOpTerm) JsonObject {
	return dnsQueryObjectToElastic(t, t.Key, basicSetOpTermToElastic)
}

// dnsQueryObjectToElastic returns a flow log queryObject object as an elastic JsonObject.
func dnsQueryObjectToElastic[E queryObject](o E, key string, basicConverter converterFunc[E]) JsonObject {
	switch key {
	case "servers.name", "servers.name_aggr", "servers.namespace", "servers.ip",
		"rrsets.name", "rrsets.type", "rrsets.class", "rrsets.rdata":

		path := key[:strings.Index(key, ".")]
		return JsonObject{
			"nested": JsonObject{
				"path":  path,
				"query": basicConverter(o),
			},
		}
	}

	switch {
	case strings.HasPrefix(key, "servers.labels."):
		return JsonObject{
			"nested": JsonObject{
				"path":  "servers",
				"query": basicConverter(o),
			},
		}
	case strings.HasPrefix(key, "client_labels."):
		return basicConverter(o)
	default:
		return basicConverter(o)
	}
}

// Helper.

func (h dnsLogsIndexHelper) NewSelectorQuery(selector string) (elastic.Query, error) {
	q, err := query.ParseQuery(selector)
	if err != nil {
		return nil, &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Err:    err,
			Msg:    fmt.Sprintf("Invalid selector (%s) in request: %v", selector, err),
		}
	} else if err := query.Validate(q, query.IsValidDNSAtom); err != nil {
		return nil, &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Err:    err,
			Msg:    fmt.Sprintf("Invalid selector (%s) in request: %v", selector, err),
		}
	}
	converter := NewDnsLogsConverter()
	return JsonObjectElasticQuery(converter.Convert(q)), nil
}

func (h dnsLogsIndexHelper) NewRBACQuery(
	resources []apiv3.AuthorizedResourceVerbs,
) (elastic.Query, error) {
	// Convert the permissions into a query that each flow must satisfy - essentially a source or
	// destination must be listable by the user to be included in the response.
	var should []elastic.Query
	for _, r := range resources {
		for _, v := range r.Verbs {
			if v.Verb != "list" {
				// Only interested in the list verbs.
				continue
			}
			for _, rg := range v.ResourceGroups {
				switch r.Resource {
				case "pods":
					if rg.Namespace == "" {
						// User can list all namespaces.
						return nil, nil
					}
					// Can list Pods in a specific namespace.
					should = append(should,
						elastic.NewTermQuery("client_namespace", rg.Namespace),
					)
				}
			}
			break
		}
	}

	if len(should) == 0 {
		return nil, &httputils.HttpStatusError{
			Status: http.StatusForbidden,
			Msg:    "Forbidden",
			Err:    errors.New("user is not permitted to access any documents for this index"),
		}
	} else if len(should) == 1 {
		return should[0], nil
	}

	return elastic.NewBoolQuery().Should(should...), nil
}

func (h dnsLogsIndexHelper) NewTimeRangeQuery(r *lmav1.TimeRange) elastic.Query {
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

func (h dnsLogsIndexHelper) GetTimeField() string {
	return "end_time"
}
