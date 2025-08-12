// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package index

import (
	"errors"
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

// l7LogsIndexHelper implements the Helper interface for l7 logs.
type l7LogsIndexHelper struct {
	singleIndex bool
}

func MultiIndexL7Logs() Helper {
	return l7LogsIndexHelper{}
}

func SingleIndexL7Logs() Helper {
	return l7LogsIndexHelper{
		singleIndex: true,
	}
}

// NewL7LogsConverter returns a Converter instance defined for l7 logs.
func NewL7LogsConverter() converter {
	return converter{atomToElastic: basicAtomToElastic, setOpTermToElastic: basicSetOpTermToElastic}
}

func (h l7LogsIndexHelper) BaseQuery(i bapi.ClusterInfo, params v1.Params) (*elastic.BoolQuery, error) {
	return defaultBaseQuery(i, h.singleIndex, params)
}

func (h l7LogsIndexHelper) NewSelectorQuery(selector string) (elastic.Query, error) {
	q, err := query.ParseQuery(selector)
	if err != nil {
		return nil, &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Err:    err,
			Msg:    fmt.Sprintf("Invalid selector (%s) in request: %v", selector, err),
		}
	} else if err := query.Validate(q, query.IsValidL7LogsAtom); err != nil {
		return nil, &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Err:    err,
			Msg:    fmt.Sprintf("Invalid selector (%s) in request: %v", selector, err),
		}
	}
	converter := NewL7LogsConverter()
	return JsonObjectElasticQuery(converter.Convert(q)), nil
}

func (h l7LogsIndexHelper) NewRBACQuery(
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
				case "hostendpoints":
					// HostEndpoints are neither tiered nor namespaced, and AuthorizationReview does not
					// determine RBAC at the instance level, so must be able to list all HostEndpoints.
					should = append(should,
						elastic.NewTermQuery("src_type", "hep"),
						elastic.NewTermQuery("dest_type", "hep"),
					)
				case "networksets":
					if rg.Namespace == "" {
						// Can list all NetworkSets. Check type is "ns" and namespace is not "-" (which would
						// be a GlobalNetworkSet).
						should = append(should,
							elastic.NewBoolQuery().Must(
								elastic.NewTermQuery("src_type", "ns"),
							).MustNot(
								elastic.NewTermQuery("src_namespace", "-"),
							),
							elastic.NewBoolQuery().Must(
								elastic.NewTermQuery("dest_type", "ns"),
							).MustNot(
								elastic.NewTermQuery("dest_namespace", "-"),
							),
						)
					} else {
						// Can list NetworkSets in a specific namespace. Check type is "ns" and namespace
						// matches.
						should = append(should,
							elastic.NewBoolQuery().Must(
								elastic.NewTermQuery("src_type", "ns"),
								elastic.NewTermQuery("src_namespace", rg.Namespace),
							),
							elastic.NewBoolQuery().Must(
								elastic.NewTermQuery("dest_type", "ns"),
								elastic.NewTermQuery("dest_namespace", rg.Namespace),
							),
						)
					}
				case "globalnetworksets":
					// GlobalNetworkSets are neither tiered nor namespaced, and AuthorizationReview does not
					// determine RBAC at the instance level, so must be able to list all GlobalNetworkSets.
					// Check type is "ns" and namespace is "-".
					should = append(should,
						elastic.NewBoolQuery().Must(
							elastic.NewTermQuery("src_type", "ns"),
							elastic.NewTermQuery("src_namespace", "-"),
						),
						elastic.NewBoolQuery().Must(
							elastic.NewTermQuery("dest_type", "ns"),
							elastic.NewTermQuery("dest_namespace", "-"),
						),
					)
				case "pods":
					if rg.Namespace == "" {
						// Can list all Pods. Check type is "wep".
						should = append(should,
							elastic.NewTermQuery("src_type", "wep"),
							elastic.NewTermQuery("dest_type", "wep"),
						)
					} else {
						// Can list Pods in a specific namespace. Check type is "wep" and namespace matches.
						should = append(should,
							elastic.NewBoolQuery().Must(
								elastic.NewTermQuery("src_type", "wep"),
								elastic.NewTermQuery("src_namespace", rg.Namespace),
							),
							elastic.NewBoolQuery().Must(
								elastic.NewTermQuery("dest_type", "wep"),
								elastic.NewTermQuery("dest_namespace", rg.Namespace),
							),
						)
					}
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
	}

	return elastic.NewBoolQuery().Should(should...), nil
}

func (h l7LogsIndexHelper) NewTimeRangeQuery(r *lmav1.TimeRange) elastic.Query {
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
		fromStr := strconv.FormatInt(r.From.Unix(), 10)
		toStr := strconv.FormatInt(r.To.Unix(), 10)
		return timeRangeQuery.Gt(fromStr).Lte(toStr)
	}
}

func (h l7LogsIndexHelper) GetTimeField() string {
	return "end_time"
}
