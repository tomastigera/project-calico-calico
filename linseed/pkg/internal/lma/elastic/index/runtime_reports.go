// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package index

import (
	"fmt"
	"net/http"

	"github.com/olivere/elastic/v7"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/validator/v3/query"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/projectcalico/calico/lma/pkg/httputils"
)

// runtimeReportsIndexHelper implements the Helper interface.
type runtimeReportsIndexHelper struct {
	singleIndex bool
}

func MultiIndexRuntimeReports() Helper {
	return runtimeReportsIndexHelper{}
}

func SingleIndexRuntimeReports() Helper {
	return runtimeReportsIndexHelper{
		singleIndex: true,
	}
}

func (h runtimeReportsIndexHelper) BaseQuery(i bapi.ClusterInfo, params v1.Params) (*elastic.BoolQuery, error) {
	return defaultBaseQuery(i, h.singleIndex, params)
}

func (h runtimeReportsIndexHelper) NewSelectorQuery(selector string) (elastic.Query, error) {
	q, err := query.ParseQuery(selector)
	if err != nil {
		return nil, &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Err:    err,
			Msg:    fmt.Sprintf("Invalid selector (%s) in request: %v", selector, err),
		}
	} else if err := query.Validate(q, IsValidRuntimeAtom); err != nil {
		return nil, &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Err:    err,
			Msg:    fmt.Sprintf("Invalid selector (%s) in request: %v", selector, err),
		}
	}
	converter := converter{basicAtomToElastic, basicSetOpTermToElastic}
	return JsonObjectElasticQuery(converter.Convert(q)), nil
}

func (h runtimeReportsIndexHelper) NewRBACQuery(resources []apiv3.AuthorizedResourceVerbs) (elastic.Query, error) {
	return nil, fmt.Errorf("not implemented")
}

func (h runtimeReportsIndexHelper) NewTimeRangeQuery(r *lmav1.TimeRange) elastic.Query {
	timeField := GetTimeFieldForQuery(h, r)
	timeRangeQuery := elastic.NewRangeQuery(timeField)
	switch timeField {
	case "generated_time":
		return processGeneratedField(r, timeRangeQuery)
	default:
		return nil
	}
}

func (h runtimeReportsIndexHelper) GetTimeField() string {
	return ""
}

func IsValidRuntimeAtom(a *query.Atom) error {
	validationMap := map[string]query.Validator{
		"count":                       query.PositiveIntValidator,
		"type":                        query.NullValidator,
		"pod.namespace":               query.DomainValidator,
		"pod.name":                    query.DomainValidator,
		"pod.name_aggr":               query.DomainValidator,
		"pod.container_name":          query.NullValidator,
		"pod.ready":                   query.NullValidator,
		"file.path":                   query.NullValidator,
		"file.host_path":              query.NullValidator,
		"process_start.invocation":    query.NullValidator,
		"process_start.hashes.md5":    query.NullValidator,
		"process_start.hashes.sha1":   query.NullValidator,
		"process_start.hashes.sha256": query.NullValidator,
		"host":                        query.NullValidator,
	}

	if validator, ok := validationMap[a.Key]; ok {
		return validator(a)
	}

	return fmt.Errorf("invalid key: %s", a.Key)
}
