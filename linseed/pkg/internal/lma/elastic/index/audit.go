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

// auditLogsIndexHelper implements the Helper interface for audit logs.
type auditLogsIndexHelper struct {
	singleIndex bool
}

// MultiIndexAuditLogs returns an instance of the audit logs index helper.
func MultiIndexAuditLogs() Helper {
	return auditLogsIndexHelper{}
}

func SingleIndexAuditLogs() Helper {
	return auditLogsIndexHelper{
		singleIndex: true,
	}
}

func NewAuditLogsConverter() converter {
	return converter{atomToElastic: basicAtomToElastic, setOpTermToElastic: basicSetOpTermToElastic}
}

func (h auditLogsIndexHelper) BaseQuery(i bapi.ClusterInfo, params v1.Params) (*elastic.BoolQuery, error) {
	return defaultBaseQuery(i, h.singleIndex, params)
}

func (h auditLogsIndexHelper) NewSelectorQuery(selector string) (elastic.Query, error) {
	q, err := query.ParseQuery(selector)
	if err != nil {
		return nil, &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Err:    err,
			Msg:    fmt.Sprintf("Invalid selector (%s) in request: %v", selector, err),
		}
	} else if err := query.Validate(q, query.IsValidAuditAtom); err != nil {
		return nil, &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Err:    err,
			Msg:    fmt.Sprintf("Invalid selector (%s) in request: %v", selector, err),
		}
	}
	converter := NewAuditLogsConverter()
	return JsonObjectElasticQuery(converter.Convert(q)), nil
}

func (h auditLogsIndexHelper) NewRBACQuery(
	resources []apiv3.AuthorizedResourceVerbs,
) (elastic.Query, error) {
	return nil, fmt.Errorf("not implemented")
}

func (h auditLogsIndexHelper) NewTimeRangeQuery(r *lmav1.TimeRange) elastic.Query {
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

func (h auditLogsIndexHelper) GetTimeField() string {
	return "requestReceivedTimestamp"
}
