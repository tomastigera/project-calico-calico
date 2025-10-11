// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package index

import (
	"time"

	"github.com/olivere/elastic/v7"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

func SingleIndexComplianceReports() Helper {
	return complianceReportsIndexHelper{singleIndex: true}
}

func MultiIndexComplianceReports() Helper {
	return complianceReportsIndexHelper{}
}

type complianceReportsIndexHelper struct {
	singleIndex bool
}

func (h complianceReportsIndexHelper) BaseQuery(i bapi.ClusterInfo, params v1.Params) (*elastic.BoolQuery, error) {
	return defaultBaseQuery(i, h.singleIndex, params)
}

func (h complianceReportsIndexHelper) NewSelectorQuery(selector string) (elastic.Query, error) {
	return nil, nil
}

func (h complianceReportsIndexHelper) NewRBACQuery(resources []apiv3.AuthorizedResourceVerbs) (elastic.Query, error) {
	return nil, nil
}

func (h complianceReportsIndexHelper) NewTimeRangeQuery(r *lmav1.TimeRange) elastic.Query {
	timeField := GetTimeFieldForQuery(h, r)
	timeRangeQuery := elastic.NewRangeQuery(timeField)
	switch timeField {
	case "generated_time":
		return processGeneratedField(r, timeRangeQuery)
	default:
		// Any query that targets the default time field will target both startTime and endTime
		unset := time.Time{}
		if r.From != unset && r.To != unset {
			return elastic.NewBoolQuery().Should(
				elastic.NewRangeQuery("startTime").From(r.From).To(r.To),
				elastic.NewRangeQuery("endTime").From(r.From).To(r.To),
			)
		} else if r.From != unset && r.To.Equal(unset) {
			return elastic.NewRangeQuery("endTime").From(r.From)
		} else if r.From.Equal(unset) && r.To != unset {
			return elastic.NewRangeQuery("startTime").To(r.To)
		}
	}
	return nil
}

func (h complianceReportsIndexHelper) GetTimeField() string {
	return ""
}
