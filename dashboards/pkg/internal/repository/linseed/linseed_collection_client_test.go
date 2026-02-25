package linseed

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

func newQueryParamsHelper(t *testing.T, now *time.Time, sortTimeFieldName string, selector string, domainMatches []string, permissions []v3.AuthorizedResourceVerbs) *queryParams {
	repositoryQueryParams, err := newQueryParams(0, 0, sortTimeFieldName, []string{"fake-cluster"}, permissions)
	require.NoError(t, err)

	repositoryQueryParams.linseedQueryParams.TimeRange = &lmav1.TimeRange{
		From: time.Date(2023, 1, 2, 3, 4, 5, 0, time.UTC),
		To:   time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		Now:  now,
	}

	if len(domainMatches) > 0 {
		repositoryQueryParams.domainMatches[lsv1.DomainMatchQname] = domainMatches
	}

	repositoryQueryParams.linseedLogSelectionParams.Selector = selector
	return repositoryQueryParams
}

// lsv1.QueryParams is the same across collection_client test cases
func expectedQueryParams(now *time.Time) lsv1.QueryParams {
	return lsv1.QueryParams{
		TimeRange: &lmav1.TimeRange{
			From: time.Date(2023, 1, 2, 3, 4, 5, 0, time.UTC),
			To:   time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
			Now:  now,
		},
		AfterKey: map[string]any{"startFrom": 0},
		Clusters: []string{"fake-cluster"},
	}
}
