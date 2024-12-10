package linseed

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/filters"
	"github.com/tigera/tds-apiserver/lib/slices"
)

func TestParams(t *testing.T) {

	collectionsMap := slices.AssociateBy(collections.Collections(), func(c collections.Collection) collections.CollectionName {
		return c.Name()
	})

	qnameField, found := collectionsMap[collections.CollectionNameDNS].Field("qname")
	require.True(t, found)

	clientNameField, found := collectionsMap[collections.CollectionNameDNS].Field("client_name")
	require.True(t, found)

	countField, found := collectionsMap[collections.CollectionNameDNS].Field("count")
	require.True(t, found)

	clientIPField, found := collectionsMap[collections.CollectionNameDNS].Field("client_ip")
	require.True(t, found)

	policyTypeField, found := collectionsMap[collections.CollectionNameFlows].Field(collections.FieldNamePolicyType)
	require.True(t, found)

	t.Run("filter criterion", func(t *testing.T) {
		t.Run("in", func(t *testing.T) {
			subject := newQueryParams(0)

			err := subject.setCriteria(filters.Criteria{
				filters.NewIn(clientNameField, []string{"test-value1", "test-value2", "test-value3"}, false),
				filters.NewIn(clientNameField, []string{"test-value4", "test-value5", "test-value6"}, true),
			}, time.Time{})
			require.NoError(t, err)

			require.Equal(t, &queryParams{
				selector: `( client_name = "test-value1" OR client_name = "test-value2" OR client_name = "test-value3" ) AND ( client_name != "test-value4" AND client_name != "test-value5" AND client_name != "test-value6" )`,

				domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
				linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "@timestamp", Descending: true}}},
			}, subject)
		})

		t.Run("or", func(t *testing.T) {
			subject := newQueryParams(0)

			err := subject.setCriteria(filters.Criteria{
				filters.NewOr(filters.Criteria{
					filters.NewEquals(clientNameField, "test-value1", false),
					filters.NewEquals(clientNameField, "test-value2", true),
				}, false),
				filters.NewOr(filters.Criteria{
					filters.NewEquals(clientNameField, "test-value3", false),
					filters.NewEquals(clientNameField, "test-value4", true),
				}, true),
			}, time.Time{})
			require.NoError(t, err)

			require.Equal(t, &queryParams{
				selector: `( client_name = "test-value1" OR client_name != "test-value2" ) AND NOT ( client_name = "test-value3" OR client_name != "test-value4" )`,

				domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
				linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "@timestamp", Descending: true}}},
			}, subject)
		})

		t.Run("range", func(t *testing.T) {
			subject := newQueryParams(0)

			err := subject.setCriteria(filters.Criteria{
				filters.NewRange(countField, 10, 20, false),
			}, time.Time{})
			require.NoError(t, err)

			require.Equal(t, &queryParams{
				selector: `count >= 10 AND count <= 20`,

				domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
				linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "@timestamp", Descending: true}}},
			}, subject)

			t.Run("negated", func(t *testing.T) {
				subject := newQueryParams(0)

				err := subject.setCriteria(filters.Criteria{
					filters.NewRange(countField, 10, 20, true),
				}, time.Time{})
				require.NoError(t, err)

				require.Equal(t, &queryParams{
					selector: `count < 10 AND count > 20`,

					domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
					linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "@timestamp", Descending: true}}},
				}, subject)
			})
		})

		t.Run("equals", func(t *testing.T) {
			subject := newQueryParams(0)

			err := subject.setCriteria(filters.Criteria{
				filters.NewEquals(qnameField, "test-domain1.com", false),
				filters.NewEquals(qnameField, "test-domain2.com", true),
				filters.NewEquals(qnameField, "test-domain3.com", true),
			}, time.Time{})
			require.NoError(t, err)

			require.Equal(t, &queryParams{
				domainMatches: map[lsv1.DomainMatchType][]string{
					lsv1.DomainMatchQname:  {"test-domain1.com", "test-domain2.com", "test-domain3.com"},
					lsv1.DomainMatchRRSet:  nil,
					lsv1.DomainMatchRRData: nil,
				},
				linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "@timestamp", Descending: true}}},
			}, subject)

			t.Run("unknown enum field", func(t *testing.T) {
				subject := newQueryParams(0)

				err := subject.setCriteria(filters.Criteria{
					filters.NewEquals(collections.NewCollectionFieldEnum("invalid-field", nil, ""), "test-value", false),
				}, time.Time{})
				require.ErrorContains(t, err, "unknown collection enum field 'invalid-field'")
			})

			t.Run("policy match", func(t *testing.T) {
				subject := newQueryParams(0)

				err := subject.setCriteria(filters.Criteria{
					filters.NewEquals(policyTypeField, "staged", false),
				}, time.Time{})
				require.NoError(t, err)

				require.Equal(t, &queryParams{
					policyMatches: []lsv1.PolicyMatch{
						{Staged: true},
					},
					domainMatches: map[lsv1.DomainMatchType][]string{
						lsv1.DomainMatchQname:  nil,
						lsv1.DomainMatchRRSet:  nil,
						lsv1.DomainMatchRRData: nil,
					},
					linseedQuerySortParams: lsv1.QuerySortParams{
						Sort: []lsv1.SearchRequestSortBy{
							{Field: "@timestamp", Descending: true},
						},
					},
				}, subject)

				t.Run("negated", func(t *testing.T) {
					subject := newQueryParams(0)

					err := subject.setCriteria(filters.Criteria{
						filters.NewEquals(policyTypeField, "staged", true),
					}, time.Time{})
					require.NoError(t, err)

					require.Equal(t, &queryParams{
						policyMatches: nil,
						domainMatches: map[lsv1.DomainMatchType][]string{
							lsv1.DomainMatchQname:  nil,
							lsv1.DomainMatchRRSet:  nil,
							lsv1.DomainMatchRRData: nil,
						},
						linseedQuerySortParams: lsv1.QuerySortParams{
							Sort: []lsv1.SearchRequestSortBy{
								{Field: "@timestamp", Descending: true},
							},
						},
					}, subject)
				})
			})
		})

		t.Run("exists", func(t *testing.T) {
			subject := newQueryParams(0)

			err := subject.setCriteria(filters.Criteria{
				filters.NewExists(clientNameField, false),
			}, time.Time{})
			require.NoError(t, err)

			require.Equal(t, &queryParams{
				selector: `client_name IN {"*"}`,

				domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
				linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "@timestamp", Descending: true}}},
			}, subject)

			t.Run("negated", func(t *testing.T) {
				subject := newQueryParams(0)

				err := subject.setCriteria(filters.Criteria{
					filters.NewExists(clientNameField, true),
				}, time.Time{})
				require.NoError(t, err)

				require.Equal(t, &queryParams{
					selector: `client_name NOTIN {"*"}`,

					domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
					linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "@timestamp", Descending: true}}},
				}, subject)
			})

		})
		t.Run("ipRange", func(t *testing.T) {
			subject := newQueryParams(0)

			err := subject.setCriteria(filters.Criteria{
				filters.NewIPRange(clientIPField, "10.0.0.1", "10.0.0.255", false),
			}, time.Time{})
			require.NoError(t, err)

			require.Equal(t, &queryParams{
				selector: `client_ip >= "10.0.0.1" AND client_ip <= "10.0.0.255"`,

				domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
				linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "@timestamp", Descending: true}}},
			}, subject)

			t.Run("negated", func(t *testing.T) {
				subject := newQueryParams(0)

				err := subject.setCriteria(filters.Criteria{
					filters.NewIPRange(clientIPField, "10.0.0.1", "10.0.0.255", true),
				}, time.Time{})
				require.NoError(t, err)

				require.Equal(t, &queryParams{
					selector: `client_ip < "10.0.0.1" AND client_ip > "10.0.0.255"`,

					domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
					linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "@timestamp", Descending: true}}},
				}, subject)
			})
		})

		t.Run("wildcard", func(t *testing.T) {
			subject := newQueryParams(0)

			err := subject.setCriteria(filters.Criteria{
				filters.NewWildcard(qnameField, "*test-domain1.com", false),
				filters.NewWildcard(qnameField, "test-domain2.com*", true),
				filters.NewWildcard(qnameField, "test-domain*.com", true),
			}, time.Time{})
			require.NoError(t, err)

			require.Equal(t, &queryParams{
				selector: `qname IN {"*test-domain1.com"} AND qname NOTIN {"test-domain2.com*"} AND qname NOTIN {"test-domain*.com"}`,

				domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
				linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "@timestamp", Descending: true}}},
			}, subject)
		})

		t.Run("dateRange", func(t *testing.T) {
			subject := newQueryParams(0)

			to := time.Date(2021, 12, 11, 10, 9, 8, 7, time.UTC)
			from := time.Date(2020, 12, 11, 10, 9, 8, 7, time.UTC)
			now := time.Date(2025, 12, 11, 10, 9, 8, 7, time.UTC)

			err := subject.setCriteria(filters.Criteria{
				filters.NewDateRange(nil, from, to, false),
			}, now)
			require.NoError(t, err)

			require.Empty(t, subject.selector)
			require.Equal(t, lsv1.QueryParams{
				TimeRange: &lmav1.TimeRange{From: from, To: to, Now: &now},
			}, subject.linseedQueryParams)
			require.Equal(t, time.Duration(365*24)*time.Hour, subject.requestedPeriod)

			t.Run("negated", func(t *testing.T) {
				subject := newQueryParams(0)
				err := subject.setCriteria(filters.Criteria{
					filters.NewDateRange(nil, from, to, true),
				}, now)
				require.ErrorContains(t, err, "negated dateRange criterion is not supported")
			})

			t.Run("with field set", func(t *testing.T) {
				subject := newQueryParams(0)
				err := subject.setCriteria(filters.Criteria{
					filters.NewDateRange(collections.NewCollectionFieldGeneric("test-field", collections.FieldTypeDate, ""), from, to, false),
				}, now)
				require.NoError(t, err)

				require.Empty(t, subject.selector)
				require.Equal(t, lsv1.QueryParams{
					TimeRange: &lmav1.TimeRange{From: from, To: to, Now: &now, Field: "test-field"},
				}, subject.linseedQueryParams)
			})
		})

		t.Run("startsWith", func(t *testing.T) {
			subject := newQueryParams(0)

			err := subject.setCriteria(filters.Criteria{
				filters.NewStartsWith(qnameField, "test-domain1.", false),
				filters.NewStartsWith(qnameField, "test-domain2.", true),
				filters.NewStartsWith(qnameField, "test-domain3.", true),
			}, time.Time{})
			require.NoError(t, err)

			require.Equal(t, &queryParams{
				selector: `qname IN {"test-domain1.*"} AND qname NOTIN {"test-domain2.*"} AND qname NOTIN {"test-domain3.*"}`,

				domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
				linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "@timestamp", Descending: true}}},
			}, subject)

		})
		t.Run("relativeTimeRange", func(t *testing.T) {
			subject := newQueryParams(0)

			now := time.Date(2025, 12, 11, 10, 30, 8, 7, time.UTC)

			criterion, err := filters.NewRelativeTimeRange(nil, "10m", "5m", false)
			require.NoError(t, err)

			err = subject.setCriteria(filters.Criteria{criterion}, now)
			require.NoError(t, err)

			require.Empty(t, subject.selector)
			require.Equal(t, lsv1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					To:   time.Date(2025, 12, 11, 10, 25, 8, 7, time.UTC),
					From: time.Date(2025, 12, 11, 10, 20, 8, 7, time.UTC),
					Now:  &now,
				},
			}, subject.linseedQueryParams)
			require.Equal(t, time.Duration(5)*time.Minute, subject.requestedPeriod)

			t.Run("negated", func(t *testing.T) {
				subject = &queryParams{}

				criterion, err = filters.NewRelativeTimeRange(nil, "10m", "5m", true)
				require.NoError(t, err)

				err = subject.setCriteria(filters.Criteria{criterion}, now)
				require.ErrorContains(t, err, "negated relativeTimeRange criterion is not supported")
			})

			t.Run("with field set", func(t *testing.T) {
				subject = &queryParams{}

				criterion, err = filters.NewRelativeTimeRange(collections.NewCollectionFieldGeneric("test-field", collections.FieldTypeDate, ""), "10m", "5m", false)
				require.NoError(t, err)

				err = subject.setCriteria(filters.Criteria{criterion}, now)
				require.NoError(t, err)

				require.Empty(t, subject.selector)
				require.Equal(t, lsv1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						To:    time.Date(2025, 12, 11, 10, 25, 8, 7, time.UTC),
						From:  time.Date(2025, 12, 11, 10, 20, 8, 7, time.UTC),
						Now:   &now,
						Field: "test-field",
					},
				}, subject.linseedQueryParams)
			})
		})

	})

	t.Run("sort documents by timestamp", func(t *testing.T) {
		subject := newQueryParams(0)
		require.Equal(t, lsv1.QuerySortParams{
			Sort: []lsv1.SearchRequestSortBy{
				{Field: "@timestamp", Descending: true},
			},
		}, subject.linseedQuerySortParams)
	})

	t.Run("value escaping", func(t *testing.T) {
		subject := newQueryParams(0)

		err := subject.setCriteria(filters.Criteria{
			filters.NewEquals(clientNameField, `test-name1" AND false`, false),
			filters.NewEquals(clientNameField, `"test-name2"OR 123`, true),
			filters.NewEquals(clientNameField, `test-name3' NOT 1=1"`, true),
		}, time.Time{})
		require.NoError(t, err)

		require.Equal(t,
			`client_name = "test-name1\" AND false" AND client_name != "\"test-name2\"OR 123" AND client_name != "test-name3' NOT 1=1\""`,
			subject.selector)
	})

	t.Run("string to numeric value conversion", func(t *testing.T) {
		subject := newQueryParams(0)

		err := subject.setCriteria(filters.Criteria{
			filters.NewEquals(countField, `124`, false),
			filters.NewEquals(countField, `123.0`, true),
		}, time.Time{})
		require.NoError(t, err)

		require.Equal(t,
			`count = 124 AND count != 123`,
			subject.selector)

		t.Run("negative numbers", func(t *testing.T) {
			subject := newQueryParams(0)

			err := subject.setCriteria(filters.Criteria{
				filters.NewEquals(countField, `-849`, false),
				filters.NewEquals(countField, `-534.0`, true),
			}, time.Time{})
			require.NoError(t, err)

			require.Equal(t,
				`count = -849 AND count != -534`,
				subject.selector)
		})
	})

}
