package linseed

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/tds-apiserver/lib/slices"

	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/collections"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/filters"
	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

func TestParams(t *testing.T) {

	collectionsMap := slices.AssociateBy(collections.Collections(nil), func(c collections.Collection) collections.CollectionName {
		return c.Name()
	})

	qnameField, found := collectionsMap[collections.CollectionNameDNS].Field("qname")
	require.True(t, found)
	require.Equal(t, collections.FieldTypeQName, qnameField.Type())

	clientNameField, found := collectionsMap[collections.CollectionNameDNS].Field("client_name")
	require.True(t, found)
	require.Equal(t, collections.FieldTypeText, clientNameField.Type())

	countField, found := collectionsMap[collections.CollectionNameDNS].Field("count")
	require.True(t, found)
	require.Equal(t, collections.FieldTypeNumber, countField.Type())

	clientIPField, found := collectionsMap[collections.CollectionNameDNS].Field("client_ip")
	require.True(t, found)
	require.Equal(t, collections.FieldTypeIP, clientIPField.Type())

	destDomainsField, found := collectionsMap[collections.CollectionNameFlows].Field("dest_domains")
	require.True(t, found)
	require.Equal(t, collections.FieldTypeDestDomains, destDomainsField.Type())

	policyTypeField, found := collectionsMap[collections.CollectionNameFlows].Field(collections.FieldNamePolicyType)
	require.True(t, found)
	require.Equal(t, collections.FieldTypeEnum, policyTypeField.Type())

	policyAllPoliciesField, found := collectionsMap[collections.CollectionNameFlows].Field("policies.all_policies")
	require.True(t, found)
	require.Equal(t, collections.FieldTypeText, policyAllPoliciesField.Type())

	enumField, found := collectionsMap[collections.CollectionNameFlows].Field("action")
	require.True(t, found)
	require.Equal(t, collections.FieldTypeEnum, enumField.Type())

	nestedField, found := collectionsMap[collections.CollectionNameDNS].Field("rrsets.type")
	require.True(t, found)
	require.Equal(t, collections.FieldTypeEnum, nestedField.Type())

	labelsField, found := collectionsMap[collections.CollectionNameFlows].Field("dest_labels.labels")
	require.True(t, found)
	require.Equal(t, collections.FieldTypeLabels, labelsField.Type())

	t.Run("clusterIDs", func(t *testing.T) {
		t.Run("non-empty", func(t *testing.T) {
			subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
			require.NoError(t, err)
			require.False(t, subject.linseedQueryParams.AllClusters)
		})
		t.Run("empty", func(t *testing.T) {
			subject, err := newQueryParams(0, 0, "start_time", []string{}, nil)
			require.NoError(t, err)
			require.True(t, subject.linseedQueryParams.AllClusters)
		})
	})

	t.Run("filter criterion", func(t *testing.T) {
		t.Run("in", func(t *testing.T) {
			subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
			require.NoError(t, err)

			err = subject.setCriteria(filters.Criteria{
				filters.NewIn(clientNameField, []string{"test-value1", "test-value2", "test-value3"}, false),
				filters.NewIn(clientNameField, []string{"test-value4", "test-value5", "test-value6"}, true),
			}, time.Time{})
			require.NoError(t, err)

			require.Equal(t, &queryParams{
				linseedLogSelectionParams: lsv1.LogSelectionParams{
					Selector: `( client_name = "test-value1" OR client_name = "test-value2" OR client_name = "test-value3" ) AND ( client_name != "test-value4" AND client_name != "test-value5" AND client_name != "test-value6" )`,
				},
				domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
				linseedQueryParams:     lsv1.QueryParams{Clusters: []string{"fake-cluster"}, AfterKey: map[string]any{"startFrom": 0}},
				linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "start_time", Descending: true}}},
			}, subject)
		})

		t.Run("or", func(t *testing.T) {
			subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
			require.NoError(t, err)

			err = subject.setCriteria(filters.Criteria{
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
				linseedLogSelectionParams: lsv1.LogSelectionParams{
					Selector: `( client_name = "test-value1" OR client_name != "test-value2" ) AND NOT ( client_name = "test-value3" OR client_name != "test-value4" )`,
				},
				domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
				linseedQueryParams:     lsv1.QueryParams{Clusters: []string{"fake-cluster"}, AfterKey: map[string]any{"startFrom": 0}},
				linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "start_time", Descending: true}}},
			}, subject)
		})

		t.Run("range", func(t *testing.T) {
			subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
			require.NoError(t, err)

			err = subject.setCriteria(filters.Criteria{
				filters.NewRange(countField, intp(10), intp(20), false),
			}, time.Time{})
			require.NoError(t, err)

			require.Equal(t, &queryParams{
				linseedLogSelectionParams: lsv1.LogSelectionParams{
					Selector: `count >= 10 AND count <= 20`,
				},
				domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
				linseedQueryParams:     lsv1.QueryParams{Clusters: []string{"fake-cluster"}, AfterKey: map[string]any{"startFrom": 0}},
				linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "start_time", Descending: true}}},
			}, subject)

			t.Run("negated", func(t *testing.T) {
				subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
				require.NoError(t, err)

				err = subject.setCriteria(filters.Criteria{
					filters.NewRange(countField, intp(10), intp(20), true),
				}, time.Time{})
				require.NoError(t, err)

				require.Equal(t, &queryParams{
					linseedLogSelectionParams: lsv1.LogSelectionParams{
						Selector: `NOT (count >= 10 AND count <= 20)`,
					},
					domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
					linseedQueryParams:     lsv1.QueryParams{Clusters: []string{"fake-cluster"}, AfterKey: map[string]any{"startFrom": 0}},
					linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "start_time", Descending: true}}},
				}, subject)
			})

			t.Run("no parameters", func(t *testing.T) {
				err := subject.setCriteria(filters.Criteria{
					filters.NewRange(countField, nil, nil, true),
				}, time.Time{})
				require.ErrorContains(t, err, "invalid range criterion for field 'count'")
			})

			t.Run("single parameter", func(t *testing.T) {
				subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
				require.NoError(t, err)

				t.Run("gte", func(t *testing.T) {
					err := subject.setCriteria(filters.Criteria{
						filters.NewRange(countField, intp(10), nil, false),
					}, time.Time{})
					require.NoError(t, err)

					require.Equal(t, &queryParams{
						linseedLogSelectionParams: lsv1.LogSelectionParams{
							Selector: `count >= 10`,
						},
						domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
						linseedQueryParams:     lsv1.QueryParams{Clusters: []string{"fake-cluster"}, AfterKey: map[string]any{"startFrom": 0}},
						linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "start_time", Descending: true}}},
					}, subject)
				})
				t.Run("lte", func(t *testing.T) {
					err := subject.setCriteria(filters.Criteria{
						filters.NewRange(countField, nil, intp(20), false),
					}, time.Time{})
					require.NoError(t, err)

					require.Equal(t, &queryParams{
						linseedLogSelectionParams: lsv1.LogSelectionParams{
							Selector: `count <= 20`,
						},
						domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
						linseedQueryParams:     lsv1.QueryParams{Clusters: []string{"fake-cluster"}, AfterKey: map[string]any{"startFrom": 0}},
						linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "start_time", Descending: true}}},
					}, subject)

					t.Run("negated", func(t *testing.T) {

						err := subject.setCriteria(filters.Criteria{
							filters.NewRange(countField, nil, intp(20), true),
						}, time.Time{})
						require.NoError(t, err)

						require.Equal(t, &queryParams{
							linseedLogSelectionParams: lsv1.LogSelectionParams{
								Selector: `NOT (count <= 20)`,
							},
							domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
							linseedQueryParams:     lsv1.QueryParams{Clusters: []string{"fake-cluster"}, AfterKey: map[string]any{"startFrom": 0}},
							linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "start_time", Descending: true}}},
						}, subject)
					})
				})
			})
		})

		t.Run("equals", func(t *testing.T) {
			subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
			require.NoError(t, err)

			err = subject.setCriteria(filters.Criteria{
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
				linseedQueryParams:     lsv1.QueryParams{Clusters: []string{"fake-cluster"}, AfterKey: map[string]any{"startFrom": 0}},
				linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "start_time", Descending: true}}},
			}, subject)

			t.Run("enum fields", func(t *testing.T) {
				subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
				require.NoError(t, err)

				err = subject.setCriteria(filters.Criteria{
					filters.NewEquals(enumField, `allow`, false),
				}, time.Time{})
				require.NoError(t, err)

				require.Equal(t, `action = "allow"`, subject.linseedLogSelectionParams.Selector)

				t.Run("invalid value", func(t *testing.T) {
					subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
					require.NoError(t, err)

					err = subject.setCriteria(filters.Criteria{
						filters.NewEquals(enumField, `invalid-value`, false),
					}, time.Time{})
					require.ErrorContains(t, err, "invalid value for field 'action': invalid-value")
				})
			})

			t.Run("labels field type", func(t *testing.T) {
				subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
				require.NoError(t, err)

				err = subject.setCriteria(filters.Criteria{
					filters.NewEquals(labelsField, `label1=value1`, false),
				}, time.Time{})
				require.NoError(t, err)

				require.Equal(t, `"dest_labels.labels" = "label1=value1"`, subject.linseedLogSelectionParams.Selector)

				t.Run("invalid value", func(t *testing.T) {
					subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
					require.NoError(t, err)

					err = subject.setCriteria(filters.Criteria{filters.NewEquals(labelsField, `invalid`, false)}, time.Time{})
					require.ErrorContains(t, err, `invalid value for "dest_labels.labels": expected format is labelName=labelValue`)
					err = subject.setCriteria(filters.Criteria{filters.NewEquals(labelsField, `invalid=`, false)}, time.Time{})
					require.ErrorContains(t, err, `invalid value for "dest_labels.labels": expected format is labelName=labelValue`)
					err = subject.setCriteria(filters.Criteria{filters.NewEquals(labelsField, `=invalid`, false)}, time.Time{})
					require.ErrorContains(t, err, `invalid value for "dest_labels.labels": expected format is labelName=labelValue`)
				})
			})

			t.Run("policy type", func(t *testing.T) {

				testCases := []struct {
					name             string
					filter           filters.Criterion
					expectedSelector string
				}{
					{
						name:             "staged",
						filter:           filters.NewEquals(policyTypeField, "staged", false),
						expectedSelector: `"policies.all_policies" IN {"*|*|*.staged:*|*|*"} OR "policies.pending_policies" IN {"*|*|*.staged:*|*|*"}`,
					},
					{
						name:             "staged negated",
						filter:           filters.NewEquals(policyTypeField, "staged", true),
						expectedSelector: `"policies.all_policies" NOTIN {"*|*|*.staged:*|*|*"} AND "policies.pending_policies" NOTIN {"*|*|*.staged:*|*|*"}`,
					},
					{
						name:             "enforced",
						filter:           filters.NewEquals(policyTypeField, "enforced", false),
						expectedSelector: `"policies.all_policies" NOTIN {"*|*|*.staged:*|*|*"} AND "policies.pending_policies" NOTIN {"*|*|*.staged:*|*|*"}`,
					},
					{
						name:             "enforced negated",
						filter:           filters.NewEquals(policyTypeField, "enforced", true),
						expectedSelector: `"policies.all_policies" IN {"*|*|*.staged:*|*|*"} OR "policies.pending_policies" IN {"*|*|*.staged:*|*|*"}`,
					},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
						require.NoError(t, err)

						err = subject.setCriteria(filters.Criteria{tc.filter}, time.Time{})
						require.NoError(t, err)

						require.Equal(t, &queryParams{
							domainMatches: map[lsv1.DomainMatchType][]string{
								lsv1.DomainMatchQname:  nil,
								lsv1.DomainMatchRRSet:  nil,
								lsv1.DomainMatchRRData: nil,
							},
							linseedQueryParams: lsv1.QueryParams{Clusters: []string{"fake-cluster"}, AfterKey: map[string]any{"startFrom": 0}},
							linseedQuerySortParams: lsv1.QuerySortParams{
								Sort: []lsv1.SearchRequestSortBy{
									{Field: "start_time", Descending: true},
								},
							},
							linseedLogSelectionParams: lsv1.LogSelectionParams{
								Selector: tc.expectedSelector,
							},
						}, subject)
					})
				}
			})

			t.Run("invalid numbers", func(t *testing.T) {
				setEqualsCriterion := func(t *testing.T, value any) error {
					subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
					require.NoError(t, err)

					return subject.setCriteria(filters.Criteria{
						filters.NewEquals(countField, value, false),
					}, time.Time{})
				}

				err := setEqualsCriterion(t, "10000000000000000000")
				require.ErrorContains(t, err, `invalid equals criterion value "10000000000000000000"`)

				err = setEqualsCriterion(t, "10000000000000000000.0")
				require.ErrorContains(t, err, `invalid equals criterion value "10000000000000000000.0"`)

				err = setEqualsCriterion(t, 9223372036854786048.0)
				require.ErrorContains(t, err, `invalid equals criterion value "9.223372036854786e+18"`)

				err = setEqualsCriterion(t, -1)
				require.ErrorContains(t, err, `invalid equals criterion value "-1"`)

				err = setEqualsCriterion(t, -1.0)
				require.ErrorContains(t, err, `invalid equals criterion value "-1"`)

				err = setEqualsCriterion(t, "-1")
				require.ErrorContains(t, err, `invalid equals criterion value "-1"`)
			})

			t.Run("nested fields", func(t *testing.T) {
				subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
				require.NoError(t, err)

				err = subject.setCriteria(filters.Criteria{
					filters.NewEquals(nestedField, "SOA", true),
				}, time.Time{})
				require.NoError(t, err)

				require.Equal(t, &queryParams{
					linseedLogSelectionParams: lsv1.LogSelectionParams{
						Selector: `NOT "rrsets.type" = "SOA"`,
					},
					domainMatches: map[lsv1.DomainMatchType][]string{
						lsv1.DomainMatchQname:  nil,
						lsv1.DomainMatchRRSet:  nil,
						lsv1.DomainMatchRRData: nil,
					},
					linseedQueryParams: lsv1.QueryParams{Clusters: []string{"fake-cluster"}, AfterKey: map[string]any{"startFrom": 0}},
					linseedQuerySortParams: lsv1.QuerySortParams{
						Sort: []lsv1.SearchRequestSortBy{
							{Field: "start_time", Descending: true},
						},
					},
				}, subject)

			})
		})

		t.Run("exists", func(t *testing.T) {

			testCases := []struct {
				name             string
				filter           filters.Criterion
				expectedSelector string
			}{
				{
					name:             "client_name",
					filter:           filters.NewExists(clientNameField, false),
					expectedSelector: `client_name IN {"*"}`,
				},
				{
					name:             "client_name negated",
					filter:           filters.NewExists(clientNameField, true),
					expectedSelector: `client_name NOTIN {"*"}`,
				},
				{
					name:             "labels field type",
					filter:           filters.NewExists(labelsField, false),
					expectedSelector: `"dest_labels.labels" IN {"*"}`,
				},
				{
					name:             "labels field type negated",
					filter:           filters.NewExists(labelsField, true),
					expectedSelector: `"dest_labels.labels" NOTIN {"*"}`,
				},
				{
					name:             "dest_domains",
					filter:           filters.NewExists(destDomainsField, false),
					expectedSelector: `NOT dest_domains EMPTY`,
				},
				{
					name:             "dest_domains negated",
					filter:           filters.NewExists(destDomainsField, true),
					expectedSelector: `dest_domains EMPTY`,
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
					require.NoError(t, err)

					err = subject.setCriteria(filters.Criteria{tc.filter}, time.Time{})
					require.NoError(t, err)

					require.Equal(t, &queryParams{
						linseedLogSelectionParams: lsv1.LogSelectionParams{
							Selector: tc.expectedSelector,
						},
						domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
						linseedQueryParams:     lsv1.QueryParams{Clusters: []string{"fake-cluster"}, AfterKey: map[string]any{"startFrom": 0}},
						linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "start_time", Descending: true}}},
					}, subject)
				})
			}
		})

		t.Run("ipRange", func(t *testing.T) {
			subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
			require.NoError(t, err)

			err = subject.setCriteria(filters.Criteria{
				filters.NewIPRange(clientIPField, "10.0.0.1", "10.0.0.255", false),
			}, time.Time{})
			require.NoError(t, err)

			require.Equal(t, &queryParams{
				linseedLogSelectionParams: lsv1.LogSelectionParams{
					Selector: `client_ip >= "10.0.0.1" AND client_ip <= "10.0.0.255"`,
				},
				domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
				linseedQueryParams:     lsv1.QueryParams{Clusters: []string{"fake-cluster"}, AfterKey: map[string]any{"startFrom": 0}},
				linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "start_time", Descending: true}}},
			}, subject)

			t.Run("negated", func(t *testing.T) {
				subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
				require.NoError(t, err)

				err = subject.setCriteria(filters.Criteria{
					filters.NewIPRange(clientIPField, "10.0.0.1", "10.0.0.255", true),
				}, time.Time{})
				require.NoError(t, err)

				require.Equal(t, &queryParams{
					linseedLogSelectionParams: lsv1.LogSelectionParams{
						Selector: `client_ip < "10.0.0.1" AND client_ip > "10.0.0.255"`,
					},
					domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
					linseedQueryParams:     lsv1.QueryParams{Clusters: []string{"fake-cluster"}, AfterKey: map[string]any{"startFrom": 0}},
					linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "start_time", Descending: true}}},
				}, subject)
			})
		})

		t.Run("wildcard", func(t *testing.T) {
			subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
			require.NoError(t, err)

			err = subject.setCriteria(filters.Criteria{
				filters.NewWildcard(qnameField, "*test-domain1.com", false),
				filters.NewWildcard(qnameField, "test-domain2.com*", true),
				filters.NewWildcard(qnameField, "test-domain*.com", true),
			}, time.Time{})
			require.NoError(t, err)

			require.Equal(t, &queryParams{
				linseedLogSelectionParams: lsv1.LogSelectionParams{
					Selector: `qname IN {"*test-domain1.com"} AND qname NOTIN {"test-domain2.com*"} AND qname NOTIN {"test-domain*.com"}`,
				},
				domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
				linseedQueryParams:     lsv1.QueryParams{Clusters: []string{"fake-cluster"}, AfterKey: map[string]any{"startFrom": 0}},
				linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "start_time", Descending: true}}},
			}, subject)

			t.Run("nested fields", func(t *testing.T) {
				subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
				require.NoError(t, err)

				err = subject.setCriteria(filters.Criteria{
					filters.NewWildcard(policyAllPoliciesField, "*_PROFILE_*", true),
				}, time.Time{})
				require.NoError(t, err)

				require.Equal(t, &queryParams{
					linseedLogSelectionParams: lsv1.LogSelectionParams{
						Selector: `"policies.all_policies" NOTIN {"*_PROFILE_*"}`,
					},
					domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
					linseedQueryParams:     lsv1.QueryParams{Clusters: []string{"fake-cluster"}, AfterKey: map[string]any{"startFrom": 0}},
					linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "start_time", Descending: true}}},
				}, subject)
			})
		})

		t.Run("dateRange", func(t *testing.T) {
			subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
			require.NoError(t, err)

			to := time.Date(2021, 12, 11, 10, 9, 8, 7, time.UTC)
			from := time.Date(2020, 12, 11, 10, 9, 8, 7, time.UTC)
			now := time.Date(2025, 12, 11, 10, 9, 8, 7, time.UTC)

			err = subject.setCriteria(filters.Criteria{
				filters.NewDateRange(nil, from, &to, false),
			}, now)
			require.NoError(t, err)

			require.Empty(t, subject.linseedLogSelectionParams.Selector)
			require.Equal(t, lsv1.QueryParams{
				TimeRange: &lmav1.TimeRange{From: from, To: to, Now: &now},
				Clusters:  []string{"fake-cluster"},
				AfterKey:  map[string]any{"startFrom": 0},
			}, subject.linseedQueryParams)
			require.Equal(t, time.Duration(365*24)*time.Hour, subject.requestedPeriod)

			t.Run("negated", func(t *testing.T) {
				subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
				require.NoError(t, err)
				err = subject.setCriteria(filters.Criteria{
					filters.NewDateRange(nil, from, &to, true),
				}, now)
				require.ErrorContains(t, err, "negated dateRange criterion is not supported")
			})

			t.Run("with field set", func(t *testing.T) {
				subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
				require.NoError(t, err)
				err = subject.setCriteria(filters.Criteria{
					filters.NewDateRange(collections.NewCollectionFieldGeneric("test-field", collections.FieldTypeDate, ""), from, &to, false),
				}, now)
				require.NoError(t, err)

				require.Empty(t, subject.linseedLogSelectionParams.Selector)
				require.Equal(t, lsv1.QueryParams{
					TimeRange: &lmav1.TimeRange{From: from, To: to, Now: &now, Field: ""},
					Clusters:  []string{"fake-cluster"},
					AfterKey:  map[string]any{"startFrom": 0},
				}, subject.linseedQueryParams)
			})

			t.Run("defaults lte field to now", func(t *testing.T) {
				subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
				require.NoError(t, err)
				err = subject.setCriteria(filters.Criteria{
					filters.NewDateRange(collections.NewCollectionFieldGeneric("test-field", collections.FieldTypeDate, ""), from, nil, false),
				}, now)
				require.NoError(t, err)
				require.True(t, subject.linseedQueryParams.TimeRange.To.Equal(now))
			})

			t.Run("gte is not greater than lte", func(t *testing.T) {
				lte := time.Date(2020, 0, 0, 0, 0, 0, 0, time.UTC)
				gte := time.Date(2020, 0, 0, 0, 0, 0, 1, time.UTC)

				subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
				require.NoError(t, err)
				err = subject.setCriteria(filters.Criteria{
					filters.NewDateRange(collections.NewCollectionFieldGeneric("test-field", collections.FieldTypeDate, ""), gte, &lte, false),
				}, now)
				require.ErrorContains(t, err, "invalid value for dateRange: gte is greater than lte")
			})
			t.Run("gte is not greater than default lte", func(t *testing.T) {
				gte := time.Date(10000, 0, 0, 0, 0, 0, 1, time.UTC)

				subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
				require.NoError(t, err)
				err = subject.setCriteria(filters.Criteria{
					filters.NewDateRange(collections.NewCollectionFieldGeneric("test-field", collections.FieldTypeDate, ""), gte, nil, false),
				}, now)
				require.ErrorContains(t, err, "invalid value for dateRange gte")
			})
		})

		t.Run("startsWith", func(t *testing.T) {
			subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
			require.NoError(t, err)

			err = subject.setCriteria(filters.Criteria{
				filters.NewStartsWith(qnameField, "test-domain1.", false),
				filters.NewStartsWith(qnameField, "test-domain2.", true),
				filters.NewStartsWith(qnameField, "test-domain3.", true),
			}, time.Time{})
			require.NoError(t, err)

			require.Equal(t, &queryParams{
				linseedLogSelectionParams: lsv1.LogSelectionParams{
					Selector: `qname IN {"test-domain1.*"} AND qname NOTIN {"test-domain2.*"} AND qname NOTIN {"test-domain3.*"}`,
				},
				domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
				linseedQueryParams:     lsv1.QueryParams{Clusters: []string{"fake-cluster"}, AfterKey: map[string]any{"startFrom": 0}},
				linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "start_time", Descending: true}}},
			}, subject)

			t.Run("value escaping", func(t *testing.T) {
				subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
				require.NoError(t, err)

				err = subject.setCriteria(filters.Criteria{
					filters.NewStartsWith(qnameField, "test-domain*1.", false),
					filters.NewStartsWith(qnameField, "test-domain?2.", true),
				}, time.Time{})
				require.NoError(t, err)

				require.Equal(t, &queryParams{
					linseedLogSelectionParams: lsv1.LogSelectionParams{
						Selector: `qname IN {"test-domain\\*1.*"} AND qname NOTIN {"test-domain\\?2.*"}`,
					},
					domainMatches:          map[lsv1.DomainMatchType][]string{lsv1.DomainMatchQname: nil, lsv1.DomainMatchRRSet: nil, lsv1.DomainMatchRRData: nil},
					linseedQueryParams:     lsv1.QueryParams{Clusters: []string{"fake-cluster"}, AfterKey: map[string]any{"startFrom": 0}},
					linseedQuerySortParams: lsv1.QuerySortParams{Sort: []lsv1.SearchRequestSortBy{{Field: "start_time", Descending: true}}},
				}, subject)
			})
		})
		t.Run("relativeTimeRange", func(t *testing.T) {
			subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
			require.NoError(t, err)

			now := time.Date(2025, 12, 11, 10, 30, 8, 7, time.UTC)

			criterion, err := filters.NewRelativeTimeRange(nil, time.Duration(10)*time.Minute, time.Duration(5)*time.Minute, false)
			require.NoError(t, err)

			err = subject.setCriteria(filters.Criteria{criterion}, now)
			require.NoError(t, err)

			require.Empty(t, subject.linseedLogSelectionParams.Selector)
			require.Equal(t, lsv1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					To:   time.Date(2025, 12, 11, 10, 25, 8, 7, time.UTC),
					From: time.Date(2025, 12, 11, 10, 20, 8, 7, time.UTC),
					Now:  &now,
				},
				Clusters: []string{"fake-cluster"},
				AfterKey: map[string]any{"startFrom": 0},
			}, subject.linseedQueryParams)
			require.Equal(t, time.Duration(5)*time.Minute, subject.requestedPeriod)

			t.Run("negated", func(t *testing.T) {
				subject = &queryParams{}

				criterion, err := filters.NewRelativeTimeRange(nil, time.Duration(10)*time.Minute, time.Duration(5)*time.Minute, true)
				require.NoError(t, err)

				err = subject.setCriteria(filters.Criteria{criterion}, now)
				require.ErrorContains(t, err, "negated relativeTimeRange criterion is not supported")
			})

			t.Run("with field set", func(t *testing.T) {

				testCase := []struct {
					field         string
					expectedField string
				}{
					{
						field:         "start_time",
						expectedField: "start_time",
					},
					{
						field:         "generated_time",
						expectedField: "generated_time",
					},
					{
						field:         "end_time",
						expectedField: "",
					},
					{
						field:         "unknown_field",
						expectedField: "",
					},
				}

				for _, tc := range testCase {
					t.Run(tc.field, func(t *testing.T) {
						subject = &queryParams{}

						criterion, err = filters.NewRelativeTimeRange(
							collections.NewCollectionFieldGeneric(collections.FieldName(tc.field), collections.FieldTypeDate, ""),
							time.Duration(10)*time.Minute,
							time.Duration(5)*time.Minute,
							false,
						)
						require.NoError(t, err)

						err = subject.setCriteria(filters.Criteria{criterion}, now)
						require.NoError(t, err)

						require.Empty(t, subject.linseedLogSelectionParams.Selector)
						require.Equal(t, lsv1.QueryParams{
							TimeRange: &lmav1.TimeRange{
								To:    time.Date(2025, 12, 11, 10, 25, 8, 7, time.UTC),
								From:  time.Date(2025, 12, 11, 10, 20, 8, 7, time.UTC),
								Now:   &now,
								Field: lmav1.TimeField(tc.expectedField),
							},
						}, subject.linseedQueryParams)
					})
				}
			})
		})

	})

	t.Run("sort documents by timestamp", func(t *testing.T) {
		subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
		require.NoError(t, err)
		require.Equal(t, lsv1.QuerySortParams{
			Sort: []lsv1.SearchRequestSortBy{
				{Field: "start_time", Descending: true},
			},
		}, subject.linseedQuerySortParams)
	})

	t.Run("value escaping", func(t *testing.T) {
		subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
		require.NoError(t, err)

		testCases := []struct {
			name             string
			filterValue      string
			expectedSelector string
		}{
			{
				name:             "quote within value",
				filterValue:      `test-name1" AND false`,
				expectedSelector: `client_name = "test-name1\" AND false"`,
			},
			{
				name:             "starting with quote",
				filterValue:      `"test-name2 OR 123`,
				expectedSelector: `client_name = "\"test-name2 OR 123"`,
			},
			{
				name:             "ending in quote",
				filterValue:      `test-name3' NOT 1=1"`,
				expectedSelector: `client_name = "test-name3' NOT 1=1\""`,
			},
			{
				name:             "starting with and containing two quotes",
				filterValue:      `"test-name2"OR 123`,
				expectedSelector: `client_name = "\"test-name2\"OR 123"`,
			},
			{
				name:             "enclosed in quotes",
				filterValue:      `"test|name4"`, // expected to be the same as filterValue: `test|name4`,
				expectedSelector: `client_name = "test|name4"`,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err = subject.setCriteria(filters.Criteria{
					filters.NewEquals(clientNameField, tc.filterValue, false),
				}, time.Time{})
				require.NoError(t, err)

				require.Equal(t, tc.expectedSelector, subject.linseedLogSelectionParams.Selector)
			})
		}
	})

	t.Run("field name escaping", func(t *testing.T) {
		subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
		require.NoError(t, err)

		err = subject.setCriteria(filters.Criteria{
			filters.NewEquals(nestedField, `SOA`, false),
			filters.NewEquals(nestedField, `CNAME`, true),
		}, time.Time{})
		require.NoError(t, err)

		require.Equal(t,
			`"rrsets.type" = "SOA" AND NOT "rrsets.type" = "CNAME"`,
			subject.linseedLogSelectionParams.Selector)
	})

	t.Run("string to numeric value conversion", func(t *testing.T) {
		subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
		require.NoError(t, err)

		err = subject.setCriteria(filters.Criteria{
			filters.NewEquals(countField, `124`, false),
			filters.NewEquals(countField, `123.0`, true),
		}, time.Time{})
		require.NoError(t, err)

		require.Equal(t,
			`count = 124 AND count != 123`,
			subject.linseedLogSelectionParams.Selector)

		t.Run("negative numbers", func(t *testing.T) {
			subject, err := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
			require.NoError(t, err)

			err = subject.setCriteria(filters.Criteria{
				filters.NewEquals(countField, `-849`, false),
			}, time.Time{})
			require.ErrorContains(t, err, `invalid equals criterion value "-849"`)
		})
	})

	t.Run("pagination", func(t *testing.T) {
		subject, err := newQueryParams(10, 5, "start_time", []string{"fake-cluster"}, nil)
		require.NoError(t, err)

		require.Equal(t, lsv1.QueryParams{
			MaxPageSize: 10,
			AfterKey: map[string]any{
				"startFrom": 50,
			},
			Clusters: []string{"fake-cluster"},
		}, subject.linseedQueryParams)
	})

	t.Run("sort field", func(t *testing.T) {
		subject, err := newQueryParams(10, 5, "another-field", []string{"fake-cluster"}, nil)
		require.NoError(t, err)
		require.NoError(t, err)
		require.Equal(t, lsv1.QuerySortParams{
			Sort: []lsv1.SearchRequestSortBy{
				{Field: "another-field", Descending: true},
			},
		}, subject.linseedQuerySortParams)
	})

	t.Run("permissions", func(t *testing.T) {
		subject, err := newQueryParams(10, 0, "start_time", []string{"fake-cluster"}, []v3.AuthorizedResourceVerbs{{
			APIGroup: "fake-group",
			Resource: "fake-resource",
			Verbs: []v3.AuthorizedResourceVerb{{
				Verb: "get",
				ResourceGroups: []v3.AuthorizedResourceGroup{
					{ManagedCluster: "fake-cluster", Namespace: "fake-namespace"},
				},
			}},
		}})
		require.NoError(t, err)

		require.Equal(t, lsv1.LogSelectionParams{
			Permissions: []v3.AuthorizedResourceVerbs{{
				APIGroup: "fake-group",
				Resource: "fake-resource",
				Verbs: []v3.AuthorizedResourceVerb{{
					Verb: "get",
					ResourceGroups: []v3.AuthorizedResourceGroup{
						{ManagedCluster: "fake-cluster", Namespace: "fake-namespace"},
					},
				}},
			}},
		}, subject.linseedLogSelectionParams)
	})
}

func intp(i int64) *int64 {
	return &i
}
