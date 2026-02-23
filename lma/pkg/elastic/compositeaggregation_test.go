// Copyright (c) 2020 Tigera, Inc. All rights reserved.
package elastic_test

import (
	"context"
	"encoding/json"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	pelastic "github.com/projectcalico/calico/lma/pkg/elastic"
)

var (
	sampleEsResponseJsonFirst = `{
  "took": 78,
  "timed_out": false,
  "_shards": {
    "total": 40,
    "successful": 40,
    "skipped": 0,
    "failed": 0
  },
  "hits": {
    "total": {
      "relation": "eq",
      "value": 1285
    },
    "max_score": 0,
    "hits": []
  },
  "aggregations": {
    "flog_buckets": {
      "after_key": {
        "source_type": "wep",
        "dest_type": "wep",
        "source_port": 20,
        "dest_port": 200
      },
      "buckets": [
        {
          "key": {
            "source_type": "wep",
            "dest_type": "hep",
            "source_port": 0,
            "dest_port": 6783
          },
          "doc_count": 1,
          "sum_bytes_out": {
            "value": 2
          },
          "sum_bytes_in": {
            "value": 3
          },
          "policies": {
            "doc_count": 4,
            "by_tiered_policy": {
              "doc_count_error_upper_bound": 0,
              "sum_other_doc_count": 0,
              "buckets": [
                {
                  "key": "abcd",
                  "doc_count": 5
                }
              ]
            },
            "by_tiered_enforced_policy": {
              "doc_count_error_upper_bound": 0,
              "sum_other_doc_count": 0,
              "buckets": [
                {
                  "key": "efgh",
                  "doc_count": 6
                }
              ]
            },
            "by_tiered_pending_policy": {
              "doc_count_error_upper_bound": 0,
              "sum_other_doc_count": 0,
              "buckets": [
                {
                  "key": "ijkl",
                  "doc_count": 7
                }
              ]
            },
            "by_tiered_transit_policy": {
              "doc_count_error_upper_bound": 0,
              "sum_other_doc_count": 0,
              "buckets": [
                {
                  "key": "mnop",
                  "doc_count": 8
                }
              ]
            }
          },
          "source_labels": {
            "doc_count": 6,
            "by_kvpair": {
              "doc_count_error_upper_bound": 0,
              "sum_other_doc_count": 0,
              "buckets": [
                {
                  "key": "aaaa",
                  "doc_count": 7
                },
                {
                  "key": "bbbb",
                  "doc_count": 8
                }
              ]
            }
          }
        }
      ]
    }
  }
}
`

	sampleEsResponseJsonNoBuckets = `{
  "took": 78,
  "timed_out": false,
  "_shards": {
    "total": 40,
    "successful": 40,
    "skipped": 0,
    "failed": 0
  },
  "hits": {
		"total": {
      "relation": "eq",
      "value": 1
    },
    "max_score": 0,
    "hits": []
  },
  "aggregations": {
    "flog_buckets": {
      "after_key": {
        "source_type": "wep",
        "dest_type": "wep",
        "source_port": 0,
        "dest_port": 9200
      },
      "buckets": []
    }
  }
}
`
	sampleEsResponseJsonTimedout = `{
  "took": 78,
  "timed_out": true,
  "_shards": {
    "total": 40,
    "successful": 40,
    "skipped": 0,
    "failed": 0
  },
  "hits": {
    "total": {
      "relation": "eq",
      "value": 1
    },
    "max_score": 0,
    "hits": []
  },
  "aggregations": {
    "flog_buckets": {
      "after_key": {
        "source_type": "wep",
        "dest_type": "wep",
        "source_port": 0,
        "dest_port": 9200
      },
      "buckets": []
    }
  }
}
`
	sampleEsResponseJsonNoAfterKey = `{
  "took": 78,
  "timed_out": false,
  "_shards": {
    "total": 40,
    "successful": 40,
    "skipped": 0,
    "failed": 0
  },
  "hits": {
    "total": {
      "relation": "eq",
      "value": 1
    },
    "max_score": 0,
    "hits": []
  },
  "aggregations": {
    "flog_buckets": {
      "buckets": [
        {
          "key": {
            "source_type": "hep",
            "dest_type": "wep",
            "source_port": 12,
            "dest_port": 13
          },
          "doc_count": 14,
          "sum_bytes_out": {
            "value": 5
          },
          "policies": {
            "doc_count": 17,
            "by_tiered_policy": {
              "doc_count_error_upper_bound": 0,
              "sum_other_doc_count": 0,
              "buckets": [
                {
                  "key": "zzzz",
                  "doc_count": 18
                }
              ]
            }
          },
          "source_labels": {
            "doc_count": 60,
            "by_kvpair": {
              "doc_count_error_upper_bound": 0,
              "sum_other_doc_count": 0,
              "buckets": [
                {
                  "key": "aaaa",
                  "doc_count": 70
                },
                {
                  "key": "bbbb",
                  "doc_count": 80
                },
                {
                  "key": 1,
                  "doc_count": 1
                }
              ]
            }
          },
          "dest_labels": {
            "doc_count": 21,
            "by_kvpair": {
              "doc_count_error_upper_bound": 0,
              "sum_other_doc_count": 0,
              "buckets": [
                {
                  "key": 123,
                  "doc_count": 22
                },
                {
                  "key": 124,
                  "doc_count": 23
                }
              ]
            }
          }
        }
      ]
    }
  }
}
`

	sampleBucketJsonTestMarshal = `        {
          "key": {
            "source_type": "wep",
            "dest_type": "hep",
            "source_port": 0,
            "dest_port": 6783
          },
          "doc_count": 1,
          "sum_bytes_out": {
            "value": 2
          },
          "sum_bytes_in": {
            "value": 3
          },
          "policies": {
            "doc_count": 4,
            "by_tiered_policy": {
              "buckets": [
                {
                  "key": "abcd",
                  "doc_count": 5
                }
              ]
            },
            "by_tiered_enforced_policy": {
              "buckets": [
                {
                  "key": "efgh",
                  "doc_count": 6
                }
              ]
            },
            "by_tiered_pending_policy": {
              "buckets": [
                {
                  "key": "ijkl",
                  "doc_count": 7
                }
              ]
            },
            "by_tiered_transit_policy": {
              "buckets": [
                {
                  "key": "mnop",
                  "doc_count": 8
                }
              ]
            }
          },
          "source_labels": {
            "doc_count": 6,
            "by_kvpair": {
              "buckets": [
                {
                  "key": "aaaa",
                  "doc_count": 8
                },
                {
                  "key": "bbbb",
                  "doc_count": 7
                }
              ]
            }
          },
          "dest_labels": {
            "doc_count": 21,
            "by_kvpair": {
              "buckets": [
                {
                  "key": 123,
                  "doc_count": 23
                },
                {
                  "key": 124,
                  "doc_count": 22
                }
              ]
            }
          }
        }
`

	sampleEsResponseJsonTestMarshal = `{
  "took": 78,
  "timed_out": false,
  "_shards": {
    "total": 40,
    "successful": 40,
    "skipped": 0,
    "failed": 0
  },
  "hits": {
    "total": {
      "relation": "eq",
      "value": 1
    },
    "max_score": 0,
    "hits": []
  },
  "aggregations": {
    "flog_buckets": {
      "after_key": {
        "source_type": "wep",
        "dest_type": "wep",
        "source_port": 20,
        "dest_port": 200
      },
      "buckets": [
` + sampleBucketJsonTestMarshal + `
      ]
    }
  }
}
`

	compositeSources = []pelastic.AggCompositeSourceInfo{
		{Name: "source_type", Field: "source_type"},
		{Name: "dest_type", Field: "dest_type"},
		{Name: "source_port", Field: "source_port"},
		{Name: "dest_port", Field: "dest_port"},
	}

	aggTerms = []pelastic.AggNestedTermInfo{
		{"policies", "policies", "by_tiered_policy", "policies.all_policies"},
		{"policies", "policies", "by_tiered_enforced_policy", "policies.enforced_policies"},
		{"policies", "policies", "by_tiered_pending_policy", "policies.pending_policies"},
		{"policies", "policies", "by_tiered_transit_policy", "policies.transit_policies"},
		{"dest_labels", "dest_labels", "by_kvpair", "dest_labels.labels"},
		{"source_labels", "source_labels", "by_kvpair", "source_labels.labels"},
	}

	aggSums = []pelastic.AggSumInfo{
		{"sum_bytes_out", "bytes_out"},
		{"sum_bytes_in", "bytes_in"},
	}
)

var _ = Describe("Test unmarshaling of sample ES response", func() {
	It("handles search returning an error", func() {
		By("Creating an ES client with a mocked out search results")
		client := pelastic.NewMockSearchClient([]any{sampleEsResponseJsonFirst, errors.New("foobar")})

		By("Creating a composite agg query")
		// Set max buckets to 1 so that we do more than one query.
		q := &pelastic.CompositeAggregationQuery{
			Name:                    "flog_buckets",
			AggCompositeSourceInfos: compositeSources,
			AggNestedTermInfos:      aggTerms,
			AggSumInfos:             aggSums,
			MaxBucketsPerQuery:      1,
		}

		By("Performing a composite agg search")
		cxt, cancel := context.WithCancel(context.Background())
		defer cancel()
		resChan, errs := client.SearchCompositeAggregations(cxt, q, nil)

		var results []*pelastic.CompositeAggregationBucket
		for result := range resChan {
			results = append(results, result)
			Expect(result).NotTo(BeNil())
			Expect(len(results)).To(BeNumerically("<", 5)) // Fail safe so tests don't get stuck
		}

		By("Checking we got the expected single result")
		Expect(results).To(HaveLen(1))
		Expect(results[0].DocCount).To(Equal(int64(1)))
		Expect(results[0].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{"source_type", "wep"},
			{"dest_type", "hep"},
			{"source_port", float64(0)},
			{"dest_port", float64(6783)},
		}))
		Expect(results[0].AggregatedSums["sum_bytes_out"]).To(Equal(float64(2)))
		Expect(results[0].AggregatedSums["sum_bytes_in"]).To(Equal(float64(3)))
		Expect(results[0].AggregatedTerms).To(HaveKey("policies"))
		Expect(results[0].AggregatedTerms["policies"].DocCount).To(Equal(int64(4)))
		Expect(results[0].AggregatedTerms["policies"].MultiTermBuckets["by_tiered_policy"]["abcd"]).To(Equal(int64(5)))
		Expect(results[0].AggregatedTerms["policies"].MultiTermBuckets["by_tiered_enforced_policy"]["efgh"]).To(Equal(int64(6)))
		Expect(results[0].AggregatedTerms["policies"].MultiTermBuckets["by_tiered_pending_policy"]["ijkl"]).To(Equal(int64(7)))
		Expect(results[0].AggregatedTerms["policies"].MultiTermBuckets["by_tiered_transit_policy"]["mnop"]).To(Equal(int64(8)))
		Expect(results[0].AggregatedTerms).To(HaveKey("source_labels"))
		Expect(results[0].AggregatedTerms["source_labels"].DocCount).To(Equal(int64(6)))
		Expect(results[0].AggregatedTerms["source_labels"].Buckets["aaaa"]).To(Equal(int64(7)))
		Expect(results[0].AggregatedTerms["source_labels"].Buckets["bbbb"]).To(Equal(int64(8)))
		Expect(results[0].AggregatedTerms).NotTo(HaveKey("dest_labels"))

		By("Checking we also got an error")
		var err error
		Expect(errs).Should(Receive(&err))
		Expect(err.Error()).To(Equal("foobar"))
	})

	It("handles search returning no buckets with an after_key", func() {
		By("Creating an ES client with a mocked out search results, second query errors")
		client := pelastic.NewMockSearchClient([]any{sampleEsResponseJsonNoBuckets})

		By("Creating a composite agg query")
		q := &pelastic.CompositeAggregationQuery{
			Name:                    "flog_buckets",
			AggCompositeSourceInfos: compositeSources,
			AggNestedTermInfos:      aggTerms,
			AggSumInfos:             aggSums,
		}

		By("Performing a composite agg search")
		cxt, cancel := context.WithCancel(context.Background())
		defer cancel()
		resChan, errs := client.SearchCompositeAggregations(cxt, q, nil)

		var results []*pelastic.CompositeAggregationBucket
		for result := range resChan {
			results = append(results, result)
			Expect(result).NotTo(BeNil())
			Expect(len(results)).To(BeNumerically("<", 5)) // Fail safe so tests don't get stuck
		}

		By("Checking we got no results and no errors")
		Expect(errs).ShouldNot(Receive())
	})

	It("handles search returning no buckets with timedout flag set", func() {
		By("Creating an ES client with a mocked out search results")
		client := pelastic.NewMockSearchClient([]any{sampleEsResponseJsonTimedout})

		By("Creating a composite agg query")
		q := &pelastic.CompositeAggregationQuery{
			Name:                    "flog_buckets",
			AggCompositeSourceInfos: compositeSources,
			AggNestedTermInfos:      aggTerms,
			AggSumInfos:             aggSums,
		}

		By("Performing a composite agg search")
		cxt, cancel := context.WithCancel(context.Background())
		defer cancel()
		resChan, errs := client.SearchCompositeAggregations(cxt, q, nil)

		var results []*pelastic.CompositeAggregationBucket
		for result := range resChan {
			results = append(results, result)
			Expect(result).NotTo(BeNil())
			Expect(len(results)).To(BeNumerically("<", 5)) // Fail safe so tests don't get stuck
		}

		By("Checking we got no results and a timedout error")
		var err pelastic.TimedOutError
		Expect(errs).Should(Receive(&err))
	})

	It("handles search returning buckets with no after key", func() {
		By("Creating an ES client with a mocked out search results")
		client := pelastic.NewMockSearchClient([]any{sampleEsResponseJsonNoAfterKey})

		By("Creating a composite agg query")
		// Set max buckets to query to be 1 so that we would normally query again - except there is no after key.
		q := &pelastic.CompositeAggregationQuery{
			Name:                    "flog_buckets",
			AggCompositeSourceInfos: compositeSources,
			AggNestedTermInfos:      aggTerms,
			AggSumInfos:             aggSums,
			MaxBucketsPerQuery:      1,
		}

		By("Performing a composite agg search")
		cxt, cancel := context.WithCancel(context.Background())
		defer cancel()
		resChan, errs := client.SearchCompositeAggregations(cxt, q, nil)

		var results []*pelastic.CompositeAggregationBucket
		for result := range resChan {
			results = append(results, result)
			Expect(result).NotTo(BeNil())
			Expect(len(results)).To(BeNumerically("<", 5)) // Fail safe so tests don't get stuck
		}

		By("Checking we got the expected single result")
		Expect(results).To(HaveLen(1))
		Expect(results[0].DocCount).To(Equal(int64(14)))
		Expect(results[0].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{"source_type", "hep"},
			{"dest_type", "wep"},
			{"source_port", float64(12)},
			{"dest_port", float64(13)},
		}))
		Expect(results[0].AggregatedSums["sum_bytes_out"]).To(Equal(float64(5)))
		Expect(results[0].AggregatedSums).NotTo(HaveKey("sum_bytes_in"))
		Expect(results[0].AggregatedTerms).To(HaveKey("policies"))
		Expect(results[0].AggregatedTerms["policies"].DocCount).To(Equal(int64(17)))
		Expect(results[0].AggregatedTerms["policies"].Buckets["zzzz"]).To(Equal(int64(18)))
		Expect(results[0].AggregatedTerms).To(HaveKey("source_labels"))
		Expect(results[0].AggregatedTerms["source_labels"].DocCount).To(Equal(int64(60)))
		Expect(results[0].AggregatedTerms["source_labels"].Buckets["aaaa"]).To(Equal(int64(70)))
		Expect(results[0].AggregatedTerms["source_labels"].Buckets["bbbb"]).To(Equal(int64(80)))
		Expect(results[0].AggregatedTerms["source_labels"].Buckets[float64(1)]).To(Equal(int64(1)))
		Expect(results[0].AggregatedTerms).To(HaveKey("dest_labels"))
		Expect(results[0].AggregatedTerms["dest_labels"].Buckets[float64(123)]).To(Equal(int64(22)))
		Expect(results[0].AggregatedTerms["dest_labels"].Buckets[float64(124)]).To(Equal(int64(23)))

		By("Checking we got no error")
		Expect(errs).ShouldNot(Receive())
	})

	It("handles search in two blocks returning buckets, and all helper methods work", func() {
		By("Creating an ES client with a mocked out search results")
		client := pelastic.NewMockSearchClient([]any{sampleEsResponseJsonFirst, sampleEsResponseJsonNoAfterKey})

		By("Creating a composite agg query")
		// Set max buckets to ensure we do a second search.
		q := &pelastic.CompositeAggregationQuery{
			Name:                    "flog_buckets",
			AggCompositeSourceInfos: compositeSources,
			AggNestedTermInfos:      aggTerms,
			AggSumInfos:             aggSums,
			MaxBucketsPerQuery:      1,
		}

		By("Performing a composite agg search")
		cxt, cancel := context.WithCancel(context.Background())
		defer cancel()
		resChan, errs := client.SearchCompositeAggregations(cxt, q, nil)

		var results []*pelastic.CompositeAggregationBucket
		for result := range resChan {
			results = append(results, result)
			Expect(result).NotTo(BeNil())
			Expect(len(results)).To(BeNumerically("<", 5)) // Fail safe so tests don't get stuck
		}

		By("Checking we got the expected two results")
		Expect(results).To(HaveLen(2))

		Expect(results[0].DocCount).To(Equal(int64(1)))
		Expect(results[0].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{"source_type", "wep"},
			{"dest_type", "hep"},
			{"source_port", float64(0)},
			{"dest_port", float64(6783)},
		}))
		Expect(results[0].AggregatedSums["sum_bytes_out"]).To(Equal(float64(2)))
		Expect(results[0].AggregatedSums["sum_bytes_in"]).To(Equal(float64(3)))
		Expect(results[0].AggregatedTerms).To(HaveKey("policies"))
		Expect(results[0].AggregatedTerms["policies"].DocCount).To(Equal(int64(4)))
		Expect(results[0].AggregatedTerms["policies"].MultiTermBuckets["by_tiered_policy"]["abcd"]).To(Equal(int64(5)))
		Expect(results[0].AggregatedTerms["policies"].MultiTermBuckets["by_tiered_enforced_policy"]["efgh"]).To(Equal(int64(6)))
		Expect(results[0].AggregatedTerms["policies"].MultiTermBuckets["by_tiered_pending_policy"]["ijkl"]).To(Equal(int64(7)))
		Expect(results[0].AggregatedTerms["policies"].MultiTermBuckets["by_tiered_transit_policy"]["mnop"]).To(Equal(int64(8)))
		Expect(results[0].AggregatedTerms).To(HaveKey("source_labels"))
		Expect(results[0].AggregatedTerms["source_labels"].DocCount).To(Equal(int64(6)))
		Expect(results[0].AggregatedTerms["source_labels"].Buckets["aaaa"]).To(Equal(int64(7)))
		Expect(results[0].AggregatedTerms["source_labels"].Buckets["bbbb"]).To(Equal(int64(8)))
		Expect(results[0].AggregatedTerms).NotTo(HaveKey("dest_labels"))

		Expect(results[1].DocCount).To(Equal(int64(14)))
		Expect(results[1].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{"source_type", "hep"},
			{"dest_type", "wep"},
			{"source_port", float64(12)},
			{"dest_port", float64(13)},
		}))
		Expect(results[1].AggregatedSums["sum_bytes_out"]).To(Equal(float64(5)))
		Expect(results[1].AggregatedSums).NotTo(HaveKey("sum_bytes_in"))
		Expect(results[1].AggregatedTerms).To(HaveKey("policies"))
		Expect(results[1].AggregatedTerms["policies"].DocCount).To(Equal(int64(17)))
		Expect(results[1].AggregatedTerms["policies"].Buckets["zzzz"]).To(Equal(int64(18)))
		Expect(results[1].AggregatedTerms).To(HaveKey("source_labels"))
		Expect(results[1].AggregatedTerms["source_labels"].DocCount).To(Equal(int64(60)))
		Expect(results[1].AggregatedTerms["source_labels"].Buckets["aaaa"]).To(Equal(int64(70)))
		Expect(results[1].AggregatedTerms["source_labels"].Buckets["bbbb"]).To(Equal(int64(80)))
		Expect(results[1].AggregatedTerms["source_labels"].Buckets[float64(1)]).To(Equal(int64(1)))
		Expect(results[1].AggregatedTerms).To(HaveKey("dest_labels"))
		Expect(results[1].AggregatedTerms["dest_labels"].Buckets[float64(123)]).To(Equal(int64(22)))
		Expect(results[1].AggregatedTerms["dest_labels"].Buckets[float64(124)]).To(Equal(int64(23)))

		By("Checking we got no error")
		Expect(errs).ShouldNot(Receive())

		By("Checking key is not modified (assumption is key is the same, but this is not enforced)")
		Expect(results[0].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{"source_type", "wep"},
			{"dest_type", "hep"},
			{"source_port", float64(0)},
			{"dest_port", float64(6783)},
		}))

		By("Checking key accessor methods work correctly")
		Expect(results[0].CompositeAggregationKey[0].String()).To(Equal("wep"))
		Expect(results[0].CompositeAggregationKey[0].Float64()).To(Equal(float64(0)))
		Expect(results[0].CompositeAggregationKey[1].String()).To(Equal("hep"))
		Expect(results[0].CompositeAggregationKey[0].Float64()).To(Equal(float64(0)))
		Expect(results[0].CompositeAggregationKey[2].String()).To(Equal(""))
		Expect(results[0].CompositeAggregationKey[2].Float64()).To(Equal(float64(0)))
		Expect(results[0].CompositeAggregationKey[3].String()).To(Equal(""))
		Expect(results[0].CompositeAggregationKey[3].Float64()).To(Equal(float64(6783)))

		By("Checking key comparison method works correctly")
		Expect(results[0].CompositeAggregationKey.SameBucket(results[0].CompositeAggregationKey)).To(BeTrue())
		Expect(results[0].CompositeAggregationKey.SameBucket(results[1].CompositeAggregationKey)).To(BeFalse())

		By("Aggregating the second result into the first")
		r1 := results[0]
		r2 := results[1]
		r1.Aggregate(r2)

		By("Checking aggregated values")
		Expect(r1.DocCount).To(Equal(int64(15)))
		Expect(r1.AggregatedSums["sum_bytes_out"]).To(Equal(float64(7)))
		Expect(r1.AggregatedSums["sum_bytes_in"]).To(Equal(float64(3)))
		Expect(r1.AggregatedTerms).To(HaveKey("policies"))
		Expect(r1.AggregatedTerms["policies"].DocCount).To(Equal(int64(21)))
		Expect(r1.AggregatedTerms["policies"].MultiTermBuckets["by_tiered_policy"]["abcd"]).To(Equal(int64(5)))
		Expect(r1.AggregatedTerms["policies"].MultiTermBuckets["by_tiered_policy"]["zzzz"]).To(Equal(int64(18)))
		Expect(r1.AggregatedTerms).To(HaveKey("source_labels"))
		Expect(r1.AggregatedTerms["source_labels"].DocCount).To(Equal(int64(66)))
		Expect(r1.AggregatedTerms["source_labels"].Buckets["aaaa"]).To(Equal(int64(77)))
		Expect(r1.AggregatedTerms["source_labels"].Buckets["bbbb"]).To(Equal(int64(88)))
		Expect(r1.AggregatedTerms["source_labels"].Buckets[float64(1)]).To(Equal(int64(1)))
		Expect(r1.AggregatedTerms).To(HaveKey("dest_labels"))
		Expect(r1.AggregatedTerms["dest_labels"].Buckets[float64(123)]).To(Equal(int64(22)))
		Expect(r1.AggregatedTerms["dest_labels"].Buckets[float64(124)]).To(Equal(int64(23)))

		By("Aggretating again, checking aggregated values")
		r1.Aggregate(r2)
		Expect(r1.DocCount).To(Equal(int64(29)))
		Expect(r1.AggregatedSums["sum_bytes_out"]).To(Equal(float64(12)))
		Expect(r1.AggregatedSums["sum_bytes_in"]).To(Equal(float64(3)))
		Expect(r1.AggregatedTerms).To(HaveKey("policies"))
		Expect(r1.AggregatedTerms["policies"].DocCount).To(Equal(int64(38)))
		Expect(r1.AggregatedTerms["policies"].MultiTermBuckets["by_tiered_policy"]["abcd"]).To(Equal(int64(5)))
		Expect(r1.AggregatedTerms["policies"].MultiTermBuckets["by_tiered_policy"]["zzzz"]).To(Equal(int64(36)))
		Expect(r1.AggregatedTerms).To(HaveKey("source_labels"))
		Expect(r1.AggregatedTerms["source_labels"].DocCount).To(Equal(int64(126)))
		Expect(r1.AggregatedTerms["source_labels"].Buckets["aaaa"]).To(Equal(int64(147)))
		Expect(r1.AggregatedTerms["source_labels"].Buckets["bbbb"]).To(Equal(int64(168)))
		Expect(r1.AggregatedTerms["source_labels"].Buckets[float64(1)]).To(Equal(int64(2)))
		Expect(r1.AggregatedTerms).To(HaveKey("dest_labels"))
		Expect(r1.AggregatedTerms["dest_labels"].Buckets[float64(123)]).To(Equal(int64(44)))
		Expect(r1.AggregatedTerms["dest_labels"].Buckets[float64(124)]).To(Equal(int64(46)))

		By("Checking the aggregated-in data is unchanged")
		Expect(r2.DocCount).To(Equal(int64(14)))
		Expect(r2.CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{"source_type", "hep"},
			{"dest_type", "wep"},
			{"source_port", float64(12)},
			{"dest_port", float64(13)},
		}))
		Expect(r2.AggregatedSums["sum_bytes_out"]).To(Equal(float64(5)))
		Expect(r2.AggregatedSums).NotTo(HaveKey("sum_bytes_in"))
		Expect(r2.AggregatedTerms).To(HaveKey("policies"))
		Expect(r2.AggregatedTerms["policies"].DocCount).To(Equal(int64(17)))
		Expect(r2.AggregatedTerms["policies"].Buckets["zzzz"]).To(Equal(int64(18)))
		Expect(r2.AggregatedTerms).To(HaveKey("source_labels"))
		Expect(r2.AggregatedTerms["source_labels"].DocCount).To(Equal(int64(60)))
		Expect(r2.AggregatedTerms["source_labels"].Buckets["aaaa"]).To(Equal(int64(70)))
		Expect(r2.AggregatedTerms["source_labels"].Buckets["bbbb"]).To(Equal(int64(80)))
		Expect(r2.AggregatedTerms["source_labels"].Buckets[float64(1)]).To(Equal(int64(1)))
		Expect(r2.AggregatedTerms).To(HaveKey("dest_labels"))
		Expect(r2.AggregatedTerms["dest_labels"].Buckets[float64(123)]).To(Equal(int64(22)))
		Expect(r2.AggregatedTerms["dest_labels"].Buckets[float64(124)]).To(Equal(int64(23)))

		By("Checking the policies can be replaced from a string slice")
		r2.SetAggregatedTermsFromStringSlice("policies", []string{"a123", "b123"})
		Expect(r2.AggregatedTerms["policies"].DocCount).To(Equal(int64(17)))
		Expect(r2.AggregatedTerms["policies"].Buckets).NotTo(HaveKey("zzzz"))
		Expect(r2.AggregatedTerms["policies"].Buckets["a123"]).To(Equal(int64(17)))
		Expect(r2.AggregatedTerms["policies"].Buckets["b123"]).To(Equal(int64(17)))

		By("Checking the a new aggregated terms set can be added from a string slice")
		r2.SetAggregatedTermsFromStringSlice("new-policies", []string{"c123", "d123"})
		Expect(r2.AggregatedTerms["new-policies"].DocCount).To(Equal(int64(14))) // count taken from main doc count
		Expect(r2.AggregatedTerms["new-policies"].Buckets["c123"]).To(Equal(int64(14)))
		Expect(r2.AggregatedTerms["new-policies"].Buckets["d123"]).To(Equal(int64(14)))
	})

	It("handles converting back into json", func() {
		By("Creating an ES client with a mocked out search results")
		client := pelastic.NewMockSearchClient([]any{sampleEsResponseJsonTestMarshal})

		By("Creating a composite agg query")
		q := &pelastic.CompositeAggregationQuery{
			Name:                    "flog_buckets",
			AggCompositeSourceInfos: compositeSources,
			AggNestedTermInfos:      aggTerms,
			AggSumInfos:             aggSums,
		}

		By("Performing a composite agg search")
		cxt, cancel := context.WithCancel(context.Background())
		defer cancel()
		resChan, _ := client.SearchCompositeAggregations(cxt, q, nil)

		var results []*pelastic.CompositeAggregationBucket
		for result := range resChan {
			results = append(results, result)
			Expect(result).NotTo(BeNil())
			Expect(len(results)).To(BeNumerically("<", 5)) // Fail safe so tests don't get stuck
		}

		By("Checking we got the expected single result")
		Expect(results).To(HaveLen(1))
		Expect(results[0].DocCount).To(Equal(int64(1)))
		Expect(results[0].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{"source_type", "wep"},
			{"dest_type", "hep"},
			{"source_port", float64(0)},
			{"dest_port", float64(6783)},
		}))

		Expect(results[0].AggregatedTerms).To(HaveKey("policies"))
		policies := results[0].AggregatedTerms["policies"]
		Expect(policies.MultiTermBuckets).To(HaveKey("by_tiered_policy"))
		Expect(policies.MultiTermBuckets["by_tiered_policy"]).To(HaveKeyWithValue("abcd", int64(5)))
		Expect(policies.MultiTermBuckets).To(HaveKey("by_tiered_enforced_policy"))
		Expect(policies.MultiTermBuckets["by_tiered_enforced_policy"]).To(HaveKeyWithValue("efgh", int64(6)))
		Expect(policies.MultiTermBuckets).To(HaveKey("by_tiered_pending_policy"))
		Expect(policies.MultiTermBuckets["by_tiered_pending_policy"]).To(HaveKeyWithValue("ijkl", int64(7)))
		Expect(policies.MultiTermBuckets).To(HaveKey("by_tiered_transit_policy"))
		Expect(policies.MultiTermBuckets["by_tiered_transit_policy"]).To(HaveKeyWithValue("mnop", int64(8)))

		By("Converting the result to a JSON map and extracting the first bucket")
		converted := pelastic.CompositeAggregationBucketsToMap(results, q)
		flog_buckets, ok := converted["flog_buckets"]
		Expect(ok).To(BeTrue())
		flog_buckets_map, ok := flog_buckets.(map[string]any)
		Expect(ok).To(BeTrue())
		buckets, ok := flog_buckets_map["buckets"]
		Expect(ok).To(BeTrue())
		buckets_slice, _ := buckets.([]map[string]any)
		Expect(buckets_slice).To(HaveLen(1))
		bucket := buckets_slice[0]

		By("Marshaling the bucket")
		marshaledbucket, err := json.Marshal(bucket)
		Expect(err).NotTo(HaveOccurred())

		By("Comparing against the expected JSON")
		Expect(marshaledbucket).To(MatchJSON(sampleBucketJsonTestMarshal))
	})
})
