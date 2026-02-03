package handler

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTransformPoliciesAggregation(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			// Simple bucket aggregation (not policy-related) - should be untouched
			name: "no policies field",
			input: `{
					"aggs": {
						"source_ip_buckets": {
							"terms": { "field": "source_ip" }
						}
					}
				}`,
			expected: `{
					"aggs": {
						"source_ip_buckets": {
							"terms": { "field": "source_ip" }
						}
					}
				}`,
		},
		{
			// Nested aggregation with path 'policies' is replaced with a match_all filter
			name: "policies with nested structural change",
			input: `{
					"aggs": {
						"policies": {
							"nested": { "path": "policies" },
							"aggs": {
								"by_policy": { "terms": { "field": "policies.name" } }
							}
						}
					}
				}`,
			expected: `{
					"aggs": {
						"policies": {
							"filter": { "match_all": {} },
							"aggs": {
								"by_policy": { "terms": { "field": "policies.name" } }
							}
						}
					}
				}`,
		},
		{
			// Deep nesting: confirm recursion works through other aggregations
			name: "deeply nested policies (complex composition)",
			input: `{
					"aggs": {
						"by_cluster": {
							"terms": { "field": "cluster" },
							"aggs": {
								"policies": {
									"nested": { "path": "policies" },
									"aggs": {
										"policy_count": { "value_count": { "field": "policies.id" } }
									}
								}
							}
						}
					}
				}`,
			expected: `{
					"aggs": {
						"by_cluster": {
							"terms": { "field": "cluster" },
							"aggs": {
								"policies": {
									"filter": { "match_all": {} },
									"aggs": {
										"policy_count": { "value_count": { "field": "policies.id" } }
									}
								}
							}
						}
					}
				}`,
		},
		{
			// Parallel aggregations: confirm all occurrences are handled
			name: "multiple policies aggregations (parallel)",
			input: `{
					"aggs": {
						"policies": {
							"nested": { "path": "policies" },
							"aggs": { "names": { "terms": { "field": "policies.name" } } }
						},
						"other_agg": {
							"aggs": {
								"policies": {
									"nested": { "path": "policies" },
									"aggs": { "ids": { "terms": { "field": "policies.id" } } }
								}
							}
						}
					}
				}`,
			expected: `{
					"aggs": {
						"policies": {
							"filter": { "match_all": {} },
							"aggs": { "names": { "terms": { "field": "policies.name" } } }
						},
						"other_agg": {
							"aggs": {
								"policies": {
									"filter": { "match_all": {} },
									"aggs": { "ids": { "terms": { "field": "policies.id" } } }
								}
							}
						}
					}
				}`,
		},
		{
			// False positive check: 'policies' agg without 'nested' should remain untouched
			name: "policies without nested (structure preserved)",
			input: `{
					"aggs": {
						"policies": {
							"filter": { "term": { "type": "network" } },
							"aggs": { "count": { "value_count": { "field": "action" } } }
						}
					}
				}`,
			expected: `{
					"aggs": {
						"policies": {
							"filter": { "term": { "type": "network" } },
							"aggs": { "count": { "value_count": { "field": "action" } } }
						}
					}
				}`,
		},
		{
			// Field replacement: policies.all_policies -> policies.enforced_policies
			name: "all_policies replacement (simple)",
			input: `{
					"aggs": {
						"policy_names": {
							"terms": { "field": "policies.all_policies" }
						}
					}
				}`,
			expected: `{
					"aggs": {
						"policy_names": {
							"terms": { "field": "policies.enforced_policies" }
						}
					}
				}`,
		},
		{
			// Field replacement: policies.all_policies -> policies.enforced_policies
			// for other aggregation types (cardinality, value_count, etc.)
			name: "all_policies replacement (other aggs)",
			input: `{
					"aggs": {
						"policy_count": {
							"cardinality": { "field": "policies.all_policies" }
						},
						"policy_values": {
							"value_count": { "field": "policies.all_policies" }
						}
					}
				}`,
			expected: `{
					"aggs": {
						"policy_count": {
							"cardinality": { "field": "policies.enforced_policies" }
						},
						"policy_values": {
							"value_count": { "field": "policies.enforced_policies" }
						}
					}
				}`,
		},
		{
			// Field replacement inside nested agg (not named 'policies')
			name: "nested all_policies replacement",
			input: `{
					"aggs": {
						"flog_buckets": {
							"aggs": {
								"my_policies": {
									"terms": { "field": "policies.all_policies" }
								}
							}
						}
					}
				}`,
			expected: `{
					"aggs": {
						"flog_buckets": {
							"aggs": {
								"my_policies": {
									"terms": { "field": "policies.enforced_policies" }
								}
							}
						}
					}
				}`,
		},
		{
			// Complex real-world case: composite + nested 'policies' + fields + parallel nested 'source_labels'
			name: "real world flow logs composite aggregation",
			input: `{
					"aggs": {
						"flog_buckets": {
							"composite": {
								"sources": [
									{"reporter": {"terms": {"field": "reporter"}}},
									{"action": {"terms": {"field": "action"}}}
								]
							},
							"aggs": {
								"policies": {
									"nested": {"path": "policies"},
									"aggs": {
										"by_tiered_policy": {
											"terms": {"field": "policies.all_policies"}
										}
									}
								},
								"source_labels": {
									"nested": {"path": "source_labels"},
									"aggs": {
										"by_kvpair": {"terms": {"field": "source_labels.labels"}}
									}
								}
							}
						}
					}
				}`,
			expected: `{
					"aggs": {
						"flog_buckets": {
							"composite": {
								"sources": [
									{"reporter": {"terms": {"field": "reporter"}}},
									{"action": {"terms": {"field": "action"}}}
								]
							},
							"aggs": {
								"policies": {
									"filter": {"match_all": {}},
									"aggs": {
										"by_tiered_policy": {
											"terms": {"field": "policies.enforced_policies"}
										}
									}
								},
								"source_labels": {
									"nested": {"path": "source_labels"},
									"aggs": {
										"by_kvpair": {"terms": {"field": "source_labels.labels"}}
									}
								}
							}
						}
					}
				}`,
		},
		{
			// Malformed JSON input - should return original input
			name:     "malformed json",
			input:    `{ "aggs": { "policies": { "nested": `, // Incomplete JSON
			expected: `{ "aggs": { "policies": { "nested": `,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputBytes := []byte(tt.input)

			// For malformed JSON, we expect exact string match since we can't unmarshal it
			if tt.name == "malformed json" {
				expectedBytes := []byte(tt.expected)
				outputBytes := transformPoliciesAggregation(inputBytes)
				assert.Equal(t, string(expectedBytes), string(outputBytes))
				return
			}

			// Compact expected for comparison
			var expectedObj map[string]interface{}
			_ = json.Unmarshal([]byte(tt.expected), &expectedObj)
			expectedNormalized, _ := json.Marshal(expectedObj)

			outputBytes := transformPoliciesAggregation(inputBytes)

			// Normalize output
			var outputObj map[string]interface{}
			err := json.Unmarshal(outputBytes, &outputObj)
			assert.NoError(t, err)
			outputNormalized, _ := json.Marshal(outputObj)

			assert.JSONEq(t, string(expectedNormalized), string(outputNormalized))
		})
	}
}
