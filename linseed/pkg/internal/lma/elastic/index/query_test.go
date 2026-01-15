// Copyright 2021 Tigera Inc. All rights reserved.
package index_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/linseed/pkg/internal/lma/elastic/index"
)

var _ = Describe("Query Converter", func() {
	Context("Alerts", func() {
		It("should return an error if the key is invalid", func() {
			query := "invalid_key=allow"
			_, err := MultiIndexAlerts().NewSelectorQuery(query)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(Equal("Invalid selector (invalid_key=allow) in request: invalid key: invalid_key"))
		})

		It("should handle a simple clause", func() {
			result := JsonObject{
				"term": JsonObject{
					"origin": JsonObject{
						"value": "aval1",
					},
				},
			}
			query := "origin=aval1"
			esquery, err := MultiIndexAlerts().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})

		It("should handle an AND clause", func() {
			result := JsonObject{
				"bool": JsonObject{
					"must": []JsonObject{
						{
							"term": JsonObject{
								"origin": JsonObject{
									"value": "aval1",
								},
							},
						},
						{
							"term": JsonObject{
								"type": JsonObject{
									"value": "global_alert",
								},
							},
						},
					},
				},
			}

			query := "origin=aval1 AND type=global_alert"
			esquery, err := MultiIndexAlerts().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})

		It("should handle an OR clause", func() {
			result := JsonObject{
				"bool": JsonObject{
					"should": []JsonObject{
						{
							"term": JsonObject{
								"origin": JsonObject{
									"value": "aval1",
								},
							},
						},
						{
							"term": JsonObject{
								"type": JsonObject{
									"value": "global_alert",
								},
							},
						},
					},
				},
			}
			query := "origin=aval1 OR type=global_alert"
			esquery, err := MultiIndexAlerts().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})

		It("should handle an composite clause", func() {
			result := JsonObject{
				"bool": JsonObject{
					"must": []JsonObject{
						{
							"bool": JsonObject{
								"should": []JsonObject{
									{
										"term": JsonObject{
											"origin": JsonObject{
												"value": "aval1",
											},
										},
									},
									{
										"term": JsonObject{
											"type": JsonObject{
												"value": "global_alert",
											},
										},
									},
								},
							},
						},
						{
							"term": JsonObject{
								"host": JsonObject{
									"value": "hostval",
								},
							},
						},
					},
				},
			}
			query := "(origin=aval1 OR type=global_alert) AND host=hostval"
			esquery, err := MultiIndexAlerts().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})

		It("should handle a clause to filter DNS queries", func() {
			// This test simulate a filter query done on the UI to filter alerts related to DNS query.
			// Currently these are implemented using the "filter" param handled by ui-apis for /events/search
			// and we want to let linseed handle them with a POST /events (List) query using a selector
			// to capture the same logic.
			//
			// Existing "filter" param sample value:
			// [
			// 	{
			// 		"terms":{
			// 			"type":[
			// 				"suspicious_dns_query",
			// 				"gtf_suspicious_dns_query"
			// 			]
			// 		}
			// 	},
			// 	{
			// 		"wildcard":{
			// 			"source_name":"*basic-123*"
			// 		}
			// 	},
			// 	{
			// 		"wildcard":{
			// 			"source_namespace":"*default*"
			// 		}
			// 	},
			// 	{
			// 		"range":{
			// 			"source_ip":{
			// 				"gte":"172.16.0.0",
			// 				"lte":"172.32.0.0"
			// 			}
			// 		}
			// 	},
			// 	{
			// 		"terms":{
			// 			"suspicious_domains":[
			// 				"sysdig.com", "cilium.com"
			// 			]
			// 		}
			// 	}
			// ]

			// A few observations to keep the same logic using a selector:
			//
			// 1. The filter for "source_namespace" use a wildcard query and adds * before and  after a user input.
			//    For example, user input "default" will generate the following filter:
			// {
			// 		"wildcard":{
			// 			"source_namespace":"*default*"
			// 		}
			// 	},
			//    Selector "source_namespace = default" generates:
			//  {
			//      "term":{
			// 	        "source_name":{
			// 		        "value": "default"
			// 	        }
			//      }
			//   },
			//    which won't achieve the same result as it looks for an exact match.
			//    Instead, we need to use the IN operator with a set containing one element
			//    in order to generate a wildcard query.
			//    Selector "source_namespace IN {'default'}" produces the following filters:
			//  {
			//      "bool":{
			//      	"should": [
			//      		{
			//      			"wildcard":{
			//      				"source_namespace":{
			//      					"value": "default"
			//      				}
			//      			}
			//      		}
			//      	]
			//      },
			//  },
			//
			// 2. The filter for source_ip used in the UI
			// {
			// 		"range":{
			// 			"source_ip":{
			// 				"gte":"172.16.0.0",
			// 				"lte":"172.32.0.0"
			// 			}
			// 		}
			// 	},
			//   can be achieved with a selector "'source_ip' >= '172.16.0.0' AND source_ip <= '172.32.0.0'"
			//   that generates the following terms
			// {
			// 		"range":{
			// 			"source_ip":{
			// 				"gte":"172.16.0.0",
			// 			}
			// 		}
			// 	},
			// {
			// 		"range":{
			// 			"source_ip":{
			// 				"lte":"172.32.0.0"
			// 			}
			// 		}
			// 	},
			//
			// 3. Filter with multiple values use a terms query what we don't support.
			//    Sample filter with multiple values generated by the UI:
			// 	{
			// 		"terms":{
			// 			"suspicious_domains":[
			// 				"sysdig.com", "cilium.com"
			// 			]
			// 		}
			// 	}
			//    This can be emulated with a selector like "suspicious_domains in {'sysdig.com','cilium.io'}"
			//    that generates the following filters:
			// {
			// 	"bool": {
			// 		"should": []{
			// 			{
			// 				"wildcard": {
			// 					"suspicious_domains": {
			// 						"value": "sysdig.com"
			// 					}
			// 				}
			// 			},
			// 			{
			// 				"wildcard": {
			// 					"suspicious_domains": {
			// 						"value": "cilium.io"
			// 					}
			// 				}
			// 			}
			// 		}
			// 	}
			// }

			result := JsonObject{
				"bool": JsonObject{
					"must": []JsonObject{
						{
							"bool": JsonObject{
								"should": []JsonObject{
									{
										"wildcard": JsonObject{
											"type": JsonObject{
												"value": "suspicious_dns_query",
											},
										},
									},
									{
										"wildcard": JsonObject{
											"type": JsonObject{
												"value": "gtf_suspicious_dns_query",
											},
										},
									},
								},
							},
						},
						{
							"bool": JsonObject{
								"should": []JsonObject{
									{
										"wildcard": JsonObject{
											"source_name": JsonObject{
												"value": "*basic-123*",
											},
										},
									},
								},
							},
						},
						{
							"bool": JsonObject{
								"should": []JsonObject{
									{
										"wildcard": JsonObject{
											"source_namespace": JsonObject{
												"value": "*default*",
											},
										},
									},
								},
							},
						},
						{
							"range": JsonObject{
								"source_ip": JsonObject{
									"gte": "172.16.0.0",
								},
							},
						},
						{
							"range": JsonObject{
								"source_ip": JsonObject{
									"lte": "172.32.0.0",
								},
							},
						},
						{
							"bool": JsonObject{
								"should": []JsonObject{
									{
										"wildcard": JsonObject{
											"suspicious_domains": JsonObject{
												"value": "sysdig.com",
											},
										},
									},
									{
										"wildcard": JsonObject{
											"suspicious_domains": JsonObject{
												"value": "cilium.io",
											},
										},
									},
								},
							},
						},
					},
				},
			}

			query := "type IN { suspicious_dns_query, gtf_suspicious_dns_query} AND " +
				"\"source_name\" IN {\"*basic-123*\"} AND \"source_namespace\" IN {\"*default*\"} AND " +
				"'source_ip' >= '172.16.0.0' AND source_ip <= '172.32.0.0' and " +
				"suspicious_domains in {'sysdig.com','cilium.io'}"
			esquery, err := MultiIndexAlerts().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})
	})

	Context("Dns", func() {
		It("should return an error if the key is invalid", func() {
			query := "invalid_key=allow"
			_, err := MultiIndexDNSLogs().NewSelectorQuery(query)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(Equal("Invalid selector (invalid_key=allow) in request: " +
				"invalid key: invalid_key"))
		})

		It("should return an error if the value is invalid", func() {
			query := "client_ip=invalid_value"
			_, err := MultiIndexDNSLogs().NewSelectorQuery(query)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(Equal("Invalid selector (client_ip=invalid_value) in request: " +
				"invalid value for client_ip: invalid_value"))
		})

		It("should handle a simple clause", func() {
			result := JsonObject{
				"term": JsonObject{
					"client_ip": JsonObject{
						"value": "1.0.1.5",
					},
				},
			}
			query := "client_ip=\"1.0.1.5\""
			esquery, err := MultiIndexDNSLogs().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})

		It("should handle an AND clause", func() {
			result := JsonObject{
				"bool": JsonObject{
					"must": []JsonObject{
						{
							"term": JsonObject{
								"start_time": JsonObject{
									"value": "2006-01-02 15:04:05",
								},
							},
						},
						{
							"term": JsonObject{
								"client_ip": JsonObject{
									"value": "10.0.0.1",
								},
							},
						},
					},
				},
			}

			query := "start_time=\"2006-01-02 15:04:05\" AND client_ip=\"10.0.0.1\""
			esquery, err := MultiIndexDNSLogs().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})

		It("should handle an OR clause", func() {
			result := JsonObject{
				"bool": JsonObject{
					"should": []JsonObject{
						{
							"term": JsonObject{
								"qname": JsonObject{
									"value": "http://www.yolo.com",
								},
							},
						},
						{
							"term": JsonObject{
								"count": JsonObject{
									"value": "5",
								},
							},
						},
					},
				},
			}
			query := "qname=\"http://www.yolo.com\" OR count=5"
			esquery, err := MultiIndexDNSLogs().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})

		It("should handle an composite clause", func() {
			result := JsonObject{
				"bool": JsonObject{
					"must": []JsonObject{
						{
							"bool": JsonObject{
								"should": []JsonObject{
									{
										"term": JsonObject{
											"end_time": JsonObject{
												"value": "2006-01-02 15:04:05",
											},
										},
									},
									{
										"term": JsonObject{
											"count": JsonObject{
												"value": "225",
											},
										},
									},
								},
							},
						},
						{
							"term": JsonObject{
								"client_ip": JsonObject{
									"value": "192.168.2.1",
								},
							},
						},
					},
				},
			}
			query := "(end_time=\"2006-01-02 15:04:05\" OR count=225) AND client_ip=\"192.168.2.1\""
			esquery, err := MultiIndexDNSLogs().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})

		It("should handle a nested fields clause", func() {
			result := JsonObject{
				"bool": JsonObject{
					"should": []JsonObject{
						{
							"nested": JsonObject{
								"path": "servers",
								"query": JsonObject{
									"term": JsonObject{
										"servers.name": JsonObject{
											"value": "my-server",
										},
									},
								},
							},
						},
						{
							"nested": JsonObject{
								"path": "rrsets",
								"query": JsonObject{
									"bool": JsonObject{
										"should": []JsonObject{
											{
												"wildcard": JsonObject{
													"rrsets.name": JsonObject{
														"value": "*hostname*",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			}

			query := "\"servers.name\" = \"my-server\" OR \"rrsets.name\" IN {\"*hostname*\"}"
			esquery, err := MultiIndexDNSLogs().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})
	})

	Context("Flow", func() {
		It("should return an error if the key is invalid", func() {
			query := "invalid_key=allow"
			_, err := MultiIndexFlowLogs().NewSelectorQuery(query)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(Equal("Invalid selector (invalid_key=allow) in request: " +
				"invalid key: invalid_key"))
		})

		It("should handle a simple clause", func() {
			result := JsonObject{
				"term": JsonObject{
					"action": JsonObject{
						"value": "allow",
					},
				},
			}
			query := "action=allow"
			esquery, err := MultiIndexFlowLogs().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})

		It("should handle an AND clause", func() {
			result := JsonObject{
				"bool": JsonObject{
					"must": []JsonObject{
						{
							"term": JsonObject{
								"action": JsonObject{
									"value": "allow",
								},
							},
						},
						{
							"term": JsonObject{
								"action": JsonObject{
									"value": "deny",
								},
							},
						},
					},
				},
			}

			query := "action=allow AND action=deny"
			esquery, err := MultiIndexFlowLogs().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})

		It("should handle an OR clause", func() {
			result := JsonObject{
				"bool": JsonObject{
					"should": []JsonObject{
						{
							"term": JsonObject{
								"action": JsonObject{
									"value": "allow",
								},
							},
						},
						{
							"term": JsonObject{
								"action": JsonObject{
									"value": "deny",
								},
							},
						},
					},
				},
			}
			query := "action=allow OR action=deny"
			esquery, err := MultiIndexFlowLogs().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})

		It("should handle a policies clause", func() {
			result := JsonObject{
				"term": JsonObject{
					"policies.all_policies": JsonObject{
						"value": "mypolicy",
					},
				},
			}
			query := "\"policies.all_policies\"=mypolicy"
			esquery, err := MultiIndexFlowLogs().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})

		It("should handle a enforced policies clause", func() {
			result := JsonObject{
				"term": JsonObject{
					"policies.enforced_policies": JsonObject{
						"value": "mypolicy",
					},
				},
			}
			query := "\"policies.enforced_policies\"=mypolicy"
			esquery, err := MultiIndexFlowLogs().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})

		It("should handle a pending policies clause", func() {
			result := JsonObject{
				"term": JsonObject{
					"policies.pending_policies": JsonObject{
						"value": "mypolicy",
					},
				},
			}
			query := "\"policies.pending_policies\"=mypolicy"
			esquery, err := MultiIndexFlowLogs().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})

		It("should handle a transit policies clause", func() {
			result := JsonObject{
				"term": JsonObject{
					"policies.transit_policies": JsonObject{
						"value": "mypolicy",
					},
				},
			}
			query := "\"policies.transit_policies\"=mypolicy"
			esquery, err := MultiIndexFlowLogs().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})

		It("should handle an composite clause", func() {
			result := JsonObject{
				"bool": JsonObject{
					"must": []JsonObject{
						{
							"bool": JsonObject{
								"should": []JsonObject{
									{
										"term": JsonObject{
											"action": JsonObject{
												"value": "allow",
											},
										},
									},
									{
										"term": JsonObject{
											"action": JsonObject{
												"value": "deny",
											},
										},
									},
								},
							},
						},
						{
							"term": JsonObject{
								"action": JsonObject{
									"value": "deny",
								},
							},
						},
					},
				},
			}
			query := "(action=allow OR action=deny) AND action=deny"
			esquery, err := MultiIndexFlowLogs().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})

		It("should handle a nested fields clause", func() {
			result := JsonObject{
				"bool": JsonObject{
					"should": []JsonObject{
						{
							"nested": JsonObject{
								"path": "dest_labels",
								"query": JsonObject{
									"term": JsonObject{
										"dest_labels.labels": JsonObject{
											"value": "my-label=value",
										},
									},
								},
							},
						},
						{
							"nested": JsonObject{
								"path": "source_labels",
								"query": JsonObject{
									"bool": JsonObject{
										"should": []JsonObject{
											{
												"wildcard": JsonObject{
													"source_labels.labels": JsonObject{
														"value": "*__PROFILE__*",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			}

			query := "\"dest_labels.labels\" = \"my-label=value\" OR \"source_labels.labels\" IN {\"*__PROFILE__*\"}"
			esquery, err := MultiIndexFlowLogs().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})
	})

	Context("L7", func() {
		It("should return an error if the key is invalid", func() {
			query := "invalid_key=allow"
			_, err := SingleIndexL7Logs().NewSelectorQuery(query)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(Equal("Invalid selector (invalid_key=allow) in request: " +
				"invalid key: invalid_key"))
		})

		It("should return an error if the value is invalid", func() {
			query := "source_type=invalid_value"
			_, err := SingleIndexL7Logs().NewSelectorQuery(query)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(Equal("Invalid selector (source_type=invalid_value) in request: " +
				"invalid value for source_type: invalid_value"))
		})

		It("should handle a simple clause", func() {
			result := JsonObject{
				"term": JsonObject{
					"source_type": JsonObject{
						"value": "wep",
					},
				},
			}
			query := "source_type=wep"
			esquery, err := SingleIndexL7Logs().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})

		It("should handle an AND clause", func() {
			result := JsonObject{
				"bool": JsonObject{
					"must": []JsonObject{
						{
							"term": JsonObject{
								"duration_mean": JsonObject{
									"value": "50",
								},
							},
						},
						{
							"term": JsonObject{
								"dest_type": JsonObject{
									"value": "net",
								},
							},
						},
					},
				},
			}

			query := "duration_mean=50 AND dest_type=net"
			esquery, err := SingleIndexL7Logs().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})

		It("should handle an OR clause", func() {
			result := JsonObject{
				"bool": JsonObject{
					"should": []JsonObject{
						{
							"term": JsonObject{
								"url": JsonObject{
									"value": "http://www.yolo.com",
								},
							},
						},
						{
							"term": JsonObject{
								"dest_service_port_num": JsonObject{
									"value": "65535",
								},
							},
						},
					},
				},
			}
			query := "url=\"http://www.yolo.com\" OR dest_service_port_num=65535"
			esquery, err := SingleIndexL7Logs().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})

		It("should handle an composite clause", func() {
			result := JsonObject{
				"bool": JsonObject{
					"must": []JsonObject{
						{
							"bool": JsonObject{
								"should": []JsonObject{
									{
										"term": JsonObject{
											"url": JsonObject{
												"value": "http://www.yolo.com",
											},
										},
									},
									{
										"term": JsonObject{
											"method": JsonObject{
												"value": "methodval",
											},
										},
									},
								},
							},
						},
						{
							"term": JsonObject{
								"dest_type": JsonObject{
									"value": "ns",
								},
							},
						},
					},
				},
			}
			query := "(url=\"http://www.yolo.com\" OR method=methodval) AND dest_type=ns"
			esquery, err := SingleIndexL7Logs().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})
	})

	Context("WAF", func() {
		It("should handle a nested fields clause", func() {
			result := JsonObject{
				"bool": JsonObject{
					"should": []JsonObject{
						{
							"nested": JsonObject{
								"path": "rules",
								"query": JsonObject{
									"term": JsonObject{
										"rules.message": JsonObject{
											"value": "waf-message",
										},
									},
								},
							},
						},
						{
							"nested": JsonObject{
								"path": "rules",
								"query": JsonObject{
									"bool": JsonObject{
										"should": []JsonObject{
											{
												"wildcard": JsonObject{
													"rules.file": JsonObject{
														"value": "*filename*",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			}

			query := "\"rules.message\" = \"waf-message\" OR \"rules.file\" IN {\"*filename*\"}"
			esquery, err := SingleIndexWAFLogs().NewSelectorQuery(query)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(esquery.Source()).Should(BeEquivalentTo(result))
		})
	})
})
