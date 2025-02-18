package collections

var collectionFlows = Collection{
	name:                 CollectionNameFlows,
	defaultTimeFieldName: "start_time",
	fields: []CollectionField{
		collectionFieldGeneric{fieldType: FieldTypeDate, fieldName: "@timestamp", internal: true},
		collectionFieldGeneric{fieldName: "end_time", fieldType: FieldTypeDate},
		collectionFieldGeneric{fieldName: "start_time", fieldType: FieldTypeDate, filterDisabled: true},

		CollectionFieldEnum{fieldName: "action", fieldValues: []string{"allow", "deny"}},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "bytes_in"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "bytes_out"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_domains", filterDisabled: true},
		collectionFieldGeneric{fieldType: FieldTypeIP, fieldName: "dest_ip"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_labels.labels", internal: true},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_name"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_name_aggr"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_namespace"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "dest_port"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "dest_port_num"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_service_name"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_service_namespace"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_service_port"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_service_port_name"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "dest_service_port_num"},
		CollectionFieldEnum{fieldName: "dest_type", fieldValues: []string{"wep", "hep", "ns", "net"}},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "destination.bytes", internal: true},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "destination.packets", internal: true},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "destination.port", internal: true},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "host", filterDisabled: true},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "http_requests_allowed_in"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "http_requests_denied_in"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "nat_outgoing_ports", internal: true},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "network.protocol", internal: true},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "num_flows"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "num_flows_completed"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "num_flows_started"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "num_original_source_ips"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "num_process_args"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "num_process_ids"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "num_process_names"},
		collectionFieldGeneric{fieldType: FieldTypeIP, fieldName: "original_source_ips"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "packets_in"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "packets_out"},
		CollectionFieldEnum{fieldName: FieldNamePolicyType, fieldValues: []string{FieldPolicyStaged, FieldPolicyEnforced}, defaultValue: FieldPolicyEnforced},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "process_args"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "process_id"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "process_name"},
		CollectionFieldEnum{fieldName: "proto", fieldValues: []string{"icmp", "tcp", "udp", "ipip", "esp", "icmp6"}},
		CollectionFieldEnum{fieldName: "reporter", fieldValues: []string{"src", "dst"}},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "source.bytes", internal: true},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "source.packets", internal: true},
		collectionFieldGeneric{fieldType: FieldTypeIP, fieldName: "source_ip"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "source_labels.labels", internal: true},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "source_name"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "source_name_aggr"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "source_namespace"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "source_port"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "source_port_num"},
		CollectionFieldEnum{fieldName: "source_type", fieldValues: []string{"wep", "hep", "ns", "net"}},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "tcp_lost_packets", filterDisabled: true},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "tcp_max_min_rtt", filterDisabled: true},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "tcp_max_smooth_rtt", filterDisabled: true},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "tcp_mean_min_rtt", filterDisabled: true},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "tcp_mean_mss", filterDisabled: true},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "tcp_mean_send_congestion_window", filterDisabled: true},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "tcp_mean_smooth_rtt", filterDisabled: true},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "tcp_min_mss", filterDisabled: true},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "tcp_min_send_congestion_window", filterDisabled: true},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "tcp_total_retransmissions", filterDisabled: true},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "tcp_unrecovered_to", filterDisabled: true},
	},
	groupBys: []GroupBy{
		groupBy{
			field: "end_time",
			nested: []GroupBy{
				groupBy{field: "action"},
			},
		},
		groupBy{
			field: "start_time",
			nested: []GroupBy{
				groupBy{field: "host"},
				groupBy{field: "dest_namespace"},
				groupBy{field: "source_namespace"},
			},
		},
		groupBy{
			field: "source_namespace",
			nested: []GroupBy{
				groupBy{
					field: "source_name_aggr",
					nested: []GroupBy{
						groupBy{
							field: "dest_domains",
							nested: []GroupBy{
								groupBy{
									field:  "dest_port",
									nested: []GroupBy{},
								},
							},
						},
						groupBy{
							field: "dest_namespace",
							nested: []GroupBy{
								groupBy{
									field: "dest_name_aggr",
									nested: []GroupBy{
										groupBy{
											field:  "dest_port",
											nested: []GroupBy{},
										},
									},
								},
							},
						},
						groupBy{
							field: "source_name",
							nested: []GroupBy{
								groupBy{
									field: "dest_namespace",
									nested: []GroupBy{
										groupBy{
											field: "dest_name_aggr",
											nested: []GroupBy{
												groupBy{
													field:  "dest_name",
													nested: []GroupBy{},
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
		},
		groupBy{
			field: "dest_ip",
			nested: []GroupBy{
				groupBy{
					field: "dest_domains",
					nested: []GroupBy{
						groupBy{
							field: "dest_port",
						},
					},
				},
			},
		},
		groupBy{
			field: "source_name",
			nested: []GroupBy{
				groupBy{field: "dest_name"},
			},
		},
		groupBy{
			field: "process_id",
			nested: []GroupBy{
				groupBy{
					field: "process_name",
					nested: []GroupBy{
						groupBy{
							field: "process_args",
						},
					},
				},
			},
		},
		groupBy{field: "dest_namespace"},
		groupBy{field: "dest_domains"},
		groupBy{field: "dest_port"},
		groupBy{field: "source_ip"},
		groupBy{field: "source_name_aggr"},
		groupBy{field: "host"},
	},
}
