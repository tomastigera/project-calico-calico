package collections

var collectionL7 = Collection{
	name:                 CollectionNameL7,
	defaultTimeFieldName: "start_time",
	fields: []CollectionField{
		collectionFieldGeneric{fieldName: "end_time", fieldType: FieldTypeDate},
		collectionFieldGeneric{fieldName: "start_time", fieldType: FieldTypeDate},

		collectionFieldGeneric{
			fieldName: "bytes_in",
			fieldType: FieldTypeNumber,
			aggregationFunctionTypes: []AggregationFunctionType{
				AggregationFunctionTypeSum,
			},
		},
		collectionFieldGeneric{
			fieldName: "bytes_out",
			fieldType: FieldTypeNumber,
			aggregationFunctionTypes: []AggregationFunctionType{
				AggregationFunctionTypeSum,
			},
		},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "cluster", filterDisabled: true},
		collectionFieldGeneric{
			fieldName: "count",
			fieldType: FieldTypeNumber,
			aggregationFunctionTypes: []AggregationFunctionType{
				AggregationFunctionTypeSum,
			},
		},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_name"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_name_aggr"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_namespace"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "dest_port_num"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_service_name"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_service_namespace"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "dest_service_port"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_service_port_name"},
		collectionFieldGeneric{
			fieldName: "duration_max",
			fieldType: FieldTypeNumber,
			aggregationFunctionTypes: []AggregationFunctionType{
				AggregationFunctionTypeAvg,
			},
		},
		collectionFieldGeneric{
			fieldName: "duration_mean",
			fieldType: FieldTypeNumber,
			aggregationFunctionTypes: []AggregationFunctionType{
				AggregationFunctionTypeAvg,
			}},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "gateway_class"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "gateway_listener_full_name"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "gateway_name"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "gateway_namespace"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "gateway_route_name"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "gateway_route_namespace"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "gateway_route_status"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "gateway_route_type"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "gateway_status"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "host"},
		collectionFieldGeneric{
			fieldName: "latency",
			fieldType: FieldTypeNumber,
			aggregationFunctionTypes: []AggregationFunctionType{
				AggregationFunctionTypeAvg,
			},
		},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "method"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "response_code"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "route_name"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "type"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "url"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "user_agent"},
	},
	groupBys: []GroupBy{
		groupBy{
			field: "dest_service_name",
			nested: []GroupBy{
				groupBy{field: "method"},
				groupBy{field: "response_code"},
			},
		},
		groupBy{
			field: "start_time",
			nested: []GroupBy{
				groupBy{field: "dest_service_name"},
				groupBy{field: "gateway_route_name"},
			},
		},
		groupBy{field: "route_name"},
		groupBy{field: "cluster"},
		groupBy{field: "response_code"},
		groupBy{field: "method"},
		groupBy{field: "url"},
		// Ingress Gateway dashboard groupBys
		groupBy{
			field: "gateway_namespace",
			nested: []GroupBy{
				groupBy{
					field: "gateway_name",
					nested: []GroupBy{
						groupBy{
							field: "gateway_listener_full_name",
							nested: []GroupBy{
								// For Gateways table: gateway_namespace -> gateway_name -> gateway_listener_full_name -> host -> gateway_class -> gateway_status
								groupBy{
									field: "host",
									nested: []GroupBy{
										groupBy{
											field: "gateway_class",
											nested: []GroupBy{
												groupBy{field: "gateway_status"},
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
		// RS-2936: Routes table mockup order - gateway_route_type first
		// gateway_route_type -> gateway_route_namespace -> gateway_route_name -> gateway_namespace -> gateway_name -> gateway_listener_full_name -> dest_service_name -> dest_port_num -> gateway_route_status
		groupBy{
			field: "gateway_route_type",
			nested: []GroupBy{
				groupBy{
					field: "gateway_route_namespace",
					nested: []GroupBy{
						groupBy{
							field: "gateway_route_name",
							nested: []GroupBy{
								groupBy{
									field: "gateway_namespace",
									nested: []GroupBy{
										groupBy{
											field: "gateway_name",
											nested: []GroupBy{
												groupBy{
													field: "gateway_listener_full_name",
													nested: []GroupBy{
														groupBy{
															field: "dest_service_name",
															nested: []GroupBy{
																groupBy{
																	field: "dest_port_num",
																	nested: []GroupBy{
																		groupBy{field: "gateway_route_status"},
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
						},
					},
				},
			},
		},
		// RS-2936: Traffic Performance table mockup order with start_time
		// start_time -> gateway_namespace -> gateway_name -> gateway_listener_full_name -> gateway_route_type -> gateway_route_namespace -> gateway_route_name -> dest_service_name -> dest_port_num -> response_code
		groupBy{
			field: "start_time",
			nested: []GroupBy{
				groupBy{
					field: "gateway_namespace",
					nested: []GroupBy{
						groupBy{
							field: "gateway_name",
							nested: []GroupBy{
								groupBy{
									field: "gateway_listener_full_name",
									nested: []GroupBy{
										groupBy{
											field: "gateway_route_type",
											nested: []GroupBy{
												groupBy{
													field: "gateway_route_namespace",
													nested: []GroupBy{
														groupBy{
															field: "gateway_route_name",
															nested: []GroupBy{
																groupBy{
																	field: "dest_service_name",
																	nested: []GroupBy{
																		groupBy{
																			field: "dest_port_num",
																			nested: []GroupBy{
																				groupBy{field: "response_code"},
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
								},
							},
						},
					},
				},
			},
		},
	},
}
