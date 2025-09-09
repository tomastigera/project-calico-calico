package collections

var collectionWAF = Collection{
	name:                 CollectionName("waf"),
	defaultTimeFieldName: "timestamp",
	fields: []CollectionField{
		collectionFieldGeneric{fieldName: "timestamp", fieldType: FieldTypeDate},

		collectionFieldGeneric{
			fieldName: "source.ip",
			fieldType: FieldTypeIP,
		},
		collectionFieldGeneric{
			fieldName: "source.pod_name",
			fieldType: FieldTypeText,
		},
		collectionFieldGeneric{
			fieldName: "source.pod_namespace",
			fieldType: FieldTypeText,
		},
		collectionFieldGeneric{
			fieldName: "source.port_num",
			fieldType: FieldTypeNumber,
		},
		collectionFieldGeneric{
			fieldName: "source.hostname",
			fieldType: FieldTypeText,
		},

		collectionFieldGeneric{
			fieldName: "destination.ip",
			fieldType: FieldTypeIP,
		},
		collectionFieldGeneric{
			fieldName: "destination.pod_name",
			fieldType: FieldTypeText,
		},
		collectionFieldGeneric{
			fieldName: "destination.pod_namespace",
			fieldType: FieldTypeText,
		},
		collectionFieldGeneric{
			fieldName: "destination.port_num",
			fieldType: FieldTypeNumber,
		},
		collectionFieldGeneric{
			fieldName: "destination.hostname",
			fieldType: FieldTypeText,
		},

		collectionFieldGeneric{
			fieldName: "level",
			fieldType: FieldTypeText,
		},
		collectionFieldGeneric{
			fieldName: "method",
			fieldType: FieldTypeText,
		},
		collectionFieldGeneric{
			fieldName: "msg",
			fieldType: FieldTypeText,
		},
		collectionFieldGeneric{
			fieldName: "path",
			fieldType: FieldTypeText,
		},
		collectionFieldGeneric{
			fieldName: "protocol",
			fieldType: FieldTypeText,
		},
		collectionFieldGeneric{
			fieldName: "request_id",
			fieldType: FieldTypeText,
		},
		collectionFieldGeneric{
			fieldName: "rule_info",
			fieldType: FieldTypeText,
		},
		collectionFieldGeneric{
			fieldName: "host",
			fieldType: FieldTypeText,
		},
		collectionFieldGeneric{
			fieldName: "gateway_name",
			fieldType: FieldTypeText,
		},
		collectionFieldGeneric{
			fieldName: "gateway_namespace",
			fieldType: FieldTypeText,
		},

		collectionFieldGeneric{
			fieldName: "cluster",
			fieldType: FieldTypeText,
		},
		collectionFieldGeneric{
			fieldName: "generated_time",
			fieldType: FieldTypeDate,
		},
	},
	groupBys: []GroupBy{
		groupBy{
			field: "source.pod_namespace",
			nested: []GroupBy{
				groupBy{
					field: "source.pod_name",
					nested: []GroupBy{
						groupBy{
							field:  "source.hostname",
							nested: []GroupBy{},
						},
					},
				},
				groupBy{
					field: "destination.pod_namespace",
					nested: []GroupBy{
						groupBy{
							field:  "destination.pod_name",
							nested: []GroupBy{},
						},
					},
				},
			},
		},
		groupBy{field: "source.ip"},
		groupBy{field: "source.port_num"},
		groupBy{field: "source.hostname"},
		groupBy{field: "destination.ip"},
		groupBy{field: "destination.pod_name"},
		groupBy{field: "destination.pod_namespace"},
		groupBy{field: "destination.port_num"},
		groupBy{field: "destination.hostname"},

		groupBy{field: "level"},
		groupBy{field: "method"},
		groupBy{field: "path"},
		groupBy{field: "protocol"},
		groupBy{field: "rule_info"},
		groupBy{field: "host"},
		groupBy{field: "gateway_name"},
		groupBy{field: "gateway_namespace"},

		groupBy{field: "cluster"},
	},
}
