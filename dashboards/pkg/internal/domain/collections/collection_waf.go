package collections

var collectionWAF = Collection{
	name:                 CollectionName("waf"),
	defaultTimeFieldName: "@timestamp",
	fields: []CollectionField{
		collectionFieldGeneric{fieldName: "@timestamp", fieldType: FieldTypeDate},

		collectionFieldGeneric{
			fieldName: "source.ip",
			fieldType: FieldTypeIP,
		},
		collectionFieldGeneric{
			fieldName:      "source.name",
			fieldType:      FieldTypeText,
			filterDisabled: true,
		},
		collectionFieldGeneric{
			fieldName:      "source.namespace",
			fieldType:      FieldTypeText,
			filterDisabled: true,
		},
		collectionFieldGeneric{
			fieldName: "source.port_num",
			fieldType: FieldTypeNumber,
		},
		collectionFieldGeneric{
			fieldName: "destination.ip",
			fieldType: FieldTypeIP,
		},
		collectionFieldGeneric{
			fieldName:      "destination.name",
			fieldType:      FieldTypeText,
			filterDisabled: true,
		},
		collectionFieldGeneric{
			fieldName:      "destination.namespace",
			fieldType:      FieldTypeText,
			filterDisabled: true,
		},
		collectionFieldGeneric{
			fieldName: "destination.port_num",
			fieldType: FieldTypeNumber,
		},
		collectionFieldGeneric{
			fieldName:      "level",
			fieldType:      FieldTypeText,
			filterDisabled: true,
		},
		collectionFieldGeneric{
			fieldName: "method",
			fieldType: FieldTypeText,
		},
		collectionFieldGeneric{
			fieldName:      "msg",
			fieldType:      FieldTypeText,
			filterDisabled: true,
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
			fieldName:      "request_id",
			fieldType:      FieldTypeText,
			filterDisabled: true,
		},
		collectionFieldGeneric{
			fieldName: "rules",
			fieldType: FieldTypeText,
		},
		collectionFieldGeneric{
			fieldName:      "host",
			fieldType:      FieldTypeText,
			filterDisabled: true,
		},
		collectionFieldGeneric{
			fieldName:      "gateway_name",
			fieldType:      FieldTypeText,
			filterDisabled: true,
		},
		collectionFieldGeneric{
			fieldName:      "gateway_namespace",
			fieldType:      FieldTypeText,
			filterDisabled: true,
		},

		collectionFieldGeneric{
			fieldName:      "cluster",
			fieldType:      FieldTypeText,
			filterDisabled: true,
		},
		collectionFieldGeneric{
			fieldName:      "generated_time",
			fieldType:      FieldTypeDate,
			filterDisabled: true,
		},
	},
	groupBys: []GroupBy{
		groupBy{
			field: "source.namespace",
			nested: []GroupBy{
				groupBy{
					field:  "source.name",
					nested: []GroupBy{},
				},
				groupBy{
					field: "destination.namespace",
					nested: []GroupBy{
						groupBy{
							field:  "destination.name",
							nested: []GroupBy{},
						},
					},
				},
			},
		},
		groupBy{field: "source.ip"},
		groupBy{field: "source.port_num"},
		groupBy{field: "destination.ip"},
		groupBy{field: "destination.name"},
		groupBy{field: "destination.namespace"},
		groupBy{field: "destination.port_num"},

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
