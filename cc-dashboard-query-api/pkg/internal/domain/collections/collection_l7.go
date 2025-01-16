package collections

var collectionL7 = Collection{
	name:                 CollectionNameL7,
	defaultTimeFieldName: "start_time",
	fields: []CollectionField{
		collectionFieldGeneric{fieldType: FieldTypeDate, fieldName: "@timestamp", internal: true},
		collectionFieldGeneric{fieldName: "end_time", fieldType: FieldTypeDate},
		collectionFieldGeneric{fieldName: "start_time", fieldType: FieldTypeDate, filterDisabled: true},

		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "bytes_in"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "bytes_out"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_name"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_name_aggr"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_namespace"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "dest_port_num"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_service_name"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_service_namespace"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "dest_service_port"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "dest_service_port_name"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "duration_mean", filterDisabled: true},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "host"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "method"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "response_code", filterDisabled: true},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "url"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "user_agent"},
	},
}
