package collections

var collectionL7 = Collection{
	name:                 CollectionNameL7,
	defaultTimeFieldName: "@timestamp",
	fields: []CollectionField{
		{fieldType: FieldTypeDate, fieldName: "@timestamp"},
		{fieldType: FieldTypeNumber, fieldName: "bytes_in"},
		{fieldType: FieldTypeNumber, fieldName: "bytes_out"},
		{fieldType: FieldTypeText, fieldName: "dest_name"},
		{fieldType: FieldTypeText, fieldName: "dest_name_aggr"},
		{fieldType: FieldTypeText, fieldName: "dest_namespace"},
		{fieldType: FieldTypeNumber, fieldName: "dest_port_num"},
		{fieldType: FieldTypeText, fieldName: "dest_service_name"},
		{fieldType: FieldTypeText, fieldName: "dest_service_namespace"},
		{fieldType: FieldTypeText, fieldName: "dest_service_port"},
		{fieldType: FieldTypeText, fieldName: "dest_service_port_name"},
		{fieldType: FieldTypeNumber, fieldName: "dest_service_port"},
		{fieldType: FieldTypeText, fieldName: "host"},
		{fieldType: FieldTypeText, fieldName: "method"},
		{fieldType: FieldTypeText, fieldName: "url"},
		{fieldType: FieldTypeText, fieldName: "user_agent"},
	},
}
