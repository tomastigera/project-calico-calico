package collections

var collectionDNS = Collection{
	name:                 CollectionNameDNS,
	defaultTimeFieldName: "start_time",
	fields: []CollectionField{
		collectionFieldGeneric{fieldType: FieldTypeDate, fieldName: "@timestamp", internal: true},
		collectionFieldGeneric{fieldName: "end_time", fieldType: FieldTypeDate},
		collectionFieldGeneric{fieldName: "start_time", fieldType: FieldTypeDate, filterDisabled: true},

		collectionFieldGeneric{fieldType: FieldTypeIP, fieldName: "client_ip"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "client_name"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "client_name_aggr"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "client_namespace"},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "count"},
		collectionFieldGeneric{fieldType: FieldTypeDate, fieldName: "generated_time", internal: true},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "host", internal: true},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "latency_count", internal: true},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "latency_max", internal: true},
		collectionFieldGeneric{fieldType: FieldTypeNumber, fieldName: "latency_mean", internal: true},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "qclass"},
		collectionFieldGeneric{fieldType: FieldTypeQName, fieldName: "qname", displayFieldType: FieldTypeText},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "qtype"},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "rcode"},
		collectionFieldGeneric{fieldType: FieldTypeRRSetsName, fieldName: "rrsets.name", displayFieldType: FieldTypeText},
		collectionFieldGeneric{fieldType: FieldTypeRRSetsData, fieldName: "rrsets.rdata", displayFieldType: FieldTypeText},
		collectionFieldGeneric{fieldType: FieldTypeIP, fieldName: "servers.ip", internal: true},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "servers.name", internal: true},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "servers.name_aggr", internal: true},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "servers.namespace", internal: true},
		collectionFieldGeneric{fieldType: FieldTypeIP, fieldName: "source.ip", internal: true},
		collectionFieldGeneric{fieldType: FieldTypeText, fieldName: "type", internal: true},
	},
}
