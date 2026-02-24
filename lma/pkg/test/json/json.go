package calicojson

import "encoding/json"

type Map map[string]any

func MustMarshal(obj any) []byte {
	jsonBytes, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}

	return jsonBytes
}

// MustUnmarshalToStandardObject uses the json library to convert an object into a common structure that can be used for
// comparisons. For example, there are multiple ways to represent the same json structure with different golang types,
// but the same representations of json using different types will not equal each other in a comparison. Using
// MustUnmarshalToStandardObject on two objects representing the same json in different ways will result in the objects
// having the same structure, and will therefore equal each other on comparisons.
func MustUnmarshalToStandardObject(obj any) any {
	var jsonBytes []byte

	switch obj := obj.(type) {
	case []byte:
		jsonBytes = obj
	case string:
		jsonBytes = []byte(obj)
	default:
		jsonBytes = MustMarshal(obj)
	}

	stdObj := map[string]any{}
	if err := json.Unmarshal(jsonBytes, &stdObj); err != nil {
		panic(err)
	}

	return stdObj
}
