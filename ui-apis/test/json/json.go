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

func MustUnmarshalToStandObject(obj any) any {
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
