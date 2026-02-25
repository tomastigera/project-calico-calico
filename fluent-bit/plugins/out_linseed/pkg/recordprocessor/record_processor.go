// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package recordprocessor

import (
	"bytes"
	"encoding/json"
	"unsafe"

	"github.com/fluent/fluent-bit-go/output"
)

type Record map[any]any

type RecordProcessor struct{}

func NewRecordProcessor() *RecordProcessor {
	return &RecordProcessor{}
}

func (rp *RecordProcessor) Process(data unsafe.Pointer, length int) (*bytes.Buffer, int, error) {
	var ndjsonBuffer bytes.Buffer

	// decode fluent-bit internal msgpack buffer to ndjson format
	dec := output.NewDecoder(data, length)
	count := 0
	for {
		rc, _, record := output.GetRecord(dec)
		if rc != 0 {
			break
		}

		jsonData, err := json.Marshal(toStringMap(record))
		if err != nil {
			return nil, count, err
		}

		ndjsonBuffer.Write(jsonData)
		ndjsonBuffer.WriteByte('\n')
		count++
	}

	return &ndjsonBuffer, count, nil
}

// prevent base64-encoding []byte values (default json.Encoder rule) by
// converting them to strings
func toStringSlice(slice []any) []any {
	var s []any
	for _, v := range slice {
		switch t := v.(type) {
		case []byte:
			s = append(s, string(t))
		case map[any]any:
			s = append(s, toStringMap(t))
		case []any:
			s = append(s, toStringSlice(t))
		default:
			s = append(s, t)
		}
	}
	return s
}

func toStringMap(record Record) map[string]any {
	m := make(map[string]any)
	for k, v := range record {
		key, ok := k.(string)
		if !ok {
			continue
		}
		switch t := v.(type) {
		case []byte:
			m[key] = string(t)
		case map[any]any:
			m[key] = toStringMap(t)
		case []any:
			m[key] = toStringSlice(t)
		default:
			m[key] = v
		}
	}
	return m
}
