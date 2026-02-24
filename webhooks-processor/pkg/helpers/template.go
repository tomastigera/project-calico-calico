// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package helpers

import (
	"bytes"
	"encoding/json"
	"html/template"
	"io"
)

func ProcessTemplate(tmpl *template.Template, payload []byte) ([]byte, error) {
	if tmpl == nil {
		return payload, nil
	}

	// Encode event as map[string]interface{} to keep the original keys in the JSON
	// so that the template uses existing JSON keys
	var eventsJson map[string]any
	err := json.Unmarshal(payload, &eventsJson)
	if err != nil {
		return payload, err
	}
	// Apply template to event to generate the required payload
	var results bytes.Buffer
	writer := io.Writer(&results)
	err = tmpl.Execute(writer, eventsJson)
	if err != nil {
		return payload, err
	}
	return results.Bytes(), nil
}
