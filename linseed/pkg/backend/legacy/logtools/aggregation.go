// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package logtools

import (
	"encoding/json"
)

// RawAggregation is a helper struct for passing aggregations to the elastic client.
// It implements the elastic.Aggregation interface for a []byte.
type RawAggregation struct {
	json.RawMessage
}

func (a RawAggregation) Source() (any, error) {
	src := map[string]any{}
	err := json.Unmarshal(a.RawMessage, &src)
	if err != nil {
		return nil, err
	}
	return src, nil
}
