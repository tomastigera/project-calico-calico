package client

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/tigera/tds-apiserver/lib/slices"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// QueryResponse A query response
type QueryResponse struct {
	Totals QueryResponseTotals `json:"totals"`

	Documents    []QueryResponseDocument   `json:"documents,omitempty"`
	Aggregations QueryResponseAggregations `json:"aggregations,omitempty"`
	GroupValues  []QueryResponseGroupValue `json:"groupValues,omitempty"`

	ClusterErrors map[string][]error `json:"clusterErrors,omitempty"`
}

type QueryResponseDocument map[string]any

// QueryResponseTotals Total document results
type QueryResponseTotals struct {
	Type  string `json:"type"`
	Value int64  `json:"value"`
}

type QueryResponseAggregations map[string]QueryResponseValueAsString

type QueryResponseValueAsString struct {
	AsString string `json:"asString"`
}

type QueryResponseGroupValue struct {
	Key          string                    `json:"key"`
	Aggregations QueryResponseAggregations `json:"aggregations,omitempty"`
	NestedValues []QueryResponseGroupValue `json:"nestedValues,omitempty"`
}

type AppendableQueryResponseGroupValue interface {
	Append(QueryResponseGroupValue)
}

var _ AppendableQueryResponseGroupValue = &QueryResponse{}
var _ AppendableQueryResponseGroupValue = &QueryResponseGroupValue{}

func (q *QueryResponse) Append(value QueryResponseGroupValue) {
	q.GroupValues = append(q.GroupValues, value)
}

func (q *QueryResponseGroupValue) Append(value QueryResponseGroupValue) {
	q.NestedValues = append(q.NestedValues, value)
}

// WriteCSV Writes QueryResponse in the CSV format to w, with the 1st line containing field names in the columnsDef slice
// columnsDef must contain a slice of fields which will have their values written to csv. If a field is suffixed
// by :<alias>, then the corresponding field column in the 1st line of the CSV export will be set to <alias> instead
// of the field name
func (q *QueryResponse) WriteCSV(w io.Writer, columnsDef []string, limit int) error {
	csvWriter := csv.NewWriter(w)

	var fields []string
	err := csvWriter.Write(slices.Map(columnsDef, func(columnDef string) string {
		values := strings.SplitN(columnDef, ":", 2)
		fields = append(fields, values[0])
		if len(values) > 1 {
			// column field in "field-name:<alias>" format. Write <alias> as the CSV the column
			return values[1]
		}
		// column field set to "field-name". Write the field name as the CSV column
		return values[0]
	}))
	if err != nil {
		return err
	}

	if len(q.Documents) > 0 {
		// Process documents to csv by mapping document fields to format.Fields

		docToMap := func(doc any) (map[string]any, error) {
			docBytes, err := json.Marshal(doc)
			if err != nil {
				return nil, err
			}

			var m map[string]any
			err = json.Unmarshal(docBytes, &m)
			if err != nil {
				return nil, err
			}
			return m, nil
		}

		for i, doc := range q.Documents {
			if limit > 0 && i >= limit {
				break
			}
			docMap, err := docToMap(doc)
			if err != nil {
				return err
			}

			err = q.writeCSVRecord(csvWriter, fields, func(field string) any {
				if value, found := docMap[field]; found {
					return value
				}
				return ""
			})
			if err != nil {
				return err
			}
		}
	} else if len(q.GroupValues) > 0 {
		rowsWritten := 0
		err := q.convertGroupValuesToCSV(csvWriter, fields, nil, 0, q.GroupValues, &rowsWritten, limit)
		if err != nil {
			return err
		}
	}

	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return err
	}
	return nil
}

var reCSVAggregationColumn = regexp.MustCompile(`^aggregations\(([^)]+)\)$`)

func (q *QueryResponse) convertGroupValuesToCSV(
	csvWriter *csv.Writer,
	fields []string,
	csvEntryMap map[string]any,
	groupIndex int,
	groupValues []QueryResponseGroupValue,
	rowsWritten *int,
	limit int,
) error {
	if rowsWritten == nil {
		return errors.New("rowsWritten pointer must be provided")
	}

	// each GroupValue.Key is identified by the pseudo field groupBys(index)
	keyColumn := fmt.Sprintf("groupBys(%d)", groupIndex)
	containsKey := slices.AnyMatch(fields, func(field string) bool {
		return field == keyColumn
	})

	for _, groupValue := range groupValues {
		if limit > 0 && *rowsWritten >= limit {
			return nil
		}
		if groupIndex == 0 {
			// Process groupValues and aggregations to csv
			csvEntryMap = make(map[string]any)
		}

		if containsKey {
			csvEntryMap[keyColumn] = groupValue.Key
		}

		var err error
		if len(groupValue.NestedValues) > 0 {
			// process subgroup values
			err = q.convertGroupValuesToCSV(csvWriter, fields, csvEntryMap, groupIndex+1, groupValue.NestedValues, rowsWritten, limit)
		} else {
			// process aggregations if no subgroup values are available
			err = q.writeCSVRecord(csvWriter, fields, func(field string) any {
				// each aggregation value is identified by the pseudo field aggregations(key)
				if m := reCSVAggregationColumn.FindStringSubmatch(field); len(m) == 2 {
					aggKey := m[1]
					if gv, ok := groupValue.Aggregations[aggKey]; ok {
						return gv.AsString
					}
				} else if value, ok := csvEntryMap[field]; ok {
					return value
				}
				return ""
			})
			if err == nil {
				*rowsWritten++
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// writeCSVRecord Writes a single CSV record, retrieving values from the result of calling columnValueMapper for each field in the fields slice
func (q *QueryResponse) writeCSVRecord(csvWriter *csv.Writer, fields []string, columnValueMapper func(c string) any) error {
	var csvRecord []string

	for _, f := range fields {
		var csvValue string
		value := columnValueMapper(f)
		if valueStr, ok := value.(string); ok {
			csvValue = valueStr
		} else {
			// non-string values are converted to json
			valueBytes, err := json.Marshal(value)
			if err != nil {
				return err
			}
			csvValue = string(valueBytes)
		}
		csvRecord = append(csvRecord, csvValue)
	}

	return csvWriter.Write(csvRecord)
}
