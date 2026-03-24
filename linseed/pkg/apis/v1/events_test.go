// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//

package v1

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/linseed/pkg/testutils"
)

func TestTimeStampOrDate_MarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		timestamp *int64
		date      *time.Time
		want      []byte
		wantErr   bool
	}{
		{
			name:      "value 0",
			timestamp: testutils.Int64Ptr(0),
			want:      []byte(`0`),
		},
		{
			name:      "value 45",
			timestamp: testutils.Int64Ptr(45),
			want:      []byte(`45`),
		},
		{
			name:      "value max int64",
			timestamp: testutils.Int64Ptr(math.MaxInt64),
			want:      []byte(`9223372036854775807`),
		},
		{
			name:      "value min int64",
			timestamp: testutils.Int64Ptr(math.MinInt64),
			want:      []byte(`-9223372036854775808`),
		},
		{
			name: "value 2023-04-28T19:38:14+00:00",
			date: parseTime(t, "2023-04-28T19:38:14+00:00", false),
			want: []byte(`"2023-04-28T19:38:14+00:00"`),
		},
		{
			name: "value 2023-04-28T",
			date: parseTime(t, "2023-04-28T", true),
			want: []byte(`"0001-01-01T00:00:00+00:00"`),
		},
		{
			name:      "value both timestamp and timeVal",
			timestamp: testutils.Int64Ptr(time.Unix(0, 0).Unix()),
			date:      parseTime(t, "2023-04-28T19:38:14+00:00", false),
			wantErr:   true,
		},
		{
			name:      "value both timestamp and timeVal as nil",
			timestamp: nil,
			date:      nil,
			wantErr:   false,
			want:      []byte(`0`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &TimestampOrDate{
				intVal:  tt.timestamp,
				timeVal: tt.date,
			}
			got, err := input.MarshalJSON()
			if tt.wantErr {
				require.Error(t, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MarshalJSON() got = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestTimeStampOrDate_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		timestamp *int64
		date      *time.Time
		wantErr   bool
		errorMsg  string
	}{
		{
			name:      "value 0",
			input:     []byte(`0`),
			timestamp: testutils.Int64Ptr(0),
		},
		{
			name:      "value 45",
			input:     []byte(`45`),
			timestamp: testutils.Int64Ptr(45),
		},
		{
			name:      "value max int64",
			input:     []byte(`9223372036854775807`),
			timestamp: testutils.Int64Ptr(math.MaxInt64),
		},
		{
			name:      "value min int64",
			input:     []byte(`-9223372036854775808`),
			timestamp: testutils.Int64Ptr(math.MinInt64),
		},
		{
			name:  "value 2023-04-28T19:38:14+00:00",
			input: []byte(`"2023-04-28T19:38:14+00:00"`),
			date:  parseTime(t, "2023-04-28T19:38:14+00:00", false),
		},
		{
			name:     "value 2023-04-28T",
			input:    []byte(`"2023-04-28T"`),
			wantErr:  true,
			errorMsg: `parsing time "2023-04-28T" as "2006-01-02T15:04:05Z07:00": cannot parse "" as "15"`,
		},
		{
			name:     "value empty json string",
			input:    []byte(`""`),
			wantErr:  true,
			errorMsg: `parsing time "" as "2006-01-02T15:04:05Z07:00": cannot parse "" as "2006"`,
		},
		{
			name:     "value invalid json string",
			input:    []byte(`"`),
			wantErr:  true,
			errorMsg: `unexpected end of input, error found in #1 byte of`,
		},
		{
			name:  "value empty string",
			input: []byte(``),
		},
		{
			name:     "value space as json string",
			input:    []byte(`" "`),
			wantErr:  true,
			errorMsg: `parsing time " " as "2006-01-02T15:04:05Z07:00": cannot parse " " as "2006"`,
		},
		{
			name:  "value zero length bytes",
			input: []byte{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := &TimestampOrDate{}
			err := actual.UnmarshalJSON(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorMsg)
			} else {
				expected := &TimestampOrDate{
					intVal:  tt.timestamp,
					timeVal: tt.date,
				}
				require.NoError(t, err)
				if !reflect.DeepEqual(actual, expected) {
					logrus.Info(cmp.Diff(actual, expected))
					if expected.intVal != nil {
						t.Errorf("UnmarshalJSON() got = %+v, want %+v", *actual.intVal, *expected.intVal)
					} else {
						t.Errorf("UnmarshalJSON() got = %+v, want %+v", *actual.timeVal, *expected.timeVal)
					}
				}
			}
		})
	}
}

func parseTime(t *testing.T, val string, wantErr bool) *time.Time {
	time, err := time.Parse(time.RFC3339, val)
	if !wantErr {
		require.NoError(t, err)
	}

	return testutils.TimePtr(time)
}

func TestTimestampOrDate_NilPointerReceiver(t *testing.T) {
	t.Run("Nil Pointer Receiver - MarshalJSON", func(t *testing.T) {
		var c *TimestampOrDate
		data, err := json.Marshal(c)
		require.NoError(t, err)
		require.Equal(t, "null", string(data))
	})

	t.Run("Nil Pointer Receiver - UnmarshalJSON", func(t *testing.T) {
		var c *TimestampOrDate
		err := c.UnmarshalJSON([]byte{})
		require.Error(t, err)
	})
}
