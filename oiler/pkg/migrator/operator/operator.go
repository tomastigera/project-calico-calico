package operator

import (
	"context"
	"time"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

// Operator handles data operation like read and writes
type Operator[T any] interface {
	Write(ctx context.Context, items []T) (*v1.BulkResponse, error)
	Read(ctx context.Context, current TimeInterval, pageSize int) (*v1.List[T], *TimeInterval, error)
	Transform(items []T) []string
}

// TimeInterval represents how a read query is defined.
// Reading from primary source is done by searching using
// time parameters. More precisely, using field generated_time
// and search_after parameter for pagination within a PIT.
// We can query data within a PIT and paginate through it.
// The field Cursor will contain the last generated_time followed
// by th document id. A query can start from time zero or from a
// specific interval
type TimeInterval struct {
	// A query with pagination is performed. Cursor keeps tracks
	// where we are in the pagination read. Cursor will contain
	// field searchFrom key that will have generated_time and shard_doc
	// values to be used as search_after. It can also contain pit key
	// to store point in time to be used in the next query.
	Cursor map[string]any
	// Start represents the value for generated_time to be used
	// in the read query as the left side of the interval.
	Start *time.Time
	// End represents the value for generated_time to be used
	// in the read query as the right side of the interval.
	End *time.Time
}

// HasReachedEnd will return true if we finished pagination through data
// within a PIT
func (it *TimeInterval) HasReachedEnd() bool {
	return len(it.Cursor) == 0
}

// Lag tracks how far behind the last generated_time is from a give time
func (it *TimeInterval) Lag(from time.Time) time.Duration {
	return from.Sub(it.LastGeneratedTime())
}

// LastGeneratedTime represents the value for field last_generated from the
// last document read. If we are in the middle of a paginated request, the value
// will be extracted from the cursor. If we perform the first read from a new request
// (first page), we need to simply return the value given as a start. Default value is
// zero time.
func (it *TimeInterval) LastGeneratedTime() time.Time {
	if len(it.Cursor) != 0 {
		// Last generated_time is extracted from the curso
		// as we are in the middle of pagination
		last, err := it.generatedTimeFromCursor()
		if err != nil || last == nil {
			if it.Start != nil {
				return *it.Start
			}

			return time.Time{}
		}
		return last.UTC()
	}
	if it.Start != nil {
		// We are performing a new request
		return *it.Start
	}
	return time.Time{}
}

func (it *TimeInterval) generatedTimeFromCursor() (*time.Time, error) {
	if len(it.Cursor) == 0 {
		return nil, nil
	}
	// searchFrom key will store an array comprised of generated_time and shard_doc
	// Each query performed is made using generated_time as a time interval or ordered
	// ASC by generated_rime and shard_doc. (This value is implicit as we perform
	// queries with PIT and the document id is used by default)
	searchFromVals := it.Cursor["searchFrom"]
	if len(searchFromVals.([]any)) > 0 {
		searchFromVal := searchFromVals.([]any)[0]
		switch searchFromVal := searchFromVal.(type) {
		case float64:
			// Values for generated_time are stored as floating number
			// representing unix milliseconds since epoch time
			last := time.UnixMilli(int64(searchFromVal)).UTC()
			return &last, nil
		}
	}
	return nil, nil
}

// Next will produce the next query parameters to read data. If we are in the middle of a paginated requests
// then we need to continue to read the next page. First page has an empty cursor, but no read data. Last
// page has an empty cursor, but we have read data (lastGeneratedTime is set to the generated_time field
// retrieved from the last document in the page)
func Next(cursor map[string]any, lastGeneratedTime *time.Time, current *time.Time) *TimeInterval {
	if len(cursor) == 0 {
		if lastGeneratedTime == nil {
			// We need to perform the query again for the same interval as no new data has been written
			return &TimeInterval{Start: current}
		}
		// We need to shift our time interval as new data has been written
		return &TimeInterval{Start: lastGeneratedTime}
	}

	// We need to paginate through our current time
	return &TimeInterval{Cursor: cursor, Start: current}
}
