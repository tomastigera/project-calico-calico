package client_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
)

// setupTest runs common logic before each test, and also returns a function to perform teardown
// after each test.
func setupTest(t *testing.T) func() {
	cancel := logutils.RedirectLogrusToTestingT(t)
	return cancel
}

func TestPager(t *testing.T) {
	type result struct {
		List  *v1.List[v1.L3Flow]
		Error error
	}

	// getListFunc takes a slice of results and returns a ListFunc that returns
	// a subsequent result on every call.
	getListFunc := func(testData []result) client.ListFunc[v1.L3Flow] {
		i := 0
		return func(context.Context, v1.Params) (*v1.List[v1.L3Flow], error) {
			// Use a local function to yield the next item from test data
			// on each call of listFunc.
			res := testData[i]
			t.Logf("PageFunc returning result %d: %+v, %s", i, res.List, res.Error)
			i++
			return res.List, res.Error
		}
	}

	t.Run("should handle a paged list with no errors", func(t *testing.T) {
		defer setupTest(t)()

		// Data to be returned by listFunc for the test.
		testData := []result{
			{
				List: &v1.List[v1.L3Flow]{
					AfterKey: map[string]any{"foo": "bar"},
				},
				Error: nil,
			},
			{
				List: &v1.List[v1.L3Flow]{
					AfterKey: nil, // Indicates this is the last page.
				},
				Error: nil,
			},
		}

		// Perform some paged lists.
		pager := client.NewListPager[v1.L3Flow](&v1.L3FlowParams{})
		listFunc := getListFunc(testData)
		getPage := pager.PageFunc(listFunc)

		var page *v1.List[v1.L3Flow]
		var err error
		var more bool
		for _, expected := range testData {
			page, more, err = getPage()
			require.NoError(t, err)
			require.NotNil(t, page)
			require.Equal(t, expected.List, page)
		}
		require.False(t, more)
	})

	t.Run("should handle a paged list with an error", func(t *testing.T) {
		defer setupTest(t)()

		// Data to be returned by listFunc for the test.
		testData := []result{
			{
				List: &v1.List[v1.L3Flow]{
					AfterKey: map[string]any{"foo": "bar"},
				},
				Error: fmt.Errorf("error in first page call"),
			},
		}

		// Perform some paged lists.
		pager := client.NewListPager[v1.L3Flow](&v1.L3FlowParams{})
		listFunc := getListFunc(testData)
		getPage := pager.PageFunc(listFunc)

		// It should only return a single page due to the error.
		page, more, err := getPage()
		require.Error(t, err)
		require.Nil(t, page)
		require.False(t, more)

		// If we call it again, we should get another error. This time, because
		// the pager has marked itself as complete due to the first error.
		page, more, err = getPage()
		require.Error(t, err)
		require.Nil(t, page)
		require.False(t, more)
	})

	t.Run("should support streaming pages of data", func(t *testing.T) {
		defer setupTest(t)()

		// Data to be returned by listFunc for the test.
		testData := []result{
			{
				List: &v1.List[v1.L3Flow]{
					AfterKey: map[string]any{"foo": "bar"},
				},
				Error: nil,
			},
			{
				List: &v1.List[v1.L3Flow]{
					AfterKey: map[string]any{"whizz": "pop"},
				},
				Error: nil,
			},
			{
				List: &v1.List[v1.L3Flow]{
					AfterKey: map[string]any{"ham": "salad"},
				},
				Error: nil,
			},
			{
				List: &v1.List[v1.L3Flow]{
					AfterKey: nil, // Indicates this is the last page.
				},
				Error: nil,
			},
		}

		// Perform some paged lists.
		pager := client.NewListPager[v1.L3Flow](&v1.L3FlowParams{})
		listFunc := getListFunc(testData)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Create the streamer and read from it.
		results, errors := pager.Stream(ctx, listFunc)
		allPages := []v1.List[v1.L3Flow]{}
		for page := range results {
			require.NotNil(t, page)
			allPages = append(allPages, page)
		}

		// We should not have received an error.
		err := <-errors
		require.NoError(t, err)

		// Check the pages we received
		require.Len(t, allPages, 4)
		for i, p := range allPages {
			require.Equal(t, *testData[i].List, p)
		}

		// Assert that the channels have been closed, since we've read all the data.
		require.Empty(t, results)
		require.Empty(t, errors)
	})

	t.Run("should support streaming pages of data with an error", func(t *testing.T) {
		defer setupTest(t)()

		// Data to be returned by listFunc for the test.
		testData := []result{
			{
				List: &v1.List[v1.L3Flow]{
					AfterKey: map[string]any{"foo": "bar"},
				},
				Error: nil,
			},
			{
				List: &v1.List[v1.L3Flow]{
					AfterKey: map[string]any{"whizz": "pop"},
				},
				Error: nil,
			},
			{
				List: &v1.List[v1.L3Flow]{
					AfterKey: map[string]any{"ham": "salad"},
				},
				Error: fmt.Errorf("ham salad is not desirable"),
			},
			{
				List: &v1.List[v1.L3Flow]{
					Items:    []v1.L3Flow{{}},
					AfterKey: nil, // Indicates this is the last page.
				},
				Error: nil,
			},
		}

		// Perform some paged lists.
		pager := client.NewListPager[v1.L3Flow](&v1.L3FlowParams{})
		listFunc := getListFunc(testData)

		// Use a timeout in case we get stuck.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Create the streamer and read from it.
		results, errors := pager.Stream(ctx, listFunc)
		allPages := []v1.List[v1.L3Flow]{}
		for page := range results {
			require.NotNil(t, page)
			allPages = append(allPages, page)
		}

		// We should have received an error.
		err := <-errors
		require.Error(t, err)

		// Check the pages we received. We should have received two pages before
		// hitting the error, so allPages should have length 2.
		require.Len(t, allPages, 2)
		for i, p := range allPages {
			require.Equal(t, *testData[i].List, p)
		}

		// Assert that the channels have been closed, since we've read all the data.
		require.Empty(t, errors)
		require.Empty(t, results)
	})

	t.Run("should respect the max results option", func(t *testing.T) {
		defer setupTest(t)()

		// Data to be returned by listFunc for the test.
		testData := []result{
			{
				List: &v1.List[v1.L3Flow]{
					Items:    []v1.L3Flow{{}, {}}, // Two items
					AfterKey: map[string]any{"foo": "bar"},
				},
				Error: nil,
			},
			{
				List: &v1.List[v1.L3Flow]{
					Items:    []v1.L3Flow{{}, {}}, // Two items
					AfterKey: map[string]any{"whizz": "pop"},
				},
				Error: nil,
			},
			{
				List: &v1.List[v1.L3Flow]{
					Items:    []v1.L3Flow{{}, {}}, // Two items
					AfterKey: map[string]any{"ham": "salad"},
				},
				Error: nil,
			},
			{
				List: &v1.List[v1.L3Flow]{
					Items:    []v1.L3Flow{{}, {}}, // Two items
					AfterKey: nil,                 // Indicates this is the last page.
				},
				Error: nil,
			},
		}

		// Params configure the parameeters for each individual
		// page request. For this, set a max page size of 2.
		params := &v1.L3FlowParams{}
		params.MaxPageSize = 2

		// Perform a paged list, specifying a max results of 5.
		opt := client.WithMaxResults[v1.L3Flow](5)
		pager := client.NewListPager(params, opt)
		listFunc := getListFunc(testData)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Create the streamer.
		allPages := []v1.List[v1.L3Flow]{}
		results, errors := pager.Stream(ctx, listFunc)
		for page := range results {
			require.NotNil(t, page)
			allPages = append(allPages, page)
		}

		// We should not have received an error.
		err := <-errors
		require.NoError(t, err)

		// Since each page has two results, and we want no more than 5
		// results total, we should only get back two pages. A third would
		// put us over our requested max.
		require.Len(t, allPages, 2)

		// Assert that the channels have been closed, since we've read all the data.
		require.Empty(t, results)
		require.Empty(t, errors)
	})
}
