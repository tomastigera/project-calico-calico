// Copyright 2019 Tigera Inc. All rights reserved.

package storage

import (
	"context"
	"errors"
	"testing"

	. "github.com/onsi/gomega"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

func TestFlowLogIterator(t *testing.T) {
	g := NewGomegaWithT(t)

	input := []v1.FlowLog{
		{
			ID: "id1",
		},
		{
			ID: "id2",
		},
		{
			ID: "id3",
		},
	}

	ctx := t.Context()

	client := lsclient.NewMockClient("", rest.MockResult{
		Body: v1.List[v1.FlowLog]{
			Items: input,
		},
	})
	params := v1.FlowLogParams{}

	expectedKey := QueryKeyFlowLogSourceIP
	i := newQueryIterator(
		ctx,
		[]queryEntry[v1.FlowLog, v1.FlowLogParams]{
			{
				key:         expectedKey,
				queryParams: params,
				listPager:   lsclient.NewListPager[v1.FlowLog](&params),
				listFn:      client.FlowLogs("test").List,
			},
		},
		"test")

	var actualHits []v1.FlowLog
	var actualKeys []QueryKey
	for i.Next() {
		k, h := i.Value()
		actualKeys = append(actualKeys, k)
		actualHits = append(actualHits, h)
	}
	g.Expect(i.Err()).ShouldNot(HaveOccurred())

	g.Expect(actualHits).Should(HaveLen(len(input)), "All events are retrieved.")
	for idx := range actualHits {
		g.Expect(actualHits[idx].ID).Should(Equal(input[idx].ID), "Events are retrieved in order.")
		g.Expect(actualKeys[idx]).Should(Equal(expectedKey))
	}
}

func TestFlowLogIteratorWithError(t *testing.T) {
	g := NewGomegaWithT(t)

	ctx := t.Context()
	client := lsclient.NewMockClient("", rest.MockResult{
		Body: v1.List[v1.FlowLog]{},
		Err:  errors.New("any error"),
	})
	params := v1.FlowLogParams{}
	i := queryIterator[v1.FlowLog, v1.FlowLogParams]{
		queries: []queryEntry[v1.FlowLog, v1.FlowLogParams]{
			{
				key:         QueryKeyFlowLogDestIP,
				queryParams: params,
				listPager: lsclient.NewMockListPager(&params, func(context.Context, v1.Params) (*v1.List[v1.FlowLog], error) {
					return nil, errors.New("any error")
				}),
				listFn: client.FlowLogs("test").List,
			},
		},
		ctx: ctx,
	}

	g.Expect(i.Next()).Should(BeFalse(), "Iterator stops immediately")
	g.Expect(i.Err()).Should(HaveOccurred())
}

func TestFlowLogIteratorWithTwoQueries(t *testing.T) {
	g := NewGomegaWithT(t)

	sourceLog := v1.FlowLog{
		ID:       "source",
		SourceIP: strPtr("1.2.3.4"),
	}
	destLog := v1.FlowLog{
		ID:       "dest",
		SourceIP: strPtr("3.4.5.6"),
	}
	client := lsclient.NewMockClient("",
		// Mock first call to retrieve the logs that
		// match the source ip
		rest.MockResult{
			Body: v1.List[v1.FlowLog]{
				Items: []v1.FlowLog{sourceLog},
			},
		},
		// Mock the second call to retrieve the logs
		// that match the destination ip
		rest.MockResult{
			Body: v1.List[v1.FlowLog]{
				Items: []v1.FlowLog{destLog},
			},
		})
	params := v1.FlowLogParams{}

	queries := []queryEntry[v1.FlowLog, v1.FlowLogParams]{
		{
			key:         QueryKeyFlowLogSourceIP,
			queryParams: params,
			listPager:   lsclient.NewListPager[v1.FlowLog](&params),
			listFn:      client.FlowLogs("test").List,
		},
		{
			key:         QueryKeyFlowLogDestIP,
			queryParams: params,
			listPager:   lsclient.NewListPager[v1.FlowLog](&params),
			listFn:      client.FlowLogs("test").List,
		},
	}

	ctx := t.Context()

	i := newQueryIterator(ctx, queries, "mock")

	var results []v1.FlowLog
	for i.Next() {
		_, h := i.Value()
		results = append(results, h)
	}
	g.Expect(i.Err()).ShouldNot(HaveOccurred(), "No errors from the iterator")
	g.Expect(results).Should(HaveLen(2), "Should have gotten back two results")
	g.Expect(results[0].ID).ShouldNot(Equal(results[1].ID), "Both have different source IDs")
	g.Expect(results[0].SourceIP).ShouldNot(Equal(results[1].SourceIP), "Both have different source IPs")
}
