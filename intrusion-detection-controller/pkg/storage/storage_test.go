// Copyright 2019 Tigera Inc. All rights reserved.

package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/araddon/dateparse"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/client/clientset_generated/clientset/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	geodb "github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/geodb"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/util"
	v1scheme "github.com/projectcalico/calico/libcalico-go/lib/apis/crd.projectcalico.org/v1/scheme"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

var oneMinuteAgo time.Time

func Test_GetIPSet(t *testing.T) {
	g := NewGomegaWithT(t)

	// mock linseed client
	lsc := lsclient.NewMockClient("")

	// mock controller runtime client.
	scheme := scheme.Scheme
	err := v1scheme.AddCalicoResourcesToScheme(scheme)
	g.Expect(err).NotTo(HaveOccurred())
	fakeClient := fakeclient.NewClientBuilder().WithScheme(scheme).Build()

	e := NewService(lsc, fakeClient, "cluster", time.Duration(1))

	ctx := t.Context()

	lsc.SetResults(rest.MockResult{
		Body: expectedIPSet(g, "test_files/1.1.json"),
	})
	ipSet, err := e.GetIPSet(ctx, "test1")
	g.Expect(err).ShouldNot(HaveOccurred())
	g.Expect(ipSet).Should(ConsistOf("35.32.82.0/24", "10.10.1.20/32"))

	lsc.SetResults(rest.MockResult{
		Body: expectedIPSet(g, "test_files/1.2.json"),
	})
	ipSet, err = e.GetIPSet(ctx, "test2")
	g.Expect(err).ShouldNot(HaveOccurred())
	g.Expect(ipSet).To(BeEmpty())

	lsc.SetResults(rest.MockResult{
		Err: fmt.Errorf("linseed error"),
	})
	_, err = e.GetIPSet(ctx, "unknown")
	g.Expect(err).Should(HaveOccurred(), "linseed error")
}

func Test_GetIPSetModified(t *testing.T) {
	g := NewGomegaWithT(t)

	// mock linseed client
	lsc := lsclient.NewMockClient("")

	// mock controller runtime client.
	scheme := scheme.Scheme
	err := v1scheme.AddCalicoResourcesToScheme(scheme)
	g.Expect(err).NotTo(HaveOccurred())
	fakeClient := fakeclient.NewClientBuilder().WithScheme(scheme).Build()

	e := NewService(lsc, fakeClient, "cluster", time.Duration(1))

	ctx := t.Context()

	lsc.SetResults(rest.MockResult{
		Body: expectedIPSet(g, "test_files/2.1.json"),
	})
	tm, err := e.GetIPSetModified(ctx, "test")
	g.Expect(err).ShouldNot(HaveOccurred(), "Proper response")
	g.Expect(tm).Should(BeTemporally("==", dateparse.MustParse("2019-03-18T12:29:18.590008-03:00")))

	lsc.SetResults(rest.MockResult{
		Body: expectedIPSet(g, "test_files/2.3.json"),
	})
	_, err = e.GetIPSetModified(ctx, "test3")
	g.Expect(err).Should(HaveOccurred(), "missing created time field")

	lsc.SetResults(rest.MockResult{
		Err: fmt.Errorf("linseed error"),
	})
	_, err = e.GetIPSetModified(ctx, "unknown")
	g.Expect(err).Should(HaveOccurred(), "linseed error")
}

func Test_QueryIPSet(t *testing.T) {
	g := NewGomegaWithT(t)

	results := []rest.MockResult{}
	results = append(results,
		// Query IPSet
		rest.MockResult{
			Body: expectedIPSet(g, "test_files/3.ipset.json"),
		},
		// Query flow logs for source IP
		rest.MockResult{
			Body: v1.List[v1.FlowLog]{
				Items: []v1.FlowLog{
					{
						SourceIP: strPtr("35.32.82.134"),
						DestIP:   strPtr("10.10.1.20"),
						ID:       "BQ15nGkBixKz5K3LBMRy",
					},
					{
						SourceIP: strPtr("35.32.82.134"),
						DestIP:   strPtr("10.10.1.20"),
						ID:       "BQ15nGkBixKz5K3LBMRz",
					},
				},
				TotalHits: 2,
			},
		},
		// Query flow logs for destination IP
		rest.MockResult{
			Body: v1.List[v1.FlowLog]{
				Items: []v1.FlowLog{
					{
						SourceIP: strPtr("35.32.82.134"),
						DestIP:   strPtr("10.10.1.20"),
						ID:       "BQ15nGkBixKz5K3LBMRy",
					},
					{
						SourceIP: strPtr("35.32.82.134"),
						DestIP:   strPtr("10.10.1.20"),
						ID:       "BQ15nGkBixKz5K3LBMRz",
					},
				},
				TotalHits: 2,
			},
		})

	lsc := lsclient.NewMockClient("", results...)

	// mock controller runtime client.
	scheme := scheme.Scheme
	err := v1scheme.AddCalicoResourcesToScheme(scheme)
	g.Expect(err).NotTo(HaveOccurred())
	fakeClient := fakeclient.NewClientBuilder().WithScheme(scheme).Build()

	e := NewService(lsc, fakeClient, "cluster", time.Duration(1))
	ctx := t.Context()

	oneMinuteAgo = time.Now().Add(-1 * time.Minute)
	toBeUpdated := &apiv3.GlobalThreatFeed{}
	toBeUpdated.Name = "test"
	toBeUpdated.Status.LastSuccessfulSearch = &metav1.Time{Time: oneMinuteAgo}

	itr, _, err := e.QueryIPSet(ctx, &geodb.MockGeoDB{}, toBeUpdated)
	g.Expect(err).ShouldNot(HaveOccurred())

	c := 0
	vals := make([]any, 0)
	for itr.Next() {
		c++
		_, val := itr.Value()
		vals = append(vals, val)
	}
	g.Expect(itr.Err()).ShouldNot(HaveOccurred())
	g.Expect(c).Should(Equal(4))
	g.Expect(len(vals)).Should(Equal(4))
}

func Test_QueryIPSet_SameIPSet(t *testing.T) {
	g := NewGomegaWithT(t)

	results := []rest.MockResult{}
	results = append(results,
		rest.MockResult{
			Body: expectedIPSet(g, "test_files/3.ipset.json"),
		},
		rest.MockResult{
			Body: v1.List[v1.FlowLog]{
				Items: []v1.FlowLog{
					{
						SourceIP:  strPtr("35.32.82.134"),
						DestIP:    strPtr("10.10.1.20"),
						ID:        "BQ15nGkBixKz5K3LBMRy",
						StartTime: 1536897600,
						EndTime:   1536897900,
					},
				},
				TotalHits: 1,
			},
		},
		rest.MockResult{
			Body: v1.List[v1.FlowLog]{
				Items: []v1.FlowLog{
					{
						SourceIP:  strPtr("35.32.82.134"),
						DestIP:    strPtr("10.10.1.20"),
						ID:        "BQ15nGkBixKz5K3LBMRy",
						StartTime: 1536897600,
						EndTime:   1536897900,
					},
				},
				TotalHits: 1,
			},
		},
		rest.MockResult{
			Body: expectedIPSet(g, "test_files/1.1.json"),
		},
	)

	lsc := lsclient.NewMockClient("", results...)

	// mock controller runtime client.
	scheme := scheme.Scheme
	err := v1scheme.AddCalicoResourcesToScheme(scheme)
	g.Expect(err).NotTo(HaveOccurred())
	fakeClient := fakeclient.NewClientBuilder().WithScheme(scheme).Build()

	e := NewService(lsc, fakeClient, "cluster", time.Duration(1))
	ctx := t.Context()

	oneMinuteAgo := time.Now().Add(-1 * time.Minute)
	toBeUpdated := &apiv3.GlobalThreatFeed{}
	toBeUpdated.Name = "test"
	toBeUpdated.Status.LastSuccessfulSearch = &metav1.Time{Time: oneMinuteAgo}

	cachedIpSet, err := e.GetIPSet(ctx, "test1")
	g.Expect(err).NotTo(HaveOccurred())
	toBeUpdated.SetAnnotations(map[string]string{IpSetHashKey: util.ComputeSha256Hash(cachedIpSet)})

	itr, _, err := e.QueryIPSet(ctx, &geodb.MockGeoDB{}, toBeUpdated)
	g.Expect(err).ShouldNot(HaveOccurred())

	c := 0
	vals := make([]any, 0)
	for itr.Next() {
		c++
		_, val := itr.Value()
		vals = append(vals, val)
	}
	g.Expect(itr.Err()).ShouldNot(HaveOccurred())
	g.Expect(c).Should(Equal(2))
	g.Expect(len(vals)).Should(Equal(2))
}

func Test_QueryIPSet_Big(t *testing.T) {
	g := NewGomegaWithT(t)

	results := []rest.MockResult{
		{
			Body: expectedIPSet(g, "test_files/big_ipset.json"),
		},
		{
			Body: v1.List[v1.FlowLog]{
				Items: []v1.FlowLog{},
			},
		},
		{
			Body: v1.List[v1.FlowLog]{
				Items: []v1.FlowLog{},
			},
		},
	}

	lsc := lsclient.NewMockClient("", results...)

	// mock controller runtime client.
	scheme := scheme.Scheme
	err := v1scheme.AddCalicoResourcesToScheme(scheme)
	g.Expect(err).NotTo(HaveOccurred())
	fakeClient := fakeclient.NewClientBuilder().WithScheme(scheme).Build()

	e := NewService(lsc, fakeClient, "cluster", time.Duration(1))
	ctx := t.Context()

	testFeed := &apiv3.GlobalThreatFeed{}
	testFeed.Name = "test_big"
	i, _, err := e.QueryIPSet(ctx, &geodb.MockGeoDB{}, testFeed)
	g.Expect(err).ShouldNot(HaveOccurred())

	itr := i.(*queryIterator[v1.FlowLog, v1.FlowLogParams])

	g.Expect(itr.queries).Should(HaveLen(4), "Input was split into 2x2 arrays")
	g.Expect(itr.queries[0].queryParams.IPMatches).Should(HaveLen(1))
	g.Expect(itr.queries[0].queryParams.IPMatches[0].IPs).Should(HaveLen(MaxClauseCount))
	g.Expect(itr.queries[1].queryParams.IPMatches).Should(HaveLen(1))
	g.Expect(itr.queries[1].queryParams.IPMatches[0].IPs).Should(HaveLen(MaxClauseCount))
	g.Expect(itr.queries[2].queryParams.IPMatches).Should(HaveLen(1))
	g.Expect(itr.queries[2].queryParams.IPMatches[0].IPs).Should(HaveLen(256))
	g.Expect(itr.queries[3].queryParams.IPMatches).Should(HaveLen(1))
	g.Expect(itr.queries[3].queryParams.IPMatches[0].IPs).Should(HaveLen(256))
}

func Test_ListSets(t *testing.T) {
	g := NewGomegaWithT(t)

	// mock linseed client
	lsc := lsclient.NewMockClient("")

	// mock controller runtime client.
	scheme := scheme.Scheme
	err := v1scheme.AddCalicoResourcesToScheme(scheme)
	g.Expect(err).NotTo(HaveOccurred())
	fakeClient := fakeclient.NewClientBuilder().WithScheme(scheme).Build()

	e := NewService(lsc, fakeClient, "cluster", time.Duration(1))
	ctx := t.Context()

	lsc.SetResults(rest.MockResult{
		Body: v1.List[v1.IPSetThreatFeed]{
			Items: []v1.IPSetThreatFeed{},
		},
		StatusCode: 200,
	})
	metas, err := e.ListIPSets(ctx)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(metas).To(HaveLen(0))

	lsc.SetResults(rest.MockResult{
		Err:        fmt.Errorf("linseed error"),
		StatusCode: 404,
	})
	metas, err = e.ListIPSets(ctx)
	g.Expect(err).To(HaveOccurred())
	g.Expect(metas).To(HaveLen(0))

	lsc.SetResults(rest.MockResult{
		Body: v1.List[v1.DomainNameSetThreatFeed]{
			Items: []v1.DomainNameSetThreatFeed{},
		},
		StatusCode: 200,
	})
	metas, err = e.ListDomainNameSets(ctx)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(metas).To(HaveLen(0))

	lsc.SetResults(rest.MockResult{
		Err:        fmt.Errorf("linseed error"),
		StatusCode: 404,
	})
	metas, err = e.ListDomainNameSets(ctx)
	g.Expect(err).To(HaveOccurred())
	g.Expect(metas).To(HaveLen(0))
}

func Test_Put_Set(t *testing.T) {
	g := NewGomegaWithT(t)

	lsc := lsclient.NewMockClient("")

	// mock controller runtime client.
	scheme := scheme.Scheme
	err := v1scheme.AddCalicoResourcesToScheme(scheme)
	g.Expect(err).NotTo(HaveOccurred())
	fakeClient := fakeclient.NewClientBuilder().WithScheme(scheme).Build()

	e := NewService(lsc, fakeClient, "cluster", time.Duration(1))

	ctx := t.Context()

	lsc.SetResults(rest.MockResult{
		Body: v1.BulkResponse{
			Total:     1,
			Succeeded: 1,
		},
	})
	err = e.PutIPSet(ctx, "test1", IPSetSpec{"1.2.3.4"})
	g.Expect(err).ToNot(HaveOccurred())

	lsc.SetResults(rest.MockResult{
		Body: v1.BulkResponse{
			Total:     1,
			Succeeded: 1,
		},
	})
	err = e.PutDomainNameSet(ctx, "test1", DomainNameSetSpec{"hackers.and.badguys"})
	g.Expect(err).ToNot(HaveOccurred())
}

func TestSplitIPSetToInterface(t *testing.T) {
	g := NewGomegaWithT(t)

	mul := 2
	offset := 11

	var input IPSetSpec
	for i := 0; i < mul*MaxClauseCount+offset; i++ {
		input = append(input, fmt.Sprintf("%d", i))
	}

	output := splitIPSet(input)

	g.Expect(len(output)).Should(Equal(mul + 1))
	for i := range mul {
		g.Expect(len(output[i])).Should(Equal(MaxClauseCount))
		for idx, v := range output[i] {
			g.Expect(v).Should(Equal(fmt.Sprintf("%d", i*MaxClauseCount+idx)))
		}
	}
	g.Expect(len(output[mul])).Should(Equal(offset))
	for idx, v := range output[mul] {
		g.Expect(v).Should(Equal(fmt.Sprintf("%d", mul*MaxClauseCount+idx)))
	}
}

func Test_Delete_Set(t *testing.T) {
	g := NewGomegaWithT(t)

	lsc := lsclient.NewMockClient("")

	// mock controller runtime client.
	scheme := scheme.Scheme
	err := v1scheme.AddCalicoResourcesToScheme(scheme)
	g.Expect(err).NotTo(HaveOccurred())
	fakeClient := fakeclient.NewClientBuilder().WithScheme(scheme).Build()

	e := NewService(lsc, fakeClient, "cluster", time.Duration(1))

	ctx := t.Context()

	lsc.SetResults(rest.MockResult{
		Body: v1.BulkResponse{
			Total:     1,
			Succeeded: 1,
		},
	})
	err = e.DeleteIPSet(ctx, Meta{Name: "test"})
	g.Expect(err).ToNot(HaveOccurred())

	three := int64(3)
	four := int64(4)
	lsc.SetResults(rest.MockResult{
		Body: v1.BulkResponse{
			Total:     1,
			Succeeded: 1,
		},
	})
	err = e.DeleteDomainNameSet(ctx, Meta{Name: "test", SeqNo: &three, PrimaryTerm: &four})
	g.Expect(err).ToNot(HaveOccurred())
}

func strPtr(val string) *string {
	return &val
}

func expectedIPSet(gomega *WithT, name string) *v1.List[v1.IPSetThreatFeed] {
	f, err := os.Open(name)
	gomega.Expect(err).ShouldNot(HaveOccurred())
	b, err := io.ReadAll(f)
	gomega.Expect(err).ShouldNot(HaveOccurred())
	err = f.Close()
	gomega.Expect(err).ShouldNot(HaveOccurred())

	dst := &bytes.Buffer{}
	if err := json.Compact(dst, b); err != nil {
		Expect(err).ShouldNot(HaveOccurred())
	}

	var params v1.List[v1.IPSetThreatFeed]
	err = json.Unmarshal(dst.Bytes(), &params)
	gomega.Expect(err).ShouldNot(HaveOccurred())

	return &params
}
