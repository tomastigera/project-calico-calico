// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package auth

import (
	"sync/atomic"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/projectcalico/calico/lma/pkg/cache/fake"
)

var _ = Describe("Test Caching Authorizer", func() {
	var (
		fakeCache *fake.Cache[string, bool]
		subject   *cachingAuthorizer
	)

	BeforeEach(func() {
		fakeAuth := &fakeAuthorizer{}
		fakeCache = fake.NewCache[string, bool]()

		subject = newCachingAuthorizer(fakeCache, fakeAuth)
	})

	It("should cache values and report metrics", func() {
		execute := func(usr user.Info, resources *authzv1.ResourceAttributes, expectedResult bool, expectedHits, expectedMisses, expectedSize int) {
			result, err := subject.Authorize(usr, resources, nil)
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			ExpectWithOffset(1, result).To(Equal(expectedResult))

			ExpectWithOffset(1, fakeCache.Hits()).To(Equal(expectedHits), "cache hits")
			ExpectWithOffset(1, fakeCache.Misses()).To(Equal(expectedMisses), "cache misses")
			ExpectWithOffset(1, fakeCache.Size()).To(Equal(expectedSize), "cache size")
		}

		ui1 := &user.DefaultInfo{
			Name:   "u1",
			Groups: []string{"g1"},
			Extra:  map[string][]string{"k1": {"v1"}},
		}
		ui2 := &user.DefaultInfo{
			Name:   "u1",
			Groups: []string{"g2"},
			Extra:  map[string][]string{"k1": {"v1"}},
		}
		res1 := &authzv1.ResourceAttributes{
			Namespace: "ns1",
			Verb:      "get",
			Resource:  "pod",
		}
		res2 := &authzv1.ResourceAttributes{
			Namespace: "ns1",
			Verb:      "get",
			Resource:  "pod",
			Name:      "allow",
		}

		execute(ui1, res1, false, 0, 1, 1)
		execute(ui1, res1, false, 1, 1, 1)
		execute(ui2, res1, false, 1, 2, 2)
		execute(ui2, res1, false, 2, 2, 2)
		execute(ui1, res2, true, 2, 3, 3)
		execute(ui1, res2, true, 3, 3, 3)

		fakeCache.Clear()

		execute(ui1, res1, false, 3, 4, 1)
		execute(ui1, res1, false, 4, 4, 1)
	})
})

var _ = Describe("Test Caching Authorizer Key", func() {
	It("should convert to the expected string", func() {
		u := &user.DefaultInfo{
			Name:   "un",
			UID:    "ui",
			Groups: []string{"ug1", "ug2"},
			Extra:  map[string][]string{"ue1": {"a", "b"}},
		}
		attrs := &authzv1.ResourceAttributes{
			Namespace:   "ns",
			Verb:        "vb",
			Group:       "gr",
			Version:     "ver",
			Resource:    "res",
			Subresource: "sub",
			Name:        "nam",
		}

		result := toAuthorizeCacheKey(u, attrs)

		Expect(result).To(Equal("{userName:un userUID:ui userGroups:[ug1 ug2] userExtra:map[ue1:[a b]] attrs:{Namespace:ns Verb:vb Group:gr Version:ver Resource:res Subresource:sub Name:nam FieldSelector:<nil> LabelSelector:<nil>}}"))
	})
})

type fakeAuthorizer struct {
	callCount atomic.Int32
}

func (a *fakeAuthorizer) Authorize(_ user.Info, resources *authzv1.ResourceAttributes, _ *authzv1.NonResourceAttributes) (bool, error) {
	a.callCount.Add(1)
	return resources != nil && resources.Name == "allow", nil
}

var benchmarkResult string

func BenchmarkFmtKey(b *testing.B) {
	u := &user.DefaultInfo{
		Name:   "un",
		UID:    "ui",
		Groups: []string{"ug1", "ug2"},
		Extra:  map[string][]string{"ue1": {"a", "b"}},
	}
	attrs := &authzv1.ResourceAttributes{
		Namespace:   "ns",
		Verb:        "vb",
		Group:       "gr",
		Version:     "ver",
		Resource:    "res",
		Subresource: "sub",
		Name:        "nam",
	}

	expected := "{userName:un userUID:ui userGroups:[ug1 ug2] userExtra:map[ue1:[a b]] attrs:{Namespace:ns Verb:vb Group:gr Version:ver Resource:res Subresource:sub Name:nam}}"

	for i := 0; i < b.N; i++ {
		res := toAuthorizeCacheKey(u, attrs)
		if res != expected {
			b.Fatal("bad result")
		}
		benchmarkResult = res
	}
}
