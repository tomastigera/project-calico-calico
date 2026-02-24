// Copyright 2019 Tigera Inc. All rights reserved.

package health

import (
	"context"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type testPinger struct{}

func (p testPinger) Ping(context.Context) error {
	return nil
}

type testReadier struct {
	r bool
}

func (r testReadier) Ready() bool {
	return r.r
}

var _ = Describe("Multi Tests", func() {
	Context("Test Livness Serve HTTP", func() {
		uut := liveness{testPinger{}}
		resp := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/liveness", nil)
		uut.ServeHTTP(resp, req)
		Expect(resp.Code).To(Equal(http.StatusOK))
	})

	Context("Test Readiness Server Http", func() {
		It("Readiness Success", func() {
			uut := readiness{testReadier{true}}
			resp := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/liveness", nil)
			uut.ServeHTTP(resp, req)
			Expect(resp.Code).To(Equal(http.StatusOK))
		})
		It("Readiness Fail", func() {
			uut := readiness{testReadier{false}}
			resp := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/liveness", nil)
			uut.ServeHTTP(resp, req)
			Expect(resp.Code).To(Equal(http.StatusInternalServerError))
		})
	})
})
