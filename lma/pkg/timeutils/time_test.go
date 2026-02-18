// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package timeutils_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lma/pkg/timeutils"
)

var _ = Describe("Time parsing works", func() {
	It("Parses now without error", func() {
		now := time.Now()
		s := "now"
		t, p, err := timeutils.ParseTime(now, &s)
		Expect(err).NotTo(HaveOccurred())
		Expect(t).NotTo(BeNil())
		Expect(now.Sub(*t)).To(BeZero())
		Expect(p).NotTo(BeNil())
		Expect(p).To(Equal(s))
	})

	It("Parses now - 0 without error", func() {
		now := time.Now()
		s := "now - 0"
		t, p, err := timeutils.ParseTime(now, &s)
		Expect(err).NotTo(HaveOccurred())
		Expect(t).NotTo(BeNil())
		Expect(now.Sub(*t)).To(BeZero())
		Expect(p).NotTo(BeNil())
		Expect(p).To(Equal(s))
	})

	It("Parses now - 15m without error", func() {
		now := time.Now()
		s := "now - 15m"
		t, p, err := timeutils.ParseTime(now, &s)
		Expect(err).NotTo(HaveOccurred())
		Expect(t).NotTo(BeNil())
		Expect(now.Sub(*t)).To(Equal(15 * time.Minute))
		Expect(p).NotTo(BeNil())
		Expect(p).To(Equal(s))
	})

	It("Parses now-10m without error", func() {
		now := time.Now()
		s := "now-10m"
		t, p, err := timeutils.ParseTime(now, &s)
		Expect(err).NotTo(HaveOccurred())
		Expect(t).NotTo(BeNil())
		Expect(now.Sub(*t)).To(Equal(10 * time.Minute))
		Expect(p).NotTo(BeNil())
		Expect(p).To(Equal(s))
	})

	It("Parses now-100h without error", func() {
		now := time.Now()
		s := "now-100h"
		t, p, err := timeutils.ParseTime(now, &s)
		Expect(err).NotTo(HaveOccurred())
		Expect(t).NotTo(BeNil())
		Expect(now.Sub(*t)).To(Equal(100 * time.Hour))
		Expect(p).NotTo(BeNil())
		Expect(p).To(Equal(s))
	})

	It("Parses now-3d without error", func() {
		now := time.Now()
		s := "now-3d"
		t, p, err := timeutils.ParseTime(now, &s)
		Expect(err).NotTo(HaveOccurred())
		Expect(t).NotTo(BeNil())
		Expect(now.Sub(*t)).To(Equal(3 * 24 * time.Hour))
		Expect(p).NotTo(BeNil())
		Expect(p).To(Equal(s))
	})

	It("Does not parse now-32", func() {
		now := time.Now()
		s := "now-32"
		t, p, err := timeutils.ParseTime(now, &s)
		Expect(err).To(HaveOccurred())
		Expect(t).To(BeNil())
		Expect(p).To(BeNil())
	})

	It("Does not parse now-xxx", func() {
		now := time.Now()
		s := "now-xxx"
		t, p, err := timeutils.ParseTime(now, &s)
		Expect(err).To(HaveOccurred())
		Expect(t).To(BeNil())
		Expect(p).To(BeNil())
	})

	It("Parses an RFC3339 format time and returns it as epoch seconds", func() {
		now := time.Now().UTC()
		s := now.Add(-5 * time.Second).UTC().Format(time.RFC3339)
		t, p, err := timeutils.ParseTime(now, &s)
		Expect(err).NotTo(HaveOccurred())
		Expect(t).NotTo(BeNil())
		Expect(now.Sub(*t) / time.Second).To(BeEquivalentTo(5)) // Avoids ms accuracy in `now` but not in `t`.
		Expect(p).NotTo(BeNil())
		Expect(p).To(Equal(t.Unix()))
	})
})
