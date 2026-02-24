// Copyright 2024 Tigera Inc. All rights reserved.

package health

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Multi Tests", func() {
	Context("Test Pingers", func() {
		ctx := context.TODO()
		Expect(Pingers{}.Ping(ctx)).ShouldNot(HaveOccurred())
		Expect(Pingers{MockPinger{}}.Ping(ctx)).ShouldNot(HaveOccurred())
		Expect(Pingers{MockPinger{}, MockPinger{}}.Ping(ctx)).ShouldNot(HaveOccurred())
		Expect(Pingers{MockPinger{errors.New("error")}}.Ping(ctx)).Should(HaveOccurred())
		Expect(Pingers{MockPinger{}, MockPinger{errors.New("error")}}.Ping(ctx)).Should(HaveOccurred())
		Expect(Pingers{MockPinger{errors.New("error")}, MockPinger{}}.Ping(ctx)).Should(HaveOccurred())
	})

	Context("Test Readiers", func() {
		Expect(Readiers{}.Ready()).Should(BeTrue())
		Expect(Readiers{MockReadier{}}.Ready()).Should(BeFalse())
		Expect(Readiers{MockReadier{}, MockReadier{}}.Ready()).Should(BeFalse())
		Expect(Readiers{MockReadier{}, MockReadier{true}}.Ready()).Should(BeFalse())
		Expect(Readiers{MockReadier{true}, MockReadier{}}.Ready()).Should(BeFalse())
		Expect(Readiers{MockReadier{true}}.Ready()).Should(BeTrue())
		Expect(Readiers{MockReadier{true}, MockReadier{true}}.Ready()).Should(BeTrue())
	})
})
