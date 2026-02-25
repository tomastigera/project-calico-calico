// Copyright 2022 Tigera Inc. All rights reserved.
package sync

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	mymock "github.com/projectcalico/calico/egress-gateway/sync/mocks"
)

// Client tests
var _ = Describe("Tests client functionality", func() {

	var (
		ctx context.Context
	)

	Context("Tests connectAndSync", func() {
		BeforeEach(func() {
			ctx = context.Background()
		})

		It("should handle a Dial failure", func() {
			// In this test we expect Dial to return an error in which case the Close is called. A Dial()
			// should have a corresponding Close() call in case.
			dialTimes := 0
			closeTimes := 0

			By("defining the mock client utility methods. Counting the number of times Dial and Close are called")
			mc := &mymock.Connection{}
			mc.On("Dial").Return(errors.New("Error Dialing")).Run(func(args mock.Arguments) { dialTimes++ })
			mc.On("Close").Return(nil).Run(func(args mock.Arguments) { closeTimes++ })

			By("defining the mock client")
			c := &Client{
				conn: mc,
			}

			By("calling connectAndSync")
			connectAndSync(ctx, c)
			By("validating the number of times the Dial and Close functions were called is equal")
			Expect(dialTimes == closeTimes).To(BeTrue())
			By("validating the number of times the Dial function was called is equal a single call")
			Expect(dialTimes).To(Equal(1))
			By("validating the number of times the Close function was called is equal to a single call")
			Expect(closeTimes).To(Equal(1))
		})

		It("should handle a Sync initiation failure", func() {
			// In this test we expect an equal number of call to Dial() and Close() connections. A Dial()
			// should have a corresponding Close() call in case.
			dialTimes := 0
			closeTimes := 0

			By("defining the mock client utility methods. Counting the number of times Dial and Close are called")
			mc := &mymock.Connection{}
			mc.On("Dial").Return(nil).Run(func(args mock.Arguments) { dialTimes++ })
			mc.On("Close").Return(nil).Run(func(args mock.Arguments) { closeTimes++ })
			mc.On("Sync").Return(nil, errors.New(
				"rpc error: code = Unavailable desc = connection error: desc = \"transport: Error while "+
					" dialing dial unix /var/run/nodeagent/socket: connect: no such file or directory\""))

			By("defining the mock client")
			c := &Client{
				conn: mc,
			}

			By("calling connectAndSync")
			connectAndSync(ctx, c)
			By("validating the number of times the Dial and Close functions were called is equal")
			Expect(dialTimes == closeTimes).To(BeTrue())
			By("validating the number of times the Dial function was called is equal a single call")
			Expect(dialTimes).To(Equal(1))
			By("validating the number of times the Close function was called is equal to a single call")
			Expect(closeTimes).To(Equal(1))
		})
	})
})
