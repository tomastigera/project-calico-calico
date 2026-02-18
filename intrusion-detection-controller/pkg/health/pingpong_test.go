package health

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("PingPonger Tests", func() {

	Context("Test Worker worker Queue", func() {
		It("Worker health check ", func() {
			ctx, CancelFunc := context.WithCancel(context.Background())
			defer CancelFunc()

			listenForPings := func(ctx <-chan struct{}, pinger PingPonger) {
				for {
					select {
					case pong := <-pinger.ListenForPings():
						pong.Pong()
					case <-ctx:
						return
					}
				}
			}

			pingPonger := NewPingPonger()

			go listenForPings(ctx.Done(), pingPonger)

			Expect(pingPonger.Ping(ctx)).To(BeNil())

		})
	})
})
