// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package forwarder

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/storage"
)

var _ = Describe("EventForwarder Close safety", func() {
	It("should not panic when Close is called before Run", func() {
		fwdr := &eventForwarder{
			logger: log.WithFields(log.Fields{
				"context": "eventforwarder",
			}),
			events: &storage.MockEvents{},
		}

		// cancel is nil because Run() was never called.
		// This must not panic.
		Expect(func() { fwdr.Close() }).ShouldNot(Panic())
	})
})
