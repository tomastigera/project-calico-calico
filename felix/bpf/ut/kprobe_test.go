//go:build !windows

// Copyright (c) 2021 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ut

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/events"
	"github.com/projectcalico/calico/felix/bpf/kprobe"
)

func TestKprobe(t *testing.T) {
	RegisterTestingT(t)
	bpfEvnt, err := events.New(events.SourceRingBuffer, 1<<20)
	Expect(err).NotTo(HaveOccurred())
	kp := kprobe.New("debug", bpfEvnt)
	Expect(kp).NotTo(BeNil())
	Expect(err).NotTo(HaveOccurred())
	err = kp.AttachTCPv4()
	Expect(err).NotTo(HaveOccurred())
	err = kp.AttachUDPv4()
	Expect(err).NotTo(HaveOccurred())
	err = kp.AttachSyscall()
	Expect(err).NotTo(HaveOccurred())
	err = bpfEvnt.Close()
	Expect(err).NotTo(HaveOccurred())
	err = kp.DetachTCPv4()
	Expect(err).NotTo(HaveOccurred())
	err = kp.DetachUDPv4()
	Expect(err).NotTo(HaveOccurred())
	err = kp.DetachSyscall()
	Expect(err).NotTo(HaveOccurred())
}
