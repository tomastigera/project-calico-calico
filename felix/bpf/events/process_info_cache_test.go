// Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.

package events_test

import (
	"fmt"
	"io/fs"
	"sync"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/events"
	collector "github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
)

var (
	gcInterval         = time.Millisecond
	ttl                = time.Second
	eventuallyTimeout  = 3 * time.Second // 3 times to TTL to avoid any flakes.
	eventuallyInterval = 10 * time.Millisecond
)

var (
	ip1           = utils.IpStrTo16Byte("10.128.0.14")
	ip2           = utils.IpStrTo16Byte("10.128.0.7")
	tuple1        = tuple.Make(ip1, ip2, 6, 40000, 80)
	processEvent1 = events.EventProtoStats{
		Proto:       uint32(6),
		Saddr:       [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 128, 0, 14}, // 10.128.0.14
		Daddr:       [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 128, 0, 7},  // 10.128.0.7
		Sport:       uint16(40000),
		Dport:       uint16(80),
		ProcessName: [events.ProcessNameLen]byte{99, 117, 114, 108, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		Pid:         uint32(12345),
	}
	tcpStatsEvent1 = events.EventTcpStats{
		Saddr:             [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 128, 0, 14}, // 10.128.0.14
		Daddr:             [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 128, 0, 7},  // 10.128.0.7
		Sport:             uint16(40000),
		Dport:             uint16(80),
		SendCongestionWnd: 10,
		SmoothRtt:         1234,
		MinRtt:            256,
		Mss:               128,
		TotalRetrans:      2,
		LostOut:           3,
		UnrecoveredRTO:    4,
	}
	processPathEvent1 = events.ProcessPath{
		Pid:       12345,
		Filename:  "/usr/bin/curl",
		Arguments: "example.com",
	}
	processEvent1DifferentProcessName = events.EventProtoStats{
		Proto:       uint32(6),
		Saddr:       [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 128, 0, 14}, // 10.128.0.14
		Daddr:       [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 128, 0, 7},  // 10.128.0.7
		Sport:       uint16(40000),
		Dport:       uint16(80),
		ProcessName: [events.ProcessNameLen]byte{119, 103, 101, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		Pid:         uint32(54321),
	}
)

type lookupResult struct {
	name collector.ProcessInfo
	ok   bool
}

var _ = Describe("ProcessPathCache tests", func() {
	var (
		procfs     *syncMapFS
		ppc        *events.BPFProcessPathCache
		kprobeChan chan events.ProcessPath

		gcInterval time.Duration
		ttl        time.Duration
	)

	BeforeEach(func() {
		gcInterval = 100 * time.Millisecond
		ttl = time.Second
		kprobeChan = make(chan events.ProcessPath)
		procfs = &syncMapFS{
			fs: fstest.MapFS{
				"98765/cmdline": &fstest.MapFile{
					Data: []byte("wget\x00example.com"),
					Mode: 0444,
				},

				// /proc is full of entries that we're not interested in.
				"nonnumber/cmdline": &fstest.MapFile{
					Data: []byte("wget\x00example.com"),
					Mode: 0444,
				},
				"nondir": &fstest.MapFile{
					Data: []byte("no important"),
					Mode: 0444,
				},
			},
		}
	})

	JustBeforeEach(func() {
		ppc = events.NewBPFProcessPathCache(kprobeChan, gcInterval, ttl, events.WithProcfs(procfs))
		ppc.Start()
	})

	AfterEach(func() {
		ppc.Stop()
	})

	sendKprobeUpdate := func(update events.ProcessPath) {
		Eventually(kprobeChan).Should(BeSent(update))
		// Dummy update to make sure the previous one was flushed (chan
		// is unbuffered).
		Eventually(kprobeChan).Should(BeSent(events.ProcessPath{
			Pid:       1001,
			Filename:  "dummy",
			Arguments: "dummy",
		}))
	}

	It("Should lookup the cmdline from /proc on first query", func() {
		pi, ok := ppc.Lookup(98765)
		Expect(ok).To(BeTrue())
		Expect(pi).To(Equal(events.ProcessPathInfo{
			Path: "wget",
			Args: "example.com",
		}))

		// Update to /proc will be ignored due to cache.
		procfs.set("98765/cmdline", &fstest.MapFile{
			Data: []byte("curl\x00example.com"),
			Mode: 0444,
		})
		pi, ok = ppc.Lookup(98765)
		Expect(ok).To(BeTrue())
		Expect(pi).To(Equal(events.ProcessPathInfo{
			Path: "wget",
			Args: "example.com",
		}), "Cache should not have re-queried procfs")
	})

	It("Should cache tombstones for missing PIDs", func() {
		_, ok := ppc.Lookup(100)
		Expect(ok).To(BeFalse())

		// Update to /proc will be ignored due to cache.
		procfs.set("100/cmdline", &fstest.MapFile{
			Data: []byte("curl\x00example.com"),
			Mode: 0444,
		})
		_, ok = ppc.Lookup(100)
		Expect(ok).To(BeFalse(), "Cache should not have re-queried procfs")
	})

	It("Should handle a kprobe followed by missing procfs lookup", func() {
		sendKprobeUpdate(events.ProcessPath{
			Pid:       100,
			Filename:  "curl",
			Arguments: "example.com",
		})

		result, ok := ppc.Lookup(100)
		Expect(ok).To(BeTrue())
		Expect(result.Path).To(Equal("curl"))
		Expect(result.Args).To(Equal("example.com"))

		// Update to /proc will be ignored due to cache.
		procfs.set("100/cmdline", &fstest.MapFile{
			Data: []byte("floof\x00boof.com"),
			Mode: 0444,
		})

		result, ok = ppc.Lookup(100)
		Expect(ok).To(BeTrue())
		Expect(result.Path).To(Equal("curl"))
		Expect(result.Args).To(Equal("example.com"))
	})

	It("Should handle a kprobe followed by procfs hit", func() {
		sendKprobeUpdate(events.ProcessPath{
			Pid:       100,
			Filename:  "curl",
			Arguments: "example.com",
		})

		// Update to /proc before Lookup should override.
		procfs.set("100/cmdline", &fstest.MapFile{
			Data: []byte("floof\x00boof.com"),
			Mode: 0444,
		})

		result, ok := ppc.Lookup(100)
		Expect(ok).To(BeTrue())
		Expect(result.Path).To(Equal("floof"))
		Expect(result.Args).To(Equal("boof.com"))

		// Update from kprobe should take effect.
		procfs.delete("100/cmdline")
		sendKprobeUpdate(events.ProcessPath{
			Pid:       100,
			Filename:  "wget",
			Arguments: "blibble.com",
		})

		result, ok = ppc.Lookup(100)
		Expect(ok).To(BeTrue())
		Expect(result.Path).To(Equal("wget"))
		Expect(result.Args).To(Equal("blibble.com"))
	})

	Describe("with an ESRCH error", func() {
		BeforeEach(func() {
			// ESRCH happens when the process exits after we open the file
			// but before we read.
			procfs.NextReadFileErr = fmt.Errorf("a wrapper around %w", syscall.ESRCH)
		})

		It("Should cache tombstones for missing PIDs", func() {
			_, ok := ppc.Lookup(100)
			Expect(ok).To(BeFalse())

			// Update to /proc will be ignored due to cache.
			procfs.set("100/cmdline", &fstest.MapFile{
				Data: []byte("curl\x00example.com"),
				Mode: 0444,
			})
			_, ok = ppc.Lookup(100)
			Expect(ok).To(BeFalse(), "Cache should not have re-queried procfs")

			Expect(ppc.UnexpectedErrorCount.Load()).To(Equal(int64(0)),
				"ESRCH errors are expected and should not go through the warning path")
		})
	})

	Describe("with an unexpected error", func() {
		BeforeEach(func() {
			procfs.NextReadFileErr = fmt.Errorf("an err-or")
		})

		It("Should cache tombstones for missing PIDs", func() {
			_, ok := ppc.Lookup(100)
			Expect(ok).To(BeFalse())

			// Update to /proc will be ignored due to cache.
			procfs.set("100/cmdline", &fstest.MapFile{
				Data: []byte("curl\x00example.com"),
				Mode: 0444,
			})
			_, ok = ppc.Lookup(100)
			Expect(ok).To(BeFalse(), "Cache should not have re-queried procfs")

			Expect(ppc.UnexpectedErrorCount.Load()).To(Equal(int64(1)),
				"Unexpected errors should be counted/warning logged")
		})
	})

	Describe("with extra short TTL", func() {
		BeforeEach(func() {
			ttl = 100 * time.Millisecond
		})

		It("should poll procfs before end of TTL", func() {
			time.Sleep(ttl)
			// Delete before lookup so that we'll only see a result if the
			// entry was already cached.
			procfs.delete("98765/cmdline")

			pi, ok := ppc.Lookup(98765)
			Expect(ok).To(BeTrue())
			Expect(pi).To(Equal(events.ProcessPathInfo{
				Path: "wget",
				Args: "example.com",
			}), "Entry should still be in the cache from the poll")

			By("checking that entries do time out")
			Eventually(func() bool {
				_, ok = ppc.Lookup(98765)
				return ok
			}, 5*ttl, "10ms").Should(BeFalse(), "Entry should have timed out")
		})
	})
})

var _ = Describe("ProcessInfoCache tests", func() {
	var (
		procfs              fstest.MapFS
		pp                  *events.BPFProcessPathCache
		pic                 *events.BPFProcessInfoCache
		testProcessChan     chan events.EventProtoStats
		testTcpStatsChan    chan events.EventTcpStats
		testProcessPathChan chan events.ProcessPath
	)

	eventuallyCheckCache := func(key tuple.Tuple, dir collector.TrafficDirection, expectedProcessInfo collector.ProcessInfo, infoInCache bool) {
		Eventually(func() lookupResult {
			processInfo, ok := pic.Lookup(key, dir)
			return lookupResult{processInfo, ok}
		}, eventuallyTimeout, eventuallyInterval).Should(Equal(lookupResult{expectedProcessInfo, infoInCache}))
	}

	BeforeEach(func() {
		testProcessChan = make(chan events.EventProtoStats, 10)
		testTcpStatsChan = make(chan events.EventTcpStats, 10)
		testProcessPathChan = make(chan events.ProcessPath, 10)
		procfs = fstest.MapFS{
			"98765/cmdline": &fstest.MapFile{
				Data: []byte("wget\x00example.com"),
				Mode: 0444,
			},
		}
		pp = events.NewBPFProcessPathCache(testProcessPathChan, gcInterval, 30*ttl, events.WithProcfs(procfs))
		pic = events.NewBPFProcessInfoCache(testProcessChan, testTcpStatsChan, gcInterval, ttl, pp)
		Expect(pic.Start()).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		pic.Stop()
	})

	It("Should cache process information", func() {
		By("Checking that lookup cache doesn't contain the right process info")
		expectedProcessInfo := collector.ProcessInfo{}

		eventuallyCheckCache(tuple1, collector.TrafficDirOutbound, expectedProcessInfo, false)

		By("Sending a process info event")
		testProcessChan <- processEvent1
		testTcpStatsChan <- tcpStatsEvent1

		By("Checking that lookup returns process information and is converted correctly")
		expectedProcessInfo = collector.ProcessInfo{
			Tuple: tuple1,
			ProcessData: collector.ProcessData{
				Name: "curl",
				Pid:  12345,
			},
			TcpStatsData: collector.TcpStatsData{
				SendCongestionWnd: 10,
				SmoothRtt:         1234,
				MinRtt:            256,
				Mss:               128,
				TotalRetrans:      2,
				LostOut:           3,
				UnrecoveredRTO:    4,
				IsDirty:           true,
			},
		}
		eventuallyCheckCache(tuple1, collector.TrafficDirOutbound, expectedProcessInfo, true)

		By("replacing the process info event")
		testProcessChan <- processEvent1DifferentProcessName

		By("Checking that lookup returns process information and is converted correctly")
		expectedProcessInfo = collector.ProcessInfo{
			Tuple: tuple1,
			ProcessData: collector.ProcessData{
				Name: "wget",
				Pid:  54321,
			},
			TcpStatsData: collector.TcpStatsData{
				SendCongestionWnd: 10,
				SmoothRtt:         1234,
				MinRtt:            256,
				Mss:               128,
				TotalRetrans:      2,
				LostOut:           3,
				UnrecoveredRTO:    4,
				IsDirty:           true,
			},
		}
		eventuallyCheckCache(tuple1, collector.TrafficDirOutbound, expectedProcessInfo, true)
	})
	It("Should cache process path information if available", func() {
		By("Checking that lookup cache doesn't contain the right process info")
		expectedProcessInfo := collector.ProcessInfo{}

		eventuallyCheckCache(tuple1, collector.TrafficDirOutbound, expectedProcessInfo, false)

		By("Sending a process info event, path event")
		testProcessPathChan <- processPathEvent1
		time.Sleep(1 * time.Millisecond)
		testProcessChan <- processEvent1
		testTcpStatsChan <- tcpStatsEvent1

		// time.Sleep(1 * time.Millisecond)
		By("Checking that lookup returns process information and is converted correctly")
		expectedProcessInfo = collector.ProcessInfo{
			Tuple: tuple1,
			ProcessData: collector.ProcessData{
				Name:      "/usr/bin/curl",
				Pid:       12345,
				Arguments: "example.com",
			},
			TcpStatsData: collector.TcpStatsData{
				SendCongestionWnd: 10,
				SmoothRtt:         1234,
				MinRtt:            256,
				Mss:               128,
				TotalRetrans:      2,
				LostOut:           3,
				UnrecoveredRTO:    4,
				IsDirty:           true,
			},
		}
		eventuallyCheckCache(tuple1, collector.TrafficDirOutbound, expectedProcessInfo, true)
	})
	It("Should expire cached process information", func() {
		By("Checking that lookup cache doesn't contain the right process info")
		expectedProcessInfo := collector.ProcessInfo{}
		eventuallyCheckCache(tuple1, collector.TrafficDirOutbound, expectedProcessInfo, false)

		By("Sending a process info event")
		testProcessChan <- processEvent1

		By("Checking that lookup returns process information")
		expectedProcessInfo = collector.ProcessInfo{
			Tuple: tuple1,
			ProcessData: collector.ProcessData{
				Name: "curl",
				Pid:  12345,
			},
		}
		eventuallyCheckCache(tuple1, collector.TrafficDirOutbound, expectedProcessInfo, true)

		By("Checking that lookup expires process information")
		expectedProcessInfo = collector.ProcessInfo{}

		eventuallyCheckCache(tuple1, collector.TrafficDirOutbound, expectedProcessInfo, false)
	})
})

var entry events.ProcessPathInfo

// BenchmarkLookupPID1 benchmarks looking up PID 1, which exists.
func BenchmarkLookupPID1(b *testing.B) {
	r := setUpBench(b)
	for i := 0; i < b.N; i++ {
		entry, _ = r.Lookup(1)
	}
}

// BenchmarkLookupPID12345678 benchmarks looking up PID 12345678, which
// doesn't exist.
func BenchmarkLookupPID12345678(b *testing.B) {
	r := setUpBench(b)
	for i := 0; i < b.N; i++ {
		entry, _ = r.Lookup(12345678)
	}
}

func setUpBench(b *testing.B) *events.BPFProcessPathCache {
	procfs := fstest.MapFS{
		"1/cmdline": &fstest.MapFile{
			Data:    []byte("init\x00some args"),
			Mode:    0444,
			ModTime: time.Now(),
		},
	}
	for i := 100; i < 10000; i++ {
		procfs[fmt.Sprintf("%d/cmdline", i)] = &fstest.MapFile{
			Data:    []byte("someprocess\x00some args"),
			Mode:    0444,
			ModTime: time.Now(),
		}
	}
	r := events.NewBPFProcessPathCache(
		nil,
		10*time.Second,
		20*time.Second,
		events.WithProcfs(procfs),
	)
	b.Cleanup(r.Stop)
	return r
}

// syncMapFS is a MapFS that is safe for concurrent access via the
// ReadFile/ReadDir methods.  Test code must use set/delete to update entries.
type syncMapFS struct {
	mu sync.Mutex
	fs fstest.MapFS

	NextReadFileErr error
}

func (s *syncMapFS) Open(name string) (fs.File, error) {
	panic("not implemented")
}

func (s *syncMapFS) ReadFile(name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.NextReadFileErr != nil {
		err := s.NextReadFileErr
		s.NextReadFileErr = nil
		return nil, err
	}
	return s.fs.ReadFile(name)
}

func (s *syncMapFS) ReadDir(name string) ([]fs.DirEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fs.ReadDir(name)
}

func (s *syncMapFS) set(path string, file *fstest.MapFile) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fs[path] = file
}

func (s *syncMapFS) delete(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.fs, path)
}
