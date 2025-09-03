// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

package l7log

import (
	"fmt"
	"time"

	"github.com/gavv/monotime"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/jitter"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

type aggregatorRef struct {
	a *Aggregator
	d []types.Reporter
}

type L7Reporter struct {
	dispatchers  map[string]types.Reporter
	aggregators  []aggregatorRef
	flushTrigger <-chan time.Time

	healthAggregator *health.HealthAggregator

	// Allow the time function to be mocked for test purposes.
	timeNowFn func() time.Duration
}

const (
	l7HealthName     = "L7Reporter"
	l7HealthInterval = 10 * time.Second
)

func NewReporter(dispatchers map[string]types.Reporter, flushInterval time.Duration, healthAggregator *health.HealthAggregator) *L7Reporter {
	return NewReporterWithShims(dispatchers, jitter.NewTicker(flushInterval, flushInterval/10).Channel(), healthAggregator)
}

func NewReporterWithShims(dispatchers map[string]types.Reporter, flushTrigger <-chan time.Time, healthAggregator *health.HealthAggregator) *L7Reporter {
	if healthAggregator != nil {
		healthAggregator.RegisterReporter(l7HealthName, &health.HealthReport{Live: true, Ready: true}, l7HealthInterval*2)
	}
	return &L7Reporter{
		dispatchers:      dispatchers,
		flushTrigger:     flushTrigger,
		timeNowFn:        monotime.Now,
		healthAggregator: healthAggregator,
	}
}

func (r *L7Reporter) AddAggregator(agg *Aggregator, dispatchers []string) {
	var ref aggregatorRef
	ref.a = agg
	for _, d := range dispatchers {
		dis, ok := r.dispatchers[d]
		if !ok {
			// This is a code error and is unrecoverable.
			log.Panic(fmt.Sprintf("unknown dispatcher \"%s\"", d))
		}
		ref.d = append(ref.d, dis)
	}
	r.aggregators = append(r.aggregators, ref)
}

func (r *L7Reporter) Start() error {
	go r.run()
	return nil
}

func (r *L7Reporter) Report(u any) error {
	update, ok := u.(Update)
	if !ok {
		return fmt.Errorf("invalid l7 log update")
	}
	for _, agg := range r.aggregators {
		if err := agg.a.FeedUpdate(update); err != nil {
			return err
		}
	}
	return nil
}

func (r *L7Reporter) run() {
	healthTicks := time.NewTicker(l7HealthInterval)
	defer healthTicks.Stop()
	r.reportHealth()
	for {
		log.Debug("L7 reporter loop iteration")

		// TODO(doublek): Stop and flush cases.
		select {
		case <-r.flushTrigger:
			log.Debug("L7 log flush tick")
			for _, agg := range r.aggregators {
				l7Log := agg.a.Get()
				log.Debugf("Flush %v L7 logs", len(l7Log))
				if len(l7Log) > 0 {
					for _, d := range agg.d {
						log.WithFields(log.Fields{
							"size":       len(l7Log),
							"dispatcher": d,
						}).Debug("Dispatching log buffer")
						if err := d.Report(l7Log); err != nil {
							log.WithError(err).Debug("failed to dispatch L7 log")
						}
					}
				}
			}
		case <-healthTicks.C:
			// Periodically report current health.
			r.reportHealth()
		}
	}
}

func (r *L7Reporter) reportHealth() {
	if r.healthAggregator != nil {
		r.healthAggregator.Report(l7HealthName, &health.HealthReport{
			Live:  true,
			Ready: r.canPublish(),
		})
	}
}

func (r *L7Reporter) canPublish() bool {
	for name, d := range r.dispatchers {
		err := d.Start()
		if err != nil {
			log.WithError(err).
				WithField("name", name).
				Error("dispatcher unable to initialize")
			return false
		}
	}
	return true
}
