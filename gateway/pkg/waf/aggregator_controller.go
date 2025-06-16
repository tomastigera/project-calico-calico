package waf

import (
	"sync"
	"time"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

// AggregatorController manages an Aggregator and runs periodic aggregation.
type AggregatorController struct {
	agg    *Aggregator
	period time.Duration
	sink   func([]*v1.WAFLog)
	mu     sync.Mutex
	// stopCh is used to signal the controller to stop.
	stopCh chan struct{}
	// stoppedCh is used to signal that the controller has stopped.
	stoppedCh chan struct{}
}

// NewAggregatorController creates a new AggregatorController.
func NewAggregatorController(period time.Duration, mustKeepFields []string, sink func([]*v1.WAFLog)) (*AggregatorController, error) {
	agg, err := NewAggregator(mustKeepFields)
	if err != nil {
		return nil, err
	}
	return &AggregatorController{
		period:    period,
		sink:      sink,
		agg:       agg,
		stopCh:    make(chan struct{}),
		stoppedCh: make(chan struct{}),
	}, nil
}

// AddLog adds a log to the controller's buffer.
func (c *AggregatorController) AddLog(log *v1.WAFLog) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.agg.AddLog(log)
}

// Run starts the aggregation loop.
func (c *AggregatorController) Run() {
	ticker := time.NewTicker(c.period)
	defer ticker.Stop()
	defer close(c.stoppedCh)
	for {
		select {
		case <-ticker.C:
			c.flushLogs()
		case <-c.stopCh:
			// Make sure we don't lose any logs when stopping.
			c.flushLogs()
			return
		}
	}
}

func (c *AggregatorController) flushLogs() {
	c.mu.Lock()
	defer c.mu.Unlock()

	aggregated := c.agg.EndAggregationPeriod()
	if len(aggregated) > 0 {
		c.sink(aggregated)
	}
}

// Stop signals the controller to stop.
func (c *AggregatorController) Stop() {
	close(c.stopCh)
	<-c.stoppedCh
}
