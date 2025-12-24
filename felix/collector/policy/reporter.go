package policy

import (
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

type ActivityLog struct {
	Policy        PolicyInfo `json:"policy"`
	Rule          string     `json:"rule"`
	LastEvaluated time.Time  `json:"last_evaluated"`
}

type PolicyInfo struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type buffer struct {
	mu   sync.Mutex
	logs []*ActivityLog
}

type PolicyActivityReporter struct {
	luc              *calc.LookupsCache
	dispatchers      map[string]types.Reporter
	flushTrigger     <-chan time.Time
	healthAggregator *health.HealthAggregator
	running          bool
	mu               sync.Mutex
	buf              *buffer
	updateQueue      chan metric.Update
	done             chan struct{}
}

const (
	HealthName     = "PolicyActivityReporter"
	HealthInterval = 10 * time.Second
)

// NewReporter creates a configured PolicyActivityReporter.
func NewReporter(luc *calc.LookupsCache, dispatchers map[string]types.Reporter, flushInterval time.Duration, healthAggregator *health.HealthAggregator) *PolicyActivityReporter {
	if len(dispatchers) == 0 {
		log.Panic("dispatchers argument cannot be empty")
	}

	flushTicker := time.NewTicker(flushInterval)

	if healthAggregator != nil {
		healthAggregator.RegisterReporter(HealthName, &health.HealthReport{Live: true, Ready: true}, HealthInterval*2)
	}

	return &PolicyActivityReporter{
		luc:              luc,
		dispatchers:      dispatchers,
		flushTrigger:     flushTicker.C,
		healthAggregator: healthAggregator,
		buf: &buffer{
			logs: make([]*ActivityLog, 0),
		},
		updateQueue: make(chan metric.Update, 1000),
		done:        make(chan struct{}),
	}
}

func (r *PolicyActivityReporter) Start() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running {
		r.running = true
		r.reportHealth()

		go r.run()
		go r.worker()
	}
	return nil
}

func (r *PolicyActivityReporter) run() {
	healthTicks := time.NewTicker(HealthInterval)
	defer healthTicks.Stop()

	for {
		select {
		case <-r.done:
			log.Info("PolicyActivityReporter exiting...")
			return
		case <-r.flushTrigger:
			r.flush()
		case <-healthTicks.C:
			r.reportHealth()
		}
	}
}

// Report receives a metric.Update, transforms it into policy ActivityLog objects.
func (r *PolicyActivityReporter) Report(u any) error {
	data, ok := u.(metric.Update)
	if !ok {
		return fmt.Errorf("unexpected type received in Report: %T", u)
	}

	select {
	case r.updateQueue <- data:
	default:
		log.Warn("PolicyActivityReporter update queue full; dropping policy activity logs")
	}
	return nil
}

func (r *PolicyActivityReporter) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		r.running = false
		close(r.updateQueue)
		close(r.done)
	}
}

func (r *PolicyActivityReporter) worker() {
	for data := range r.updateQueue {
		for _, rule := range data.RuleIDs {
			r.processRule(rule)
		}
		for _, rule := range data.PendingRuleIDs {
			r.processRule(rule)
		}
		for _, rule := range data.TransitRuleIDs {
			r.processRule(rule)
		}
		if data.UnknownRuleID != nil {
			ri := data.UnknownRuleID
			r.processRule(ri)
		}
	}
}

func (r *PolicyActivityReporter) processRule(rule *calc.RuleID) {
	kind := rule.Kind
	if kind == "" {
		// This is a profile rule, skip logging.
		return
	}

	generation := r.luc.GetGeneration(
		model.PolicyKey{
			Kind:      kind,
			Namespace: rule.Namespace,
			Name:      rule.Name,
		},
	)

	r.buf.mu.Lock()
	defer r.buf.mu.Unlock()
	r.buf.logs = append(r.buf.logs, &ActivityLog{
		Policy: PolicyInfo{
			Kind:      kind,
			Namespace: rule.Namespace,
			Name:      rule.Name,
		},
		Rule:          fmt.Sprintf("%d-%s-%s", generation, rule.DirectionString(), rule.IndexStr),
		LastEvaluated: time.Now(),
	})
}

// flush sends the buffered logs to the dispatchers and clears the buffer.
func (r *PolicyActivityReporter) flush() {
	r.buf.mu.Lock()
	logsToFlush := r.buf.logs
	r.buf.logs = make([]*ActivityLog, 0, cap(r.buf.logs))
	r.buf.mu.Unlock()

	if len(logsToFlush) == 0 {
		return
	}

	deduped := aggregate(logsToFlush)

	for name, dispatcher := range r.dispatchers {
		if err := dispatcher.Report(deduped); err != nil {
			log.Printf("Error flushing policy logs to dispatcher '%s': %v", name, err)
		}
	}
}

func (r *PolicyActivityReporter) reportHealth() {
	if r.healthAggregator == nil {
		return
	}
	r.healthAggregator.Report(HealthName, &health.HealthReport{
		Live:  true,
		Ready: r.canPublish(),
	})
}

func (r *PolicyActivityReporter) canPublish() bool {
	for _, d := range r.dispatchers {
		err := d.Start()
		if err != nil {
			log.WithError(err).Error("dispatcher unable to initialize")
			return false
		}
	}
	return true
}
