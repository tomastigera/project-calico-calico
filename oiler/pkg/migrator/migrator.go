// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package migrator

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/oiler/pkg/config"
	"github.com/projectcalico/calico/oiler/pkg/metrics"
	"github.com/projectcalico/calico/oiler/pkg/migrator/operator"
)

const (
	Primary   = "primary"
	Secondary = "secondary"
)

// Config is the configuration of a migrator that
// tracks its actions via Prometheus metrics
type Config struct {
	primaryLabels   prometheus.Labels
	secondaryLabels prometheus.Labels
	jobLabels       prometheus.Labels
	pageSize        int
	sleepTime       time.Duration
	timeOut         time.Duration
	name            string
	cluster         string
}

func NewConfig(cluster string, cfg config.Config) *Config {
	return &Config{
		primaryLabels:   primaryLabels(cluster, cfg),
		secondaryLabels: secondaryLabels(cluster, cfg),
		jobLabels:       jobLabels(cluster, cfg),
		pageSize:        cfg.ElasticPageSize,
		sleepTime:       cfg.WaitForNewData,
		timeOut:         cfg.ElasticTimeOut,
		name:            cfg.JobName,
		cluster:         cluster,
	}
}

func secondaryLabels(cluster string, cfg config.Config) prometheus.Labels {
	return prometheus.Labels{
		metrics.LabelTenantID:  cfg.SecondaryTenantID,
		metrics.LabelClusterID: cluster,
		metrics.JobName:        cfg.JobName,
		metrics.Source:         Secondary,
	}
}

func primaryLabels(cluster string, cfg config.Config) prometheus.Labels {
	return prometheus.Labels{
		metrics.LabelTenantID:  cfg.PrimaryTenantID,
		metrics.LabelClusterID: cluster,
		metrics.JobName:        cfg.JobName,
		metrics.Source:         Primary,
	}
}

func jobLabels(cluster string, cfg config.Config) prometheus.Labels {
	return prometheus.Labels{
		metrics.LabelClusterID: cluster,
		metrics.JobName:        cfg.JobName,
	}
}

// Migrator will migrate data continuously by reading a time interval
// from primary and writing it to a secondary location, regardless of
// the type of the data
type Migrator[T any] struct {
	Primary   operator.Operator[T]
	Secondary operator.Operator[T]
	Cfg       *Config
}

func (m Migrator[T]) Run(ctx context.Context, current operator.TimeInterval, checkpoints chan operator.TimeInterval) {
	log := logrus.WithFields(logrus.Fields{"cluster": m.Cfg.cluster})

	for {
		select {
		case <-ctx.Done():
			log.Info("Context canceled. Will stop migration")
			return
		default:
			// Reading data from primary location
			list, next, err := m.Retry(ctx, m.ReadFromPrimary, current, m.Cfg.pageSize, log, 3)
			if err != nil {
				log.WithError(err).Fatalf("Failed to read data for interval %#v", current)
			}

			// Writing data to secondary location
			err = m.Write(ctx, list.Items, log)
			if err != nil {
				log.WithError(err).Fatal("Failed to write data")
			}

			// Tracking migration metrics
			m.trackMigrationMetrics(current, log)

			// Store periodical checkpoints in case of failure
			select {
			case checkpoints <- current:
				log.Infof("Store last known time interval as a checkpoint: %v", current)
			default:
				log.Info("Skipping storing checkpoint because channel is full")
			}

			// Advance to next interval
			if next != nil {
				current = *next
			}

			// Waiting for new data to be generated
			if next.HasReachedEnd() {
				log.Infof("Will sleep as we need to wait for more data to be generated")
				metrics.WaitForData.With(m.Cfg.jobLabels).Set(1)
				time.Sleep(m.Cfg.sleepTime)
			}
		}
	}
}

func (m Migrator[T]) trackMigrationMetrics(current operator.TimeInterval, log *logrus.Entry) {
	lag := current.Lag(time.Now().UTC())
	lastGeneratedTime := current.LastGeneratedTime()
	metrics.MigrationLag.With(m.Cfg.jobLabels).Set(lag.Round(time.Second).Seconds())
	metrics.LastReadGeneratedTimestamp.With(m.Cfg.jobLabels).Set(float64(lastGeneratedTime.UnixMilli()))
	log.Infof("Migration is behind current time with %s with %s from current %v", lag, lastGeneratedTime, current)
}

func (m Migrator[T]) Write(ctx context.Context, items []T, log *logrus.Entry) error {
	timeOutContext, cancel := context.WithTimeout(ctx, m.Cfg.timeOut)
	defer cancel()

	if len(items) == 0 {
		log.Infof("Will skip write to as there are no items to write")
		return nil
	}

	log.Infof("Writing %d items", len(items))
	startWrite := time.Now().UTC()
	response, err := m.Secondary.Write(timeOutContext, items)
	if err != nil {
		return err
	}

	endWrite := time.Since(startWrite).Seconds()
	metrics.WriteDurationPerClusterIDAndTenantID.With(m.Cfg.secondaryLabels).Observe(endWrite)
	metrics.DocsWrittenPerClusterIDAndTenantID.With(m.Cfg.secondaryLabels).Add(float64(response.Succeeded))
	metrics.FailedDocsWrittenPerClusterIDAndTenantID.With(m.Cfg.secondaryLabels).Add(float64(response.Failed))
	metrics.LastWrittenGeneratedTimestamp.With(m.Cfg.jobLabels).Set(float64(time.Now().UTC().UnixMilli()))

	log.Infof("Finished writing. total=%d, success=%d, failed=%d in %v seconds", response.Total, response.Succeeded, response.Failed, endWrite)

	return nil
}

type RetryFunc[T any] func(ctx context.Context, current operator.TimeInterval, pageSize int, log *logrus.Entry) (*v1.List[T], *operator.TimeInterval, error)

func (m Migrator[T]) Retry(ctx context.Context, f RetryFunc[T], current operator.TimeInterval, pageSize int, log *logrus.Entry, retryAttempts int) (*v1.List[T], *operator.TimeInterval, error) {
	var err error
	var list *v1.List[T]
	var next *operator.TimeInterval
	for i := range retryAttempts {
		select {
		case <-ctx.Done():
			return list, next, ctx.Err()
		default:
		}
		list, next, err = f(ctx, current, pageSize, log)
		if err == nil {
			return list, next, nil
		}
		log.Infof("Retry attempt #%d failed", i)
		time.Sleep(500 * time.Millisecond)
	}
	return list, next, err
}

func (m Migrator[T]) ReadFromPrimary(ctx context.Context, current operator.TimeInterval, pageSize int, log *logrus.Entry) (*v1.List[T], *operator.TimeInterval, error) {
	timeOutContext, cancel := context.WithTimeout(ctx, m.Cfg.timeOut)
	defer cancel()

	startRead := time.Now().UTC()
	log.Infof("Reading data for current=%v for primary", current)
	list, next, err := m.Primary.Read(timeOutContext, current, pageSize)

	if err != nil {
		return nil, nil, err
	}

	endReadTime := time.Since(startRead).Seconds()
	log.Infof("Read %d items in %v seconds for primary", len(list.Items), endReadTime)
	metrics.ReadDurationPerClusterIDAndTenantID.With(m.Cfg.primaryLabels).Observe(endReadTime)
	metrics.DocsReadPerClusterIDAndTenantID.With(m.Cfg.primaryLabels).Add(float64(len(list.Items)))

	return list, next, err
}

func (m Migrator[T]) ReadFromSecondary(ctx context.Context, current operator.TimeInterval, pageSize int, log *logrus.Entry) (*v1.List[T], *operator.TimeInterval, error) {
	timeOutContext, cancel := context.WithTimeout(ctx, m.Cfg.timeOut)
	defer cancel()

	startRead := time.Now().UTC()
	log.Infof("Reading data for current=%v for secondary", current)
	list, next, err := m.Secondary.Read(timeOutContext, current, pageSize)

	if err != nil {
		return nil, nil, err
	}

	endReadTime := time.Since(startRead).Seconds()
	log.Infof("Read %d items in %v seconds for secondary", len(list.Items), endReadTime)
	metrics.ReadDurationPerClusterIDAndTenantID.With(m.Cfg.secondaryLabels).Observe(endReadTime)
	metrics.DocsReadPerClusterIDAndTenantID.With(m.Cfg.secondaryLabels).Add(float64(len(list.Items)))

	return list, next, err
}

func (m Migrator[T]) Validate(ctx context.Context, start time.Time, end time.Time, interval int) {
	log := logrus.WithFields(logrus.Fields{"cluster": m.Cfg.cluster})

	select {
	case <-ctx.Done():
		log.Info("Context canceled. Will stop validation")
		return
	default:
		log.Infof("[VALIDATE] Interval start=%s end=%s", start.Format(time.RFC3339), end.Format(time.RFC3339))

		primaryIDs := m.readIDs(ctx, start, end, log, Primary)
		secondaryIDs := m.readIDs(ctx, start, end, log, Secondary)

		missingFromSecondary := m.compare(primaryIDs, secondaryIDs)
		metrics.MissingDocs.With(m.secondaryValidationLabels(interval)).Add(float64(len(missingFromSecondary)))
		log.Infof("[VALIDATE] Number of documents missing from secondary: %d", len(missingFromSecondary))
		if len(missingFromSecondary) != 0 {
			log.Infof("[VALIDATE] Documents missing from secondary: %v", missingFromSecondary)
		}

		missingFromPrimary := m.compare(secondaryIDs, primaryIDs)
		metrics.MissingDocs.With(m.primaryValidationLabels(interval)).Add(float64(len(missingFromPrimary)))
		log.Infof("[VALIDATE] Number of documents missing from primary: %d", len(missingFromPrimary))
		if len(missingFromPrimary) != 0 {
			log.Infof("[VALIDATE] Documents missing from primary: %v", missingFromPrimary)
		}
	}

}

func (m Migrator[T]) compare(one map[string]struct{}, another map[string]struct{}) []string {
	var missing []string
	for id := range one {
		if _, ok := another[id]; !ok {
			missing = append(missing, id)
		}
	}
	return missing
}

func (m Migrator[T]) readIDs(ctx context.Context, start time.Time, end time.Time, log *logrus.Entry, source string) map[string]struct{} {
	var ids = make(map[string]struct{})

	interval := operator.TimeInterval{Start: &start, End: &end}
	log.Infof("Reading from %s", source)
	for {
		list, err := m.read(ctx, interval, log, source)
		if err != nil {
			log.WithError(err).Fatalf("Failed to read data for interval for %s %#v", source, interval)
			continue
		}

		m.transform(list, ids, source)

		if len(list.GetAfterKey()) == 0 {
			break
		}

		interval.Cursor = list.GetAfterKey()
	}

	return ids
}

func (m Migrator[T]) transform(list *v1.List[T], ids map[string]struct{}, source string) {
	switch source {
	case Primary:
		for _, id := range m.Primary.Transform(list.Items) {
			ids[id] = struct{}{}
		}
	case Secondary:
		for _, id := range m.Secondary.Transform(list.Items) {
			ids[id] = struct{}{}
		}
	default:
	}
}

func (m Migrator[T]) read(ctx context.Context, interval operator.TimeInterval, log *logrus.Entry, source string) (*v1.List[T], error) {
	switch strings.ToLower(source) {
	case Primary:
		list, _, err := m.ReadFromPrimary(ctx, interval, m.Cfg.pageSize, log)
		return list, err
	case Secondary:
		list, _, err := m.ReadFromSecondary(ctx, interval, m.Cfg.pageSize, log)
		return list, err
	default:
		return nil, errors.Errorf("Unknown source %s", source)

	}
}

func (m Migrator[T]) primaryValidationLabels(Interval int) prometheus.Labels {
	return prometheus.Labels{
		metrics.LabelClusterID: m.Cfg.cluster,
		metrics.JobName:        m.Cfg.name,
		metrics.Source:         Primary,
		metrics.IntervalBehind: strconv.Itoa(Interval),
	}
}

func (m Migrator[T]) secondaryValidationLabels(interval int) prometheus.Labels {
	return prometheus.Labels{
		metrics.LabelClusterID: m.Cfg.cluster,
		metrics.JobName:        m.Cfg.name,
		metrics.Source:         Secondary,

		metrics.IntervalBehind: strconv.Itoa(interval),
	}
}
