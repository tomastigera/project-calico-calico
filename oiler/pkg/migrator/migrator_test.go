// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package migrator_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/oiler/pkg/config"
	"github.com/projectcalico/calico/oiler/pkg/migrator"
	"github.com/projectcalico/calico/oiler/pkg/migrator/operator"
	"github.com/projectcalico/calico/oiler/pkg/migrator/operator/fake"
)

var ctx context.Context

func setupAndTeardown(t *testing.T) func() {
	// Hook logrus into testing.T
	config.ConfigureLogging("DEBUG")
	logCancel := logutils.RedirectLogrusToTestingT(t)

	// Set up context with a timeout.
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)

	return func() {
		logCancel()
		cancel()
	}
}

func TestMigrator_Run(t *testing.T) {

	t.Run("Migrate historical data", func(t *testing.T) {
		defer setupAndTeardown(t)()

		fakePrimary := fake.Operator{}
		fakePrimary.AddReadCommand(
			fake.ReadCommand{Data: &v1.List[fake.AnyLog]{Items: []fake.AnyLog{{}}},
				Next: &operator.TimeInterval{
					Cursor: map[string]any{"searchFrom": []any{"1", "2"}},
					Start:  nil,
				},
			},
			fake.ReadCommand{Data: &v1.List[fake.AnyLog]{Items: []fake.AnyLog{{}}},
				Next: &operator.TimeInterval{
					Cursor: map[string]any{"searchFrom": []any{"3", "4"}},
					Start:  nil,
				},
			},
			fake.ReadCommand{Data: &v1.List[fake.AnyLog]{Items: []fake.AnyLog{{}}},
				Next: &operator.TimeInterval{
					Cursor: nil,
					Start:  ptrTime(time.Unix(1, 0).UTC()),
				},
			},
		)

		fakeSecondary := fake.Operator{}
		anyLogMigrator := migrator.Migrator[fake.AnyLog]{
			Primary: &fakePrimary,
			Cfg: migrator.NewConfig("cluster", config.Config{
				PrimaryTenantID:   "primary",
				SecondaryTenantID: "secondary",
				JobName:           "jobName",
				WaitForNewData:    5 * time.Millisecond,
				ElasticTimeOut:    5 * time.Minute,
			}),
			Secondary: &fakeSecondary,
		}

		stopMigration, cancel := context.WithCancel(ctx)
		backups := make(chan operator.TimeInterval, 5)
		go func() {
			defer close(backups)
			defer cancel()

			var received []operator.TimeInterval
			for range 4 {
				received = append(received, <-backups)
			}
			require.Equal(t, received, []operator.TimeInterval{
				{},
				{Cursor: map[string]any{"searchFrom": []any{"1", "2"}}},
				{Cursor: map[string]any{"searchFrom": []any{"3", "4"}}},
				{Start: ptrTime(time.Unix(1, 0).UTC())},
			})
		}()
		anyLogMigrator.Run(stopMigration, operator.TimeInterval{}, backups)
	})

	t.Run("Wait for new data to be written", func(t *testing.T) {
		defer setupAndTeardown(t)()

		fakePrimary := fake.Operator{}
		fakePrimary.AddReadCommand(
			fake.ReadCommand{Data: &v1.List[fake.AnyLog]{},
				Next: &operator.TimeInterval{
					Cursor: nil,
					Start:  ptrTime(time.Unix(1, 0).UTC()),
				},
			},
			fake.ReadCommand{Data: &v1.List[fake.AnyLog]{},
				Next: &operator.TimeInterval{
					Cursor: nil,
					Start:  ptrTime(time.Unix(1, 0).UTC()),
				},
			},
			fake.ReadCommand{Data: &v1.List[fake.AnyLog]{Items: []fake.AnyLog{{}}},
				Next: &operator.TimeInterval{
					Cursor: nil,
					Start:  ptrTime(time.Unix(2, 0).UTC()),
				},
			},
		)

		fakeSecondary := fake.Operator{}
		anyLogMigrator := migrator.Migrator[fake.AnyLog]{
			Primary: &fakePrimary,
			Cfg: migrator.NewConfig("cluster", config.Config{
				PrimaryTenantID:   "primary",
				SecondaryTenantID: "secondary",
				JobName:           "jobName",
				WaitForNewData:    5 * time.Millisecond,
				ElasticTimeOut:    5 * time.Minute,
			}),
			Secondary: &fakeSecondary,
		}

		stopMigration, cancel := context.WithCancel(ctx)
		backups := make(chan operator.TimeInterval, 5)
		go func() {
			defer close(backups)
			defer cancel()

			var received []operator.TimeInterval
			for range 4 {
				received = append(received, <-backups)
			}
			require.Equal(t, received, []operator.TimeInterval{
				{},
				{Start: ptrTime(time.Unix(1, 0).UTC())},
				{Start: ptrTime(time.Unix(1, 0).UTC())},
				{Start: ptrTime(time.Unix(2, 0).UTC())},
			})
		}()
		anyLogMigrator.Run(stopMigration, operator.TimeInterval{}, backups)
	})
}

func ptrTime(time time.Time) *time.Time {
	return &time
}
