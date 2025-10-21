// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package fv

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/linseed/pkg/backend/api"
	backendutils "github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/config"
	"github.com/projectcalico/calico/oiler/pkg/migrator"
)

func TestRunOiler(t *testing.T) {
	specs := []TestSpec{
		{
			name:            "external-to-external",
			primaryTenant:   backendutils.RandomTenantName(),
			secondaryTenant: backendutils.RandomTenantName(),
			clusters:        []string{backendutils.RandomClusterName(), backendutils.RandomClusterName()},
			backend:         config.BackendTypeMultiIndex,
		},
		{
			name:            "internal-to-external",
			primaryTenant:   "",
			secondaryTenant: backendutils.RandomTenantName(),
			clusters:        []string{backendutils.RandomClusterName(), backendutils.RandomClusterName()},
			backend:         config.BackendTypeMultiIndex,
		},
	}

	Run(t, "Migrate historical data", specs, func(t *testing.T, spec TestSpec) {
		catalogue := migrator.MustGetCatalogue(esConfig, spec.backend, "DEBUG", "utility")

		var primaries []api.ClusterInfo
		var secondaries []api.ClusterInfo
		for _, cluster := range spec.clusters {
			primaries = append(primaries, api.ClusterInfo{
				Cluster: cluster,
				Tenant:  spec.primaryTenant,
			})
			secondaries = append(secondaries, api.ClusterInfo{
				Cluster: cluster,
				Tenant:  spec.secondaryTenant,
			})
		}

		numLogs := 100
		for idx := range spec.clusters {
			generateData(t, catalogue, numLogs, spec.dataType, primaries[idx])
			err := backendutils.RefreshIndex(ctx, esClient, spec.idx.Index(primaries[idx]))
			require.NoError(t, err)
		}
		defer cleanUpData(t, spec.idx, append(primaries, secondaries...)...)

		jobName := backendutils.RandStringRunes(4)
		oiler := RunOiler(t, OilerArgs{
			Clusters:         spec.clusters,
			PrimaryTenantID:  spec.primaryTenant,
			PrimaryBackend:   spec.backend,
			SecondTenantID:   spec.secondaryTenant,
			SecondaryBackend: spec.backend,
			DataType:         spec.dataType,
			JobName:          jobName,
			MetricsPort:      spec.metricsPort,
		})

		defer func() {
			oiler.StopLogs()
			oiler.Stop()
			cleanUpCheckPoints(spec.dataType, primaries...)
		}()

		require.True(t, oiler.ListedInDockerPS())

		for idx := range spec.clusters {
			err := backendutils.RefreshIndex(ctx, esClient, spec.idx.Index(secondaries[idx]))
			require.NoError(t, err)
			validateMigratedData(t, primaries[idx], secondaries[idx], catalogue, spec.dataType, 30*time.Second, 1*time.Second)

			last := lastGeneratedTimeFromPrimary(t, catalogue, spec.dataType, primaries[idx])
			validateMetrics(t, jobName, primaries[idx], secondaries[idx], int64(numLogs), last.UnixMilli(), spec.metricsPort)
			validateCheckpoints(t, spec.dataType, primaries[idx], last)
		}
	})

	Run(t, "Migrate new data", specs, func(t *testing.T, spec TestSpec) {
		catalogue := migrator.MustGetCatalogue(esConfig, config.BackendTypeMultiIndex, "DEBUG", "utility")

		var primaries []api.ClusterInfo
		var secondaries []api.ClusterInfo
		for _, cluster := range spec.clusters {
			primaries = append(primaries, api.ClusterInfo{
				Cluster: cluster,
				Tenant:  spec.primaryTenant,
			})
			secondaries = append(secondaries, api.ClusterInfo{
				Cluster: cluster,
				Tenant:  spec.secondaryTenant,
			})
		}

		jobName := backendutils.RandStringRunes(4)
		oiler := RunOiler(t, OilerArgs{
			Clusters:         spec.clusters,
			PrimaryTenantID:  spec.primaryTenant,
			PrimaryBackend:   spec.backend,
			SecondTenantID:   spec.secondaryTenant,
			SecondaryBackend: spec.backend,
			DataType:         spec.dataType,
			JobName:          jobName,
			MetricsPort:      spec.metricsPort,
		})

		defer func() {
			oiler.StopLogs()
			oiler.Stop()
			cleanUpCheckPoints(spec.dataType, primaries...)
		}()

		require.True(t, oiler.ListedInDockerPS())

		numLogs := 100
		for idx := range spec.clusters {
			generateData(t, catalogue, numLogs, spec.dataType, primaries[idx])
			err := backendutils.RefreshIndex(ctx, esClient, spec.idx.Index(primaries[idx]))
			require.NoError(t, err)
		}
		defer cleanUpData(t, spec.idx, append(primaries, secondaries...)...)

		for idx := range spec.clusters {
			err := backendutils.RefreshIndex(ctx, esClient, spec.idx.Index(secondaries[idx]))
			require.NoError(t, err)
			validateMigratedData(t, primaries[idx], secondaries[idx], catalogue, spec.dataType, 90*time.Second, 1*time.Second)

			last := lastGeneratedTimeFromPrimary(t, catalogue, spec.dataType, primaries[idx])
			validateMetrics(t, jobName, primaries[idx], secondaries[idx], int64(numLogs), last.UnixMilli(), spec.metricsPort)
			validateCheckpoints(t, spec.dataType, primaries[idx], last)
		}
	})
}
