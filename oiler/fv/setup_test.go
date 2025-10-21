// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package fv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/linseed/pkg/backend"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	linseedconfig "github.com/projectcalico/calico/linseed/pkg/config"
	"github.com/projectcalico/calico/lma/pkg/elastic"
	"github.com/projectcalico/calico/oiler/pkg/checkpoint"
	"github.com/projectcalico/calico/oiler/pkg/config"
)

var (
	ctx       context.Context
	esConfig  linseedconfig.ElasticClientConfig
	esClient  elastic.Client
	k8sClient *kubernetes.Clientset
	cwd       string
	certsPath string
)

type TestSpec struct {
	name            string
	clusters        []string
	primaryTenant   string
	secondaryTenant string
	backend         linseedconfig.BackendType
	idx             bapi.Index
	dataType        bapi.DataType
	metricsPort     int
}

var (
	MultiIndexMappings = map[bapi.DataType]bapi.Index{
		bapi.AuditEELogs:    index.AuditLogEEMultiIndex,
		bapi.AuditKubeLogs:  index.AuditLogKubeMultiIndex,
		bapi.BGPLogs:        index.BGPLogMultiIndex,
		bapi.DNSLogs:        index.DNSLogMultiIndex,
		bapi.Benchmarks:     index.ComplianceBenchmarkMultiIndex,
		bapi.ReportData:     index.ComplianceReportMultiIndex,
		bapi.Snapshots:      index.ComplianceSnapshotMultiIndex,
		bapi.Events:         index.EventsMultiIndex,
		bapi.FlowLogs:       index.FlowLogMultiIndex,
		bapi.L7Logs:         index.L7LogMultiIndex,
		bapi.WAFLogs:        index.WAFLogMultiIndex,
		bapi.RuntimeReports: index.RuntimeReportMultiIndex,
		bapi.IPSet:          index.ThreatfeedsIPSetMultiIndex,
		bapi.DomainNameSet:  index.ThreatfeedsIPSetMultiIndex,
	}
)

func Run(t *testing.T, name string, specs []TestSpec, testFn func(t *testing.T, spec TestSpec)) {
	metricPort := 8080
	for _, spec := range specs {
		if spec.backend == linseedconfig.BackendTypeMultiIndex {
			for k, v := range MultiIndexMappings {
				spec.idx = v
				spec.dataType = k
				spec.metricsPort = metricPort
				metricPort++
				t.Run(fmt.Sprintf("%s [%s] %s", name, spec.name, spec.dataType), func(t *testing.T) {
					defer setupAndTeardown(t)()
					testFn(t, spec)
				})
			}
		}
	}
}

type OilerArgs struct {
	PrimaryTenantID string
	PrimaryBackend  linseedconfig.BackendType

	SecondTenantID   string
	SecondaryBackend linseedconfig.BackendType

	DataType    bapi.DataType
	JobName     string
	Clusters    []string
	MetricsPort int
}

func RunOiler(t *testing.T, args OilerArgs) *containers.Container {
	// The container library uses gomega, so we need to connect our testing.T to it.
	gomega.RegisterTestingT(t)

	dockerArgs := []string{
		"--net=host",
		"-v", fmt.Sprintf("%s/oiler-token:/var/run/secrets/kubernetes.io/serviceaccount/token", cwd),
		"-v", fmt.Sprintf("%s/ca.pem:/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", certsPath),
		"-e", "OILER_PRIMARY_ELASTIC_HOST=localhost",
		"-e", "OILER_SECONDARY_ELASTIC_HOST=localhost",
		"-e", "OILER_PRIMARY_ELASTIC_SCHEME=http",
		"-e", "OILER_SECONDARY_ELASTIC_SCHEME=http",
		"-e", fmt.Sprintf("OILER_CLUSTERS=%s", strings.Join(args.Clusters, ",")),
		"-e", fmt.Sprintf("OILER_PRIMARY_TENANT_ID=%s", args.PrimaryTenantID),
		"-e", fmt.Sprintf("OILER_SECONDARY_TENANT_ID=%s", args.SecondTenantID),
		"-e", fmt.Sprintf("OILER_PRIMARY_BACKEND=%s", args.PrimaryBackend),
		"-e", fmt.Sprintf("OILER_SECONDARY_BACKEND=%s", args.SecondaryBackend),
		"-e", fmt.Sprintf("OILER_DATA_TYPE=%s", args.DataType),
		"-e", fmt.Sprintf("OILER_MODE=%s", "migrate"),
		"-e", fmt.Sprintf("OILER_JOB_NAME=%s", args.JobName),
		"-e", fmt.Sprintf("OILER_WAIT_FOR_NEW_DATA=%s", "1s"),
		"-e", "KUBERNETES_SERVICE_HOST=127.0.0.1",
		"-e", "KUBERNETES_SERVICE_PORT=6443",
		"-e", "OILER_LOG_LEVEL=INFO",
		"-e", fmt.Sprintf("OILER_METRICS_PORT=%d", args.MetricsPort),
		"-e", "OILER_NAMESPACE=default",
		"tigera/oiler:latest",
	}

	name := "tigera-oiler-fv"

	c := containers.Run(name, containers.RunOpts{RunAndExit: false, AutoRemove: true, OutputWriter: logutils.TestingTWriter{T: t}}, dockerArgs...)
	return c
}

// setupAndTeardown provides common setup and teardown logic for all FV tests to use.
func setupAndTeardown(t *testing.T) func() {
	// Hook logrus into testing.T
	config.ConfigureLogging("DEBUG")
	logCancel := logutils.RedirectLogrusToTestingT(t)

	// Set up context with a timeout.
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), 15*time.Minute)

	// Get the current working directory, which we expect to by the fv dir.
	var err error
	cwd, err = os.Getwd()
	require.NoError(t, err)
	logrus.Infof("cwd: %s", cwd)

	// Turn it to an absolute path.
	cwd, err = filepath.Abs(cwd)
	require.NoError(t, err)
	logrus.Infof("cwd: %s", cwd)

	// The certs path is relative to the fv dir.
	certsPath = filepath.Join(cwd, "../../hack/test/certs/")

	esConfig = linseedconfig.ElasticClientConfig{
		ElasticScheme:        "http",
		ElasticHost:          "localhost",
		ElasticPort:          "9200",
		ElasticShards:        1,
		ElasticFlowShards:    1,
		ElasticAuditShards:   1,
		ElasticBGPShards:     1,
		ElasticDNSShards:     1,
		ElasticL7Shards:      1,
		ElasticWAFShards:     1,
		ElasticRuntimeShards: 1,
	}
	esClient = backend.MustGetElasticClient(esConfig, "INFO", "utility")

	k8sClient, err = checkpoint.NewRealK8sClient(filepath.Join(cwd, "kube", "kubeconfig"))
	require.NoError(t, err)

	return func() {
		logCancel()
		cancel()
	}
}
