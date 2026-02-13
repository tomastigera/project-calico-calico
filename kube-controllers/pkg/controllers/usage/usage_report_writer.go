package usage

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	usagev1 "github.com/tigera/api/pkg/apis/usage.tigera.io/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	crtlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/licensing/client"
)

const apiServerOperationAttempts = 3

var (
	hmacKey               = []byte("e94818465e656dc3082610a08c300cdf30f3d3a2c2fb8505f83406befe7bce83ba028b6862ebc8aaa473063fc03a7b4ccb5a9a34426a85b563457d68befdde96")
	rfc1123Base32Encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
)

// newReportWriter observes the basicLicenseUsageReport objects sent on the reports channel, and enriches them with context from the cluster
// to create LicenseUsageReport objects. These objects are then written to the datastore, with retries if appropriate.
func newReportWriter(
	reports chan basicLicenseUsageReport,
	stopIssued chan struct{},
	ctx context.Context,
	k8sClient kubernetes.Interface,
	calicoClient clientv3.Interface,
	usageClient crtlclient.Client,
	retentionPeriod time.Duration,
) reportWriter {
	return reportWriter{
		reports:         reports,
		stopIssued:      stopIssued,
		ctx:             ctx,
		k8sClient:       k8sClient,
		calicoClient:    calicoClient,
		usageClient:     usageClient,
		retentionPeriod: retentionPeriod,
	}
}

func (w *reportWriter) startWriting() {
	log.Info("Starting Report Writer")
	w.startedReportingAt = time.Now()

	for {
		select {
		case report := <-w.reports:
			datastoreReport, err := w.convertToDatastoreReport(report)
			if err != nil {
				log.WithError(err).Error("Failed to convert basic usage report to datastore report. No datastore report will be written")
			} else {
				err = w.writeDatastoreReport(datastoreReport)
				if err != nil {
					log.WithError(err).Error("Failed to write usage report to datastore")
				}
			}

			err = w.removeOldDatastoreReports()
			if err != nil {
				log.WithError(err).Error("Failed to clean up old usage reports in datastore")
			}

		case <-w.stopIssued:
			log.Info("Stopping Report Writer")
			return
		}
	}
}

// convertToDatastoreReport converts a basicLicenseUsageReport into a LicenseUsageReport object by enriching it with additional context.
// Some fields of LicenseUsageReport require fetches from the datastore and/or certain conditions to be met. If either of these
// fail, the field will simply be omitted.
func (w *reportWriter) convertToDatastoreReport(report basicLicenseUsageReport) (*usagev1.LicenseUsageReport, error) {
	// Establish the base report data that requires no fetching of data.
	reportData := &LicenseUsageReportData{
		VCPUs: Stats{
			Min: report.minCounts.vCPU,
			Max: report.maxCounts.vCPU,
		},
		Nodes: Stats{
			Min: report.minCounts.nodes,
			Max: report.maxCounts.nodes,
		},
		IntervalStart:  report.intervalStart,
		IntervalEnd:    report.intervalEnd,
		CompleteReport: report.complete,
		ReporterUptime: int(time.Since(w.startedReportingAt).Seconds()),
	}

	// Fetch the subject UID.
	kubeSystemNamespace, err := w.k8sClient.CoreV1().Namespaces().Get(w.ctx, "kube-system", v1.GetOptions{})
	if err != nil {
		log.WithError(err).Error("Failed to fetch subject UID for usage report. Omitting field from report.")
	} else {
		reportData.SubjectUID = string(kubeSystemNamespace.UID)
	}

	// Fetch the license UID.
	licenseClaims, err := w.getLicenseClaims()
	if err != nil {
		log.WithError(err).Error("Failed to fetch license UID for usage report. Omitting field from report.")
	} else {
		reportData.LicenseUID = licenseClaims.LicenseID
	}

	// Resolve the last published report UID.
	if w.lastPublishedReportUID == nil {
		log.Debug("No previous published report UID in memory. Omitting field from report.")
	} else {
		reportData.LastPublishedReportUID = *w.lastPublishedReportUID
	}

	// Serialize the report into our message.
	message, err := reportData.ToMessage()
	if err != nil {
		return nil, err
	}

	return &usagev1.LicenseUsageReport{
		ObjectMeta: v1.ObjectMeta{Name: generateReportName(report)},
		Spec: usagev1.LicenseUsageReportSpec{
			ReportData: message,
			HMAC:       ComputeHMAC(message),
		},
	}, nil
}

// writeDatastoreReport writes a LicenseUsageReport object to the datastore. If the request fails and the failure is retryable
// with a delay, then the request is retried a fixed amount of times. An error will be returned if the datastore commit
// failed.
func (w *reportWriter) writeDatastoreReport(datastoreReport *usagev1.LicenseUsageReport) error {
	err := w.performAPIServerOperationWithRetries("create", func() error {
		return w.usageClient.Create(w.ctx, datastoreReport)
	})
	if err != nil {
		return err
	}

	reportUID := string(datastoreReport.UID)
	w.lastPublishedReportUID = &reportUID
	return nil
}

func (w *reportWriter) performAPIServerOperationWithRetries(opName string, op func() error) error {
	for attempt := 0; attempt < apiServerOperationAttempts; attempt++ {
		err := op()
		if err != nil {
			log.WithError(err).Debugf("Inner attempt %d (of %d) to %s usage report to datastore failed", attempt, apiServerOperationAttempts, opName)

			delay, retryable := errors.SuggestsClientDelay(err)
			if !retryable {
				return err
			}

			if attempt == apiServerOperationAttempts-1 {
				return err
			}

			time.Sleep(time.Duration(delay) * time.Second)
			continue
		}
		break
	}

	log.Debugf("Usage report %s to datastore succeeded", opName)
	return nil
}

func (w *reportWriter) removeOldDatastoreReports() error {
	// List all reports. The usage client is cached, so this read should not put load on the API server.
	var datastoreReports usagev1.LicenseUsageReportList
	err := w.usageClient.List(w.ctx, &datastoreReports)
	if err != nil {
		return err
	}

	// Delete all reports before the retention cutoff.
	retentionCutoff := time.Now().Add(-w.retentionPeriod)
	for _, datastoreReport := range datastoreReports.Items {
		if datastoreReport.CreationTimestamp.Time.Before(retentionCutoff) {
			err := w.performAPIServerOperationWithRetries("delete", func() error {
				return w.usageClient.Delete(w.ctx, &datastoreReport)
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *reportWriter) getLicenseClaims() (client.LicenseClaims, error) {
	licenseKey, err := w.calicoClient.LicenseKey().Get(w.ctx, "default", options.GetOptions{})
	if err != nil {
		return client.LicenseClaims{}, err
	}
	licenseClaims, err := client.Decode(*licenseKey)
	if err != nil {
		return client.LicenseClaims{}, err
	}
	return licenseClaims, nil
}

type reportWriter struct {
	reports                chan basicLicenseUsageReport
	stopIssued             chan struct{}
	ctx                    context.Context
	k8sClient              kubernetes.Interface
	calicoClient           clientv3.Interface
	usageClient            crtlclient.Client
	lastPublishedReportUID *string
	startedReportingAt     time.Time
	retentionPeriod        time.Duration
}

func ComputeHMAC(message string) string {
	hash := hmac.New(sha256.New, hmacKey)
	hash.Write([]byte(message))
	return fmt.Sprintf("%x", hash.Sum(nil))
}

// generateReportName generates a RFC1123 name based on the report interval end. The function will attempt to add randomness
// to the name to prevent naming collisions when multiple report intervals end at the same hour.
func generateReportName(report basicLicenseUsageReport) string {
	// Generate base name using date.
	baseName := report.intervalEnd.Format("2006-01-02-15h")

	// Add randomness to the name in case of collisions.
	randomBytes := make([]byte, 6)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return baseName
	} else {
		return baseName + "-" + rfc1123Base32Encoding.EncodeToString(randomBytes)
	}
}
