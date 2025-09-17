package reporting

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	calicoclient "github.com/tigera/api/pkg/client/clientset_generated/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

// UpdateGlobalAlertStatusWithRetryOnConflict
func UpdateGlobalAlertStatusWithRetryOnConflict(globalAlert *v3.GlobalAlert, clusterName string, calicoCLI calicoclient.Interface, ctx context.Context) error {

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error { return updateGlobalAlertStatus(globalAlert, clusterName, calicoCLI, ctx) }); err != nil {
		log.WithError(err).Errorf("failed to update status GlobalAlert %s in cluster %s, maximum retries reached", globalAlert.Name, clusterName)
		return err
	}

	return nil
}

// UpdateGlobalAlertStatus gets the latest GlobalAlert and updates its status.
func updateGlobalAlertStatus(globalAlert *v3.GlobalAlert, clusterName string, calicoCLI calicoclient.Interface, ctx context.Context) error {
	log.Debugf("Updating status of GlobalAlert %s in cluster %s", globalAlert.Name, clusterName)
	retrievedAlert, err := calicoCLI.ProjectcalicoV3().GlobalAlerts().Get(ctx, globalAlert.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	retrievedAlert.Status = globalAlert.Status
	_, err = calicoCLI.ProjectcalicoV3().GlobalAlerts().UpdateStatus(ctx, retrievedAlert, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

// GetGlobalAlertErrorStatus creates a
func GetGlobalAlertErrorStatus(err error) v3.GlobalAlertStatus {
	return v3.GlobalAlertStatus{
		Healthy:         false,
		Active:          false,
		ErrorConditions: []v3.ErrorCondition{{Message: err.Error()}},
		LastUpdate:      &metav1.Time{Time: time.Now()},
	}
}

func GetGlobalAlertSuccessStatus() v3.GlobalAlertStatus {
	metav1TimeNow := &metav1.Time{Time: time.Now()}

	return v3.GlobalAlertStatus{
		Healthy:         true,
		Active:          true,
		ErrorConditions: nil,
		LastUpdate:      metav1TimeNow,
		LastEvent:       metav1TimeNow,
	}
}
