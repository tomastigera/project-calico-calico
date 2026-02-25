// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package authorization

import (
	log "github.com/sirupsen/logrus"
)

const (
	resourceUpdated = "updated"
	resourceDeleted = "deleted"
)

type resourceUpdate struct {
	typ      string
	name     string
	resource any
}

type k8sUpdateHandler struct {
	stopChan        chan chan struct{}
	resourceUpdates chan resourceUpdate
	synchronizer    k8sRBACSynchronizer
}

// listenAndSynchronize watches for updates over the resourceUpdates channel, attempts to update the ClusterRoleCache or OIDCUserCache
// with the updates (either "updated" / "deleted" ClusterRole / ClusterRoleBinding / ConfigMap) and if the cache was updated
// it calls k8sRBACSynchronizer to either update the role mapping or native users.
func (r *k8sUpdateHandler) listenAndSynchronize() {
	for {
		select {
		case notify, ok := <-r.stopChan:
			if !ok {
				return
			}

			close(notify)
			return
		case update, ok := <-r.resourceUpdates:
			if !ok {
				return
			}
			if err := r.synchronizer.synchronize(update); err != nil {
				//TODO we might want to try requeueing the failed updates
				log.WithError(err).Errorf("failed to listenAndSynchronize %#v", update)
			}
		}
	}
}

// stop sends a signal to the stopChan which stops the loop running in listenAndSynchronize. This function blocks until
// it receives confirm.
func (r *k8sUpdateHandler) stop() {
	done := make(chan struct{})
	r.stopChan <- done
	<-done
	close(r.stopChan)
}
