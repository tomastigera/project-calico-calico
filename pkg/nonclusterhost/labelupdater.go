// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package nonclusterhost

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/sirupsen/logrus"
	calicoclient "github.com/tigera/api/pkg/client/clientset_generated/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

type LabelUpdater struct {
	ctx             context.Context
	calicoClientSet calicoclient.Interface
}

func NewLabelUpdater(ctx context.Context) (*LabelUpdater, error) {
	kubeConfigPath := os.Getenv("KUBECONFIG")
	kubeConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		return nil, err
	}
	cs, err := calicoclient.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}

	return &LabelUpdater{
		ctx:             ctx,
		calicoClientSet: cs,
	}, nil
}

// UpdateLabels adds standardized labels to all HostEndpoints on this node.
//
// Applies the NonClusterHost endpoint type classification and standard
// Kubernetes node metadata labels (arch, os, hostname) to enable consistent
// endpoint selection in policies and reporting.
//
// Returns nil on success or if no updates were needed.
// Returns error if hostname can't be determined, endpoints can't be listed.
func (lu *LabelUpdater) UpdateLabels() error {
	hostname, err := names.Hostname()
	if err != nil {
		return err
	}

	hepList, err := lu.calicoClientSet.ProjectcalicoV3().HostEndpoints().List(lu.ctx, metav1.ListOptions{FieldSelector: fmt.Sprintf("spec.node=%s", hostname)})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	// Configure exponential backoff with jitter for HostEndpoint label update retries.
	// This helps prevent excessive load on systemd or the Kubernetes API server during outages.
	// The configured backoff parameters result in a total retry duration of approximately one minute.
	backoff := wait.Backoff{
		Duration: 2 * time.Second,
		Factor:   2.0,
		Jitter:   0.1,
		Steps:    6,
	}

	for _, hep := range hepList.Items {
		if hep.Labels == nil {
			hep.Labels = make(map[string]string)
		}

		// Update the labels to include the new host endpoint type
		hep.Labels[names.HostEndpointTypeLabelKey] = string(names.HostEndpointTypeNonClusterHost)
		// Simulate the kubelet behavior of adding the node labels to the host endpoint
		// https://kubernetes.io/docs/reference/node/node-labels/
		hep.Labels["kubernetes.io/arch"] = runtime.GOARCH
		hep.Labels["kubernetes.io/hostname"] = hostname
		hep.Labels["kubernetes.io/os"] = runtime.GOOS

		if err := wait.ExponentialBackoff(backoff, func() (bool, error) {
			if _, err := lu.calicoClientSet.ProjectcalicoV3().HostEndpoints().Update(lu.ctx, &hep, metav1.UpdateOptions{}); err != nil {
				logrus.WithError(err).WithField("hep", hep.Name).Warn("failed to update HostEndpoint labels; will retry...")
				return false, nil
			}
			return true, nil
		}); err != nil {
			return fmt.Errorf("failed to update HostEndpoint labels for %s: %w", hep.Name, err)
		}
	}
	return nil
}
