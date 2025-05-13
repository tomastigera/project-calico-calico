// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package nonclusterhost

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/sirupsen/logrus"
	calicoclient "github.com/tigera/api/pkg/client/clientset_generated/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	for _, hep := range hepList.Items {
		// Update the labels to include the new host endpoint type
		hep.Labels[names.HostEndpointTypeLabelKey] = string(names.HostEndpointTypeNonClusterHost)
		// Simulate the kubelet behavior of adding the node labels to the host endpoint
		// https://kubernetes.io/docs/reference/node/node-labels/
		hep.Labels["kubernetes.io/arch"] = runtime.GOARCH
		hep.Labels["kubernetes.io/hostname"] = hostname
		hep.Labels["kubernetes.io/os"] = runtime.GOOS

		_, err := lu.calicoClientSet.ProjectcalicoV3().HostEndpoints().Update(lu.ctx, &hep, metav1.UpdateOptions{})
		if err != nil {
			logrus.WithError(err).WithField("hep", hep.Name).Warn("Failed to update non-cluster host labels")
		}
	}
	return nil
}
