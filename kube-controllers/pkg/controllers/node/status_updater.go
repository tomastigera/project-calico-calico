// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package node

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/util/retry"

	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// NewStatusUpdateController creates a new controller responsible for cleaning the node
// specific status field in resource when corresponding node is deleted.
func NewStatusUpdateController(calicoClient client.Interface, nodeCache func() []string) *statusUpdateController {
	return &statusUpdateController{
		calicoClient:     calicoClient,
		nodeCacheFn:      nodeCache,
		reconcilerPeriod: time.Minute * 30,
		syncChan:         make(chan any),
	}
}

type statusUpdateController struct {
	calicoClient     client.Interface
	nodeCacheFn      func() []string
	reconcilerPeriod time.Duration
	syncChan         chan any
}

func (c *statusUpdateController) Start(stop chan struct{}) {
	go c.acceptScheduledRequest(stop)
}

// acceptScheduledRequest cleans the deleted node's status in custom resource periodically.
func (c *statusUpdateController) acceptScheduledRequest(stopCh <-chan struct{}) {
	cleanup := func() {
		err := c.cleanupDPINodes()
		if err != nil {
			log.Errorf("An error occurred while cleaning DPI nodes: %v", err)
		}
		err = c.retryCleanupPacketCaptureNodes()
		if err != nil {
			log.Errorf("An error occurred while cleaning DPI nodes: %v", err)
		}
	}

	// Perform cleanup once during start-up
	cleanup()

	t := time.NewTicker(c.reconcilerPeriod)
	for {
		select {
		case <-c.syncChan:
			log.Debug("Invoke cleanup on deletion event")
			cleanup()
		case <-t.C:
			log.Debug("Invoke cleanup on ticker")
			cleanup()
		case <-stopCh:
			log.Debug("Stopping controller")
			return
		}
	}
}

func (c *statusUpdateController) cleanupDPINodes() error {
	ctx := context.Background()

	cleanUp := func(res v3.DeepPacketInspection) error {
		possibleNodes := set.FromArray(c.nodeCacheFn())
		var newNodes []v3.DPINode
		for _, node := range res.Status.Nodes {
			if possibleNodes.Contains(node.Node) {
				newNodes = append(newNodes, node)
			}
		}
		if len(newNodes) == len(res.Status.Nodes) {
			return nil
		}
		res.Status.Nodes = newNodes
		_, err := c.calicoClient.DeepPacketInspections().UpdateStatus(ctx, &res, options.SetOptions{})
		return err
	}

	dpiResources, err := c.calicoClient.DeepPacketInspections().List(ctx, options.ListOptions{})
	if err != nil {
		return err
	}
	for _, res := range dpiResources.Items {
		if err = cleanUp(res); err != nil {
			if errors.IsConflict(err) {
				err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
					// On conflict get the latest version of resource and update it.
					latestRes, err := c.calicoClient.DeepPacketInspections().Get(ctx, res.Namespace, res.Name, options.GetOptions{})
					if err != nil {
						return err
					}
					return cleanUp(*latestRes)
				})
			}
			return err
		}
	}
	return nil
}

func (c *statusUpdateController) retryCleanupPacketCaptureNodes() error {
	ctx := context.Background()

	cleanup := func(res v3.PacketCapture) error {
		possibleNodes := set.FromArray(c.nodeCacheFn())
		var newFiles []v3.PacketCaptureFile
		for _, file := range res.Status.Files {
			if possibleNodes.Contains(file.Node) {
				newFiles = append(newFiles, file)
			}
		}
		if len(newFiles) == len(res.Status.Files) {
			return nil
		}
		res.Status.Files = newFiles
		_, err := c.calicoClient.PacketCaptures().Update(ctx, &res, options.SetOptions{})
		return err
	}

	pcapResources, err := c.calicoClient.PacketCaptures().List(ctx, options.ListOptions{})
	if err != nil {
		return err
	}
	for _, res := range pcapResources.Items {
		if err = cleanup(res); err != nil {
			if errors.IsConflict(err) {
				err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
					// On conflict get the latest version of resource and update it
					latestRes, err := c.calicoClient.PacketCaptures().Get(ctx, res.Namespace, res.Name, options.GetOptions{})
					if err != nil {
						return err
					}
					return cleanup(*latestRes)
				})
			}
			return err
		}
	}
	return nil
}

func (c *statusUpdateController) OnKubernetesNodeDeleted(_ *v1.Node) {
	// When a Kubernetes node is deleted, trigger a sync.
	log.Debug("Kubernetes node deletion event")
	kick(c.syncChan)
}
