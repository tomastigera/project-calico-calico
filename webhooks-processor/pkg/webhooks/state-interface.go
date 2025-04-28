// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package webhooks

import (
	"context"
	"sync"

	"github.com/cnf/structhash"
	"github.com/sirupsen/logrus"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
)

type webhookState struct {
	specHash       string
	cancelFunc     context.CancelFunc
	webhookUpdates chan *api.SecurityEventWebhook
	dependencies   webhookDependencies
}

type webhookDependencies struct {
	secrets    map[string]bool
	configMaps map[string]bool
}

type ControllerState struct {
	outUpdatesChan  chan *api.SecurityEventWebhook
	webhooksTrail   map[string]*webhookState
	preventRestarts map[string]bool
	config          *ControllerConfig
	wg              sync.WaitGroup
	cli             kubernetes.Interface
}

func (d webhookDependencies) CheckConfigMap(cmName string) bool {
	_, ok := d.configMaps[cmName]
	return ok
}

func (d webhookDependencies) CheckSecret(secretName string) bool {
	_, ok := d.secrets[secretName]
	return ok
}

func NewControllerState() *ControllerState {
	return &ControllerState{
		outUpdatesChan:  make(chan *api.SecurityEventWebhook),
		webhooksTrail:   make(map[string]*webhookState),
		preventRestarts: make(map[string]bool),
	}
}

func (s *ControllerState) WithConfig(config *ControllerConfig) *ControllerState {
	s.config = config
	return s
}

func (s *ControllerState) WithK8sClient(client kubernetes.Interface) *ControllerState {
	s.cli = client
	return s
}

func (s *ControllerState) IncomingWebhookUpdate(ctx context.Context, webhook *api.SecurityEventWebhook) {
	logEntry(webhook).Info("Processing incoming webhook update")

	if trail, ok := s.webhooksTrail[webhook.Name]; ok {
		specHash := string(structhash.Md5(webhook.Spec, 1))
		if trail.specHash == specHash {
			trail.webhookUpdates <- webhook
			return
		}
		logEntry(webhook).Info("Webhook spec changed")
		s.Stop(ctx, webhook)
	}

	if _, preventRestart := s.preventRestarts[webhook.Name]; preventRestart {
		logEntry(webhook).Info("Webhook restart prevented")
		delete(s.preventRestarts, webhook.Name)
		return
	}

	s.startNewInstance(ctx, webhook)
}

func (s *ControllerState) CheckDependencies(changedObject runtime.Object) {
	var dependencyCheck func(webhookDependencies) bool
	if configMap, ok := changedObject.(*corev1.ConfigMap); ok {
		dependencyCheck = func(deps webhookDependencies) bool {
			return deps.CheckConfigMap(configMap.Name)
		}
	} else if secret, ok := changedObject.(*corev1.Secret); ok {
		dependencyCheck = func(deps webhookDependencies) bool {
			return deps.CheckSecret(secret.Name)
		}
	} else {
		return
	}
	for webhookUid, trail := range s.webhooksTrail {
		if dependencyCheck(trail.dependencies) {
			logrus.WithField("uid", webhookUid).Info("Webhook will be restarted due to dependency change")
			trail.specHash = "restart-the-webhook-pretty-please"
		}
	}
}

func (s *ControllerState) Stop(ctx context.Context, webhook *api.SecurityEventWebhook) {
	if trail, ok := s.webhooksTrail[webhook.Name]; ok {
		trail.cancelFunc()
		delete(s.webhooksTrail, webhook.Name)
		logEntry(webhook).Info("Webhook stopped")
	}
}

func (s *ControllerState) StopAll() {
	for _, trail := range s.webhooksTrail {
		trail.cancelFunc()
	}
	logrus.Info("Waiting for all webhooks to terminate")
	s.wg.Wait()
	s.webhooksTrail = make(map[string]*webhookState)
}

func (s *ControllerState) OutgoingWebhookUpdates() <-chan *api.SecurityEventWebhook {
	return s.outUpdatesChan
}
