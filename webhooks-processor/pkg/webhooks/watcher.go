// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package webhooks

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	calicoWatch "github.com/projectcalico/calico/libcalico-go/lib/watch"
)

const (
	WebhooksWatcherTimeout        = 1 * time.Minute
	InformerResyncTime            = 1 * time.Minute
	RetryOnErrorDelay             = 1 * time.Second
	MaxRetryTimesBeforeBailingOut = 5
)

type WebhookWatcherUpdater struct {
	client             kubernetes.Interface
	whClient           clientv3.SecurityEventWebhookInterface
	controller         WebhookControllerInterface
	webhookUpdatesChan chan *api.SecurityEventWebhook
	webhookInventory   map[string]*api.SecurityEventWebhook
}

func NewWebhookWatcherUpdater() (watcher *WebhookWatcherUpdater) {
	watcher = new(WebhookWatcherUpdater)
	watcher.webhookUpdatesChan = make(chan *api.SecurityEventWebhook)
	watcher.webhookInventory = make(map[string]*api.SecurityEventWebhook)
	return
}

func (w *WebhookWatcherUpdater) WithWebhooksClient(client clientv3.SecurityEventWebhookInterface) *WebhookWatcherUpdater {
	w.whClient = client
	return w
}

func (w *WebhookWatcherUpdater) WithK8sClient(client kubernetes.Interface) *WebhookWatcherUpdater {
	w.client = client
	return w
}

func (w *WebhookWatcherUpdater) WithController(controller WebhookControllerInterface) *WebhookWatcherUpdater {
	w.controller = controller
	return w
}

func (w *WebhookWatcherUpdater) UpdatesChan() chan<- *api.SecurityEventWebhook {
	return w.webhookUpdatesChan
}

func (w *WebhookWatcherUpdater) Run(ctx context.Context, wg *sync.WaitGroup) {
	logrus.Info("Webhook updater/watcher started")
	defer wg.Done()
	defer logrus.Info("Webhook updater/watcher is terminating")

	if err := w.startInformers(ctx); err != nil {
		logrus.WithError(err).Error("unable to start informers")
	}

	webhooksWaitGroup := new(sync.WaitGroup)
	go w.executeWhileContextIsAlive(ctx, webhooksWaitGroup, w.watchWebhooks)
	go w.executeWhileContextIsAlive(ctx, webhooksWaitGroup, w.updateWebhooks)
	webhooksWaitGroup.Wait()
}

func (w *WebhookWatcherUpdater) executeWhileContextIsAlive(ctx context.Context, wg *sync.WaitGroup, f func(context.Context) error) {
	wg.Add(1)
	defer wg.Done()
	for errorCounter := 0; ctx.Err() == nil; {
		if err := f(ctx); err == nil {
			errorCounter = 0
		} else if errorCounter++; errorCounter >= MaxRetryTimesBeforeBailingOut {
			logrus.WithError(err).Fatal("terminating due to recurring errors")
		} else {
			<-time.After(RetryOnErrorDelay * time.Duration(errorCounter))
		}
	}
}

func (w *WebhookWatcherUpdater) startInformers(ctx context.Context) error {
	informerFactory := informers.NewSharedInformerFactoryWithOptions(
		w.client, InformerResyncTime, informers.WithNamespace(ConfigVarNamespace),
	)

	configMapInfomer := informerFactory.Core().V1().ConfigMaps().Informer()
	eventHandlerConfigMapFunctions := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if cm, ok := obj.(v1.ConfigMap); ok {
				w.controller.K8sEventsChan() <- watch.Event{Type: watch.Added, Object: &cm}
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			if cm, ok := newObj.(v1.ConfigMap); ok {
				w.controller.K8sEventsChan() <- watch.Event{Type: watch.Modified, Object: &cm}
			}
		},
		DeleteFunc: func(obj any) {
			if cm, ok := obj.(v1.ConfigMap); ok {
				w.controller.K8sEventsChan() <- watch.Event{Type: watch.Deleted, Object: &cm}
			}
		},
	}

	_, err := configMapInfomer.AddEventHandler(eventHandlerConfigMapFunctions)

	if err != nil {
		return err
	}

	secretInformer := informerFactory.Core().V1().Secrets().Informer()
	eventHandlerSecretFunctions := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if secret, ok := obj.(v1.Secret); ok {
				w.controller.K8sEventsChan() <- watch.Event{Type: watch.Added, Object: &secret}
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			if secret, ok := newObj.(v1.Secret); ok {
				w.controller.K8sEventsChan() <- watch.Event{Type: watch.Modified, Object: &secret}
			}
		},
		DeleteFunc: func(obj any) {
			if secret, ok := obj.(v1.Secret); ok {
				w.controller.K8sEventsChan() <- watch.Event{Type: watch.Deleted, Object: &secret}
			}
		},
	}

	_, err = secretInformer.AddEventHandler(eventHandlerSecretFunctions)

	if err != nil {
		return err
	}

	informerFactory.Start(ctx.Done())
	informerFactory.WaitForCacheSync(ctx.Done())
	return nil
}

func (w *WebhookWatcherUpdater) updateWebhooks(ctx context.Context) error {
	for {
		select {
		case webhook := <-w.webhookUpdatesChan:
			if _, err := w.whClient.Update(ctx, webhook, options.SetOptions{}); err != nil {
				logrus.WithError(err).Error("unable to update webhook definition")
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (w *WebhookWatcherUpdater) watchWebhooks(ctx context.Context) error {
	var watchRevision string
	if webhooks, err := w.whClient.List(ctx, options.ListOptions{}); err != nil {
		logrus.WithError(err).Error("unable to list webhooks")
		return err
	} else {
		watchRevision = webhooks.ResourceVersion
		localInventory := make(map[string]*api.SecurityEventWebhook)
		for _, webhook := range webhooks.Items {
			w.controller.WebhookEventsChan() <- calicoWatch.Event{Type: calicoWatch.Added, Previous: nil, Object: &webhook}
			delete(w.webhookInventory, webhook.Name)
			localInventory[webhook.Name] = &webhook
		}
		// swap the watcher/updater inventory with the local one:
		w.webhookInventory, localInventory = localInventory, w.webhookInventory
		// and make sure no delete operations were lost in the process,
		// whatever is left in the old inventory must now be gone:
		for _, webhook := range localInventory {
			w.controller.WebhookEventsChan() <- calicoWatch.Event{Type: calicoWatch.Deleted, Previous: webhook, Object: nil}
		}
	}

	watcherCtx, watcherCtxCancel := context.WithTimeout(ctx, WebhooksWatcherTimeout)
	defer watcherCtxCancel()

	watcher, err := w.whClient.Watch(watcherCtx, options.ListOptions{ResourceVersion: watchRevision})

	if err != nil {
		logrus.WithError(err).Error("unable to watch for webhook changes")
		return err
	}

	for event := range watcher.ResultChan() {
		switch event.Type {
		case calicoWatch.Deleted:
			if webhook, ok := event.Previous.(*api.SecurityEventWebhook); ok {
				delete(w.webhookInventory, webhook.Name)
			}
		default:
			if webhook, ok := event.Object.(*api.SecurityEventWebhook); ok {
				w.webhookInventory[webhook.Name] = webhook
			}
		}
		w.controller.WebhookEventsChan() <- event
	}
	return nil
}
