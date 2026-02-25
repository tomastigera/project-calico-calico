// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package webhooks

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/cnf/structhash"
	"github.com/sirupsen/logrus"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/validator/v3/query"
	lsApi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/webhooks-processor/pkg/helpers"
	"github.com/projectcalico/calico/webhooks-processor/pkg/providers"
)

const (
	ConfigVarNamespace          = "tigera-intrusion-detection"
	WebhookLabelsAnnotation     = "webhooks.projectcalico.org/labels"
	WebhookTestAnnotation       = "webhooks.projectcalico.org/testEvent"
	WebhookTestResultAnnotation = "webhooks.projectcalico.org/testResult"
	ConditionHealthy            = "Healthy"
	ConditionHealthyDesc        = "the webhook is healthy"
	ConditionLastFetch          = "EventsFetched"
)

func (s *ControllerState) startNewInstance(ctx context.Context, webhook *api.SecurityEventWebhook) {
	logEntry(webhook).Info("Webhook validation process started")

	if webhook.Spec.State == api.SecurityEventWebhookStateDisabled {
		s.preventRestarts[webhook.Name] = true
		s.updateWebhookHealth(webhook, "WebhookState", time.Now(), errors.New("the webhook has been disabled"))
		return
	}
	parsedQuery, err := query.ParseQuery(webhook.Spec.Query)
	if err != nil {
		s.preventRestarts[webhook.Name] = true
		s.updateWebhookHealth(webhook, "QueryParsing", time.Now(), err)
		return
	}
	err = query.Validate(parsedQuery, query.IsValidEventsKeysAtom)
	if err != nil {
		s.preventRestarts[webhook.Name] = true
		s.updateWebhookHealth(webhook, "QueryValidation", time.Now(), err)
		return
	}
	config, err := s.parseConfig(ctx, webhook.Spec.Config)
	if err != nil {
		s.preventRestarts[webhook.Name] = true
		s.updateWebhookHealth(webhook, "ConfigurationParsing", time.Now(), err)
		return
	}
	provider, ok := s.config.Providers[webhook.Spec.Consumer]
	if !ok {
		s.preventRestarts[webhook.Name] = true
		s.updateWebhookHealth(webhook, "ConsumerDiscovery", time.Now(), fmt.Errorf("unknown consumer: %s", webhook.Spec.Consumer))
		return
	}
	if err = provider.Validate(config); err != nil {
		s.preventRestarts[webhook.Name] = true
		s.updateWebhookHealth(webhook, "ConsumerConfigurationValidation", time.Now(), err)
		return
	}
	if webhook.Spec.State == api.SecurityEventWebhookStateTest {
		s.testFire(ctx, webhook, provider, config)
		return
	}

	processFunc := provider.Process
	if webhook.Spec.State == api.SecurityEventWebhookStateDebug {
		processFunc = s.debugProcessFunc(webhook)
	}

	webhookCtx, cancelFunc := context.WithCancel(ctx)
	webhookUpdateChan := make(chan *api.SecurityEventWebhook)
	specHash := string(structhash.Md5(webhook.Spec, 1))

	s.webhooksTrail[webhook.Name] = &webhookState{
		specHash:       specHash,
		cancelFunc:     cancelFunc,
		webhookUpdates: webhookUpdateChan,
		dependencies:   s.extractDependencies(webhook),
	}

	rateLimiter := helpers.NewRateLimiter(provider.Config().RateLimiterDuration, provider.Config().RateLimiterCount)

	s.wg.Add(1)
	go s.webhookGoroutine(webhookCtx, config, parsedQuery, processFunc, webhookUpdateChan, webhook, rateLimiter)
	s.updateWebhookHealth(webhook, "WebhookValidation", time.Now(), nil)

	logEntry(webhook).Info("Webhook validated and registered")
}

func (s *ControllerState) parseConfig(ctx context.Context, config []api.SecurityEventWebhookConfigVar) (map[string]string, error) {
	parsed := make(map[string]string)
	for _, configItem := range config {
		if configItem.ValueFrom == nil {
			parsed[configItem.Name] = configItem.Value
			continue
		}
		value, err := s.retrieveConfigValue(ctx, configItem.ValueFrom)
		if err == nil {
			parsed[configItem.Name] = value
			continue
		}
		return nil, err
	}
	return parsed, nil
}

func (s *ControllerState) updateWebhookHealth(webhook *api.SecurityEventWebhook, reason string, timestamp time.Time, err error) {
	var status metav1.ConditionStatus
	var message string

	logEntry := logrus.WithFields(logrus.Fields{
		"webhook.Name": webhook.Name,
		"reason":       reason,
		"timestamp":    timestamp,
	}).WithError(err)

	if err == nil {
		logEntry.Debug("updateWebhookHealth update")
		status, message = metav1.ConditionTrue, ConditionHealthyDesc
	} else {
		logEntry.Error("updateWebhookHealth update")
		status, message = metav1.ConditionFalse, err.Error()
	}

	webhook.Status = []metav1.Condition{
		{
			Type:               ConditionHealthy,
			Reason:             reason,
			Status:             status,
			Message:            message,
			LastTransitionTime: metav1.NewTime(timestamp),
		},
	}
	go func() {
		s.outUpdatesChan <- webhook
	}()
}

func (s *ControllerState) retrieveConfigValue(ctx context.Context, src *api.SecurityEventWebhookConfigVarSource) (string, error) {
	switch {
	case src.ConfigMapKeyRef != nil:
		cm, err := s.cli.CoreV1().ConfigMaps(ConfigVarNamespace).Get(ctx, src.ConfigMapKeyRef.Name, metav1.GetOptions{})
		if err != nil {
			return "", err
		}
		if value, present := cm.Data[src.ConfigMapKeyRef.Key]; present {
			return value, nil
		}
		return "", fmt.Errorf("key '%s' not found in the ConfigMap '%s'", src.ConfigMapKeyRef.Key, src.ConfigMapKeyRef.Name)
	case src.SecretKeyRef != nil:
		secret, err := s.cli.CoreV1().Secrets(ConfigVarNamespace).Get(ctx, src.SecretKeyRef.Name, metav1.GetOptions{})
		if err != nil {
			return "", err
		}
		if value, present := secret.Data[src.SecretKeyRef.Key]; present {
			return string(value), nil
		}
		return "", fmt.Errorf("key '%s' not found in the Secret '%s'", src.SecretKeyRef.Key, src.SecretKeyRef.Name)
	default:
		return "", errors.New("neither ConfigMap nor Secret reference present") // this should never happen
	}
}

func (s *ControllerState) extractLabels(webhook api.SecurityEventWebhook) map[string]string {
	labels := make(map[string]string)
	if annotation, ok := webhook.Annotations[WebhookLabelsAnnotation]; ok {
		for label := range strings.SplitSeq(annotation, ",") {
			if keyValue := strings.SplitN(label, ":", 2); len(keyValue) == 2 {
				labels[keyValue[0]] = keyValue[1]
			}
		}
	}
	return labels
}

func (s *ControllerState) extractDependencies(webhook *api.SecurityEventWebhook) webhookDependencies {
	secretDeps, cmDeps := make(map[string]bool), make(map[string]bool)
	for _, configVar := range webhook.Spec.Config {
		if configVar.ValueFrom == nil {
			continue
		}
		switch {
		case configVar.ValueFrom.ConfigMapKeyRef != nil:
			cmDeps[configVar.ValueFrom.ConfigMapKeyRef.Name] = true
		case configVar.ValueFrom.SecretKeyRef != nil:
			secretDeps[configVar.ValueFrom.SecretKeyRef.Name] = true
		}
	}
	return webhookDependencies{secrets: secretDeps, configMaps: cmDeps}
}

func (s *ControllerState) debugProcessFunc(webhook *api.SecurityEventWebhook) ProcessFunc {
	return func(context.Context, map[string]string, map[string]string, *lsApi.Event) (providers.ProviderResponse, error) {
		logEntry(webhook).Info("Processing Security Events for a webhook in 'Debug' state")
		return providers.ProviderResponse{
			Timestamp:             time.Now(),
			HttpStatusCode:        http.StatusOK,
			HttpStatusDescription: http.StatusText(http.StatusOK),
		}, nil
	}
}

func (s *ControllerState) testFire(ctx context.Context, webhook *api.SecurityEventWebhook, provider providers.Provider, config map[string]string) {
	logEntry(webhook).Info("Test fire in progress...")
	testEvent := s.selectTestEvent(webhook)
	testEvent.Time = lsApi.NewEventDate(time.Now())
	webhook.Spec.State = api.SecurityEventWebhookStateEnabled
	testResult, err := provider.Process(ctx, config, s.extractLabels(*webhook), testEvent)
	if webhook.Annotations == nil {
		webhook.Annotations = make(map[string]string)
	}
	webhook.Annotations[WebhookTestResultAnnotation] = testResult.String()
	s.updateWebhookHealth(webhook, "TestFireProcedure", time.Now(), err)
	logEntry(webhook).Info("Webhook has been re-enabled")
}

func (s *ControllerState) selectTestEvent(webhook *api.SecurityEventWebhook) *lsApi.Event {
	if testPayloadIndex, annotated := webhook.Annotations[WebhookTestAnnotation]; !annotated {
		return s.selectRandomTestEvent()
	} else if payload, validPayloadAnnotation := webhookTestPayloads[testPayloadIndex]; !validPayloadAnnotation {
		return s.selectRandomTestEvent()
	} else {
		return &payload
	}
}

func (s *ControllerState) selectRandomTestEvent() (payload *lsApi.Event) {
	randomIndex := rand.Intn(len(webhookTestPayloads))
	for _, testPayload := range webhookTestPayloads {
		if randomIndex == 0 {
			payload = &testPayload
			break
		}
		randomIndex--
	}
	return
}
