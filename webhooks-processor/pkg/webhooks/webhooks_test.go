// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package webhooks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8swatch "k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/validator/v3/query"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
	lsApi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/webhooks-processor/pkg/providers"
	"github.com/projectcalico/calico/webhooks-processor/pkg/providers/generic"
	"github.com/projectcalico/calico/webhooks-processor/pkg/providers/slack"
	"github.com/projectcalico/calico/webhooks-processor/pkg/testutils"
)

// This file contains tests that combine the webhooks building blocks as a cohesive unit
// and assert that all work together as expected to implement the desired behavior.

func TestWebhooksProcessorExitsOnCancel(t *testing.T) {
	testState := Setup(t, func(context.Context, *query.Query, time.Time, time.Time) ([]lsApi.Event, error) {
		return []lsApi.Event{}, nil
	})

	// Just making sure everything can run without crashing
	require.True(t, testState.Running)

	// And that we can stop it on demand
	testState.Stop()
	require.Eventually(t, func() bool { return !testState.Running }, 3*time.Second, 10*time.Millisecond)

	// Flag that we already stopped it and don't need to clean it up further during test teardown..
	testState.Stop = nil
}

func TestWebhookHealthy(t *testing.T) {
	testState := Setup(t, func(context.Context, *query.Query, time.Time, time.Time) ([]lsApi.Event, error) {
		return []lsApi.Event{}, nil
	})

	startTime := time.Now()

	// New webhook has no status
	wh := testutils.NewTestWebhook("test-wh")
	require.Nil(t, wh.Status)

	_, err := testState.WebHooksAPI.Update(context.Background(), wh, options.SetOptions{})
	require.NoError(t, err)

	// Check that webhook status is eventually updated to healthy
	require.Eventually(t, isHealthy(wh), time.Second, 10*time.Millisecond)
	require.True(t, wh.Status[0].LastTransitionTime.After(startTime))
}

func TestWebhookDependencyModifications(t *testing.T) {
	// note: this is not really a unit test per-se as it verifies the behaviour of a webhook when k8s dependencies change.
	// it should be an e2e test and lives here due to the character of already exising tests in this repository.
	t.Run("webhook dependency modification test", func(t *testing.T) {

		// create a new test state - we need to be able to reference K8s APIs as well as the webhooks controller
		testState := Setup(t, func(context.Context, *query.Query, time.Time, time.Time) ([]lsApi.Event, error) {
			return []lsApi.Event{}, nil
		})

		// create the new "test-secret" that will be referenced by the webhook
		testSecret, err := testState.K8sClient.CoreV1().Secrets("tigera-intrusion-detection").Create(
			context.TODO(),
			&v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "tigera-intrusion-detection",
				},
				Data: map[string][]byte{
					"secret-url": []byte("https://example.net/not-important-in-this-context"),
				},
			},
			metav1.CreateOptions{},
		)
		require.NoError(t, err)

		// create the "test-webhook" webhook referencing the "test-secret" create above
		webhook := testutils.NewTestWebhook("test-webhook")
		webhook.Spec.Config = []api.SecurityEventWebhookConfigVar{
			{
				Name: "url",
				ValueFrom: &api.SecurityEventWebhookConfigVarSource{
					SecretKeyRef: &v1.SecretKeySelector{
						LocalObjectReference: v1.LocalObjectReference{
							Name: "test-secret",
						},
						Key: "secret-url",
					},
				},
			},
		}

		timeMarker := time.Now()

		testState.WebHooksAPI.Watcher.Results <- watch.Event{Type: watch.Added, Object: webhook}

		// the webhook should eventually be in a healthy state
		require.EventuallyWithT(
			t, func(t *assert.CollectT) {
				assert.NotNil(t, webhook.Status)
				assert.Len(t, webhook.Status, 1)
				assert.Equal(t, "Healthy", webhook.Status[0].Type)
				assert.Equal(t, metav1.ConditionStatus("True"), webhook.Status[0].Status)
				assert.Equal(t, "the webhook is healthy", webhook.Status[0].Message)
				assert.True(t, webhook.Status[0].LastTransitionTime.After(timeMarker))
			}, time.Second, 100*time.Millisecond,
		)

		timeMarker = webhook.Status[0].LastTransitionTime.Time

		// update the referenced secret by removing all data in it:
		testSecret.Data = map[string][]byte{}
		testSecret, err = testState.K8sClient.CoreV1().Secrets("tigera-intrusion-detection").Update(
			context.TODO(), testSecret, metav1.UpdateOptions{},
		)
		require.NoError(t, err)

		// fake k8s clientset used in the unit test does not propagate watches (this is by design) so we have to take care of it ourselves
		testState.WebhooksCtrl.K8sEventsChan() <- k8swatch.Event{Type: k8swatch.Modified, Object: testSecret}

		// the webhook should eventually be in a non-healthy state as the secret does not contain referenced data
		require.EventuallyWithT(
			t, func(t *assert.CollectT) {
				assert.NotNil(t, webhook.Status)
				assert.Len(t, webhook.Status, 1)
				assert.Equal(t, "Healthy", webhook.Status[0].Type)
				assert.Equal(t, metav1.ConditionStatus("False"), webhook.Status[0].Status)
				assert.Equal(t, "key 'secret-url' not found in the Secret 'test-secret'", webhook.Status[0].Message)
				assert.True(t, webhook.Status[0].LastTransitionTime.After(timeMarker))
			}, 30*time.Second, 1*time.Second,
		)
	})
}

func TestWebhookNonHealthyStates(t *testing.T) {
	testNonHealthyState := func(webhook *api.SecurityEventWebhook, reason string, message string) {
		testState := Setup(t, func(context.Context, *query.Query, time.Time, time.Time) ([]lsApi.Event, error) {
			return []lsApi.Event{}, nil
		})

		startTime := time.Now()

		// New webhook has no status
		require.Nil(t, webhook.Status)

		testState.WebHooksAPI.Watcher.Results <- watch.Event{Type: watch.Added, Object: webhook}

		// Check that webhook status is eventually updated to non-healthy
		require.Eventually(t, func() bool {
			return webhook != nil &&
				webhook.Status != nil &&
				len(webhook.Status) == 1 &&
				webhook.Status[0].Type == "Healthy" &&
				webhook.Status[0].Status == metav1.ConditionStatus("False")
		}, time.Second, 10*time.Millisecond)
		require.True(t, webhook.Status[0].LastTransitionTime.After(startTime))

		// Check details
		require.Contains(t, webhook.Status[0].Reason, reason)
		require.Contains(t, webhook.Status[0].Message, message)
	}

	t.Run("disabled", func(t *testing.T) {
		wh := testutils.NewTestWebhook("test-wh")
		wh.Spec.State = "Disabled"
		testNonHealthyState(wh, "WebhookState", "the webhook has been disabled")
	})

	t.Run("malformed query", func(t *testing.T) {
		wh := testutils.NewTestWebhook("test-wh")
		wh.Spec.Query = "= runtime_security"
		testNonHealthyState(wh, "QueryParsing", "unexpected token")
	})

	t.Run("invalid query", func(t *testing.T) {
		wh := testutils.NewTestWebhook("test-wh")
		wh.Spec.Query = "type = runtime_securit"
		testNonHealthyState(wh, "QueryValidation", "invalid value for type: runtime_securit")
	})

	t.Run("config parsing - referenced value not found", func(t *testing.T) {
		wh := testutils.NewTestWebhook("test-wh")
		wh.Spec.Config = append(wh.Spec.Config, api.SecurityEventWebhookConfigVar{
			Name: "some-secret",
			ValueFrom: &api.SecurityEventWebhookConfigVarSource{
				SecretKeyRef: &v1.SecretKeySelector{
					LocalObjectReference: v1.LocalObjectReference{
						Name: "non-existing-secret",
					},
					Key: "non-existing-key",
				},
			},
		})
		testNonHealthyState(wh, "ConfigurationParsing", "secrets \"non-existing-secret\" not found")
	})

	t.Run("config parsing - no cm or secret referenced - k8s validation shouldn't allow for this to ever happen", func(t *testing.T) {
		wh := testutils.NewTestWebhook("test-wh")
		wh.Spec.Config = append(wh.Spec.Config, api.SecurityEventWebhookConfigVar{
			Name:      "some-secret",
			ValueFrom: &api.SecurityEventWebhookConfigVarSource{},
		})
		testNonHealthyState(wh, "ConfigurationParsing", "neither ConfigMap nor Secret reference present")
	})

	t.Run("unknown consumer", func(t *testing.T) {
		wh := testutils.NewTestWebhook("test-wh")
		wh.Spec.Consumer = "Unknown"
		testNonHealthyState(wh, "ConsumerDiscovery", "unknown consumer: Unknown")
	})

	t.Run("invalid provider config", func(t *testing.T) {
		wh := testutils.NewTestWebhook("test-wh")
		wh.Spec.Config = []api.SecurityEventWebhookConfigVar{}
		testNonHealthyState(wh, "ConsumerConfigurationValidation", "url field is not present in webhook configuration")
	})
}

func TestWebhookSent(t *testing.T) {
	testEvent := lsApi.Event{
		ID:          "testid",
		Description: "This is an event",
		Severity:    42,
		Time:        lsApi.NewEventTimestamp(time.Now().Unix()),
		Type:        "runtime_security",
	}
	testState := Setup(t, func(context.Context, *query.Query, time.Time, time.Time) ([]lsApi.Event, error) {
		return []lsApi.Event{testEvent}, nil
	})

	wh := testutils.NewTestWebhook("test-wh")
	_, err := testState.WebHooksAPI.Update(context.Background(), wh, options.SetOptions{})
	require.NoError(t, err)

	// Make sure the webhook eventually hits the test provider
	require.Eventually(t, hasOneRequest(testState.TestSlackProvider()), testState.FetchingInterval*4, 10*time.Millisecond)
	require.Equal(t, wh.Spec.Config[0].Name, "url")
	require.Equal(t, wh.Spec.Config[0].Value, testState.TestSlackProvider().Requests[0].Config["url"])
	require.Equal(t, testEvent, testState.TestSlackProvider().Requests[0].Event)

	// Make sure labels annotation is correctly processed
	require.Eventually(t,
		func() bool {
			return assert.Equal(t,
				map[string]string{
					"hips dont lie": "true",
					"anything":      "goes",
					"also-this":     "",
				},
				testState.TestSlackProvider().Requests[0].Labels,
			)
		}, testState.FetchingInterval*4, 10*time.Millisecond,
	)
}

func TestWebhookTestEventSent(t *testing.T) {
	testState := Setup(t, func(context.Context, *query.Query, time.Time, time.Time) ([]lsApi.Event, error) {
		return []lsApi.Event{}, nil
	})

	wh := testutils.NewTestWebhook("test-wh")
	wh.Spec.State = api.SecurityEventWebhookStateTest
	wh.Annotations["webhooks.projectcalico.org/testEvent"] = "runtime_security"
	_, err := testState.WebHooksAPI.Update(context.Background(), wh, options.SetOptions{})
	require.NoError(t, err)

	// Make sure the webhook eventually hits the test provider
	require.Eventually(t, hasOneRequest(testState.TestSlackProvider()), time.Second, 100*time.Millisecond)
	require.Equal(t, wh.Spec.Config[0].Name, "url")
	require.Equal(t, wh.Spec.Config[0].Value, testState.TestSlackProvider().Requests[0].Config["url"])

	// Make sure that the test event is of the correct type
	require.Equal(t, "runtime_security", testState.TestSlackProvider().Requests[0].Event.Type)

	// Make sure labels annotation is correctly processed
	require.Eventually(t,
		func() bool {
			return assert.Equal(t,
				map[string]string{
					"hips dont lie": "true",
					"anything":      "goes",
					"also-this":     "",
				},
				testState.TestSlackProvider().Requests[0].Labels,
			)
		}, time.Second, 100*time.Millisecond,
	)

	// Make sure the webhook's state has been changed to 'Enabled'
	require.Eventually(t,
		func() bool {
			return wh.Spec.State == api.SecurityEventWebhookStateEnabled
		}, time.Second, 100*time.Millisecond,
	)
}

func TestSendsOneWebhookPerEvent(t *testing.T) {
	// Making sure that if we test multiple events at once
	// we still get the expected number of webhooks triggered.
	testEvent1 := lsApi.Event{
		ID:          "testid1",
		Description: "This is an event",
		Severity:    41,
		Time:        lsApi.NewEventTimestamp(time.Now().Unix()),
		Type:        "runtime_security",
	}
	testEvent2 := lsApi.Event{
		ID:          "testid2",
		Description: "This is an event",
		Severity:    42,
		Time:        lsApi.NewEventTimestamp(time.Now().Unix()),
		Type:        "runtime_security",
	}
	testState := Setup(t, func(context.Context, *query.Query, time.Time, time.Time) ([]lsApi.Event, error) {
		return []lsApi.Event{testEvent1, testEvent2}, nil
	})

	wh := testutils.NewTestWebhook("test-wh")
	_, err := testState.WebHooksAPI.Update(context.Background(), wh, options.SetOptions{})
	require.NoError(t, err)

	// Make sure the webhook eventually hits the test provider
	testProvider := testState.TestSlackProvider()
	require.Eventually(t, hasNRequest(testProvider, 2), 15*time.Second, 10*time.Millisecond)

	eventsFromLinseed := []lsApi.Event{testEvent1, testEvent2}
	eventsSentToProvider := []lsApi.Event{testProvider.Requests[0].Event, testProvider.Requests[1].Event}
	require.ElementsMatch(t, eventsFromLinseed, eventsSentToProvider)
}

func TestEventsFetchedUsingNonOverlappingIntervals(t *testing.T) {
	// Making sure that a webhook goroutine does not fetch/process
	// the same event twice by looking at the queried timestamps
	// and make sure they don't overlap.
	testStartTime := time.Now()
	requestedTimes := [][]time.Time{}
	testState := Setup(t, func(ctx context.Context, query *query.Query, from time.Time, to time.Time) ([]lsApi.Event, error) {
		logrus.Infof("Reading events (from: %s, to: %s)", from, to)
		requestedTimes = append(requestedTimes, []time.Time{from, to})
		return []lsApi.Event{}, nil
	})

	wh := testutils.NewTestWebhook("test-wh")
	_, err := testState.WebHooksAPI.Update(context.Background(), wh, options.SetOptions{})
	require.NoError(t, err)

	// Wait that we get a few fetch requests
	require.Eventually(t, func() bool {
		return len(requestedTimes) == 3
	}, 35*time.Second, 10*time.Millisecond)

	testEndTime := time.Now()
	require.Less(t, testStartTime, testEndTime)

	// No time overlap within queries
	require.Less(t, requestedTimes[0][0], requestedTimes[0][1])
	require.Less(t, requestedTimes[1][0], requestedTimes[1][1])
	require.Less(t, requestedTimes[2][0], requestedTimes[2][1])

	// Next time range picks up exactly where the previous one stopped
	require.Equal(t, requestedTimes[0][1], requestedTimes[1][0])
	require.Equal(t, requestedTimes[1][1], requestedTimes[2][0])
}

func TestTooManyEventsAreRateLimited(t *testing.T) {
	// Testing what happens when we get a burst of events that's larger than the rate limiter allows...
	// In this case we simply ignore the additional events. That doesn't feel right...
	fetchedEvents := []lsApi.Event{newEvent(1), newEvent(2), newEvent(3), newEvent(4), newEvent(5), newEvent(6)}
	testState := Setup(t, func(context.Context, *query.Query, time.Time, time.Time) ([]lsApi.Event, error) {
		return fetchedEvents, nil
	})

	// TODO: Add a check to test that the rate limiter is set to less than len(fetchedEvents)
	// Right now it's hardcoded to 5 in the test setup (but that could and likely will change)
	wh := testutils.NewTestWebhook("test-wh")
	_, err := testState.WebHooksAPI.Update(context.Background(), wh, options.SetOptions{})
	require.NoError(t, err)

	// Make sure the webhook eventually hits the test server
	testProvider := testState.TestSlackProvider()
	// Make sure the test is valid (we're providing more events than allowed)
	numEventsAllowed := int(testState.Providers[api.SecurityEventWebhookConsumerSlack].Config().RateLimiterCount)
	require.Less(t, numEventsAllowed, len(fetchedEvents))
	require.Eventually(t, hasNRequest(testProvider, numEventsAllowed), 15*time.Second, 10*time.Millisecond)

	// Even if we wait, we're not getting the missing event, it's gone forever.
	// Is this good enough?
	time.Sleep(testState.FetchingInterval * 2)
	require.Eventually(t, hasNRequest(testProvider, numEventsAllowed), 15*time.Second, 10*time.Millisecond)
}

func TestGenericProvider(t *testing.T) {
	requests := []testutils.HttpRequest{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "Does anyone read this?")
		request := testutils.HttpRequest{
			Method: r.Method,
			URL:    r.URL.String(),
			Header: r.Header,
		}
		var err error
		request.Body, err = io.ReadAll(r.Body)
		require.NoError(t, err)
		requests = append(requests, request)
	}))
	defer ts.Close()

	fetchedEvents := []lsApi.Event{newEvent(1)}
	testState := NewTestState(func(context.Context, *query.Query, time.Time, time.Time) ([]lsApi.Event, error) {
		return fetchedEvents, nil
	}, DefaultProviders())

	SetupWithTestState(t, testState)

	whUrl := fmt.Sprintf("%s/test-hook", ts.URL)
	wh := testutils.NewTestWebhook("test-generic-webhook")
	// Set the Webhook consumer to Generic
	wh.Spec.Consumer = api.SecurityEventWebhookConsumerGeneric
	// Making sure we'll update the right config...
	require.Equal(t, wh.Spec.Config[0].Name, "url")
	// Updating URL to point to the test server
	wh.Spec.Config[0].Value = whUrl
	// Adding arbitrary headers:
	wh.Spec.Config = append(wh.Spec.Config, api.SecurityEventWebhookConfigVar{
		Name: "headers",
		Value: `
Origin:unit-test:the-generic-webhook
Warning:this is a deprecated header so be wary
this line will be ignored
		`,
	})
	_, err := testState.WebHooksAPI.Update(context.Background(), wh, options.SetOptions{})
	require.NoError(t, err)

	// Make sure the webhook eventually hits the test provider
	require.Eventually(t, func() bool { return len(requests) == 1 }, 5*time.Second, 10*time.Millisecond)

	// We got the webhook as expected
	require.Equal(t, "POST", requests[0].Method)
	require.Equal(t, "/test-hook", requests[0].URL)
	require.Contains(t, requests[0].Header, "Content-Type")
	require.Equal(t, requests[0].Header["Content-Type"], []string{"application/json"})
	require.Contains(t, requests[0].Header, "Origin")
	require.Equal(t, requests[0].Header["Origin"], []string{"unit-test:the-generic-webhook"})
	require.Contains(t, requests[0].Header, "Warning")
	require.Equal(t, requests[0].Header["Warning"], []string{"this is a deprecated header so be wary"})

	// And check that we get a JSON of the original event
	var whEvent lsApi.Event
	err = json.Unmarshal(requests[0].Body, &whEvent)
	require.NoError(t, err)
	require.Equal(t, fetchedEvents[0], whEvent)
}

func TestGenericProviderWithTemplate(t *testing.T) {
	requests := []testutils.HttpRequest{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "Does anyone read this?")
		request := testutils.HttpRequest{
			Method: r.Method,
			URL:    r.URL.String(),
			Header: r.Header,
		}
		var err error
		request.Body, err = io.ReadAll(r.Body)
		require.NoError(t, err)
		requests = append(requests, request)
	}))
	defer ts.Close()

	fetchedEvents := []lsApi.Event{newEvent(1)}
	testState := NewTestState(func(context.Context, *query.Query, time.Time, time.Time) ([]lsApi.Event, error) {
		return fetchedEvents, nil
	}, DefaultProviders())

	SetupWithTestState(t, testState)

	whUrl := fmt.Sprintf("%s/test-hook", ts.URL)
	wh := testutils.NewTestWebhook("test-generic-webhook")
	// Set the Webhook consumer to Generic
	wh.Spec.Consumer = api.SecurityEventWebhookConsumerGeneric
	// Making sure we'll update the right config...
	require.Equal(t, wh.Spec.Config[0].Name, "url")
	// Updating URL to point to the test server
	wh.Spec.Config[0].Value = whUrl
	// Adding arbitrary headers:
	wh.Spec.Config = append(wh.Spec.Config, api.SecurityEventWebhookConfigVar{
		Name: "template",
		Value: `{
	"message": "We got a security event from Tigera",
	"event": "{{.description}}",
	"event_type": "{{.type}}",
	"missing_data": "{{.this_field_does_not_exists}}"
}`,
	})
	_, err := testState.WebHooksAPI.Update(context.Background(), wh, options.SetOptions{})
	require.NoError(t, err)

	// Make sure the webhook eventually hits the test provider
	require.Eventually(t, func() bool { return len(requests) == 1 }, 5*time.Second, 10*time.Millisecond)

	// We got the webhook as expected
	require.Equal(t, "POST", requests[0].Method)
	require.Equal(t, "/test-hook", requests[0].URL)

	// And check that we get a templated JSON with the values from the original event
	var whJson map[string]string
	err = json.Unmarshal(requests[0].Body, &whJson)
	require.NoError(t, err)
	require.Equal(t, "We got a security event from Tigera", whJson["message"])
	require.Equal(t, fetchedEvents[0].Description, whJson["event"])
	require.Equal(t, fetchedEvents[0].Type, whJson["event_type"])
	require.Equal(t, "", whJson["missing_data"])
}

func TestBackoffOnInitialFailure(t *testing.T) {
	const retryTimes int = 3
	requests := []testutils.HttpRequest{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Let's make the first requests fail
		if len(requests) < retryTimes {
			w.WriteHeader(http.StatusInternalServerError)
		}
		_, _ = fmt.Fprintln(w, "Does anyone read this?")
		request := testutils.HttpRequest{
			Method: r.Method,
			URL:    r.URL.String(),
			Header: r.Header,
		}
		var err error
		request.Body, err = io.ReadAll(r.Body)
		require.NoError(t, err)
		requests = append(requests, request)
	}))
	defer ts.Close()

	fetchedEvents := []lsApi.Event{newEvent(1)}
	providers := DefaultProviders()
	genericProviderConfig := providers[api.SecurityEventWebhookConsumerGeneric].Config()
	genericProviderConfig.RetryTimes = uint(retryTimes)
	genericProviderConfig.RetryDuration = 1 * time.Second
	providers[api.SecurityEventWebhookConsumerGeneric] = generic.NewProvider(genericProviderConfig)
	testState := NewTestState(func(context.Context, *query.Query, time.Time, time.Time) ([]lsApi.Event, error) {
		return fetchedEvents, nil
	}, providers)

	SetupWithTestState(t, testState)

	whUrl := fmt.Sprintf("%s/test-hook", ts.URL)
	wh := testutils.NewTestWebhook("test-generic-webhook")
	wh.Spec.Consumer = api.SecurityEventWebhookConsumerGeneric
	// Making sure we'll update the right config...
	require.Equal(t, wh.Spec.Config[0].Name, "url")
	// Updating URL to point to the test server
	wh.Spec.Config[0].Value = whUrl
	_, err := testState.WebHooksAPI.Update(context.Background(), wh, options.SetOptions{})
	require.NoError(t, err)

	// The health of the webhook is only updated to an error status after the maximum number of retries
	// has been reached and we give up on that event.
	require.Eventually(t, func() bool { return !isHealthy(wh)() }, 20*time.Second, 10*time.Millisecond)
	require.Contains(t, wh.Status[0].Message, "unexpected response [500]:Does anyone read this?")

	// And check that the data is as expected
	require.Equal(t, "POST", requests[0].Method)
	require.Equal(t, "/test-hook", requests[0].URL)
	// And check that we get a JSON of the original event
	var whEvent lsApi.Event
	err = json.Unmarshal(requests[0].Body, &whEvent)
	require.NoError(t, err)
	require.Equal(t, fetchedEvents[0], whEvent)

	// Eventually, the webhook gets back to healthy status as requests start to go through
	require.Eventually(t, func() bool { return isHealthy(wh)() }, 5*time.Second, 10*time.Millisecond)
}

func TestWebhookErrorsDontDisappear(t *testing.T) {
	providers := DefaultProviders()
	genericProviderConfig := providers[api.SecurityEventWebhookConsumerGeneric].Config()
	genericProviderConfig.RequestTimeout = 100 * time.Millisecond
	genericProviderConfig.RetryTimes = 3
	genericProviderConfig.RetryDuration = 1 * time.Second
	providers[api.SecurityEventWebhookConsumerGeneric] = generic.NewProvider(genericProviderConfig)
	shouldSendEvents := false
	testState := NewTestState(func(context.Context, *query.Query, time.Time, time.Time) ([]lsApi.Event, error) {
		if shouldSendEvents {
			// Set to false so that we only do it once
			return []lsApi.Event{{ID: "test", Description: "test", Severity: 3, Type: "runtime_security", Origin: "test"}}, nil
		}
		return []lsApi.Event{}, nil
	}, providers)

	SetupWithTestState(t, testState)

	previousTime := time.Now()

	// New webhook has no status
	wh := testutils.NewTestWebhook("test-wh")
	wh.Spec.Consumer = api.SecurityEventWebhookConsumerGeneric
	// Use an invalid URL to generate an error
	require.Equal(t, "url", wh.Spec.Config[0].Name)
	wh.Spec.Config[0].Value = "http://my-fake-webhook-server.test/does-not-exists"
	require.Nil(t, wh.Status)

	_, err := testState.WebHooksAPI.Update(context.Background(), wh, options.SetOptions{})
	require.NoError(t, err)

	// Check that webhook status is eventually updated to healthy
	require.Eventually(t, hasHealthStatus(wh, true), time.Second, 10*time.Millisecond)
	require.True(t, wh.Status[0].LastTransitionTime.After(previousTime))
	previousTime = wh.Status[0].LastTransitionTime.Time

	// Let's return test events
	shouldSendEvents = true
	logrus.Debug("Setting shouldSendEvents to true")
	// Wait for the status to go bad
	require.Eventually(t, hasHealthStatus(wh, false), 20*time.Second, time.Second)
	require.True(t, wh.Status[0].LastTransitionTime.After(previousTime))
	previousTime = wh.Status[0].LastTransitionTime.Time
	// We don't check the error message as it can either be "host not found" or "context deadline exceeded"

	shouldSendEvents = false

	// Wait for another round of processing (with no new events)
	time.Sleep(testState.FetchingInterval * 2)

	// And make sure that the previous error is still visible
	require.Eventually(t, hasHealthStatus(wh, false), time.Second, 10*time.Millisecond)
	require.Greater(t, wh.Status[0].LastTransitionTime.Time, previousTime)
}

func TestLinseedErrorHandling(t *testing.T) {
	// In this test, we want to test that:
	//  - Linseed query error (fetchError) gets cleared once issue is resolved
	//  - A fetchError does not update the health status timestamp so that we don't skip any event once we recover
	providers := DefaultProviders()
	genericProviderConfig := providers[api.SecurityEventWebhookConsumerGeneric].Config()
	genericProviderConfig.RequestTimeout = 100 * time.Millisecond
	genericProviderConfig.RetryTimes = 3
	genericProviderConfig.RetryDuration = 1 * time.Second
	providers[api.SecurityEventWebhookConsumerGeneric] = generic.NewProvider(genericProviderConfig)

	fetchError := errors.New("Failed to fetch events from Linseed")
	queriedTimes := []map[string]time.Time{}
	testState := NewTestState(func(ctx context.Context, query *query.Query, start, end time.Time) ([]lsApi.Event, error) {
		times := make(map[string]time.Time)
		times["start"] = start
		times["end"] = end
		queriedTimes = append(queriedTimes, times)
		return []lsApi.Event{}, fetchError
	}, providers)

	SetupWithTestState(t, testState)

	previousTime := time.Now()

	// New webhook has no status
	wh := testutils.NewTestWebhook("test-wh")
	wh.Spec.Consumer = api.SecurityEventWebhookConsumerGeneric

	_, err := testState.WebHooksAPI.Update(context.Background(), wh, options.SetOptions{})
	require.NoError(t, err)

	// Check that webhook status is non-healthy because of a fetch error
	require.Eventually(t, healthStatusIs(wh, false, fetchError.Error()), 5*time.Second, 10*time.Millisecond)
	require.True(t, wh.Status[0].LastTransitionTime.After(previousTime))
	previousTime = wh.Status[0].LastTransitionTime.Time

	// Wait for 2 requests to fetch events for next test
	var numFetchErrors int
	require.Eventually(t, func() bool {
		numFetchErrors = len(queriedTimes)
		return numFetchErrors > 1
	}, 5*time.Second, 10*time.Millisecond)

	// Check that request following a fetchError used the same start time (so that we don't miss events)
	require.Equal(t, queriedTimes[0]["start"], queriedTimes[1]["start"])
	// But they should not have the same end time
	require.NotEqual(t, queriedTimes[0]["end"], queriedTimes[1]["end"])

	// Clear fetchError
	fetchError = nil

	// Wait for the status to become healthy
	require.Eventually(t, hasHealthStatus(wh, true), 5*time.Second, time.Second)
	require.True(t, wh.Status[0].LastTransitionTime.After(previousTime))

	previousTime = wh.Status[0].LastTransitionTime.Time

	// Wait for successful fetch after recovering form fetchError
	require.Eventually(t, func() bool {
		return wh.Status[0].LastTransitionTime.After(previousTime) &&
			wh.Status[0].Status == "True"
	}, 5*time.Second, time.Second)

	// Check that request after recovering from a fetchError no longer has overlapping times
	last := len(queriedTimes) - 1
	// Expecting to have at least 3 requests at this stage (initial fetchError, transition to fix fetchError, next request with no fetchError)
	require.Greater(t, last, 2)
	// The start time should match the previous message's end time
	require.NotEqual(t, queriedTimes[last]["start"], queriedTimes[last-1]["start"], queriedTimes)
	require.Equal(t, queriedTimes[last]["start"], queriedTimes[last-1]["end"])
	// But they should not have the same end time
	require.NotEqual(t, queriedTimes[last]["end"], queriedTimes[last-1]["end"])
}

func newEvent(n int) lsApi.Event {
	return lsApi.Event{
		ID:          fmt.Sprintf("testid%d", n),
		Description: "This is an event",
		Severity:    n,
		Time:        lsApi.NewEventTimestamp(time.Now().Unix()),
		Type:        "runtime_security",
	}
}

func healthStatusIs(webhook *api.SecurityEventWebhook, status bool, message string) func() bool {
	value := "False"
	if status {
		value = "True"
	}
	return func() bool {
		return webhook != nil &&
			webhook.Status != nil &&
			len(webhook.Status) == 1 &&
			webhook.Status[0].Type == "Healthy" &&
			webhook.Status[0].Status == metav1.ConditionStatus(value) &&
			strings.Contains(webhook.Status[0].Message, message)
	}
}

func hasHealthStatus(webhook *api.SecurityEventWebhook, status bool) func() bool {
	return healthStatusIs(webhook, status, "")
}

func isHealthy(webhook *api.SecurityEventWebhook) func() bool {
	return hasHealthStatus(webhook, true)
}

func hasOneRequest(provider *TestProvider) func() bool {
	return hasNRequest(provider, 1)
}

func hasNRequest(provider *TestProvider, n int) func() bool {
	return func() bool {
		return len(provider.Requests) == n
	}
}

type TestState struct {
	Running          bool
	Stop             func()
	WebHooksAPI      *testutils.FakeSecurityEventWebhook
	GetEvents        func(context.Context, *query.Query, time.Time, time.Time) ([]lsApi.Event, error)
	Providers        map[api.SecurityEventWebhookConsumer]providers.Provider
	FetchingInterval time.Duration
	K8sClient        kubernetes.Interface
	WebhooksCtrl     WebhookControllerInterface
}

func NewTestState(getEvents func(context.Context, *query.Query, time.Time, time.Time) ([]lsApi.Event, error), providers map[api.SecurityEventWebhookConsumer]providers.Provider) *TestState {
	testState := &TestState{}
	testState.WebHooksAPI = &testutils.FakeSecurityEventWebhook{}
	testState.GetEvents = getEvents
	testState.Running = false
	testState.FetchingInterval = 2 * time.Second
	testState.Providers = providers
	testState.K8sClient = fake.NewClientset()

	return testState
}

func (t *TestState) TestSlackProvider() *TestProvider {
	return t.Providers[api.SecurityEventWebhookConsumerSlack].(*TestProvider)
}

func Setup(t *testing.T, getEvents func(context.Context, *query.Query, time.Time, time.Time) ([]lsApi.Event, error)) *TestState {
	testProviders := make(map[api.SecurityEventWebhookConsumer]providers.Provider)
	testProviders[api.SecurityEventWebhookConsumerSlack] = NewTestProvider()

	require.NotZero(t, testProviders[api.SecurityEventWebhookConsumerSlack].Config().RateLimiterCount)
	testState := NewTestState(getEvents, testProviders)

	return SetupWithTestState(t, testState)
}

func SetupWithTestState(t *testing.T, testState *TestState) *TestState {
	logrus.SetLevel(logrus.DebugLevel)

	config := &ControllerConfig{
		ClientV3:            testState.WebHooksAPI,
		EventsFetchFunction: testState.GetEvents,
		Providers:           testState.Providers,
		FetchingInterval:    testState.FetchingInterval,
	}

	webhookWatcherUpdater := NewWebhookWatcherUpdater().WithWebhooksClient(config.ClientV3).WithK8sClient(testState.K8sClient)
	controllerState := NewControllerState().WithConfig(config).WithK8sClient(testState.K8sClient)
	webhookController := NewWebhookController().WithUpdater(webhookWatcherUpdater).WithState(controllerState)
	webhookWatcherUpdater.WithController(webhookController)
	testState.WebhooksCtrl = webhookController

	var ctx context.Context
	ctx, testState.Stop = context.WithCancel(context.Background())

	cancelFunc := SetUp(ctx, webhookController, webhookWatcherUpdater)
	testState.Running = true
	testState.Stop = func() {
		cancelFunc()
		testState.Running = false
	}

	require.Eventually(t, func() bool { return testState.Running }, time.Second, 10*time.Millisecond)

	// Sanity test
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		assert.NotNil(t, testState.WebHooksAPI.Watcher)
	}, time.Second, 100*time.Millisecond)

	t.Cleanup(func() {
		if testState.Stop != nil {
			// Making sure it's still running before we turn it off
			require.Eventually(t, func() bool { return testState.Running }, time.Second, 10*time.Millisecond)

			// make sure the webhook updater and webhook controller exit in the correct
			testState.Stop()

			require.Eventually(t, func() bool { return !testState.Running }, 10*time.Second, 10*time.Millisecond)

		}
	})

	return testState
}

type Request struct {
	Config map[string]string
	Labels map[string]string
	Event  lsApi.Event
}

type SlackProvider = slack.Slack
type TestProvider struct {
	SlackProvider
	Requests []Request
}

func NewTestProvider() providers.Provider {
	return &TestProvider{
		SlackProvider: *slack.NewProvider(GetTestProviderConfig()).(*slack.Slack),
	}
}
func (p *TestProvider) Validate(config map[string]string) error {
	if _, urlPresent := config["url"]; !urlPresent {
		return errors.New("url field is not present in webhook configuration")
	}
	return nil
}

func (p *TestProvider) Process(ctx context.Context, config map[string]string, labels map[string]string, event *lsApi.Event) (resp providers.ProviderResponse, err error) {
	logrus.Infof("Processing event %s", event.ID)
	p.Requests = append(p.Requests, Request{
		Config: config,
		Labels: labels,
		Event:  *event,
	})

	return providers.ProviderResponse{}, nil
}

func (p *TestProvider) Config() providers.Config {
	return p.SlackProvider.Config()
}

func GetTestProviderConfig() providers.Config {
	return providers.Config{
		RateLimiterDuration: time.Hour,
		RateLimiterCount:    5,
		RequestTimeout:      time.Second,
		RetryDuration:       time.Millisecond,
		RetryTimes:          2,
	}
}
