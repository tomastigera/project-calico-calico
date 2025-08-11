package alertmanager_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	api "github.com/tigera/api/pkg/apis/projectcalico/v3"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/webhooks-processor/pkg/providers/alertmanager"
	"github.com/projectcalico/calico/webhooks-processor/pkg/webhooks"
)

var (
	alertMangerProvider = webhooks.DefaultProviders()[api.SecurityEventWebhookConsumerAlertManager]
)

func TestValidate(t *testing.T) {
	testCases := map[error]map[string]string{
		nil: {
			"url": "https://alertmanager/api/v2/alerts",
		},
		alertmanager.ErrWrongPrefix: {
			"url": "alertmanager/api/v2/alerts",
		},
		alertmanager.ErrWrongSuffix: {
			"url": "https://alertmanager/api",
		},
		alertmanager.ErrNoUrlField: {},
	}
	for expectedErr, config := range testCases {
		err := alertMangerProvider.Validate(config)
		if !errors.Is(err, expectedErr) {
			t.Errorf("validation error, expected '%s' got '%s'", expectedErr, err)
		}
	}
}

func TestProcess(t *testing.T) {
	// placeholders for tracking server side data:
	serverSideData := []alertmanager.AlertManagerProviderPayload{}
	headers := map[string][]string{}
	requestsCount := 0

	// start test HTTP server
	testServer := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				requestsCount += 1
				// always fail the first incoming HTTP request
				// the provider will then retry as per its
				// retry policy configuration
				if requestsCount == 1 {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				headers = r.Header
				bytes, _ := io.ReadAll(r.Body)
				if err := json.Unmarshal(bytes, &serverSideData); err != nil {
					t.Errorf("got payload unmarshalling error: %s", err)
				}
			},
		),
	)
	defer testServer.Close()

	// prepare the test URL
	testUrl, err := url.JoinPath(testServer.URL, "api", "v2", "alerts")
	if err != nil {
		t.Errorf("got error preparing test URL: %s", err)
	}

	// context is required for provider processing
	ctx, ctxCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer ctxCancel()

	// processing test event
	response, err := alertMangerProvider.Process(
		ctx,
		map[string]string{
			"url":          testUrl,
			"generatorURL": "just-a-test",
			"basicAuth":    "johnybravo:password",
		},
		map[string]string{
			"label": "unit-test",
		},
		&v1.Event{
			Origin:      "unit-test",
			Description: "this is a test event",
			MitreTactic: "none for the unit test",
			Severity:    1,
		},
	)

	// ensure all went well
	if err != nil {
		t.Errorf("got error processing event: %s", err)
	}

	// verification of HTTP response data (1)
	if response.HttpStatusCode != 200 {
		t.Errorf("got unexpected HTTP response code: %d", response.HttpStatusCode)
	}

	// verification of HTTP response data (2)
	if response.HttpStatusDescription != "OK" {
		t.Errorf("got unexpected HTTP response description: %s", response.HttpStatusDescription)
	}

	// make sure there was only 2 HTTP requests received
	if requestsCount != 2 {
		t.Errorf("got unexpected number of HTTP requests: %d", requestsCount)
	}

	// verify if the HTTP headers are as expected
	if value, present := headers["Authorization"]; present {
		if !reflect.DeepEqual(value, []string{"Basic am9obnlicmF2bzpwYXNzd29yZA=="}) {
			t.Errorf("Authorization HTTP header is not as expected: %+v", value)
		}
	} else {
		t.Error("Authorization HTTP header is missing")
	}
	if value, present := headers["Content-Type"]; present {
		if !reflect.DeepEqual(value, []string{"application/json"}) {
			t.Errorf("Content-Type HTTP header is not as expected: %+v", value)
		}
	} else {
		t.Error("Content-Type HTTP header is missing")
	}

	// make sure there was only 1 security event issued
	if len(serverSideData) != 1 {
		t.Errorf("got unexpected amount of data: %d", len(serverSideData))
	}

	// verify if the payload data is as expected
	eventPayload := serverSideData[0]
	if eventPayload.GeneratorURL != "just-a-test" {
		t.Errorf("received invalid value for GeneratorURL: %s", eventPayload.GeneratorURL)
	}
	if !reflect.DeepEqual(
		eventPayload.Labels,
		map[string]string{
			"alertname": "Calico Security Event",
			"label":     "unit-test",
		},
	) {
		t.Errorf("received invalid value for Labels: %+v", eventPayload.Labels)
	}
	if !reflect.DeepEqual(
		eventPayload.Annotations,
		map[string]string{
			"Attack Vector":  "n/a",
			"Description":    "this is a test event",
			"Destination IP": "n/a",
			"Mitigations":    "n/a",
			"Mitre IDs":      "n/a",
			"Mitre Tactic":   "none for the unit test",
			"Origin":         "unit-test",
			"Severity":       "1",
			"Source IP":      "n/a",
			"Record Data":    "{}",
		},
	) {
		t.Errorf("received invalid value for Annotations: %+v", eventPayload.Annotations)
	}
}
