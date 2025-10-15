// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	lsApi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/webhooks-processor/pkg/helpers"
	"github.com/projectcalico/calico/webhooks-processor/pkg/providers"
)

type Slack struct {
	config providers.Config
}

func NewProvider(config providers.Config) providers.Provider {
	return &Slack{
		config: config,
	}
}

func (p *Slack) Validate(config map[string]string) error {
	if url, urlPresent := config["url"]; !urlPresent {
		return errors.New("url field is not present in webhook configuration")
	} else if !strings.HasPrefix(url, "https://hooks.slack.com/") {
		return errors.New("url field does not start with 'https://hooks.slack.com/'")
	}
	return nil
}

func (p *Slack) Process(ctx context.Context, config map[string]string, labels map[string]string, event *lsApi.Event) (httpResponse providers.ProviderResponse, err error) {
	helpers.FillInEventBlanks(event)
	payload, err := p.message(event, labels).JSON()
	if err != nil {
		return
	}

	retryFunc := func() (err error) {
		requestCtx, requestCtxCancel := context.WithTimeout(ctx, p.config.RequestTimeout)
		defer requestCtxCancel()

		request, err := http.NewRequestWithContext(requestCtx, "POST", config["url"], bytes.NewReader(payload))
		if err != nil {
			return
		}
		request.Header.Set("Content-Type", "application/json")

		response, err := new(http.Client).Do(request)
		if err != nil {
			return
		}
		defer func() { _ = response.Body.Close() }()
		responseBytes, err := io.ReadAll(response.Body)
		if err != nil {
			return
		}
		responseText := string(responseBytes)

		logrus.WithField("url", config["url"]).
			WithField("statusCode", response.StatusCode).
			WithField("response", responseText).
			Info("HTTP request processed")

		httpResponse = providers.ProviderResponse{
			Timestamp:             time.Now(),
			HttpStatusCode:        response.StatusCode,
			HttpStatusDescription: http.StatusText(response.StatusCode),
		}

		_, slackError := SlackErrors[responseText]

		switch {
		case response.StatusCode == 200:
			return
		case slackError:
			return helpers.NewNoRetryError(fmt.Errorf("known Slack error: %s", responseText))
		default:
			return fmt.Errorf("unexpected Slack response [%d]:%s", response.StatusCode, responseText)
		}
	}

	return httpResponse, helpers.RetryWithLinearBackOff(retryFunc, p.config.RetryDuration, p.config.RetryTimes)
}

func (p *Slack) message(event *lsApi.Event, labels map[string]string) *SlackMessage {
	var record string
	recordData := make(map[string]any)
	if err := event.GetRecord(&recordData); err != nil || recordData == nil {
		record = "n/a"
	} else if recordBytes, err := json.MarshalIndent(recordData, "", "\t"); err != nil {
		record = "n/a"
	} else {
		record = string(recordBytes)
	}
	mitigations := []string{}
	mitigations = append(mitigations, *event.Mitigations...)
	message := NewMessage().AddBlocks(
		NewBlock("header", NewField("plain_text", "⚠ Calico Security Alert")),
		NewBlock("section", NewField("mrkdwn", fmt.Sprintf("*%s*", event.Description))),
		NewBlock("section", NewField("mrkdwn", fmt.Sprintf("*‣ Mitigations:*\n\n%s", strings.Join(mitigations, "\n\n")))),
		NewBlock("section", NewField("mrkdwn", fmt.Sprintf("*‣ Event source:* %s", event.Origin))),
		NewBlock("section", NewField("mrkdwn", fmt.Sprintf("*‣ Attack vector:* %s", event.AttackVector))),
		NewBlock("section", NewField("mrkdwn", fmt.Sprintf("*‣ Severity:* %d/100", event.Severity))),
		NewBlock("section", NewField("mrkdwn", fmt.Sprintf("*‣ Mitre IDs:* %s", strings.Join(*event.MitreIDs, ", ")))),
		NewBlock("section", NewField("mrkdwn", fmt.Sprintf("*‣ Mitre tactic:* %s", event.MitreTactic))),
	)

	for label, value := range labels {
		message.AddBlocks(
			NewBlock("section", NewField("mrkdwn", fmt.Sprintf("*‣ %s:* %s", label, value))),
		)
	}

	message.AddBlocks(
		NewBlock("section", NewField("mrkdwn", fmt.Sprintf("*‣ Detailed record information:* ```%s```", record))),
	)

	return message
}

func (p *Slack) Config() providers.Config {
	return p.config
}
