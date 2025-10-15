// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package generic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	lsApi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/webhooks-processor/pkg/helpers"
	"github.com/projectcalico/calico/webhooks-processor/pkg/providers"
)

const (
	GenericProviderTemplateName = "genericProviderTemplate"
)

type GenericProvider struct {
	config providers.Config
}

type GenericProviderPayload struct {
	*lsApi.Event
	Labels map[string]string `json:"labels"`
}

func NewProvider(config providers.Config) providers.Provider {
	return &GenericProvider{
		config: config,
	}
}

func (p *GenericProvider) Validate(config map[string]string) error {
	if _, urlPresent := config["url"]; !urlPresent {
		return errors.New("url field is not present in webhook configuration")
	}
	if headers, hasHeaders := config["headers"]; hasHeaders {
		if _, err := helpers.ProcessHeaders(headers); err != nil {
			return err
		}
	}
	if templateData, hasTemplate := config["template"]; hasTemplate {
		if _, err := template.New(GenericProviderTemplateName).Parse(templateData); err != nil {
			return err
		}
	}
	return nil
}

func (p *GenericProvider) Process(ctx context.Context, config map[string]string, labels map[string]string, event *lsApi.Event) (httpResponse providers.ProviderResponse, err error) {
	payload, err := json.Marshal(GenericProviderPayload{Event: event, Labels: labels})
	if err != nil {
		return
	}

	retryFunc := func() (err error) {
		requestCtx, requestCtxCancel := context.WithTimeout(ctx, p.Config().RequestTimeout)
		defer requestCtxCancel()

		// If template config is set, we will interpret its content as a go-template and use it
		// to transform the event to match whatever format is defined in the template.
		if templateData, ok := config["template"]; ok {
			tmpl, err := template.New(GenericProviderTemplateName).Parse(templateData)
			if err != nil {
				// this is just defensive coding, we should never get here because the validation happens first:
				return helpers.NewNoRetryError(err)
			}
			result, err := helpers.ProcessTemplate(tmpl, payload)
			if err != nil {
				return err
			}
			payload = result
		}

		request, err := http.NewRequestWithContext(requestCtx, "POST", config["url"], bytes.NewReader(payload))
		if err != nil {
			return
		}

		headers := make(map[string]string)
		if rawHeaders, ok := config["headers"]; ok {
			if headers, err = helpers.ProcessHeaders(rawHeaders); err != nil {
				// this is just defensive coding, we should never get here because the validation happens first:
				return helpers.NewNoRetryError(err)
			}
		}
		if _, hasContentType := headers["Content-Type"]; !hasContentType {
			headers["Content-Type"] = "application/json"
		}
		for header, value := range headers {
			request.Header.Set(header, value)
		}

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

		if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
			return
		}

		return fmt.Errorf("unexpected response [%d]:%s", response.StatusCode, responseText)
	}

	return httpResponse, helpers.RetryWithLinearBackOff(retryFunc, p.config.RetryDuration, p.config.RetryTimes)
}

func (p *GenericProvider) Config() providers.Config {
	return p.config
}
