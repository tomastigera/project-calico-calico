// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package events

import (
	"context"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/validator/v3/query"
	lsApi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsClient "github.com/projectcalico/calico/linseed/pkg/client"
	lsRest "github.com/projectcalico/calico/linseed/pkg/client/rest"
	lmaV1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/projectcalico/calico/ui-apis/pkg/middleware/search"
)

var securityEventsClient lsClient.EventsInterface
var alertExceptionsClient clientv3.AlertExceptionInterface

type LinseedCfg struct {
	TenantId   string `envconfig:"LINSEED_TENANT_ID"`
	URL        string `envconfig:"LINSEED_URL" default:"https://tigera-linseed.tigera-elasticsearch.svc"`
	CA         string `envconfig:"LINSEED_CA" default:"/etc/pki/tls/certs/ca.crt"`
	ClientCert string `envconfig:"LINSEED_CLIENT_CERT" default:"/etc/pki/tls/certs/ca.crt"`
	ClientKey  string `envconfig:"LINSEED_CLIENT_KEY"`
	Token      string `envconfig:"LINSEED_TOKEN" default:"/var/run/secrets/kubernetes.io/serviceaccount/token"`
}

func init() {
	// Init linseed client
	config := new(LinseedCfg)
	envconfig.MustProcess("linseed", config)

	client, err := lsClient.NewClient(
		config.TenantId,
		lsRest.Config{
			URL:            config.URL,
			CACertPath:     config.CA,
			ClientCertPath: config.ClientCert,
			ClientKeyPath:  config.ClientKey,
		},
		lsRest.WithTokenPath(config.Token),
	)

	if err == nil {
		securityEventsClient = client.Events("")
		logrus.Info("Linseed connection initialized")
	} else {
		logrus.WithError(err).Fatal(("Linseed connection error"))
	}

	// Init calico client
	calicoClient, err := clientv3.NewFromEnv()
	if err != nil {
		logrus.WithError(err).Fatal("Unable to initialize v3 client")
	}

	alertExceptionsClient = calicoClient.AlertExceptions()
}

func FetchSecurityEventsFunc(ctx context.Context, query *query.Query, fromStamp time.Time, toStamp time.Time) ([]lsApi.Event, error) {
	selector := query.String()

	alertExceptions, err := alertExceptionsClient.List(ctx, options.ListOptions{})
	if err != nil {
		logrus.WithError(err).Error("Error occurred when listing AlertExceptions")
		return []lsApi.Event{}, err
	}

	selector = search.UpdateSelectorWithAlertExceptions(alertExceptions, selector)

	logrus.WithFields(logrus.Fields{
		"query":    query,
		"selector": selector,
	}).Info("Fetching security events from Linseed")

	queryParameters := lsApi.EventParams{
		QueryParams: lsApi.QueryParams{
			TimeRange: &lmaV1.TimeRange{
				From: fromStamp,
				To:   toStamp,
			},
		},
		LogSelectionParams: lsApi.LogSelectionParams{
			Selector: selector,
		},
	}

	if events, err := securityEventsClient.List(ctx, &queryParameters); err != nil {
		logrus.WithError(err).Error("Linseed error occurred when fetching events")
		return []lsApi.Event{}, err
	} else {
		return events.Items, nil
	}
}
