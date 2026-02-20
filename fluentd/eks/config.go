// Copyright (c) 2019-2026 Tigera Inc. All rights reserved.
package main

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	// Credentials
	AWSRegion          string `envconfig:"AWS_REGION"`
	AWSAccessKeyId     string `envconfig:"AWS_ACCESS_KEY_ID"`
	AWSSecretAccessKey string `envconfig:"AWS_SECRET_ACCESS_KEY"`

	// Cloudwatch config
	EKSCloudwatchLogGroup        string `envconfig:"EKS_CLOUDWATCH_LOG_GROUP"`
	EKSCloudwatchLogStreamPrefix string `envconfig:"EKS_CLOUDWATCH_LOG_STREAM_PREFIX" default:"kube-apiserver-audit-"`
	EKSStateFileDir              string `envconfig:"EKS_CLOUDWATCH_STATE_FILE_PFX" default:"/fluentd/cloudwatch-logs/"`

	// Linseed parameters
	LinseedURL        string `envconfig:"LINSEED_ENDPOINT" default:"https://tigera-linseed.tigera-elasticsearch.svc"`
	LinseedCA         string `envconfig:"LINSEED_CA_PATH" default:"/etc/pki/tls/certs/ca.crt"`
	LinseedClientCert string `envconfig:"TLS_CRT_PATH"`
	LinseedClientKey  string `envconfig:"TLS_KEY_PATH"`
	LinseedToken      string `envconfig:"LINSEED_TOKEN" default:"/var/run/secrets/kubernetes.io/serviceaccount/token"`

	// FIPSModeEnabled Enables FIPS 140-2 verified crypto mode.
	FIPSModeEnabled bool `envconfig:"FIPS_MODE_ENABLED" default:"false"`

	// For Calico Cloud, the tenant ID to use.
	TenantID string `envconfig:"TENANT_ID"`
}

func LoadConfig() (*Config, error) {
	var err error

	config := &Config{}
	err = envconfig.Process("", config)
	if err != nil {
		return nil, err
	}

	// Validate credentials
	if config.AWSRegion == "" || config.AWSAccessKeyId == "" || config.AWSSecretAccessKey == "" {
		return nil, fmt.Errorf("missing AWS credentials. make sure AWS_REGION, AWS_ACCESS_KEY_ID, and AWS_SECRET_ACCESS_KEY are available")
	}

	if config.EKSCloudwatchLogGroup == "" {
		return nil, fmt.Errorf("missing EKS logs information. make sure EKS_CLOUDWATCH_LOG_GROUP, EKS_CLOUDWATCH_LOG_STREAM_PREFIX variables are available")
	}

	return config, nil
}
