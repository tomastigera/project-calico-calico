// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.
package config

import (
	"net/url"
	"strconv"
	"unsafe"

	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type PluginConfigKeyFunc func(pointer unsafe.Pointer, key string) string

type Config struct {
	InsecureSkipVerify bool `default:"false" split_words:"true"`

	Kubeconfig string `envconfig:"KUBECONFIG" default:""`
	Endpoint   string `envconfig:"ENDPOINT" default:""`

	RestConfig *rest.Config
}

func NewConfig(plugin unsafe.Pointer, pluginConfigKeyFn PluginConfigKeyFunc) (*Config, error) {
	config := &Config{}

	// read from environment variables
	if err := envconfig.Process("", config); err != nil {
		logrus.WithError(err).Error("failed to load envconfig")
		return nil, err
	}

	// read extras from plugin config
	if config.Kubeconfig == "" {
		config.Kubeconfig = pluginConfigKeyFn(plugin, "Kubeconfig")
	}
	if config.Endpoint == "" {
		config.Endpoint = pluginConfigKeyFn(plugin, "Endpoint")
	}
	if tlsVerify, err := strconv.ParseBool(pluginConfigKeyFn(plugin, "tls.verify")); err == nil {
		config.InsecureSkipVerify = !tlsVerify
	}

	// validate configurations
	restConfig, err := clientcmd.BuildConfigFromFlags("", config.Kubeconfig)
	if err != nil {
		return nil, err
	}
	config.RestConfig = restConfig

	if _, err := url.ParseRequestURI(config.Endpoint); err != nil {
		logrus.WithError(err).Infof("failed to parse endpoint %q from environment or plugin config", config.Endpoint)
		config.Endpoint = ""
	}

	logrus.Debugf("kubeconfig=%s", config.Kubeconfig)
	logrus.Debugf("endpoint=%s", config.Endpoint)
	logrus.Debugf("skip_verify=%v", config.InsecureSkipVerify)

	return config, nil
}
