// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package earlynetworking

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"go.yaml.in/yaml/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	KindEarlyNetworkConfiguration = "EarlyNetworkConfiguration"
)

type EarlyNetworkConfiguration struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the EarlyNetworkConfiguration.
	Spec EarlyNetworkConfigurationSpec `json:"spec,omitempty"`
}

type EarlyNetworkConfigurationSpec struct {
	Nodes    []ConfigNode
	Platform string
	Legacy   LegacyConfig `yaml:"legacy,omitempty" json:"legacy,omitempty"`
}

const (
	PlatformOpenShift = "openshift"
)

type ConfigNode struct {
	InterfaceAddresses []string            `yaml:"interfaceAddresses"`
	ASNumber           int                 `yaml:"asNumber"`
	StableAddress      ConfigStableAddress `yaml:"stableAddress"`
	Peerings           []ConfigPeering     `yaml:"peerings"`
	Labels             map[string]string   `yaml:"labels"`
}

type LegacyConfig struct {
	NodeIPFromDefaultRoute               bool `yaml:"nodeIPFromDefaultRoute,omitempty" json:"nodeIPFromDefaultRoute,omitempty"`
	UnconditionalDefaultRouteProgramming bool `yaml:"unconditionalDefaultRouteProgramming,omitempty" json:"unconditionalDefaultRouteProgramming,omitempty"`
}

type ConfigStableAddress struct {
	Address string
}

type ConfigPeering struct {
	PeerIP       string `yaml:"peerIP"`
	PeerASNumber int    `yaml:"peerASNumber"`
}

func GetEarlyNetworkConfig(yamlFileName string) (*EarlyNetworkConfiguration, error) {
	yamlFile, err := os.Open(yamlFileName)
	if err != nil {
		return nil, fmt.Errorf("Failed to open YAML file at %v: %v", yamlFileName, err)
	}
	defer yamlFile.Close()

	var cfg EarlyNetworkConfiguration
	err = yaml.NewDecoder(yamlFile).Decode(&cfg)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode YAML file at %v: %v", yamlFileName, err)
	}
	logrus.WithField("cfg", cfg).Infof("Read YAML file at %v", yamlFileName)

	return &cfg, nil
}
