// Copyright 2019, 2023 Tigera Inc. All rights reserved.

package config

import (
	"fmt"
	"time"

	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/firewall-integration/pkg/util"
)

const (
	fwRoutablePod  = "pod"
	fwRoutableNode = "node"
)

type FwFortiGateConfig struct {
	Ip     string
	Port   string
	ApiKey string
	Vdom   string
}

type FwFortiMgrConfig struct {
	Ip       string
	Port     string
	Username string
	Password string
	Adom     string
}

type Config struct {
	FwType                      string        `envconfig:"FW_TYPE" default:"PANW" json:"type"`
	FwUserName                  string        `envconfig:"FW_USERNAME" json:"username"`
	FwPassword                  string        `envconfig:"FW_PASSWORD" json:"password"`
	FwAPIKey                    string        `envconfig:"FW_APIKEY" json:"apiKey"`
	FwHostName                  string        `envconfig:"FW_HOSTNAME" json:"hostname"`
	FwHostPort                  int16         `envconfig:"FW_HOSTPORT" default:"443" json:"port"`
	FwHostProtocol              string        `envconfig:"FW_HOSTPROTO" default:"https" json:"protocol"`
	FwDeviceGroup               string        `envconfig:"FW_DEVGROUP" json:"devicegroups"`
	FwPollInterval              time.Duration `envconfig:"FW_POLL_INTERVAL" default:"10s" json:"poll_interval"`
	FwPolicyTier                string        `envconfig:"FW_POLICY_TIER" default:"firewallpolicy" json:"fwPolicyTier"`
	FwPolicyTierOrder           float64       `envconfig:"FW_POLICY_TIER_ORDER" default:"101" json:"fwPolicyTierOrder"`
	FwTimeout                   int           `envconfig:"FW_TIMEOUT" default:"10" json:"timeout"`
	FwInsecureSkipVerify        bool          `envconfig:"FW_INSECURE_SKIP_VERIFY" required:"true" default:"false" json:"fwInsecureSkipVerify"`
	FwAdom                      string        `envconfig:"FW_ADOM" json:"adom"`
	FwPolicyControllerNamespace string        `envconfig:"FW_POLICY_CONTROLLER_NAMESPACE_SELECTOR" default:"tigera-firewall-integration" json:"fwPolicyControllerNamespace"`
	FwPolicyNamespaceSelector   string        `envconfig:"FW_POLICY_NAMESPACE_SELECTOR" default:"global()" json:"fwPolicyNamespaceSelector"`
	FwPolicySelectorExpression  string        `envconfig:"FW_POLICY_SELECTOR_EXPRESSION" default:"projectcalico.org/tier == 'default'" json:"fwPolicySelectorExpression"`
	FwPolicyOrder               float64       `envconfig:"FW_POLICY_ORDER" default:"1000" json:"fwPolicyOrder"`
	FwAddressSelection          string        `envconfig:"FW_ADDRESS_SELECTION" default:"node" json:"addressSelection"`
	FwFortiGateConfig           string        `envconfig:"FW_FORTIGATE_CONFIG_PATH" json:"fwfortiGateConfigPath"`
	FwFortiMgrConfig            string        `envconfig:"FW_FORTIMGR_CONFIG_PATH"  json:"fwfortiMgrConfigPath"`
	FwFortiMgrEWPollInterval    time.Duration `envconfig:"FW_FORTIMGR_EW_POLL_INTERVAL" default:"3s" json:"fwfortiMgrEWPollInterval"`
	FwFortiMgrEWConfig          string        `envconfig:"FW_FORTIMGR_EW_CONFIG_PATH"  json:"fwfortiMgrEWConfigPath"`

	TSTierPrefix     string `envconfig:"TSEE_TIER_PREFIX" default:"fw" json:"tsTierPrefix"`
	TSNetworkPrefix  string `envconfig:"TSEE_NETWORK_PREFIX" default:"fw" json:"tsNetworkPrefix"`
	TSTierOrder      string `envconfig:"TSEE_TIER_ORDER" default:"101" json:"tsTierOrder"`
	TSPassToNextTier bool   `envconfig:"TSEE_PASS_TO_NEXT_TIER" json:"tSPassToNextTier"`
	TSEtcdEndpoint   string `envconfig:"ETCD_ENDPOINTS" json:"tsEtcdEndpoint"`

	// TODO(doublek): Check if we need json tags here.
	EnabledControllers string `envconfig:"ENABLED_CONTROLLERS" split_words:"true" required:"true" json:"enabledControllers"`
	KubeConfig         string `envconfig:"KUBECONFIG" default:"" split_words:"false" json:"kubeConfig"`
}

func LoadConfig() (*Config, error) {
	var err error

	config := &Config{}
	err = envconfig.Process("", config)
	if err != nil {
		return nil, err
	}

	if config.FwAddressSelection != fwRoutablePod && config.FwAddressSelection != fwRoutableNode {
		return nil, fmt.Errorf("valid Firewall Address selector is 'node' or 'pod', given value isn't correct value %#v", config.FwAddressSelection)
	}

	// Validate and define tier name.
	if !util.IsValidTierName(config.FwPolicyTier) {
		log.Debugf("Invalid tier name: %s", config.FwPolicyTier)
		return nil, fmt.Errorf("invalid tier name: %s", config.FwPolicyTier)
	}

	return config, nil
}
