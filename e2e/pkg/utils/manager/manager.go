// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package manager

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	. "github.com/onsi/gomega"
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/projectcalico/calico/e2e/pkg/utils"
)

const (
	managerNamespace = "calico-system"
	managerService   = "svc/calico-manager"
	managerLocalPort = "9443"
)

// Client provides authenticated access to the calico-manager API.
type Client struct {
	httpClient *http.Client
	token      string
	baseURL    string
}

// PortForward starts port-forwarding to the calico-manager service and returns
// the allocated local port and a cancel function to stop the forward.
func PortForward() (int, func()) {
	stopCh := make(chan time.Time, 1)
	k := utils.Kubectl{}
	port, err := k.PortForward(managerNamespace, managerService, managerLocalPort, "", stopCh)
	Expect(err).NotTo(HaveOccurred(), "failed to start manager port-forward")
	return port, func() {
		stopCh <- time.Now()
		close(stopCh)
	}
}

// NewClient creates a manager API client with TLS verification and a
// tigera-network-admin bearer token. The port should be the local port
// returned by PortForward.
func NewClient(ctx context.Context, f *framework.Framework, port int) *Client {
	caCert := utils.GetTigeraCACert(ctx, f)
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: caCert,
	}}}

	token, err := utils.NetworkAdminToken(ctx, f.ClientSet, f.Namespace.Name)
	Expect(err).NotTo(HaveOccurred(), "Failed to create network admin token for manager API")

	return &Client{httpClient: httpClient, token: token, baseURL: fmt.Sprintf("https://localhost:%d", port)}
}

// BatchStagedActionParams is the request body for the /batchActions endpoint.
type BatchStagedActionParams struct {
	StagedNetworkPolicies []StagedNetworkPolicyRef `json:"stagedNetworkPolicies"`
	StagedAction          string                   `json:"stagedAction"`
}

// StagedNetworkPolicyRef identifies a staged network policy for batch operations.
type StagedNetworkPolicyRef struct {
	Name            string `json:"name"`
	Namespace       string `json:"namespace"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resourceVersion"`
}

// BatchEnforce calls /batchActions with stagedAction="Set" for the given policies,
// mirroring the UI enforcement flow.
func (c *Client) BatchEnforce(policies []StagedNetworkPolicyRef) {
	body := BatchStagedActionParams{
		StagedNetworkPolicies: policies,
		StagedAction:          "Set",
	}
	bodyBytes, err := json.Marshal(body)
	Expect(err).NotTo(HaveOccurred())

	url := fmt.Sprintf("%s/tigera-elasticsearch/batchActions", c.baseURL)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(bodyBytes))
	Expect(err).NotTo(HaveOccurred())
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	Expect(err).NotTo(HaveOccurred(), "failed to call /batchActions")
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	Expect(resp.StatusCode).To(Equal(http.StatusOK),
		"expected 200 from /batchActions, got %d: %s", resp.StatusCode, string(respBody))
}

// WaitForManager polls the manager until it responds, ensuring the port-forward is ready.
func WaitForManager(c *Client) {
	EventuallyWithOffset(1, func() error {
		req, err := http.NewRequest(http.MethodGet, c.baseURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("manager not reachable: %w", err)
		}
		resp.Body.Close()
		return nil
	}, 30*time.Second, 2*time.Second).Should(Succeed(), "manager should be reachable via port-forward")
}
