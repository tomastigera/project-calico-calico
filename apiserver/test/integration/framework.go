// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.package util

package integration

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	calicoclient "github.com/tigera/api/pkg/client/clientset_generated/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	restclient "k8s.io/client-go/rest"

	"github.com/projectcalico/calico/apiserver/cmd/apiserver/server"
	"github.com/projectcalico/calico/apiserver/pkg/apiserver"
	licutils "github.com/projectcalico/calico/licensing/utils"
)

const defaultEtcdPathPrefix = ""

type TestServerConfig struct {
	etcdServerList                []string
	emptyObjFunc                  func() runtime.Object
	enableManagedClusterCreateAPI bool
	managementClusterAddr         string
	tunnelSecretName              string
	applyTigeraLicense            bool
}

// NewTestServerConfig is a default constructor for the standard test-apiserver setup
func NewTestServerConfig() *TestServerConfig {
	return &TestServerConfig{
		etcdServerList: []string{"http://localhost:2379"},
	}
}

func withConfigGetFreshAPIServerServerAndClient(
	t *testing.T,
	serverConfig *TestServerConfig,
) (*apiserver.ProjectCalicoServer,
	calicoclient.Interface,
	*restclient.Config,
	func(),
) {
	securePort := rand.Intn(31743) + 1024
	secureAddr := fmt.Sprintf("https://localhost:%d", securePort)
	stopCh := make(chan struct{})
	serverFailed := make(chan struct{})
	shutdownServer := func() {
		t.Logf("Shutting down server on port: %d", securePort)
		close(stopCh)
	}

	t.Logf("Starting server on port: %d", securePort)
	ro := genericoptions.NewRecommendedOptions(defaultEtcdPathPrefix, apiserver.Codecs.LegacyCodec(v3.SchemeGroupVersion))
	ro.Etcd.StorageConfig.Transport.ServerList = serverConfig.etcdServerList
	ro.Features.EnablePriorityAndFairness = false
	options := &server.CalicoServerOptions{
		RecommendedOptions: ro,
		DisableAuth:        true,
		StopCh:             stopCh,
	}
	options.RecommendedOptions.SecureServing.BindPort = securePort
	// Set this so that we avoid RecommendedOptions.CoreAPI's initialization from calling InClusterConfig()
	// and uses our fv kubeconfig instead.
	options.RecommendedOptions.CoreAPI.CoreAPIKubeconfigPath = os.Getenv("KUBECONFIG")

	options.EnableManagedClustersCreateAPI = serverConfig.enableManagedClusterCreateAPI
	options.ManagementClusterAddr = serverConfig.managementClusterAddr
	options.TunnelSecretName = serverConfig.tunnelSecretName

	var err error
	pcs, err := server.PrepareServer(options)
	if err != nil {
		close(serverFailed)
		t.Fatalf("Error preparing the server: %v", err)
	}

	// Run the server in the background
	go func() {
		err := server.RunServer(options, pcs)
		if err != nil {
			close(serverFailed)
		}
	}()

	if err := waitForAPIServerUp(secureAddr, serverFailed); err != nil {
		t.Fatalf("%v", err)
	}
	if pcs == nil {
		t.Fatal("Calico server is nil")
	}

	cfg := &restclient.Config{}
	cfg.Host = secureAddr
	cfg.Insecure = true
	clientset, err := calicoclient.NewForConfig(cfg)
	if err != nil {
		t.Fatal("can't make the client from the config", err)
	}

	licenseClient := clientset.ProjectcalicoV3().LicenseKeys()
	_ = licenseClient.Delete(context.Background(), "default", metav1.DeleteOptions{})

	if serverConfig.applyTigeraLicense {
		validLicenseKey := licutils.ValidEnterpriseTestLicense()
		_, err = licenseClient.Create(context.Background(), validLicenseKey, metav1.CreateOptions{})
		if err != nil {
			t.Fatal("License cannot be applied", err)
		}
	}

	return pcs, clientset, cfg, shutdownServer
}

func getFreshAPIServerServerAndClient(t *testing.T, newEmptyObj func() runtime.Object) (*apiserver.ProjectCalicoServer, calicoclient.Interface, func()) {
	serverConfig := &TestServerConfig{
		etcdServerList:     []string{"http://localhost:2379"},
		emptyObjFunc:       newEmptyObj,
		applyTigeraLicense: true,
	}
	pcs, client, _, shutdownFunc := withConfigGetFreshAPIServerServerAndClient(t, serverConfig)
	return pcs, client, shutdownFunc
}

func getFreshAPIServerAndClient(t *testing.T, newEmptyObj func() runtime.Object, applyTigeraLicense bool) (calicoclient.Interface, func()) {
	serverConfig := &TestServerConfig{
		etcdServerList:     []string{"http://localhost:2379"},
		emptyObjFunc:       newEmptyObj,
		applyTigeraLicense: applyTigeraLicense,
	}
	_, client, _, shutdownFunc := withConfigGetFreshAPIServerServerAndClient(t, serverConfig)
	return client, shutdownFunc
}

func customizeFreshAPIServerAndClient(
	t *testing.T,
	serverConfig *TestServerConfig,
) (calicoclient.Interface, *restclient.Config, func()) {
	_, client, restConfig, shutdownFunc := withConfigGetFreshAPIServerServerAndClient(t, serverConfig)
	return client, restConfig, shutdownFunc
}

func waitForAPIServerUp(serverURL string, stopCh <-chan struct{}) error {
	interval := 1 * time.Second
	timeout := 30 * time.Second
	startWaiting := time.Now()
	tries := 0
	return wait.PollUntilContextTimeout(context.Background(), interval, timeout, true,
		func(ctx context.Context) (bool, error) {
			select {
			// we've been told to stop, so no reason to keep going
			case <-stopCh:
				return true, fmt.Errorf("apiserver failed")
			default:
				logrus.Infof("Waiting for : %#v", serverURL)
				tr := &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}
				c := &http.Client{Transport: tr}
				_, err := c.Get(serverURL)
				if err == nil {
					logrus.Tracef("Found server after %v tries and duration %v",
						tries, time.Since(startWaiting))
					return true, nil
				}
				tries++
				return false, nil
			}
		},
	)
}

func createEnterprise(client calicoclient.Interface, ctx context.Context) error {
	enterpriseValidLicenseKey := licutils.ValidEnterpriseTestLicense()
	_, err := client.ProjectcalicoV3().LicenseKeys().Create(ctx, enterpriseValidLicenseKey, metav1.CreateOptions{})
	return err
}
