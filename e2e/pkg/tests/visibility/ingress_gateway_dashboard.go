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

package visibility

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	dashclient "github.com/projectcalico/calico/dashboards/pkg/client"
	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	cclient "github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/elasticsearch"
)

// DESCRIPTION: This test validates the Ingress Gateway L7 Dashboard by querying the
// dashboards service API and verifying that L7 logs contain gateway-specific fields.
// DOCS_URL: https://docs.tigera.io/calico-enterprise/latest/visibility/dashboards
// PRECONDITIONS: Enterprise v3.23 or later with Gateway API support.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.EV),
	describe.WithFeature("Dashboards"),
	describe.WithCategory(describe.Visibility),
	"ingress gateway dashboard",
	func() {
		var (
			f          = utils.NewDefaultFramework("ingress-gateway-dashboard")
			httpClient *http.Client
			token      string
			cli        client.Client
			connTester conncheck.ConnectionTester

			gatewayAPIName string
			clusterIP      string
			pf             *elasticsearch.PortForwardInfo
			backendNS      *corev1.Namespace
		)

		BeforeEach(func() {
			ctx := context.Background()

			var err error
			cli, err = cclient.New(f.ClientConfig())
			Expect(err).ShouldNot(HaveOccurred())

			// Fail if not enterprise - this test requires Calico Enterprise with operator
			isEnterprise, err := utils.IsEnterprise(ctx, cli)
			Expect(err).NotTo(HaveOccurred(), "Failed to check enterprise status")
			if !isEnterprise {
				Fail("Ingress Gateway Dashboard tests require Calico Enterprise")
			}

			gatewayAPIName = "tigera-secure"

			// Set up port-forwarding to manager.
			pf = elasticsearch.PortForward()

			// HTTP client with proper TLS CA verification
			caCert := utils.GetTigeraCACert(ctx, f)
			httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs: caCert,
			}}}

			// Ensure the port-forward is ready before proceeding.
			kubectl := utils.Kubectl{}
			kubectl.WaitForPortForward(httpClient, config.ManagerURL())

			// Create network-admin service account and get token for dashboard API access.
			// The utility creates the SA/CRB and registers DeferCleanup automatically.
			token, err = utils.NetworkAdminToken(ctx, f.ClientSet, f.Namespace.Name)
			Expect(err).NotTo(HaveOccurred(), "Failed to create network admin token")

			// Initialize connection tester
			connTester = conncheck.NewConnectionTester(f)

			DeferCleanup(func() {
				// Stop port-forwarding
				if pf != nil {
					pf.Stop()
				}

				// Cleanup Gateway API resources
				deleteGatewayAPICR(context.Background(), cli, gatewayAPIName)

				// Wait for tigera-gateway namespace to be deleted
				err := framework.WaitForNamespacesDeleted(context.TODO(), f.ClientSet, []string{"tigera-gateway"}, 5*time.Minute)
				if err != nil {
					logrus.WithError(err).Warn("tigera-gateway namespace may not have been fully deleted")
				}
			})
		})

		// This Context uses Ordered to ensure BeforeAll runs before any It blocks.
		// BeforeAll is needed because we deploy infrastructure (Gateway, HTTPRoutes, backend)
		// once and then run multiple test cases against the same L7 log data.
		Context("L7 logs with gateway metadata", Ordered, func() {
			BeforeAll(func() {
				ctx := context.Background()

				By("Setting L7 logs flush interval to 5 seconds")
				originalFelixConfig := v3.NewFelixConfiguration()
				err := cli.Get(ctx, types.NamespacedName{Name: "default"}, originalFelixConfig)
				Expect(err).NotTo(HaveOccurred())

				testFelixConfig := originalFelixConfig.DeepCopy()
				testFelixConfig.Spec.L7LogsFlushInterval = &metav1.Duration{Duration: 5 * time.Second}
				err = cli.Update(ctx, testFelixConfig)
				Expect(err).NotTo(HaveOccurred())

				DeferCleanup(func() {
					err := cli.Get(ctx, types.NamespacedName{Name: "default"}, testFelixConfig)
					Expect(err).NotTo(HaveOccurred())
					originalFelixConfig.ResourceVersion = testFelixConfig.ResourceVersion
					err = cli.Update(ctx, originalFelixConfig)
					Expect(err).NotTo(HaveOccurred())
				})

				By("Enabling Gateway API support")
				createGatewayAPICR(ctx, cli, gatewayAPIName)

				By("Waiting for GatewayClass CRD")
				Eventually(func() bool {
					return utils.GatewayAPIInstalled(f.ClientSet.Discovery())
				}, 30*time.Second, 1*time.Second).Should(BeTrue())

				// Create a separate namespace for the backend service to test cross-namespace routing.
				// The Gateway lives in f.Namespace, the backend in backendNS, and the HTTPRoute
				// references the backend across namespaces using a ReferenceGrant.
				By("Creating backend namespace")
				backendNS = &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: f.Namespace.Name + "-backend"},
				}
				_, err = f.ClientSet.CoreV1().Namespaces().Create(ctx, backendNS, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(func() {
					_ = f.ClientSet.CoreV1().Namespaces().Delete(ctx, backendNS.Name, metav1.DeleteOptions{})
				})

				By("Deploying echo server using conncheck")
				echoServer := conncheck.NewServer("echoserver", backendNS,
					conncheck.WithPorts(8888),
				)
				connTester.AddServer(echoServer)

				By("Deploying client pod using conncheck")
				clientPod := conncheck.NewClient("test-client", f.Namespace)
				connTester.AddClient(clientPod)

				connTester.Deploy()
				DeferCleanup(connTester.Stop)

				By("Deploying Gateway")
				gateway := newGateway("ingress-gw", f.Namespace.Name)
				err = cli.Create(ctx, gateway)
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(func() {
					if err := cli.Delete(context.Background(), gateway); err != nil {
						logrus.WithError(err).Warn("Failed to delete Gateway")
					}
				})

				By("Deploying HTTPRoute")
				httpRoute := newHTTPRoute("backend-route", f.Namespace.Name, backendNS.Name)
				err = cli.Create(ctx, httpRoute)
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(func() {
					if err := cli.Delete(context.Background(), httpRoute); err != nil {
						logrus.WithError(err).Warn("Failed to delete HTTPRoute")
					}
				})

				By("Deploying ReferenceGrant")
				refGrant := newReferenceGrant("allow-gateway-to-backend", backendNS.Name, f.Namespace.Name)
				err = cli.Create(ctx, refGrant)
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(func() {
					if err := cli.Delete(context.Background(), refGrant); err != nil {
						logrus.WithError(err).Warn("Failed to delete ReferenceGrant")
					}
				})

				By("Finding Gateway service cluster IP")
				Eventually(func() error {
					svcList, err := f.ClientSet.CoreV1().Services("tigera-gateway").List(ctx, metav1.ListOptions{})
					if err != nil {
						return err
					}
					for _, svc := range svcList.Items {
						if svc.Name == "envoy-gateway" {
							continue
						}
						if svc.Spec.ClusterIP != "" {
							clusterIP = svc.Spec.ClusterIP
							return nil
						}
					}
					return fmt.Errorf("couldn't find Service in tigera-gateway with a cluster IP")
				}, 30*time.Second, 1*time.Second).ShouldNot(HaveOccurred())
				logrus.Infof("Gateway cluster IP: %s", clusterIP)

				By("Generating L7 traffic through the gateway")
				gwTarget := conncheck.NewTarget(clusterIP, conncheck.TypeClusterIP, conncheck.HTTP,
					conncheck.WithHTTP("GET", "/backend/test", nil))
				for i := range 10 {
					_, err := connTester.Connect(clientPod, gwTarget)
					if err != nil {
						logrus.WithError(err).Warnf("HTTP request attempt %d failed", i)
					}
					time.Sleep(100 * time.Millisecond)
				}
				// Note: L7 logs are flushed asynchronously. The Eventually clauses in the
				// test cases will handle waiting for logs to appear in the dashboard API.
			})

			It("should return L7 logs with gateway_route_type field populated", func() {
				queryReq := dashclient.QueryRequest{
					CollectionName: dashclient.CollectionName("l7"),
					MaxDocs:        ptr.To(100),
					GroupBys: []dashclient.QueryRequestGroup{
						{FieldName: "gateway_route_type"},
					},
					Filters: []dashclient.QueryRequestFilter{
						{Criterion: dashclient.QueryRequestFilterCriterion{Type: dashclient.CriterionTypeRelativeTimeRange, GTE: "PT30M", LTE: "PT0M"}},
					},
				}

				var resp dashclient.QueryResponse
				Eventually(func() error {
					resp = queryDashboardsAPI(httpClient, pf.ManagerURL, token, queryReq)
					if len(resp.GroupValues) == 0 {
						return fmt.Errorf("no group values returned")
					}
					for _, gv := range resp.GroupValues {
						if gv.Key != "" && gv.Key != "-" {
							return nil
						}
					}
					return fmt.Errorf("no valid gateway_route_type values found")
				}, 30*time.Second, 2*time.Second).Should(Succeed(), "Expected L7 logs with gateway_route_type field populated")

				foundHTTPRoute := false
				for _, gv := range resp.GroupValues {
					logrus.Infof("Found gateway_route_type: %s", gv.Key)
					Expect(gv.Key).NotTo(BeEmpty(), "gateway_route_type should not be empty")
					Expect(gv.Key).NotTo(Equal("-"), "gateway_route_type should not be '-'")
					if gv.Key == "http" {
						foundHTTPRoute = true
					}
				}
				Expect(foundHTTPRoute).To(BeTrue(), "Expected to find at least one HTTP route type")
			})

			It("should return L7 logs with dest_service_name resolved from endpoint IP", func() {
				queryReq := dashclient.QueryRequest{
					CollectionName: dashclient.CollectionName("l7"),
					MaxDocs:        ptr.To(100),
					GroupBys: []dashclient.QueryRequestGroup{
						{FieldName: "dest_service_name"},
						{FieldName: "dest_service_namespace"},
					},
					Filters: []dashclient.QueryRequestFilter{
						{Criterion: dashclient.QueryRequestFilterCriterion{Type: dashclient.CriterionTypeRelativeTimeRange, GTE: "PT30M", LTE: "PT0M"}},
					},
				}

				var resp dashclient.QueryResponse
				Eventually(func() error {
					resp = queryDashboardsAPI(httpClient, pf.ManagerURL, token, queryReq)
					if len(resp.GroupValues) == 0 {
						return fmt.Errorf("no group values returned")
					}
					for _, gv := range resp.GroupValues {
						if gv.Key != "" && gv.Key != "-" {
							return nil
						}
					}
					return fmt.Errorf("no valid dest_service_name values found")
				}, 30*time.Second, 2*time.Second).Should(Succeed(), "Expected L7 logs with dest_service_name populated")

				for _, gv := range resp.GroupValues {
					logrus.Infof("Found dest_service_name: %s", gv.Key)
					if strings.Contains(gv.Key, "echoserver") {
						Expect(gv.Key).To(ContainSubstring("echoserver"), "dest_service_name should contain 'echoserver'")
					}
				}
			})

			It("should return L7 logs with gateway metadata fields", func() {
				queryReq := dashclient.QueryRequest{
					CollectionName: dashclient.CollectionName("l7"),
					MaxDocs:        ptr.To(100),
					GroupBys: []dashclient.QueryRequestGroup{
						{FieldName: "gateway_namespace"},
						{FieldName: "gateway_name"},
						{FieldName: "gateway_listener_full_name"},
					},
					Filters: []dashclient.QueryRequestFilter{
						{Criterion: dashclient.QueryRequestFilterCriterion{Type: dashclient.CriterionTypeRelativeTimeRange, GTE: "PT30M", LTE: "PT0M"}},
					},
				}

				var resp dashclient.QueryResponse
				Eventually(func() error {
					resp = queryDashboardsAPI(httpClient, pf.ManagerURL, token, queryReq)
					if len(resp.GroupValues) == 0 {
						return fmt.Errorf("no group values returned")
					}
					// With nested groupBys, check the first level for gateway_namespace
					for _, gv := range resp.GroupValues {
						if gv.Key != "" && gv.Key != "-" {
							return nil
						}
					}
					return fmt.Errorf("no valid gateway metadata values found")
				}, 30*time.Second, 2*time.Second).Should(Succeed(), "Expected L7 logs with gateway metadata fields")

				for _, gv := range resp.GroupValues {
					if gv.Key != "" {
						logrus.Infof("Found gateway_namespace: %s", gv.Key)
						Expect(gv.Key).NotTo(Equal("-"), "gateway_namespace should not be '-'")
					}
				}
			})

			It("should support Traffic Performance groupBy pattern", func() {
				queryReq := dashclient.QueryRequest{
					CollectionName: dashclient.CollectionName("l7"),
					MaxDocs:        ptr.To(100),
					GroupBys: []dashclient.QueryRequestGroup{
						{FieldName: "start_time"},
						{FieldName: "gateway_namespace"},
						{FieldName: "gateway_name"},
						{FieldName: "gateway_listener_full_name"},
					},
					Filters: []dashclient.QueryRequestFilter{
						{Criterion: dashclient.QueryRequestFilterCriterion{Type: dashclient.CriterionTypeRelativeTimeRange, GTE: "PT30M", LTE: "PT0M"}},
					},
				}

				var resp dashclient.QueryResponse
				Eventually(func() error {
					resp = queryDashboardsAPI(httpClient, pf.ManagerURL, token, queryReq)
					if len(resp.GroupValues) == 0 {
						return fmt.Errorf("no group values returned")
					}
					return nil
				}, 30*time.Second, 2*time.Second).Should(Succeed(), "Expected Traffic Performance groupBy query to succeed")

				logrus.Infof("Traffic Performance query returned %d group values", len(resp.GroupValues))
			})
		})
	},
)

// createGatewayAPICR creates the GatewayAPI custom resource using the controller-runtime client.
func createGatewayAPICR(ctx context.Context, cli client.Client, name string) {
	gatewayAPI := &operatorv1.GatewayAPI{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		// Spec is optional - empty spec uses defaults (tigera-gateway-class)
	}
	err := cli.Create(ctx, gatewayAPI)
	Expect(err).NotTo(HaveOccurred(), "Failed to create GatewayAPI CR")
}

// deleteGatewayAPICR deletes the GatewayAPI custom resource.
func deleteGatewayAPICR(ctx context.Context, cli client.Client, name string) {
	gatewayAPI := &operatorv1.GatewayAPI{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	if err := cli.Delete(ctx, gatewayAPI); err != nil {
		logrus.WithError(err).Warn("Failed to delete GatewayAPI CR")
	}
}

// newGateway creates a Gateway resource.
func newGateway(name, namespace string) *gatewayv1.Gateway {
	return &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "tigera-gateway-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Protocol: gatewayv1.HTTPProtocolType,
					Port:     80,
				},
			},
		},
	}
}

// newHTTPRoute creates an HTTPRoute resource.
func newHTTPRoute(name, namespace, backendNamespace string) *gatewayv1.HTTPRoute {
	backendNS := gatewayv1.Namespace(backendNamespace)
	port := gatewayv1.PortNumber(8888)
	pathType := gatewayv1.PathMatchPathPrefix
	pathValue := "/backend"
	weight := int32(1)

	return &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "ingress-gw"},
				},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					Matches: []gatewayv1.HTTPRouteMatch{
						{
							Path: &gatewayv1.HTTPPathMatch{
								Type:  &pathType,
								Value: &pathValue,
							},
						},
					},
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name:      "svc-echoserver",
									Namespace: &backendNS,
									Port:      &port,
								},
								Weight: &weight,
							},
						},
					},
				},
			},
		},
	}
}

// newReferenceGrant creates a ReferenceGrant resource.
func newReferenceGrant(name, namespace, fromNamespace string) *gatewayv1beta1.ReferenceGrant {
	return &gatewayv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: gatewayv1beta1.ReferenceGrantSpec{
			From: []gatewayv1beta1.ReferenceGrantFrom{
				{
					Group:     gatewayv1beta1.Group("gateway.networking.k8s.io"),
					Kind:      gatewayv1beta1.Kind("HTTPRoute"),
					Namespace: gatewayv1beta1.Namespace(fromNamespace),
				},
			},
			To: []gatewayv1beta1.ReferenceGrantTo{
				{
					Group: "",
					Kind:  "Service",
				},
			},
		},
	}
}

// queryDashboardsAPI sends a query to the dashboards service API.
func queryDashboardsAPI(httpClient *http.Client, managerURL, token string, req dashclient.QueryRequest) dashclient.QueryResponse {
	bodyBytes, err := json.Marshal(req)
	Expect(err).NotTo(HaveOccurred())

	url := fmt.Sprintf("%s/dashboards/api/query", managerURL)

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(bodyBytes))
	Expect(err).NotTo(HaveOccurred())
	httpReq.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	httpReq.Header.Add("Content-Type", "application/json")

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		logrus.WithError(err).Warn("Dashboard API request failed")
		return dashclient.QueryResponse{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		logrus.Warnf("Dashboard API returned status %d: %s", resp.StatusCode, string(bodyBytes))
		return dashclient.QueryResponse{}
	}

	var queryResp dashclient.QueryResponse
	err = json.NewDecoder(resp.Body).Decode(&queryResp)
	if err != nil {
		logrus.WithError(err).Warn("Failed to decode dashboard API response")
		return dashclient.QueryResponse{}
	}

	return queryResp
}
