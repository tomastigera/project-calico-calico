// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

package server_test

import (
	"context"
	"crypto/md5"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	clientv3 "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	"golang.org/x/net/http2"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/projectcalico/calico/apiserver/pkg/authentication"
	"github.com/projectcalico/calico/lib/std/chanutil"
	"github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/auth/testing"
	"github.com/projectcalico/calico/voltron/internal/pkg/bootstrap"
	voltronconfig "github.com/projectcalico/calico/voltron/internal/pkg/config"
	"github.com/projectcalico/calico/voltron/internal/pkg/proxy"
	"github.com/projectcalico/calico/voltron/internal/pkg/regex"
	"github.com/projectcalico/calico/voltron/internal/pkg/server"
	"github.com/projectcalico/calico/voltron/internal/pkg/server/accesslog"
	accesslogtest "github.com/projectcalico/calico/voltron/internal/pkg/server/accesslog/test"
	"github.com/projectcalico/calico/voltron/internal/pkg/test"
	"github.com/projectcalico/calico/voltron/internal/pkg/utils"
	mockwatch "github.com/projectcalico/calico/voltron/pkg/thirdpartymocks/k8s.io/apimachinery/pkg/watch"
	mockk8sclient "github.com/projectcalico/calico/voltron/pkg/thirdpartymocks/sigs.k8s.io/controller-runtime/pkg/client"
	"github.com/projectcalico/calico/voltron/pkg/tunnel"
)

type MockManagedClusterQuerierFactory struct{}

func (f *MockManagedClusterQuerierFactory) New(dialFunc func(network, addr string, cfg *tls.Config) (net.Conn, error)) (server.ManagedClusterQuerier, error) {
	return &MockManagedClusterDataQuerier{
		dialFunc: dialFunc,
	}, nil
}

type MockManagedClusterDataQuerier struct {
	dialFunc func(network, addr string, cfg *tls.Config) (net.Conn, error)
}

func (mc *MockManagedClusterDataQuerier) GetVersion() (string, error) {
	return "v3.24", nil
}

const (
	k8sIssuer           = "kubernetes/serviceaccount"
	managerSAAuthHeader = "Bearer tigera-manager-token"
)

var (
	clusterA = "clusterA"
	clusterB = "clusterB"
	clusterC = "clusterC"
	config   = &rest.Config{BearerToken: "tigera-manager-token"}

	// Tokens issued by k8s.
	janeBearerToken = testing.NewFakeJWT(k8sIssuer, "jane@example.io")
	bobBearerToken  = testing.NewFakeJWT(k8sIssuer, "bob@example.io")
	janeUserInfo    = &user.DefaultInfo{Name: "jane@example.io", Groups: []string{"developers"}}
	mockFactory     = &MockManagedClusterQuerierFactory{}
)

type k8sClient struct {
	kubernetes.Interface
	clientv3.ProjectcalicoV3Interface
}

func describe(name string, testFn func(string)) bool {
	Describe(name+" cluster-scoped", func() { testFn("") })
	Describe(name+" namespace-scoped", func() { testFn("resource-ns") })
	return true
}

var _ = describe("Server Proxy to tunnel", func(clusterNS string) {
	var (
		ctx               context.Context
		ctxCancel         func()
		mockAuthenticator *auth.MockJWTAuth
		mockAuthorizer    *auth.MockRBACAuthorizer

		fakeK8s    *k8sfake.Clientset
		k8sAPI     bootstrap.K8sClient
		fakeClient ctrlclient.WithWatch

		voltronTunnelCert      *x509.Certificate
		voltronTunnelTLSCert   tls.Certificate
		voltronTunnelPrivKey   *rsa.PrivateKey
		voltronExtHttpsCert    *x509.Certificate
		voltronExtHttpsPrivKey *rsa.PrivateKey
		voltronIntHttpsCert    *x509.Certificate
		voltronIntHttpsPrivKey *rsa.PrivateKey
		voltronTunnelCAs       *x509.CertPool
		voltronHttpsCAs        *x509.CertPool

		managedClusterA, managedClusterB, managedClusterC                         *v3.ManagedCluster
		clusterATLSCert, clusterBTLSCert, clusterCTLSCert                         tls.Certificate
		clusterATunnelTLSConfig, clusterBTunnelTLSConfig, clusterCTunnelTLSConfig *tls.Config
	)

	BeforeEach(func() {
		var err error
		ctx, ctxCancel = context.WithCancel(context.Background())
		mockAuthenticator = new(auth.MockJWTAuth)
		mockAuthorizer = new(auth.MockRBACAuthorizer)

		fakeK8s = k8sfake.NewClientset()
		k8sAPI = &k8sClient{
			Interface:                fakeK8s,
			ProjectcalicoV3Interface: fake.NewSimpleClientset().ProjectcalicoV3(),
		}

		scheme := kscheme.Scheme
		Expect(v3.AddToScheme(scheme)).NotTo(HaveOccurred())
		fakeClient = fakeclient.NewClientBuilder().WithScheme(scheme).Build()

		voltronTunnelCertTemplate := test.CreateCACertificateTemplate("voltron")
		voltronTunnelPrivKey, voltronTunnelCert, err = test.CreateCertPair(voltronTunnelCertTemplate, nil, nil)
		Expect(err).ShouldNot(HaveOccurred())

		// convert x509 cert to tls cert
		voltronTunnelTLSCert, err = test.X509CertToTLSCert(voltronTunnelCert, voltronTunnelPrivKey)
		Expect(err).NotTo(HaveOccurred())

		voltronExtHttpCertTemplate := test.CreateServerCertificateTemplate("localhost")
		voltronExtHttpsPrivKey, voltronExtHttpsCert, err = test.CreateCertPair(voltronExtHttpCertTemplate, nil, nil)
		Expect(err).ShouldNot(HaveOccurred())

		voltronIntHttpCertTemplate := test.CreateServerCertificateTemplate("tigera-manager.tigera-manager.svc")
		voltronIntHttpsPrivKey, voltronIntHttpsCert, err = test.CreateCertPair(voltronIntHttpCertTemplate, nil, nil)
		Expect(err).ShouldNot(HaveOccurred())

		voltronTunnelCAs = x509.NewCertPool()
		voltronTunnelCAs.AppendCertsFromPEM(test.CertToPemBytes(voltronTunnelCert))

		voltronHttpsCAs = x509.NewCertPool()
		voltronHttpsCAs.AppendCertsFromPEM(test.CertToPemBytes(voltronExtHttpsCert))
		voltronHttpsCAs.AppendCertsFromPEM(test.CertToPemBytes(voltronIntHttpsCert))

		clusterACertTemplate := test.CreateClientCertificateTemplate(clusterA, "localhost")
		clusterAPrivKey, clusterACert, err := test.CreateCertPair(clusterACertTemplate, voltronTunnelCert, voltronTunnelPrivKey)
		Expect(err).ShouldNot(HaveOccurred())

		clusterATLSCert, err = test.X509CertToTLSCert(clusterACert, clusterAPrivKey)
		Expect(err).NotTo(HaveOccurred())

		managedClusterA = &v3.ManagedCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:        clusterA,
				Namespace:   clusterNS,
				Annotations: map[string]string{server.AnnotationActiveCertificateFingerprint: utils.GenerateFingerprint(clusterACert)},
			},
			Spec: v3.ManagedClusterSpec{
				Certificate: test.CertToPemBytes(clusterACert),
			},
		}

		clusterATunnelTLSConfig = &tls.Config{Certificates: []tls.Certificate{clusterATLSCert}, RootCAs: voltronTunnelCAs}

		clusterBCertTemplate := test.CreateClientCertificateTemplate(clusterB, "localhost")
		clusterBPrivKey, clusterBCert, err := test.CreateCertPair(clusterBCertTemplate, voltronTunnelCert, voltronTunnelPrivKey)
		Expect(err).ShouldNot(HaveOccurred())

		clusterBTLSCert, err = test.X509CertToTLSCert(clusterBCert, clusterBPrivKey)
		Expect(err).NotTo(HaveOccurred())

		managedClusterB = &v3.ManagedCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:        clusterB,
				Namespace:   clusterNS,
				Annotations: map[string]string{server.AnnotationActiveCertificateFingerprint: utils.GenerateFingerprint(clusterBCert)},
			},
			Spec: v3.ManagedClusterSpec{
				Certificate: test.CertToPemBytes(clusterBCert),
			},
		}

		clusterBTunnelTLSConfig = &tls.Config{Certificates: []tls.Certificate{clusterBTLSCert}, RootCAs: voltronTunnelCAs}

		clusterCCertTemplate := test.CreateClientCertificateTemplate(clusterC, "localhost")
		clusterCPrivKey, clusterCCert, err := test.CreateCertPair(clusterCCertTemplate, voltronTunnelCert, voltronTunnelPrivKey)
		Expect(err).NotTo(HaveOccurred())

		managedClusterC = &v3.ManagedCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterC,
				Namespace: clusterNS,
			},
			Spec: v3.ManagedClusterSpec{
				Certificate: test.CertToPemBytes(clusterCCert),
			},
		}

		clusterCTLSCert, err = test.X509CertToTLSCert(clusterCCert, clusterCPrivKey)
		Expect(err).NotTo(HaveOccurred())

		clusterCTunnelTLSConfig = &tls.Config{Certificates: []tls.Certificate{clusterCTLSCert}, RootCAs: voltronTunnelCAs}
	})

	JustAfterEach(func() {
		ctxCancel()
	})

	It("should fail to start the server when the paths to the external credentials are invalid", func() {
		vfg := &voltronconfig.Config{TenantNamespace: clusterNS}
		_, err := server.New(
			fakeClient,
			config,
			*vfg,
			mockAuthenticator,
			mockFactory,
			server.WithExternalCredFiles("dog/gopher.crt", "dog/gopher.key"),
			server.WithInternalCredFiles("dog/gopher.crt", "dog/gopher.key"),
		)
		Expect(err).To(HaveOccurred())
	})

	Context("Proxying requests over the tunnel", func() {
		var (
			mockClient *mockk8sclient.WithWatch
			events     chan watch.Event

			voltronServerAddr, voltronTunnelAddr string
			srvWg                                *sync.WaitGroup
			srv                                  *server.Server
			defaultServer                        *httptest.Server
		)

		BeforeEach(func() {
			mockAuthenticator.On("Authenticate", mock.Anything).Return(janeUserInfo, 0, nil)
			mockAuthorizer.On("Authorize", mock.Anything, mock.Anything, mock.Anything).Return(true, nil)

			mockClient = new(mockk8sclient.WithWatch)
			mockClient.EXPECT().List(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(setList("1")).Once()

			var watchInf *mockwatch.Interface
			watchInf, events = newWatchInf()
			mockClient.EXPECT().Watch(mock.Anything, mock.Anything, mock.Anything).Return(watchInf, nil).Once()

			defaultServer = httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set(authentication.AuthorizationHeader, r.Header.Get(authentication.AuthorizationHeader))
					w.Header().Set(authnv1.ImpersonateUserHeader, r.Header.Get(authnv1.ImpersonateUserHeader))
					w.Header().Set(authnv1.ImpersonateGroupHeader, r.Header.Get(authnv1.ImpersonateGroupHeader))
				}))

			defaultURL, err := url.Parse(defaultServer.URL)
			Expect(err).NotTo(HaveOccurred())

			defaultProxy, err := proxy.New([]proxy.Target{
				{Path: "/", Dest: defaultURL}, {Path: "/compliance/", Dest: defaultURL},
			})
			Expect(err).NotTo(HaveOccurred())

			tunnelTargetWhitelist, err := regex.CompileRegexStrings([]string{`^/$`, `^/some/path$`})
			Expect(err).ShouldNot(HaveOccurred())

			k8sTargets, err := regex.CompileRegexStrings([]string{`^/api/?`, `^/apis/?`})
			Expect(err).ShouldNot(HaveOccurred())

			managementBackendTargets, err := regex.CompileRegexStrings([]string{`^/apis/projectcalico.org/v3/authorizationreviews$`})
			Expect(err).ShouldNot(HaveOccurred())

			srv, voltronServerAddr, _, voltronTunnelAddr, srvWg = createAndStartServer(
				mockClient, config, mockAuthenticator, clusterNS,
				server.WithTunnelSigningCreds(voltronTunnelCert),
				server.WithTunnelCert(voltronTunnelTLSCert),
				server.WithExternalCreds(test.CertToPemBytes(voltronExtHttpsCert), test.KeyToPemBytes(voltronExtHttpsPrivKey)),
				server.WithInternalCreds(test.CertToPemBytes(voltronIntHttpsCert), test.KeyToPemBytes(voltronIntHttpsPrivKey)),
				server.WithDefaultProxy(defaultProxy),
				server.WithKubernetesAPITargets(k8sTargets),
				server.WithTunnelTargetWhitelist(tunnelTargetWhitelist),
				server.WithManagementBackendTargets(managementBackendTargets),
				server.WithCheckManagedClusterAuthorizationBeforeProxy(true, 0, mockAuthorizer),
			)
		})

		AfterEach(func() {
			Expect(srv.Close()).NotTo(HaveOccurred())
			defaultServer.Close()
			srvWg.Wait()
			close(events)
		})

		It("should not proxy anywhere without valid headers", func() {
			resp, err := http.Get("http://" + voltronServerAddr + "/")
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(400))
		})

		It("Should reject requests to clusters that don't exist", func() {
			req, err := http.NewRequest("GET", "http://"+voltronServerAddr+"/", nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Add(utils.ClusterHeaderField, "zzzzzzz")
			resp, err := http.DefaultClient.Do(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(400))
		})

		It("Should not proxy anywhere - multiple headers", func() {
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         "localhost",
				},
			}
			client := &http.Client{Transport: tr}
			req, err := http.NewRequest("GET", "https://"+voltronServerAddr+"/", nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Add(utils.ClusterHeaderField, clusterA)
			req.Header.Add(utils.ClusterHeaderField, "helloworld")
			resp, err := client.Do(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(400))
		})

		It("should not be able to proxy to a cluster without a tunnel", func() {
			mockClient.EXPECT().
				Get(mock.Anything, types.NamespacedName{Name: clusterA, Namespace: clusterNS}, mock.Anything).RunAndReturn(setGet(managedClusterA))
			mockClient.EXPECT().Update(mock.Anything, mock.Anything, mock.Anything).Return(nil)

			err := chanutil.WriteWithDeadline(ctx, events, watch.Event{
				Type:   watch.Added,
				Object: managedClusterA,
			}, 2*time.Second)
			Expect(err).NotTo(HaveOccurred())
			clientHelloReq(voltronServerAddr, clusterA, 400)
		})

		It("Should proxy to default if no header", func() {
			resp, err := http.Get(defaultServer.URL)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(200))
		})

		It("Should proxy to default even with header, if request path matches one of bypass tunnel targets", func() {
			req, err := http.NewRequest(
				"GET",
				"https://"+voltronServerAddr+"/compliance/reports",
				strings.NewReader("HELLO"),
			)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Add(utils.ClusterHeaderField, clusterA)
			req.Header.Set(authentication.AuthorizationHeader, janeBearerToken.BearerTokenHeader())

			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}
			resp, err := httpClient.Do(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(200))
		})

		It("Should swap the auth header and impersonate the user for requests to k8s (a)api server", func() {
			req, err := http.NewRequest("GET", fmt.Sprintf("https://%s%s", voltronServerAddr, "/api/v1/namespaces"), nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set(authentication.AuthorizationHeader, janeBearerToken.BearerTokenHeader())

			resp, err := configureHTTPSClient().Do(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(200))
			Expect(resp.Header.Get(authentication.AuthorizationHeader)).To(Equal(managerSAAuthHeader))
			Expect(resp.Header.Get(authnv1.ImpersonateUserHeader)).To(Equal(janeBearerToken.UserName()))
			Expect(resp.Header.Get(authnv1.ImpersonateGroupHeader)).To(Equal("developers"))
		})

		It("should not overwrite impersonation headers if they have already been configured by client", func() {
			req, err := http.NewRequest("GET", fmt.Sprintf("https://%s%s", voltronServerAddr, "/api/v1/namespaces"), nil)
			Expect(err).NotTo(HaveOccurred())

			impersonatedUser := "impersonated-user"
			impersonatedGroup := "impersonated-group"

			req.Header.Set(authentication.AuthorizationHeader, janeBearerToken.BearerTokenHeader())
			req.Header.Set(authnv1.ImpersonateUserHeader, impersonatedUser)
			req.Header.Set(authnv1.ImpersonateGroupHeader, impersonatedGroup)

			resp, err := configureHTTPSClient().Do(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(200))
			Expect(resp.Header.Get(authentication.AuthorizationHeader)).To(Equal(managerSAAuthHeader))
			Expect(resp.Header.Get(authnv1.ImpersonateUserHeader)).To(Equal(impersonatedUser))
			Expect(resp.Header.Get(authnv1.ImpersonateGroupHeader)).To(Equal(impersonatedGroup))
		})

		It("should not add impersonation headers for management backend targets", func() {
			req, err := http.NewRequest("POST", fmt.Sprintf("https://%s%s", voltronServerAddr, "/apis/projectcalico.org/v3/authorizationreviews"), nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set(authentication.AuthorizationHeader, janeBearerToken.BearerTokenHeader())

			resp, err := configureHTTPSClient().Do(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(200))
			Expect(resp.Header.Get(authnv1.ImpersonateUserHeader)).To(BeEmpty())
			Expect(resp.Header.Get(authnv1.ImpersonateGroupHeader)).To(BeEmpty())
		})

		Context("A single cluster is registered", func() {
			var (
				clusterAConnected chan struct{}
			)

			BeforeEach(func() {
				clusterAConnected = make(chan struct{})
				closeOnce := sync.OnceFunc(func() { close(clusterAConnected) })

				mockClient.EXPECT().
					Get(mock.Anything, types.NamespacedName{Name: clusterA, Namespace: clusterNS}, mock.Anything).RunAndReturn(setGet(managedClusterA))

				mockClient.EXPECT().
					Update(mock.Anything, mock.MatchedBy(func(obj *v3.ManagedCluster) bool {
						if obj.Name == clusterA {
							closeOnce()
							return true
						}

						return false
					}), mock.Anything).Return(nil)

				err := chanutil.WriteWithDeadline(ctx, events, watch.Event{
					Type:   watch.Added,
					Object: managedClusterA,
				}, 2*time.Second)
				Expect(err).ShouldNot(HaveOccurred())
			})

			It("should not send requests if not authorized on that managed cluster", func() {
				// Reset the expected calls so we can ensure false is returned on the authorize call.
				mockAuthorizer.ExpectedCalls = nil

				mockAuthorizer.On("Authorize", mock.Anything, mock.Anything, mock.Anything).Return(false, nil)
				resp := clientHelloReq(voltronServerAddr, clusterA, http.StatusForbidden)
				bits, err := io.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(bits)).To(Equal("not authorized for managed cluster\n"))
			})

			It("can send requests from the server to the cluster", func() {
				clusterATunnel, err := tunnel.DialTLS(voltronTunnelAddr, clusterATunnelTLSConfig, 5*time.Second, nil)
				Expect(err).NotTo(HaveOccurred())

				_, err = chanutil.ReadWithDeadline(ctx, clusterAConnected, 5*time.Second)
				Expect(err).Should(Equal(chanutil.ErrChannelClosed))

				reqAChan := startMgdClusterService(ctx, clusterATunnel, clusterATLSCert)

				cli := &http.Client{
					Transport: &http2.Transport{
						TLSClientConfig: &tls.Config{
							NextProtos: []string{"h2"}, RootCAs: voltronHttpsCAs, ServerName: "localhost",
						},
					},
				}

				sendReqToManagedCluster(cli, voltronServerAddr, clusterA, "HELLO")

				body, err := chanutil.ReadWithDeadline(ctx, reqAChan, 2*time.Second)
				Expect(err).NotTo(HaveOccurred())
				Expect(body).To(Equal("HELLO"))

				By("testing that the tunnel is closed when the cluster is deleted")
				err = chanutil.WriteWithDeadline(ctx, events, watch.Event{
					Type:   watch.Deleted,
					Object: managedClusterA,
				}, 2*time.Second)
				Expect(err).ShouldNot(HaveOccurred())

				clusterATunnel, err = tunnel.DialTLS(voltronTunnelAddr, &tls.Config{
					Certificates: []tls.Certificate{clusterATLSCert}, RootCAs: voltronTunnelCAs,
				}, 5*time.Second, nil)
				Expect(err).NotTo(HaveOccurred())
				Eventually(clusterATunnel.CloseChan()).Should(BeClosed())
			})

			Context("A second cluster is registered", func() {
				var (
					clusterBConnected chan struct{}
				)

				BeforeEach(func() {
					clusterBConnected = make(chan struct{})
					closeOnce := sync.OnceFunc(func() { close(clusterBConnected) })

					mockClient.EXPECT().
						Get(mock.Anything, types.NamespacedName{Name: clusterB, Namespace: clusterNS}, mock.Anything).RunAndReturn(setGet(managedClusterB))

					mockClient.EXPECT().
						Update(mock.Anything, mock.MatchedBy(func(obj *v3.ManagedCluster) bool {
							if obj.Name == clusterB {
								closeOnce()
								return true
							}

							return false
						}), mock.Anything).Return(nil)

					err := chanutil.WriteWithDeadline(ctx, events, watch.Event{
						Type: watch.Added, Object: managedClusterB,
					}, 2*time.Second)
					Expect(err).ShouldNot(HaveOccurred())
				})

				It("can send requests from the server to the second cluster", func() {
					clusterBTunnel, err := tunnel.DialTLS(voltronTunnelAddr, clusterBTunnelTLSConfig, 5*time.Second, nil)
					Expect(err).NotTo(HaveOccurred())

					_, err = chanutil.ReadWithDeadline(ctx, clusterBConnected, 5*time.Second)
					Expect(err).Should(Equal(chanutil.ErrChannelClosed))

					reqBChan := startMgdClusterService(ctx, clusterBTunnel, clusterATLSCert)

					cli := &http.Client{
						Transport: &http2.Transport{
							TLSClientConfig: &tls.Config{
								NextProtos: []string{"h2"}, RootCAs: voltronHttpsCAs, ServerName: "localhost",
							},
						},
					}

					sendReqToManagedCluster(cli, voltronServerAddr, clusterB, "HELLO")

					body, err := chanutil.ReadWithDeadline(ctx, reqBChan, 2*time.Second)
					Expect(err).NotTo(HaveOccurred())
					Expect(body).To(Equal("HELLO"))
				})

				It("should not be possible to open a two tunnels to the same cluster", func() {
					_, err := tunnel.DialTLS(voltronTunnelAddr, clusterBTunnelTLSConfig, 5*time.Second, nil)
					Expect(err).NotTo(HaveOccurred())

					tunB2, err := tunnel.DialTLS(voltronTunnelAddr, clusterBTunnelTLSConfig, 5*time.Second, nil)
					Expect(err).NotTo(HaveOccurred())

					_, err = tunB2.Accept()
					Expect(err).Should(HaveOccurred())
				})

				Context("A third cluster with certificate is registered", func() {
					It("can send requests from the server to the third cluster", func() {
						clusterCConnected := make(chan struct{})
						closeOnce := sync.OnceFunc(func() { close(clusterCConnected) })

						mockClient.EXPECT().
							Get(mock.Anything, types.NamespacedName{Name: clusterC, Namespace: clusterNS}, mock.Anything).RunAndReturn(setGet(managedClusterC))

						mockClient.EXPECT().
							Update(mock.Anything, mock.MatchedBy(func(obj *v3.ManagedCluster) bool {
								if obj.Name == clusterC {
									closeOnce()
									return true
								}
								return false
							}), mock.Anything).Return(nil)

						err := chanutil.WriteWithDeadline(ctx, events, watch.Event{
							Type: watch.Added, Object: managedClusterC,
						}, 2*time.Second)
						Expect(err).ShouldNot(HaveOccurred())

						// Wait for the cluster to be registered before dialing the tunnel.
						_, err = chanutil.ReadWithDeadline(ctx, clusterCConnected, 5*time.Second)
						Expect(err).Should(Equal(chanutil.ErrChannelClosed))

						clusterCTunnel, err := tunnel.DialTLS(voltronTunnelAddr, clusterCTunnelTLSConfig, 5*time.Second, nil)
						Expect(err).NotTo(HaveOccurred())

						reqCChan := startMgdClusterService(ctx, clusterCTunnel, clusterATLSCert)

						cli := &http.Client{
							Transport: &http2.Transport{
								TLSClientConfig: &tls.Config{
									NextProtos: []string{"h2"}, RootCAs: voltronHttpsCAs, ServerName: "localhost",
								},
							},
						}

						sendReqToManagedCluster(cli, voltronServerAddr, clusterC, "HELLO")

						body, err := chanutil.ReadWithDeadline(ctx, reqCChan, 2*time.Second)
						Expect(err).NotTo(HaveOccurred())
						Expect(body).To(Equal("HELLO"))
					})
				})
			})
		})

		Context("A resync is forced on the watch", func() {
			var (
				clusterATunnel, clusterBTunnel tunnel.Tunnel

				reqAChan, reqBChan chan string
			)

			BeforeEach(func() {
				clusterAConnected := make(chan struct{})
				closeAOnce := sync.OnceFunc(func() { close(clusterAConnected) })
				clusterBConnected := make(chan struct{})
				closeBOnce := sync.OnceFunc(func() { close(clusterBConnected) })

				mockClient.EXPECT().
					Get(mock.Anything, types.NamespacedName{Name: clusterA, Namespace: clusterNS}, mock.Anything).RunAndReturn(setGet(managedClusterA))

				mockClient.EXPECT().
					Get(mock.Anything, types.NamespacedName{Name: clusterB, Namespace: clusterNS}, mock.Anything).RunAndReturn(setGet(managedClusterB))

				mockClient.EXPECT().
					Update(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(
					func(ctx context.Context, obj ctrlclient.Object, opts ...ctrlclient.UpdateOption) error {
						if obj.(*v3.ManagedCluster).Name == clusterA {
							closeAOnce()
						}
						if obj.(*v3.ManagedCluster).Name == clusterB {
							closeBOnce()
						}
						return nil
					})

				err := chanutil.WriteWithDeadline(ctx, events, watch.Event{
					Type:   watch.Added,
					Object: managedClusterA,
				}, 2*time.Second)
				Expect(err).ShouldNot(HaveOccurred())

				err = chanutil.WriteWithDeadline(ctx, events, watch.Event{
					Type:   watch.Added,
					Object: managedClusterB,
				}, 2*time.Second)
				Expect(err).ShouldNot(HaveOccurred())

				clusterATunnel, err = tunnel.DialTLS(voltronTunnelAddr, clusterATunnelTLSConfig, 5*time.Second, nil)
				Expect(err).NotTo(HaveOccurred())

				_, err = chanutil.ReadWithDeadline(context.Background(), clusterAConnected, 5*time.Second)
				Expect(err).Should(Equal(chanutil.ErrChannelClosed))

				clusterBTunnel, err = tunnel.DialTLS(voltronTunnelAddr, clusterBTunnelTLSConfig, 5*time.Second, nil)
				Expect(err).NotTo(HaveOccurred())

				_, err = chanutil.ReadWithDeadline(context.Background(), clusterBConnected, 5*time.Second)
				Expect(err).Should(Equal(chanutil.ErrChannelClosed))

				cli := &http.Client{
					Transport: &http2.Transport{
						TLSClientConfig: &tls.Config{NextProtos: []string{"h2"}, RootCAs: voltronHttpsCAs, ServerName: "localhost"},
					},
				}

				reqAChan = startMgdClusterService(ctx, clusterATunnel, clusterATLSCert)
				reqBChan = startMgdClusterService(ctx, clusterBTunnel, clusterBTLSCert)

				// Verify that both managed clusters are connected and working properly before continuing with the test.
				sendReqToManagedCluster(cli, voltronServerAddr, clusterA, "HELLO A")
				sendReqToManagedCluster(cli, voltronServerAddr, clusterB, "HELLO B")

				body, err := chanutil.ReadWithDeadline(ctx, reqAChan, 2*time.Second)
				Expect(err).NotTo(HaveOccurred())
				Expect(body).To(Equal("HELLO A"))

				body, err = chanutil.ReadWithDeadline(ctx, reqBChan, 2*time.Second)
				Expect(err).NotTo(HaveOccurred())
				Expect(body).To(Equal("HELLO B"))
			})

			It("stops the tunnel when no managed clusters are returned from the resync", func() {
				mockClient.EXPECT().
					Watch(mock.Anything, mock.Anything, mock.Anything).Return(nil, k8serrors.NewResourceExpired("resource expired")).Once()

				oldEventChan := events

				var watchInf *mockwatch.Interface
				watchInf, events = newWatchInf()

				mockClient.EXPECT().Watch(mock.Anything, mock.Anything, mock.Anything).Return(watchInf, nil).Once()
				mockClient.EXPECT().List(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(setList("1")).Once()

				close(oldEventChan)

				// Test that eventually the server closes both tunnels, this is the real test.
				Eventually(clusterATunnel.CloseChan(), 5*time.Second, 100*time.Millisecond).Should(BeClosed())
				Eventually(clusterBTunnel.CloseChan(), 5*time.Second, 100*time.Millisecond).Should(BeClosed())
			})

			It("stops the tunnel that doesn't appear in the resync list but not the other one", func() {
				mockClient.EXPECT().
					Watch(mock.Anything, mock.Anything, mock.Anything).Return(nil, k8serrors.NewResourceExpired("resource expired")).Once()

				oldEventChan := events

				var watchInf *mockwatch.Interface
				watchInf, events = newWatchInf()

				mockClient.EXPECT().Watch(mock.Anything, mock.Anything, mock.Anything).Return(watchInf, nil).Once()
				mockClient.EXPECT().
					List(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(setList("1", *managedClusterA)).Once()

				close(oldEventChan)

				// Test that the server closes tunnel B but not tunnel A.
				Eventually(clusterBTunnel.CloseChan(), 5*time.Second, 100*time.Millisecond).Should(BeClosed())

				cli := &http.Client{
					Transport: &http2.Transport{
						TLSClientConfig: &tls.Config{NextProtos: []string{"h2"}, RootCAs: voltronHttpsCAs, ServerName: "localhost"},
					},
				}

				Consistently(func() string {
					sendReqToManagedCluster(cli, voltronServerAddr, clusterA, "HELLO A AGAIN")
					body, err := chanutil.ReadWithDeadline(ctx, reqAChan, 2*time.Second)
					Expect(err).NotTo(HaveOccurred())
					return body
				}, 2*time.Second, 500*time.Millisecond).Should(Equal("HELLO A AGAIN"))
			})
		})
	})

	// Standalone mode: no tunnel support, mimics Enterprise standalone deployment.
	// Validates that managementBackendTargets bypass impersonation even when
	// no tunnel is configured.
	Context("Standalone mode (no tunnel)", func() {
		var (
			voltronServerAddr string
			srvWg             *sync.WaitGroup
			srv               *server.Server
			defaultServer     *httptest.Server
		)

		BeforeEach(func() {
			mockAuthenticator.On("Authenticate", mock.Anything).Return(janeUserInfo, 0, nil)

			defaultServer = httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set(authentication.AuthorizationHeader, r.Header.Get(authentication.AuthorizationHeader))
					w.Header().Set(authnv1.ImpersonateUserHeader, r.Header.Get(authnv1.ImpersonateUserHeader))
					w.Header().Set(authnv1.ImpersonateGroupHeader, r.Header.Get(authnv1.ImpersonateGroupHeader))
				}))

			defaultURL, err := url.Parse(defaultServer.URL)
			Expect(err).NotTo(HaveOccurred())

			defaultProxy, err := proxy.New([]proxy.Target{
				{Path: "/", Dest: defaultURL},
			})
			Expect(err).NotTo(HaveOccurred())

			k8sTargets, err := regex.CompileRegexStrings([]string{`^/api/?`, `^/apis/?`})
			Expect(err).ShouldNot(HaveOccurred())

			managementBackendTargets, err := regex.CompileRegexStrings([]string{`^/apis/projectcalico.org/v3/authorizationreviews$`})
			Expect(err).ShouldNot(HaveOccurred())

			// No WithTunnelSigningCreds, WithTunnelCert, or WithTunnelTargetWhitelist —
			// this mimics a standalone Enterprise deployment without MCM.
			srv, voltronServerAddr, _, _, srvWg = createAndStartServer(
				fakeClient,
				config,
				mockAuthenticator,
				clusterNS,
				server.WithExternalCreds(test.CertToPemBytes(voltronExtHttpsCert), test.KeyToPemBytes(voltronExtHttpsPrivKey)),
				server.WithInternalCreds(test.CertToPemBytes(voltronIntHttpsCert), test.KeyToPemBytes(voltronIntHttpsPrivKey)),
				server.WithDefaultProxy(defaultProxy),
				server.WithKubernetesAPITargets(k8sTargets),
				server.WithManagementBackendTargets(managementBackendTargets),
			)
		})

		AfterEach(func() {
			Expect(srv.Close()).NotTo(HaveOccurred())
			defaultServer.Close()
			srvWg.Wait()
		})

		It("should add impersonation headers for normal k8s API requests", func() {
			req, err := http.NewRequest("GET", fmt.Sprintf("https://%s%s", voltronServerAddr, "/apis/projectcalico.org/v3/tiers"), nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set(authentication.AuthorizationHeader, janeBearerToken.BearerTokenHeader())

			resp, err := configureHTTPSClient().Do(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(200))
			Expect(resp.Header.Get(authnv1.ImpersonateUserHeader)).To(Equal(janeUserInfo.Name))
			Expect(resp.Header.Get(authnv1.ImpersonateGroupHeader)).To(Equal(janeUserInfo.Groups[0]))
		})

		It("should not add impersonation headers for management backend targets", func() {
			req, err := http.NewRequest("POST", fmt.Sprintf("https://%s%s", voltronServerAddr, "/apis/projectcalico.org/v3/authorizationreviews"), nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set(authentication.AuthorizationHeader, janeBearerToken.BearerTokenHeader())

			resp, err := configureHTTPSClient().Do(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(200))
			Expect(resp.Header.Get(authnv1.ImpersonateUserHeader)).To(BeEmpty())
			Expect(resp.Header.Get(authnv1.ImpersonateGroupHeader)).To(BeEmpty())
		})
	})

	Context("with logging, metrics & auth caching enabled", func() {
		var (
			srvWg         *sync.WaitGroup
			srv           *server.Server
			defaultServer *httptest.Server
			httpsAddr     string
			internalAddr  string
			tunnelAddr    string

			publicHTTPClient   *http.Client
			internalHTTPClient *http.Client

			defaultProxy  *proxy.Proxy
			k8sTargets    []regexp.Regexp
			accessLogFile *os.File
		)

		const (
			managedCluster1 = "mc-one"
			managedCluster2 = "mc-two"
			authCacheTTL    = 500 * time.Millisecond
		)

		BeforeEach(func() {
			var err error

			accessLogFile, err = os.CreateTemp("", "voltron-access-log")
			Expect(err).ToNot(HaveOccurred())

			authenticator, err := auth.NewJWTAuth(&rest.Config{BearerToken: janeBearerToken.ToString()}, k8sAPI,
				auth.WithTokenReviewCacheTTL(ctx, authCacheTTL),
			)
			Expect(err).NotTo(HaveOccurred())

			testing.SetTokenReviewsReactor(fakeK8s, janeBearerToken, bobBearerToken)
			testing.SetSubjectAccessReviewsReactor(fakeK8s, clusterNS,
				testing.UserPermissions{
					Username: janeBearerToken.UserName(),
					Attrs: []authzv1.ResourceAttributes{
						{
							Verb:      "get",
							Group:     "projectcalico.org",
							Version:   "v3",
							Resource:  "managedclusters",
							Name:      managedCluster1,
							Namespace: clusterNS,
						},
						{
							Verb:      "get",
							Group:     "projectcalico.org",
							Version:   "v3",
							Resource:  "managedclusters",
							Name:      managedCluster2,
							Namespace: clusterNS,
						},
					},
				},
				testing.UserPermissions{
					Username: bobBearerToken.UserName(),
					Attrs: []authzv1.ResourceAttributes{
						{
							Verb:      "get",
							Group:     "projectcalico.org",
							Version:   "v3",
							Resource:  "managedclusters",
							Name:      managedCluster1,
							Namespace: clusterNS,
						},
					},
				},
			)

			defaultServer = httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					log.Info("request received, path=", r.URL.Path)
					http.Error(w, "an error occurred", http.StatusBadGateway)
				}))

			defaultURL, err := url.Parse(defaultServer.URL)
			Expect(err).NotTo(HaveOccurred())

			defaultProxy, err = proxy.New([]proxy.Target{
				{Path: "/", Dest: defaultURL},
				{Path: "/metrics", Dest: defaultURL},
			})
			Expect(err).NotTo(HaveOccurred())

			tunnelTargetWhitelist, err := regex.CompileRegexStrings([]string{`^/$`, `^/some/path$`})
			Expect(err).ShouldNot(HaveOccurred())

			srv, httpsAddr, internalAddr, tunnelAddr, srvWg = createAndStartServer(fakeClient,
				config,
				authenticator,
				clusterNS,
				server.WithTunnelSigningCreds(voltronTunnelCert),
				server.WithTunnelCert(voltronTunnelTLSCert),
				server.WithExternalCreds(test.CertToPemBytes(voltronExtHttpsCert), test.KeyToPemBytes(voltronExtHttpsPrivKey)),
				server.WithInternalCreds(test.CertToPemBytes(voltronIntHttpsCert), test.KeyToPemBytes(voltronIntHttpsPrivKey)),
				server.WithDefaultProxy(defaultProxy),
				server.WithKubernetesAPITargets(k8sTargets),
				server.WithUnauthenticatedTargets([]string{"/metrics"}), // we want /metrics on the public server to reach the defaultProxy
				server.WithTunnelTargetWhitelist(tunnelTargetWhitelist),
				server.WithCheckManagedClusterAuthorizationBeforeProxy(true, authCacheTTL, auth.NewNamespacedRBACAuthorizer(fakeK8s, clusterNS)),
				server.WithInternalMetricsEndpointEnabled(true),
				server.WithHTTPAccessLogging(
					accesslog.WithPath(accessLogFile.Name()),
					accesslog.WithRequestHeader(server.ClusterHeaderFieldCanon, "xClusterID"),
					accesslog.WithStandardJWTClaims(),
					accesslog.WithStringJWTClaim("email", "username"),
					accesslog.WithStringArrayJWTClaim("groups", "groups"),
					accesslog.WithErrorResponseBodyCaptureSize(250),
				),
			)

			publicHTTPClient = &http.Client{
				Transport: &http2.Transport{
					TLSClientConfig: &tls.Config{
						NextProtos: []string{"h2"},
						RootCAs:    voltronHttpsCAs,
						ServerName: "localhost",
					},
				},
			}
			internalHTTPClient = &http.Client{
				Transport: &http2.Transport{
					TLSClientConfig: &tls.Config{
						NextProtos: []string{"h2"},
						RootCAs:    voltronHttpsCAs,
						ServerName: "tigera-manager.tigera-manager.svc",
					},
				},
			}
		})

		AfterEach(func() {
			Expect(srv.Close()).NotTo(HaveOccurred())
			defaultServer.Close()
			srvWg.Wait()
		})

		scrapeCacheMetrics := func() []string {
			resp, err := internalHTTPClient.Get("https://" + internalAddr + "/metrics")
			Expect(err).ToNot(HaveOccurred())
			respBody, err := io.ReadAll(resp.Body)
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			lines := strings.Split(string(respBody), "\n")
			var result []string
			for _, line := range lines {
				if strings.HasPrefix(line, "tigera_cache") && !strings.HasPrefix(line, "tigera_cache_size") {
					result = append(result, line)
				}
			}
			return result
		}

		It("should write access logs", func() {
			req, err := http.NewRequest("GET", "https://"+httpsAddr+"/?foo=bar", nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set(authentication.AuthorizationHeader, janeBearerToken.BearerTokenHeader())
			req.Header.Set(server.ClusterHeaderFieldCanon, "tigera-labs")
			resp, err := publicHTTPClient.Do(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))

			// as the access log is written after the http response was written, we may get here before the logs are written, so wait for them to appear
			log.Info("before sync")
			Eventually(func() bool {
				srv.FlushAccessLogs()
				info, _ := accessLogFile.Stat()
				return info.Size() > 0
			}).Should(BeTrue())
			log.Info("after sync")

			logMessage, err := accesslogtest.ReadLastAccessLog(accessLogFile)
			Expect(err).ToNot(HaveOccurred())
			Expect(logMessage.Response.Status).To(Equal(http.StatusBadRequest))
			Expect(logMessage.Response.BytesWritten).To(Equal(95))
			Expect(logMessage.Response.Body).To(ContainSubstring("Cluster with ID tigera-labs not found"))
			Expect(logMessage.Request.Method).To(Equal(http.MethodGet))
			Expect(logMessage.Request.Host).To(Equal(httpsAddr))
			Expect(logMessage.Request.Path).To(Equal("/"))
			Expect(logMessage.Request.Query).To(Equal("foo=bar"))
			Expect(logMessage.Request.ClusterID).To(Equal("tigera-labs"))
			Expect(logMessage.Request.Auth.Iss).To(Equal(k8sIssuer))
			Expect(logMessage.Request.Auth.Sub).To(Equal("jane@example.io"))
			Expect(logMessage.Request.Auth.Username).To(Equal("jane@example.io"))
			Expect(logMessage.Request.Auth.Groups).To(Equal([]string{"system:authenticated"}))
			Expect(logMessage.TLS.ServerName).To(Equal("localhost"))
			Expect(logMessage.TLS.CipherSuite).To(Equal("TLS_AES_128_GCM_SHA256"))
		})

		It("metrics should not be available on the public addr", func() {
			resp, err := publicHTTPClient.Get("https://" + httpsAddr + "/metrics")
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusBadGateway))
		})

		It("should cache token requests", func() {
			closeCluster1 := createAndStartManagedCluster(managedCluster1, clusterNS, tunnelAddr, voltronTunnelCAs, voltronTunnelCert, voltronTunnelPrivKey, fakeClient, newEchoHandler(managedCluster1))
			closeCluster2 := createAndStartManagedCluster(managedCluster2, clusterNS, tunnelAddr, voltronTunnelCAs, voltronTunnelCert, voltronTunnelPrivKey, fakeClient, newEchoHandler(managedCluster2))
			defer closeCluster1()
			defer closeCluster2()

			doHttpRequest := func(fakeJWT *testing.FakeJWT, clusterName string) {
				req, err := http.NewRequest(http.MethodPost, "https://"+httpsAddr+"/some/path", strings.NewReader("foo"))
				Expect(err).ToNot(HaveOccurred())
				req.Header.Set(utils.ClusterHeaderField, clusterName)
				req.Header.Set(authentication.AuthorizationHeader, fakeJWT.BearerTokenHeader())

				resp, err := publicHTTPClient.Do(req)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))
				Expect(resp.Header.Get("x-echoed-by")).To(Equal(clusterName))
				Expect(resp.Header.Get(authnv1.ImpersonateUserHeader)).To(Equal(fakeJWT.UserName()))
				respBody, err := io.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(respBody)).To(Equal("foo"))
			}

			Expect(scrapeCacheMetrics()).To(BeEmpty())

			type authCacheMetrics struct {
				AuthnHits   int
				AuthnMisses int
				AuthzHits   int
				AuthzMisses int
			}
			scrapeAuthCacheMetrics := func() authCacheMetrics {
				metrics := scrapeCacheMetrics()
				metricExtractor := regexp.MustCompile(`.* (\d+)$`)
				metricValue := func(prefix string) int {
					for _, metric := range metrics {
						if strings.HasPrefix(metric, prefix) {
							valueStr := metricExtractor.FindStringSubmatch(metric)[1]
							value, err := strconv.Atoi(valueStr)
							if err != nil {
								return -2
							} else {
								return value
							}
						}
					}
					return -1
				}
				return authCacheMetrics{
					AuthnHits:   metricValue("tigera_cache_hits_total{cacheName=\"lma-token-reviewer\"}"),
					AuthnMisses: metricValue("tigera_cache_misses_total{cacheName=\"lma-token-reviewer\"}"),
					AuthzHits:   metricValue("tigera_cache_hits_total{cacheName=\"managedcluster-access-authorizer\"}"),
					AuthzMisses: metricValue("tigera_cache_misses_total{cacheName=\"managedcluster-access-authorizer\"}"),
				}
			}
			expectMetrics := func(exp authCacheMetrics) {
				metrics := scrapeCacheMetrics()
				if exp.AuthnHits > 0 {
					Expect(metrics).To(ContainElement(fmt.Sprintf("tigera_cache_hits_total{cacheName=\"lma-token-reviewer\"} %d", exp.AuthnHits)))
				}
				if exp.AuthnMisses > 0 {
					Expect(metrics).To(ContainElement(fmt.Sprintf("tigera_cache_misses_total{cacheName=\"lma-token-reviewer\"} %d", exp.AuthnMisses)))
				}
				if exp.AuthzHits > 0 {
					Expect(metrics).To(ContainElement(fmt.Sprintf("tigera_cache_hits_total{cacheName=\"managedcluster-access-authorizer\"} %d", exp.AuthzHits)))
				}
				if exp.AuthzMisses > 0 {
					Expect(metrics).To(ContainElement(fmt.Sprintf("tigera_cache_misses_total{cacheName=\"managedcluster-access-authorizer\"} %d", exp.AuthzMisses)))
				}
			}

			By("making the first request", func() {
				doHttpRequest(janeBearerToken, managedCluster1)
				expectMetrics(authCacheMetrics{AuthnHits: 0, AuthnMisses: 1, AuthzHits: 0, AuthzMisses: 1})
			})

			By("making a second request for the same user & cluster", func() {
				doHttpRequest(janeBearerToken, managedCluster1)
				expectMetrics(authCacheMetrics{AuthnHits: 1, AuthnMisses: 1, AuthzHits: 1, AuthzMisses: 1})
			})

			By("making a third request for the same user & cluster", func() {
				doHttpRequest(janeBearerToken, managedCluster1)
				expectMetrics(authCacheMetrics{AuthnHits: 2, AuthnMisses: 1, AuthzHits: 2, AuthzMisses: 1})
			})

			By("making a request for a different user", func() {
				doHttpRequest(bobBearerToken, managedCluster1)
				expectMetrics(authCacheMetrics{AuthnHits: 2, AuthnMisses: 2, AuthzHits: 2, AuthzMisses: 2})
			})

			By("making a request for a different cluster", func() {
				doHttpRequest(janeBearerToken, managedCluster2)
				expectMetrics(authCacheMetrics{AuthnHits: 3, AuthnMisses: 2, AuthzHits: 2, AuthzMisses: 3})
			})

			By("repeatedly requesting the same value will eventually increase misses due to cache expiry", func() {
				type result struct { // only interested in misses
					authnMisses int
					authzMisses int
				}
				Eventually(func() result {
					doHttpRequest(janeBearerToken, managedCluster1)
					metrics := scrapeAuthCacheMetrics()
					return result{
						authnMisses: metrics.AuthnMisses,
						authzMisses: metrics.AuthzMisses,
					}
				}, 3*authCacheTTL, 100*time.Millisecond).Should(Equal(result{authnMisses: 3, authzMisses: 4}))

				Eventually(func() result {
					doHttpRequest(janeBearerToken, managedCluster1)
					metrics := scrapeAuthCacheMetrics()
					return result{
						authnMisses: metrics.AuthnMisses,
						authzMisses: metrics.AuthzMisses,
					}
				}, 3*authCacheTTL, 100*time.Millisecond).Should(Equal(result{authnMisses: 4, authzMisses: 5}))
			})
		})
	})

	Context("auth cache TTLs are configured above the maximum permitted", func() {
		k8sAPI = &k8sClient{
			Interface: k8sfake.NewSimpleClientset(),
		}

		It("creating an authenticator should fail when TokenReviewCacheTTL is too large", func() {
			_, err := auth.NewJWTAuth(&rest.Config{BearerToken: janeBearerToken.ToString()}, k8sAPI,
				auth.WithTokenReviewCacheTTL(context.Background(), auth.TokenReviewCacheMaxTTL+time.Second),
			)
			Expect(err).To(MatchError(MatchRegexp("configured cacheTTL of 21s exceeds maximum permitted of 20s")))
		})

		It("creating a server should fail when CheckManagedClusterAuthorizationBeforeProxyTTL is too large", func() {
			authenticator, err := auth.NewJWTAuth(&rest.Config{BearerToken: janeBearerToken.ToString()}, k8sAPI,
				auth.WithTokenReviewCacheTTL(context.Background(), auth.TokenReviewCacheMaxTTL),
			)
			Expect(err).NotTo(HaveOccurred())

			vfg := &voltronconfig.Config{TenantNamespace: clusterNS}
			_, err = server.New(fakeClient, config, *vfg, authenticator, mockFactory,
				server.WithCheckManagedClusterAuthorizationBeforeProxy(true, 42*time.Second, auth.NewNamespacedRBACAuthorizer(fakeK8s, clusterNS)),
			)
			Expect(err).To(MatchError(MatchRegexp("configured cacheTTL of 42s exceeds maximum permitted of 20s")))
		})
	})

	Context("A managed cluster connects to voltron and the current active fingerprint is in the md5 format", func() {
		var (
			tunnelAddr    string
			srvWg         *sync.WaitGroup
			srv           *server.Server
			defaultServer *httptest.Server

			defaultProxy          *proxy.Proxy
			k8sTargets            []regexp.Regexp
			tunnelTargetWhitelist []regexp.Regexp
		)

		BeforeEach(func() {
			var err error

			mockAuthenticator.On("Authenticate", mock.Anything).Return(janeUserInfo, 0, nil)

			defaultServer = httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Echo the token, such that we can determine if the auth header was successfully swapped.
					w.Header().Set(authentication.AuthorizationHeader, r.Header.Get(authentication.AuthorizationHeader))
				}))

			defaultURL, err := url.Parse(defaultServer.URL)
			Expect(err).NotTo(HaveOccurred())

			defaultProxy, err = proxy.New([]proxy.Target{
				{Path: "/", Dest: defaultURL},
				{Path: "/compliance/", Dest: defaultURL},
			})
			Expect(err).NotTo(HaveOccurred())

			tunnelTargetWhitelist, err = regex.CompileRegexStrings([]string{`^/$`, `^/some/path$`})
			Expect(err).ShouldNot(HaveOccurred())

			k8sTargets, err = regex.CompileRegexStrings([]string{`^/api/?`, `^/apis/?`})
			Expect(err).ShouldNot(HaveOccurred())

			srv, _, _, tunnelAddr, srvWg = createAndStartServer(fakeClient,
				config,
				mockAuthenticator,
				clusterNS,
				server.WithTunnelSigningCreds(voltronTunnelCert),
				server.WithTunnelCert(voltronTunnelTLSCert),
				server.WithExternalCreds(test.CertToPemBytes(voltronExtHttpsCert), test.KeyToPemBytes(voltronExtHttpsPrivKey)),
				server.WithInternalCreds(test.CertToPemBytes(voltronIntHttpsCert), test.KeyToPemBytes(voltronIntHttpsPrivKey)),
				server.WithDefaultProxy(defaultProxy),
				server.WithKubernetesAPITargets(k8sTargets),
				server.WithTunnelTargetWhitelist(tunnelTargetWhitelist),
			)
		})

		AfterEach(func() {
			Expect(srv.Close()).NotTo(HaveOccurred())
			defaultServer.Close()
			srvWg.Wait()
		})

		When("the connecting clusters fingerprint matches the md5 active fingerprint", func() {
			It("upgrades the active fingerprint to sha256", func() {
				certTemplate := test.CreateClientCertificateTemplate(clusterA, "localhost")
				privKey, cert, err := test.CreateCertPair(certTemplate, voltronTunnelCert, voltronTunnelPrivKey)
				Expect(err).NotTo(HaveOccurred())

				Expect(fakeClient.Create(context.Background(), &v3.ManagedCluster{
					ObjectMeta: metav1.ObjectMeta{
						Name:      clusterA,
						Namespace: clusterNS,
						Annotations: map[string]string{
							server.AnnotationActiveCertificateFingerprint: fmt.Sprintf("%x", md5.Sum(cert.Raw)), // old md5 sum
						},
					},
				})).NotTo(HaveOccurred())
				list := &v3.ManagedClusterList{}
				Expect(fakeClient.List(context.Background(), list, &ctrlclient.ListOptions{Namespace: clusterNS})).NotTo(HaveOccurred())
				Expect(list.Items).To(HaveLen(1))

				tlsCert, err := test.X509CertToTLSCert(cert, privKey)
				Expect(err).NotTo(HaveOccurred())

				t, err := tunnel.DialTLS(tunnelAddr, &tls.Config{
					Certificates: []tls.Certificate{tlsCert},
					RootCAs:      voltronTunnelCAs,
					ServerName:   "voltron",
				}, 5*time.Second, nil)
				Expect(err).NotTo(HaveOccurred())

				Eventually(func() string {
					mc := &v3.ManagedCluster{}
					err := fakeClient.Get(context.Background(), types.NamespacedName{Name: clusterA, Namespace: clusterNS}, mc)
					Expect(err).NotTo(HaveOccurred())
					return mc.Annotations[server.AnnotationActiveCertificateFingerprint]
				}, 3*time.Second, 500*time.Millisecond).Should(Equal(utils.GenerateFingerprint(cert))) // new sha256 sum

				Expect(t.Close()).NotTo(HaveOccurred())
			})
		})

		When("the connecting clusters fingerprint doesn't match the md5 active fingerprint", func() {
			It("doesn't modify the existing md5 active fingerprint", func() {
				certTemplate := test.CreateClientCertificateTemplate(clusterB, "localhost")
				privKey, cert, err := test.CreateCertPair(certTemplate, voltronTunnelCert, voltronTunnelPrivKey)
				Expect(err).NotTo(HaveOccurred())

				Expect(fakeClient.Create(context.Background(), &v3.ManagedCluster{
					ObjectMeta: metav1.ObjectMeta{
						Name:      clusterB,
						Namespace: clusterNS,
						Annotations: map[string]string{
							server.AnnotationActiveCertificateFingerprint: "md5-sum-can-not-be-matched",
						},
					},
				})).NotTo(HaveOccurred())
				list := &v3.ManagedClusterList{}
				Expect(fakeClient.List(context.Background(), list, &ctrlclient.ListOptions{Namespace: clusterNS})).NotTo(HaveOccurred())
				Expect(list.Items).To(HaveLen(1))

				tlsCert, err := test.X509CertToTLSCert(cert, privKey)
				Expect(err).NotTo(HaveOccurred())

				t, err := tunnel.DialTLS(tunnelAddr, &tls.Config{
					Certificates: []tls.Certificate{tlsCert},
					RootCAs:      voltronTunnelCAs,
					ServerName:   "voltron",
				}, 5*time.Second, nil)
				Expect(err).NotTo(HaveOccurred())

				time.Sleep(2 * time.Second)

				mc := &v3.ManagedCluster{}
				Expect(fakeClient.Get(context.Background(), types.NamespacedName{Name: clusterB, Namespace: clusterNS}, mc)).NotTo(HaveOccurred())
				Expect(mc.Annotations[server.AnnotationActiveCertificateFingerprint]).To(Equal("md5-sum-can-not-be-matched"))

				Expect(t.Close()).NotTo(HaveOccurred())
			})
		})
	})

	Context("Voltron tunnel configured with tls certificate with invalid Key Extension", func() {
		var (
			wg            *sync.WaitGroup
			srv           *server.Server
			tunnelAddr    string
			defaultServer *httptest.Server
		)

		BeforeEach(func() {
			mockAuthenticator.On("Authenticate", mock.Anything).Return(janeUserInfo, 0, nil)
			defaultServer = httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

			defaultURL, err := url.Parse(defaultServer.URL)
			Expect(err).NotTo(HaveOccurred())

			defaultProxy, e := proxy.New([]proxy.Target{
				{Path: "/", Dest: defaultURL},
				{Path: "/compliance/", Dest: defaultURL},
				{Path: "/api/v1/namespaces", Dest: defaultURL},
			})
			Expect(e).NotTo(HaveOccurred())

			tunnelTargetWhitelist, _ := regex.CompileRegexStrings([]string{
				`^/$`,
				`^/some/path$`,
			})

			// Recreate the voltron certificate specifying client auth key usage
			voltronTunnelCertTemplate := test.CreateCACertificateTemplate("voltron")
			voltronTunnelCertTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

			voltronTunnelPrivKey, voltronTunnelCert, err = test.CreateCertPair(voltronTunnelCertTemplate, nil, nil)
			Expect(err).ShouldNot(HaveOccurred())

			// convert x509 cert to tls cert
			voltronTunnelTLSCert, err = test.X509CertToTLSCert(voltronTunnelCert, voltronTunnelPrivKey)
			Expect(err).NotTo(HaveOccurred())

			voltronTunnelCAs = x509.NewCertPool()
			voltronTunnelCAs.AppendCertsFromPEM(test.CertToPemBytes(voltronTunnelCert))

			srv, _, _, tunnelAddr, wg = createAndStartServer(
				fakeClient,
				config,
				mockAuthenticator,
				clusterNS,
				server.WithTunnelSigningCreds(voltronTunnelCert),
				server.WithTunnelCert(voltronTunnelTLSCert),
				server.WithDefaultProxy(defaultProxy),
				server.WithTunnelTargetWhitelist(tunnelTargetWhitelist),
				server.WithInternalCreds(test.CertToPemBytes(voltronIntHttpsCert), test.KeyToPemBytes(voltronIntHttpsPrivKey)),
				server.WithExternalCreds(test.CertToPemBytes(voltronExtHttpsCert), test.KeyToPemBytes(voltronExtHttpsPrivKey)),
			)

			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			Expect(srv.Close()).NotTo(HaveOccurred())
			wg.Wait()
		})

		It("server with invalid key types will not accept connections", func() {
			var err error

			certTemplate := test.CreateClientCertificateTemplate(clusterA, "localhost")
			privKey, cert, err := test.CreateCertPair(certTemplate, voltronTunnelCert, voltronTunnelPrivKey)
			Expect(err).ShouldNot(HaveOccurred())

			By("adding ClusterA")
			Expect(fakeClient.Create(context.Background(), &v3.ManagedCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:        clusterA,
					Namespace:   clusterNS,
					Annotations: map[string]string{server.AnnotationActiveCertificateFingerprint: utils.GenerateFingerprint(cert)},
				},
			})).NotTo(HaveOccurred())
			list := &v3.ManagedClusterList{}
			Expect(fakeClient.List(context.Background(), list, &ctrlclient.ListOptions{Namespace: clusterNS})).ShouldNot(HaveOccurred())
			Expect(list.Items).To(HaveLen(1))

			// Try to connect clusterA to the new fake voltron, should fail
			tlsCert, err := test.X509CertToTLSCert(cert, privKey)
			Expect(err).NotTo(HaveOccurred())

			_, err = tunnel.DialTLS(tunnelAddr, &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
				RootCAs:      voltronTunnelCAs,
				ServerName:   "voltron",
			}, 5*time.Second, nil)
			Expect(err).Should(MatchError("TLS dial failed: tls: failed to verify certificate: x509: certificate specifies an incompatible key usage"))
		})
	})

	Context("paths with authorization enabled", func() {
		var (
			srvWg                 *sync.WaitGroup
			srv                   *server.Server
			defaultServer         *httptest.Server
			httpsAddr             string
			publicHTTPClient      *http.Client
			defaultProxy          *proxy.Proxy
			authorizerInvocations int
		)

		const (
			authCacheTTL = 500 * time.Millisecond
		)

		BeforeEach(func() {
			var err error

			// Configure authentication and authorization.
			authorizerInvocations = 0
			authenticator, err := auth.NewJWTAuth(
				&rest.Config{BearerToken: janeBearerToken.ToString()},
				k8sAPI,
				auth.WithTokenReviewCacheTTL(ctx, authCacheTTL),
			)
			Expect(err).NotTo(HaveOccurred())
			testing.SetTokenReviewsReactor(fakeK8s, janeBearerToken, bobBearerToken)
			testing.SetSubjectAccessReviewsReactor(fakeK8s, clusterNS,
				testing.UserPermissions{
					Username: janeBearerToken.UserName(),
					Attrs: []authzv1.ResourceAttributes{
						{
							Verb:      "create",
							Group:     "linseed.tigera.io",
							Resource:  "flowlogs",
							Namespace: clusterNS,
						},
					},
				},
				testing.UserPermissions{
					Username: bobBearerToken.UserName(),
					// Bob has no privilege :)
					Attrs: []authzv1.ResourceAttributes{},
				},
			)
			incrementAuthorizationCount := func(action k8stesting.Action) (bool, runtime.Object, error) {
				authorizerInvocations++
				return false, nil, nil
			}
			fakeK8s.PrependReactor("create", "subjectaccessreviews", incrementAuthorizationCount)
			fakeK8s.PrependReactor("create", "localsubjectaccessreviews", incrementAuthorizationCount)

			// Set up the proxy.
			defaultServer = httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					log.Info("request received, path=", r.URL.Path)
					w.WriteHeader(http.StatusOK)
				}))
			defaultURL, err := url.Parse(defaultServer.URL)
			Expect(err).NotTo(HaveOccurred())
			defaultProxy, err = proxy.New([]proxy.Target{
				{Path: "/authorization-required", Dest: defaultURL},
				{Path: "/no-authorization-required", Dest: defaultURL},
			})
			Expect(err).NotTo(HaveOccurred())

			srv, httpsAddr, _, _, srvWg = createAndStartServer(
				fakeClient,
				config,
				authenticator,
				clusterNS,
				server.WithTunnelSigningCreds(voltronTunnelCert),
				server.WithTunnelCert(voltronTunnelTLSCert),
				server.WithExternalCreds(test.CertToPemBytes(voltronExtHttpsCert), test.KeyToPemBytes(voltronExtHttpsPrivKey)),
				server.WithInternalCreds(test.CertToPemBytes(voltronIntHttpsCert), test.KeyToPemBytes(voltronIntHttpsPrivKey)),
				server.WithDefaultProxy(defaultProxy),
				server.WithAuthAttributesMap(map[string]*proxy.AuthorizationDetails{
					"/authorization-required": {
						Authorizer: auth.NewNamespacedRBACAuthorizer(k8sAPI, clusterNS),
						AttributesFunc: func(request *http.Request) (*authzv1.ResourceAttributes, *authzv1.NonResourceAttributes, error) {
							return &authzv1.ResourceAttributes{
								Verb:     "create",
								Group:    "linseed.tigera.io",
								Resource: "flowlogs",
							}, nil, nil
						},
					},
				}),
			)

			publicHTTPClient = &http.Client{
				Transport: &http2.Transport{
					TLSClientConfig: &tls.Config{
						NextProtos: []string{"h2"},
						RootCAs:    voltronHttpsCAs,
						ServerName: "localhost",
					},
				},
			}
		})

		AfterEach(func() {
			Expect(srv.Close()).NotTo(HaveOccurred())
			defaultServer.Close()
			srvWg.Wait()
		})

		It("should allow jane to access the authorized path", func() {
			req, err := http.NewRequest(http.MethodPost, "https://"+httpsAddr+"/authorization-required", strings.NewReader("foo"))
			Expect(err).ToNot(HaveOccurred())
			req.Header.Set(authentication.AuthorizationHeader, janeBearerToken.BearerTokenHeader())

			resp, err := publicHTTPClient.Do(req)
			Expect(authorizerInvocations).To(Equal(1))
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
		})

		It("should NOT allow bob to access the authorized path", func() {
			req, err := http.NewRequest(http.MethodPost, "https://"+httpsAddr+"/authorization-required", strings.NewReader("foo"))
			Expect(err).ToNot(HaveOccurred())
			req.Header.Set(authentication.AuthorizationHeader, bobBearerToken.BearerTokenHeader())

			resp, err := publicHTTPClient.Do(req)
			Expect(authorizerInvocations).To(Equal(1))
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))
		})

		It("should NOT invoke an authorizer for an path that is not configured for authorization", func() {
			req, err := http.NewRequest(http.MethodPost, "https://"+httpsAddr+"/no-authorization-required", strings.NewReader("foo"))
			Expect(err).ToNot(HaveOccurred())
			req.Header.Set(authentication.AuthorizationHeader, janeBearerToken.BearerTokenHeader())

			resp, err := publicHTTPClient.Do(req)
			Expect(authorizerInvocations).To(Equal(0))
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
		})
	})
})

func configureHTTPSClient() *http.Client {
	return &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"h2"},
			},
		},
	}
}

func clientHelloReq(addr string, target string, expectStatus int) (resp *http.Response) {
	Eventually(func() error {
		req, err := http.NewRequest("GET", "https://"+addr+"/some/path", strings.NewReader("HELLO"))
		Expect(err).NotTo(HaveOccurred())

		req.Header[utils.ClusterHeaderField] = []string{target}
		req.Header.Set(authentication.AuthorizationHeader, janeBearerToken.BearerTokenHeader())
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "localhost",
			},
		}
		client := &http.Client{Transport: tr}
		resp, err = client.Do(req)
		if err != nil || resp.StatusCode != expectStatus {
			return fmt.Errorf("err=%v status=%d expectedStatus=%d", err, resp.StatusCode, expectStatus)
		}
		return nil
	}, 2*time.Second, 400*time.Millisecond).ShouldNot(HaveOccurred())
	return
}

func createAndStartServer(fakeClient ctrlclient.WithWatch, config *rest.Config, authenticator auth.JWTAuth, clusterNS string,
	options ...server.Option,
) (*server.Server, string, string, string, *sync.WaitGroup) {
	vcfg := &voltronconfig.Config{TenantNamespace: clusterNS, ManagedClusterSupportsImpersonation: true}
	srv, err := server.New(fakeClient, config, *vcfg, authenticator, mockFactory, options...)
	Expect(err).ShouldNot(HaveOccurred())

	lisHTTPS, err := net.Listen("tcp", "localhost:0")
	Expect(err).NotTo(HaveOccurred())

	lisInternalHTTPS, err := net.Listen("tcp", "localhost:0")
	Expect(err).NotTo(HaveOccurred())

	lisTun, err := net.Listen("tcp", "localhost:0")
	Expect(err).NotTo(HaveOccurred())

	var wg sync.WaitGroup
	wg.Go(func() {
		_ = srv.ServeHTTPS(lisHTTPS, "", "")
	})
	wg.Go(func() {
		_ = srv.ServeInternalHTTPS(lisInternalHTTPS, "", "")
	})
	wg.Go(func() {
		_ = srv.ServeTunnelsTLS(lisTun)
	})

	go func() {
		_ = srv.WatchK8s()
	}()

	return srv, lisHTTPS.Addr().String(), lisInternalHTTPS.Addr().String(), lisTun.Addr().String(), &wg
}

func WaitForClusterToConnect(fakeClient ctrlclient.WithWatch, clusterName, clusterNS string) {
	Eventually(func() v3.ManagedClusterStatus {
		managedCluster := &v3.ManagedCluster{}
		err := fakeClient.Get(context.Background(), types.NamespacedName{Name: clusterName, Namespace: clusterNS}, managedCluster)
		Expect(err).ShouldNot(HaveOccurred())
		return managedCluster.Status
	}, 5*time.Second, 100*time.Millisecond).Should(Equal(v3.ManagedClusterStatus{
		Conditions: []v3.ManagedClusterStatusCondition{
			{Status: v3.ManagedClusterStatusValueTrue, Type: v3.ManagedClusterStatusTypeConnected},
		},
	}))
}

func createAndStartManagedCluster(
	clusterName, clusterNS string,
	tunnelAddr string,
	tunnelCA *x509.CertPool,
	voltronTunnelCert *x509.Certificate,
	voltronTunnelPrivKey *rsa.PrivateKey,
	fakeClient ctrlclient.WithWatch,
	handler http.Handler,
) (closer func()) {
	certTemplate := test.CreateClientCertificateTemplate(clusterName, "localhost")
	clusterKey, clusterCert, err := test.CreateCertPair(certTemplate, voltronTunnelCert, voltronTunnelPrivKey)
	Expect(err).ShouldNot(HaveOccurred())

	Expect(fakeClient.Create(context.Background(), &v3.ManagedCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:        clusterName,
			Namespace:   clusterNS,
			Annotations: map[string]string{server.AnnotationActiveCertificateFingerprint: utils.GenerateFingerprint(clusterCert)},
		},
	})).ShouldNot(HaveOccurred())

	tlsCert, err := test.X509CertToTLSCert(clusterCert, clusterKey)
	Expect(err).NotTo(HaveOccurred())

	tun, err := tunnel.DialTLS(tunnelAddr, &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      tunnelCA,
	}, 5*time.Second, nil)
	Expect(err).NotTo(HaveOccurred())

	WaitForClusterToConnect(fakeClient, clusterName, clusterNS)

	httpServer := &http.Server{
		Handler: handler,
	}

	go func() {
		defer GinkgoRecover()
		err := httpServer.Serve(tls.NewListener(tun, &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			NextProtos:   []string{"h2"},
		}))
		Expect(err).Should(Equal(fmt.Errorf("http: Server closed")))
	}()

	return func() {
		Expect(httpServer.Close()).NotTo(HaveOccurred())
	}
}

func newEchoHandler(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqBody, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		copyHeaders := func(name string) {
			if v := r.Header[name]; len(v) > 0 {
				w.Header()[name] = v
			}
		}

		w.Header().Set("x-echoed-by", name)
		copyHeaders(authnv1.ImpersonateUserHeader)
		copyHeaders(authnv1.ImpersonateGroupHeader)

		_, _ = w.Write(reqBody)
	})
}

func newWatchInf() (*mockwatch.Interface, chan watch.Event) {
	watchInf := new(mockwatch.Interface)
	events := make(chan watch.Event, 1)
	watchInf.EXPECT().ResultChan().Return(events)
	watchInf.EXPECT().Stop().Return()

	return watchInf, events
}

func setList(resourceVersion string, managedClusters ...v3.ManagedCluster) func(ctx context.Context, list ctrlclient.ObjectList, opts ...ctrlclient.ListOption) error {
	return func(ctx context.Context, list ctrlclient.ObjectList, opts ...ctrlclient.ListOption) error {
		*(list.(*v3.ManagedClusterList)) = v3.ManagedClusterList{
			ListMeta: metav1.ListMeta{ResourceVersion: resourceVersion},
			Items:    managedClusters,
		}
		return nil
	}
}

func sendReqToManagedCluster(cli *http.Client, voltronServerAddr, clusterName, body string) {
	req, err := http.NewRequest("GET", "https://"+voltronServerAddr+"/some/path", strings.NewReader(body))
	Expect(err).NotTo(HaveOccurred())

	req.Header[utils.ClusterHeaderField] = []string{clusterName}
	req.Header.Set(authentication.AuthorizationHeader, janeBearerToken.BearerTokenHeader())

	_, err = cli.Do(req)
	Expect(err).ShouldNot(HaveOccurred())
}

func startMgdClusterService(ctx context.Context, listener net.Listener, tlsCert tls.Certificate) chan string {
	reqChan := make(chan string, 1)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			Expect(err).NotTo(HaveOccurred())

			if err := chanutil.WriteWithDeadline(ctx, reqChan, string(body), 2*time.Second); err != nil {
				panic(err)
			}
		}),
	}

	go func() {
		defer GinkgoRecover()
		defer close(reqChan)
		_ = srv.Serve(tls.NewListener(listener, &tls.Config{
			NextProtos:   []string{"h2"},
			Certificates: []tls.Certificate{tlsCert},
		}))
	}()

	go func() {
		defer GinkgoRecover()
		<-ctx.Done()
		_ = srv.Close()
	}()

	return reqChan
}

func setGet(managedCluster *v3.ManagedCluster) func(ctx context.Context, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
	return func(ctx context.Context, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
		managedCluster.DeepCopyInto(obj.(*v3.ManagedCluster))
		return nil
	}
}
