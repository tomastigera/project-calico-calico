// Copyright (c) 2019-2022 Tigera, Inc. All rights reserved.

package elasticsearchconfiguration

import (
	"context"
	"fmt"
	"strings"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/kube-controllers/pkg/elasticsearch"
	esusers "github.com/projectcalico/calico/kube-controllers/pkg/elasticsearch/users"
	"github.com/projectcalico/calico/kube-controllers/pkg/resource"
	relasticsearchfake "github.com/projectcalico/calico/kube-controllers/pkg/resource/elasticsearch/fake"
	"github.com/projectcalico/calico/linseed/pkg/testutils"
	"github.com/projectcalico/calico/lma/pkg/k8s"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
)

var cert = `-----BEGIN CERTIFICATE-----
MIIDWTCCAkGgAwIBAgIIKE0AM+B4dY0wDQYJKoZIhvcNAQELBQAwLDEqMCgGA1UE
AwwhdGlnZXJhLW9wZXJhdG9yLXNpZ25lckAxNTc4MzQ2ODMxMCAXDTIwMDEwNjIx
NDAzMVoYDzIxMTkxMjEzMjE0MDMyWjA5MTcwNQYDVQQDEy50aWdlcmEtc2VjdXJl
LWVzLWh0dHAudGlnZXJhLWVsYXN0aWNzZWFyY2guc3ZjMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAtaItUVI2AneysowgnqV/4sfECgm1VERx5yb7Ew/8
k84zJTy/rUGGi9pwrBmP3lmSo2ybG++iWeePVi6P0LFX96M0Utf5t0Aqei+m9VPV
kBqmUmRZa3dms0Bk9WHN+2Uz1ihFS4YG1im8Z5OkchjEuNLWPaMYKdygr+mi9ABQ
0uWxPYcCTTuWlx0/yY0s/sfiGKYVoS3FdqaaKtuYkbAahrWwnUSbFnv6x7U/H5/i
m5W9Cmu0FUHR14VodfnrtdqLSL9qHc7oLTr5UrvKBhE8Dgnh4L2bzHyUX45UbTCP
CKbRda0JmyDpmcoRHKiyk335nrTBEw2UXa/L828qOl3YiQIDAQABo3AwbjAOBgNV
HQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADA5
BgNVHREEMjAwgi50aWdlcmEtc2VjdXJlLWVzLWh0dHAudGlnZXJhLWVsYXN0aWNz
ZWFyY2guc3ZjMA0GCSqGSIb3DQEBCwUAA4IBAQCGI4KqgQMJOj0JxDTFtPhj/Zfq
Lj8bvakolAMcMrKwxpudduQ4wKBoAGqZ3jG/LW2FMcmoecDOIPkZzutMUqOy0rT9
t7TUosM4Zh4T9R+h4Bmp77OzDVxn2OrDRcCf5sjh+PsiUtOBR9ItvLWzkrVnbqgw
eHmw5HZk2NCsCYtzm+pbgkti3fK6mQk9icbuC9RX5YxoB7SfwwpKW67gcreF96j7
5hlYzzHNryg7kGIwlCgX57btFxEgl7rJgIyBU2JOdoYvxJOolUFri+Km6t4EKKZP
HejNjkLxDHyPkQE10NeFIOpbiP0QwfqPWq+iwbIlDqnCEThdKqtwD2HP+21H
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIC+DCCAeCgAwIBAgIBATANBgkqhkiG9w0BAQsFADAsMSowKAYDVQQDDCF0aWdl
cmEtb3BlcmF0b3Itc2lnbmVyQDE1NzgzNDY4MzEwIBcNMjAwMTA2MjE0MDMwWhgP
MjExOTEyMTMyMTQwMzFaMCwxKjAoBgNVBAMMIXRpZ2VyYS1vcGVyYXRvci1zaWdu
ZXJAMTU3ODM0NjgzMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMOx
VLeF4BosWxl4UP3mK01SsbVXzSVh6k9pbTWUacQEdAoWa2h6SEk2KU55nmUB85BO
9lX3pERn5NhdA961iT2CUg9RRmxQC/evHnJTi5fD1IFDc8EbDXYOiVTZteU5FeOA
oJv81a1hjijn0Fh7V3CjkELSd46upZQo59SsP6yEEPpcs8sgPpd0NWJglr92+2fD
bAsOBajeUmelMiv04MIueSSoK3tdTDvAL5AD/Zm/CIxTmozXcLphw3MZ4ZFuBHne
r/qzOYbrkDBdpKyzz1N3+sI/d8RVjksveW7eLZyFGByzg3XZisCL1FgIda/XfB5I
LT3Vn2xP0kRhU7EMoRkCAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgKkMA8GA1UdEwEB
/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJKnJdJDRmQo4HE7pc40LCARqAuJ
ttBL9uxf1ME+vNh6LAZVLexQnFoXFIxRcLyDWQi6qXFEH4O4YeilN7sPY1vEqa/t
jbKz0l8OnyZ931uqxNCvtuSdfifb60xzr2oM5M9NF874VQz+WRzEcOgM6dfpyb93
B/dzEyp9joofP7W+vGaYGnUgZB+iPgbArJkY+m60/3hK/nGIFebVHOaAXccii1z3
hJfZim1BMG4OqVMaa5zWVw/E0ugMLJE+s6ZKtYLiRmbpzsrZqWl47+6kq2teQUKr
B9toN8cP+e8juLjxCDoxWoackGhjV0ieTbXnqEppadjxsKXgNTqhnIY6kuc=
-----END CERTIFICATE-----`

var key = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtaItUVI2AneysowgnqV/4sfECgm1VERx5yb7Ew/8k84zJTy/
rUGGi9pwrBmP3lmSo2ybG++iWeePVi6P0LFX96M0Utf5t0Aqei+m9VPVkBqmUmRZ
a3dms0Bk9WHN+2Uz1ihFS4YG1im8Z5OkchjEuNLWPaMYKdygr+mi9ABQ0uWxPYcC
TTuWlx0/yY0s/sfiGKYVoS3FdqaaKtuYkbAahrWwnUSbFnv6x7U/H5/im5W9Cmu0
FUHR14VodfnrtdqLSL9qHc7oLTr5UrvKBhE8Dgnh4L2bzHyUX45UbTCPCKbRda0J
myDpmcoRHKiyk335nrTBEw2UXa/L828qOl3YiQIDAQABAoIBAC81ieXbImKdzfqO
ZWQWzBibp56cS18tsxVLknKv8wxPygdhtMhJgbkT+7kfo789NNn5Po+SR3Zqs1zJ
GWQ61AxvhQgLTsKMkP3VKOYW9ilQY+6CWqOOE0l/8T2+QBWZhlGhgfFRUrGTg37A
ZzuoqGkJk9nNbFhlGfbfGRWmh1tpG/0ASptOnDZYli31kncZf3qRJ+YZ0dF3JIW0
/avL1XBox4/z61RdjxDWNP9v9M35Jjx3+OR8Ko6mq59Zn2vj0ZK0S4vxwz0a3TvL
RkaHassVsyARVkkY/w1kVFfyRQjnR19ZQUY7b+Qiw38AryFJpNZ9t4Ma5SRm1nDq
PDwWoAECgYEA0515dEK6WMIdkxVplqYgiFP0dNQnDCF1R9b5tXGHu7QZ8hJLS2hf
JfQ/VFq2Kt99dyLw+wn16mUI/QMbgY7B9O2sDCCBNE7bU92Crdt+emGTWG3f8fm3
Tlp0JwDveOR6nfrHFaezj+/bKn4vni6rXiqmKz84Q7TE/VYG2f3ktokCgYEA27rc
LRyNF2d1AuaE6D40IaZi5oP17EqB/waFh55gcG7ItfcoofF8/nMjHG345KRKObyV
izMTppnQGIUI7zmIYR2zPUiEkeP+KibqY2fVy4ZnHT69Odo8VELo6sf7CaZY3Mjj
W86vp8J6+Xf3cIVF76R4qILKwtvlJMNzPLGnkgECgYEAyRQ/zmuBqsl5VMPp+06M
Zz5vcXwORoacbNEnonPoqEGwzcb4aQUaNHRsoPk5VG/dRpGbLs/+LuYmrlR/lJJU
Vypoa3WPkGbGHmDDxfRlsGB7pHFzdPj2Z6un51AKPXPN18Pt3PPnugQO28ff840h
JW+dSkbebeedr6RJCmcpJxECgYAPtSr6OplHfAjcXThRFelKIofdbL+O1cC3R3MS
P9srDnBgubt44DeMRRTUenQZfDkmKXoTSmJ0PXin2BLMbzN1pdbjYaTAfSj1QHTv
CEQ7WW9TouGKGjTH3USjTAqBJRgjKGVAceUSvA9oeBADRjO6rupFOZxfE7MszqAV
TanqAQKBgHKNLFb9xGmhpsGMbFq7MIXbTEiEtp2br6XfMUWiz2V8GC4aXqKSuV4I
kdjulhPG079HRWabxrqxv49z9Hb1w71iD6Yd/oDVzeXyvj/pfBaAit6qq9yEAyTT
2PaQ6pTUBR4lWDm0TCJa7MGGEwYuCsohk8X7c3OVfi0/+tLjpTSW
-----END RSA PRIVATE KEY-----`

var _ = Describe("Reconcile", func() {
	var managementK8sCli *k8sfake.Clientset
	var esK8sCli *relasticsearchfake.RESTClient
	var esCertSecret, gatewayCertSecret, voltronLinseedCertSecret *corev1.Secret
	var managementESConfigMap *corev1.ConfigMap
	var managementClientObjects []runtime.Object
	var mockESCli *elasticsearch.MockClient
	var mockESClientBuild *elasticsearch.MockClientBuilder
	var restartChan chan string

	BeforeEach(func() {
		// Make chan size >1 so we don't need to wait for a listener to insert
		restartChan = make(chan string, 5)
		esCertSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      resource.ElasticsearchCertSecret,
				Namespace: resource.OperatorNamespace,
			},
			Data: map[string][]byte{
				"tls.crt": []byte(cert),
				"tls.key": []byte(key),
			},
		}

		gatewayCertSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      resource.ESGatewayCertSecret,
				Namespace: resource.OperatorNamespace,
			},
			Data: map[string][]byte{
				"tls.crt": []byte(cert),
				"tls.key": []byte(key),
			},
		}

		voltronLinseedCertSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      resource.VoltronLinseedPublicCert,
				Namespace: resource.OperatorNamespace,
			},
			Data: map[string][]byte{
				"tls.crt": []byte(cert),
				"tls.key": []byte(key),
			},
		}

		managementESConfigMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      resource.ElasticsearchConfigMapName,
				Namespace: resource.OperatorNamespace,
			},
			Data: map[string]string{
				"clusterName": "cluster",
				"replicas":    "1",
				"shards":      "5",
			},
		}

		activeOperatorConfigMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "active-operator",
				Namespace: "calico-system",
			},
			Data: map[string]string{
				"active-namespace": resource.OperatorNamespace,
			},
		}
		managementClientObjects = []runtime.Object{
			esCertSecret,
			gatewayCertSecret,
			voltronLinseedCertSecret,
			managementESConfigMap,
			activeOperatorConfigMap,
		}

		var err error
		esK8sCli, err = relasticsearchfake.NewFakeRESTClient(&esv1.Elasticsearch{ObjectMeta: metav1.ObjectMeta{
			Name:              resource.DefaultTSEEInstanceName,
			Namespace:         resource.TigeraElasticsearchNamespace,
			CreationTimestamp: metav1.Now(),
		}})
		Expect(err).ShouldNot(HaveOccurred())

		mockESCli = elasticsearch.NewMockClient()
		mockESCli.On("CreateRoles", mock.Anything).Return(nil)
		mockESCli.On("CreateUser", mock.Anything).Return(nil)
		// GetUsers is currently only called inside cleanupDecommissionedElasticsearchusers so we only need to return
		// a non-empty list if we're specifically trying to test the functionality of that function
		mockESCli.On("GetUsers").Return([]elasticsearch.User{}, nil)

		mockESClientBuild = new(elasticsearch.MockClientBuilder)
		mockESClientBuild.On("Build").Return(mockESCli, nil)
	})

	JustBeforeEach(func() {
		managementK8sCli = k8sfake.NewSimpleClientset(managementClientObjects...)
	})

	AfterEach(func() {
		Expect(mockESCli.AssertExpectations(GinkgoT()))
	})

	Context("Management cluster configuration successfully created", func() {
		It("Creates the initial necessary configuration", func() {
			ctx := context.Background()

			es := &esv1.Elasticsearch{}
			err := esK8sCli.Get().Resource("elasticsearches").Namespace(resource.TigeraElasticsearchNamespace).Name(resource.DefaultTSEEInstanceName).Do(ctx).Into(es)
			Expect(err).ShouldNot(HaveOccurred())

			r := NewReconciler(mockESClientBuild, managementK8sCli, managementK8sCli, esK8sCli, restartChan, nil)

			Expect(r.Reconcile(types.NamespacedName{})).ShouldNot(HaveOccurred())

			assertManagementConfiguration(managementK8sCli, resource.OperatorNamespace, esCertSecret, gatewayCertSecret, managementESConfigMap)
		})

		It("Recreates the verification secrets if they're removed", func() {
			ctx := context.Background()

			es := &esv1.Elasticsearch{}
			err := esK8sCli.Get().Resource("elasticsearches").Namespace(resource.TigeraElasticsearchNamespace).Name(resource.DefaultTSEEInstanceName).Do(ctx).Into(es)
			Expect(err).ShouldNot(HaveOccurred())

			r := NewReconciler(mockESClientBuild, managementK8sCli, managementK8sCli, esK8sCli, restartChan, nil)

			Expect(r.Reconcile(types.NamespacedName{})).ShouldNot(HaveOccurred())

			// Assert the configuration is initially correct.
			assertManagementConfiguration(managementK8sCli, resource.OperatorNamespace, esCertSecret, gatewayCertSecret, managementESConfigMap)

			verificationSecretName := fmt.Sprintf("%s-gateway-verification-credentials", esusers.ElasticsearchUserNameFluentd)
			err = managementK8sCli.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).
				Delete(context.Background(), verificationSecretName, metav1.DeleteOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(r.Reconcile(types.NamespacedName{})).ShouldNot(HaveOccurred())

			// Assert that the configuration has been rectified.
			assertManagementConfiguration(managementK8sCli, resource.OperatorNamespace, esCertSecret, gatewayCertSecret, managementESConfigMap)
		})

		It("Rectifies the verification secrets if they're changed", func() {
			ctx := context.Background()

			es := &esv1.Elasticsearch{}
			err := esK8sCli.Get().Resource("elasticsearches").Namespace(resource.TigeraElasticsearchNamespace).Name(resource.DefaultTSEEInstanceName).Do(ctx).Into(es)
			Expect(err).ShouldNot(HaveOccurred())

			r := NewReconciler(mockESClientBuild, managementK8sCli, managementK8sCli, esK8sCli, restartChan, nil)

			Expect(r.Reconcile(types.NamespacedName{})).ShouldNot(HaveOccurred())

			// Assert the configuration is initially correct.
			assertManagementConfiguration(managementK8sCli, resource.OperatorNamespace, esCertSecret, gatewayCertSecret, managementESConfigMap)

			verificationSecretName := fmt.Sprintf("%s-gateway-verification-credentials", esusers.ElasticsearchUserNameFluentd)
			verificationSecret, err := managementK8sCli.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).
				Get(context.Background(), verificationSecretName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			verificationSecret.Data["password"] = []byte("foobar")

			_, err = managementK8sCli.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).
				Update(context.Background(), verificationSecret, metav1.UpdateOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(r.Reconcile(types.NamespacedName{})).ShouldNot(HaveOccurred())

			// Assert that the configuration has been rectified.
			assertManagementConfiguration(managementK8sCli, resource.OperatorNamespace, esCertSecret, gatewayCertSecret, managementESConfigMap)
		})

		It("should clean up decommissioned Elasticsearch users and secrets", func() {
			// Simulate an upgrade scenario by initializing the management and managed clusters with old ES users
			// and secrets
			mgmtClientObjs := managementClientObjects
			mgmtClientObjs = append(mgmtClientObjs, []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tigera-ee-curator-elasticsearch-access",
						Namespace: resource.TigeraElasticsearchNamespace,
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tigera-ee-curator-gateway-verification-credentials",
						Namespace: resource.TigeraElasticsearchNamespace,
					},
				},
			}...)
			managementK8sCli = k8sfake.NewSimpleClientset(mgmtClientObjs...)

			mgdClientObjs := []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tigera-ee-curator-access-gateway",
					Namespace: common.TigeraOperatorNamespace,
				},
			}}
			managedK8sCli := k8sfake.NewSimpleClientset(mgdClientObjs...)

			// We need to override what gets returned by GetUsers() so that we can test the functionality of our
			// deletion of decommissioned users so recreate the mock client here.
			mockESCli = elasticsearch.NewMockClient()
			mockESCli.On("CreateRoles", mock.Anything).Return(nil)
			mockESCli.On("CreateUser", mock.Anything).Return(nil)

			mockESClientBuild = new(elasticsearch.MockClientBuilder)
			mockESClientBuild.On("Build").Return(mockESCli, nil)

			curatorRole := elasticsearch.Role{
				Name: "tigera-ee-curator-secure",
				Definition: &elasticsearch.RoleDefinition{
					Cluster: []string{"monitor", "manage_index_templates"},
					Indices: []elasticsearch.RoleIndex{{
						Names:      []string{"tigera_secure_ee_*.*.*", "tigera_secure_ee_events.*"},
						Privileges: []string{"all"},
					}},
				},
			}

			curatorUser := elasticsearch.User{
				Username: "tigera-ee-curator-secure",
				Roles:    []elasticsearch.Role{curatorRole},
			}

			allESUsers := []elasticsearch.User{curatorUser}

			mockESCli.On("DeleteUser", curatorUser).Return(nil)
			mockESCli.On("DeleteRole", curatorRole).Return(nil)
			mockESCli.On("GetUsers").Return(allESUsers, nil)

			r := NewReconciler(mockESClientBuild, managementK8sCli, managedK8sCli, esK8sCli, restartChan, nil)
			Expect(r.Reconcile(types.NamespacedName{})).ShouldNot(HaveOccurred())

			// Now verify that the secrets associated with the decommissioned user have been deleted.
			_, err := managementK8sCli.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Get(context.Background(), "tigera-ee-curator-gateway-verification-credentials", metav1.GetOptions{})
			Expect(err).Should(HaveOccurred())

			_, err = managedK8sCli.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Get(context.Background(), "tigera-ee-curator-elasticsearch-access-gateway", metav1.GetOptions{})
			Expect(err).Should(HaveOccurred())

			_, err = managementK8sCli.CoreV1().Secrets(common.TigeraOperatorNamespace).Get(context.Background(), "tigera-ee-curator-elasticsearch-access", metav1.GetOptions{})
			Expect(err).Should(HaveOccurred())
		})
	})

	Context("Management cluster configuration successfully created with alternate operator namespace", func() {
		altOperatorNamespace := "alternate-operator"
		BeforeEach(func() {
			esCertSecret.Namespace = altOperatorNamespace
			gatewayCertSecret.Namespace = altOperatorNamespace
			managementESConfigMap.Namespace = altOperatorNamespace
			activeOperatorConfigMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "active-operator",
					Namespace: "calico-system",
				},
				Data: map[string]string{
					"active-namespace": altOperatorNamespace,
				},
			}
			managementClientObjects = []runtime.Object{
				esCertSecret,
				gatewayCertSecret,
				managementESConfigMap,
				activeOperatorConfigMap,
			}
		})
		It("Creates the initial necessary configuration", func() {
			ctx := context.Background()

			es := &esv1.Elasticsearch{}
			err := esK8sCli.Get().Resource("elasticsearches").Namespace(resource.TigeraElasticsearchNamespace).Name(resource.DefaultTSEEInstanceName).Do(ctx).Into(es)
			Expect(err).ShouldNot(HaveOccurred())

			r := NewReconciler(mockESClientBuild, managementK8sCli, managementK8sCli, esK8sCli, restartChan,
				func(r *reconciler) {
					r.managementOperatorNamespace = altOperatorNamespace
					r.managedOperatorNamespace = altOperatorNamespace
				})

			Expect(r.Reconcile(types.NamespacedName{})).ShouldNot(HaveOccurred())

			assertManagementConfiguration(managementK8sCli, altOperatorNamespace, esCertSecret, gatewayCertSecret, managementESConfigMap)
		})

		It("Recreates the verification secrets if they're removed", func() {
			ctx := context.Background()

			es := &esv1.Elasticsearch{}
			err := esK8sCli.Get().Resource("elasticsearches").Namespace(resource.TigeraElasticsearchNamespace).Name(resource.DefaultTSEEInstanceName).Do(ctx).Into(es)
			Expect(err).ShouldNot(HaveOccurred())

			r := NewReconciler(mockESClientBuild, managementK8sCli, managementK8sCli, esK8sCli, restartChan,
				func(r *reconciler) {
					r.managementOperatorNamespace = altOperatorNamespace
					r.managedOperatorNamespace = altOperatorNamespace
				})

			Expect(r.Reconcile(types.NamespacedName{})).ShouldNot(HaveOccurred())

			// Assert the configuration is initially correct.
			assertManagementConfiguration(managementK8sCli, altOperatorNamespace, esCertSecret, gatewayCertSecret, managementESConfigMap)

			verificationSecretName := fmt.Sprintf("%s-gateway-verification-credentials", esusers.ElasticsearchUserNameFluentd)
			err = managementK8sCli.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).
				Delete(context.Background(), verificationSecretName, metav1.DeleteOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(r.Reconcile(types.NamespacedName{})).ShouldNot(HaveOccurred())

			// Assert that the configuration has been rectified.
			assertManagementConfiguration(managementK8sCli, altOperatorNamespace, esCertSecret, gatewayCertSecret, managementESConfigMap)
		})

		It("Rectifies the verification secrets if they're changed", func() {
			ctx := context.Background()

			es := &esv1.Elasticsearch{}
			err := esK8sCli.Get().Resource("elasticsearches").Namespace(resource.TigeraElasticsearchNamespace).Name(resource.DefaultTSEEInstanceName).Do(ctx).Into(es)
			Expect(err).ShouldNot(HaveOccurred())

			r := NewReconciler(mockESClientBuild, managementK8sCli, managementK8sCli, esK8sCli, restartChan,
				func(r *reconciler) {
					r.managementOperatorNamespace = altOperatorNamespace
					r.managedOperatorNamespace = altOperatorNamespace
				})

			Expect(r.Reconcile(types.NamespacedName{})).ShouldNot(HaveOccurred())

			// Assert the configuration is initially correct.
			assertManagementConfiguration(managementK8sCli, altOperatorNamespace, esCertSecret, gatewayCertSecret, managementESConfigMap)

			verificationSecretName := fmt.Sprintf("%s-gateway-verification-credentials", esusers.ElasticsearchUserNameFluentd)
			verificationSecret, err := managementK8sCli.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).
				Get(context.Background(), verificationSecretName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			verificationSecret.Data["password"] = []byte("foobar")

			_, err = managementK8sCli.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).
				Update(context.Background(), verificationSecret, metav1.UpdateOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(r.Reconcile(types.NamespacedName{})).ShouldNot(HaveOccurred())

			// Assert that the configuration has been rectified.
			assertManagementConfiguration(managementK8sCli, altOperatorNamespace, esCertSecret, gatewayCertSecret, managementESConfigMap)
		})
	})

	Context("Managed cluster configuration successfully created", func() {
		var managedK8sCli *k8sfake.Clientset
		var managedESConfigMap *corev1.ConfigMap
		BeforeEach(func() {
			managedESConfigMap = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resource.ElasticsearchConfigMapName,
					Namespace: resource.OperatorNamespace,
				},
				Data: map[string]string{
					"clusterName": "managed-1",
					"replicas":    "1",
					"shards":      "5",
				},
			}
			managedK8sCli = k8sfake.NewSimpleClientset()
		})

		It("creates all the necessary Secrets and ConfigMaps in the managed cluster when they don't exist", func() {
			ctx := context.Background()

			es := &esv1.Elasticsearch{}
			err := esK8sCli.Get().Resource("elasticsearches").Namespace(resource.TigeraElasticsearchNamespace).Name(resource.DefaultTSEEInstanceName).Do(ctx).Into(es)
			Expect(err).ShouldNot(HaveOccurred())

			r := NewReconciler(mockESClientBuild, managementK8sCli, managedK8sCli, esK8sCli, restartChan,
				func(r *reconciler) {
					r.clusterName = "managed-1"
					r.management = false
				})

			err = r.Reconcile(types.NamespacedName{})
			Expect(err).ShouldNot(HaveOccurred())

			assertManagedConfiguration(managedK8sCli, managementK8sCli, resource.OperatorNamespace, esCertSecret, gatewayCertSecret, managedESConfigMap)
		})

		It("regenerates user Secrets if the Secret's hash is stale", func() {
			r := NewReconciler(mockESClientBuild, managementK8sCli, managedK8sCli, esK8sCli, restartChan,
				func(r *reconciler) {
					r.clusterName = "managed-1"
					r.management = false
				})

			err := r.Reconcile(types.NamespacedName{})
			Expect(err).ShouldNot(HaveOccurred())

			assertManagedConfiguration(managedK8sCli, managementK8sCli, resource.OperatorNamespace, esCertSecret, gatewayCertSecret, managedESConfigMap)

			ctx := context.Background()

			fluentdSecret, err := managedK8sCli.CoreV1().Secrets(resource.OperatorNamespace).Get(ctx, fmt.Sprintf("%s-elasticsearch-access", esusers.ElasticsearchUserNameFluentd), metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			fluentdSecret.Labels[UserChangeHashLabel] = "differentlabel"
			_, err = managedK8sCli.CoreV1().Secrets(resource.OperatorNamespace).Update(ctx, fluentdSecret, metav1.UpdateOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			err = r.Reconcile(types.NamespacedName{})
			Expect(err).ShouldNot(HaveOccurred())

			newFluentdSecret, err := managedK8sCli.CoreV1().Secrets(resource.OperatorNamespace).Get(ctx, fmt.Sprintf("%s-elasticsearch-access", esusers.ElasticsearchUserNameFluentd), metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(newFluentdSecret.Labels[UserChangeHashLabel]).ShouldNot(Equal(fluentdSecret.Labels[UserChangeHashLabel]))
			Expect(newFluentdSecret.Data).ShouldNot(Equal(fluentdSecret.Data))
		})

		It("does not regenerate the user secrets when the owner reference hasn't changed", func() {
			r := NewReconciler(mockESClientBuild, managementK8sCli, managedK8sCli, esK8sCli, restartChan,
				func(r *reconciler) {
					r.clusterName = "managed-1"
					r.ownerReference = "reference1"
					r.management = false
				})
			err := r.Reconcile(types.NamespacedName{})
			Expect(err).ShouldNot(HaveOccurred())

			assertManagedConfiguration(managedK8sCli, managementK8sCli, resource.OperatorNamespace, esCertSecret, gatewayCertSecret, managedESConfigMap)

			ctx := context.Background()

			fluentdSecret, err := managedK8sCli.CoreV1().Secrets(resource.OperatorNamespace).Get(ctx, fmt.Sprintf("%s-elasticsearch-access", esusers.ElasticsearchUserNameFluentd), metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			r = NewReconciler(mockESClientBuild, managementK8sCli, managedK8sCli, esK8sCli, restartChan,
				func(r *reconciler) {
					r.clusterName = "managed-1"
					r.ownerReference = "reference1"
					r.management = false
				})
			err = r.Reconcile(types.NamespacedName{})
			Expect(err).ShouldNot(HaveOccurred())

			newFluentdSecret, err := managedK8sCli.CoreV1().Secrets(resource.OperatorNamespace).Get(ctx, fmt.Sprintf("%s-elasticsearch-access", esusers.ElasticsearchUserNameFluentd), metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(newFluentdSecret.Labels[UserChangeHashLabel]).Should(Equal(fluentdSecret.Labels[UserChangeHashLabel]))
			Expect(newFluentdSecret.Data).Should(Equal(fluentdSecret.Data))
		})

		It("regenerates the user secrets when the owner reference has changed", func() {
			r := NewReconciler(mockESClientBuild, managementK8sCli, managedK8sCli, esK8sCli, restartChan,
				func(r *reconciler) {
					r.clusterName = "managed-1"
					r.ownerReference = "reference1"
					r.management = false
				})

			err := r.Reconcile(types.NamespacedName{})
			Expect(err).ShouldNot(HaveOccurred())

			assertManagedConfiguration(managedK8sCli, managementK8sCli, resource.OperatorNamespace, esCertSecret, gatewayCertSecret, managedESConfigMap)

			ctx := context.Background()

			fluentdSecret, err := managedK8sCli.CoreV1().Secrets(resource.OperatorNamespace).Get(ctx, fmt.Sprintf("%s-elasticsearch-access", esusers.ElasticsearchUserNameFluentd), metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			r = NewReconciler(mockESClientBuild, managementK8sCli, managedK8sCli, esK8sCli, restartChan,
				func(r *reconciler) {
					r.clusterName = "managed-1"
					r.ownerReference = "reference2"
					r.management = false
				})
			err = r.Reconcile(types.NamespacedName{})
			Expect(err).ShouldNot(HaveOccurred())

			newFluentdSecret, err := managedK8sCli.CoreV1().Secrets(resource.OperatorNamespace).Get(ctx, fmt.Sprintf("%s-elasticsearch-access", esusers.ElasticsearchUserNameFluentd), metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(newFluentdSecret.Labels[UserChangeHashLabel]).ShouldNot(Equal(fluentdSecret.Labels[UserChangeHashLabel]))
			Expect(newFluentdSecret.Data).ShouldNot(Equal(fluentdSecret.Data))
		})

		It("Creates verification secrets", func() {
			ctx := context.Background()

			es := &esv1.Elasticsearch{}
			err := esK8sCli.Get().Resource("elasticsearches").Namespace(resource.TigeraElasticsearchNamespace).Name(resource.DefaultTSEEInstanceName).Do(ctx).Into(es)
			Expect(err).ShouldNot(HaveOccurred())

			r := NewReconciler(mockESClientBuild, managementK8sCli, managedK8sCli, esK8sCli, restartChan,
				func(r *reconciler) {
					r.clusterName = "managed-1"
					r.management = false
				})

			err = r.Reconcile(types.NamespacedName{})
			Expect(err).ShouldNot(HaveOccurred())

			assertManagedConfiguration(managedK8sCli, managementK8sCli, resource.OperatorNamespace, esCertSecret, gatewayCertSecret, managedESConfigMap)
		})

		It("propagates voltron secrets with new name when no version skew", func() {
			managedClientSetFactory := k8s.NewMockClientSetFactory(GinkgoT())

			managedClusterName := "managed-1"

			mockK8sClient := k8sfake.NewSimpleClientset()
			cs := fake.NewSimpleClientset([]runtime.Object{
				&v3.ClusterInformation{
					ObjectMeta: metav1.ObjectMeta{
						Name: "default",
					},
					Spec: v3.ClusterInformationSpec{
						CalicoEnterpriseVersion: "v3.23.0",
					},
				},
			}...)
			mockClientSet := testutils.ClientSetSet{Interface: mockK8sClient, Calico: cs}

			managedClientSetFactory.On("NewClientSetForApplication", managedClusterName).Return(&mockClientSet, nil)

			r := NewReconciler(mockESClientBuild, managementK8sCli, managedK8sCli, esK8sCli, restartChan,
				func(r *reconciler) {
					r.clusterName = managedClusterName
					r.management = false
					r.managedClientSetFactory = managedClientSetFactory
				})

			err := r.Reconcile(types.NamespacedName{})
			Expect(err).ShouldNot(HaveOccurred())

			ctx := context.Background()
			_, err = managedK8sCli.CoreV1().Secrets(resource.OperatorNamespace).Get(ctx, resource.VoltronLinseedPublicCert, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("propagates voltron secrets with old name with version skew", func() {
			managedClientSetFactory := k8s.NewMockClientSetFactory(GinkgoT())

			managedClusterName := "managed-1"

			mockK8sClient := k8sfake.NewSimpleClientset()
			cs := fake.NewSimpleClientset([]runtime.Object{
				&v3.ClusterInformation{
					ObjectMeta: metav1.ObjectMeta{
						Name: "default",
					},
					Spec: v3.ClusterInformationSpec{
						CalicoEnterpriseVersion: "v3.19.0",
					},
				},
			}...)
			mockClientSet := testutils.ClientSetSet{Interface: mockK8sClient, Calico: cs}

			managedClientSetFactory.On("NewClientSetForApplication", managedClusterName).Return(&mockClientSet, nil)

			r := NewReconciler(mockESClientBuild, managementK8sCli, managedK8sCli, esK8sCli, restartChan,
				func(r *reconciler) {
					r.clusterName = managedClusterName
					r.management = false
					r.managedClientSetFactory = managedClientSetFactory
				})

			err := r.Reconcile(types.NamespacedName{})
			Expect(err).ShouldNot(HaveOccurred())

			ctx := context.Background()
			_, err = managedK8sCli.CoreV1().Secrets(resource.OperatorNamespace).Get(ctx, resource.VoltronLinseedPublicCertOld, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
		})
	})

	Context("Managed cluster configuration successfully created with alternate operator namespace", func() {
		var managedK8sCli *k8sfake.Clientset
		var managedESConfigMap *corev1.ConfigMap
		altOperatorNamespace := "alternate-operator"
		BeforeEach(func() {
			managedESConfigMap = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resource.ElasticsearchConfigMapName,
					Namespace: resource.OperatorNamespace,
				},
				Data: map[string]string{
					"clusterName": "managed-1",
					"replicas":    "1",
					"shards":      "5",
				},
			}

			activeOperatorConfigMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "active-operator",
					Namespace: "calico-system",
				},
				Data: map[string]string{
					"active-namespace": altOperatorNamespace,
				},
			}
			managedK8sCli = k8sfake.NewSimpleClientset(activeOperatorConfigMap)
		})

		It("creates all the necessary Secrets and ConfigMaps in the managed cluster when they don't exist", func() {
			ctx := context.Background()

			es := &esv1.Elasticsearch{}
			err := esK8sCli.Get().Resource("elasticsearches").Namespace(resource.TigeraElasticsearchNamespace).Name(resource.DefaultTSEEInstanceName).Do(ctx).Into(es)
			Expect(err).ShouldNot(HaveOccurred())

			r := NewReconciler(mockESClientBuild, managementK8sCli, managedK8sCli, esK8sCli, restartChan,
				func(r *reconciler) {
					r.clusterName = "managed-1"
					r.management = false
					r.managedOperatorNamespace = altOperatorNamespace
				})

			err = r.Reconcile(types.NamespacedName{})
			Expect(err).ShouldNot(HaveOccurred())

			assertManagedConfiguration(managedK8sCli, managementK8sCli, altOperatorNamespace, esCertSecret, gatewayCertSecret, managedESConfigMap)
		})

		It("regenerates user Secrets if the Secret's hash is stale", func() {
			r := NewReconciler(mockESClientBuild, managementK8sCli, managedK8sCli, esK8sCli, restartChan,
				func(r *reconciler) {
					r.clusterName = "managed-1"
					r.management = false
					r.managedOperatorNamespace = altOperatorNamespace
				})

			err := r.Reconcile(types.NamespacedName{})
			Expect(err).ShouldNot(HaveOccurred())

			assertManagedConfiguration(managedK8sCli, managementK8sCli, altOperatorNamespace, esCertSecret, gatewayCertSecret, managedESConfigMap)

			ctx := context.Background()

			fluentdSecret, err := managedK8sCli.CoreV1().Secrets(altOperatorNamespace).Get(ctx, fmt.Sprintf("%s-elasticsearch-access", esusers.ElasticsearchUserNameFluentd), metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			fluentdSecret.Labels[UserChangeHashLabel] = "differentlabel"
			_, err = managedK8sCli.CoreV1().Secrets(altOperatorNamespace).Update(ctx, fluentdSecret, metav1.UpdateOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			err = r.Reconcile(types.NamespacedName{})
			Expect(err).ShouldNot(HaveOccurred())

			newFluentdSecret, err := managedK8sCli.CoreV1().Secrets(altOperatorNamespace).Get(ctx, fmt.Sprintf("%s-elasticsearch-access", esusers.ElasticsearchUserNameFluentd), metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(newFluentdSecret.Labels[UserChangeHashLabel]).ShouldNot(Equal(fluentdSecret.Labels[UserChangeHashLabel]))
			Expect(newFluentdSecret.Data).ShouldNot(Equal(fluentdSecret.Data))
		})

		It("does not regenerate the user secrets when the owner reference hasn't changed", func() {
			r := NewReconciler(mockESClientBuild, managementK8sCli, managedK8sCli, esK8sCli, restartChan,
				func(r *reconciler) {
					r.clusterName = "managed-1"
					r.ownerReference = "reference1"
					r.management = false
					r.managedOperatorNamespace = altOperatorNamespace
				})
			err := r.Reconcile(types.NamespacedName{})
			Expect(err).ShouldNot(HaveOccurred())

			assertManagedConfiguration(managedK8sCli, managementK8sCli, altOperatorNamespace, esCertSecret, gatewayCertSecret, managedESConfigMap)

			ctx := context.Background()

			fluentdSecret, err := managedK8sCli.CoreV1().Secrets(altOperatorNamespace).Get(ctx, fmt.Sprintf("%s-elasticsearch-access", esusers.ElasticsearchUserNameFluentd), metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			r = NewReconciler(mockESClientBuild, managementK8sCli, managedK8sCli, esK8sCli, restartChan,
				func(r *reconciler) {
					r.clusterName = "managed-1"
					r.ownerReference = "reference1"
					r.management = false
					r.managedOperatorNamespace = altOperatorNamespace
				})
			err = r.Reconcile(types.NamespacedName{})
			Expect(err).ShouldNot(HaveOccurred())

			newFluentdSecret, err := managedK8sCli.CoreV1().Secrets(altOperatorNamespace).Get(ctx, fmt.Sprintf("%s-elasticsearch-access", esusers.ElasticsearchUserNameFluentd), metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(newFluentdSecret.Labels[UserChangeHashLabel]).Should(Equal(fluentdSecret.Labels[UserChangeHashLabel]))
			Expect(newFluentdSecret.Data).Should(Equal(fluentdSecret.Data))
		})

		It("regenerates the user secrets when the owner reference has changed", func() {
			r := NewReconciler(mockESClientBuild, managementK8sCli, managedK8sCli, esK8sCli, restartChan,
				func(r *reconciler) {
					r.clusterName = "managed-1"
					r.ownerReference = "reference1"
					r.management = false
					r.managedOperatorNamespace = altOperatorNamespace
				})

			err := r.Reconcile(types.NamespacedName{})
			Expect(err).ShouldNot(HaveOccurred())

			assertManagedConfiguration(managedK8sCli, managementK8sCli, altOperatorNamespace, esCertSecret, gatewayCertSecret, managedESConfigMap)

			ctx := context.Background()

			fluentdSecret, err := managedK8sCli.CoreV1().Secrets(altOperatorNamespace).Get(ctx, fmt.Sprintf("%s-elasticsearch-access", esusers.ElasticsearchUserNameFluentd), metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			r = NewReconciler(mockESClientBuild, managementK8sCli, managedK8sCli, esK8sCli, restartChan,
				func(r *reconciler) {
					r.clusterName = "managed-1"
					r.ownerReference = "reference2"
					r.management = false
					r.managedOperatorNamespace = altOperatorNamespace
				})
			err = r.Reconcile(types.NamespacedName{})
			Expect(err).ShouldNot(HaveOccurred())

			newFluentdSecret, err := managedK8sCli.CoreV1().Secrets(altOperatorNamespace).Get(ctx, fmt.Sprintf("%s-elasticsearch-access", esusers.ElasticsearchUserNameFluentd), metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(newFluentdSecret.Labels[UserChangeHashLabel]).ShouldNot(Equal(fluentdSecret.Labels[UserChangeHashLabel]))
			Expect(newFluentdSecret.Data).ShouldNot(Equal(fluentdSecret.Data))
		})

		It("Creates verification secrets", func() {
			ctx := context.Background()

			es := &esv1.Elasticsearch{}
			err := esK8sCli.Get().Resource("elasticsearches").Namespace(resource.TigeraElasticsearchNamespace).Name(resource.DefaultTSEEInstanceName).Do(ctx).Into(es)
			Expect(err).ShouldNot(HaveOccurred())

			r := NewReconciler(mockESClientBuild, managementK8sCli, managedK8sCli, esK8sCli, restartChan,
				func(r *reconciler) {
					r.clusterName = "managed-1"
					r.management = false
					r.managedOperatorNamespace = altOperatorNamespace
				})

			err = r.Reconcile(types.NamespacedName{})
			Expect(err).ShouldNot(HaveOccurred())

			assertManagedConfiguration(managedK8sCli, managementK8sCli, altOperatorNamespace, esCertSecret, gatewayCertSecret, managedESConfigMap)
		})
	})
})

func assertManagementConfiguration(managementK8sCli kubernetes.Interface, operatorNs string, expectedESCertSecret *corev1.Secret, expectedGatewayCertSecret *corev1.Secret, expectedESConfigMap *corev1.ConfigMap) {
	ctx := context.Background()

	publicUserSecrets, err := managementK8sCli.CoreV1().Secrets(operatorNs).List(ctx, metav1.ListOptions{LabelSelector: ElasticsearchUserNameLabel})
	Expect(err).ShouldNot(HaveOccurred())

	publicUserSecretsMap := map[string]corev1.Secret{}
	for _, publicUserSecret := range publicUserSecrets.Items {
		username := string(publicUserSecret.Data["username"])
		Expect(username).ShouldNot(BeEmpty())
		publicUserSecretsMap[username] = publicUserSecret
	}

	verificationSecrets, err := managementK8sCli.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).
		List(ctx, metav1.ListOptions{LabelSelector: ESGatewaySelectorLabel})
	Expect(err).ShouldNot(HaveOccurred())

	verificationSecretsMap := map[string]corev1.Secret{}
	for _, verificationSecret := range verificationSecrets.Items {
		username := string(verificationSecret.Data["username"])
		Expect(username).ShouldNot(BeEmpty())
		verificationSecretsMap[username] = verificationSecret
	}

	// Test the public and verification secrets both exist for every user, and that those two secrets match (i.e. that
	// the verification secrets hashed password matches the original).
	privateUserMap, publicUserMap := esusers.ElasticsearchUsers("cluster", true)
	for _, user := range publicUserMap {
		publicUserSecret, exists := publicUserSecretsMap[user.Username]
		Expect(exists).Should(BeTrue())

		Expect(user.Username).Should(Equal(string(publicUserSecret.Data["username"])))
		Expect(publicUserSecret.Data["password"]).ShouldNot(BeEmpty())

		verificationSecret, exists := verificationSecretsMap[user.Username]
		Expect(exists).Should(BeTrue())

		Expect(user.Username).Should(Equal(string(verificationSecret.Data["username"])))
		Expect(verificationSecret.Data["password"]).ShouldNot(BeEmpty())

		Expect(bcrypt.CompareHashAndPassword(verificationSecret.Data["password"], publicUserSecret.Data["password"]))
	}

	privateUserSecrets, err := managementK8sCli.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).
		List(ctx, metav1.ListOptions{LabelSelector: ElasticsearchUserNameLabel})
	Expect(err).ShouldNot(HaveOccurred())

	for _, userSecret := range privateUserSecrets.Items {
		userName := userSecret.Labels[ElasticsearchUserNameLabel]
		if userName == "tigera-ee-ad-job" {
			// The secret with user name tigera-ee-ad-job only exists because we have
			// buggy operator code in Enterprise releases prior to 3.18ep2 that requires
			// that secret to exist.  Specifically, in an MCM setup where the management
			// cluster is >=3.18ep2 and someone then tries to provision a managed
			// cluster with <3.18ep2, the managed cluster install will fail if this
			// secret does not exist in the management cluster.
			//
			// Therefore kube-controllers continues to provision that secret - to make
			// the backlevel operators happy - but it does not provision any of the
			// corresponding 'private' resources, and hence we skip the rest of this
			// loop iteration.
			continue
		}
		user, exists := privateUserMap[esusers.ElasticsearchUserName(userName)]

		Expect(exists).Should(BeTrue(), fmt.Sprintf("missing privateUserMap for %v (%v)", esusers.ElasticsearchUserName(userName), userName))
		if strings.HasSuffix(userSecret.Name, esusers.ElasticsearchSecureUserSuffix) {
			Expect(user.Username).Should(Equal(string(userSecret.Data["username"])))
		}
	}

	esCertSecret, err := managementK8sCli.CoreV1().Secrets(operatorNs).Get(ctx, resource.ElasticsearchCertSecret, metav1.GetOptions{})
	Expect(err).ShouldNot(HaveOccurred())
	Expect(esCertSecret.Data).Should(Equal(expectedESCertSecret.Data))

	gatewayCertSecret, err := managementK8sCli.CoreV1().Secrets(operatorNs).Get(ctx, resource.ESGatewayCertSecret, metav1.GetOptions{})
	Expect(err).ShouldNot(HaveOccurred())
	Expect(gatewayCertSecret.Data).Should(Equal(expectedGatewayCertSecret.Data))

	managementESConfigMap, err := managementK8sCli.CoreV1().ConfigMaps(operatorNs).Get(ctx, resource.ElasticsearchConfigMapName, metav1.GetOptions{})
	Expect(err).ShouldNot(HaveOccurred())
	Expect(managementESConfigMap.Data).Should(Equal(map[string]string{
		"clusterName": "cluster",
		"replicas":    expectedESConfigMap.Data["replicas"],
		"shards":      expectedESConfigMap.Data["shards"],
	}))
}

func assertManagedConfiguration(managedk8sCli, managementK8sCli kubernetes.Interface, managedOperatorNs string, expectedESCertSecret *corev1.Secret, expectedGatewayCertSecret *corev1.Secret, expectedESConfigMap *corev1.ConfigMap) {
	ctx := context.Background()

	publicUserSecrets, err := managedk8sCli.CoreV1().Secrets(managedOperatorNs).List(ctx, metav1.ListOptions{LabelSelector: ElasticsearchUserNameLabel})
	Expect(err).ShouldNot(HaveOccurred())

	publicUserSecretsMap := map[string]corev1.Secret{}
	for _, publicUserSecret := range publicUserSecrets.Items {
		username := string(publicUserSecret.Data["username"])
		Expect(username).ShouldNot(BeEmpty())
		publicUserSecretsMap[username] = publicUserSecret
	}

	verificationSecrets, err := managementK8sCli.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).
		List(ctx, metav1.ListOptions{LabelSelector: ESGatewaySelectorLabel})
	Expect(err).ShouldNot(HaveOccurred())

	verificationSecretsMap := map[string]corev1.Secret{}
	for _, verificationSecret := range verificationSecrets.Items {
		username := string(verificationSecret.Data["username"])
		Expect(username).ShouldNot(BeEmpty())
		verificationSecretsMap[username] = verificationSecret
	}

	// Test user secrets are created
	privateUserMap, publicUserMap := esusers.ElasticsearchUsers("managed-1", false)
	for _, user := range publicUserMap {
		publicUserSecret, exists := publicUserSecretsMap[user.Username]
		Expect(exists).Should(BeTrue())

		Expect(user.Username).Should(Equal(string(publicUserSecret.Data["username"])))
		Expect(publicUserSecret.Data["password"]).ShouldNot(BeEmpty())

		verificationSecret, exists := verificationSecretsMap[user.Username]
		Expect(exists).Should(BeTrue())

		Expect(user.Username).Should(Equal(string(verificationSecret.Data["username"])))
		Expect(verificationSecret.Data["password"]).ShouldNot(BeEmpty())

		Expect(bcrypt.CompareHashAndPassword(verificationSecret.Data["password"], publicUserSecret.Data["password"]))
	}

	privateUserSecrets, err := managementK8sCli.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).List(ctx, metav1.ListOptions{LabelSelector: ElasticsearchUserNameLabel})
	Expect(err).ShouldNot(HaveOccurred())

	for _, userSecret := range privateUserSecrets.Items {
		userName := userSecret.Labels[ElasticsearchUserNameLabel]
		if userName == "tigera-ee-ad-job" {
			// The secret with user name tigera-ee-ad-job only exists because we have
			// buggy operator code in Enterprise releases prior to 3.18ep2 that requires
			// that secret to exist.  Specifically, in an MCM setup where the management
			// cluster is >=3.18ep2 and someone then tries to provision a managed
			// cluster with <3.18ep2, the managed cluster install will fail if this
			// secret does not exist in the management cluster.
			//
			// Therefore kube-controllers continues to provision that secret - to make
			// the backlevel operators happy - but it does not provision any of the
			// corresponding 'private' resources, and hence we skip the rest of this
			// loop iteration.
			continue
		}
		user, exists := privateUserMap[esusers.ElasticsearchUserName(userName)]

		Expect(exists).Should(BeTrue(), fmt.Sprintf("missing privateUserMap for %v (%v)", esusers.ElasticsearchUserName(userName), userName))
		if strings.HasSuffix(userSecret.Name, esusers.ElasticsearchSecureUserSuffix) {
			Expect(user.Username).Should(Equal(string(userSecret.Data["username"])))
		}
	}

	esCertSecret, err := managedk8sCli.CoreV1().Secrets(managedOperatorNs).Get(ctx, resource.ElasticsearchCertSecret, metav1.GetOptions{})
	Expect(err).ShouldNot(HaveOccurred())
	Expect(esCertSecret.Data).Should(Equal(expectedESCertSecret.Data))

	gatewayCertSecret, err := managedk8sCli.CoreV1().Secrets(managedOperatorNs).Get(ctx, resource.ESGatewayCertSecret, metav1.GetOptions{})
	Expect(err).ShouldNot(HaveOccurred())
	Expect(gatewayCertSecret.Data).Should(Equal(expectedGatewayCertSecret.Data))

	managedESConfigMap, err := managedk8sCli.CoreV1().ConfigMaps(managedOperatorNs).Get(ctx, resource.ElasticsearchConfigMapName, metav1.GetOptions{})
	Expect(err).ShouldNot(HaveOccurred())
	Expect(managedESConfigMap.Data).Should(Equal(map[string]string{
		"clusterName": "managed-1",
		"replicas":    expectedESConfigMap.Data["replicas"],
		"shards":      expectedESConfigMap.Data["shards"],
	}))
}

var _ = Describe("test user hash function", func() {
	It("should detect changes in role definitions", func() {
		createUser := func() elasticsearch.User {
			return elasticsearch.User{
				Username: "a",
				Password: "b",
				FullName: "c",
				Roles: []elasticsearch.Role{
					{
						Name: "d",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"e"},
							Indices: []elasticsearch.RoleIndex{
								{
									Names:      []string{"f"},
									Privileges: []string{"g"},
								},
							},
							Applications: []elasticsearch.Application{
								{
									Application: "h",
									Resources:   []string{"i"},
									Privileges:  []string{"j"},
								},
							},
						},
					},
				},
				DirectConnection: false,
			}
		}
		u1 := createUser()
		u2 := createUser()
		r := reconciler{}
		hash1, err := r.calculateUserChangeHash(u1)
		Expect(err).NotTo(HaveOccurred())
		hash2, err := r.calculateUserChangeHash(u2)
		Expect(err).NotTo(HaveOccurred())
		Expect(hash1).To(Equal(hash2))
		u2.Roles[0].Definition.Indices[0].Privileges = append(u2.Roles[0].Definition.Indices[0].Privileges, "new-privilege")
		hash2, err = r.calculateUserChangeHash(u2)
		Expect(err).NotTo(HaveOccurred())
		Expect(hash1).NotTo(Equal(hash2))
	})
})
