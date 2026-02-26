// Copyright (c) 2018-2020 Tigera, Inc. All rights reserved.

package node

import (
	"context"
	"regexp"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/pkg/api/v1/endpoints"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var (
	eventuallyTimeout   = "15s"
	eventuallyPoll      = "500ms"
	consistentlyTimeout = "2s"
	consistentlyPoll    = "500ms"

	node1Name = "node-1"
	node2Name = "node-2"
	ns1Name   = "ns-1"
	ns2Name   = "ns-2"
	ctx       = context.Background()

	// svc1 has the federation label
	svc1 = &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"federate": "yes",
			},
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Name:     "port1",
					Port:     1234,
					Protocol: v1.ProtocolUDP,
				},
				{
					Name:     "port2",
					Port:     1234,
					Protocol: v1.ProtocolTCP,
				},
				{
					Name:     "port3",
					Port:     1200,
					Protocol: v1.ProtocolTCP,
				},
			},
		},
	}

	eps1 = &v1.Endpoints{ //nolint:staticcheck
		ObjectMeta: metav1.ObjectMeta{},
		Subsets: []v1.EndpointSubset{ //nolint:staticcheck
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP:       "1.0.0.1",
						NodeName: &node1Name,
					},
				},
				NotReadyAddresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP:       "1.0.0.2",
						NodeName: &node2Name,
						TargetRef: &v1.ObjectReference{
							Kind:      "Pod",
							Namespace: ns1Name,
							Name:      "pod1",
						},
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port1",
						Port:     1234,
						Protocol: v1.ProtocolUDP,
					},
				},
			},
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP:       "1.0.0.1",
						NodeName: &node1Name,
					},
				},
				NotReadyAddresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP:       "1.0.0.2",
						NodeName: &node2Name,
						TargetRef: &v1.ObjectReference{
							Kind:      "Pod",
							Namespace: ns1Name,
							Name:      "pod1",
						},
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port3",
						Port:     1200,
						Protocol: v1.ProtocolTCP,
					},
				},
			},
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "2.0.0.1",
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port2",
						Port:     1234,
						Protocol: v1.ProtocolTCP,
					},
				},
			},
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "3.0.0.1",
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port3",
						Port:     1200,
						Protocol: v1.ProtocolTCP,
					},
				},
			},
		},
	}

	// svc2 has the federation label and a different set of endpoints from svc1
	svc2 = &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"federate": "yes",
			},
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Name:     "port1",
					Port:     1234,
					Protocol: v1.ProtocolUDP,
				},
				{
					Name:     "port2",
					Port:     1234,
					Protocol: v1.ProtocolTCP,
				},
				{
					Name:     "port3",
					Port:     1200,
					Protocol: v1.ProtocolTCP,
				},
			},
		},
	}

	eps2 = &v1.Endpoints{ //nolint:staticcheck
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"federate": "yes",
			},
		},
		Subsets: []v1.EndpointSubset{ //nolint:staticcheck
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP:       "10.10.10.1",
						NodeName: &node1Name,
					},
				},
				NotReadyAddresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP:       "10.10.10.2",
						NodeName: &node2Name,
						TargetRef: &v1.ObjectReference{
							Kind:      "Pod",
							Namespace: ns1Name,
							Name:      "pod1",
						},
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port1",
						Port:     1234,
						Protocol: v1.ProtocolUDP,
					},
				},
			},
		},
	}
)

var _ = Describe("[federation] kube-controllers Federated Services FV tests", func() {
	var (
		localEtcd            *containers.Container
		localApiserver       *containers.Container
		localCalicoClient    client.Interface
		localK8sClient       *kubernetes.Clientset
		federationController *containers.Container
		remoteEtcd           *containers.Container
		remoteApiserver      *containers.Container
		remoteK8sClient      *kubernetes.Clientset
		remoteKubeconfig     string
		localKubeconfig      string
		cleanupRC, cleanupLC func()
	)

	getSubsets := func(namespace, name string) []v1.EndpointSubset { //nolint:staticcheck
		eps, err := localK8sClient.CoreV1().Endpoints(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil && kerrors.IsNotFound(err) {
			return nil
		}
		Expect(err).NotTo(HaveOccurred())
		return endpoints.RepackSubsets(eps.Subsets)
	}

	getSubsetsFn := func(namespace, name string) func() []v1.EndpointSubset { //nolint:staticcheck
		return func() []v1.EndpointSubset { //nolint:staticcheck
			return getSubsets(namespace, name)
		}
	}

	setup := func(isCalicoEtcdDatastore bool) {
		// Create local etcd and run the local apiserver. Wait for the API server to come online.
		localEtcd = testutils.RunEtcd()
		localApiserver = testutils.RunK8sApiserver(localEtcd.IP)

		// Write out a kubeconfig file for the local API server, and create a k8s client.
		localKubeconfig, cleanupLC = testutils.BuildKubeconfig(localApiserver.IP)

		var err error
		localK8sClient, err = testutils.GetK8sClient(localKubeconfig)
		Expect(err).NotTo(HaveOccurred())

		// Create remote etcd and run the remote apiserver.
		remoteEtcd = testutils.RunEtcd()
		remoteApiserver = testutils.RunK8sApiserver(remoteEtcd.IP)

		// Write out a kubeconfig file for the remote API server.
		remoteKubeconfig, cleanupRC = testutils.BuildKubeconfig(remoteApiserver.IP)
		remoteK8sClient, err = testutils.GetK8sClient(remoteKubeconfig)
		Expect(err).NotTo(HaveOccurred())

		// Wait for the api servers to be available.
		Eventually(func() error {
			_, err := localK8sClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
			return err
		}, eventuallyTimeout, eventuallyPoll).Should(BeNil())
		Eventually(func() error {
			_, err := remoteK8sClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
			return err
		}, eventuallyTimeout, eventuallyPoll).Should(BeNil())

		if !isCalicoEtcdDatastore {
			testutils.ApplyCRDs(localApiserver)
		}

		// Create the appropriate local Calico client depending on whether this is an etcd or kdd test.
		if isCalicoEtcdDatastore {
			localCalicoClient = testutils.GetCalicoClient(apiconfig.EtcdV3, localEtcd.IP, localKubeconfig)
		} else {
			localCalicoClient = testutils.GetCalicoKubernetesClient(localKubeconfig)
		}

		// Run the federation controller on the local cluster.
		federationController = testutils.RunFederationController(
			localEtcd.IP,
			localKubeconfig,
			[]string{remoteKubeconfig},
			isCalicoEtcdDatastore,
		)

		// Create two test namespaces in both kubernetes clusters.
		ns := &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: ns1Name,
			},
			Spec: v1.NamespaceSpec{},
		}
		_, err = localK8sClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		_, err = remoteK8sClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		ns = &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: ns2Name,
			},
			Spec: v1.NamespaceSpec{},
		}
		_, err = localK8sClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		_, err = remoteK8sClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
	}

	makeService := func(base *v1.Service, name string, prev *v1.Service) *v1.Service {
		copy := base.DeepCopy()
		if prev == nil {
			copy.Name = name
			return copy
		}
		copy.ObjectMeta = *prev.ObjectMeta.DeepCopy()
		return copy
	}
	makeEndpoints := func(base *v1.Endpoints, name string, prev *v1.Endpoints) *v1.Endpoints { //nolint:staticcheck
		copy := base.DeepCopy()
		if prev == nil {
			copy.Name = name
			return copy
		}
		copy.ObjectMeta = *prev.ObjectMeta.DeepCopy()
		return copy
	}

	AfterEach(func() {
		By("Cleaning up after the test should complete")
		_ = localCalicoClient.Close()
		federationController.Stop()
		federationController.Remove()
		localApiserver.Stop()
		localEtcd.Stop()
		remoteApiserver.Stop()
		remoteEtcd.Stop()
		cleanupLC()
		cleanupRC()
	})

	DescribeTable("Test with specific local Calico datastore type", func(isCalicoEtcdDatastore bool) {
		By("Setting up the local and remote clusters")
		setup(isCalicoEtcdDatastore)

		By("Creating two identical backing services and endpoints")
		svcBacking1, err := localK8sClient.CoreV1().Services(ns1Name).Create(ctx, makeService(svc1, "backing1", nil), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, err = localK8sClient.CoreV1().Endpoints(ns1Name).Create(ctx, makeEndpoints(eps1, "backing1", nil), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, err = localK8sClient.CoreV1().Services(ns1Name).Create(ctx, makeService(svc1, "backing2", nil), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		epsBacking2, err := localK8sClient.CoreV1().Endpoints(ns1Name).Create(ctx, makeEndpoints(eps1, "backing2", nil), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Creating a service with endpoints in a different namespace but the correct labels")
		_, err = localK8sClient.CoreV1().Services(ns2Name).Create(ctx, makeService(svc2, "wrongns", nil), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, err = localK8sClient.CoreV1().Endpoints(ns2Name).Create(ctx, makeEndpoints(eps2, "wrongns", nil), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Creating a federated service which matches the two identical backing services")
		fedCfg, err := localK8sClient.CoreV1().Services(ns1Name).Create(ctx, &v1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "federated",
				Namespace: ns1Name,
				Annotations: map[string]string{
					"federation.tigera.io/serviceSelector": "federate == 'yes'",
				},
			},
			Spec: v1.ServiceSpec{
				Ports: []v1.ServicePort{
					{
						Name:     "port1",
						Port:     8080,
						Protocol: v1.ProtocolUDP,
					},
					{
						Name:     "port2",
						Port:     80,
						Protocol: v1.ProtocolTCP,
					},
				},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Checking the federated endpoints have not been created without a license applied")
		Consistently(getSubsetsFn(ns1Name, "federated"), consistentlyTimeout, consistentlyPoll).Should(BeNil())

		By("Applying a valid license to enable the federated services controller")
		infrastructure.ApplyValidLicense(localCalicoClient)

		By("Checking the federated endpoints contain the expected set ips/ports")
		eSubset := []v1.EndpointSubset{ //nolint:staticcheck
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "2.0.0.1",
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port2",
						Port:     1234,
						Protocol: v1.ProtocolTCP,
					},
				},
			},
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP:       "1.0.0.1",
						NodeName: &node1Name,
					},
				},
				NotReadyAddresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP:       "1.0.0.2",
						NodeName: &node2Name,
						TargetRef: &v1.ObjectReference{
							Kind:      "Pod",
							Namespace: ns1Name,
							Name:      "pod1",
						},
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port1",
						Port:     1234,
						Protocol: v1.ProtocolUDP,
					},
				},
			},
		}
		Eventually(getSubsetsFn(ns1Name, "federated"), eventuallyTimeout, eventuallyPoll).Should(Equal(eSubset))

		// Stop the federationController container so we can register the watch on Stdout
		federationController.Stop()
		watchChan := federationController.WatchStdoutFor(regexp.MustCompile("Received exit status [[:digit:]]*, restarting"))
		federationController.Start()

		By("Updating the license to an expired license - controller should keep running")
		infrastructure.ApplyExpiredLicense(localCalicoClient)
		Eventually(watchChan, 10*time.Second).ShouldNot(BeClosed())

		By("Updating backing2 to have a different set of endpoints while license is expired")
		_, err = localK8sClient.CoreV1().Endpoints(ns1Name).Update(ctx, makeEndpoints(eps2, "backing2", epsBacking2), metav1.UpdateOptions{})
		Expect(err).ShouldNot(HaveOccurred())

		By("Checking the federated endpoints contain the expected set ips/ports [2]")
		Eventually(getSubsetsFn(ns1Name, "federated"), eventuallyTimeout, eventuallyPoll).Should(Equal([]v1.EndpointSubset{ //nolint:staticcheck
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "2.0.0.1",
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port2",
						Port:     1234,
						Protocol: v1.ProtocolTCP,
					},
				},
			},
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP:       "1.0.0.1",
						NodeName: &node1Name,
					},
					{
						IP:       "10.10.10.1",
						NodeName: &node1Name,
					},
				},
				NotReadyAddresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP:       "1.0.0.2",
						NodeName: &node2Name,
						TargetRef: &v1.ObjectReference{
							Kind:      "Pod",
							Namespace: ns1Name,
							Name:      "pod1",
						},
					},
					{
						IP:       "10.10.10.2",
						NodeName: &node2Name,
						TargetRef: &v1.ObjectReference{
							Kind:      "Pod",
							Namespace: ns1Name,
							Name:      "pod1",
						},
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port1",
						Port:     1234,
						Protocol: v1.ProtocolUDP,
					},
				},
			},
		}))

		By("Updating backing1 to have no labels")
		svcBacking1.Labels = nil
		_, err = localK8sClient.CoreV1().Services(ns1Name).Update(ctx, svcBacking1, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Checking the federated endpoints contain the expected set ips/ports [3]")
		// Store this set of expected endpoints as we'll use it a few times below.
		es := []v1.EndpointSubset{ //nolint:staticcheck
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP:       "10.10.10.1",
						NodeName: &node1Name,
					},
				},
				NotReadyAddresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP:       "10.10.10.2",
						NodeName: &node2Name,
						TargetRef: &v1.ObjectReference{
							Kind:      "Pod",
							Namespace: ns1Name,
							Name:      "pod1",
						},
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port1",
						Port:     1234,
						Protocol: v1.ProtocolUDP,
					},
				},
			},
		}
		Eventually(getSubsetsFn(ns1Name, "federated"), eventuallyTimeout, eventuallyPoll).Should(Equal(es))

		By("Removing the federation annotation")
		fedCfg.Annotations = nil
		fedCfg, err = localK8sClient.CoreV1().Services(ns1Name).Update(ctx, fedCfg, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Checking the federated endpoints has been deleted")
		Eventually(getSubsetsFn(ns1Name, "federated"), eventuallyTimeout, eventuallyPoll).Should(BeNil())

		By("Adding the federation annotation back")
		fedCfg.Annotations = map[string]string{
			"federation.tigera.io/serviceSelector": "federate == 'yes'",
		}
		fedCfg, err = localK8sClient.CoreV1().Services(ns1Name).Update(ctx, fedCfg, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Checking the federated endpoints contain the expected set ips/ports [4]")
		Eventually(getSubsetsFn(ns1Name, "federated"), eventuallyTimeout, eventuallyPoll).Should(Equal(es))

		By("Removing the federation selector from the federated endpoints to disable controller updates")
		eps, err := localK8sClient.CoreV1().Endpoints(ns1Name).Get(ctx, "federated", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		eps.Annotations = nil
		_, err = localK8sClient.CoreV1().Endpoints(ns1Name).Update(ctx, eps, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Modifying the federation annotation to be a no match")
		fedCfg.Annotations = map[string]string{
			"federation.tigera.io/serviceSelector": "federate == 'idontthinkso'",
		}
		fedCfg, err = localK8sClient.CoreV1().Services(ns1Name).Update(ctx, fedCfg, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Checking the federated endpoints remains unchanged")
		Consistently(getSubsetsFn(ns1Name, "federated"), consistentlyTimeout, consistentlyPoll).Should(Equal(es))
		Expect(getSubsets(ns1Name, "federated")).ToNot(BeNil())

		By("Removing the federated endpoints completely")
		err = localK8sClient.CoreV1().Endpoints(ns1Name).Delete(ctx, "federated", metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Modifying the federation annotation again - but still is a no match")
		fedCfg.Annotations = map[string]string{
			"federation.tigera.io/serviceSelector": "foo == 'bar'",
		}
		fedCfg, err = localK8sClient.CoreV1().Services(ns1Name).Update(ctx, fedCfg, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Checking the federated endpoints is recreated but contains no subsets")
		Eventually(getSubsetsFn(ns1Name, "federated"), eventuallyTimeout, eventuallyPoll).ShouldNot(BeNil())
		Expect(getSubsets(ns1Name, "federated")).To(HaveLen(0))

		By("Adding the federation annotation back")
		fedCfg.Annotations = map[string]string{
			"federation.tigera.io/serviceSelector": "federate == 'yes'",
		}
		_, err = localK8sClient.CoreV1().Services(ns1Name).Update(ctx, fedCfg, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Checking the federated endpoints contain the expected set ips/ports [5]")
		Eventually(getSubsetsFn(ns1Name, "federated"), eventuallyTimeout, eventuallyPoll).Should(Equal(es))

		By("Adding backing service to the remote cluster")
		_, err = remoteK8sClient.CoreV1().Services(ns1Name).Create(ctx, makeService(svc1, "backing1", nil), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, err = remoteK8sClient.CoreV1().Endpoints(ns1Name).Create(ctx, makeEndpoints(eps1, "backing1", nil), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Adding remote cluster config")
		rcc, err := localCalicoClient.RemoteClusterConfigurations().Create(ctx, &apiv3.RemoteClusterConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: "my-remote",
			},
			Spec: apiv3.RemoteClusterConfigurationSpec{
				DatastoreType: "kubernetes",
				KubeConfig: apiv3.KubeConfig{
					Kubeconfig: remoteKubeconfig,
				},
			},
		}, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Checking the federated endpoints contain the expected set ips/ports [6]")
		// Any port that has a name in the target object, should be updated to include the remote cluster name.
		Eventually(getSubsetsFn(ns1Name, "federated"), eventuallyTimeout, eventuallyPoll).Should(Equal([]v1.EndpointSubset{ //nolint:staticcheck
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "2.0.0.1",
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port2",
						Port:     1234,
						Protocol: v1.ProtocolTCP,
					},
				},
			},
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP:       "1.0.0.1",
						NodeName: &node1Name,
					},
					{
						IP:       "10.10.10.1",
						NodeName: &node1Name,
					},
				},
				NotReadyAddresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP:       "1.0.0.2",
						NodeName: &node2Name,
						TargetRef: &v1.ObjectReference{
							Kind:      "Pod",
							Namespace: ns1Name,
							Name:      "my-remote/pod1",
						},
					},
					{
						IP:       "10.10.10.2",
						NodeName: &node2Name,
						TargetRef: &v1.ObjectReference{
							Kind:      "Pod",
							Namespace: ns1Name,
							Name:      "pod1",
						},
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port1",
						Port:     1234,
						Protocol: v1.ProtocolUDP,
					},
				},
			},
		}))

		By("Deleting the local services")
		err = localK8sClient.CoreV1().Services(ns1Name).Delete(ctx, "backing1", metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
		err = localK8sClient.CoreV1().Services(ns1Name).Delete(ctx, "backing2", metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
		err = localK8sClient.CoreV1().Services(ns2Name).Delete(ctx, "wrongns", metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Checking the federated endpoints contain the expected set ips/ports [7]")
		Eventually(getSubsetsFn(ns1Name, "federated"), eventuallyTimeout, eventuallyPoll).Should(Equal([]v1.EndpointSubset{ //nolint:staticcheck
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "2.0.0.1",
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port2",
						Port:     1234,
						Protocol: v1.ProtocolTCP,
					},
				},
			},
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP:       "1.0.0.1",
						NodeName: &node1Name,
					},
				},
				NotReadyAddresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP:       "1.0.0.2",
						NodeName: &node2Name,
						TargetRef: &v1.ObjectReference{
							Kind:      "Pod",
							Namespace: ns1Name,
							Name:      "my-remote/pod1",
						},
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port1",
						Port:     1234,
						Protocol: v1.ProtocolUDP,
					},
				},
			},
		}))

		By("Deleting the RemoteClusterConfiguration")
		_, err = localCalicoClient.RemoteClusterConfigurations().Delete(ctx, "my-remote", options.DeleteOptions{ResourceVersion: rcc.ResourceVersion})
		Expect(err).NotTo(HaveOccurred())

		By("Checking the federated endpoints is present but contains no subsets")
		Eventually(getSubsetsFn(ns1Name, "federated"), eventuallyTimeout, eventuallyPoll).Should(HaveLen(0))
		Expect(getSubsets(ns1Name, "federated")).ToNot(BeNil())
	},
		Entry("etcd datastore", true),
		Entry("kubernetes datastore", false))
})
