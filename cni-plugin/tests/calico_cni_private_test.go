// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

package main_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"

	"github.com/containernetworking/plugins/pkg/ns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/testutils"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	k8sconversion "github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// This file is to hold private only tests to try to reduce the possibility of
// merge conflicts from the OS repo.
var _ = Describe("CalicoCni Private", func() {
	hostname, _ := names.Hostname()
	ctx := context.Background()
	calicoClient, err := client.NewFromEnv()
	if err != nil {
		panic(err)
	}

	BeforeEach(func() {
		if os.Getenv("DATASTORE_TYPE") == "kubernetes" {
			Skip("Don't run non-kubernetes test with Kubernetes Datastore")
		}
		testutils.WipeDatastore()
		// Create the node for these tests. The IPAM code requires a corresponding Calico node to exist.
		var err error
		n := api.NewNode()
		n.Name, err = names.Hostname()
		Expect(err).NotTo(HaveOccurred())
		_, err = calicoClient.Nodes().Create(context.Background(), n, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		if os.Getenv("DATASTORE_TYPE") == "kubernetes" {
			// no cleanup needed.
			return
		}

		// Delete the node.
		name, err := names.Hostname()
		Expect(err).NotTo(HaveOccurred())
		_, err = calicoClient.Nodes().Delete(context.Background(), name, options.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("Run Calico CNI plugin in K8s mode", func() {
		cniVersion := os.Getenv("CNI_SPEC_VERSION")

		Context("using host-local IPAM", func() {
			netconf := fmt.Sprintf(`
			{
			  "cniVersion": "%s",
			  "name": "net1",
			  "type": "calico",
			  "etcd_endpoints": "http://%s:2379",
			  "datastore_type": "%s",
			  "ipam": {
			    "type": "host-local",
			    "subnet": "10.0.0.0/8"
			  },
			  "kubernetes": {
			    "kubeconfig": "/home/user/certs/kubeconfig"
			  },
			  "policy": {"type": "k8s"},
			  "nodename_file_optional": true,
			  "log_level":"debug"
			}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

			It("converts AWS SecurityGroup annotation to label", func() {
				clientset := getKubernetesClient()
				ensureNamespace(clientset, "test2")

				name := fmt.Sprintf("run%d", rand.Uint32())

				// Create a K8s pod with AWS SG annotation
				_, err = clientset.CoreV1().Pods("test2").Create(context.Background(), &v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:        name,
						Annotations: map[string]string{k8sconversion.AnnotationSecurityGroups: "[\"sg-test\"]"},
					},
					Spec: v1.PodSpec{
						Containers: []v1.Container{{
							Name:  name,
							Image: "ignore",
						}},
						NodeName: hostname,
					},
				}, metav1.CreateOptions{})
				if err != nil {
					panic(err)
				}
				_, _, _, _, _, contNs, err := testutils.CreateContainer(netconf, name, "test2", "")
				defer func() {
					_, err = testutils.DeleteContainer(netconf, contNs.Path(), name, "test2")
					Expect(err).ShouldNot(HaveOccurred())
				}()
				Expect(err).ShouldNot(HaveOccurred())

				// The endpoint is created
				endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpoints.Items).Should(HaveLen(1))

				Expect(endpoints.Items[0].Labels).Should(
					HaveKeyWithValue(k8sconversion.SecurityGroupLabelPrefix+"/sg-test", ""))
			})
		})
	})
})

var _ = Describe("CalicoCNI Private Kubernetes CNI tests", func() {
	hostname, _ := names.Hostname()
	calicoClient, err := client.NewFromEnv()
	if err != nil {
		panic(err)
	}

	BeforeEach(func() {
		if os.Getenv("DATASTORE_TYPE") == "kubernetes" {
			Skip("Don't run non-kubernetes test with Kubernetes Datastore")
		}
		testutils.WipeDatastore()
		// Create the node for these tests. The IPAM code requires a corresponding Calico node to exist.
		var err error
		n := api.NewNode()
		n.Name, err = names.Hostname()
		Expect(err).NotTo(HaveOccurred())
		_, err = calicoClient.Nodes().Create(context.Background(), n, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		if os.Getenv("DATASTORE_TYPE") == "kubernetes" {
			// no cleanup needed.
			return
		}

		// Delete the node.
		name, err := names.Hostname()
		Expect(err).NotTo(HaveOccurred())
		_, err = calicoClient.Nodes().Delete(context.Background(), name, options.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	cniVersion := os.Getenv("CNI_SPEC_VERSION")

	Context("with WindowsUseSingleNetwork: true", func() {
		var nc types.NetConf
		var netconf string
		pool1 := "50.60.0.0/24"
		var clientset *kubernetes.Clientset
		BeforeEach(func() {
			// Build the network config for this set of tests.
			nc = types.NetConf{
				CNIVersion:              cniVersion,
				Name:                    "calico-uts",
				Type:                    "calico",
				EtcdEndpoints:           fmt.Sprintf("http://%s:2379", os.Getenv("ETCD_IP")),
				DatastoreType:           os.Getenv("DATASTORE_TYPE"),
				Kubernetes:              types.Kubernetes{Kubeconfig: "/home/user/certs/kubeconfig"},
				Policy:                  types.Policy{PolicyType: "k8s"},
				NodenameFileOptional:    true,
				LogLevel:                "info",
				WindowsUseSingleNetwork: true,
			}
			nc.IPAM.Type = "calico-ipam"
			ncb, err := json.Marshal(nc)
			Expect(err).NotTo(HaveOccurred())
			netconf = string(ncb)

			// Create IP Pools.
			testutils.MustCreateNewIPPoolBlockSize(calicoClient, pool1, false, false, true, 31)

			// Set up clients.
			clientset = getKubernetesClient()
		})

		AfterEach(func() {
			// Delete the IP Pools.
			testutils.MustDeleteIPPool(calicoClient, pool1)
		})

		It("should fail to assign an IP when single allowed IPAM block is full", func() {
			// Create the Namespace.
			testNS := fmt.Sprintf("run%d", rand.Uint32())
			_, err = clientset.CoreV1().Namespaces().Create(context.Background(), &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: testNS,
					Annotations: map[string]string{
						"cni.projectcalico.org/ipv4pools": "[\"50.60.0.0/24\"]",
					},
				},
			}, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			type container struct {
				contNS ns.NetNS
				name   string
			}
			var containers []container

			defer func() {
				for _, c := range containers {
					// Delete the container.
					_, err = testutils.DeleteContainer(netconf, c.contNS.Path(), c.name, testNS)
					Expect(err).ShouldNot(HaveOccurred())
				}
			}()

			for i := 0; i < 3; i++ {
				// Now create a K8s pod.
				name := fmt.Sprintf("run-%d-%d", i, rand.Uint32())
				pod, err := clientset.CoreV1().Pods(testNS).Create(context.Background(), &v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:        name,
						Annotations: map[string]string{},
					},
					Spec: v1.PodSpec{
						Containers: []v1.Container{{
							Name:  name,
							Image: "ignore",
						}},
						NodeName: hostname,
					},
				}, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				log.Infof("Created POD object: %v", pod)

				// Expect an error when invoking the CNI plugin for the last pod.
				_, _, _, _, _, contNs, err := testutils.CreateContainer(netconf, name, testNS, "")
				if err == nil {
					containers = append(containers, container{
						contNS: contNs,
						name:   name,
					})
				}
				if i < 2 {
					Expect(err).NotTo(HaveOccurred())
				} else {
					Expect(err).To(HaveOccurred())
				}
			}
		})
	})
})
