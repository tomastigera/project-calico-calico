// Copyright (c) 2019, 2022 Tigera, Inc. All rights reserved.
package policyrec_test

import (
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	clientsetfake "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	"github.com/projectcalico/calico/lma/pkg/policyrec"
)

var (
	depPod = &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind: "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-app-abcdefg",
			Namespace: "test-dep-namespace",
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind: "Deployment",
					Name: "test-app",
				},
			},
		},
	}
	deployment = &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind: "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-app",
			Namespace: "test-dep-namespace",
		},
	}
	jobPod = &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind: "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-app-abcdefg",
			Namespace: "test-job-namespace",
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind: "Job",
					Name: "test-app",
				},
			},
		},
	}
	job = &batchv1.Job{
		TypeMeta: metav1.TypeMeta{
			Kind: "Job",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-app",
			Namespace: "test-job-namespace",
		},
	}
	dsPod = &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind: "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-app-abcdefg",
			Namespace: "test-ds-namespace",
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind: "DaemonSet",
					Name: "test-app",
				},
			},
		},
	}
	ds = &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{
			Kind: "DaemonSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-app",
			Namespace: "test-ds-namespace",
		},
	}
	rsPod = &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind: "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-app-abcdefg",
			Namespace: "test-rs-namespace",
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind: "ReplicaSet",
					Name: "test-app-rs",
				},
			},
		},
	}
	rs = &appsv1.ReplicaSet{
		TypeMeta: metav1.TypeMeta{
			Kind: "ReplicaSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-app-rs",
			Namespace: "test-rs-namespace",
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind: "Deployment",
					Name: "test-app",
				},
			},
		},
	}
	rsDep = &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind: "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-app",
			Namespace: "test-rs-namespace",
		},
	}
	orphanPod = &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind: "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-app-abcdefg",
			Namespace: "test-orphan-namespace",
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind: "Deployment",
					Name: "test-app",
				},
			},
		},
	}
	alonePod = &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind: "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-app-abcdefg",
			Namespace: "test-alone-namespace",
		},
	}
	wcDep = &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind: "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-app",
			Namespace: "test-wc-namespace",
		},
	}
	namespace1Object = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace1",
		},
	}
	namespace2Object = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace2",
		},
	}
)

var _ = Describe("Test Generating Names for Recommended Policies", func() {
	req := &http.Request{Header: http.Header{}}

	// Define the kubernetes interface
	mockLmaK8sClientSet := &lmak8s.MockClientSet{}
	mockLmaK8sClientSet.On("ProjectcalicoV3").Return(
		clientsetfake.NewClientset().ProjectcalicoV3(),
	)
	coreV1 := fake.NewClientset().CoreV1()
	_, err := coreV1.Namespaces().Create(req.Context(), namespace1Object, metav1.CreateOptions{})
	Expect(err).To(BeNil())
	_, err = coreV1.Namespaces().Create(req.Context(), namespace2Object, metav1.CreateOptions{})
	Expect(err).To(BeNil())
	_, err = coreV1.Pods("test-dep-namespace").Create(req.Context(), depPod, metav1.CreateOptions{})
	Expect(err).To(BeNil())
	_, err = coreV1.Pods("test-job-namespace").Create(req.Context(), jobPod, metav1.CreateOptions{})
	Expect(err).To(BeNil())
	_, err = coreV1.Pods("test-rs-namespace").Create(req.Context(), rsPod, metav1.CreateOptions{})
	Expect(err).To(BeNil())
	_, err = coreV1.Pods("test-orphan-namespace").Create(req.Context(), orphanPod, metav1.CreateOptions{})
	Expect(err).To(BeNil())
	_, err = coreV1.Pods("test-alone-namespace").Create(req.Context(), alonePod, metav1.CreateOptions{})
	Expect(err).To(BeNil())
	_, err = coreV1.Pods("test-ds-namespace").Create(req.Context(), dsPod, metav1.CreateOptions{})
	Expect(err).To(BeNil())

	appV1 := fake.NewClientset().AppsV1()
	_, err = appV1.Deployments("test-dep-namespace").Create(req.Context(), deployment, metav1.CreateOptions{})
	Expect(err).To(BeNil())
	_, err = appV1.DaemonSets("test-ds-namespace").Create(req.Context(), ds, metav1.CreateOptions{})
	Expect(err).To(BeNil())
	_, err = appV1.ReplicaSets("test-rs-namespace").Create(req.Context(), rs, metav1.CreateOptions{})
	Expect(err).To(BeNil())
	_, err = appV1.Deployments("test-rs-namespace").Create(req.Context(), rsDep, metav1.CreateOptions{})
	Expect(err).To(BeNil())
	_, err = appV1.Deployments("test-wc-namespace").Create(req.Context(), wcDep, metav1.CreateOptions{})
	Expect(err).To(BeNil())

	batchV1 := fake.NewClientset().BatchV1()
	_, err = batchV1.Jobs("test-job-namespace").Create(req.Context(), job, metav1.CreateOptions{})
	Expect(err).To(BeNil())

	batchV1beta1 := fake.NewClientset().BatchV1beta1()

	// Define the return methods called by this test.
	mockLmaK8sClientSet.On("CoreV1").Return(coreV1)
	mockLmaK8sClientSet.On("AppsV1").Return(appV1)
	mockLmaK8sClientSet.On("BatchV1").Return(batchV1)
	mockLmaK8sClientSet.On("BatchV1beta1").Return(batchV1beta1)

	DescribeTable("Extracts the query parameters from the request and validates them",
		func(k lmak8s.ClientSet, searchName, searchNamespace, expectedName string) {
			genName := policyrec.GeneratePolicyName(k, searchName, searchNamespace)
			Expect(genName).To(Equal(expectedName))
		},
		// pod -> deployment
		Entry("Given a pod name that has a reference to a deployment, it should return the deployment name", mockLmaK8sClientSet, "test-app-abcdefg", "test-dep-namespace", "test-app"),
		// pod -> job
		Entry("Given a pod name that has a reference to a job, it should return the job name", mockLmaK8sClientSet, "test-app-abcdefg", "test-job-namespace", "test-app"),
		// pod -> daemonset
		Entry("Given a pod name that has a reference to a daemonset, it should return the daemonset name", mockLmaK8sClientSet, "test-app-abcdefg", "test-ds-namespace", "test-app"),
		// pod -> replicaset -> deployment
		Entry("Given a pod name that has a reference to a replicaset which was created by a deployment, it should return the deployment name", mockLmaK8sClientSet, "test-app-abcdefg", "test-rs-namespace", "test-app"),
		// something that doesn't exist
		Entry("Given a pod name that has a reference to a deployment that doesn't exist, the non-existing deployment name is returned", mockLmaK8sClientSet, "test-app-abcdefg", "test-orphan-namespace", "test-app"),
		// no owner reference
		Entry("Given a pod name that does not have a reference, it should return the pod name", mockLmaK8sClientSet, "test-app-abcdefg", "test-alone-namespace", "test-app-abcdefg"),
		// wildcard name -> deployment
		Entry("Given a wildcard name (probably replicaset), it should return the deployment that would create it", mockLmaK8sClientSet, "test-app-*", "test-wc-namespace", "test-app"),
	)
})
