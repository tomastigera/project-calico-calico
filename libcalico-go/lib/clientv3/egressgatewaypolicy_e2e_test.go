// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package clientv3_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

var _ = testutils.E2eDatastoreDescribe("EgressGatewayPolicy tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {
	ctx := context.Background()
	name1 := "egressgatewaypolicy-1"
	name2 := "egressgatewaypolicy-2"

	preferNone := apiv3.GatewayPreferenceNone
	ruleLocal := apiv3.EgressGatewayRule{
		Destination: &apiv3.EgressGatewayPolicyDestinationSpec{
			CIDR: "192.168.0.0/16",
		},
		Description:       "local network",
		GatewayPreference: &preferNone,
	}
	ruleOnPrem := apiv3.EgressGatewayRule{
		Destination: &apiv3.EgressGatewayPolicyDestinationSpec{
			CIDR: "10.0.0.0/8",
		},
		Description: "to external datacenter",
		Gateway: &apiv3.EgressSpec{
			Selector:          "egress-code == 'red'",
			NamespaceSelector: "projectcalico.org/name == 'calico-egress'",
			MaxNextHops:       3,
		},
		GatewayPreference: &preferNone,
	}
	ruleInternet := apiv3.EgressGatewayRule{
		Destination: &apiv3.EgressGatewayPolicyDestinationSpec{
			CIDR: "0.0.0.0/0",
		},
		Description: "Internet access",
		Gateway: &apiv3.EgressSpec{
			Selector:          "egress-code == 'blue'",
			NamespaceSelector: "projectcalico.org/name == 'calico-egress'",
		},
		GatewayPreference: &preferNone,
	}
	spec1 := apiv3.EgressGatewayPolicySpec{}
	spec1.Rules = []apiv3.EgressGatewayRule{ruleLocal, ruleOnPrem}

	spec2 := apiv3.EgressGatewayPolicySpec{}
	spec2.Rules = []apiv3.EgressGatewayRule{ruleLocal, ruleInternet}

	It("EgressGatewayPolicy e2e CRUD tests", func() {
		c, err := clientv3.New(config)
		Expect(err).NotTo(HaveOccurred())

		be, err := backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		be.Clean()

		By("Updating the EgressGatewayPolicy before it is created")
		_, outError := c.EgressGatewayPolicy().Update(ctx, &apiv3.EgressGatewayPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now(), UID: uid},
			Spec:       spec1,
		}, options.SetOptions{})
		Expect(outError).To(HaveOccurred())
		Expect(outError.Error()).To(ContainSubstring("resource does not exist: EgressGatewayPolicy(" + name1 + ") with error:"))

		By("Attempting to creating a new EgressGatewayPolicy with name1/spec1 and a non-empty ResourceVersion")
		_, outError = c.EgressGatewayPolicy().Create(ctx, &apiv3.EgressGatewayPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "12345"},
			Spec:       spec1,
		}, options.SetOptions{})
		Expect(outError).To(HaveOccurred())
		Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))

		By("Creating a new EgressGatewayPolicy with name1/spec1")
		res1, outError := c.EgressGatewayPolicy().Create(ctx, &apiv3.EgressGatewayPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name1},
			Spec:       spec1,
		}, options.SetOptions{})
		Expect(outError).NotTo(HaveOccurred())

		// Track the version of the original data for name1.
		rv1_1 := res1.ResourceVersion

		By("Attempting to create the same EgressGatewayPolicy with name1 but with spec2")
		_, outError = c.EgressGatewayPolicy().Create(ctx, &apiv3.EgressGatewayPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name1},
			Spec:       spec2,
		}, options.SetOptions{})
		Expect(outError).To(HaveOccurred())
		Expect(outError.Error()).To(ContainSubstring("resource already exists: EgressGatewayPolicy(" + name1 + ")"))

		By("Getting EgressGatewayPolicy (name1) and comparing the output against spec1")
		res, outError := c.EgressGatewayPolicy().Get(ctx, name1, options.GetOptions{})
		Expect(outError).NotTo(HaveOccurred())
		Expect(res).To(MatchResource(apiv3.KindEgressGatewayPolicy, testutils.ExpectNoNamespace, name1, spec1))
		Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))

		By("Getting EgressGatewayPolicy (name2) before it is created")
		_, outError = c.EgressGatewayPolicy().Get(ctx, name2, options.GetOptions{})
		Expect(outError).To(HaveOccurred())
		Expect(outError.Error()).To(ContainSubstring("resource does not exist: EgressGatewayPolicy(" + name2 + ") with error:"))

		By("Listing all the EgressGatewayPolicy, expecting a single result with name1/spec1")
		outList, outError := c.EgressGatewayPolicy().List(ctx, options.ListOptions{})
		Expect(outError).NotTo(HaveOccurred())
		Expect(outList.Items).To(ConsistOf(
			testutils.Resource(apiv3.KindEgressGatewayPolicy, testutils.ExpectNoNamespace, name1, spec1),
		))

		By("Creating a new EgressGatewayPolicy with name2")
		res2, outError := c.EgressGatewayPolicy().Create(ctx, &apiv3.EgressGatewayPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name2},
			Spec:       spec2,
		}, options.SetOptions{})
		Expect(outError).NotTo(HaveOccurred())

		By("Getting EgressGatewayPolicy (name2) and comparing the output against spec2")
		res, outError = c.EgressGatewayPolicy().Get(ctx, name2, options.GetOptions{})
		Expect(outError).NotTo(HaveOccurred())
		Expect(res2).To(MatchResource(apiv3.KindEgressGatewayPolicy, testutils.ExpectNoNamespace, name2, spec2))
		Expect(res.ResourceVersion).To(Equal(res2.ResourceVersion))

		By("Listing all the EgressGatewayPolicies, expecting two results with name1/spec1 and name2/spec2")
		outList, outError = c.EgressGatewayPolicy().List(ctx, options.ListOptions{})
		Expect(outError).NotTo(HaveOccurred())
		Expect(outList.Items).To(ConsistOf(
			testutils.Resource(apiv3.KindEgressGatewayPolicy, testutils.ExpectNoNamespace, name1, spec1),
			testutils.Resource(apiv3.KindEgressGatewayPolicy, testutils.ExpectNoNamespace, name2, spec2),
		))

		By("Updating EgressGatewayPolicy name1's Export with spec2's values")
		res1.Spec.Rules = []apiv3.EgressGatewayRule{ruleLocal, ruleInternet}
		res1, outError = c.EgressGatewayPolicy().Update(ctx, res1, options.SetOptions{})
		Expect(outError).NotTo(HaveOccurred())
		Expect(res1).To(MatchResource(apiv3.KindEgressGatewayPolicy, testutils.ExpectNoNamespace, name1, spec2))

		By("Attempting to update the EgressGatewayPolicy without a Creation Timestamp")
		res, outError = c.EgressGatewayPolicy().Update(ctx, &apiv3.EgressGatewayPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", UID: uid},
			Spec:       spec1,
		}, options.SetOptions{})
		Expect(outError).To(HaveOccurred())
		Expect(res).To(BeNil())
		Expect(outError.Error()).To(Equal("error with field Metadata.CreationTimestamp = '0001-01-01 00:00:00 +0000 UTC' (field must be set for an Update request)"))

		By("Attempting to update the EgressGatewayPolicy without a UID")
		res, outError = c.EgressGatewayPolicy().Update(ctx, &apiv3.EgressGatewayPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now()},
			Spec:       spec1,
		}, options.SetOptions{})
		Expect(outError).To(HaveOccurred())
		Expect(res).To(BeNil())
		Expect(outError.Error()).To(Equal("error with field Metadata.UID = '' (field must be set for an Update request)"))

		// Track the version of the updated name1 data.
		rv1_2 := res1.ResourceVersion

		By("Updating EgressGatewayPolicy name1 without specifying a resource version")
		res1.Spec = spec1
		res1.ObjectMeta.ResourceVersion = ""
		_, outError = c.EgressGatewayPolicy().Update(ctx, res1, options.SetOptions{})
		Expect(outError).To(HaveOccurred())
		Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '' (field must be set for an Update request)"))

		By("Updating EgressGatewayPolicy name1 using the previous resource version")
		res1.Spec = spec1
		res1.ResourceVersion = rv1_1
		_, outError = c.EgressGatewayPolicy().Update(ctx, res1, options.SetOptions{})
		Expect(outError).To(HaveOccurred())
		Expect(outError.Error()).To(Equal("update conflict: EgressGatewayPolicy(" + name1 + ")"))

		if config.Spec.DatastoreType != apiconfig.Kubernetes {
			By("Getting EgressGatewayPolicy (name1) with the original resource version and comparing the output against spec1")
			res, outError = c.EgressGatewayPolicy().Get(ctx, name1, options.GetOptions{ResourceVersion: rv1_1})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindEgressGatewayPolicy, testutils.ExpectNoNamespace, name1, spec1))
			Expect(res.ResourceVersion).To(Equal(rv1_1))
		}

		By("Getting EgressGatewayPolicy (name1) with the updated resource version and comparing the output against spec2")
		res, outError = c.EgressGatewayPolicy().Get(ctx, name1, options.GetOptions{ResourceVersion: rv1_2})
		Expect(outError).NotTo(HaveOccurred())
		Expect(res).To(MatchResource(apiv3.KindEgressGatewayPolicy, testutils.ExpectNoNamespace, name1, spec2))
		Expect(res.ResourceVersion).To(Equal(rv1_2))

		if config.Spec.DatastoreType != apiconfig.Kubernetes {
			By("Listing EgressGatewayPolicy with the original resource version and checking for a single result with name1/spec1")
			outList, outError = c.EgressGatewayPolicy().List(ctx, options.ListOptions{ResourceVersion: rv1_1})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindEgressGatewayPolicy, testutils.ExpectNoNamespace, name1, spec1),
			))
		}

		By("Listing EgressGatewayPolicy with the latest resource version and checking for two results with name1/spec1 and name2/spec2")
		outList, outError = c.EgressGatewayPolicy().List(ctx, options.ListOptions{})
		Expect(outError).NotTo(HaveOccurred())
		Expect(outList.Items).To(ConsistOf(
			// Use spec2 for name1 as it was changed previously
			testutils.Resource(apiv3.KindEgressGatewayPolicy, testutils.ExpectNoNamespace, name1, spec2),
			testutils.Resource(apiv3.KindEgressGatewayPolicy, testutils.ExpectNoNamespace, name2, spec2),
		))

		if config.Spec.DatastoreType != apiconfig.Kubernetes {
			By("Deleting EgressGatewayPolicy (name1) with the old resource version")
			_, outError = c.EgressGatewayPolicy().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: rv1_1})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: EgressGatewayPolicy(" + name1 + ")"))
		}

		By("Deleting EgressGatewayPolicy (name1) with the new resource version")
		dres, outError := c.EgressGatewayPolicy().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: rv1_2})
		Expect(outError).NotTo(HaveOccurred())
		Expect(dres).To(MatchResource(apiv3.KindEgressGatewayPolicy, testutils.ExpectNoNamespace, name1, spec2))

		if config.Spec.DatastoreType != apiconfig.Kubernetes {
			By("Updating EgressGatewayPolicy name2 with a 2s TTL and waiting for the entry to be deleted")
			_, outError = c.EgressGatewayPolicy().Update(ctx, res2, options.SetOptions{TTL: 2 * time.Second})
			Expect(outError).NotTo(HaveOccurred())
			Eventually(func() string {
				_, err := c.EgressGatewayPolicy().Get(ctx, name2, options.GetOptions{})
				if err != nil {
					return err.Error()
				}
				return ""
			}, 5*time.Second, 200*time.Millisecond).Should(ContainSubstring("resource does not exist: EgressGatewayPolicy(" + name2 + ") with error:"))

			By("Creating EgressGatewayPolicy name2 with a 2s TTL and waiting for the entry to be deleted")
			_, outError = c.EgressGatewayPolicy().Create(ctx, &apiv3.EgressGatewayPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name2},
				Spec:       spec2,
			}, options.SetOptions{TTL: 2 * time.Second})
			Expect(outError).NotTo(HaveOccurred())
			Eventually(func() string {
				_, err := c.EgressGatewayPolicy().Get(ctx, name2, options.GetOptions{})
				if err != nil {
					return err.Error()
				}
				return ""
			}, 5*time.Second, 200*time.Millisecond).Should(ContainSubstring("resource does not exist: EgressGatewayPolicy(" + name2 + ") with error:"))
		}

		if config.Spec.DatastoreType == apiconfig.Kubernetes {
			By("Attempting to deleting EgressGatewayPolicy (name2)")
			dres, outError = c.EgressGatewayPolicy().Delete(ctx, name2, options.DeleteOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(dres).To(MatchResource(apiv3.KindEgressGatewayPolicy, testutils.ExpectNoNamespace, name2, spec2))
		}

		By("Attempting to delete EgressGatewayPolicy (name2) again")
		_, outError = c.EgressGatewayPolicy().Delete(ctx, name2, options.DeleteOptions{})
		Expect(outError).To(HaveOccurred())
		Expect(outError.Error()).To(ContainSubstring("resource does not exist: EgressGatewayPolicy(" + name2 + ") with error:"))

		By("Listing all EgressGatewayPolicy and expecting no items")
		outList, outError = c.EgressGatewayPolicy().List(ctx, options.ListOptions{})
		Expect(outError).NotTo(HaveOccurred())
		Expect(outList.Items).To(HaveLen(0))

		By("Getting EgressGatewayPolicy (name2) and expecting an error")
		_, outError = c.EgressGatewayPolicy().Get(ctx, name2, options.GetOptions{})
		Expect(outError).To(HaveOccurred())
		Expect(outError.Error()).To(ContainSubstring("resource does not exist: EgressGatewayPolicy(" + name2 + ") with error:"))
	})

	Describe("EgressGatewayPolicy watch functionality", func() {
		It("should handle watch events for different resource versions and event types", func() {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Listing EgressGatewayPolicy with the latest resource version and checking for two results with name1 and name2")
			outList, outError := c.EgressGatewayPolicy().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))
			rev0 := outList.ResourceVersion

			By("Configuring a EgressGatewayPolicy name1/spec1 and storing the response")
			outRes1, err := c.EgressGatewayPolicy().Create(
				ctx,
				&apiv3.EgressGatewayPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			rev1 := outRes1.ResourceVersion

			By("Configuring a EgressGatewayPolicy name2/spec2 and storing the response")
			outRes2, err := c.EgressGatewayPolicy().Create(
				ctx,
				&apiv3.EgressGatewayPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: name2},
					Spec:       spec2,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			By("Starting a watcher from revision rev1 - this should skip the first creation")
			w, err := c.EgressGatewayPolicy().Watch(ctx, options.ListOptions{ResourceVersion: rev1})
			Expect(err).NotTo(HaveOccurred())
			testWatcher1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher1.Stop()

			By("Deleting res1")
			_, err = c.EgressGatewayPolicy().Delete(ctx, name1, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Checking for two events, create res2 and delete re1")
			testWatcher1.ExpectEvents(apiv3.KindEgressGatewayPolicy, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes2,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
			})
			testWatcher1.Stop()

			By("Starting a watcher from rev0 - this should get all events")
			w, err = c.EgressGatewayPolicy().Watch(ctx, options.ListOptions{ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher2.Stop()

			By("Modifying res2")
			outRes3, err := c.EgressGatewayPolicy().Update(
				ctx,
				&apiv3.EgressGatewayPolicy{
					ObjectMeta: outRes2.ObjectMeta,
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			testWatcher2.ExpectEvents(apiv3.KindEgressGatewayPolicy, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes1,
				},
				{
					Type:   watch.Added,
					Object: outRes2,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
				{
					Type:     watch.Modified,
					Previous: outRes2,
					Object:   outRes3,
				},
			})
			testWatcher2.Stop()

			// Only etcdv3 supports watching a specific instance of a resource.
			if config.Spec.DatastoreType == apiconfig.EtcdV3 {
				By("Starting a watcher from rev0 watching name1 - this should get all events for name1")
				w, err = c.EgressGatewayPolicy().Watch(ctx, options.ListOptions{Name: name1, ResourceVersion: rev0})
				Expect(err).NotTo(HaveOccurred())
				testWatcher2_1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
				defer testWatcher2_1.Stop()
				testWatcher2_1.ExpectEvents(apiv3.KindEgressGatewayPolicy, []watch.Event{
					{
						Type:   watch.Added,
						Object: outRes1,
					},
					{
						Type:     watch.Deleted,
						Previous: outRes1,
					},
				})
				testWatcher2_1.Stop()
			}

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.EgressGatewayPolicy().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher3 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher3.Stop()
			testWatcher3.ExpectEvents(apiv3.KindEgressGatewayPolicy, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})
			testWatcher3.Stop()

			By("Configuring EgressGatewayPolicy name1/spec1 again and storing the response")
			outRes1, err = c.EgressGatewayPolicy().Create(
				ctx,
				&apiv3.EgressGatewayPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       spec1,
				},
				options.SetOptions{},
			)

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.EgressGatewayPolicy().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher4 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher4.Stop()
			testWatcher4.ExpectEventsAnyOrder(apiv3.KindEgressGatewayPolicy, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes1,
				},
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})

			By("Cleaning the datastore and expecting deletion events for each configured resource (tests prefix deletes results in individual events for each key)")
			be.Clean()
			testWatcher4.ExpectEventsAnyOrder(apiv3.KindEgressGatewayPolicy, []watch.Event{
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes3,
				},
			})
			testWatcher4.Stop()
		})
	})
})
