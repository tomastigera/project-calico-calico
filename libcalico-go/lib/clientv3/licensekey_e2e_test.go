// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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
// limitations under the License.

package clientv3_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

var _ = testutils.E2eDatastoreDescribe("LicenseKey tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {
	ctx := context.Background()
	name := "default"
	spec1 := apiv3.LicenseKeySpec{
		Token:       "token1",
		Certificate: "cert1",
	}
	spec2 := apiv3.LicenseKeySpec{
		Token:       "token2",
		Certificate: "cert2",
	}

	var c clientv3.Interface
	var be bapi.Client

	BeforeEach(func() {
		var err error
		c, err = clientv3.New(config)
		Expect(err).NotTo(HaveOccurred())

		be, err = backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		be.Clean()
	})

	DescribeTable("LicenseKey e2e CRUD tests",
		func(name string, spec1, spec2 apiv3.LicenseKeySpec) {
			By("Updating the LicenseKey before it is created")
			_, outError := c.LicenseKey().Update(ctx, &apiv3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "1234", CreationTimestamp: metav1.Now(), UID: uid},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: LicenseKey(" + name + ") with error:"))

			By("Attempting to creating a new LicenseKey with name/spec1 and a non-empty ResourceVersion")
			_, outError = c.LicenseKey().Create(ctx, &apiv3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "12345"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))

			By("Getting LicenseKey (name) before it is created")
			_, outError = c.LicenseKey().Get(ctx, name, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: LicenseKey(" + name + ") with error:"))

			By("Attempting to create a new LicenseKey with a non-default name and spec1")
			_, outError = c.LicenseKey().Create(ctx, &apiv3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: "not-default"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("Cannot create a License Key resource with a name other than \"default\""))

			By("Creating a new LicenseKey with name/spec1")
			res1, outError := c.LicenseKey().Create(ctx, &apiv3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(apiv3.KindLicenseKey, testutils.ExpectNoNamespace, name, spec1))

			// Track the version of the original data for name.
			rv1_1 := res1.ResourceVersion

			By("Attempting to create the same LicenseKey with name but with spec2")
			_, outError = c.LicenseKey().Create(ctx, &apiv3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource already exists: LicenseKey(" + name + ")"))

			By("Getting LicenseKey (name) and comparing the output against spec1")
			res, outError := c.LicenseKey().Get(ctx, name, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindLicenseKey, testutils.ExpectNoNamespace, name, spec1))
			Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))

			By("Listing all the LicenseKey, expecting a single result with name/spec1")
			outList, outError := c.LicenseKey().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(1))
			Expect(&outList.Items[0]).To(MatchResource(apiv3.KindLicenseKey, testutils.ExpectNoNamespace, name, spec1))

			By("Updating LicenseKey name with spec2")
			res1.Spec = spec2
			res1, outError = c.LicenseKey().Update(ctx, res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(apiv3.KindLicenseKey, testutils.ExpectNoNamespace, name, spec2))

			By("Attempting to update the LicenseKey without a Creation Timestamp")
			res, outError = c.LicenseKey().Update(ctx, &apiv3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "1234", UID: uid},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.CreationTimestamp = '0001-01-01 00:00:00 +0000 UTC' (field must be set for an Update request)"))

			By("Attempting to update the LicenseKey without a UID")
			res, outError = c.LicenseKey().Update(ctx, &apiv3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "1234", CreationTimestamp: metav1.Now()},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.UID = '' (field must be set for an Update request)"))

			// Track the version of the updated name data.
			rv1_2 := res1.ResourceVersion

			By("Updating LicenseKey name without specifying a resource version")
			res1.Spec = spec1
			res1.ObjectMeta.ResourceVersion = ""
			_, outError = c.LicenseKey().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '' (field must be set for an Update request)"))

			By("Updating LicenseKey name using the previous resource version")
			res1.Spec = spec1
			res1.ResourceVersion = rv1_1
			_, outError = c.LicenseKey().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: LicenseKey(" + name + ")"))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Getting LicenseKey (name) with the original resource version and comparing the output against spec1")
				res, outError = c.LicenseKey().Get(ctx, name, options.GetOptions{ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(res).To(MatchResource(apiv3.KindLicenseKey, testutils.ExpectNoNamespace, name, spec1))
				Expect(res.ResourceVersion).To(Equal(rv1_1))
			}

			By("Getting LicenseKey (name) with the updated resource version and comparing the output against spec2")
			res, outError = c.LicenseKey().Get(ctx, name, options.GetOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindLicenseKey, testutils.ExpectNoNamespace, name, spec2))
			Expect(res.ResourceVersion).To(Equal(rv1_2))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Listing LicenseKey with the original resource version and checking for a single result with name/spec1")
				outList, outError = c.LicenseKey().List(ctx, options.ListOptions{ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(outList.Items).To(HaveLen(1))
				Expect(&outList.Items[0]).To(MatchResource(apiv3.KindLicenseKey, testutils.ExpectNoNamespace, name, spec1))
			}

			By("Listing LicenseKey with the latest resource version and checking for one result with name/spec2")
			outList, outError = c.LicenseKey().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(1))
			Expect(&outList.Items[0]).To(MatchResource(apiv3.KindLicenseKey, testutils.ExpectNoNamespace, name, spec2))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Deleting LicenseKey (name) with the old resource version")
				_, outError = c.LicenseKey().Delete(ctx, name, options.DeleteOptions{ResourceVersion: rv1_1})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(Equal("update conflict: LicenseKey(" + name + ")"))
			}

			By("Deleting LicenseKey (name) with the new resource version")
			dres, outError := c.LicenseKey().Delete(ctx, name, options.DeleteOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(dres).To(MatchResource(apiv3.KindLicenseKey, testutils.ExpectNoNamespace, name, spec2))

			By("Listing all LicenseKey and expecting no items")
			outList, outError = c.LicenseKey().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))
		},

		// Test 1: Pass two fully populated LicenseKeySpecs and expect the series of operations to succeed.
		Entry("Two fully populated LicenseKeySpecs", name, spec1, spec2),
	)

	Describe("LicenseKey watch functionality", func() {
		It("should handle watch events for different resource versions and event types", func() {
			By("Listing LicenseKey with the latest resource version and checking for one result with name/spec2")
			outList, outError := c.LicenseKey().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))
			rev0 := outList.ResourceVersion

			By("Configuring a LicenseKey name/spec1 and storing the response")
			outRes1, err := c.LicenseKey().Create(
				ctx,
				&apiv3.LicenseKey{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			rev1 := outRes1.ResourceVersion

			By("Starting a watcher from revision rev1 - this should skip the first creation")
			w, err := c.LicenseKey().Watch(ctx, options.ListOptions{ResourceVersion: rev1})
			Expect(err).NotTo(HaveOccurred())
			testWatcher1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher1.Stop()

			By("Deleting res1")
			_, err = c.LicenseKey().Delete(ctx, name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Checking for event: delete res1")
			testWatcher1.ExpectEvents(apiv3.KindLicenseKey, []watch.Event{
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
			})
			testWatcher1.Stop()

			By("Configuring a LicenseKey name2/spec2 and storing the response")
			outRes2, err := c.LicenseKey().Create(
				ctx,
				&apiv3.LicenseKey{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec:       spec2,
				},
				options.SetOptions{},
			)

			By("Starting a watcher from rev0 - this should get all events")
			w, err = c.LicenseKey().Watch(ctx, options.ListOptions{ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher2.Stop()

			By("Modifying res2")
			outRes3, err := c.LicenseKey().Update(
				ctx,
				&apiv3.LicenseKey{
					ObjectMeta: outRes2.ObjectMeta,
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			testWatcher2.ExpectEvents(apiv3.KindLicenseKey, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes1,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
				{
					Type:   watch.Added,
					Object: outRes2,
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
				By("Starting a watcher from rev0 watching name - this should get all events for name")
				w, err = c.LicenseKey().Watch(ctx, options.ListOptions{Name: name, ResourceVersion: rev0})
				Expect(err).NotTo(HaveOccurred())
				testWatcher2_1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
				defer testWatcher2_1.Stop()
				testWatcher2_1.ExpectEvents(apiv3.KindLicenseKey, []watch.Event{
					{
						Type:   watch.Added,
						Object: outRes1,
					},
					{
						Type:     watch.Deleted,
						Previous: outRes1,
					},
					{
						Type:   watch.Added,
						Object: outRes2,
					},
					{
						Type:     watch.Modified,
						Previous: outRes2,
						Object:   outRes3,
					},
				})
				testWatcher2_1.Stop()
			}

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.LicenseKey().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher3 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher3.Stop()
			testWatcher3.ExpectEventsAnyOrder(apiv3.KindLicenseKey, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})

			By("Cleaning the datastore and expecting deletion events for each configured resource (tests prefix deletes results in individual events for each key)")
			be.Clean()
			testWatcher3.ExpectEvents(apiv3.KindLicenseKey, []watch.Event{
				{
					Type:     watch.Deleted,
					Previous: outRes3,
				},
			})
			testWatcher3.Stop()
		})
	})
})
