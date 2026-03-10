// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

var _ = testutils.E2eDatastoreDescribe("GlobalThreatFeed tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {
	ctx := context.Background()
	name1 := "threatfeed-1"
	name2 := "threatfeed-2"

	mode1 := new(apiv3.ThreatFeedMode)
	*mode1 = apiv3.ThreatFeedModeEnabled
	mode2 := new(apiv3.ThreatFeedMode)
	*mode2 = apiv3.ThreatFeedModeDisabled

	type1 := new(apiv3.ThreatFeedType)
	*type1 = apiv3.ThreatFeedTypeBuiltin
	type2 := new(apiv3.ThreatFeedType)
	*type2 = apiv3.ThreatFeedTypeCustom

	spec1 := apiv3.GlobalThreatFeedSpec{
		Content:     apiv3.ThreatFeedContentIPset,
		Mode:        mode1,
		Description: "test1",
		FeedType:    type1,
		GlobalNetworkSet: &apiv3.GlobalNetworkSetSync{
			Labels: map[string]string{"level": "high"},
		},
		Pull: &apiv3.Pull{
			Period: "24h",
			HTTP: &apiv3.HTTPPull{
				Format: apiv3.ThreatFeedFormat{
					NewlineDelimited: &apiv3.ThreatFeedFormatNewlineDelimited{},
				},
				URL: "https://tigera.io/feed",
				Headers: []apiv3.HTTPHeader{
					{Name: "Accept", Value: "text/plain"},
					{
						Name: "Key",
						ValueFrom: &apiv3.HTTPHeaderSource{
							SecretKeyRef: &v1.SecretKeySelector{
								LocalObjectReference: v1.LocalObjectReference{Name: apiv3.SecretConfigMapNamePrefix + "-" + name1 + "-tigera.io"},
								Key:                  "apikey",
							},
						},
					},
				},
			},
		},
	}
	spec2 := apiv3.GlobalThreatFeedSpec{
		Content:     apiv3.ThreatFeedContentIPset,
		Mode:        mode2,
		Description: "test2",
		FeedType:    type2,
		GlobalNetworkSet: &apiv3.GlobalNetworkSetSync{
			Labels: map[string]string{"level": "low"},
		},
		Pull: &apiv3.Pull{
			Period: "10h",
			HTTP: &apiv3.HTTPPull{
				Format: apiv3.ThreatFeedFormat{
					NewlineDelimited: &apiv3.ThreatFeedFormatNewlineDelimited{},
				},
				URL: "https://projectcalico.org/feed",
				Headers: []apiv3.HTTPHeader{
					{Name: "Accept", Value: "text/plain"},
					{
						Name: "Config",
						ValueFrom: &apiv3.HTTPHeaderSource{
							ConfigMapKeyRef: &v1.ConfigMapKeySelector{
								LocalObjectReference: v1.LocalObjectReference{Name: apiv3.SecretConfigMapNamePrefix + "-" + name2 + "-projectcalico"},
								Key:                  "config",
							},
						},
					},
				},
			},
		},
	}

	DescribeTable("GlobalThreatFeed e2e CRUD tests",
		func(name1, name2 string, spec1, spec2 apiv3.GlobalThreatFeedSpec) {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			err = be.Clean()
			Expect(err).NotTo(HaveOccurred())

			By("Updating the GlobalThreatFeed before it is created")
			_, outError := c.GlobalThreatFeeds().Update(ctx, &apiv3.GlobalThreatFeed{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now(), UID: uid},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring(fmt.Sprintf("resource does not exist: GlobalThreatFeed(%s)", name1)))

			By("Attempting to creating a new GlobalThreatFeed with name1/spec1 and a non-empty ResourceVersion")
			_, outError = c.GlobalThreatFeeds().Create(ctx, &apiv3.GlobalThreatFeed{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "12345"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))

			By("Creating a new GlobalThreatFeed with name1/spec1")
			res1, outError := c.GlobalThreatFeeds().Create(ctx, &apiv3.GlobalThreatFeed{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(apiv3.KindGlobalThreatFeed, testutils.ExpectNoNamespace, name1, spec1))

			// Track the version of the original data for name1.
			rv11 := res1.ResourceVersion

			By("Attempting to create the same GlobalThreatFeed with name1")
			_, outError = c.GlobalThreatFeeds().Create(ctx, &apiv3.GlobalThreatFeed{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring(fmt.Sprintf("resource already exists: GlobalThreatFeed(%s)", name1)))

			By("Getting GlobalThreatFeed (name1) and comparing the output against spec1")
			res, outError := c.GlobalThreatFeeds().Get(ctx, name1, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindGlobalThreatFeed, testutils.ExpectNoNamespace, name1, spec1))
			Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))

			By("Getting GlobalThreatFeed (name2) before it is created")
			_, outError = c.GlobalThreatFeeds().Get(ctx, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring(fmt.Sprintf("resource does not exist: GlobalThreatFeed(%s)", name2)))

			By("Listing all the GlobalThreatFeeds, expecting a single result with name1/spec1")
			outList, outError := c.GlobalThreatFeeds().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(1))
			Expect(&outList.Items[0]).To(MatchResource(apiv3.KindGlobalThreatFeed, testutils.ExpectNoNamespace, name1, spec1))

			By("Creating a new GlobalThreatFeed with name2/spec2")
			res2, outError := c.GlobalThreatFeeds().Create(ctx, &apiv3.GlobalThreatFeed{
				ObjectMeta: metav1.ObjectMeta{Name: name2},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res2).To(MatchResource(apiv3.KindGlobalThreatFeed, testutils.ExpectNoNamespace, name2, spec2))

			By("Getting GlobalThreatFeed (name2) and comparing the output against spec2")
			res, outError = c.GlobalThreatFeeds().Get(ctx, name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindGlobalThreatFeed, testutils.ExpectNoNamespace, name2, spec2))
			Expect(res.ResourceVersion).To(Equal(res2.ResourceVersion))

			By("Listing all the GlobalThreatFeeds, expecting a two results with name1/spec1 and name2/spec2")
			outList, outError = c.GlobalThreatFeeds().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(2))
			Expect(&outList.Items[0]).To(MatchResource(apiv3.KindGlobalThreatFeed, testutils.ExpectNoNamespace, name1, spec1))
			Expect(&outList.Items[1]).To(MatchResource(apiv3.KindGlobalThreatFeed, testutils.ExpectNoNamespace, name2, spec2))

			By("Updating GlobalThreatFeed name1")
			spec1Tmp := apiv3.GlobalThreatFeedSpec{
				Content:     apiv3.ThreatFeedContentIPset,
				Mode:        mode1,
				Description: "test1",
				FeedType:    type1,
				GlobalNetworkSet: &apiv3.GlobalNetworkSetSync{
					Labels: map[string]string{"level": "high"},
				},
				Pull: &apiv3.Pull{
					Period: "10h",
					HTTP: &apiv3.HTTPPull{
						Format: apiv3.ThreatFeedFormat{
							NewlineDelimited: &apiv3.ThreatFeedFormatNewlineDelimited{},
						},
						URL: "https://tigera.io/feed",
						Headers: []apiv3.HTTPHeader{
							{Name: "Accept", Value: "text/plain"},
							{
								Name: "Key",
								ValueFrom: &apiv3.HTTPHeaderSource{
									SecretKeyRef: &v1.SecretKeySelector{
										LocalObjectReference: v1.LocalObjectReference{Name: apiv3.SecretConfigMapNamePrefix + "-" + name1 + "-tigera.io"},
										Key:                  "apikey",
									},
								},
							},
						},
					},
				},
			}
			res1.Spec = spec1Tmp
			res1, outError = c.GlobalThreatFeeds().Update(ctx, res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(apiv3.KindGlobalThreatFeed, testutils.ExpectNoNamespace, name1, spec1Tmp))

			By("Attempting to update the GlobalThreatFeed without a Creation Timestamp")
			res, outError = c.GlobalThreatFeeds().Update(ctx, &apiv3.GlobalThreatFeed{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", UID: uid},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.CreationTimestamp = '0001-01-01 00:00:00 +0000 UTC' (field must be set for an Update request)"))

			By("Attempting to update the GlobalThreatFeed without a UID")
			res, outError = c.GlobalThreatFeeds().Update(ctx, &apiv3.GlobalThreatFeed{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now()},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.UID = '' (field must be set for an Update request)"))

			// Track the version of the updated name1 data.
			rv12 := res1.ResourceVersion

			By("Updating GlobalThreatFeed name1 without specifying a resource version")
			res1.Spec = spec1
			res1.ObjectMeta.ResourceVersion = ""
			_, outError = c.GlobalThreatFeeds().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '' (field must be set for an Update request)"))

			By("Updating GlobalThreatFeed name1 using the previous resource version")
			res1.Spec = spec1
			res1.ResourceVersion = rv11
			_, outError = c.GlobalThreatFeeds().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: GlobalThreatFeed(" + name1 + ")"))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Getting GlobalThreatFeed (name1) with the original resource version and comparing the output against spec1")
				res, outError = c.GlobalThreatFeeds().Get(ctx, name1, options.GetOptions{ResourceVersion: rv11})
				Expect(outError).NotTo(HaveOccurred())
				Expect(res).To(MatchResource(apiv3.KindGlobalThreatFeed, testutils.ExpectNoNamespace, name1, spec1))
				Expect(res.ResourceVersion).To(Equal(rv11))
			}

			By("Getting GlobalThreatFeed (name1) with the updated resource version and comparing the output against spec1Tmp")
			res, outError = c.GlobalThreatFeeds().Get(ctx, name1, options.GetOptions{ResourceVersion: rv12})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(apiv3.KindGlobalThreatFeed, testutils.ExpectNoNamespace, name1, spec1Tmp))
			Expect(res.ResourceVersion).To(Equal(rv12))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Listing GlobalThreatFeeds with the original resource version and checking for a single result with name1/spec1")
				outList, outError = c.GlobalThreatFeeds().List(ctx, options.ListOptions{ResourceVersion: rv11})
				Expect(outError).NotTo(HaveOccurred())
				Expect(outList.Items).To(HaveLen(1))
				Expect(&outList.Items[0]).To(MatchResource(apiv3.KindGlobalThreatFeed, testutils.ExpectNoNamespace, name1, spec1))
			}

			By("Listing GlobalThreatFeeds with the latest resource version and checking for two results with name1/spec2 and name2/spec2")
			outList, outError = c.GlobalThreatFeeds().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(2))
			Expect(&outList.Items[0]).To(MatchResource(apiv3.KindGlobalThreatFeed, testutils.ExpectNoNamespace, name1, spec1Tmp))
			Expect(&outList.Items[1]).To(MatchResource(apiv3.KindGlobalThreatFeed, testutils.ExpectNoNamespace, name2, spec2))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Deleting GlobalThreatFeed (name1) with the old resource version")
				_, outError = c.GlobalThreatFeeds().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: rv11})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(Equal("update conflict: GlobalThreatFeed(" + name1 + ")"))
			}

			By("Deleting GlobalThreatFeed (name1) with the new resource version")
			dres, outError := c.GlobalThreatFeeds().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: rv12})
			Expect(outError).NotTo(HaveOccurred())
			Expect(dres).To(MatchResource(apiv3.KindGlobalThreatFeed, testutils.ExpectNoNamespace, name1, spec1Tmp))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Updating GlobalThreatFeed name2 with a 2s TTL and waiting for the entry to be deleted")
				_, outError = c.GlobalThreatFeeds().Update(ctx, res2, options.SetOptions{TTL: 2 * time.Second})
				Expect(outError).NotTo(HaveOccurred())
				Eventually(func() string {
					_, err := c.GlobalThreatFeeds().Get(ctx, name2, options.GetOptions{})
					if err != nil {
						return err.Error()
					}
					return ""
				}, 5*time.Second, 200*time.Millisecond).Should(ContainSubstring("resource does not exist: GlobalThreatFeed(" + name2 + ")"))

				By("Creating GlobalThreatFeed name2 with a 2s TTL and waiting for the entry to be deleted")
				_, outError = c.GlobalThreatFeeds().Create(ctx, &apiv3.GlobalThreatFeed{
					ObjectMeta: metav1.ObjectMeta{Name: name2},
					Spec:       spec2,
				}, options.SetOptions{TTL: 2 * time.Second})
				Expect(outError).NotTo(HaveOccurred())
				Eventually(func() string {
					_, err := c.GlobalThreatFeeds().Get(ctx, name2, options.GetOptions{})
					if err != nil {
						return err.Error()
					}
					return ""
				}, 5*time.Second, 200*time.Millisecond).Should(ContainSubstring("resource does not exist: GlobalThreatFeed(" + name2 + ")"))
			}

			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				By("Attempting to delete GlobalThreatFeed (name2) again")
				dres, outError = c.GlobalThreatFeeds().Delete(ctx, name2, options.DeleteOptions{})
				Expect(outError).NotTo(HaveOccurred())
				Expect(dres).To(MatchResource(apiv3.KindGlobalThreatFeed, testutils.ExpectNoNamespace, name2, spec2))
			}

			By("Listing all GlobalThreatFeeds and expecting no items")
			outList, outError = c.GlobalThreatFeeds().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))

			By("Getting GlobalThreatFeed (name2) and expecting an error")
			_, outError = c.GlobalThreatFeeds().Get(ctx, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: GlobalThreatFeed(" + name2 + ")"))
		},

		// Test 1: Pass two fully populated GlobalThreatFeedSpecs and expect the series of operations to succeed.
		Entry("Two fully populated GlobalThreatFeedSpecs", name1, name2, spec1, spec2),
	)

	Describe("GlobalThreatFeed watch functionality", func() {
		It("should handle watch events for different resource versions and event types", func() {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			err = be.Clean()
			Expect(err).NotTo(HaveOccurred())

			By("Listing GlobalThreatFeeds with the latest resource version and checking for two results with name1/spec2 and name2/spec2")
			outList, outError := c.GlobalThreatFeeds().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))
			rev0 := outList.ResourceVersion

			By("Configuring a GlobalThreatFeed name1/spec1 and storing the response")
			outRes1, err := c.GlobalThreatFeeds().Create(
				ctx,
				&apiv3.GlobalThreatFeed{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			Expect(err).ToNot(HaveOccurred())
			rev1 := outRes1.ResourceVersion

			By("Configuring a GlobalThreatFeed name2/spec2 and storing the response")
			outRes2, err := c.GlobalThreatFeeds().Create(
				ctx,
				&apiv3.GlobalThreatFeed{
					ObjectMeta: metav1.ObjectMeta{Name: name2},
					Spec:       spec2,
				},
				options.SetOptions{},
			)
			Expect(err).ToNot(HaveOccurred())

			By("Starting a watcher from revision rev1 - this should skip the first creation")
			w, err := c.GlobalThreatFeeds().Watch(ctx, options.ListOptions{ResourceVersion: rev1})
			Expect(err).NotTo(HaveOccurred())
			testWatcher1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher1.Stop()

			By("Deleting res1")
			_, err = c.GlobalThreatFeeds().Delete(ctx, name1, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Checking for two events, create res2 and delete re1")
			testWatcher1.ExpectEvents(apiv3.KindGlobalThreatFeed, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes2,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
			})

			By("Starting a watcher from rev0 - this should get all events")
			w, err = c.GlobalThreatFeeds().Watch(ctx, options.ListOptions{ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher2.Stop()

			By("Modifying res2")
			spec2Tmp := spec2
			spec2Tmp.Pull.Period = "24h"
			outRes3, err := c.GlobalThreatFeeds().Update(
				ctx,
				&apiv3.GlobalThreatFeed{
					ObjectMeta: outRes2.ObjectMeta,
					Spec:       spec2Tmp,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			testWatcher2.ExpectEvents(apiv3.KindGlobalThreatFeed, []watch.Event{
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

			// Only etcdv3 supports watching a specific instance of a resource.
			if config.Spec.DatastoreType == apiconfig.EtcdV3 {
				By("Starting a watcher from rev0 watching name1 - this should get all events for name1")
				w, err = c.GlobalThreatFeeds().Watch(ctx, options.ListOptions{Name: name1, ResourceVersion: rev0})
				Expect(err).NotTo(HaveOccurred())
				testwatcher21 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
				defer testwatcher21.Stop()
				testwatcher21.ExpectEvents(apiv3.KindGlobalThreatFeed, []watch.Event{
					{
						Type:   watch.Added,
						Object: outRes1,
					},
					{
						Type:     watch.Deleted,
						Previous: outRes1,
					},
				})
				testwatcher21.Stop()
			}

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.GlobalThreatFeeds().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher3 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher3.Stop()
			testWatcher3.ExpectEvents(apiv3.KindGlobalThreatFeed, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})

			By("Configuring GlobalThreatFeed name1/spec1 again and storing the response")
			outRes1, err = c.GlobalThreatFeeds().Create(
				ctx,
				&apiv3.GlobalThreatFeed{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       spec1,
				},
				options.SetOptions{},
			)

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.GlobalThreatFeeds().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher4 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher4.Stop()
			testWatcher4.ExpectEventsAnyOrder(apiv3.KindGlobalThreatFeed, []watch.Event{
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
			err = be.Clean()
			Expect(err).NotTo(HaveOccurred())
			testWatcher4.ExpectEvents(apiv3.KindGlobalThreatFeed, []watch.Event{
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes3,
				},
			})
		})
	})
})
