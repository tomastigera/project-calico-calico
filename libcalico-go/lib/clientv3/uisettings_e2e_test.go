// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package clientv3_test

import (
	"context"

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

var _ = testutils.E2eDatastoreDescribe("UISettings tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {
	ctx := context.Background()
	name1 := "group1.uisettings-1"
	name2 := "group2.uisettings-2"
	TRUE := true
	FALSE := false

	namedselector1 := []apiv3.NamedSelector{
		{
			Name:     "ns1",
			Selector: "sel1 == '1'",
		},
		{
			Name:     "ns2",
			Selector: "sel2 != '2'",
		},
	}
	nodes := []apiv3.UIGraphNodeView{
		{
			UIGraphNode: apiv3.UIGraphNode{
				ID:        "ideg1",
				Type:      "typeeg1",
				Name:      "eg1",
				Namespace: "nseg1",
			},
			InFocus:       &TRUE,
			Expanded:      &TRUE,
			FollowIngress: &TRUE,
			FollowEgress:  &TRUE,
			Deemphasize:   &TRUE,
			Hide:          &TRUE,
			HideUnrelated: &TRUE,
		}, {
			UIGraphNode: apiv3.UIGraphNode{
				ID:        "ideg2",
				Type:      "typeeg2",
				Name:      "eg1",
				Namespace: "nseg2",
			},
		},
	}
	position1 := []apiv3.Position{
		{
			ID:   "namespace/ns1",
			XPos: 10,
			YPos: 100,
			ZPos: 9,
		},
		{
			ID:   "namespace/ns2",
			XPos: 4,
			YPos: 65,
			ZPos: 87,
		},
	}
	layers1 := []string{
		"l1", "l2", "l3", "l4",
	}

	uigraphview1 := &apiv3.UIGraphView{
		ExpandPorts:               &TRUE,
		FollowConnectionDirection: &FALSE,
		SplitIngressEgress:        &TRUE,
		HostAggregationSelectors:  namedselector1,
		LayoutType:                "standard",
		Positions:                 position1,
		Layers:                    layers1,
		Nodes:                     nodes,
	}

	uigraphlayer1 := &apiv3.UIGraphLayer{
		Nodes: []apiv3.UIGraphNode{
			{ID: "namespace/n1", Type: "namespace", Name: "n1"},
			{ID: "namespace/n2", Type: "namespace", Name: "n2"},
			{ID: "namespace/n3", Type: "namespace", Name: "n3"},
		},
		Icon: "smiley face",
	}

	dashboard1 := &apiv3.UIDashboard{}

	spec1 := apiv3.UISettingsSpec{
		Group:       "group1",
		Description: "cluster",
		View:        uigraphview1,
		Layer:       nil,
		Dashboard:   nil,
	}
	spec2 := apiv3.UISettingsSpec{
		Group:       "group2",
		Description: "cluster",
		View:        nil,
		Layer:       uigraphlayer1,
		Dashboard:   nil,
	}
	spec3 := apiv3.UISettingsSpec{
		Group:       "group1",
		Description: "cluster",
		View:        nil,
		Layer:       nil,
		Dashboard:   dashboard1,
	}

	It("supports CRUD and validates correctly", func() {
		c, err := clientv3.New(config)
		Expect(err).NotTo(HaveOccurred())

		be, err := backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		_ = be.Clean()

		By("Updating the UISettings before it is created")
		_, outError := c.UISettings().Update(ctx, &apiv3.UISettings{
			ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now(), UID: uid},
			Spec:       spec1,
		}, options.SetOptions{})
		Expect(outError).To(HaveOccurred())
		Expect(outError.Error()).To(ContainSubstring("resource does not exist: UISettings(" + name1 + ") with error:"))

		By("Attempting to create a new UISettings with name1/spec1 and a non-empty ResourceVersion")
		_, outError = c.UISettings().Create(ctx, &apiv3.UISettings{
			ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "12345"},
			Spec:       spec1,
		}, options.SetOptions{})
		Expect(outError).To(HaveOccurred())
		Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))

		By("Creating a new UISettings with name1/spec1")
		res1, outError := c.UISettings().Create(ctx, &apiv3.UISettings{
			ObjectMeta: metav1.ObjectMeta{Name: name1},
			Spec:       spec1,
		}, options.SetOptions{})
		Expect(outError).NotTo(HaveOccurred())
		Expect(res1).To(MatchResource(apiv3.KindUISettings, testutils.ExpectNoNamespace, name1, spec1))

		By("Getting UISettings (name1) and comparing the output against spec1")
		res, outError := c.UISettings().Get(ctx, name1, options.GetOptions{})
		Expect(outError).NotTo(HaveOccurred())
		Expect(res).To(MatchResource(apiv3.KindUISettings, testutils.ExpectNoNamespace, name1, spec1))
		Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))

		By("Listing all the UISettings, expecting a single result with name1/spec1")
		outList, outError := c.UISettings().List(ctx, options.ListOptions{})
		Expect(outError).NotTo(HaveOccurred())
		Expect(outList.Items).To(ConsistOf(
			testutils.Resource(apiv3.KindUISettings, testutils.ExpectNoNamespace, name1, spec1),
		))

		By("Creating a new UISettings with name2/spec2")
		res2, outError := c.UISettings().Create(ctx, &apiv3.UISettings{
			ObjectMeta: metav1.ObjectMeta{Name: name2},
			Spec:       spec2,
		}, options.SetOptions{})
		Expect(outError).NotTo(HaveOccurred())
		Expect(res2).To(MatchResource(apiv3.KindUISettings, testutils.ExpectNoNamespace, name2, spec2))

		By("Getting UISettings (name2) and comparing the output against spec2")
		res, outError = c.UISettings().Get(ctx, name2, options.GetOptions{})
		Expect(outError).NotTo(HaveOccurred())
		Expect(res2).To(MatchResource(apiv3.KindUISettings, testutils.ExpectNoNamespace, name2, spec2))
		Expect(res.ResourceVersion).To(Equal(res2.ResourceVersion))

		By("Listing all the UISettings, expecting a two results with name1/spec1 and name2/spec2")
		outList, outError = c.UISettings().List(ctx, options.ListOptions{})
		Expect(outError).NotTo(HaveOccurred())
		Expect(outList.Items).To(ConsistOf(
			testutils.Resource(apiv3.KindUISettings, testutils.ExpectNoNamespace, name1, spec1),
			testutils.Resource(apiv3.KindUISettings, testutils.ExpectNoNamespace, name2, spec2),
		))

		By("Updating UISettings name1 with spec3")
		res1.Spec = spec3
		res1, outError = c.UISettings().Update(ctx, res1, options.SetOptions{})
		Expect(outError).NotTo(HaveOccurred())
		Expect(res1).To(MatchResource(apiv3.KindUISettings, testutils.ExpectNoNamespace, name1, spec3))

		By("Deleting UISettings (name1)")
		dres, outError := c.UISettings().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: res1.ResourceVersion})
		Expect(outError).NotTo(HaveOccurred())
		Expect(dres).To(MatchResource(apiv3.KindUISettings, testutils.ExpectNoNamespace, name1, spec3))

		By("Deleting UISettings (name2)")
		dres, outError = c.UISettings().Delete(ctx, name2, options.DeleteOptions{ResourceVersion: res2.ResourceVersion})
		Expect(outError).NotTo(HaveOccurred())
		Expect(dres).To(MatchResource(apiv3.KindUISettings, testutils.ExpectNoNamespace, name2, spec2))

		By("Listing all UISettings and expecting no items")
		outList, outError = c.UISettings().List(ctx, options.ListOptions{})
		Expect(outError).NotTo(HaveOccurred())
		Expect(outList.Items).To(HaveLen(0))
	})

	Describe("UISettings watch functionality", func() {
		It("should handle watch events for different resource versions and event types", func() {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			_ = be.Clean()

			By("Listing UISettings with the latest resource version and checking for two results with name1/spec2 and name2/spec2")
			outList, outError := c.UISettings().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))

			By("Configuring a UISettings name1/spec1 and storing the response")
			outRes1, err := c.UISettings().Create(
				ctx,
				&apiv3.UISettings{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			rev1 := outRes1.ResourceVersion

			By("Configuring a UISettings name2/spec2 and storing the response")
			outRes2, err := c.UISettings().Create(
				ctx,
				&apiv3.UISettings{
					ObjectMeta: metav1.ObjectMeta{Name: name2},
					Spec:       spec2,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			By("Starting a watcher from revision rev1 - this should skip the first creation")
			w, err := c.UISettings().Watch(ctx, options.ListOptions{ResourceVersion: rev1})
			Expect(err).NotTo(HaveOccurred())
			testWatcher1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher1.Stop()

			By("Deleting res1")
			_, err = c.UISettings().Delete(ctx, name1, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Checking for two events, create res2 and delete re1")
			testWatcher1.ExpectEvents(apiv3.KindUISettings, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes2,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
			})

			By("Cleaning the datastore and expecting deletion events for each configured resource (tests prefix deletes results in individual events for each key)")
			_ = be.Clean()
			testWatcher1.ExpectEvents(apiv3.KindUISettings, []watch.Event{
				{
					Type:     watch.Deleted,
					Previous: outRes2,
				},
			})
		})
	})
})
