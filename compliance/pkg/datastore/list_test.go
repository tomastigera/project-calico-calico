// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package datastore_test

import (
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/compliance/pkg/datastore"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
)

var _ = ginkgo.Describe("list typemeta", func() {
	ginkgo.It("should fill in list typemeta", func() {
		in := &v3.NetworkPolicyList{
			Items: []v3.NetworkPolicy{
				{}, {},
			},
		}

		err := datastore.SetListTypeMeta(in, resources.TypeCalicoNetworkPolicies)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(in.TypeMeta).To(gomega.Equal(resources.TypeCalicoNetworkPolicies))
		gomega.Expect(in.Items[0].TypeMeta).To(gomega.Equal(resources.TypeCalicoNetworkPolicies))
		gomega.Expect(in.Items[1].TypeMeta).To(gomega.Equal(resources.TypeCalicoNetworkPolicies))
	})
})
