// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package list_test

import (
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"

	"github.com/projectcalico/calico/lma/pkg/list"
)

var _ = Describe("types", func() {
	It("should support TimestampedResourceList marshal and unmarshal", func() {
		var blob []byte
		l := new(list.TimestampedResourceList)

		// Pods
		blob = []byte(`{
  "apiVersion": "v1",
  "kind": "Pod",
  "items": [
     {
       "apiVersion": "v1",
       "kind": "Pod",
       "metadata": {
         "name": "pod1",
         "namespace": "namespace1",
         "creationTimestamp": "2018-03-20T15:20:22Z"
       },
       "spec": {
         "containers": null
       },
       "status": {}
     }
   ],
  "requestStartedTimestamp": "2019-03-20T15:20:11Z",
  "requestCompletedTimestamp": "2019-04-20T15:20:12Z",
  "cluster": "cluster1",		
  "metadata": {
    "resourceVersion": "abcdef"
  }
}
`)
		Expect(json.Unmarshal(blob, l)).ToNot(HaveOccurred())
		_, ok := l.ResourceList.(*corev1.PodList)
		Expect(ok).To(BeTrue())

		b, err := json.Marshal(l)
		Expect(err).ToNot(HaveOccurred())
		Expect(b).To(MatchJSON(blob))
	})

	It("should fail gracefully trying to unmarshal an unknown resource kind", func() {
		var blob []byte
		l := new(list.TimestampedResourceList)

		// Pods
		blob = []byte(`{
  "apiVersion": "v1",
  "kind": "FooBarBazList",
  "items": [
     {
       "apiVersion": "v1",
       "kind": "FooBarBaz",
       "metadata": {
         "name": "pod1",
         "namespace": "namespace1",
         "creationTimestamp": "2018-03-20T15:20:22Z"
       },
       "spec": {
         "containers": null
       },
       "status": {}
     }
   ],
  "requestStartedTimestamp": "2019-03-20T15:20:11Z",
  "requestCompletedTimestamp": "2019-04-20T15:20:12Z",
  "cluster": "cluster1",		
  "metadata": {
    "resourceVersion": "abcdef"
  }
}
`)
		Expect(json.Unmarshal(blob, l)).To(HaveOccurred())
	})
})
