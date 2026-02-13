// Copyright (c) 2017 Tigera, Inc. All rights reserved.
//
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

package cache

import (
	"fmt"
	"reflect"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	gocache "github.com/patrickmn/go-cache"
	"k8s.io/client-go/util/workqueue"
)

type resource struct {
	name string
}

func listFunc() (map[string]interface{}, error) {
	m := make(map[string]interface{})
	for i := 1; i <= 10; i++ {
		resourceName := fmt.Sprintf("ns%d", i)
		obj := resource{
			name: resourceName,
		}
		m[resourceName] = obj
	}

	return m, nil
}

var _ = Describe("Cache", func() {

	rcargs := ResourceCacheArgs{
		ListFunc:   listFunc,
		ObjectType: reflect.TypeOf(resource{}),
	}

	Context("Get operation", func() {
		Context("With non-existing key", func() {
			rc := NewResourceCache(rcargs)
			rc.Run("0m")

			returnedObject, exists := rc.Get("nokey")
			It("should return nil", func() {
				Expect(exists).Should(BeFalse())
				Expect(returnedObject).Should(BeNil())
			})
		})

		Context("With empty key", func() {
			rc := NewResourceCache(rcargs)
			rc.Run("0m")

			returnedObject, exists := rc.Get("")
			It("should return nil", func() {
				Expect(exists).Should(BeFalse())
				Expect(returnedObject).Should(BeNil())
			})
		})

		Context("With key/value present in cache", func() {
			rc := NewResourceCache(rcargs)
			rc.Run("0m")

			resourceName := "namespace1"
			obj := resource{
				name: resourceName,
			}
			rc.Set(resourceName, obj)
			storedObj, exists := rc.Get(resourceName)
			It("should return same resource", func() {
				Expect(exists).To(BeTrue())
				Expect(storedObj).To(Equal(obj))
			})
		})
	})

	Context("Prime operation", func() {
		Context("When key not present in cache", func() {
			rc := NewResourceCache(rcargs)
			rc.Run("0m")

			resourceName := "namespace1"
			obj := resource{
				name: resourceName,
			}
			rc.Prime(resourceName, obj)
			returnedObject, exists := rc.Get(resourceName)
			It("should add it to cache", func() {
				Expect(exists).Should(BeTrue())
				Expect(returnedObject).Should(Equal(obj))
			})

			queue := rc.GetQueue()
			It("should not add resource to queue", func() {
				Expect(queue.Len()).To(Equal(0))
			})
		})

		Context("With the duplicate key", func() {
			rc := NewResourceCache(rcargs)
			rc.Run("0m")

			resourceName := "namespace1"
			obj := resource{
				name: resourceName,
			}
			rc.Prime("namespace1", obj)
			rc.Prime("namespace1", obj)

			queue := rc.GetQueue()
			It("should return list of single key", func() {
				Expect(len(rc.ListKeys())).To(Equal(1))
			})

			It("should not add resource to queue", func() {
				Expect(queue.Len()).To(Equal(0))
			})
		})
	})

	Context("Set Operation", func() {
		Context("when resource already not present in cache", func() {
			rc := NewResourceCache(rcargs)
			rc.Run("0m")

			resourceName := "namespace1"
			obj := resource{
				name: resourceName,
			}

			// Set the resource in resource
			rc.Set(resourceName, obj)
			It("should store resource in cache", func() {
				storedobj, exists := rc.Get(resourceName)
				Expect(exists).To(BeTrue())
				Expect(storedobj).To(Equal(obj))
			})

			// Assert that resource gets queued.
			queue := rc.GetQueue()
			queuedKey, _ := queue.Get()
			It("should add resource to queue", func() {
				Expect(queuedKey).To(Equal(resourceName))
			})
		})

		Context("when exact resource already present in cache", func() {
			rc := NewResourceCache(rcargs)
			rc.Run("0m")

			resourceName := "namespace1"
			obj := resource{
				name: resourceName,
			}

			// Set resource to
			rc.Set(resourceName, obj)
			queue := rc.GetQueue()

			// Remove the key for already added resource
			queue.Get()

			// Set same resource in
			rc.Set(resourceName, obj)

			// Assert that cache does not queue new key for already existing resource
			It("should not add key in queue", func() {
				Expect(queue.Len()).To(Equal(0))
			})
		})
	})

	Context("Delete Operation", func() {
		Context("delete valid resource in cache", func() {
			rc := NewResourceCache(rcargs)
			rc.Run("0m")

			resourceName := "namespace1"
			obj := resource{
				name: resourceName,
			}

			// Add resource in
			rc.Set(resourceName, obj)
			_, exists := rc.Get(resourceName)
			It("should add resource to cache", func() {
				Expect(exists).To(BeTrue())
			})

			rc.Delete(resourceName)
			storedObj1, exists1 := rc.Get(resourceName)
			It("should remove resource from cache", func() {
				Expect(len(rc.ListKeys())).To(Equal(0))
				Expect(exists1).To(BeFalse())
				Expect(storedObj1).To(BeNil())
			})

			// Assert that key gets added in queue
			queue := rc.GetQueue()
			queuedObj, _ := queue.Get()
			It("should add key in queue", func() {
				Expect(queuedObj).To(Equal(resourceName))
			})
		})
	})

	Context("Clean Operation", func() {
		Context("With resource present in cache", func() {
			rc := NewResourceCache(rcargs)
			rc.Run("0m")

			resourceName := "namespace1"
			obj := resource{
				name: resourceName,
			}

			// Add resource in
			rc.Set(resourceName, obj)
			_, exists := rc.Get(resourceName)
			It("should add resource to cache", func() {
				Expect(exists).To(BeTrue())
			})

			// Cleanup resource.
			rc.Clean(resourceName)

			// Assert that resource is cleaned up.
			storedObj, existsAfterClean := rc.Get(resourceName)
			It("should remove resource from cache", func() {
				Expect(existsAfterClean).To(BeFalse())
				Expect(storedObj).To(BeNil())
			})
		})
	})

	Context("Stop operation", func() {
		var (
			c           *calicoCache
			mockQueue   workqueue.TypedRateLimitingInterface[any]
			mockCache   *gocache.Cache
			stopChannel chan struct{}
		)

		const (
			noExpiration      = 0
			defaultExpiration = 5 * time.Minute
		)
		BeforeEach(func() {
			mockQueue = workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[any]())
			mockCache = gocache.New(noExpiration, defaultExpiration)
			mockCache.Set("namespace1", resource{name: "namespace1"}, gocache.NoExpiration)
			mockCache.Set("namespace2", resource{name: "namespace2"}, gocache.NoExpiration)
			stopChannel = make(chan struct{})

			c = &calicoCache{
				threadSafeCache: mockCache,
				workqueue:       mockQueue,
				stopChan:        stopChannel,
				running:         true,
				mut:             &sync.Mutex{},
			}
		})

		Describe("Stop", func() {
			It("should shut down the workqueue", func() {
				c.Stop()
				Expect(mockQueue.ShuttingDown()).To(BeTrue())
			})

			It("should flush the cache", func() {
				Expect(mockCache.ItemCount()).To(Equal(2))
				c.Stop()
				Expect(mockCache.ItemCount()).To(Equal(0))
			})

			It("should set running to false", func() {
				c.Stop()
				Expect(c.running).To(BeFalse())
			})

			It("should close the stop channel", func() {
				c.Stop()
				_, open := <-stopChannel
				Expect(open).To(BeFalse())
			})
		})
	})
})
