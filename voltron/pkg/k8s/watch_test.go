package k8s_test

import (
	"context"
	"errors"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/lib/std/chanutil"
	"github.com/projectcalico/calico/voltron/pkg/k8s"
	mockwatch "github.com/projectcalico/calico/voltron/pkg/thirdpartymocks/k8s.io/apimachinery/pkg/watch"
	mockk8sclient "github.com/projectcalico/calico/voltron/pkg/thirdpartymocks/sigs.k8s.io/controller-runtime/pkg/client"
)

func TestWatchResource(t *testing.T) {
	RegisterTestingT(t)

	scheme := kscheme.Scheme
	Expect(v3.AddToScheme(scheme)).NotTo(HaveOccurred())

	setList := func(mcList v3.ManagedClusterList) func(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
		return func(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
			*(list.(*v3.ManagedClusterList)) = mcList
			return nil
		}
	}

	mustReadChannel := func(ctx context.Context, results chan k8s.Event[v3.ManagedCluster]) k8s.Event[v3.ManagedCluster] {
		t.Helper()
		result, err := chanutil.ReadWithDeadline(ctx, results, 5*time.Second)
		Expect(err).ShouldNot(HaveOccurred())
		return result
	}

	t.Run("happy paths", func(t *testing.T) {
		t.Run("list returns initial sync values then wait sends a value.", func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			results := make(chan k8s.Event[v3.ManagedCluster], 1)
			defer close(results)

			mockClient := new(mockk8sclient.WithWatch)

			mockClient.EXPECT().
				List(ctx, mock.Anything, mock.Anything).RunAndReturn(
				setList(v3.ManagedClusterList{
					ListMeta: metav1.ListMeta{ResourceVersion: "1"},
					Items:    []v3.ManagedCluster{{ObjectMeta: metav1.ObjectMeta{Name: "test"}}},
				}))

			go func() {
				Expect(k8s.WatchManagedClusters(ctx, mockClient, "", results)).ShouldNot(HaveOccurred())
			}()

			watchInf := new(mockwatch.Interface)
			events := make(chan watch.Event, 1)
			defer close(events)

			watchInf.EXPECT().ResultChan().Return(events)
			watchInf.EXPECT().Stop().Return()

			mockClient.EXPECT().
				Watch(mock.Anything, mock.Anything, mock.Anything).Return(watchInf, nil).Maybe()

			result := mustReadChannel(ctx, results)
			Expect(result.Type).Should(Equal(k8s.SyncStart))

			result = mustReadChannel(ctx, results)
			Expect(result.Type).Should(Equal(k8s.Added))
			Expect(result.Obj.Name).Should(Equal("test"))

			result = mustReadChannel(ctx, results)
			Expect(result.Type).Should(Equal(k8s.SyncEnd))
		})

		t.Run("list doesn't return any values and sync event is still done, watch still sends a value.", func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			results := make(chan k8s.Event[v3.ManagedCluster], 1)
			defer close(results)

			mockClient := new(mockk8sclient.WithWatch)

			mockClient.EXPECT().
				List(ctx, mock.Anything, mock.Anything).RunAndReturn(
				setList(v3.ManagedClusterList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}}))

			go func() {
				Expect(k8s.WatchManagedClusters(ctx, mockClient, "", results)).ShouldNot(HaveOccurred())
			}()

			watchInf := new(mockwatch.Interface)
			events := make(chan watch.Event, 1)
			defer close(events)

			watchInf.EXPECT().ResultChan().Return(events)
			watchInf.EXPECT().Stop().Return()

			mockClient.EXPECT().
				Watch(mock.Anything, mock.Anything, mock.Anything).Return(watchInf, nil).Maybe()

			events <- watch.Event{Type: watch.Added, Object: &v3.ManagedCluster{ObjectMeta: metav1.ObjectMeta{Name: "test"}}}

			result := mustReadChannel(ctx, results)
			Expect(result.Type).Should(Equal(k8s.SyncStart))

			result = mustReadChannel(ctx, results)
			Expect(result.Type).Should(Equal(k8s.SyncEnd))

			result = mustReadChannel(ctx, results)
			Expect(result.Type).Should(Equal(k8s.Added))
			Expect(result.Obj.Name).Should(Equal("test"))
		})
	})

	t.Run("recovers from k8s failures", func(t *testing.T) {
		t.Run("retries the initial list and sync when the k8s list call returns an error", func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			results := make(chan k8s.Event[v3.ManagedCluster], 1)
			defer close(results)

			mockClient := new(mockk8sclient.WithWatch)

			// The initial list call returns an error.
			mockClient.EXPECT().
				List(mock.Anything, mock.Anything, mock.Anything).Return(errors.New("error")).Once()

			// The next list call succeeds and sends the event.
			mockClient.EXPECT().
				List(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(
				func(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
					l := list.(*v3.ManagedClusterList)
					l.Items = append(l.Items, v3.ManagedCluster{
						ObjectMeta: metav1.ObjectMeta{Name: "test"},
					})
					return nil
				}).Once()

			watchInf := new(mockwatch.Interface)
			events := make(chan watch.Event, 1)
			defer close(events)
			watchInf.EXPECT().ResultChan().Return(events)
			watchInf.EXPECT().Stop().Return()

			mockClient.EXPECT().
				Watch(mock.Anything, mock.Anything, mock.Anything).Return(watchInf, nil).Maybe()

			go func() {
				Expect(k8s.WatchManagedClusters(ctx, mockClient, "", results)).ShouldNot(HaveOccurred())
			}()

			// The list failures aren't notices by the receiver of the events, it just waits for some event to happen.
			result := mustReadChannel(ctx, results)
			Expect(result.Type).Should(Equal(k8s.SyncStart))

			result = mustReadChannel(ctx, results)
			Expect(result.Type).Should(Equal(k8s.Added))
			Expect(result.Obj.Name).Should(Equal("test"))

			result = mustReadChannel(ctx, results)
			Expect(result.Type).Should(Equal(k8s.SyncEnd))

			mockClient.AssertExpectations(t)
		})

		t.Run("retries the watch when an error is returned", func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			results := make(chan k8s.Event[v3.ManagedCluster], 1)
			defer close(results)

			mockClient := new(mockk8sclient.WithWatch)

			mockClient.EXPECT().
				List(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(
				func(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
					l := list.(*v3.ManagedClusterList)
					l.ResourceVersion = "1"
					return nil
				}).Once()

			watchInf := new(mockwatch.Interface)
			events := make(chan watch.Event, 1)
			defer close(events)

			watchInf.EXPECT().ResultChan().Return(events)
			watchInf.EXPECT().Stop().Return()

			mockClient.EXPECT().
				Watch(mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("someerror")).Once()

			mockClient.EXPECT().
				Watch(mock.Anything, mock.Anything, &client.ListOptions{Raw: &metav1.ListOptions{ResourceVersion: "1"}}).Return(watchInf, nil).Once()

			go func() {
				Expect(k8s.WatchManagedClusters(ctx, mockClient, "", results)).ShouldNot(HaveOccurred())
			}()

			events <- watch.Event{Type: watch.Added, Object: &v3.ManagedCluster{ObjectMeta: metav1.ObjectMeta{Name: "test"}}}

			result := mustReadChannel(ctx, results)
			Expect(result.Type).Should(Equal(k8s.SyncStart))

			result = mustReadChannel(ctx, results)
			Expect(result.Type).Should(Equal(k8s.SyncEnd))

			result = mustReadChannel(ctx, results)
			Expect(result.Type).Should(Equal(k8s.Added))
			Expect(result.Obj.Name).Should(Equal("test"))

			mockClient.AssertExpectations(t)
		})

		// This is a more complicated test that simulates successful lists and watches, the watch channel closing,
		// the watch returning a Gone error, then re syncing and re watching. This is a valid scenario in the case that
		// the watch is disrupted and the k8s server can no longer handle the resource version we send.
		t.Run("re-syncs and restarts the watch when the watch returns a Gone or Resource Expired error", func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			results := make(chan k8s.Event[v3.ManagedCluster], 1)
			defer func() {
				cancel() // cancel the context first to ensure that the watcher stops before the results channel is closed.
				close(results)
			}()

			mockClient := new(mockk8sclient.WithWatch)

			mockClient.EXPECT().
				List(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(setList(v3.ManagedClusterList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}})).Once()

			mockClient.EXPECT().
				List(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(setList(
				v3.ManagedClusterList{
					ListMeta: metav1.ListMeta{ResourceVersion: "3"},
					Items:    []v3.ManagedCluster{{ObjectMeta: metav1.ObjectMeta{Name: "test"}}},
				},
			)).Once()

			watchInf := new(mockwatch.Interface)
			events := make(chan watch.Event, 1)
			watchInf.EXPECT().ResultChan().Return(events).Once()
			watchInf.EXPECT().Stop().Return().Once()

			mockClient.EXPECT().
				Watch(mock.Anything, mock.Anything, &client.ListOptions{Raw: &metav1.ListOptions{ResourceVersion: "1"}}).Return(watchInf, nil).Once()

			mockClient.EXPECT().
				Watch(mock.Anything, mock.Anything, &client.ListOptions{Raw: &metav1.ListOptions{ResourceVersion: "2"}}).Return(nil, k8serrors.NewResourceExpired("resource expired")).Once()

			watchInf2 := new(mockwatch.Interface)
			eventsChan2 := make(chan watch.Event, 1)
			defer close(eventsChan2)

			watchInf2.EXPECT().ResultChan().Return(eventsChan2).Once()
			watchInf2.EXPECT().Stop().Return().Once()

			mockClient.EXPECT().
				Watch(mock.Anything, mock.Anything, &client.ListOptions{Raw: &metav1.ListOptions{ResourceVersion: "3"}}).Return(watchInf2, nil).Once()

			go func() {
				Expect(k8s.WatchManagedClusters(ctx, mockClient, "", results)).ShouldNot(HaveOccurred())
			}()

			events <- watch.Event{Type: watch.Added, Object: &v3.ManagedCluster{ObjectMeta: metav1.ObjectMeta{Name: "test", ResourceVersion: "2"}}}

			result := mustReadChannel(ctx, results)
			Expect(result.Type).Should(Equal(k8s.SyncStart))

			result = mustReadChannel(ctx, results)
			Expect(result.Type).Should(Equal(k8s.SyncEnd))

			result = mustReadChannel(ctx, results)
			Expect(result.Type).Should(Equal(k8s.Added))
			Expect(result.Obj.Name).Should(Equal("test"))

			close(events)

			result = mustReadChannel(ctx, results)
			Expect(result.Type).Should(Equal(k8s.SyncStart))

			result = mustReadChannel(ctx, results)
			Expect(result.Type).Should(Equal(k8s.Added))
			Expect(result.Obj.Name).Should(Equal("test"))

			result = mustReadChannel(ctx, results)
			Expect(result.Type).Should(Equal(k8s.SyncEnd))

			eventsChan2 <- watch.Event{Type: watch.Added, Object: &v3.ManagedCluster{ObjectMeta: metav1.ObjectMeta{Name: "test3", ResourceVersion: "5"}}}

			result = mustReadChannel(ctx, results)
			Expect(result.Type).Should(Equal(k8s.Added))
			Expect(result.Obj.Name).Should(Equal("test3"))

			mockClient.AssertExpectations(t)
		})
	})
}
