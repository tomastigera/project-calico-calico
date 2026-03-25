package webhooks_test

import (
	"context"
	"sync"
	"testing"
	"time"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/libcalico-go/lib/options"
	calicoWatch "github.com/projectcalico/calico/libcalico-go/lib/watch"
	"github.com/projectcalico/calico/webhooks-processor/pkg/testutils"
	"github.com/projectcalico/calico/webhooks-processor/pkg/webhooks"
)

type MockCtrl struct {
	webhooksChan    chan calicoWatch.Event
	receivedUpdates []calicoWatch.Event
	updatesLock     sync.Mutex
}

func NewMockCtrl() *MockCtrl {
	return &MockCtrl{
		webhooksChan:    make(chan calicoWatch.Event),
		receivedUpdates: []calicoWatch.Event{},
		updatesLock:     sync.Mutex{},
	}
}

func (m *MockCtrl) WebhookEventsChan() chan<- calicoWatch.Event {
	return m.webhooksChan
}

func (m *MockCtrl) K8sEventsChan() chan<- watch.Event {
	// This is just to provide the expected interface for the controller.
	// K8sEventsChan() is not being used in the context of this test.
	return make(chan<- watch.Event)
}

func (m *MockCtrl) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case update := <-m.webhooksChan:
			m.updatesLock.Lock()
			m.receivedUpdates = append(m.receivedUpdates, update)
			m.updatesLock.Unlock()
		case <-ctx.Done():
			return
		}
	}
}

func (m *MockCtrl) GetUpdates() []calicoWatch.Event {
	m.updatesLock.Lock()
	defer m.updatesLock.Unlock()
	return append([]calicoWatch.Event{}, m.receivedUpdates...)
}

func TestWebhookWatcherUpdaterMissingDeletions(t *testing.T) {
	// RECAP: this tests verifies the corner case where:
	// - the webhooks watcher/updater performs list and watch operations
	// - during the watch operation it receives some webhooks updates
	// - then the watch operation is then terminated
	// - the next list operation retrieves webhooks list inconsistent with the state of the internal webhooks inventory
	// - therefore we should observe generated DELETE event issued for the inconsistencies
	// Fact that the List() operation of &testutils.FakeSecurityEventWebhook{}
	// always returns an empty list is of webhooks leveraged here.

	// --- BOILERPLATE ---

	mockCtrl := NewMockCtrl()
	mockWebhooksClient := &testutils.FakeSecurityEventWebhook{DontCloseWatchOnCtxCancellation: true}
	watcherUpdater := webhooks.NewWebhookWatcherUpdater().
		WithK8sClient(fake.NewClientset()).
		WithWebhooksClient(mockWebhooksClient).
		WithController(mockCtrl)

	wg := new(sync.WaitGroup)
	defer wg.Wait()

	ctx, ctxCancel := context.WithTimeout(context.Background(), time.Minute)
	defer ctxCancel()

	wg.Add(2)
	go watcherUpdater.Run(ctx, wg)
	go mockCtrl.Run(ctx, wg)

	// wait for the mockWebhooksClient watch to be ready
	// (Watch() inside watcherUpdater needs to be called before Update() calls are possible)
	for loopStart := time.Now(); mockWebhooksClient.GetWatcher() == nil; {
		if <-time.After(100 * time.Millisecond); time.Since(loopStart) > 5*time.Second {
			t.Error("timed-out waiting for Watch() call (1)")
			break
		}
	}

	watcherRef := mockWebhooksClient.GetWatcher()

	// --- ACTUAL TEST STARTS HERE ---

	webhook := v3.SecurityEventWebhook{
		ObjectMeta: v1.ObjectMeta{Name: "test-webhook"},
	}
	// this update will result in ADDED event type sent to the controller:
	if _, err := mockWebhooksClient.Update(ctx, &webhook, options.SetOptions{}); err != nil {
		t.Error("this will never happen (1)")
	}
	// this update will result in MODIFIED event type sent to the controller:
	if _, err := mockWebhooksClient.Update(ctx, &webhook, options.SetOptions{}); err != nil {
		t.Error("this will never happen (2)")
	}
	// NOTE: we are NOT sending DELETED event type here.

	// let's now close the watcher channel - this should result in reconcilliation and the controller
	// should also receive DELETED event type after the initial List() call detect inconsistencies:
	mockWebhooksClient.Watcher.Stop()

	// wait for another Watch() call and retrieve issued updates
	for loopStart := time.Now(); mockWebhooksClient.GetWatcher() == watcherRef; {
		if <-time.After(100 * time.Millisecond); time.Since(loopStart) > 5*time.Second {
			t.Error("timed-out waiting for Watch() call (2)")
			break
		}
	}
	receivedUpdates := mockCtrl.GetUpdates()

	// make sure the updates received by the controller are the ones sent here (ADDED/MODIFIED)
	// and one after reconcilliation (DELETED):
	if len(receivedUpdates) != 3 {
		t.Error("unexpected number of updates received", len(mockCtrl.receivedUpdates))
	}
	if receivedUpdates[0].Type != calicoWatch.Added {
		t.Error("unexpected received update type (1)")
	}
	if receivedUpdates[1].Type != calicoWatch.Modified {
		t.Error("unexpected received update type (2)")
	}
	if receivedUpdates[2].Type != calicoWatch.Deleted {
		t.Error("unexpected received update type (3)")
	}
}
