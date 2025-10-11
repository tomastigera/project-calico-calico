// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package testutils

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// My typical approach is to use simple solutions while acceptable and reach for proper mocking tools
// once their advantages become more obvious.
// So this approach is likely to evolve as test coverage increases...
type FakeSecurityEventWebhook struct {
	ExpectedWebhook                 *api.SecurityEventWebhook
	Watcher                         *FakeWatcher
	DontCloseWatchOnCtxCancellation bool
	WatcherLock                     sync.Mutex
	webhookNames                    []string
}

type FakeWatcher struct {
	Results chan watch.Event
}

func (fw *FakeWatcher) Stop() {
	close(fw.Results)
}
func (fw *FakeWatcher) ResultChan() <-chan watch.Event {
	return fw.Results
}

func (w *FakeSecurityEventWebhook) Update(ctx context.Context, res *api.SecurityEventWebhook, opts options.SetOptions) (*api.SecurityEventWebhook, error) {
	eventType := watch.Added
	for _, name := range w.webhookNames {
		if name == res.Name {
			eventType = watch.Modified
			break
		}
	}
	if eventType == watch.Added {
		w.webhookNames = append(w.webhookNames, res.Name)
	}
	w.Watcher.Results <- watch.Event{Type: eventType, Object: res}
	return res, nil
}

func (w *FakeSecurityEventWebhook) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	w.WatcherLock.Lock()
	defer w.WatcherLock.Unlock()

	w.Watcher = &FakeWatcher{
		Results: make(chan watch.Event),
	}

	if w.DontCloseWatchOnCtxCancellation {
		return w.Watcher, nil
	}

	// Otherwise close on context cancellation
	go func() {
		<-ctx.Done()
		w.Watcher.Stop()
	}()
	return w.Watcher, nil
}

func (w *FakeSecurityEventWebhook) GetWatcher() *FakeWatcher {
	w.WatcherLock.Lock()
	defer w.WatcherLock.Unlock()

	return w.Watcher
}

// We only care about list and watch, the other ones are only here to please the compiler
func (w *FakeSecurityEventWebhook) Create(ctx context.Context, res *api.SecurityEventWebhook, opts options.SetOptions) (*api.SecurityEventWebhook, error) {
	return nil, nil
}
func (w *FakeSecurityEventWebhook) Delete(ctx context.Context, name string, opts options.DeleteOptions) (*api.SecurityEventWebhook, error) {
	return nil, nil
}
func (w *FakeSecurityEventWebhook) Get(ctx context.Context, name string, opts options.GetOptions) (*api.SecurityEventWebhook, error) {
	return nil, nil
}
func (w *FakeSecurityEventWebhook) List(ctx context.Context, opts options.ListOptions) (*api.SecurityEventWebhookList, error) {
	return &api.SecurityEventWebhookList{}, nil
}

type FakeConsumer struct {
	Requests   []HttpRequest
	ShouldFail bool
	ts         *httptest.Server
}

func (fc *FakeConsumer) Url() string {
	return fc.ts.URL
}

func NewFakeConsumer(t *testing.T) *FakeConsumer {
	fc := &FakeConsumer{}
	require.False(t, fc.ShouldFail)
	fc.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Let's make requests fail on demand
		if fc.ShouldFail {
			w.WriteHeader(http.StatusInternalServerError)
		}
		_, _ = fmt.Fprintln(w, "Does anyone read this?")
		request := HttpRequest{
			Method: r.Method,
			URL:    r.URL.String(),
			Header: r.Header,
		}
		var err error
		request.Body, err = io.ReadAll(r.Body)
		require.NoError(t, err)
		fc.Requests = append(fc.Requests, request)
	}))
	t.Cleanup(func() {
		fc.ts.Close()
	})
	return fc
}
