// Copyright (c) 2022 Tigera, Inc. All rights reserved.
package exceptions

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"

	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
)

type FakeAlertExceptions struct {
	Exceptions []*v3.AlertException
}

func (f *FakeAlertExceptions) Create(ctx context.Context, alertException *v3.AlertException, opts metav1.CreateOptions) (*v3.AlertException, error) {
	f.Exceptions = append(f.Exceptions, alertException)
	return alertException, nil
}

func (f *FakeAlertExceptions) Update(ctx context.Context, alertException *v3.AlertException, opts metav1.UpdateOptions) (*v3.AlertException, error) {
	return nil, errors.New("Not implemented")
}

func (f *FakeAlertExceptions) UpdateStatus(ctx context.Context, alertException *v3.AlertException, opts metav1.UpdateOptions) (*v3.AlertException, error) {
	return nil, errors.New("Not implemented")
}

func (f *FakeAlertExceptions) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	if len(f.Exceptions) == 0 {
		return errors.New("AlertException not found")
	}
	remaining := []*v3.AlertException{}
	for _, e := range f.Exceptions {
		if e.Name != name {
			remaining = append(remaining, e)
		}
	}
	if len(remaining) == len(f.Exceptions) {
		return errors.New("AlertException not found")
	} else {
		f.Exceptions = remaining
	}
	return nil
}

func (f *FakeAlertExceptions) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	return errors.New("Not implemented")
}

func (f *FakeAlertExceptions) Get(ctx context.Context, name string, opts metav1.GetOptions) (*v3.AlertException, error) {
	for _, e := range f.Exceptions {
		if e.Name == name {
			return e, nil
		}
	}
	return nil, errors.New("AlertException not found")
}

func (f *FakeAlertExceptions) List(ctx context.Context, opts metav1.ListOptions) (*v3.AlertExceptionList, error) {
	exceptions := v3.NewAlertExceptionList()
	for _, e := range f.Exceptions {
		exceptions.Items = append(exceptions.Items, *e)
	}
	return exceptions, nil
}

func (f *FakeAlertExceptions) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return nil, nil
}

func (f *FakeAlertExceptions) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v3.AlertException, err error) {
	return nil, nil
}

type FakeEventsProvider struct {
	PretendNumEventsRead int64
}

func (f *FakeEventsProvider) List(context.Context, lapi.Params) (*lapi.List[lapi.Event], error) {
	return &lapi.List[lapi.Event]{
		TotalHits: f.PretendNumEventsRead,
	}, nil
}
func (f *FakeEventsProvider) Create(context.Context, []lapi.Event) (*lapi.BulkResponse, error) {
	return nil, nil
}
func (f *FakeEventsProvider) UpdateDismissFlag(context.Context, []lapi.Event) (*lapi.BulkResponse, error) {
	return nil, nil
}
func (f *FakeEventsProvider) Delete(context.Context, []lapi.Event) (*lapi.BulkResponse, error) {
	return nil, nil
}
func (f *FakeEventsProvider) Statistics(context.Context, lapi.EventStatisticsParams) (*lapi.EventStatistics, error) {
	return nil, nil
}

var _ = Describe("Exceptions middleware tests", func() {

	Context("EventExceptions API", func() {
		var fae FakeAlertExceptions
		var fep FakeEventsProvider
		var ee eventExceptions
		var ctx context.Context
		var cancel func()

		BeforeEach(func() {
			fae = FakeAlertExceptions{}
			fep = FakeEventsProvider{}
			ee = eventExceptions{alertExceptions: &fae, eventsProvider: &fep}

			ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		})

		AfterEach(func() {
			cancel()
		})

		It("List is initially empty", func() {
			exceptionsList, err := ee.List(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(exceptionsList).To(BeEmpty())
		})

		It("Cannot create EventException with incomplete data", func() {
			_, err := ee.Create(ctx, &v1.EventException{})
			Expect(err).To(HaveOccurred())

			_, err = ee.Create(ctx, &v1.EventException{Type: "waf"})
			Expect(err).To(HaveOccurred())

			_, err = ee.Create(ctx, &v1.EventException{Type: "waf", Event: "WAF Event"})
			Expect(err).To(HaveOccurred())

			newException, err := ee.Create(ctx, &v1.EventException{Type: "waf", Event: "WAF Event", Namespace: "hipster-shop"})
			Expect(err).NotTo(HaveOccurred())
			// Newly created exception is given an ID
			Expect(newException.ID).NotTo(BeEmpty())
		})

		It("Alert Exception with overly complex selector will be flagged as having unexpected data (incompatible with UI)", func() {
			ae := v3.NewAlertException()
			ae.Name = "created-with-kubectl"
			ae.Spec.Selector = "type='waf' AND dest_namespace IN {'hipster-shop', 'test-shop'}"
			_, err := fae.Create(ctx, ae, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			exceptions, err := ee.List(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(exceptions[0].HasUnexpectedData).To(Equal(true))
			Expect(exceptions[0].Namespace).To(Equal(""))
		})

		It("Old WAF event exception", func() {
			ae := v3.NewAlertException()
			ae.Name = "created-with-kubectl"
			ae.Spec.Selector = "type='waf' AND name='WAF Event' AND dest_namespace='hipster-shop' AND dest_name='test-pod'"
			_, err := fae.Create(ctx, ae, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			exceptions, err := ee.List(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(exceptions[0].HasUnexpectedData).To(Equal(true))
			Expect(exceptions[0].Namespace).To(Equal(""))
		})

		It("Incomplete AlertException, but containing expected data (although in a weird format) will not be flagged as having unexpected data", func() {
			ae := v3.NewAlertException()
			ae.Name = "we-are-too-nice"
			ae.Spec.Selector = "type='waf' AND source_namespace IN {'hipster-shop'}"
			_, err := fae.Create(ctx, ae, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			exceptions, err := ee.List(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(exceptions[0].HasUnexpectedData).To(Equal(false))
			Expect(exceptions[0].Namespace).To(Equal("hipster-shop"))
		})

		It("Alert Exception with a selector containing expected data but using an unusual format will not be flagged as having unexpected data", func() {
			ae := v3.NewAlertException()
			ae.Name = "so-weird"
			ae.Spec.Selector = "type IN {'runtime_security'} and source_name_aggr=\"test-deployment-abcde56-\" AND source_namespace IN {'def*'}"
			_, err := fae.Create(ctx, ae, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			exceptions, err := ee.List(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(exceptions[0].HasUnexpectedData).To(Equal(false))
			Expect(exceptions[0].Type).To(Equal("runtime_security"))
			Expect(exceptions[0].Pod).To(Equal("test-deployment-abcde56-"))
			Expect(exceptions[0].UseNameAggr).To(Equal(true))
			Expect(exceptions[0].Namespace).To(Equal("def*"))
		})

		It("WAF Event uses source info", func() {
			newException, err := ee.Create(ctx, &v1.EventException{Type: "waf", Event: "WAF Event", Namespace: "hipster-shop", Pod: "test-pod"})
			Expect(err).NotTo(HaveOccurred())

			Expect(newException.ID).NotTo(BeEmpty())
			alertException, err := fae.Get(ctx, newException.ID, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(alertException.Spec.Selector).To(Equal("type='waf' AND name='WAF Event' AND source_namespace='hipster-shop' AND source_name='test-pod'"))
		})

		It("GTF Event uses source info", func() {
			newException, err := ee.Create(ctx, &v1.EventException{Type: "gtf_suspicious_flow", Event: "Suspicious Flow", Namespace: "hipster-shop", Pod: "test-pod"})
			Expect(err).NotTo(HaveOccurred())

			Expect(newException.ID).NotTo(BeEmpty())
			alertException, err := fae.Get(ctx, newException.ID, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(alertException.Spec.Selector).To(Equal("type='gtf_suspicious_flow' AND name='Suspicious Flow' AND source_namespace='hipster-shop' AND source_name='test-pod'"))
		})

		It("Pod name containing '*' uses a wildcard selector", func() {
			newException, err := ee.Create(ctx, &v1.EventException{Type: "waf", Event: "WAF Event", Namespace: "hipster-shop", Pod: "test-deployment-*"})
			Expect(err).NotTo(HaveOccurred())

			Expect(newException.ID).NotTo(BeEmpty())
			alertException, err := fae.Get(ctx, newException.ID, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(alertException.Spec.Selector).To(Equal("type='waf' AND name='WAF Event' AND source_namespace='hipster-shop' AND source_name IN {'test-deployment-*'}"))
		})

		It("Can List Pod name containing '*'", func() {
			_, err := ee.Create(ctx, &v1.EventException{Type: "waf", Event: "WAF Event", Namespace: "hipster-shop", Pod: "test-deployment-*"})
			Expect(err).NotTo(HaveOccurred())

			exceptions, err := ee.List(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(exceptions[0].Pod).To(Equal("test-deployment-*"))
		})

		It("Pod name can refer to SourceNameAggr", func() {
			newException, err := ee.Create(ctx, &v1.EventException{Type: "gtf_suspicious_flow", Event: "Suspicious Flow", Namespace: "hipster-shop", Pod: "test-deployment-*", UseNameAggr: true})
			Expect(err).NotTo(HaveOccurred())

			Expect(newException.ID).NotTo(BeEmpty())
			alertException, err := fae.Get(ctx, newException.ID, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(alertException.Spec.Selector).To(Equal("type='gtf_suspicious_flow' AND name='Suspicious Flow' AND source_namespace='hipster-shop' AND source_name_aggr IN {'test-deployment-*'}"))
		})

		It("Pod name must contain '*' when UseNameAggr is true", func() {
			_, err := ee.Create(ctx, &v1.EventException{Type: "gtf_suspicious_flow", Event: "Suspicious Flow", Namespace: "hipster-shop", Pod: "a-single-pod", UseNameAggr: true})
			Expect(err).To(HaveOccurred())
		})

		It("UseNameAggr is set when listing exceptions", func() {
			_, err := ee.Create(ctx, &v1.EventException{Type: "gtf_suspicious_flow", Event: "Suspicious Flow", Namespace: "hipster-shop", Pod: "test-deployment-*", UseNameAggr: true})
			Expect(err).NotTo(HaveOccurred())

			exceptions, err := ee.List(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(exceptions[0].UseNameAggr).To(BeTrue())
		})

		It("Description is optional", func() {
			newException, err := ee.Create(ctx, &v1.EventException{Type: "waf", Event: "WAF Event", Namespace: "hipster-shop"})
			Expect(err).NotTo(HaveOccurred())
			Expect(newException.Description).To(Equal(""))

			Expect(newException.ID).NotTo(BeEmpty())
			alertException, err := fae.Get(ctx, newException.ID, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(alertException.Spec.Description).To(Equal("Description: "))
		})

		It("Description value is kept in EventException", func() {
			newException, err := ee.Create(ctx, &v1.EventException{Type: "waf", Event: "WAF Event", Namespace: "hipster-shop", Description: `"Let's ignore 'hipster-shop' for now!"`})
			Expect(err).NotTo(HaveOccurred())
			Expect(newException.Description).To(Equal("\"Let's ignore 'hipster-shop' for now!\""))

			Expect(newException.ID).NotTo(BeEmpty())
			alertException, err := fae.Get(ctx, newException.ID, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(alertException.Spec.Description).To(Equal("Description: \"Let's ignore 'hipster-shop' for now!\""))

			exceptions, err := ee.List(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(exceptions[0].Description).To(Equal("\"Let's ignore 'hipster-shop' for now!\""))
		})

		It("List updates matching events count of exceptions", func() {
			newException, err := ee.Create(ctx, &v1.EventException{Type: "waf", Event: "WAF Event", Namespace: "hipster-shop"})
			Expect(err).NotTo(HaveOccurred())
			// This could be a surprise and technically we probably should update Count but there is no need for it so not doing it
			Expect(newException.Count).To(Equal(0))

			fep.PretendNumEventsRead = 12
			exceptions, err := ee.List(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(exceptions[0].Count).To(Equal(12))
		})

		It("Full Description is shown if AlertException created with kubectl", func() {
			description := "Should really edit global alerts instead of ignoring them..."
			ae := v3.NewAlertException()
			ae.Name = "ignore-ga"
			ae.Spec.Selector = "type = global_alert"
			ae.Spec.Description = description
			alertException, err := fae.Create(ctx, ae, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(alertException.Spec.Description).To(Equal(description))

			exceptions, err := ee.List(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(exceptions[0].Description).To(Equal(description))
		})

		It("ID is required to delete and EventException", func() {
			err := ee.Delete(ctx, &v1.EventException{})
			Expect(err).To(HaveOccurred())
		})

		It("Existing ID is required to delete and EventException", func() {
			err := ee.Delete(ctx, &v1.EventException{ID: "does-not-exit"})
			Expect(err).To(HaveOccurred())
		})

		It("Deleting an EventException removes it from the list", func() {
			e1, err := ee.Create(ctx, &v1.EventException{Type: "waf", Event: "WAF Event", Namespace: "hipster-shop"})
			Expect(err).NotTo(HaveOccurred())
			e2, err := ee.Create(ctx, &v1.EventException{Type: "waf", Event: "WAF Event", Namespace: "another-hipster-shop"})
			Expect(err).NotTo(HaveOccurred())

			err = ee.Delete(ctx, &v1.EventException{ID: e1.ID})
			Expect(err).NotTo(HaveOccurred())

			exceptions, err := ee.List(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(exceptions)).To(Equal(1))
			Expect(exceptions[0].ID).To(Equal(e2.ID))
			Expect(exceptions[0]).To(Equal(e2))
		})
	})

	Context("EventExceptionsHandler sample requests", func() {
		It("Should be able to edit alert exceptions using various /event-exceptions requests", func() {
			var err error
			rr := httptest.NewRecorder()
			ee := &eventExceptions{
				alertExceptions: &FakeAlertExceptions{},
				eventsProvider:  &FakeEventsProvider{},
			}

			// Create new event exception
			newException := v1.EventException{Type: "waf", Event: "WAF Event", Namespace: "default"}
			var newExceptionBytes []byte
			newExceptionBytes, err = json.Marshal(newException)
			Expect(err).NotTo(HaveOccurred())
			var newExceptionReq *http.Request
			newExceptionReq, err = http.NewRequest(http.MethodPost, "", bytes.NewReader(newExceptionBytes))
			Expect(err).NotTo(HaveOccurred())

			handleExceptionRequest(rr, newExceptionReq, ee)

			Expect(rr.Code).To(Equal(http.StatusOK))

			// List event exceptions
			var listExceptionReq *http.Request
			listExceptionReq, err = http.NewRequest(http.MethodGet, "", bytes.NewReader([]byte{}))
			Expect(err).NotTo(HaveOccurred())
			rr = httptest.NewRecorder()

			handleExceptionRequest(rr, listExceptionReq, ee)

			Expect(rr.Code).To(Equal(http.StatusOK))

			var exceptions []*v1.EventException
			err = json.Unmarshal(rr.Body.Bytes(), &exceptions)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(exceptions)).To(Equal(1))
			Expect(exceptions[0].Type).To(Equal(newException.Type))
			Expect(exceptions[0].Event).To(Equal(newException.Event))
			Expect(exceptions[0].Namespace).To(Equal(newException.Namespace))
			Expect(exceptions[0].ID).NotTo(BeEmpty())

			// Delete existing exception
			exceptionToDelete := v1.EventException{ID: exceptions[0].ID}
			var exceptionToDeleteBytes []byte
			exceptionToDeleteBytes, err = json.Marshal(exceptionToDelete)
			Expect(err).NotTo(HaveOccurred())
			var deleteReq *http.Request
			deleteReq, err = http.NewRequest(http.MethodDelete, "", bytes.NewReader(exceptionToDeleteBytes))
			Expect(err).NotTo(HaveOccurred())
			rr = httptest.NewRecorder()

			handleExceptionRequest(rr, deleteReq, ee)

			Expect(rr.Code).To(Equal(http.StatusOK))

			// And finally confirm that the list is now empty
			var listAgainReq *http.Request
			listAgainReq, err = http.NewRequest(http.MethodGet, "", bytes.NewReader([]byte("")))
			Expect(err).NotTo(HaveOccurred())
			rr = httptest.NewRecorder()

			handleExceptionRequest(rr, listAgainReq, ee)

			Expect(rr.Code).To(Equal(http.StatusOK))
			err = json.Unmarshal(rr.Body.Bytes(), &exceptions)
			Expect(err).NotTo(HaveOccurred())
			Expect(exceptions).To(BeEmpty())

			// Just confirming that errors go through too
			var deleteAgainReq *http.Request
			deleteAgainReq, err = http.NewRequest(http.MethodDelete, "", bytes.NewReader(exceptionToDeleteBytes))
			Expect(err).NotTo(HaveOccurred())
			rr = httptest.NewRecorder()

			handleExceptionRequest(rr, deleteAgainReq, ee)

			Expect(rr.Code).To(Equal(http.StatusInternalServerError))
		})
	})
})
