// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package exceptions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	clientsetV3 "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/pkg/kubelet/checkpointmanager/checksum"

	"github.com/projectcalico/calico/libcalico-go/lib/validator/v3/query"
	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
)

const (
	descriptionPrefix = "Description: "
)

type EventExceptions interface {
	List(context.Context) ([]*v1.EventException, error)
	Create(context.Context, *v1.EventException) (*v1.EventException, error)
	Delete(context.Context, *v1.EventException) error
}

type eventExceptions struct {
	alertExceptions clientsetV3.AlertExceptionInterface
	eventsProvider  client.EventsInterface
}

// We just list everything. No fear :)
func (ee *eventExceptions) List(ctx context.Context) ([]*v1.EventException, error) {
	eventExceptions := []*v1.EventException{}

	alertExceptions, err := ee.alertExceptions.List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, alertException := range alertExceptions.Items {
		e, err := getEventException(alertException)
		if err != nil {
			return nil, err
		}
		err = ee.updateIgnoredEventsCount(e, alertException)
		if err != nil {
			return nil, err
		}
		eventExceptions = append(eventExceptions, e)
	}

	return eventExceptions, nil
}

func (ee *eventExceptions) updateIgnoredEventsCount(eventException *v1.EventException, alertException v3.AlertException) error {
	if ee.eventsProvider != nil {
		params := lapi.EventParams{
			QueryParams: lapi.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: alertException.Spec.StartTime.Time,
				},
				MaxPageSize: 1, // We don't need a big request, only interested in the total count
			},
			LogSelectionParams: lapi.LogSelectionParams{
				Selector: alertException.Spec.Selector,
			},
		}
		if alertException.Spec.EndTime != nil {
			params.TimeRange.To = alertException.Spec.EndTime.Time
		} else {
			params.TimeRange.To = time.Now()
		}

		results, err := ee.eventsProvider.List(context.TODO(), &params)
		if err != nil {
			return err
		}
		eventException.Count = int(results.TotalHits)
	}
	return nil
}

func (ee *eventExceptions) Create(ctx context.Context, eventException *v1.EventException) (*v1.EventException, error) {
	if len(eventException.Type) == 0 || len(eventException.Event) == 0 || len(eventException.Namespace) == 0 {
		return nil, errors.New("new EventException must contain at least type, event and namespace")
	}
	a, err := getAlertException(eventException)
	if err != nil {
		return nil, err
	}
	a, err = ee.alertExceptions.Create(ctx, a, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	return &v1.EventException{
		ID:          a.Name,
		Type:        eventException.Type,
		Event:       eventException.Event,
		Namespace:   eventException.Namespace,
		Description: eventException.Description,
	}, nil
}

func (ee *eventExceptions) Delete(ctx context.Context, eventException *v1.EventException) error {
	if len(eventException.ID) == 0 {
		return errors.New("EventException ID is required for delete operation")
	}
	return ee.alertExceptions.Delete(ctx, eventException.ID, metav1.DeleteOptions{})
}

type QueryExceptionData struct {
	Type              string
	Name              string
	SourceNamespace   string
	DestNamespace     string
	SourceName        string
	DestName          string
	SourceNameAggr    string
	DestNameAggr      string
	HasUnexpectedData bool
}

func (q *QueryExceptionData) Store(key string, value string) {
	switch key {
	case "type":
		q.Type = value
	case "name":
		q.Name = value
	case "source_namespace":
		q.SourceNamespace = value
	case "source_name":
		q.SourceName = value
	case "source_name_aggr":
		q.SourceNameAggr = value
	default:
		q.HasUnexpectedData = true
	}
}

func (q *QueryExceptionData) Pod() (pod string) {
	pod = q.SourceName
	if len(pod) == 0 {
		pod = q.SourceNameAggr
	}
	return pod
}

func (q *QueryExceptionData) UseNameAggr() bool {
	return len(q.SourceNameAggr) > 0 || len(q.DestNameAggr) > 0
}

func (q *QueryExceptionData) Namespace() (ns string) {
	return q.SourceNamespace
}

// Traverses a query.Query (obtained by parsing a selector) and extract
// relevant information in a QueryExceptionData object.
// This is needed because query.Query.Atoms() for example give us atoms (e.g. `type = waf`).
// I know the cue is in the name :).
// It traverses sub-queries but  does not deal with Set data (e.g. `name IN {'pod-*'}`),
// and there is no existing code I could find that could be used to get key-value pairs of
// both atoms and sets.
// As a side effect of the current implementation in the query package is that
// keys used in sets are not validated. A selector like "type = my_new_alert" will fail
// validation but "type IN {'my_new_alert'}" will not.
func extractQueryExceptionData(o any, d *QueryExceptionData) {
	switch v := o.(type) {
	case *query.Query:
		extractQueryExceptionData(v.Left, d)
		for _, r := range v.Right {
			extractQueryExceptionData(r, d)
		}
	case *query.Term:
		extractQueryExceptionData(v.Left, d)
		for _, r := range v.Right {
			extractQueryExceptionData(r, d)
		}
	case *query.OpTerm:
		if v.Operator != query.OpAnd {
			d.HasUnexpectedData = true
		}
		extractQueryExceptionData(v.Term, d)
	case *query.OpValue:
		if v.Operator != query.OpAnd {
			d.HasUnexpectedData = true
		}
		extractQueryExceptionData(v.Value, d)
	case *query.UnaryOpTerm:
		if v.Negator != nil {
			d.HasUnexpectedData = true
		}
		extractQueryExceptionData(v.Value, d)
	case *query.Value:
		if v.Atom != nil {
			extractQueryExceptionData(v.Atom, d)
		}
		if v.Set != nil {
			extractQueryExceptionData(v.Set, d)
		}
		if v.Subquery != nil {
			extractQueryExceptionData(v.Subquery, d)
		}
	case *query.Atom:
		if v.Comparator != query.CmpEqual {
			d.HasUnexpectedData = true
		}
		d.Store(v.Key, v.Value)
	case *query.SetOpTerm:
		if v.Operator != query.OpIn {
			d.HasUnexpectedData = true
		}
		if len(v.Members) == 1 {
			d.Store(v.Key, v.Members[0].Value)
		} else {
			d.HasUnexpectedData = true
		}
	}
}

func getNamespaceSelector(e *v1.EventException) string {
	return fmt.Sprintf("%s='%s'", "source_namespace", e.Namespace)
}

func getPodSelector(e *v1.EventException) string {
	key := "source_name"
	if e.UseNameAggr {
		key = fmt.Sprintf("%s_aggr", key)
	}
	if strings.Contains(e.Pod, "*") {
		return fmt.Sprintf("%s IN {'%s'}", key, e.Pod)
	} else {
		return fmt.Sprintf("%s='%s'", key, e.Pod)
	}
}

func getEventException(alertException v3.AlertException) (*v1.EventException, error) {
	q, err := query.ParseQuery(alertException.Spec.Selector)
	if err != nil {
		return nil, err
	}

	qed := QueryExceptionData{}
	extractQueryExceptionData(q, &qed)

	e := v1.EventException{
		ID:                alertException.Name,
		Type:              qed.Type,
		Event:             qed.Name,
		Namespace:         qed.Namespace(),
		Pod:               qed.Pod(),
		Description:       strings.TrimPrefix(alertException.Spec.Description, descriptionPrefix),
		UseNameAggr:       qed.UseNameAggr(),
		HasUnexpectedData: qed.HasUnexpectedData,
	}

	return &e, nil
}

func getAlertException(eventException *v1.EventException) (*v3.AlertException, error) {
	s, err := json.Marshal(eventException)
	if err != nil {
		return nil, err
	}
	if eventException.UseNameAggr && !strings.ContainsAny(eventException.Pod, "*") {
		return nil, fmt.Errorf("pod field '%v' must contain a '*' when use_name_aggr is true", eventException.Pod)
	}
	name := fmt.Sprintf("security-event-exception-%x", checksum.New(s))
	description := fmt.Sprintf("%s%s", descriptionPrefix, eventException.Description)
	selector := fmt.Sprintf("type='%s' AND name='%s' AND %s", eventException.Type, eventException.Event, getNamespaceSelector(eventException))
	if len(eventException.Pod) > 0 {
		selector = strings.Join([]string{selector, getPodSelector(eventException)}, " AND ")
	}

	a := v3.NewAlertException()
	a.Name = name
	a.Spec = v3.AlertExceptionSpec{
		Description: description,
		Selector:    selector,
		StartTime:   metav1.Time{Time: time.Unix(1, 0)},
	}

	return a, nil
}
