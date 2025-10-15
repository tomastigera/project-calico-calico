// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package securityeventwebhook

import (
	"context"
	"fmt"
	"reflect"

	calico "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/names"
)

type apiServerStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// NewStrategy returns a new NamespaceScopedStrategy for instances
func NewStrategy(typer runtime.ObjectTyper) apiServerStrategy {
	return apiServerStrategy{typer, names.SimpleNameGenerator}
}

func (apiServerStrategy) NamespaceScoped() bool {
	return false
}

func (apiServerStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
}

func (apiServerStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
}

func (apiServerStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

func (apiServerStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (apiServerStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (apiServerStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return []string{}
}

func (apiServerStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return []string{}
}

func (apiServerStrategy) Canonicalize(obj runtime.Object) {
}

func (apiServerStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	apiserver, ok := obj.(*calico.SecurityEventWebhook)
	if !ok {
		return nil, nil, fmt.Errorf("given object (type %v) is not a Security Event Webhook", reflect.TypeOf(obj))
	}
	return labels.Set(apiserver.Labels), generic.ObjectMetaFieldsSet(&apiserver.ObjectMeta, false), nil
}

// MatchSecurityEventWebhookConfiguration is the event filter used by clients of the apiserver only interested in specific labels/fields.
func MatchSecurityEventWebhookConfiguration(label labels.Selector, field fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    field,
		GetAttrs: GetAttrs,
	}
}
