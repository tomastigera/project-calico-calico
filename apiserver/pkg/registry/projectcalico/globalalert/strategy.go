/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package globalalert

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
	apivalidation "k8s.io/kubernetes/pkg/apis/core/validation"
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

// PrepareForCreate clears the Status
func (apiServerStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	globalAlert := obj.(*calico.GlobalAlert)
	globalAlert.Status = calico.GlobalAlertStatus{}
}

// PrepareForUpdate copies the Status from old to obj
func (apiServerStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newGlobalAlert := obj.(*calico.GlobalAlert)
	oldGlobalAlert := old.(*calico.GlobalAlert)
	newGlobalAlert.Status = oldGlobalAlert.Status
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
	return ValidateGlobalAlertUpdate(obj.(*calico.GlobalAlert), old.(*calico.GlobalAlert))
}

type apiServerStatusStrategy struct {
	apiServerStrategy
}

func NewStatusStrategy(strategy apiServerStrategy) apiServerStatusStrategy {
	return apiServerStatusStrategy{strategy}
}

func (apiServerStatusStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newGlobalAlert := obj.(*calico.GlobalAlert)
	oldGlobalAlert := old.(*calico.GlobalAlert)
	newGlobalAlert.Spec = oldGlobalAlert.Spec
	newGlobalAlert.Labels = oldGlobalAlert.Labels
}

// ValidateUpdate is the default update validation for an end user updating status
func (apiServerStatusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return ValidateGlobalAlertUpdate(obj.(*calico.GlobalAlert), old.(*calico.GlobalAlert))
}

func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	apiserver, ok := obj.(*calico.GlobalAlert)
	if !ok {
		return nil, nil, fmt.Errorf("given object (type %v) is not a Global Alert", reflect.TypeOf(obj))
	}
	return labels.Set(apiserver.Labels), AlertToSelectableFields(apiserver), nil
}

// MatchAlert is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchAlert(label labels.Selector, field fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    field,
		GetAttrs: GetAttrs,
	}
}

// AlertToSelectableFields returns a field set that represents the object.
func AlertToSelectableFields(obj *calico.GlobalAlert) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, false)
}

func ValidateGlobalAlertUpdate(update, old *calico.GlobalAlert) field.ErrorList {
	return apivalidation.ValidateObjectMetaUpdate(&update.ObjectMeta, &old.ObjectMeta, field.NewPath("metadata"))
}
