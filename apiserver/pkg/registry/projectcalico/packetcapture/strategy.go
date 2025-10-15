package packetcapture

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
	return true
}

// PrepareForCreate clears the Status
func (apiServerStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	packetCapture := obj.(*calico.PacketCapture)
	packetCapture.Status = calico.PacketCaptureStatus{}
}

// PrepareForUpdate copies the Status from old to obj
func (apiServerStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newPacketCapture := obj.(*calico.PacketCapture)
	oldPacketCapture := old.(*calico.PacketCapture)
	newPacketCapture.Status = oldPacketCapture.Status
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
	return ValidatePacketCaptureUpdate(obj.(*calico.PacketCapture), old.(*calico.PacketCapture))
}

type apiServerStatusStrategy struct {
	apiServerStrategy
}

func NewStatusStrategy(strategy apiServerStrategy) apiServerStatusStrategy {
	return apiServerStatusStrategy{strategy}
}

func (apiServerStatusStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newPacketCapture := obj.(*calico.PacketCapture)
	oldPacketCapture := old.(*calico.PacketCapture)
	newPacketCapture.Spec = oldPacketCapture.Spec
	newPacketCapture.Labels = oldPacketCapture.Labels
}

// ValidateUpdate is the default update validation for an end user updating status
func (apiServerStatusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return ValidatePacketCaptureUpdate(obj.(*calico.PacketCapture), old.(*calico.PacketCapture))
}

func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	apiserver, ok := obj.(*calico.PacketCapture)
	if !ok {
		return nil, nil, fmt.Errorf("given object (type %v) is not a PacketCapture Set", reflect.TypeOf(obj))
	}
	return labels.Set(apiserver.Labels), PacketCaptureToSelectableFields(apiserver), nil
}

// MatchPacketCapture is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchPacketCapture(label labels.Selector, field fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    field,
		GetAttrs: GetAttrs,
	}
}

// PacketCaptureToSelectableFields returns a field set that represents the object.
func PacketCaptureToSelectableFields(obj *calico.PacketCapture) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, true)
}

func ValidatePacketCaptureUpdate(update, old *calico.PacketCapture) field.ErrorList {
	return apivalidation.ValidateObjectMetaUpdate(&update.ObjectMeta, &old.ObjectMeta, field.NewPath("metadata"))
}
