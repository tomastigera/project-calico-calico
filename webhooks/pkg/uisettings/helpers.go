// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package uisettings

import (
	"fmt"
	"reflect"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ValidateImmutableFields checks that ownerReferences, spec.group, and spec.user
// have not been modified between old and new. These fields are set at creation time
// by the webhook and must not change.
func ValidateImmutableFields(old, new *v3.UISettings) error {
	if !reflect.DeepEqual(old.OwnerReferences, new.OwnerReferences) {
		return fmt.Errorf("not permitted to change UISettingsGroup owner reference")
	}
	if old.Spec.Group != new.Spec.Group {
		return fmt.Errorf("not permitted to change spec.group")
	}
	if old.Spec.User != new.Spec.User {
		return fmt.Errorf("not permitted to change spec.user")
	}
	return nil
}

// BuildGroupOwnerReference creates the OwnerReference that links a UISettings
// resource to its parent UISettingsGroup. Controller and BlockOwnerDeletion are
// both set to false — the group owns the settings for garbage collection only.
func BuildGroupOwnerReference(group *v3.UISettingsGroup) metav1.OwnerReference {
	falseVal := false
	return metav1.OwnerReference{
		APIVersion:         v3.GroupVersionCurrent,
		Kind:               v3.KindUISettingsGroup,
		Name:               group.Name,
		UID:                group.UID,
		Controller:         &falseVal,
		BlockOwnerDeletion: &falseVal,
	}
}

// ShouldInjectUser returns true if the UISettingsGroup uses per-user filtering,
// meaning the webhook should inject the requesting user into spec.user on create.
func ShouldInjectUser(group *v3.UISettingsGroup) bool {
	return group.Spec.FilterType == v3.FilterTypeUser
}
