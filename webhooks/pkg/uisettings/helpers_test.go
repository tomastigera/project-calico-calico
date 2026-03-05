// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package uisettings

import (
	"testing"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestValidateImmutableFields(t *testing.T) {
	falseVal := false
	ownerRefs := []metav1.OwnerReference{{
		APIVersion:         v3.GroupVersionCurrent,
		Kind:               v3.KindUISettingsGroup,
		Name:               "my-group",
		UID:                "abc-123",
		Controller:         &falseVal,
		BlockOwnerDeletion: &falseVal,
	}}

	base := &v3.UISettings{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "my-group.my-setting",
			OwnerReferences: ownerRefs,
		},
		Spec: v3.UISettingsSpec{
			Group:       "my-group",
			User:        "alice",
			Description: "original",
		},
	}

	tests := []struct {
		name    string
		modify  func(s *v3.UISettings)
		wantErr string
	}{
		{
			name:   "no changes",
			modify: func(s *v3.UISettings) {},
		},
		{
			name:   "mutable field changed",
			modify: func(s *v3.UISettings) { s.Spec.Description = "updated" },
		},
		{
			name:    "ownerReferences changed",
			modify:  func(s *v3.UISettings) { s.OwnerReferences = nil },
			wantErr: "not permitted to change UISettingsGroup owner reference",
		},
		{
			name:    "spec.group changed",
			modify:  func(s *v3.UISettings) { s.Spec.Group = "other-group" },
			wantErr: "not permitted to change spec.group",
		},
		{
			name:    "spec.user changed",
			modify:  func(s *v3.UISettings) { s.Spec.User = "bob" },
			wantErr: "not permitted to change spec.user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newSettings := base.DeepCopy()
			tt.modify(newSettings)

			err := ValidateImmutableFields(base, newSettings)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if err.Error() != tt.wantErr {
					t.Fatalf("expected error %q, got %q", tt.wantErr, err.Error())
				}
			}
		})
	}
}

func TestBuildGroupOwnerReference(t *testing.T) {
	group := &v3.UISettingsGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-group",
			UID:  types.UID("uid-456"),
		},
	}

	ref := BuildGroupOwnerReference(group)

	if ref.APIVersion != v3.GroupVersionCurrent {
		t.Errorf("expected APIVersion %q, got %q", v3.GroupVersionCurrent, ref.APIVersion)
	}
	if ref.Kind != v3.KindUISettingsGroup {
		t.Errorf("expected Kind %q, got %q", v3.KindUISettingsGroup, ref.Kind)
	}
	if ref.Name != "test-group" {
		t.Errorf("expected Name %q, got %q", "test-group", ref.Name)
	}
	if ref.UID != "uid-456" {
		t.Errorf("expected UID %q, got %q", "uid-456", ref.UID)
	}
	if ref.Controller == nil || *ref.Controller {
		t.Error("expected Controller to be false")
	}
	if ref.BlockOwnerDeletion == nil || *ref.BlockOwnerDeletion {
		t.Error("expected BlockOwnerDeletion to be false")
	}
}

func TestShouldInjectUser(t *testing.T) {
	tests := []struct {
		name       string
		filterType string
		want       bool
	}{
		{"user filter", v3.FilterTypeUser, true},
		{"no filter", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := &v3.UISettingsGroup{
				Spec: v3.UISettingsGroupSpec{
					FilterType: tt.filterType,
				},
			}
			if got := ShouldInjectUser(group); got != tt.want {
				t.Errorf("ShouldInjectUser() = %v, want %v", got, tt.want)
			}
		})
	}
}
