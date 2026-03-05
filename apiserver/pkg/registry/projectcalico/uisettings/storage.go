// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.

package uisettings

import (
	"context"
	"fmt"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/authorizer"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/server"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/util"
	"github.com/projectcalico/calico/apiserver/pkg/storage/calico"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	uisettingswebhook "github.com/projectcalico/calico/webhooks/pkg/uisettings"
)

// rest implements a RESTStorage for API services against etcd
type REST struct {
	*registry.Store
	authorizer authorizer.UISettingsAuthorizer
	shortNames []string
	client     clientv3.Interface
}

func (r *REST) ShortNames() []string {
	return r.shortNames
}

func (r *REST) Categories() []string {
	return []string{""}
}

// EmptyObject returns an empty instance
func EmptyObject() runtime.Object {
	return &v3.UISettings{}
}

// NewList returns a new shell of a binding list
func NewList() runtime.Object {
	return &v3.UISettingsList{}
}

// NewREST returns a RESTStorage object that will work against API services.
func NewREST(scheme *runtime.Scheme, opts server.Options) (*REST, error) {
	strategy := NewStrategy(scheme)

	client := calico.CreateClientFromConfig()

	prefix := "/" + opts.ResourcePrefix()
	// We adapt the store's keyFunc so that we can use it with the StorageDecorator
	// without making any assumptions about where objects are stored in etcd
	keyFunc := func(obj runtime.Object) (string, error) {
		accessor, err := meta.Accessor(obj)
		if err != nil {
			return "", err
		}
		return registry.NoNamespaceKeyFunc(
			genericapirequest.NewContext(),
			prefix,
			accessor.GetName(),
		)
	}
	storageInterface, dFunc, err := opts.GetStorage(
		prefix,
		keyFunc,
		strategy,
		func() runtime.Object { return &v3.UISettings{} },
		func() runtime.Object { return &v3.UISettingsList{} },
		GetAttrs,
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}
	store := &registry.Store{
		NewFunc:     func() runtime.Object { return &v3.UISettings{} },
		NewListFunc: func() runtime.Object { return &v3.UISettingsList{} },
		KeyRootFunc: opts.KeyRootFunc(false),
		KeyFunc:     opts.KeyFunc(false),
		ObjectNameFunc: func(obj runtime.Object) (string, error) {
			return obj.(*v3.UISettings).Name, nil
		},
		PredicateFunc:            MatchUISettings,
		DefaultQualifiedResource: v3.Resource("uisettings"),

		CreateStrategy:          strategy,
		UpdateStrategy:          strategy,
		DeleteStrategy:          strategy,
		EnableGarbageCollection: true,

		Storage:     storageInterface,
		DestroyFunc: dFunc,
	}

	return &REST{store, authorizer.NewUISettingsAuthorizer(opts.Authorizer), opts.ShortNames, client}, nil
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, val rest.ValidateObjectFunc, createOpt *metav1.CreateOptions) (runtime.Object, error) {
	uiSettings := obj.(*v3.UISettings)
	group := uiSettings.Spec.Group
	if group == "" {
		return nil, fmt.Errorf("UISettings Spec.Group is not specified")
	}
	err := r.authorizer.AuthorizeUISettingsOperation(ctx, uiSettings.Name, group)
	if err != nil {
		return nil, err
	}

	// Check the UISettingsGroup exists. The registry will validate the field is specified.
	if gp, err := r.client.UISettingsGroups().Get(ctx, group, options.GetOptions{}); err != nil {
		return nil, err
	} else {
		// Set the owner reference to only include the group. This is a private API and nothing should be changing
		// how these resources are garbage collected.
		uiSettings = uiSettings.DeepCopy()
		uiSettings.OwnerReferences = []metav1.OwnerReference{uisettingswebhook.BuildGroupOwnerReference(gp)}

		// If the group is user-specific, set the user name of the creator.
		if uisettingswebhook.ShouldInjectUser(gp) {
			//  Get the user name from the context attributes.
			uiSettings.Spec.User = r.user(ctx)
		}
	}

	return r.Store.Create(ctx, uiSettings, val, createOpt)
}

func (r *REST) Update(ctx context.Context, name string, objInfo rest.UpdatedObjectInfo, createValidation rest.ValidateObjectFunc,
	updateValidation rest.ValidateObjectUpdateFunc, forceAllowCreate bool, options *metav1.UpdateOptions) (runtime.Object, bool, error) {
	groupName, _ := util.GetUISettingsGroupFromUISettingsName(name)
	err := r.authorizer.AuthorizeUISettingsOperation(ctx, name, groupName)
	if err != nil {
		return nil, false, err
	}

	// Modify the update validation to check that the owner reference is not being updated to remove or change the
	// group.
	updatedUpdateValidation := func(ctx context.Context, obj, old runtime.Object) error {
		if err := uisettingswebhook.ValidateImmutableFields(old.(*v3.UISettings), obj.(*v3.UISettings)); err != nil {
			return err
		}
		return updateValidation(ctx, obj, old)
	}

	return r.Store.Update(ctx, name, objInfo, createValidation, updatedUpdateValidation, forceAllowCreate, options)
}

// Get retrieves the item from storage.
func (r *REST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	groupName, _ := util.GetUISettingsGroupFromUISettingsName(name)
	err := r.authorizer.AuthorizeUISettingsOperation(ctx, name, groupName)
	if err != nil {
		return nil, err
	}

	return r.Store.Get(ctx, name, options)
}

func (r *REST) Delete(ctx context.Context, name string, deleteValidation rest.ValidateObjectFunc, options *metav1.DeleteOptions) (runtime.Object, bool, error) {
	groupName, err := util.GetUISettingsGroupFromUISettingsName(name)
	if err != nil {
		return nil, false, err
	}
	err = r.authorizer.AuthorizeUISettingsOperation(ctx, name, groupName)
	if err != nil {
		return nil, false, err
	}

	return r.Store.Delete(ctx, name, deleteValidation, options)
}

func (r *REST) List(ctx context.Context, opts *metainternalversion.ListOptions) (runtime.Object, error) {
	groupName, serr := util.GetUISettingsGroupNameFromSelector(opts)

	// Ignore selector errors for now - AuthorizeUISettingsOperation will check that the user is able to GET all
	// settings for all groups. If not then return the selector error.
	err := r.authorizer.AuthorizeUISettingsOperation(ctx, "", groupName)
	if err != nil {
		if k8serrors.IsForbidden(err) && serr != nil {
			// If not authorized and no group selector was specified, use the selector error message as this is the
			// primary cause of the error.
			return nil, serr
		}
		return nil, err
	}

	if serr == nil {
		// If a group was supplied then check the group configuration to see if the settings are user specific and if
		// so, modify the filter to only include UISettings created by the requesting user.

		// Grab the group settings and check if we require user specific settings. If so include the user field in the
		// list query.
		if gp, err := r.client.UISettingsGroups().Get(ctx, groupName, options.GetOptions{}); err != nil {
			return nil, err
		} else if gp.Spec.FilterType == v3.FilterTypeUser {
			defaultUserSelector := fields.SelectorFromSet(map[string]string{"spec.user": r.user(ctx)})
			opts.FieldSelector = fields.AndSelectors(opts.FieldSelector, defaultUserSelector)
		}
	}

	return r.Store.List(ctx, opts)
}

func (r *REST) Watch(ctx context.Context, opts *metainternalversion.ListOptions) (watch.Interface, error) {
	groupName, serr := util.GetUISettingsGroupNameFromSelector(opts)

	// Ignore selector errors for now - AuthorizeUISettingsOperation will check that the user is able to GET all
	// settings for all groups. If not then return the selector error.
	err := r.authorizer.AuthorizeUISettingsOperation(ctx, "", groupName)
	if err != nil {
		if k8serrors.IsForbidden(err) && serr != nil {
			// If not authorized and no group selector was specified, use the selector error message as this is the
			// primary cause of the error.
			return nil, serr
		}
		return nil, err
	}

	if serr == nil {
		// If a group was supplied then check the group configuration to see if the settings are user specific and if
		// so, modify the filter to only include UISettings created by the requesting user.

		// Grab the group settings and check if we require user specific settings. If so include the user field in the
		// list query.
		if gp, err := r.client.UISettingsGroups().Get(ctx, groupName, options.GetOptions{}); err != nil {
			return nil, err
		} else if gp.Spec.FilterType == v3.FilterTypeUser {
			defaultUserSelector := fields.SelectorFromSet(map[string]string{"spec.user": r.user(ctx)})
			opts.FieldSelector = fields.AndSelectors(opts.FieldSelector, defaultUserSelector)
		}
	}

	return r.Store.Watch(ctx, opts)
}

// user extracts the user name from the context. If unknown it returns "<anonymous>" - this is primarily to get
// our FVs working where requests are made without user information - this is not
func (r *REST) user(ctx context.Context) string {
	info, ok := genericapirequest.UserFrom(ctx)
	if !ok {
		return "<anonymous>"
	}
	return info.GetName()
}
