// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package nonclusterhost

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

const (
	defaultTSEEInstanceName = "tigera-secure"
)

var NonClusterHostGVR = schema.GroupVersionResource{
	Group:    "operator.tigera.io",
	Version:  "v1",
	Resource: "nonclusterhosts",
}

type validateFn func(string) error

func GetNonClusterHost(ctx context.Context, dynamicClient dynamic.Interface) (*unstructured.Unstructured, error) {
	return dynamicClient.Resource(NonClusterHostGVR).Namespace(corev1.NamespaceAll).Get(ctx, defaultTSEEInstanceName, metav1.GetOptions{})
}

func ExtractFromNonClusterHostSpec(unstructuredObj *unstructured.Unstructured, fieldName string, validator validateFn) (string, error) {
	if unstructuredObj == nil {
		return "", errors.New("object is nil")
	}

	specObj, ok := unstructuredObj.Object["spec"]
	if !ok {
		return "", errors.New("failed to get spec from object")
	}

	spec, ok := specObj.(map[string]interface{})
	if !ok {
		return "", errors.New("failed to cast spec object")
	}
	v, ok := spec[fieldName]
	if !ok {
		return "", fmt.Errorf("failed to get %s from spec", fieldName)
	}
	value, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("failed to cast %s to string", fieldName)
	}

	if validator != nil {
		if err := validator(value); err != nil {
			return "", err
		}
	}
	return value, nil
}
