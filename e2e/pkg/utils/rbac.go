// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// networkAdminClusterRole is the Calico Enterprise cluster role for network administrators.
	networkAdminClusterRole = "tigera-network-admin"
)

// NetworkAdminToken creates a ServiceAccount with tigera-network-admin privileges in the
// specified namespace, generates an authentication token, and registers cleanup with DeferCleanup.
//
// This utility abstracts RBAC setup for tests that need elevated permissions to access
// Calico Enterprise APIs (dashboards, manager, etc.). The ServiceAccount and ClusterRoleBinding
// are automatically cleaned up when the test completes.
//
// Usage:
//
//	token, err := utils.NetworkAdminToken(ctx, f.ClientSet, "test-namespace")
//	Expect(err).NotTo(HaveOccurred())
//	// Use token for API authentication
func NetworkAdminToken(ctx context.Context, clientset kubernetes.Interface, namespace string) (string, error) {
	saName := fmt.Sprintf("test-admin-%s", namespace)
	crbName := fmt.Sprintf("test-admin-%s-network-admin", namespace)

	// Create ServiceAccount and register cleanup immediately.
	// This ensures SA is cleaned up even if subsequent operations fail.
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      saName,
			Namespace: namespace,
		},
	}
	_, err := clientset.CoreV1().ServiceAccounts(namespace).Create(ctx, sa, metav1.CreateOptions{})
	if err != nil && !errors.IsAlreadyExists(err) {
		return "", fmt.Errorf("failed to create service account: %w", err)
	}
	DeferCleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := clientset.CoreV1().ServiceAccounts(namespace).Delete(cleanupCtx, saName, metav1.DeleteOptions{}); err != nil {
			if !errors.IsNotFound(err) {
				logrus.WithError(err).Warnf("Failed to delete ServiceAccount %s/%s", namespace, saName)
			}
		}
	})

	// Create ClusterRoleBinding and register cleanup immediately.
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: crbName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     networkAdminClusterRole,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      saName,
				Namespace: namespace,
			},
		},
	}
	_, err = clientset.RbacV1().ClusterRoleBindings().Create(ctx, crb, metav1.CreateOptions{})
	if err != nil && !errors.IsAlreadyExists(err) {
		return "", fmt.Errorf("failed to create cluster role binding: %w", err)
	}
	DeferCleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := clientset.RbacV1().ClusterRoleBindings().Delete(cleanupCtx, crbName, metav1.DeleteOptions{}); err != nil {
			if !errors.IsNotFound(err) {
				logrus.WithError(err).Warnf("Failed to delete ClusterRoleBinding %s", crbName)
			}
		}
	})

	// Create token using TokenRequest API
	expirationSeconds := int64(3600) // 1 hour
	tokenRequest := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: &expirationSeconds,
		},
	}

	result, err := clientset.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, saName, tokenRequest, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create token: %w", err)
	}

	Expect(result.Status.Token).NotTo(BeEmpty(), "Token should not be empty")
	return result.Status.Token, nil
}
