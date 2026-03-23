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
	"crypto/x509"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	operatorv1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// IsEnterprise checks if the cluster has Calico Enterprise installed
// by checking the Installation CR's Spec.Variant field.
func IsEnterprise(ctx context.Context, cli ctrlclient.Client) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	installation := &operatorv1.Installation{}
	err := cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, installation)
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return installation.Spec.Variant == operatorv1.TigeraSecureEnterprise, nil
}

// GetTigeraCACert retrieves the CA certificate for TLS connections from the tigera-ca-bundle.
// This bundle is created by the tigera-operator and contains the CA used to sign all Tigera component certificates.
// It checks both calico-system and tigera-operator namespaces for the bundle.
func GetTigeraCACert(ctx context.Context, f *framework.Framework) *x509.CertPool {
	var cm *corev1.ConfigMap
	var err error

	for _, ns := range []string{"calico-system", "tigera-operator"} {
		cm, err = f.ClientSet.CoreV1().ConfigMaps(ns).Get(ctx, "tigera-ca-bundle", metav1.GetOptions{})
		if err == nil {
			break
		}
	}
	gomega.ExpectWithOffset(1, err).NotTo(gomega.HaveOccurred(), "failed to get tigera-ca-bundle ConfigMap")

	roots := x509.NewCertPool()
	if caCert, ok := cm.Data["tigera-ca-bundle.crt"]; ok {
		roots.AppendCertsFromPEM([]byte(caCert))
	} else {
		ginkgo.Fail("tigera-ca-bundle.crt not found in tigera-ca-bundle ConfigMap")
	}
	return roots
}
