// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package sidecar

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calico/l7-admission-controller/cmd/l7-admission-controller/config"
)

const (
	testEnvoyImage    = "test-envoy-image"
	testDikastesImage = "test-dikastes-image"
)

func admissionReviewBytes(pod *corev1.Pod) ([]byte, error) {
	admissionReviewRequest := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AdmissionReview",
			APIVersion: "admission.k8s.io/v1",
		},
		Request: &admissionv1.AdmissionRequest{
			UID: "test-uid",
			Kind: metav1.GroupVersionKind{
				Group:   "apps",
				Version: "v1",
				Kind:    "Pod",
			},
			Namespace: "test-namespace",
			Name:      "test-name",
			Operation: admissionv1.Create,
			UserInfo:  authenticationv1.UserInfo{},
			Object: runtime.RawExtension{
				Raw: podBytes(pod),
			},
		},
	}

	admissionReviewBytes, err := json.Marshal(admissionReviewRequest)
	if err != nil {
		return nil, err
	}

	return admissionReviewBytes, nil
}

func podBytes(pod *corev1.Pod) []byte {
	podBytes, err := json.Marshal(pod)
	if err != nil {
		panic(err)
	}
	return podBytes
}

type testCase struct {
	name                            string
	pod                             *corev1.Pod
	expectedResponseCode            int
	expectedAdmissionReviewResponse *admissionv1.AdmissionReview
}

func testPodWithAnnotations(annotations map[string]string) *corev1.Pod {
	return &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-name",
			Namespace:   "test-namespace",
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "test-container",
					Image: "test-image",
				},
			},
		},
	}
}

func testAdmissionReview(t *testing.T, handler http.Handler, tc testCase) {
	admissionReviewBytes, err := admissionReviewBytes(tc.pod)
	if err != nil {
		t.Fatal(err)
	}

	admissionReviewReader := io.NopCloser(bytes.NewReader(admissionReviewBytes))

	req, err := http.NewRequest("POST", "/", admissionReviewReader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/json")

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != tc.expectedResponseCode {
		t.Errorf("Expected status code %d, but got %d", tc.expectedResponseCode, recorder.Code)
	}

	if tc.expectedAdmissionReviewResponse != nil {
		var admissionReviewResponse admissionv1.AdmissionReview
		if err := json.Unmarshal(recorder.Body.Bytes(), &admissionReviewResponse); err != nil {
			t.Fatal(err)
		}

		if admissionReviewResponse.Response.Allowed != tc.expectedAdmissionReviewResponse.Response.Allowed {
			t.Errorf("Expected Allowed %t, but got %t", tc.expectedAdmissionReviewResponse.Response.Allowed, admissionReviewResponse.Response.Allowed)
		}

		if !bytes.Equal(admissionReviewResponse.Response.Patch, tc.expectedAdmissionReviewResponse.Response.Patch) {
			t.Errorf("Expected Patch %s, but got %s",
				string(tc.expectedAdmissionReviewResponse.Response.Patch),
				string(admissionReviewResponse.Response.Patch),
			)
		}
	}
}

func TestServeHTTP(t *testing.T) {
	// Create a new sidecarWebhook instance
	sidecar := NewSidecarHandler(&config.Config{
		EnvoyImg:    testEnvoyImage,
		DikastesImg: testDikastesImage,
	})

	testCases := []testCase{
		genTestCase(
			"Pod with Policy annotation",
			testPodWithAnnotations(map[string]string{"applicationlayer.projectcalico.org/policy": "Enabled"}),
			http.StatusOK,
			sidecarCfg{
				envoyImg:    testEnvoyImage,
				dikastesImg: testDikastesImage,
				policy:      true,
			},
		),
		genTestCase(
			"Pod with WAF annotation",
			testPodWithAnnotations(map[string]string{"applicationlayer.projectcalico.org/waf": "Enabled"}),
			http.StatusOK,
			sidecarCfg{
				envoyImg:    testEnvoyImage,
				dikastesImg: testDikastesImage,
				waf:         true,
			},
		),
		genTestCase(
			"Pod with Logging annotation",
			testPodWithAnnotations(map[string]string{"applicationlayer.projectcalico.org/logging": "Enabled"}),
			http.StatusOK,
			sidecarCfg{
				envoyImg:    testEnvoyImage,
				dikastesImg: testDikastesImage,
				logging:     true,
			},
		),
		genTestCase(
			"Pod with all annotations",
			testPodWithAnnotations(map[string]string{
				"applicationlayer.projectcalico.org/policy":  "Enabled",
				"applicationlayer.projectcalico.org/waf":     "Enabled",
				"applicationlayer.projectcalico.org/logging": "Enabled",
			}),
			http.StatusOK,
			sidecarCfg{
				envoyImg:    testEnvoyImage,
				dikastesImg: testDikastesImage,
				policy:      true,
				waf:         true,
				logging:     true,
			},
		),
		genTestCase(
			"Pod with unknown annotation",
			testPodWithAnnotations(map[string]string{"intothe": "unknown"}),
			http.StatusOK,
			sidecarCfg{},
		),
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testAdmissionReview(t, sidecar, tc)
		})
	}
}

// TestNoPatchTypWithoutPatch verifies that when no sidecar injection is needed,
// the webhook returns a response without PatchType set. Setting PatchType without
// Patch is an invalid admission response per Kubernetes API spec.
func TestNoPatchTypeWithoutPatch(t *testing.T) {
	sidecar := NewSidecarHandler(&config.Config{
		EnvoyImg:    testEnvoyImage,
		DikastesImg: testDikastesImage,
	})

	// Pod with sidecar label but NO feature annotations - this is the bug scenario
	pod := testPodWithAnnotations(map[string]string{
		"some-unrelated-annotation": "value",
	})

	admissionReviewBytes, err := admissionReviewBytes(pod)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", "/", io.NopCloser(bytes.NewReader(admissionReviewBytes)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	sidecar.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", recorder.Code)
	}

	var admissionReviewResponse admissionv1.AdmissionReview
	if err := json.Unmarshal(recorder.Body.Bytes(), &admissionReviewResponse); err != nil {
		t.Fatal(err)
	}

	response := admissionReviewResponse.Response
	if !response.Allowed {
		t.Error("Expected Allowed to be true")
	}

	// This is the key assertion: PatchType must be nil when Patch is nil
	// Otherwise Kubernetes will reject the response with:
	// "webhook returned response.patchType but not response.patch"
	if response.Patch != nil {
		t.Errorf("Expected Patch to be nil, got %s", string(response.Patch))
	}
	if response.PatchType != nil {
		t.Errorf("Expected PatchType to be nil when Patch is nil, got %v", *response.PatchType)
	}
}

func genTestCase(name string, pod *corev1.Pod, expectedResponseCode int, fromSidecarCfg sidecarCfg) testCase {
	return testCase{
		name:                 name,
		pod:                  pod,
		expectedResponseCode: expectedResponseCode,
		expectedAdmissionReviewResponse: &admissionv1.AdmissionReview{
			Response: &admissionv1.AdmissionResponse{
				Allowed: true,
				Patch: func() []byte {
					patch, err := fromSidecarCfg.patchBytes()
					if err != nil {
						panic(fmt.Errorf("failed to marshal patch: %v", err))
					}
					return patch
				}(),
			},
		},
	}
}
