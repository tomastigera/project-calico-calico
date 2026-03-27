// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package splunk

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/kubernetes/test/e2e/framework"
	e2ekubectl "k8s.io/kubernetes/test/e2e/framework/kubectl"
	e2enetwork "k8s.io/kubernetes/test/e2e/framework/network"
	e2esvc "k8s.io/kubernetes/test/e2e/framework/service"
	"k8s.io/utils/ptr"
)

const (
	logcollectorSplunkSecretName = "logcollector-splunk-credentials"

	splunkDeployName  = "splunk-deploy"
	splunkPassword    = "SplunkP@ss1234"
	splunkServiceName = "splunk-service"
	splunkHECToken    = "splunk-hec-token-1234"

	splunkWebPort  = 8000
	splunkHECPort  = 8088
	splunkRestPort = 8089
)

type Manager struct {
	f             *framework.Framework
	splunkPodName string

	// The LogCollector YAML template that the manager will apply after deploying Splunk.
	// It must have a single `%s` specifier, which the manager will replace with the Splunk endpoint.
	logCollectorSplunkTemplate string

	// The LogCollector YAML that the manager will restore after cleanup.
	logCollectorDefault string
}

func NewManager(f *framework.Framework, logCollectorSplunkTemplate string, logCollectorDefault string) *Manager {
	return &Manager{
		f:                          f,
		logCollectorSplunkTemplate: logCollectorSplunkTemplate,
		logCollectorDefault:        logCollectorDefault,
	}
}

func (s *Manager) Deploy(ctx context.Context) string {
	By("creating a Splunk enterprise server")
	_, err := s.f.ClientSet.AppsV1().Deployments(s.f.Namespace.Name).Create(ctx, s.splunkDeployment(), metav1.CreateOptions{})
	Expect(err).WithOffset(1).NotTo(HaveOccurred())
	_, err = s.f.ClientSet.CoreV1().Services(s.f.Namespace.Name).Create(ctx, s.splunkService(), metav1.CreateOptions{})
	Expect(err).WithOffset(1).NotTo(HaveOccurred())

	By("waiting for Splunk enterprise deployment and service to be ready")
	Eventually(func() error {
		logrus.Info("Still waiting for Splunk deployment to be ready...")
		pods, err := s.f.ClientSet.CoreV1().Pods(s.f.Namespace.Name).List(ctx, metav1.ListOptions{
			LabelSelector: "app=splunk-enterprise",
		})
		if err != nil {
			return err
		}
		for _, p := range pods.Items {
			if p.Status.Phase != corev1.PodRunning {
				return fmt.Errorf("pod %s is %s, not Running", p.Name, p.Status.Phase)
			}
			for _, c := range p.Status.ContainerStatuses {
				if !c.Ready {
					return fmt.Errorf("container %s in pod %s is not ready", c.Name, p.Name)
				}
			}
		}
		if len(pods.Items) == 0 {
			return fmt.Errorf("no splunk pods found")
		}
		return nil
	}, 5*time.Minute, 15*time.Second).WithOffset(1).Should(Succeed())
	err = e2enetwork.WaitForService(ctx, s.f.ClientSet, s.f.Namespace.Name, splunkServiceName, true, framework.Poll, e2esvc.RespondingTimeout)
	Expect(err).WithOffset(1).NotTo(HaveOccurred())
	s.splunkPodName = s.getSplunkPodName()
	Expect(s.splunkPodName).WithOffset(1).NotTo(BeEmpty())

	// configuration steps documented in https://docs.tigera.io/calico-enterprise/latest/visibility/elastic/archive-storage
	By("creating LogCollector Splunk secret")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "tigera-operator",
			Name:      logcollectorSplunkSecretName,
		},
		StringData: map[string]string{
			"token": splunkHECToken,
		},
	}
	// Delete (with ignore-not-found) then create the secret
	_, err = e2ekubectl.RunKubectl("tigera-operator", "delete", "secret", logcollectorSplunkSecretName, "--ignore-not-found=true")
	Expect(err).WithOffset(1).NotTo(HaveOccurred())
	_, err = s.f.ClientSet.CoreV1().Secrets("tigera-operator").Create(ctx, secret, metav1.CreateOptions{})
	Expect(err).WithOffset(1).NotTo(HaveOccurred())

	By("Update LogCollector with Splunk additional stores")
	endpoint := fmt.Sprintf("http://%s.%s.svc:%d", splunkServiceName, s.f.Namespace.Name, splunkHECPort)
	logrus.Infof("Splunk HEC endpoint=%s", endpoint)
	lcYAML := fmt.Sprintf(s.logCollectorSplunkTemplate, endpoint)
	_, err = e2ekubectl.RunKubectlInput("", lcYAML, "replace", "-f", "-")
	Expect(err).WithOffset(1).NotTo(HaveOccurred())

	return s.splunkPodName
}

func (s *Manager) Cleanup() {
	By("Restore LogCollector to default")
	Eventually(func() error {
		_, err := e2ekubectl.RunKubectlInput("", s.logCollectorDefault, "replace", "-f", "-")
		return err
	}, 5*time.Second, 1*time.Second).WithOffset(1).ShouldNot(HaveOccurred())

	By("Delete LogCollector Splunk secret")
	_, err := e2ekubectl.RunKubectl("tigera-operator", "delete", "secret", logcollectorSplunkSecretName, "--ignore-not-found=true")
	Expect(err).WithOffset(1).NotTo(HaveOccurred())
}

func (s *Manager) ApplyLogCollectorPatch(yaml string) {
	_, err := e2ekubectl.RunKubectlInput("", yaml, "apply", "-f", "-")
	Expect(err).WithOffset(1).NotTo(HaveOccurred())
}

func (s *Manager) SearchLogs(query string) (int, error) {
	out, err := e2ekubectl.RunKubectl(s.f.Namespace.Name, "exec", s.splunkPodName, "--",
		"curl",
		"-k",
		"-s",
		"-u", fmt.Sprintf("admin:%s", splunkPassword),
		// https://help.splunk.com/en/splunk-enterprise/rest-api-reference/9.4/search-endpoints/search-endpoint-descriptions#ariaid-title30
		fmt.Sprintf("https://127.0.0.1:%d/services/search/jobs/export", splunkRestPort),
		"-d", fmt.Sprintf("%s | stats count", query),
		"-d", "output_mode=json",
	)
	if err != nil {
		logrus.WithError(err).Info("failed to search Splunk")
		return 0, err
	}
	var resp splunkSearchResponse
	decoder := json.NewDecoder(strings.NewReader(out))
	if err := decoder.Decode(&resp); err != nil {
		logrus.WithError(err).Info("failed to decode Splunk response")
		return 0, err
	}

	if resp.Result == nil {
		return 0, nil
	}

	return resp.Result.Count, nil
}

func (s *Manager) getSplunkPodName() string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	podlist, err := s.f.ClientSet.CoreV1().Pods(s.f.Namespace.Name).List(ctx, metav1.ListOptions{})
	Expect(err).NotTo(HaveOccurred())
	Expect(podlist.Items).NotTo(BeEmpty())

	podName := ""
	for _, item := range podlist.Items {
		if strings.Contains(item.Name, splunkDeployName) {
			podName = item.Name
			break
		}
	}
	Expect(podName).NotTo(BeEmpty())
	return podName
}

func (s *Manager) splunkDeployment() *appsv1.Deployment {
	label := map[string]string{
		"app": "splunk-enterprise",
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      splunkDeployName,
			Namespace: s.f.Namespace.Name,
			Labels:    label,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](1),
			Selector: &metav1.LabelSelector{MatchLabels: label},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: label},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "splunk",
							Image: "splunk/splunk:9.4",
							Env: []corev1.EnvVar{
								{
									Name:  "SPLUNK_GENERAL_TERMS",
									Value: "--accept-sgt-current-at-splunk-com",
								},
								{
									Name:  "SPLUNK_START_ARGS",
									Value: "--accept-license",
								},
								{
									Name:  "SPLUNK_PASSWORD",
									Value: splunkPassword,
								},
								{
									Name:  "SPLUNK_HEC_ENABLE",
									Value: "true",
								},
								{
									Name:  "SPLUNK_HEC_PORT",
									Value: strconv.Itoa(splunkHECPort),
								},
								{
									Name:  "SPLUNK_HEC_TOKEN",
									Value: splunkHECToken,
								},
								{
									// LogCollector does not support forwarding logs to a Splunk HEC endpoint with a self-signed certificate.
									// Disabling SSL allows LogCollector to archive logs to the Splunk Enterprise server.
									Name:  "SPLUNK_HEC_SSL",
									Value: "false",
								},
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "web",
									ContainerPort: splunkWebPort,
									Protocol:      corev1.ProtocolTCP,
								},
								{
									Name:          "hec",
									ContainerPort: splunkHECPort,
									Protocol:      corev1.ProtocolTCP,
								},
								{
									Name:          "restapi",
									ContainerPort: splunkRestPort,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							StartupProbe: &corev1.Probe{
								FailureThreshold: 10,
								PeriodSeconds:    30,
								TimeoutSeconds:   5,
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/",
										Port: intstr.FromInt(splunkWebPort),
									},
								},
							},
							LivenessProbe: &corev1.Probe{
								FailureThreshold: 5,
								PeriodSeconds:    30,
								TimeoutSeconds:   5,
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/",
										Port: intstr.FromInt(splunkWebPort),
									},
								},
							},
							ReadinessProbe: &corev1.Probe{
								FailureThreshold:    5,
								InitialDelaySeconds: 60,
								PeriodSeconds:       15,
								TimeoutSeconds:      5,
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/",
										Port: intstr.FromInt(splunkWebPort),
									},
								},
							},
							SecurityContext: &corev1.SecurityContext{
								// run as root to be able to modify Splunk hec config files
								RunAsUser: ptr.To[int64](0),
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									MountPath: "/opt/splunk/var",
									Name:      "splunk-var",
									ReadOnly:  false,
								},
							},
						},
					},
					Tolerations: []corev1.Toleration{
						{Key: "kubernetes.io/arch", Value: "arm64", Effect: corev1.TaintEffectNoSchedule},
					},
					Volumes: []corev1.Volume{
						{
							Name: "splunk-var",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
					},
				},
			},
		},
	}
}

func (s *Manager) splunkService() *corev1.Service {
	label := map[string]string{
		"app": "splunk-enterprise",
	}

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      splunkServiceName,
			Namespace: s.f.Namespace.Name,
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: label,
			Ports: []corev1.ServicePort{
				{
					Name:       "web",
					Protocol:   corev1.ProtocolTCP,
					Port:       splunkWebPort,
					TargetPort: intstr.FromInt(splunkWebPort),
				},
				{
					Name:       "hec",
					Protocol:   corev1.ProtocolTCP,
					Port:       splunkHECPort,
					TargetPort: intstr.FromInt(splunkHECPort),
				},
				{
					Name:       "restapi",
					Protocol:   corev1.ProtocolTCP,
					Port:       splunkRestPort,
					TargetPort: intstr.FromInt(splunkRestPort),
				},
			},
		},
	}
}

type splunkSearchResponse struct {
	Result *splunkSearchResult `json:"result,omitempty"`
}

type splunkSearchResult struct {
	Count int `json:",string"`
}
