// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package sidecar

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"dario.cat/mergo"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog/v2"

	"github.com/projectcalico/calico/l7-admission-controller/cmd/l7-admission-controller/config"
)

type sidecarWebhook struct {
	deserializer runtime.Decoder
	cfg          *config.Config
}

func NewSidecarHandler(cfg *config.Config) http.Handler {
	scheme := runtime.NewScheme()
	codecs := serializer.NewCodecFactory(scheme)
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(admissionv1.AddToScheme(scheme))
	utilruntime.Must(admissionregistrationv1.AddToScheme(scheme))

	return &sidecarWebhook{
		deserializer: codecs.UniversalDeserializer(),
		cfg:          cfg,
	}
}

func (s *sidecarWebhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var (
		res  runtime.Object
		obj  runtime.Object
		gvk  *schema.GroupVersionKind
		body []byte
		err  error
	)

	// Check content-type
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		klog.Errorf("contentType=%s, expect application/json", contentType)
		goto badRequest
	}

	// Parse body
	body, err = io.ReadAll(r.Body)
	if err != nil {
		klog.Errorf("Request body could not be read: %v", err)
		goto badRequest
	}
	obj, gvk, err = s.deserializer.Decode(body, nil, nil)
	if err != nil {
		klog.Errorf("Request could not be decoded: %v", err)
		goto badRequest
	}
	switch *gvk {
	case admissionv1.SchemeGroupVersion.WithKind("AdmissionReview"):
		admrev, ok := obj.(*admissionv1.AdmissionReview)
		if !ok {
			klog.Errorf("Expected v1.AdmissionReview but got %T", obj)
			goto badRequest
		}
		resAdmrev := &admissionv1.AdmissionReview{}
		resAdmrev.SetGroupVersionKind(*gvk)
		resAdmrev.Response = &admissionv1.AdmissionResponse{
			UID:     admrev.Request.UID,
			Allowed: true,
		}
		err = s.patch(resAdmrev.Response, admrev.Request)
		if err != nil {
			klog.Error(err)
			goto internalErr
		}
		res = resAdmrev
	default:
		klog.Errorf("Unsupported group version kind: %v", gvk)
		goto badRequest
	}

	body, err = json.Marshal(res)
	if err != nil {
		klog.Error(err)
		goto internalErr
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err = w.Write(body); err != nil {
		klog.Error(err)
	}
	return

internalErr:
	w.WriteHeader(http.StatusInternalServerError)
	return

badRequest:
	w.WriteHeader(http.StatusBadRequest)
}

var defaultVolumes = []map[string]interface{}{
	{"name": "envoy-config", "emptyDir": map[string]interface{}{}},
	{"name": "dikastes-sock", "hostPath": map[string]interface{}{"path": "/var/run/dikastes", "type": "Directory"}},
	{"name": "l7-collector-sock", "hostPath": map[string]interface{}{"path": "/var/run/l7-collector", "type": "Directory"}},
}

func generateDikastesInitContainer(image string, args []string, dataplane string) []map[string]interface{} {
	capabilites := []string{"NET_ADMIN", "NET_RAW"}
	if dataplane == "nftables" {
		capabilites = append(capabilites, "SYS_ADMIN", "NET_BIND_SERVICE")
	}
	return []map[string]interface{}{
		{
			"name":    "tigera-dikastes-init",
			"image":   image,
			"command": []string{"/dikastes", "init-sidecar"},
			"args":    args,
			"env": []map[string]interface{}{
				{
					"name":  "ENVOY_CONFIG_PATH",
					"value": "/etc/tigera/envoy.yaml",
				},
				{
					"name":  "ENVOY_INBOUND_PORT",
					"value": "16001",
				},
				{
					"name":  "DATAPLANE",
					"value": dataplane,
				},
			},
			"volumeMounts": []map[string]interface{}{
				{
					"name":      "envoy-config",
					"mountPath": "/etc/tigera",
				},
			},
			"securityContext": map[string]interface{}{
				"runAsGroup": 0,
				"runAsUser":  0,
				"capabilities": map[string]interface{}{
					"add": capabilites,
				},
			},
		},
	}
}

func generateEnvoyContainer(image string, attrs map[string]interface{}) ([]map[string]interface{}, error) {
	res := map[string]interface{}{
		"name":          "tigera-envoy",
		"image":         image,
		"command":       []string{"envoy", "-c", "/etc/tigera/envoy.yaml"},
		"restartPolicy": "Always",
		"ports": []map[string]interface{}{
			{
				"containerPort": 16001,
			},
		},
		"env": []map[string]interface{}{
			{
				"name":  "TIGERA_TPROXY",
				"value": "Disabled",
			},
		},
		"startupProbe": map[string]interface{}{
			"tcpSocket": map[string]interface{}{
				"port": 16001,
			},
		},
		"securityContext": map[string]interface{}{
			"runAsGroup": 0,
			"runAsUser":  0,
			"capabilities": map[string]interface{}{
				"add": []string{"NET_ADMIN"},
			},
		},
		"volumeMounts": []map[string]interface{}{
			{
				"name":      "envoy-config",
				"mountPath": "/etc/tigera",
			},
			{
				"name":      "dikastes-sock",
				"mountPath": "/var/run/dikastes",
			},
			{
				"name":      "l7-collector-sock",
				"mountPath": "/var/run/l7-collector",
			},
		},
	}

	if err := mergo.Map(&res, attrs); err != nil {
		return nil, err
	}

	return []map[string]interface{}{res}, nil
}

type sidecarCfg struct {
	dikastesImg    string
	envoyImg       string
	dataplane      string
	logging        bool
	policy         bool
	waf            bool
	envoyResources string
}

func (cfg *sidecarCfg) volumes() (res []map[string]interface{}) {
	res = append(res, defaultVolumes...)

	if cfg.logging || cfg.policy {
		res = append(res, map[string]interface{}{
			"name": "felix-sync",
			"csi": map[string]interface{}{
				"driver": "csi.tigera.io",
			},
		})
	}

	if cfg.waf {
		res = append(res, map[string]interface{}{
			"name": "tigera-waf-logfiles",
			"hostPath": map[string]interface{}{
				"path": "/var/log/calico/waf",
				"type": "DirectoryOrCreate",
			},
		})
	}

	return res
}

func (cfg *sidecarCfg) dikastesInitArgs() []string {
	args := []string{}

	if cfg.logging {
		args = append(args, "--sidecar-logs-enabled")
	}
	if cfg.policy {
		args = append(args, "--sidecar-alp-enabled")
	}
	if cfg.waf {
		args = append(args, "--sidecar-waf-enabled")
	}

	return args
}

func (cfg *sidecarCfg) envoyOptionalAttributes() (map[string]interface{}, error) {
	res := map[string]interface{}{}
	if cfg.envoyResources != "" {
		var envres interface{}
		err := json.Unmarshal([]byte(cfg.envoyResources), &envres)
		if err != nil {
			return nil, err
		}
		res["resources"] = envres
	}
	return res, nil
}

func (cfg *sidecarCfg) patchBytes(additionalPatches ...patchOp) ([]byte, error) {
	if !cfg.logging && !cfg.policy && !cfg.waf {
		return nil, nil
	}

	envoyOpts, err := cfg.envoyOptionalAttributes()
	if err != nil {
		return nil, fmt.Errorf("failed to parse envoy optional attributes: %w", err)
	}
	envoyValues, err := generateEnvoyContainer(cfg.envoyImg, envoyOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate envoy container patch: %w", err)
	}

	// build patch with volumes and initContainers
	var patch patchOps
	patch = append(patch, additionalPatches...)
	for _, vol := range cfg.volumes() {
		patch = append(patch, patchOp{
			Op:    "add",
			Path:  "/spec/volumes/-",
			Value: vol,
		})
	}
	patch = append(patch, patchOp{
		Op:   "add",
		Path: "/spec/initContainers",
		Value: append(
			generateDikastesInitContainer(cfg.dikastesImg, cfg.dikastesInitArgs(), cfg.dataplane),
			envoyValues...,
		),
	})

	return patch.MarshalJSON()
}

func relocateRunAsNonRoot(p *corev1.Pod) []patchOp {
	res := make([]patchOp, 0)

	if p.Spec.SecurityContext != nil && p.Spec.SecurityContext.RunAsNonRoot != nil && *p.Spec.SecurityContext.RunAsNonRoot {
		res = append(res, patchOp{
			Op:   "remove",
			Path: "/spec/securityContext/runAsNonRoot",
		})

		for i := range p.Spec.Containers {
			res = append(res, patchOp{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/containers/%d/securityContext", i),
				Value: map[string]interface{}{"runAsNonRoot": true},
			})
		}
	}

	return res
}

func (s *sidecarWebhook) patch(res *admissionv1.AdmissionResponse, req *admissionv1.AdmissionRequest) error {
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return err
	}

	cfg := sidecarCfg{
		dikastesImg:    s.cfg.DikastesImg,
		envoyImg:       s.cfg.EnvoyImg,
		dataplane:      s.cfg.Dataplane,
		logging:        pod.Annotations["applicationlayer.projectcalico.org/logging"] == "Enabled",
		policy:         pod.Annotations["applicationlayer.projectcalico.org/policy"] == "Enabled",
		waf:            pod.Annotations["applicationlayer.projectcalico.org/waf"] == "Enabled",
		envoyResources: pod.Annotations["applicationlayer.projectcalico.org/sidecarResources"],
	}

	pt := admissionv1.PatchTypeJSONPatch
	res.PatchType = &pt

	additionalPatches := relocateRunAsNonRoot(&pod)

	patchBytes, err := cfg.patchBytes(additionalPatches...)
	if err != nil {
		return err
	}
	res.Patch = patchBytes

	return nil
}

type patchOp struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

type patchOps []patchOp

func (p patchOps) MarshalJSON() ([]byte, error) {
	return json.Marshal([]patchOp(p))
}
