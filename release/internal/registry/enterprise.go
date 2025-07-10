package registry

const (
	DefaultEnterpriseRegistry = "quay.io/tigera"

	// DefaultEnterpriseHashreleaseRegistry is the default registry for hashrelease images.
	DefaultEnterpriseHashreleaseRegistry = "gcr.io/unique-caldron-775/cnx/tigera"

	// HelmDevRegistry is the registry for hashrelease Helm charts.
	HelmDevRegistry = "oci://us-central1-docker.pkg.dev/unique-caldron-775/hashrelease-charts"
)

// EnterpriseImageMap maps the component name to its image for enterprise.
var EnterpriseImageMap = map[string]string{
	"cnx-kube-controllers":        "kube-controllers",
	"csi-node-driver-registrar":   "node-driver-registrar",
	"elastic-tsee-installer":      "intrusion-detection-job-installer",
	"elasticsearch-operator":      "eck-operator",
	"flexvol":                     "pod2daemon-flexvol",
	"tigera-cni":                  "cni",
	"tigera-cni-windows":          "cni-windows",
	"tigera-prometheus-service":   "prometheus-service",
	"gateway-api-envoy-gateway":   "envoy-gateway",
	"gateway-api-envoy-proxy":     "envoy-proxy",
	"gateway-api-envoy-ratelimit": "envoy-ratelimit",
}
