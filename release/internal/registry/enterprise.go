package registry

const (
	TigeraNamespace = "tigera"

	DefaultEnterpriseRegistry = "quay.io/tigera"

	// DefaultEnterpriseHashreleaseRegistry is the default registry for hashrelease images.
	DefaultEnterpriseHashreleaseRegistry = "gcr.io/unique-caldron-775/cnx/tigera"

	// DefaultEnterpriseHelmRegistry is the default registry for hashrelease Helm charts.
	DefaultEnterpriseHelmRegistry = "quay.io/tigera/charts"
)

// EnterpriseImageMap maps the component name to its image for enterprise.
var EnterpriseImageMap = map[string]string{
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
