# Application Layer Policy

Application Layer Policy for [Project Calico][calico] enforces network and application layer authorization policies via Envoy External Authorization.

The `envoy.ext_authz` filter inserted into the proxy, which calls out to Dikastes when service requests are
processed.  We compute policy based on a global store which is distributed to Dikastes by its local Felix.

## Command-line options and environment variables

### Dikastes Server

      $ dikastes -h

      Usage of dikastes:
      -dial string
            PolicySync address e.g. /var/run/nodeagent/socket
      -dial-network string
            PolicySync network e.g. tcp, unix (default "unix")
      -envoy-health-check-port string
            Envoy health check port (default "16007")
      -envoy-inbound-port string
            Envoy inbound port (default "16001")
      -envoy-liveness-port string
            Envoy liveness port (default "16004")
      -envoy-metrics-port string
            Envoy metrics port (default "9901")
      -envoy-readiness-port string
            Envoy readiness port (default "16005")
      -envoy-startup-probe-port string
            Envoy startup probe port (default "16006")
      -http-server-addr string
            HTTP server address (default "0.0.0.0")
      -http-server-port string
            HTTP server port
      -listen string
            Listen address (default "/var/run/dikastes/dikastes.sock")
      -listen-network string
            Listen network e.g. tcp, unix (default "unix")
      -log-level string
            Log at specified level e.g. panic, fatal, info, debug, trace (default "info")
      -per-host-alp-enabled
            Enable ALP.
      -per-host-waf-enabled
            Enable WAF.
      -sidecar-alp-enabled
            Enable ALP.
      -sidecar-logs-enabled
            Enable HTTP logging.
      -sidecar-waf-enabled
            Enable WAF.
      -subscription-type string
            Subscription type e.g. per-pod-policies, per-host-policies (default "per-host-policies")
      -waf-directive value
            Additional directives to specify for WAF (if enabled). Can be specified multiple times.
      -waf-ruleset-file value
            WAF ruleset file path to load. e.g. /etc/modsecurity-ruleset/tigera.conf. Can be specified multiple times.
      -waf-ruleset-root-dir string
            WAF ruleset root dir path. e.g. /etc/waf

    Environment variables:

    DIKASTES_SUBSCRIPTION_TYPE

      sets the subscription type that's sent as a synchronization request to policy sync. valid values: per-pod-policies (default), per-host-policies.

    DIKASTES_HTTP_BIND_ADDR

      sets the HTTP server address.

    DIKASTES_HTTP_PORT

      sets the HTTP server port.

    DIKASTES_ENABLE_CHECKER_REFLECTION

      this can be set to any value. if set, it enables grpc service reflection. Used for debugging / development.



