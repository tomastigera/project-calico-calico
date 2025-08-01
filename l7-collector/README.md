# Envoy Log Collector

This implementation and code is largely taken from the implementation of [ingress-collector](https://github.com/tigera/ingress-collector). This collector runs in the same container as the envoy sidecar (another sidecar), collects logs written to a file specified in the config and sends them to felix through a socket using gRPC.

## Build and Testing

To build the image use

```bash
make image
```

The image expects a logs file to be present in the location as specified in the config. To run the container locally create a dummy log file in the location specified in the config.

```bash
docker run -v <log-file-location-in-config>:dummy.log <image-hash>
```


### Using with CIG (Calico Ingress Gateway)

Prerequisites:
- set `pod-security.kubernetes.io/enforce` of `tigera-gateway` namespace labels to `privileged` first.
- enable policysync with felix: https://docs.tigera.io/calico/latest/reference/resources/felixconfig?#:~:text=policySyncPathPrefix
- grab a link to the latest l7-collector image e.g. gcr.io/cnx/tigera/l7-collector:v3.22-2.0 (please verify if valid before proceeding)

Example `EnvoyProxy` Config:

        apiVersion: gateway.envoyproxy.io/v1alpha1
        kind: EnvoyProxy
        metadata:
        name: envoy-proxy-config
        namespace: tigera-gateway
        spec:
        logging:
            level:
            default: debug
        provider:
            kubernetes:
            envoyDeployment:
                patch:
                type: StrategicMerge
                value:
                    spec:
                    template:
                        spec:
                        containers:
                            - env:
                                - name: LOG_LEVEL
                                value: Debug
                                - name: FELIX_DIAL_TARGET
                                value: /var/run/felix/nodeagent/socket
                                - name: LISTEN_ADDRESS
                                value: :8080
                                - name: LISTEN_NETWORK
                                value: tcp
                                - name: ENVOY_ACCESS_LOG_PATH
                                value: /access_logs/access.log
                                - name: ENVOY_LOG_INTERVAL_SECONDS
                                value: "10"
                            image: <latest l7-collector-image>
                            imagePullPolicy: IfNotPresent
                            name: tigera-l7-log-collector
                            resources: {}
                            securityContext:
                                allowPrivilegeEscalation: true
                                capabilities:
                                drop:
                                    - ALL
                                privileged: true
                                runAsGroup: 0
                                runAsNonRoot: false
                                runAsUser: 0
                                seccompProfile:
                                type: RuntimeDefault
                            terminationMessagePath: /dev/termination-log
                            terminationMessagePolicy: File
                            volumeMounts:
                                - mountPath: /access_logs
                                name: access-logs
                                - mountPath: /var/run/felix
                                name: felix-sync
                container:
                image: envoyproxy/envoy:v1.31-latest
                volumeMounts:
                    - mountPath: /access_logs
                    name: access-logs
                    readOnly: false
                securityContext:
                    allowPrivilegeEscalation: true
                    capabilities:
                    drop:
                        - ALL
                    privileged: true
                    runAsGroup: 0
                    runAsNonRoot: false
                    runAsUser: 0
                    seccompProfile:
                    type: RuntimeDefault
                pod:
                volumes:
                    - name: access-logs
                    emptyDir: {}
                    - csi:
                        driver: csi.tigera.io
                    name: felix-sync
                imagePullSecrets:
                    - name: tigera-pull-secret
            type: Kubernetes
        telemetry:
            accessLog:
            settings:
                - format:
                    json:
                    reporter: "destination"
                    start_time: "%START_TIME%"
                    duration: "%DURATION%"
                    response_code: "%RESPONSE_CODE%"
                    bytes_sent: "%BYTES_SENT%"
                    bytes_received: "%BYTES_RECEIVED%"
                    user_agent: "%REQ(USER-AGENT)%"
                    request_path: "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%"
                    request_method: "%REQ(:METHOD)%"
                    request_id: "%REQ(X-REQUEST-ID)%"
                    type: "{{.}}"
                    downstream_remote_address: "%DOWNSTREAM_REMOTE_ADDRESS%"
                    downstream_local_address: "%DOWNSTREAM_LOCAL_ADDRESS%"
                    downstream_direct_remote_address: "%DOWNSTREAM_DIRECT_REMOTE_ADDRESS%"
                    domain: "%REQ(HOST?:AUTHORITY)%"
                    upstream_host: "%UPSTREAM_HOST%"
                    upstream_local_address: "%UPSTREAM_LOCAL_ADDRESS%"
                    upstream_service_time: "%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%"
                    route_name: "%ROUTE_NAME%"
                    x_forwarded_for: "%REQ(X-FORWARDED-FOR)%"
                    type: JSON
                sinks:
                    - type: File
                    file:
                        path: /access_logs/access.log
                type: Route


please note that the important fields in the above config are: 

1. `reporter` - statically set, must be set to either `gateway`, `gateway-edge`, `gateway-proxied`, and `destination`. `gateway` and `gateway-edge` are handled the same.
    - `gateway`, `gateway-edge` - this is the reporter field value to use if your gateway is directly connected to your downstream clients (i.e. edge proxy). if in doubt, use this configuration.
    - `gateway-proxied` - this is the reporter field value to use if your gateway is behind one or more other proxies. in this mode, remote client addresses are filled from x-forwarded-for[1] field. this requires a proper `xff_num_trusted_hops` configuration which is not covered here. Please see envoy docs for more details[2]
1. `downstream_direct_remote_address: "%DOWNSTREAM_DIRECT_REMOTE_ADDRESS%"` - gateway, gateway-edge
1. `x_forwarded_for: "%REQ(X-FORWARDED-FOR)%"` - gateway-proxied. if invalid or unavailable, falls back to gateway, gateway-proxied reporting mode
1. `upstream_host: "%UPSTREAM_HOST%"` - gateway, gateway-edge, gateway-proxied


References:
1: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-for
2: https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto