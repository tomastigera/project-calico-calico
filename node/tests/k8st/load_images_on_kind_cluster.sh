#!/bin/bash

function load_image() {
    local node=$1
    docker cp ./operator.tar ${node}:/operator.tar
    docker cp ./calico-node.tar ${node}:/calico-node.tar
    docker cp ./calico-typha.tar ${node}:/calico-typha.tar
    docker cp ./calico-apiserver.tar ${node}:/calico-apiserver.tar
    docker cp ./calicoctl.tar ${node}:/calicoctl.tar
    docker cp ./calico-cni.tar ${node}:/calico-cni.tar
    docker cp ./csi.tar ${node}:/csi.tar
    docker cp ./node-driver-registrar.tar ${node}:/node-driver-registrar.tar
    docker cp ./pod2daemon.tar ${node}:/pod2daemon.tar
    docker cp ./kube-controllers.tar ${node}:/kube-controllers.tar

    docker exec -t ${node} ctr -n=k8s.io images import /operator.tar
    docker exec -t ${node} ctr -n=k8s.io images import /calico-node.tar
    docker exec -t ${node} ctr -n=k8s.io images import /calico-typha.tar
    docker exec -t ${node} ctr -n=k8s.io images import /calico-apiserver.tar
    docker exec -t ${node} ctr -n=k8s.io images import /calicoctl.tar
    docker exec -t ${node} ctr -n=k8s.io images import /calico-cni.tar
    docker exec -t ${node} ctr -n=k8s.io images import /csi.tar
    docker exec -t ${node} ctr -n=k8s.io images import /node-driver-registrar.tar
    docker exec -t ${node} ctr -n=k8s.io images import /pod2daemon.tar
    docker exec -t ${node} ctr -n=k8s.io images import /kube-controllers.tar

    docker exec -t ${node} rm /calico-node.tar /calico-typha.tar /calicoctl.tar /calico-cni.tar /pod2daemon.tar /csi.tar /node-driver-registrar.tar /kube-controllers.tar /calico-apiserver.tar /operator.tar

    ## Enterprise images
    docker cp ./egress-gateway.tar ${node}:/egress-gateway.tar
    docker cp ./calico-queryserver.tar ${node}:/calico-queryserver.tar
    docker cp ./prometheus-operator.tar ${node}:/prometheus-operator.tar
    docker cp ./prometheus.tar ${node}:/prometheus.tar
    docker cp ./prometheus-service.tar ${node}:/prometheus-service.tar
    docker cp ./alertmanager.tar ${node}:/alertmanager.tar
    docker cp ./config-reloader.tar ${node}:/config-reloader.tar
    docker cp ./fluentd.tar ${node}:/fluentd.tar
    docker cp ./policy-rec.tar ${node}:/policy-rec.tar
    docker cp ./eck.tar ${node}:/eck.tar
    docker cp ./manager.tar  ${node}:/manager.tar
    docker cp ./voltron.tar ${node}:/voltron.tar
    docker cp ./ui-apis.tar ${node}:/ui-apis.tar
    docker cp ./kibana.tar ${node}:/kibana.tar
    docker cp ./elastic.tar ${node}:/elastic.tar
    docker cp ./es-gw.tar ${node}:/es-gw.tar
    docker cp ./linseed.tar ${node}:/linseed.tar
    docker cp ./idc.tar ${node}:/idc.tar
    docker cp ./webhooks-processor.tar ${node}:/webhooks-processor.tar
    docker cp ./dashboards-installer.tar ${node}:/dashboards-installer.tar
    docker cp ./es-metrics.tar ${node}:/es-metrics.tar

    docker exec -t ${node} ctr -n=k8s.io images import /egress-gateway.tar
    docker exec -t ${node} ctr -n=k8s.io images import /calico-queryserver.tar
    docker exec -t ${node} ctr -n=k8s.io images import /prometheus-operator.tar
    docker exec -t ${node} ctr -n=k8s.io images import /prometheus.tar
    docker exec -t ${node} ctr -n=k8s.io images import /prometheus-service.tar
    docker exec -t ${node} ctr -n=k8s.io images import /alertmanager.tar
    docker exec -t ${node} ctr -n=k8s.io images import /config-reloader.tar
    docker exec -t ${node} ctr -n=k8s.io images import /fluentd.tar
    docker exec -t ${node} ctr -n=k8s.io images import /policy-rec.tar
    docker exec -t ${node} ctr -n=k8s.io images import /eck.tar
    docker exec -t ${node} ctr -n=k8s.io images import /manager.tar
    docker exec -t ${node} ctr -n=k8s.io images import /voltron.tar
    docker exec -t ${node} ctr -n=k8s.io images import /ui-apis.tar
    docker exec -t ${node} ctr -n=k8s.io images import /kibana.tar
    docker exec -t ${node} ctr -n=k8s.io images import /elastic.tar
    docker exec -t ${node} ctr -n=k8s.io images import /es-gw.tar
    docker exec -t ${node} ctr -n=k8s.io images import /linseed.tar
    docker exec -t ${node} ctr -n=k8s.io images import /idc.tar
    docker exec -t ${node} ctr -n=k8s.io images import /webhooks-processor.tar
    docker exec -t ${node} ctr -n=k8s.io images import /dashboards-installer.tar
    docker exec -t ${node} ctr -n=k8s.io images import /es-metrics.tar

    docker exec -t ${node} rm /egress-gateway.tar /calico-queryserver.tar /prometheus-operator.tar /prometheus.tar /prometheus-service.tar /alertmanager.tar /config-reloader.tar
    docker exec -t ${node} rm /fluentd.tar /policy-rec.tar /eck.tar /voltron.tar /ui-apis.tar /kibana.tar elastic.tar es-gw.tar linseed.tar idc.tar webhooks-processor.tar
    docker exec -t ${node} rm /dashboards-installer.tar /es-metrics.tar /manager.tar
}

load_image kind-control-plane
load_image kind-worker
load_image kind-worker2
load_image kind-worker3
