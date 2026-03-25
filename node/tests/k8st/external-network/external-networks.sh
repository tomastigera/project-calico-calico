#!/bin/bash -e

# test directory.
TEST_DIR=./tests/k8st

# kubectl binary.
: ${kubectl:=../hack/test/kind/kubectl}

# Normally, cleanup any leftover state, then setup, then test.
: ${STEPS:=cleanup setup}

nodeIP=$(${kubectl} get node kind-worker -o jsonpath='{.status.addresses[0].address}' || echo "unknown")
echo kind-worker node ip $nodeIP

function add_calico_resources() {
  # Setup BGPPeers for each router.
    ${kubectl} apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: peer-a1
spec:
  nodeSelector: "egress == 'true'"
  peerIP: 172.31.11.1
  asNumber: 64512
  sourceAddress: None
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: peer-a1-v6
spec:
  nodeSelector: "egress == 'true'"
  peerIP: fd00:0:1234:1111::1
  asNumber: 64512
  sourceAddress: None
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: peer-b1
spec:
  nodeSelector: "egress == 'true'"
  peerIP: 172.31.21.1
  asNumber: 64512
  sourceAddress: None
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: peer-b1-v6
spec:
  nodeSelector: "egress == 'true'"
  peerIP: fd00:0:1234:2222::1
  asNumber: 64512
  sourceAddress: None
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: peer-b2
spec:
  nodeSelector: "egress == 'true'"
  peerIP: 172.31.21.3
  asNumber: 64512
  sourceAddress: None
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: peer-b2-v6
spec:
  nodeSelector: "egress == 'true'"
  peerIP: fd00:0:1234:2222::3
  asNumber: 64512
  sourceAddress: None
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: peer-c1
spec:
  nodeSelector: "egress == 'true'"
  peerIP: 172.31.31.1
  asNumber: 64512
  sourceAddress: None
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: peer-c1-v6
spec:
  nodeSelector: "egress == 'true'"
  peerIP: fd00:0:1234:3333::1
  asNumber: 64512
  sourceAddress: None
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: peer-d1
spec:
  nodeSelector: "egress == 'true'"
  peerIP: 172.31.51.1
  asNumber: 64512
  sourceAddress: None
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: peer-d1-v6
spec:
  nodeSelector: "egress == 'true'"
  peerIP: fd00:0:1234:5555::1
  asNumber: 64512
  sourceAddress: None
EOF

    # Label and annotate nodes.
    ${kubectl} label node kind-worker egress=true --overwrite

    # Set IP autodetection to use eth0 so the correct node IP is used on
    # the node-node mesh.  Configure via Installation CR so the operator
    # reconciles the change into the calico-node DaemonSet.
    ${kubectl} patch installation default --type=json -p '[
      {"op":"replace","path":"/spec/calicoNetwork/nodeAddressAutodetectionV4","value":{"interface":"eth0"}},
      {"op":"replace","path":"/spec/calicoNetwork/nodeAddressAutodetectionV6","value":{"interface":"eth0"}}
    ]'

    # Wait for the operator to update the DaemonSet template before checking
    # rollout status.  Without this, "rollout status" can return immediately
    # because the operator hasn't reconciled the change yet.
    echo "Waiting for operator to set IP_AUTODETECTION_METHOD on calico-node DaemonSet..."
    for i in $(seq 1 30); do
        val=$(${kubectl} get ds calico-node -n calico-system -o jsonpath='{.spec.template.spec.containers[?(@.name=="calico-node")].env[?(@.name=="IP_AUTODETECTION_METHOD")].value}' 2>/dev/null)
        if [ "$val" = "interface=eth0" ]; then
            echo "IP_AUTODETECTION_METHOD set after ${i}s"
            break
        fi
        if [ "$i" -eq 30 ]; then
            echo "ERROR: operator did not update calico-node DaemonSet within 30s"
            exit 1
        fi
        sleep 1
    done
    ${kubectl} rollout status daemonset/calico-node -n calico-system --timeout=5m
}

function do_setup {
    # Fix rp_filter setting.
    sudo sysctl -w net.ipv4.conf.all.rp_filter=1

    # Create docker networks for this topology:
    #
    #    +---------+            +---------+                       +---------+                                  +---------+
    #    | nginx-a |            | nginx-b |                       | nginx-c |                                  | nginx-d |
    #    +---------+            +---------+                       +---------+                                  +---------+
    #         | .1                | .1                                |.1                                          | .1
    #         |                   |                                   |                                            |
    #         | 172.31.91         | 172.31.91                         | 172.31.101                                 | 172.31.91
    #         | 'servernetA'      | 'servernetB'                      | 'servernetC'                               | 'servernetD'
    #         |                   |                                   |                                            |
    #         |                   |                                   |                             'enetD2'       |
    #         |.2                 |.2                                 |.2                           172.31.51      |.2
    #    +---------+         +---------+         +---------+      +---------+         +---------+ .4        .1 +---------+
    #    | bird-a1 |         | bird-b1 |---------| bird-b2 |      | bird-c1 |         | node-d1 |--------------| bird-d1 |
    #    +---------+         +---------+         +---------+      +---------+         +---------+              +---------+
    #         |.1                 |.1                 |.3             |.1                  |.1
    #         |                   |                   |               |                    |
    #         |                   |--------------------               |                    |
    #         | 172.31.11         | 172.31.21                         | 172.31.31          | 172.31.41
    #         |  'enetA'          |  'enetB'                          |  'enetC'           |  'enetD1'
    #         |                   |                                   |                    |
    #         |.4                 |.4                                 |.4                  |.4
    #  +---------------------------------------------------------------------------------------------------+
    #  |                                                                                                   |
    #  +---------------------------------------------------------------------------------------------------+
    #                  kind-worker (node ip 172.24.0.x)

    # Create external networks
    docker network create --subnet=172.31.11.0/24 --gateway 172.31.11.2 --ipv6 --subnet=fd00:0:1234:1111::/64 --gateway fd00:0:1234:1111::2 enetA
    docker network create --subnet=172.31.21.0/24 --gateway 172.31.21.2 --ipv6 --subnet=fd00:0:1234:2222::/64 --gateway fd00:0:1234:2222::2 enetB
    docker network create --subnet=172.31.31.0/24 --gateway 172.31.31.2 --ipv6 --subnet=fd00:0:1234:3333::/64 --gateway fd00:0:1234:3333::2 enetC
    docker network create --subnet=172.31.41.0/24 --gateway 172.31.41.2 --ipv6 --subnet=fd00:0:1234:4444::/64 --gateway fd00:0:1234:4444::2 enetD1
    docker network create --subnet=172.31.51.0/24 --gateway 172.31.51.2 --ipv6 --subnet=fd00:0:1234:5555::/64 --gateway fd00:0:1234:5555::2 enetD2

    # Create routers on external networks
    docker run -d --privileged --net=enetA --ip=172.31.11.1 --ip6=fd00:0:1234:1111::1 --name=bird-a1 ${ROUTER_IMAGE}
    docker run -d --privileged --net=enetB --ip=172.31.21.1 --ip6=fd00:0:1234:2222::1 --name=bird-b1 ${ROUTER_IMAGE}
    docker run -d --privileged --net=enetB --ip=172.31.21.3 --ip6=fd00:0:1234:2222::3 --name=bird-b2 ${ROUTER_IMAGE}
    docker run -d --privileged --net=enetC --ip=172.31.31.1 --ip6=fd00:0:1234:3333::1 --name=bird-c1 ${ROUTER_IMAGE}
    docker run -d --privileged --net=enetD1 --ip=172.31.41.1 --ip6=fd00:0:1234:4444::1 --name=node-d1 ${ROUTER_IMAGE}
    docker run -d --privileged --net=enetD2 --ip=172.31.51.1 --ip6=fd00:0:1234:5555::1 --name=bird-d1 ${ROUTER_IMAGE}

    # Connect kind-worker to networks
    docker network connect --ip=172.31.11.4 --ip6=fd00:0:1234:1111::4 enetA kind-worker
    docker network connect --ip=172.31.21.4 --ip6=fd00:0:1234:2222::4 enetB kind-worker
    docker network connect --ip=172.31.31.4 --ip6=fd00:0:1234:3333::4 enetC kind-worker
    docker network connect --ip=172.31.41.4 --ip6=fd00:0:1234:4444::4 enetD1 kind-worker

    # Connect node-d1 to bird-d1 via the enetD2 network
    docker network connect --ip=172.31.51.4 --ip6=fd00:0:1234:5555::4 enetD2 node-d1

    # Add bootstrap routes to enable kind-worker and bird-d1 to reach each other
    docker exec kind-worker ip route add 172.31.51.0/24 via 172.31.41.1
    docker exec kind-worker ip -6 route add fd00:0:1234:5555::/64 via fd00:0:1234:4444::1
    docker exec bird-d1 ip route add 172.31.41.0/24 via 172.31.51.4
    docker exec bird-d1 ip -6 route add fd00:0:1234:4444::/64 via fd00:0:1234:5555::4

    # Add bootstrap routes to node-d1 to enable it to reach the nginx-d server
    docker exec node-d1 ip route add 172.31.91.0/24 via 172.31.51.1
    docker exec node-d1 ip -6 route add fd00:0:1234:9999::/64 via fd00:0:1234:5555::1

    # Common BGP peer templates used in router configuration
    ipv4_template="template bgp nodes {
  description \"Connection to BGP peer\";
  local as 64512;
  direct;
  gateway recursive;
  import all;
  export filter {
      if net = 0.0.0.0/0 then reject;
      accept;
  };
  add paths on;
  graceful restart;
  graceful restart time 0;
  long lived graceful restart yes;
  connect delay time 2;
  connect retry time 5;
  error wait time 5,30;
  next hop self;
  bfd graceful;
}"
    ipv6_template="template bgp nodes {
  description \"Connection to BGP peer\";
  local as 64512;
  direct;
  gateway recursive;
  import all;
  export filter {
      if net = ::/0 then reject;
      accept;
  };
  add paths on;
  graceful restart;
  graceful restart time 0;
  long lived graceful restart yes;
  connect delay time 2;
  connect retry time 5;
  error wait time 5,30;
  next hop self;
  bfd graceful;
}"

    # Configure Router end of cluster node peerings.
    # Note default route will be filtered out for each router.
    cat <<EOF | docker exec -i bird-a1 sh -c "cat > /etc/bird/nodes-enetA.conf"
$ipv4_template
protocol bgp node1 from nodes {
  neighbor 172.31.11.4 as 64512;
}
EOF
    docker exec bird-a1 birdcl configure

    cat <<EOF | docker exec -i bird-a1 sh -c "cat > /etc/bird6/nodes-enetA-v6.conf"
$ipv6_template
protocol bgp node1 from nodes {
  neighbor fd00:0:1234:1111::4 as 64512;
}
EOF
    docker exec bird-a1 birdcl6 configure

    cat <<EOF | docker exec -i bird-b1 sh -c "cat > /etc/bird/nodes-enetB.conf"
$ipv4_template
protocol bgp node1 from nodes {
  neighbor 172.31.21.4 as 64512;
}
EOF
    docker exec bird-b1 birdcl configure

    cat <<EOF | docker exec -i bird-b1 sh -c "cat > /etc/bird6/nodes-enetB-v6.conf"
$ipv6_template
protocol bgp node1 from nodes {
  neighbor fd00:0:1234:2222::4 as 64512;
}
EOF
    docker exec bird-b1 birdcl6 configure

     cat <<EOF | docker exec -i bird-b2 sh -c "cat > /etc/bird/nodes-enetB.conf"
$ipv4_template
protocol bgp node1 from nodes {
  neighbor 172.31.21.4 as 64512;
}
EOF
    docker exec bird-b2 birdcl configure

    cat <<EOF | docker exec -i bird-b2 sh -c "cat > /etc/bird6/nodes-enetB-v6.conf"
$ipv6_template
protocol bgp node1 from nodes {
  neighbor fd00:0:1234:2222::4 as 64512;
}
EOF
    docker exec bird-b2 birdcl6 configure

         cat <<EOF | docker exec -i bird-c1 sh -c "cat > /etc/bird/nodes-enetC.conf"
$ipv4_template
protocol bgp node1 from nodes {
  neighbor 172.31.31.4 as 64512;
}
EOF
    docker exec bird-c1 birdcl configure

    cat <<EOF | docker exec -i bird-c1 sh -c "cat > /etc/bird6/nodes-enetC-v6.conf"
$ipv6_template
protocol bgp node1 from nodes {
  neighbor fd00:0:1234:3333::4 as 64512;
}
EOF
    docker exec bird-c1 birdcl6 configure

    cat <<EOF | docker exec -i bird-d1 sh -c "cat > /etc/bird/nodes-enetD.conf"
log "/var/log/bird.log" all;
template bgp nodes {
  description "Connection to BGP peer";
  local as 64512;
  multihop;
  gateway recursive;
  import all;
  export filter {
      #if net ~ 172.31.41.0/24 then reject;
      if net ~ 172.31.51.0/24 then reject;
      if net = 0.0.0.0/0 then reject;
      accept;
  };
  add paths on;
  graceful restart;
  graceful restart time 0;
  long lived graceful restart yes;
  connect delay time 2;
  connect retry time 5;
  error wait time 5,30;
}
protocol bgp node1 from nodes {
  neighbor 172.31.41.4 as 64512;
}
EOF
    docker exec bird-d1 birdcl configure

    cat <<EOF | docker exec -i bird-d1 sh -c "cat > /etc/bird6/nodes-enetD-v6.conf"
log "/var/log/bird.log" all;
template bgp nodes {
  description "Connection to BGP peer";
  local as 64512;
  multihop;
  gateway recursive;
  import all;
  export filter {
      if net ~ fd00:0:1234:4444::/64 then reject;
      if net ~ fd00:0:1234:5555::/64 then reject;
      if net = ::/0 then reject;
      accept;
  };
  add paths on;
  graceful restart;
  graceful restart time 0;
  long lived graceful restart yes;
  connect delay time 2;
  connect retry time 5;
  error wait time 5,30;
}
protocol bgp node1 from nodes {
  neighbor fd00:0:1234:4444::4 as 64512;
}
EOF
    docker exec bird-d1 birdcl6 configure

    # Create BGPConfiguration, BGPPeers etc.
    add_calico_resources

    # Add some routes for each routers
    docker exec bird-a1 ip route add blackhole 10.233.11.8
    docker exec bird-b1 ip route add blackhole 10.233.21.8
    docker exec bird-b2 ip route add blackhole 10.233.21.9
    docker exec bird-c1 ip route add blackhole 10.233.31.8
    docker exec bird-d1 ip route add blackhole 10.233.41.8

    # Wait for dockerd (docker-in-docker) to start in the containers
    (
    set +e # do manual error checking to be able to output more details
    for container in bird-a1 bird-b1 bird-b2 bird-c1 bird-d1; do
        timeout 60s sh -c "echo Wait for docker-in-docker to be ready on $container:; docker exec $container docker ps; ret=\$?; while [ \$ret -ne 0 ]; do docker exec $container docker ps; ret=\$?; sleep 5s; done;"; if [ $? -eq 0 ]; then echo dockerd started on $container; else echo dockerd failed to start on $container after a 60s timeout; exit 1; fi;
    done
    )

    # Add nginx docker containers to each external network (as docker-in-docker on the external bird containers)
    docker exec bird-a1 docker network create --subnet 172.31.91.0/24 --gateway 172.31.91.2 servernetA --ipv6 --subnet=fd00:0:1234:9999::/64 --gateway fd00:0:1234:9999::2
    docker exec bird-a1 mkdir -p /tmp/nginx
    cat <<EOF | docker exec -i bird-a1 sh -c "cat > /tmp/nginx/index.html"
server A
EOF
    docker exec bird-a1 chmod -R 0755 /tmp/nginx/
    docker exec bird-a1 docker run --network servernetA --ip 172.31.91.1 --ip6 fd00:0:1234:9999::1 -d --restart always --name nginx-a -v /tmp/nginx/:/usr/share/nginx/html:ro nginx

    docker exec bird-b1 docker network create --subnet 172.31.91.0/24 --gateway 172.31.91.2 servernetB --ipv6 --subnet=fd00:0:1234:9999::/64 --gateway fd00:0:1234:9999::2
    docker exec bird-b1 mkdir -p /tmp/nginx
    cat <<EOF | docker exec -i bird-b1 sh -c "cat > /tmp/nginx/index.html"
server B
EOF
    docker exec bird-b1 chmod -R 0755 /tmp/nginx/
    docker exec bird-b1 docker run --network servernetB --ip 172.31.91.1 --ip6 fd00:0:1234:9999::1 -d --restart always --name nginx-b -v /tmp/nginx/:/usr/share/nginx/html:ro nginx

    docker exec bird-c1 docker network create --subnet 172.31.101.0/24 --gateway 172.31.101.2 servernetC --ipv6 --subnet=fd00:0:1234:1010::/64 --gateway fd00:0:1234:1010::2
    docker exec bird-c1 mkdir -p /tmp/nginx
    cat <<EOF | docker exec -i bird-c1 sh -c "cat > /tmp/nginx/index.html"
server C
EOF
    docker exec bird-c1 chmod -R 0755 /tmp/nginx/
    docker exec bird-c1 docker run --network servernetC --ip 172.31.101.1 --ip6 fd00:0:1234:1010::1 -d --restart always --name nginx-c -v /tmp/nginx/:/usr/share/nginx/html:ro nginx

    docker exec bird-d1 docker network create --subnet 172.31.91.0/24 --gateway 172.31.91.2 servernetD --ipv6 --subnet=fd00:0:1234:9999::/64 --gateway fd00:0:1234:9999::2
    docker exec bird-d1 mkdir -p /tmp/nginx
    cat <<EOF | docker exec -i bird-d1 sh -c "cat > /tmp/nginx/index.html"
server D
EOF
    docker exec bird-d1 chmod -R 0755 /tmp/nginx/
    docker exec bird-d1 docker run --network servernetD --ip 172.31.91.1 --ip6 fd00:0:1234:9999::1 -d --restart always --name nginx-d -v /tmp/nginx/:/usr/share/nginx/html:ro nginx

    # Set the RPF to strict on the interfaces connecting to the external networks.
    docker exec kind-worker sysctl -w net.ipv4.conf.eth1.rp_filter=1
    docker exec kind-worker sysctl -w net.ipv4.conf.eth2.rp_filter=1
    docker exec kind-worker sysctl -w net.ipv4.conf.eth3.rp_filter=1
    docker exec kind-worker sysctl -w net.ipv4.conf.eth4.rp_filter=1

    docker exec kind-worker sysctl -w net.ipv4.conf.eth1.src_valid_mark=1
    docker exec kind-worker sysctl -w net.ipv4.conf.eth2.src_valid_mark=1
    docker exec kind-worker sysctl -w net.ipv4.conf.eth3.src_valid_mark=1
    docker exec kind-worker sysctl -w net.ipv4.conf.eth4.src_valid_mark=1
}

function do_cleanup {
    # Clean up calico resources and network topology created by do_setup/do_infra_setup.
    ${kubectl} delete bgppeer peer-a1 peer-a1-v6 peer-b1 peer-b1-v6 peer-b2 peer-b2-v6 peer-c1 peer-c1-v6 peer-d1 peer-d1-v6 || true

    # Revert node label and annotations
    ${kubectl} label node kind-worker egress- --overwrite || true
    ${kubectl} label node kind-worker3 egress- --overwrite || true

    # Revert IP autodetection to the default (first-found) via the Installation CR.
    ${kubectl} patch installation default --type=json -p '[{"op":"remove","path":"/spec/calicoNetwork/nodeAddressAutodetectionV4"},{"op":"remove","path":"/spec/calicoNetwork/nodeAddressAutodetectionV6"}]' || true
    ${kubectl} rollout status daemonset/calico-node -n calico-system --timeout=5m || true

    # Remove bootstrap routes from kind-worker
    docker exec kind-worker ip route del 172.31.51.0/24 via 172.31.41.1 || true
    docker exec kind-worker ip -6 route del fd00:0:1234:5555::/64 via fd00:0:1234:4444::1 || true

    docker rm -f bird-a1 bird-b1 bird-b2 bird-c1 node-d1 bird-d1 || true

    docker network disconnect enetA kind-worker || true
    docker network disconnect enetB kind-worker || true
    docker network disconnect enetC kind-worker || true
    docker network disconnect enetD1 kind-worker || true
    docker network disconnect enetC kind-worker3 || true
    docker network rm enetA enetB enetC enetD1 enetD2 || true

    docker network ls
    docker ps -a
}

# Execute requested steps.
for step in ${STEPS}; do
    eval do_${step}
done
