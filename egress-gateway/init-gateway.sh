#!/bin/sh

# This script initializes settings necessary for EGW pods to run.
# The reason for having a separate init script is that, this script
# runs as part of an init container, which runs in privileged mode.
# This allows us to run the EGW pods as non-privileged.

configure_iptables()
{
  MSS_CLAMP_VALUE=$1

  # IPTABLES_BACKEND may be set to "legacy" or "nft".  If not defined
  # try to auto-detect nft or legacy.
  if [ "$IPTABLES_BACKEND" ]
  then
      echo "IPTABLES_BACKEND set to $IPTABLES_BACKEND"
      iptables-${IPTABLES_BACKEND} -t nat -A POSTROUTING -j MASQUERADE
      IPTABLES_BINARY="iptables-${IPTABLES_BACKEND}"
  elif iptables-nft -t nat -A POSTROUTING -j MASQUERADE
  then
      IPTABLES_BINARY="iptables-nft"
      echo "Successfully configured iptables with iptables-nft."
  elif iptables-legacy -t nat -A POSTROUTING -j MASQUERADE
  then
      IPTABLES_BINARY="iptables-legacy"
      echo "Successfully configured iptables with iptables-legacy."
  else
      echo "Failed to configure iptables (tried both nft and legacy)."
      exit 1
  fi

  args="FORWARD -t mangle -o eth0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $MSS_CLAMP_VALUE"
  $IPTABLES_BINARY -C $args 2>/dev/null || $IPTABLES_BINARY -A $args
}

configure_nftables()
{
  MSS_CLAMP_VALUE=$1

  nft -f - <<EOF
create table egw
add chain egw mangle-FORWARD { type filter hook forward priority mangle; }
add rule ip egw mangle-FORWARD oifname "eth0" tcp flags & (syn|rst) == syn counter tcp option maxseg size set ${MSS_CLAMP_VALUE}
EOF
}

set -e

# Capture the usual signals and exit from the script
trap 'echo "INT received, simply exiting..."; exit 0' INT
trap 'echo "TERM received, simply exiting..."; exit 0' TERM
trap 'echo "HUP received, simply exiting..."; exit 0' HUP

if [ -z "$EGRESS_POD_IPS" ]
then
    echo "EGRESS_POD_IPS not defined."
    exit 1
fi

if [ -z "$EGRESS_VXLAN_VNI" ]
then
    echo "EGRESS_VXLAN_VNI not defined."
    exit 1
fi

if [ -z "$EGRESS_VXLAN_PORT" ]
then
    echo "EGRESS_VXLAN_PORT not defined."
    exit 1
fi

# EGRESS_POD_IPS contains the list of all addresses assigned to this egress gateway separated by comma.
# As an example, the value could be either 192.168.0.1 or 2001::1111:1,192.168.0.1. The value should not
# contain two IPv4, like 192.168.0.1,10.10.10.10, but if that happens (for whatever reason),
# we should always use the first IPv4 address.
IPV4=$(echo "$EGRESS_POD_IPS" | awk '{split($0,a,","); print a[1]}' | awk -F. 'NF == 4')
if [ -z "$IPV4" ]
then
    IPV4=$(echo "$EGRESS_POD_IPS" | awk '{split($0,a,","); print a[2]}' | awk -F. 'NF == 4')
fi
echo "EGRESS_POD_IPS: $EGRESS_POD_IPS - Detected IPv4 address to use: $IPV4"

MAC=`echo $IPV4 | awk -F. '{printf "a2:2a:%02x:%02x:%02x:%02x", $1, $2, $3, $4}'`

echo Egress VXLAN VNI: $EGRESS_VXLAN_VNI  VXLAN PORT: $EGRESS_VXLAN_PORT VXLAN MAC: $MAC

echo Configure iptable rules

echo Configure vxlan tunnel device
ip link add vxlan0 type vxlan id $EGRESS_VXLAN_VNI dstport $EGRESS_VXLAN_PORT dev eth0 || printf " (and that's fine)"
ip link set vxlan0 address $MAC
ip link set vxlan0 up


DATAPLANE=${DATAPLANE:-iptables}
echo "Dataplane is ${DATAPLANE}"

echo "Adding iptables MSS clamping rules on interface eth0"

# Detect vxlan0 MTU
VXLAN_MTU=`awk '{print $1}' /sys/class/net/vxlan0/mtu`

# Calculate MSS_CLAMP_VALUE=VXLAN_MTU - 40 (IPv4 header len + TCP header len)
MSS_CLAMP_VALUE="$(($VXLAN_MTU - 40))"
echo "Detected vxlan0 MTU=$VXLAN_MTU. Clamping MSS value to $MSS_CLAMP_VALUE"
if [ "$DATAPLANE" = "nftables" ]
then
  configure_nftables $MSS_CLAMP_VALUE
else
  configure_iptables $MSS_CLAMP_VALUE
fi

echo Configure network settings
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/vxlan0/rp_filter
