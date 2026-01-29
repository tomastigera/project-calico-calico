# Common definitions for the tests that are run on cloud
# VMs rather than Semaphore VMs
set -e

export batches=(k8s-test enet egw-none egw-ipip egw-vxlan)

# These batches are broken due to upstream changes to kind/k8s, fixing them
# is tracked by CORE-11685.
disabled_batches=(dual-tor dual-tor-legacy)

run_batch() {
  local remote_exec="$1"
  local batch="$2"
  local vm_name="$3"
  local log_file="$4"

  case $batch in
    k8s-test)
      cmd=("make" "--directory=${CALICO_DIR_NAME}/node" "k8s-test")
      ;;
    dual-tor)
      cmd=("make" "--directory=${CALICO_DIR_NAME}/node" "dual-tor-test")
      ;;
    dual-tor-legacy)
      cmd=("make" "--directory=${CALICO_DIR_NAME}/node" "dual-tor-test-legacy")
      ;;
    enet)
      cmd=("make" "--directory=${CALICO_DIR_NAME}/node" "external-network-test")
      ;;
    egw-none)
      cmd=('K8ST_TO_RUN="-A egress_ip_no_overlay"' 'K8ST_REPORT_FILENAME=node-k8s-egress-ip-no-overlay.xml' 'make' "--directory=${CALICO_DIR_NAME}/node" "k8s-test")
      ;;
    egw-ipip)
      cmd=('K8ST_TO_RUN="-A egress_ip_ipip"' "K8ST_REPORT_FILENAME=node-k8s-egress-ip-ipip.xml" "make" "--directory=${CALICO_DIR_NAME}/node" "k8s-test")
      ;;
    egw-vxlan)
      cmd=('K8ST_TO_RUN="-A egress_ip_vxlan"' "K8ST_REPORT_FILENAME=node-k8s-egress-ip-vxlan.xml" "make" "--directory=${CALICO_DIR_NAME}/node" "k8s-test")
      ;;
    *)
      echo "invalid batch name" && exit 1
      ;;
  esac

  VM_NAME="$vm_name" ${remote_exec} SEMAPHORE_GIT_BRANCH="${SEMAPHORE_GIT_BRANCH}" "${cmd[@]}" >& "$log_file"
}
