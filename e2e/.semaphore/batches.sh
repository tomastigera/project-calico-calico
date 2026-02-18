# Common definitions for the e2e conformance tests that run on cloud
# VMs rather than Semaphore VMs.
set -e

export batches=(conformance)

run_batch() {
  local remote_exec="$1"
  local batch="$2"
  local vm_name="$3"
  local log_file="$4"

  case $batch in
    conformance)
      cmd=("make" "--directory=${CALICO_DIR_NAME}" "e2e-test")
      ;;
    *)
      echo "invalid batch name" && exit 1
      ;;
  esac

  VM_NAME="$vm_name" ${remote_exec} SEMAPHORE_GIT_BRANCH="${SEMAPHORE_GIT_BRANCH}" "${cmd[@]}" >& "$log_file"
}
