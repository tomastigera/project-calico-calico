# Common definitions for the tests that are run on cloud
# VMs rather than Semaphore VMs

batches=(k8s-test enet egw-none egw-ipip egw-vxlan)

# These batches are broken due to upstream changes to kind/k8s, fixing them
# is tracked by CORE-11685.
disabled_batches=(dual-tor dual-tor-legacy)