# Test data generation and initialization

This subdirectory within the compliance repo establishes a framework for generating data that can be used for testing this compliance reporting feature.
The `demo.sh` script executes a sample system deployment workflow where all the compliance reporting relevant resources are created, modified, and deleted.
This script uses the `kubectl` to modify some resource and then sleeps for some constant amount of time so that the timeslice between each state change can be reasonably captured.
You will need to ensure that your TSEE installation has the LMA stack installed as well as [audit logs enabled](https://docs.tigera.io/v2.3/usage/logs/elastic/ee-audit).
Run the following `kubectl` commands to set up port-forward to the appropriate backend services:

- `kubectl port-forward -nkube-system svc/tigera-manager 8080:8080                           # for manager ui`
- `kubectl port-forward -ncalico-monitoring svc/elasticsearch-tigera-elasticsearch 9200:9200 # for elasticsearch`
- `kubectl port-forward -ncalico-monitoring svc/tigera-kibana 5601:5601                      # for kibana`
- `kubectl port-forward -nkube-system svc/calico-etcd 6666:6666                              # for etcd (only in etcd mode)`

## Snapshotter

1. Execute `testdata/demo.sh`
2. Once all the resources are created, execute the `snapshotter/pull_resources.sh` script to dump all the relevant resources into json files.
3. Now these generated json files can be used for the snapshotter component's functional verification tests
   - Execute `cmd/testdata-exporter snapshotter` to initialize a kubernetes instance with the data referenced within the tests.

## Replayer

1. Execute the `cmd/snapshotter` binary to do an initial snapshot.
2. Execute `demo.sh`
   - Execute the snapshotter every minute to capture different points in time
3. When the script completes, execute the `replayer/pull.sh` script to dump all the list and event data from elastic into json files.
4. Now these generated json files can be used for the replayer component's functional verification tests
   - Execute `cmd/testdata-exporter replayer` to initialize an elasticsearch instance with the data referenced within the tests.
