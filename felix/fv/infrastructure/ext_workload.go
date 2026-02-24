package infrastructure

import (
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/utils"
)

// StartExternalWorkloads creates and starts a specified number of external workload containers.
// Each container runs a simple HTTP server on port 80 and remains active.
//
// Parameters:
//   - workloadBaseName: This parameter serves as the core part of the actual container name, with additional metadata appended for context
//   - workloadNumber: The total number of workload containers to create.
//
// Returns:
//   - A slice of pointers to the created containers (*containers.Container).
//     The slice length will match the workloadNumber parameter.
//
// Example:
//
//	workloads := StartExternalWorkloads("dns-external-workload", 2)
//	// This will create and start 2 containers with names prefixed by "dns-external-workload".
//
// Panics:
//   - If the number of created workloads does not match the requested workloadNumber.
func StartExternalWorkloads(infra CleanupProvider, workloadBaseName string, workloadNumber int) []*containers.Container {
	workloads := make([]*containers.Container, workloadNumber)

	for i := range workloadNumber {
		workloads[i] = containers.Run(
			workloadBaseName,
			containers.RunOpts{
				AutoRemove: true,
			},
			utils.Config.BusyboxImage,
			"/bin/sh", "-c", "httpd -f -p 80 & tail -f /dev/null", // Start HTTP server and keep container running
		)
		infra.AddCleanup(workloads[i].Stop)
	}

	return workloads
}
