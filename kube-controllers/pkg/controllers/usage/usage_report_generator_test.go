package usage

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// These UTs validate that the reportGenerator generates the correct basic reports in response to many different permutations
// of input events. The wiring of the reportGenerator source and sink is tested in the FVs.
var _ = Describe("reportGenerator", func() {
	var reporter reportGenerator

	BeforeEach(func() {
		reporter = newReportGenerator(
			events{
				nodeUpdates:         make(chan event[*v1.Node]),
				podUpdates:          make(chan event[*v1.Pod]),
				intervalComplete:    make(chan bool),
				initialSyncComplete: make(chan bool),
			},
			make(chan struct{}),
		)
		go reporter.startGeneratingReports()
	})
	AfterEach(func() {
		reporter.stopIssued <- struct{}{}
	})

	sequences := []testSequence{
		// The following tests are scenarios where the initial sync includes node and pod events.
		{
			desc: "a node set is synced and flushed",
			steps: []testStep{
				updateNodes([]event[*v1.Node]{
					addNode(node("node1", "4")),
					addNode(node("node2", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node1")),
					addPod(calicoNodePod("node2")),
				}),
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
			},
		},
		{
			desc: "a node set is synced and flushed, followed by the addition of a node and a flush",
			steps: []testStep{
				updateNodes([]event[*v1.Node]{
					addNode(node("node1", "4")),
					addNode(node("node2", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node1")),
					addPod(calicoNodePod("node2")),
				}),
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
				updateNodes([]event[*v1.Node]{
					addNode(node("node3", "6")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node3")),
				}),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 3, vCPU: 18}, complete: true}),
			},
		},
		{
			desc: "a node set is synced and flushed, followed by the removal of a node and a flush",
			steps: []testStep{
				updateNodes([]event[*v1.Node]{
					addNode(node("node1", "4")),
					addNode(node("node2", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node1")),
					addPod(calicoNodePod("node2")),
				}),
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
				updateNodes([]event[*v1.Node]{
					removeNode(node("node1", "4")),
				}),
				updatePods([]event[*v1.Pod]{
					removePod(calicoNodePod("node1")),
				}),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 1, vCPU: 8}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
			},
		},
		{
			desc: "a node set is synced and flushed, followed by the removal of all nodes and a flush",
			steps: []testStep{
				updateNodes([]event[*v1.Node]{
					addNode(node("node1", "4")),
					addNode(node("node2", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node1")),
					addPod(calicoNodePod("node2")),
				}),
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
				updateNodes([]event[*v1.Node]{
					removeNode(node("node1", "4")),
					removeNode(node("node2", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					removePod(calicoNodePod("node1")),
					removePod(calicoNodePod("node2")),
				}),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 0, vCPU: 0}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
			},
		},
		{
			desc: "a node set is synced and flushed, followed by the edit of a nodes (that changes capacity) and a flush",
			steps: []testStep{
				updateNodes([]event[*v1.Node]{
					addNode(node("node1", "4")),
					addNode(node("node2", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node1")),
					addPod(calicoNodePod("node2")),
				}),
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
				updateNodes([]event[*v1.Node]{
					updateNode(node("node1", "4"), node("node1", "6")),
				}),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 2, vCPU: 14}, complete: true}),
			},
		},
		{
			desc: "a node set is synced and flushed, followed by the edit of a node (that doesn't change capacity) and a flush",
			steps: []testStep{
				updateNodes([]event[*v1.Node]{
					addNode(node("node1", "4")),
					addNode(node("node2", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node1")),
					addPod(calicoNodePod("node2")),
				}),
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
				updateNodes([]event[*v1.Node]{
					updateNode(node("node1", "4"), node("node1", "4")),
				}),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
			},
		},
		{
			desc: "a node set is synced and flushed three times without any node changes",
			steps: []testStep{
				updateNodes([]event[*v1.Node]{
					addNode(node("node1", "4")),
					addNode(node("node2", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node1")),
					addPod(calicoNodePod("node2")),
				}),
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
			},
		},
		{
			desc: "a node set is synced and flushed, followed by a rapid jump in nodes and recovery",
			steps: []testStep{
				updateNodes([]event[*v1.Node]{
					addNode(node("node1", "4")),
					addNode(node("node2", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node1")),
					addPod(calicoNodePod("node2")),
				}),
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
				updateNodes([]event[*v1.Node]{
					addNode(node("node3", "8")),
					addNode(node("node4", "8")),
					addNode(node("node5", "8")),
					addNode(node("node6", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node3")),
					addPod(calicoNodePod("node4")),
					addPod(calicoNodePod("node5")),
					addPod(calicoNodePod("node6")),
				}),
				updateNodes([]event[*v1.Node]{
					removeNode(node("node3", "8")),
					removeNode(node("node4", "8")),
					removeNode(node("node5", "8")),
					removeNode(node("node6", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					removePod(calicoNodePod("node3")),
					removePod(calicoNodePod("node4")),
					removePod(calicoNodePod("node5")),
					removePod(calicoNodePod("node6")),
				}),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 6, vCPU: 44}, complete: true}),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
			},
		},
		{
			desc: "a node set is synced and flushed, followed by a rapid drop in nodes and recovery",
			steps: []testStep{
				updateNodes([]event[*v1.Node]{
					addNode(node("node1", "4")),
					addNode(node("node2", "8")),
					addNode(node("node3", "8")),
					addNode(node("node4", "8")),
					addNode(node("node5", "8")),
					addNode(node("node6", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node1")),
					addPod(calicoNodePod("node2")),
					addPod(calicoNodePod("node3")),
					addPod(calicoNodePod("node4")),
					addPod(calicoNodePod("node5")),
					addPod(calicoNodePod("node6")),
				}),
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 6, vCPU: 44}, maxCounts: counts{nodes: 6, vCPU: 44}, complete: true}),
				updateNodes([]event[*v1.Node]{
					removeNode(node("node3", "8")),
					removeNode(node("node4", "8")),
					removeNode(node("node5", "8")),
					removeNode(node("node6", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					removePod(calicoNodePod("node3")),
					removePod(calicoNodePod("node4")),
					removePod(calicoNodePod("node5")),
					removePod(calicoNodePod("node6")),
				}),
				updateNodes([]event[*v1.Node]{
					addNode(node("node3", "8")),
					addNode(node("node4", "8")),
					addNode(node("node5", "8")),
					addNode(node("node6", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node3")),
					addPod(calicoNodePod("node4")),
					addPod(calicoNodePod("node5")),
					addPod(calicoNodePod("node6")),
				}),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 6, vCPU: 44}, complete: true}),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 6, vCPU: 44}, maxCounts: counts{nodes: 6, vCPU: 44}, complete: true}),
			},
		},
		{
			desc: "a node set is synced and flushed with fractional cores",
			steps: []testStep{
				updateNodes([]event[*v1.Node]{
					addNode(node("node1", "4.20")),
					addNode(node("node2", "8.60")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node1")),
					addPod(calicoNodePod("node2")),
				}),
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 13}, maxCounts: counts{nodes: 2, vCPU: 13}, complete: true}),
			},
		},

		// The following tests are scenarios where the initial sync has _no_ node or pod events.
		{
			desc: "an empty node set is synced and flushed",
			steps: []testStep{
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 0, vCPU: 0}, maxCounts: counts{nodes: 0, vCPU: 0}, complete: true}),
			},
		},
		{
			desc: "an empty node set is synced and flushed, followed by the addition of nodes and a flush",
			steps: []testStep{
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 0, vCPU: 0}, maxCounts: counts{nodes: 0, vCPU: 0}, complete: true}),
				updateNodes([]event[*v1.Node]{
					addNode(node("node1", "4")),
					addNode(node("node2", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node1")),
					addPod(calicoNodePod("node2")),
				}),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 0, vCPU: 0}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
			},
		},
		{
			desc: "a empty node set is synced and flushed three times without any node changes",
			steps: []testStep{
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 0, vCPU: 0}, maxCounts: counts{nodes: 0, vCPU: 0}, complete: true}),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 0, vCPU: 0}, maxCounts: counts{nodes: 0, vCPU: 0}, complete: true}),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 0, vCPU: 0}, maxCounts: counts{nodes: 0, vCPU: 0}, complete: true}),
			},
		},
		{
			desc: "an empty node set is synced and flushed, followed by a rapid jump in nodes and recovery",
			steps: []testStep{
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 0, vCPU: 0}, maxCounts: counts{nodes: 0, vCPU: 0}, complete: true}),
				updateNodes([]event[*v1.Node]{
					addNode(node("node3", "8")),
					addNode(node("node4", "8")),
					addNode(node("node5", "8")),
					addNode(node("node6", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node3")),
					addPod(calicoNodePod("node4")),
					addPod(calicoNodePod("node5")),
					addPod(calicoNodePod("node6")),
				}),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 0, vCPU: 0}, maxCounts: counts{nodes: 4, vCPU: 32}, complete: true}),
				updateNodes([]event[*v1.Node]{
					removeNode(node("node3", "8")),
					removeNode(node("node4", "8")),
					removeNode(node("node5", "8")),
					removeNode(node("node6", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					removePod(calicoNodePod("node3")),
					removePod(calicoNodePod("node4")),
					removePod(calicoNodePod("node5")),
					removePod(calicoNodePod("node6")),
				}),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 0, vCPU: 0}, maxCounts: counts{nodes: 4, vCPU: 32}, complete: true}),
			},
		},

		// The following tests are scenarios where the first flush occurs before any sync.
		{
			desc: "flush occurs without a sync or node events",
			steps: []testStep{
				flushAndVerifyReport(basicLicenseUsageReport{complete: false}),
			},
		},
		{
			desc: "flush occurs three times without a sync or node events",
			steps: []testStep{
				flushAndVerifyReport(basicLicenseUsageReport{complete: false}),
				flushAndVerifyReport(basicLicenseUsageReport{complete: false}),
				flushAndVerifyReport(basicLicenseUsageReport{complete: false}),
			},
		},
		{
			desc: "flush occurs without a sync or node events, then an initial node set is established and flushed",
			steps: []testStep{
				flushAndVerifyReport(basicLicenseUsageReport{complete: false}),
				updateNodes([]event[*v1.Node]{
					addNode(node("node1", "4")),
					addNode(node("node2", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node1")),
					addPod(calicoNodePod("node2")),
				}),
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
			},
		},

		// The following tests are scenarios where the calico-node pods differ from the mainline cases above (mainline case: a linux pod on each node)
		{
			desc: "flush occurs when some nodes do not have a calico-node pod",
			steps: []testStep{
				updateNodes([]event[*v1.Node]{
					addNode(node("node1", "4")),
					addNode(node("node2", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node1")),
				}),
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 1, vCPU: 4}, maxCounts: counts{nodes: 1, vCPU: 4}, complete: true}),
			},
		},
		{
			desc: "flush occurs when all nodes do not have a calico-node pod",
			steps: []testStep{
				updateNodes([]event[*v1.Node]{
					addNode(node("node1", "4")),
					addNode(node("node2", "8")),
				}),
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 0, vCPU: 0}, maxCounts: counts{nodes: 0, vCPU: 0}, complete: true}),
			},
		},
		{
			desc: "flush occurs when a node loses its calico-node pod",
			steps: []testStep{
				updateNodes([]event[*v1.Node]{
					addNode(node("node1", "4")),
					addNode(node("node2", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node1")),
					addPod(calicoNodePod("node2")),
				}),
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
				updatePods([]event[*v1.Pod]{
					removePod(calicoNodePod("node1")),
				}),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 1, vCPU: 8}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
			},
		},
		{
			desc: "flush occurs after a pod is edited in a way that does not change its node assignment",
			steps: []testStep{
				updateNodes([]event[*v1.Node]{
					addNode(node("node1", "4")),
					addNode(node("node2", "8")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node1")),
					addPod(calicoNodePod("node2")),
				}),
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
				updatePods([]event[*v1.Pod]{
					updatePod(calicoNodePod("node1"), calicoNodePod("node1")),
				}),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
			},
		},
		{
			desc: "flush occurs with only pod events",
			steps: []testStep{
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node1")),
					addPod(calicoNodePod("node2")),
				}),
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 0, vCPU: 0}, maxCounts: counts{nodes: 0, vCPU: 0}, complete: true}),
			},
		},
		{
			desc: "flush occurs with a mix of linux and windows calico-nodes",
			steps: []testStep{
				updateNodes([]event[*v1.Node]{
					addNode(node("node1", "4")),
					addNode(node("node2", "8")),
					addNode(node("node3", "2")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node1")),
					addPod(calicoNodePod("node2")),
					addPod(calicoNodeWindowsPod("node3")),
				}),
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 3, vCPU: 14}, maxCounts: counts{nodes: 3, vCPU: 14}, complete: true}),
			},
		},
		{
			desc: "flush occurs after a windows node is added to a set of linux nodes",
			steps: []testStep{
				updateNodes([]event[*v1.Node]{
					addNode(node("node1", "4")),
					addNode(node("node2", "8")),
					addNode(node("node3", "2")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodePod("node1")),
					addPod(calicoNodePod("node2")),
				}),
				sendSync(),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 2, vCPU: 12}, complete: true}),
				updateNodes([]event[*v1.Node]{
					addNode(node("node3", "2")),
				}),
				updatePods([]event[*v1.Pod]{
					addPod(calicoNodeWindowsPod("node3")),
				}),
				flushAndVerifyReport(basicLicenseUsageReport{minCounts: counts{nodes: 2, vCPU: 12}, maxCounts: counts{nodes: 3, vCPU: 14}, complete: true}),
			},
		},
	}

	Context("sequence-based tests", func() {
		for _, loopSequence := range sequences {
			sequence := loopSequence
			It(fmt.Sprintf("should generate the correct report when %s", sequence.desc), func() {
				execSequence(sequence.steps, reporter)
			})
		}
	})
})

type testStepType int

const (
	publishNodeEvents testStepType = iota
	publishPodEvents
	setSynced
	flush
)

// testStep is a union type, whose interpretation differs depending on the stepType.
type testStep struct {
	stepType testStepType

	// Events to publish to the reporter if the stepType is publishNodeEvents.
	nodeEvents []event[*v1.Node]

	// Events to publish to the reporter if the stepType is publishPodEvents.
	podEvents []event[*v1.Pod]

	// Expected report to compare against the actual report if stepType is flush.
	expectedReport basicLicenseUsageReport
}

type testSequence struct {
	desc  string
	steps []testStep
}

func sendSync() testStep {
	return testStep{
		stepType: setSynced,
	}
}

func flushAndVerifyReport(report basicLicenseUsageReport) testStep {
	return testStep{
		stepType:       flush,
		expectedReport: report,
	}
}

func updateNodes(nodes []event[*v1.Node]) testStep {
	return testStep{
		stepType:   publishNodeEvents,
		nodeEvents: nodes,
	}
}

func addNode(node *v1.Node) event[*v1.Node] {
	return event[*v1.Node]{
		old: nil,
		new: node,
	}
}

func removeNode(node *v1.Node) event[*v1.Node] {
	return event[*v1.Node]{
		old: node,
		new: nil,
	}
}

func updateNode(previousNode, newNode *v1.Node) event[*v1.Node] {
	return event[*v1.Node]{
		old: previousNode,
		new: newNode,
	}
}

func node(name string, vCPU string) *v1.Node {
	return &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			// For consistency between calls, the 'UID' is deterministically generated from the node details.
			UID: types.UID(name),
		},
		Status: v1.NodeStatus{
			Capacity: map[v1.ResourceName]resource.Quantity{
				v1.ResourceCPU: resource.MustParse(vCPU),
			},
		},
	}
}

func updatePods(pods []event[*v1.Pod]) testStep {
	return testStep{
		stepType:  publishPodEvents,
		podEvents: pods,
	}
}

func addPod(pod *v1.Pod) event[*v1.Pod] {
	return event[*v1.Pod]{
		old: nil,
		new: pod,
	}
}

func removePod(pod *v1.Pod) event[*v1.Pod] {
	return event[*v1.Pod]{
		old: pod,
		new: nil,
	}
}

func updatePod(oldPod, newPod *v1.Pod) event[*v1.Pod] {
	return event[*v1.Pod]{
		old: oldPod,
		new: newPod,
	}
}

func calicoNodePod(node string) *v1.Pod {
	return calicoNodePodConstructor(node, false)
}

func calicoNodeWindowsPod(node string) *v1.Pod {
	return calicoNodePodConstructor(node, true)
}

func calicoNodePodConstructor(node string, isWindows bool) *v1.Pod {
	podName := "calico-node-xxxxx"
	if isWindows {
		podName = "calico-node-windows-xxxxx"
	}
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			// For consistency between calls, the 'UID' is deterministically generated from the node details.
			UID:       types.UID(node + "/" + podName),
			Name:      podName,
			Namespace: "calico-system",
			Labels: map[string]string{
				"app.kubernetes.io/name": podName,
			},
		},
		Spec: v1.PodSpec{
			NodeName: node,
		},
	}
}

func execSequence(testSequence []testStep, reporter reportGenerator) {
	for _, step := range testSequence {
		switch step.stepType {
		case publishNodeEvents:
			for _, event := range step.nodeEvents {
				reporter.nodeUpdates <- event
			}
		case publishPodEvents:
			for _, event := range step.podEvents {
				reporter.podUpdates <- event
			}
		case flush:
			reporter.intervalComplete <- true
			report := <-reporter.reports

			// Sanitize for comparison. Validation of timestamps are tested in FVs, where there is a fixed duration between reports.
			report.intervalStart = time.Time{}
			report.intervalEnd = time.Time{}
			step.expectedReport.intervalStart = time.Time{}
			step.expectedReport.intervalEnd = time.Time{}

			// Compare.
			Expect(report).To(Equal(step.expectedReport))
		case setSynced:
			reporter.initialSyncComplete <- true
		}
	}
}
