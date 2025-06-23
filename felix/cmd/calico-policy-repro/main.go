package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/bpf/ipsets"
	"github.com/projectcalico/calico/felix/bpf/jump"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/bpf/state"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/proto"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Please provide a number > 0 as a command-line argument.")
		return
	}

	argStr := os.Args[1]
	n, err := strconv.Atoi(argStr)
	if err != nil {
		fmt.Printf("Error: Invalid argument '%s'. Please provide a valid integer.\n", argStr)
		return
	}

	// Create a channel to receive OS signals
	signals := make(chan os.Signal, 1)

	// Register to be notified of SIGINT (Ctrl+C) and SIGTERM signals
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	ipSetIDAlloc := idalloc.New()
	ipSetIDAlloc.ReserveWellKnownID("xyz", 0x12345678)

	ipsetsMap := ipsets.Map()
	err = ipsetsMap.EnsureExists()
	if err != nil {
		fmt.Println("Failed to create ipsets map: %w", err)
		return
	}

	stateMap := state.Map()
	err = stateMap.EnsureExists()
	if err != nil {
		fmt.Println("Failed to create state map: %w", err)
		return
	}

	progsMap := jump.Map()
	err = progsMap.EnsureExists()
	if err != nil {
		fmt.Println("Failed to create progs map: %w", err)
		return
	}

	jumpMap := hook.NewProgramsMap()
	err = jumpMap.EnsureExists()
	if err != nil {
		fmt.Println("Failed to create jump map: %w", err)
		return
	}

	pg := polprog.NewBuilder(
		ipSetIDAlloc,
		ipsetsMap.MapFD(),
		stateMap.MapFD(),
		progsMap.MapFD(),
		jumpMap.MapFD(),
	)

	rules := polprog.Rules{
		Tiers: []polprog.Tier{{
			Name: "default",
		}},
	}

	for i := 0; i < n; i++ {
		rules.Tiers[0].Policies = append(rules.Tiers[0].Policies, polprog.Policy{
			Name: fmt.Sprintf("policy-%05d", i),
			Rules: []polprog.Rule{{
				Rule: &proto.Rule{
					Action:      "allow",
					DstIpSetIds: []string{"xyz"},
				},
			}},
		})
	}

	programs, err := pg.Instructions(rules)
	if err != nil {
		fmt.Println("Failed to generate policy bytecode: %w", err)
		return
	}

	fmt.Printf("instructions %d\n", len(programs[0]))

	progType := unix.BPF_PROG_TYPE_SCHED_CLS

	_, err = bpf.LoadBPFProgramFromInsns(programs[0], "repro-prog", "Apache-2.0", uint32(progType))

	if err != nil {
		fmt.Println("Failed to load program: %w", err)
		return
	}

	// Block forever until a signal is received
	fmt.Println("Press Ctrl+C to exit.")
	<-signals

	err = os.RemoveAll(bpfdefs.GlobalPinDir)
	if err != nil {
		fmt.Println("Failed to clean up pins")
		return
	}
}
