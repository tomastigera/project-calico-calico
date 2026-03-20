// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package calc_test

import "github.com/projectcalico/calico/felix/proto"

var (
	localRemote     = []proto.RouteType{proto.RouteType_LOCAL_WORKLOAD, proto.RouteType_REMOTE_WORKLOAD}
	remoteTunnelWep = []proto.RouteType{proto.RouteType_REMOTE_TUNNEL}
)

// Base state for remote cluster VXLAN block tests. This base ensures that there is always local VXLAN encap, which is useful
// for cases like validating when two remote clusters overlap. The pool here is referred to as "pool 1".
var remoteClusterVXLANBlocksBase = func() State {
	state := empty.withName("remoteClusterVXLANBase")

	state = StateWithPool(state, local, "11.0.0.0/16", true)
	state = StateWithBlock(state, local, "11.0.1.0/29", true, proto.IPPoolType_VXLAN, localClusterHost2, localClusterHost2IPAddr)
	state = StateWithVTEP(state, local, "11.0.1.1", true, localClusterHost2MAC, proto.IPPoolType_VXLAN, localClusterHost2, localClusterHost2IPAddr, remoteTunnelWep...)
	state = StateWithNode(state, local, localClusterHost2, localClusterHost2IPAddr, "11.0.1.1", "", "")

	return state
}()

// Local VXLAN pool 1 exists alongside local VXLAN pool 2.
var remoteClusterVXLANLocalOnly = func() State {
	state := remoteClusterVXLANBlocksBase.withName("remoteClusterVXLANLocalOnly")
	return StateWithVXLANBlockForLocal(state, true)
}()

// Local VXLAN pool 1 exists alongside remote A VXLAN pool 2.
var remoteClusterVXLANRemoteAOnly = func() State {
	state := remoteClusterVXLANBlocksBase.withName("remoteClusterVXLANRemoteAOnly")
	return StateWithVXLANBlockForRemoteA(state, true)
}()

// Local VXLAN pool 1 exists alongside local AND remote A pool 2.
var remoteClusterVXLANLocalOverlapsWithRemoteA = func() State {
	state := remoteClusterVXLANBlocksBase.withName("remoteClusterVXLANOverlapsWithRemoteA")

	state = StateWithVXLANBlockForLocal(state, true)
	state = StateWithVXLANBlockForRemoteA(state, false)

	return state
}()

// Local VXLAN pool 1 exists alongside remote A and remote B pool 2.
var remoteClusterVXLANRemoteAOverlapsWithRemoteB = func() State {
	state := remoteClusterVXLANBlocksBase.withName("remoteClusterVXLANOverlapsWithRemoteB")

	state = StateWithVXLANBlockForRemoteA(state, true)
	state = StateWithVXLANBlockForRemoteB(state, false)

	return state
}()

// Base state for remote cluster VXLAN WEP tests. This base ensures that there is always local VXLAN encap, which is useful
// for cases like validating when two remote clusters overlap. The pool here is referred to as "pool 1".
var remoteClusterVXLANWEPsBase = func() State {
	state := empty.withName("remoteClusterVXLANWEPsBase")

	state = StateWithPool(state, local, "11.0.0.0/16", true)
	state = StateWithWEP(state, local, "11.0.0.5", true, proto.IPPoolType_VXLAN, "base-wep", localClusterHost2, localClusterHost2IPAddr, false)
	state = StateWithVTEP(state, local, "11.0.1.1", true, localClusterHost2MAC, proto.IPPoolType_VXLAN, localClusterHost2, localClusterHost2IPAddr)
	state = StateWithNode(state, local, localClusterHost2, localClusterHost2IPAddr, "11.0.1.1", "", "")

	return state
}()

// Local VXLAN pool 1 exists alongside local VXLAN pool 2.
var remoteClusterVXLANWEPsLocalOnly = func() State {
	state := remoteClusterVXLANWEPsBase.withName("remoteClusterVXLANWEPsLocalOnly")

	return StateWithVXLANWEPForLocal(state, true)
}()

// Local VXLAN pool 1 exists alongside remote A VXLAN pool 2.
var remoteClusterVXLANWEPsRemoteAOnly = func() State {
	state := remoteClusterVXLANWEPsBase.withName("remoteClusterVXLANWEPsRemoteAOnly")

	return StateWithVXLANWEPForRemoteA(state, true)
}()

// Local VXLAN pool 1 exists alongside local AND remote A VXLAN pool 2.
var remoteClusterVXLANWEPsLocalOverlapsWithRemoteA = func() State {
	state := remoteClusterVXLANWEPsBase.withName("remoteClusterVXLANWEPsLocalOverlapsWithRemoteA")

	state = StateWithVXLANWEPForLocal(state, true)
	state = StateWithVXLANWEPForRemoteA(state, false)

	return state
}()

// Local VXLAN pool 1 exists alongside remote A AND remote B VXLAN pool 2.
var remoteClusterVXLANWEPsRemoteAOverlapsWithRemoteB = func() State {
	state := remoteClusterVXLANWEPsBase.withName("remoteClusterVXLANWEPsRemoteAOverlapsWithRemoteB")

	state = StateWithVXLANWEPForRemoteA(state, true)
	state = StateWithVXLANWEPForRemoteB(state, false)

	return state
}()

// Overlap resolution depends on containing IP pools, but no IP pools are present. Both blocks flush.
var remoteClusterBlockEnclosesLocalBlock = func() State {
	state := empty.withName("remoteClusterBlockEnclosesLocalBlock")

	state = StateWithBlock(state, remoteA, "10.0.0.0/28", true, proto.IPPoolType_NONE, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithBlock(state, local, "10.0.0.0/29", true, proto.IPPoolType_NONE, localClusterHost, localClusterHostIPAddr)

	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "", "", "")
	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "", "", "")

	return state
}()

// Overlap resolution depends on containing IP pools, but no IP pools are present. Both WEP and block flush.
var remoteClusterBlockEnclosesLocalWEP = func() State {
	state := empty.withName("remoteClusterBlockEnclosesLocalWEP")

	state = StateWithBlock(state, remoteA, "10.0.0.0/28", true, proto.IPPoolType_NONE, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithWEP(state, local, "10.0.0.0", true, proto.IPPoolType_NONE, "wep", localHostname, localClusterHostIPAddr, true, localRemote...)

	state = StateWithNode(state, local, localHostname, localClusterHostIPAddr, "", "", "")
	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "", "", "")

	return state
}()

// Overlap resolution depends on containing IP pools, but no IP pools are present. Both blocks flush.
var remoteClusterBlockEnclosesRemoteBlock = func() State {
	state := empty.withName("remoteClusterBlockEnclosesRemoteBlock")

	state = StateWithBlock(state, remoteA, "10.0.0.0/28", true, proto.IPPoolType_NONE, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithBlock(state, remoteB, "10.0.0.0/29", true, proto.IPPoolType_NONE, remoteClusterBHost, remoteClusterBHostIPAddr)

	state = StateWithNode(state, remoteB, remoteClusterBHost, remoteClusterBHostIPAddr, "", "", "")
	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "", "", "")

	return state
}()

// Overlap resolution depends on containing IP pool. The local block should flush since it is not contained by a conflicting pool.
// The remote pool and block should flush as if the local block was not enclosing them.
var localClusterOrphanBlockContainsRemotePoolAndBlock = func() State {
	state := empty.withName("localClusterOrphanBlockContainsRemotePoolAndBlock")

	state = StateWithBlock(state, local, "10.0.0.0/20", true, proto.IPPoolType_NONE, localClusterHost, localClusterHostIPAddr)
	state = StateWithPool(state, remoteA, "10.0.0.0/24", true)
	state = StateWithBlock(state, remoteA, "10.0.0.0/29", true, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)

	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "", "", "")
	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "", "", "")

	return state
}()

// Overlap resolution depends on containing IP pool. The remote block should flush since it is not contained by a conflicting pool.
// The local pool and block should flush as if the remote block was not enclosing them.
var remoteClusterOrphanBlockContainsLocalPoolAndBlock = func() State {
	state := empty.withName("remoteClusterOrphanBlockContainsLocalPoolAndBlock")

	state = StateWithBlock(state, remoteB, "10.0.0.0/16", true, proto.IPPoolType_NONE, remoteClusterBHost, remoteClusterBHostIPAddr)
	state = StateWithPool(state, local, "10.0.0.0/18", true)
	state = StateWithBlock(state, local, "10.0.0.0/20", true, proto.IPPoolType_VXLAN, localClusterHost, localClusterHostIPAddr)

	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "", "", "")
	state = StateWithNode(state, remoteB, remoteClusterBHost, remoteClusterBHostIPAddr, "", "", "")

	return state
}()

// ROUGH EDGE: Overlap resolution depends on containing IP pool. The orphaned local block should not be flushed since the remote pool
// governs this path. Ideally we always preserve local CIDRs, but orphans typically* do not have functioning routing, so
// we allow this principle to be broken in this case to simplify the implementation.
//
//   - One case where orphans do have functioning routing: a WireGuard-enabled cluster not using Calico CNI - we would expect
//     connecting a remote cluster with an enclosing IP pool to cause disruption to local routing as orphan WEPs are removed.
var remoteClusterPoolAndBlockContainLocalOrphanBlock = func() State {
	state := empty.withName("remoteClusterPoolAndBlockContainLocalOrphanBlock")

	state = StateWithPool(state, remoteA, "10.0.0.0/16", true)
	state = StateWithBlock(state, remoteA, "10.0.0.0/24", true, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithBlock(state, local, "10.0.0.0/26", false, proto.IPPoolType_NONE, localClusterHost, localClusterHostIPAddr)

	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "", "", "")
	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "", "", "")

	return state
}()

// Overlap resolution depends on containing IP pool. The orphaned remote block should not be flushed since the local pool
// governs this path.
var localClusterPoolAndBlockContainRemoteOrphanBlock = func() State {
	state := empty.withName("localClusterPoolAndBlockContainRemoteOrphanBlock")

	state = StateWithPool(state, local, "10.0.0.0/22", true)
	state = StateWithBlock(state, local, "10.0.0.0/26", true, proto.IPPoolType_VXLAN, localClusterHost, localClusterHostIPAddr)
	state = StateWithBlock(state, remoteB, "10.0.0.0/29", false, proto.IPPoolType_NONE, remoteClusterBHost, remoteClusterBHostIPAddr)

	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "", "", "")
	state = StateWithNode(state, remoteB, remoteClusterBHost, remoteClusterBHostIPAddr, "", "", "")

	return state
}()

// Overlap resolution depends on containing IP pool. In this case, the remote IP pool asserts itself first on the path,
// but since a local pool appears, it asserts itself as the containing IP pool for the remainder of the path. This means
// that the remote block should not flush. This also means that both pools flush, since the first had no parents that
// invalidated it.
var remoteClusterPoolWithLargerBlockSizeContainsLocalPoolWithBlocks = func() State {
	state := empty.withName("remoteClusterPoolWithLargerBlockSizeContainsLocalPoolWithBlocks")

	state = StateWithPool(state, remoteA, "10.0.0.0/16", true)
	state = StateWithPool(state, local, "10.0.0.0/24", true)
	state = StateWithBlock(state, remoteA, "10.0.0.0/26", false, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithBlock(state, local, "10.0.0.0/29", true, proto.IPPoolType_VXLAN, localClusterHost, localClusterHostIPAddr)

	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "", "", "")
	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "", "", "")

	return state
}()

// Overlap resolution depends on containing IP pool. The local pool asserts itself first on the path before the remote
// pool. This means that both the remote pool and the remote block should not flush.
var localClusterPoolWithLargerBlockSizeContainsRemotePoolWithBlocks = func() State {
	state := empty.withName("localClusterPoolWithLargerBlockSizeContainsRemotePoolWithBlocks")

	state = StateWithPool(state, local, "10.0.0.0/16", true)
	state = StateWithPool(state, remoteA, "10.0.0.0/24", false)
	state = StateWithBlock(state, local, "10.0.0.0/26", true, proto.IPPoolType_VXLAN, localClusterHost, localClusterHostIPAddr)
	state = StateWithBlock(state, remoteA, "10.0.0.0/29", false, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)

	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "", "", "")
	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "", "", "")

	return state
}()

// Overlap resolution depends on containing IP pool. The remote A pool asserts itself first on the path before the remote
// B pool. This means that both the remote B pool and the remote B block should not flush.
var remoteClusterAPoolWithLargerBlockSizeContainsRemoteBPoolWithBlocks = func() State {
	state := empty.withName("remoteClusterAPoolWithLargerBlockSizeContainsRemoteBPoolWithBlocks")

	state = StateWithPool(state, remoteA, "10.0.0.0/16", true)
	state = StateWithPool(state, remoteB, "10.0.0.0/24", false)
	state = StateWithBlock(state, remoteA, "10.0.0.0/26", true, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithBlock(state, remoteB, "10.0.0.0/29", false, proto.IPPoolType_VXLAN, remoteClusterBHost, remoteClusterBHostIPAddr)

	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "", "", "")
	state = StateWithNode(state, remoteB, remoteClusterBHost, remoteClusterBHostIPAddr, "", "", "")

	return state
}()

// Overlap resolution depends on containing IP pool. In this case, the remote IP pool asserts itself first on the path,
// but since a local pool appears, it asserts itself as the containing IP pool for the remainder of the path. We expect
// that the local block to be preferred, for both the conflict at it's CIDR and the conflict with its pool CIDRs.
var remoteClusterPoolContainsLocalPoolWithOverlappedBlocks = func() State {
	state := empty.withName("remoteClusterPoolContainsLocalPoolWithOverlappedBlocks")

	state = StateWithPool(state, remoteA, "10.0.0.0/16", true)
	state = StateWithPool(state, local, "10.0.0.0/24", true)
	state = StateWithBlock(state, remoteA, "10.0.0.0/26", false, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithBlock(state, local, "10.0.0.0/26", true, proto.IPPoolType_VXLAN, localClusterHost, localClusterHostIPAddr)

	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "", "", "")
	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "", "", "")

	return state
}()

// Overlap resolution depends on containing IP pool. The local pool asserts itself first on the path. We expect only
// the local pool to be flushed, and for the local block to be preferred, for both the conflict at it's CIDR and the
// conflict with its pool CIDRs.
var localClusterPoolContainsRemotePoolWithOverlappedBlocks = func() State {
	state := empty.withName("localClusterPoolContainsRemotePoolWithOverlappedBlocks")

	state = StateWithPool(state, local, "10.0.0.0/16", true)
	state = StateWithPool(state, remoteA, "10.0.0.0/24", false)
	state = StateWithBlock(state, remoteA, "10.0.0.0/26", false, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithBlock(state, local, "10.0.0.0/26", true, proto.IPPoolType_VXLAN, localClusterHost, localClusterHostIPAddr)

	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "", "", "")
	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "", "", "")

	return state
}()

var remoteClusterAPoolWithOverlappedBlocks = func() State {
	state := empty.withName("remoteClusterAPoolWithOverlappedRemoteBlocks")

	state = StateWithPool(state, remoteA, "10.0.0.0/16", true)
	state = StateWithBlock(state, remoteA, "10.0.0.0/26", true, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithBlock(state, remoteB, "10.0.0.0/26", false, proto.IPPoolType_VXLAN, remoteClusterBHost, remoteClusterBHostIPAddr)

	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "", "", "")
	state = StateWithNode(state, remoteB, remoteClusterBHost, remoteClusterBHostIPAddr, "", "", "")

	return state
}()

// Overlap resolution depends on containing IP pool. The remote A pool asserts itself first on the path. We expect only
// the remote A pool to be flushed, and for the remote A block to be preferred, for both the conflict at it's CIDR
// (resolved lexicographically) and the conflict with its pool CIDRs.
var remoteClusterAPoolContainsRemoteBPoolWithOverlappedBlocks = func() State {
	state := remoteClusterAPoolWithOverlappedBlocks.withName("remoteClusterAPoolContainsRemoteBPoolWithOverlappedBlocks")
	state = StateWithPool(state, remoteB, "10.0.0.0/24", false)
	return state
}()

// ROUGH EDGE: Overlap resolution depends on containing IP pool. The remote B pool asserts itself first on the path. We expect only
// the remote B pool to be flushed. The blocks conflict - since the conflict at the CIDR level is won by remote A
// (lexicographically) and the path is for remote B, no blocks are flushed.
var remoteClusterBPoolContainsRemoteAPoolWithOverlappedBlocks = func() State {
	state := empty.withName("remoteClusterBPoolContainsRemoteAPoolWithOverlappedBlocks")

	state = StateWithPool(state, remoteB, "10.0.0.0/12", true)
	state = StateWithPool(state, remoteA, "10.0.0.0/16", false)
	state = StateWithBlock(state, remoteA, "10.0.0.0/26", false, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithBlock(state, remoteB, "10.0.0.0/26", false, proto.IPPoolType_VXLAN, remoteClusterBHost, remoteClusterBHostIPAddr)

	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "", "", "")
	state = StateWithNode(state, remoteB, remoteClusterBHost, remoteClusterBHostIPAddr, "", "", "")

	return state
}()

// Overlap resolution depends on containing IP pool. In this case, the remote IP pool asserts itself first on the path,
// but since a local pool appears, it asserts itself as the containing IP pool for the remainder of the path. We expect
// the remote VTEP route to be ignored.
var remoteClusterPoolWithLargerBlockSizeContainsLocalPoolWithTunnels = func() State {
	state := empty.withName("remoteClusterPoolWithLargerBlockSizeContainsLocalPoolWithTunnels")

	state = StateWithPool(state, remoteA, "10.0.0.0/16", true)
	state = StateWithPool(state, local, "10.0.0.0/24", true)
	state = StateWithVTEP(state, remoteA, "10.0.0.2", false, remoteClusterAHostMAC, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithVTEP(state, local, "10.0.0.1", true, localClusterHostMAC, proto.IPPoolType_VXLAN, localClusterHost, localClusterHostIPAddr)

	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "10.0.0.2", "", "")
	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "10.0.0.1", "", "")

	return state
}()

// Overlap resolution depends on containing IP pool. The local IP pool asserts itself first on the path. We expect
// the remote pool and the remote VTEP route won't flush.
var localClusterPoolWithLargerBlockSizeContainsRemotePoolWithTunnels = func() State {
	state := empty.withName("localClusterPoolWithLargerBlockSizeContainsRemotePoolWithTunnels")

	state = StateWithPool(state, local, "10.0.0.0/16", true)
	state = StateWithPool(state, remoteA, "10.0.0.0/24", false)
	state = StateWithVTEP(state, remoteA, "10.0.0.2", false, remoteClusterAHostMAC, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithVTEP(state, local, "10.0.0.1", true, localClusterHostMAC, proto.IPPoolType_VXLAN, localClusterHost, localClusterHostIPAddr)

	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "10.0.0.2", "", "")
	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "10.0.0.1", "", "")

	return state
}()

// Overlap resolution depends on containing IP pool. The remote A IP pool asserts itself first on the path. We expect
// the remote B pool and the remote B VTEP route won't flush.
var remoteClusterAPoolWithLargerBlockSizeContainsRemoteBPoolWithTunnels = func() State {
	state := empty.withName("remoteClusterAPoolWithLargerBlockSizeContainsRemoteBPoolWithTunnels")

	state = StateWithPool(state, remoteA, "10.0.0.0/16", true)
	state = StateWithPool(state, remoteB, "10.0.0.0/24", false)
	state = StateWithVTEP(state, remoteA, "10.0.0.2", true, remoteClusterAHostMAC, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithVTEP(state, remoteB, "10.0.0.3", false, remoteClusterBHostMAC, proto.IPPoolType_VXLAN, remoteClusterBHost, remoteClusterBHostIPAddr)

	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "10.0.0.2", "", "")
	state = StateWithNode(state, remoteB, remoteClusterBHost, remoteClusterBHostIPAddr, "10.0.0.3", "", "")

	return state
}()

// Overlap resolution depends on containing IP pool. In this case, the remote IP pool asserts itself first on the path,
// followed by a remote block. These both flush as there is no IP pool from another cluster that asserted itself before them.
// A local IP pool follows, which changes the assertion of the path. This flushes, along with its child block.
var remoteClusterPoolAndBlocksContainLocalPoolWithBlocks = func() State {
	state := empty.withName("remoteClusterPoolAndBlocksContainLocalPoolWithBlocks")

	state = StateWithPool(state, remoteA, "10.0.0.0/16", true)
	state = StateWithBlock(state, remoteA, "10.0.0.0/22", true, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithPool(state, local, "10.0.0.0/24", true)
	state = StateWithBlock(state, local, "10.0.0.0/29", true, proto.IPPoolType_VXLAN, localClusterHost, localClusterHostIPAddr)

	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "", "", "")
	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "", "", "")

	return state
}()

// Overlap resolution depends on containing IP pool. The local IP pool asserts itself first on the path, followed by a local block.
// These both flush as there is no IP pool from another cluster that asserted itself before them. A remote IP pool and
// block follow, which do not change the assertion of the path, and therefore do not flush.
var localClusterPoolAndBlocksContainRemotePoolWithBlocks = func() State {
	state := empty.withName("localClusterPoolAndBlocksContainRemotePoolWithBlocks")

	state = StateWithPool(state, local, "10.0.0.0/16", true)
	state = StateWithBlock(state, local, "10.0.0.0/22", true, proto.IPPoolType_VXLAN, localClusterHost, localClusterHostIPAddr)
	state = StateWithPool(state, remoteA, "10.0.0.0/24", false)
	state = StateWithBlock(state, remoteA, "10.0.0.0/29", false, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)

	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "", "", "")
	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "", "", "")

	return state
}()

// Overlap resolution depends on containing IP pool. The remote A IP pool asserts itself first on the path, followed by a local block.
// These both flush as there is no IP pool from another cluster that asserted itself before them. Remote B IP pool and
// block follow, which do not change the assertion of the path, and therefore do not flush.
var remoteClusterAPoolAndBlocksContainRemoteBPoolWithBlock = func() State {
	state := empty.withName("remoteClusterAPoolAndBlocksContainRemoteBPoolWithBlock")

	state = StateWithPool(state, remoteA, "10.0.0.0/16", true)
	state = StateWithBlock(state, remoteA, "10.0.0.0/22", true, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithPool(state, remoteB, "10.0.0.0/24", false)
	state = StateWithBlock(state, remoteB, "10.0.0.0/29", false, proto.IPPoolType_VXLAN, remoteClusterBHost, remoteClusterBHostIPAddr)

	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "", "", "")
	state = StateWithNode(state, remoteB, remoteClusterBHost, remoteClusterBHostIPAddr, "", "", "")

	return state
}()

// Overlap resolution depends on containing IP pool. We expect the local IP pool to win the conflict at the CIDR level,
// and assert itself as the pool for the path. The remote block is not flushed as it does not match the asserted pool.
var overlappedRemoteAndLocalClusterPoolContainsRemoteBlock = func() State {
	state := empty.withName("overlappedRemoteAndLocalClusterPoolContainsRemoteBlock")

	state = StateWithPool(state, remoteA, "10.0.0.0/16", false)
	state = StateWithPool(state, local, "10.0.0.0/16", true)
	state = StateWithBlock(state, remoteA, "10.0.0.0/22", false, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)

	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "", "", "")

	return state
}()

// Overlap resolution depends on containing IP pool. We expect the local IP pool to win the conflict at the CIDR level,
// and assert itself as the pool for the path. The local block is flushed as it matches the asserted pool.
var overlappedRemoteAndLocalClusterPoolContainsLocalBlock = func() State {
	state := empty.withName("overlappedRemoteAndLocalClusterPoolContainsLocalBlock")

	state = StateWithPool(state, remoteA, "10.0.0.0/16", false)
	state = StateWithPool(state, local, "10.0.0.0/16", true)
	state = StateWithBlock(state, local, "10.0.0.0/22", true, proto.IPPoolType_VXLAN, localClusterHost, localClusterHostIPAddr)

	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "", "", "")

	return state
}()

// Overlap resolution depends on containing IP pool. We expect the remote A IP pool to win the conflict at the CIDR level
// (lexicographically) and assert itself as the pool for the path. The remote A block is flushed as it matches the asserted pool.
var remoteOverlappedPoolsContainRemoteABlock = func() State {
	state := empty.withName("remoteOverlappedPoolsContainRemoteABlock")

	state = StateWithPool(state, remoteA, "10.0.0.0/16", true)
	state = StateWithPool(state, remoteB, "10.0.0.0/16", false)
	state = StateWithBlock(state, remoteA, "10.0.0.0/22", true, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)

	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "", "", "")

	return state
}()

// ROUGH EDGE: Overlap resolution depends on containing IP pool. We expect the remote A pool to win the conflict at the CIDR level
// (lexicographically), and assert itself as the pool for the path. The remote B block is not flushed as it doesn't match the pool.
var remoteOverlappedPoolsContainRemoteBBlock = func() State {
	state := empty.withName("remoteOverlappedPoolsContainRemoteBBlock")

	state = StateWithPool(state, remoteA, "10.0.0.0/16", true)
	state = StateWithPool(state, remoteB, "10.0.0.0/16", false)
	state = StateWithBlock(state, remoteB, "10.0.0.0/22", false, proto.IPPoolType_VXLAN, remoteClusterBHost, remoteClusterBHostIPAddr)

	state = StateWithNode(state, remoteB, remoteClusterBHost, remoteClusterBHostIPAddr, "", "", "")

	return state
}()

var multipleTunnelEndpointsOverlapBetweenLocalAndRemoteA = func() State {
	state := empty.withName("multipleTunnelEndpointsOverlapBetweenLocalAndRemoteA")

	state = StateWithPool(state, local, "10.0.0.0/16", true)
	state = StateWithBlock(state, local, "10.0.1.0/29", true, proto.IPPoolType_VXLAN, localClusterHost, localClusterHostIPAddr)
	state = StateWithVTEP(state, local, "10.0.1.1", true, localClusterHostMAC, proto.IPPoolType_VXLAN, localClusterHost, localClusterHostIPAddr, remoteTunnelWep...)
	state = StateWithWGEP(state, local, "10.0.1.2", true, wgPublicKey1.String(), proto.IPPoolType_VXLAN, localClusterHost, localClusterHostIPAddr, remoteTunnelWep...)
	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "10.0.1.1", "10.0.1.2", wgPublicKey1.String())

	state = StateWithPool(state, remoteA, "10.0.0.0/16", false)
	state = StateWithBlock(state, remoteA, "10.0.1.0/29", false, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithVTEP(state, remoteA, "10.0.1.1", false, remoteClusterAHostMAC, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithWGEP(state, remoteA, "10.0.1.2", false, wgPublicKey2.String(), proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "10.0.1.1", "10.0.1.2", wgPublicKey2.String())

	return state
}()

var multipleTunnelEndpointsOverlapIndirectlyBetweenLocalAndRemoteA = func() State {
	state := empty.withName("multipleTunnelEndpointsOverlapIndirectlyBetweenLocalAndRemoteA")

	state = StateWithPool(state, local, "10.0.0.0/16", true)
	state = StateWithBlock(state, local, "10.0.1.0/29", true, proto.IPPoolType_VXLAN, localClusterHost, localClusterHostIPAddr)
	state = StateWithVTEP(state, local, "10.0.1.1", true, localClusterHostMAC, proto.IPPoolType_VXLAN, localClusterHost, localClusterHostIPAddr, remoteTunnelWep...)
	state = StateWithWGEP(state, local, "10.0.1.2", true, wgPublicKey1.String(), proto.IPPoolType_VXLAN, localClusterHost, localClusterHostIPAddr, remoteTunnelWep...)
	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "10.0.1.1", "10.0.1.2", wgPublicKey1.String())

	state = StateWithPool(state, remoteA, "10.0.0.0/16", false)
	state = StateWithBlock(state, remoteA, "10.0.1.0/29", false, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithVTEP(state, remoteA, "10.0.1.5", false, remoteClusterAHostMAC, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithWGEP(state, remoteA, "10.0.1.6", false, wgPublicKey2.String(), proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "10.0.1.5", "10.0.1.6", wgPublicKey2.String())

	return state
}()

var multipleTunnelEndpointsOverlapWithoutPoolsBetweenLocalAndRemoteA = func() State {
	state := empty.withName("multipleTunnelEndpointsOverlapWithoutPoolsBetweenLocalAndRemoteA")

	state = StateWithVTEP(state, local, "10.0.1.1", true, localClusterHostMAC, proto.IPPoolType_NONE, localClusterHost, localClusterHostIPAddr)
	state = StateWithWGEP(state, local, "10.0.1.2", true, wgPublicKey1.String(), proto.IPPoolType_NONE, localClusterHost, localClusterHostIPAddr)
	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "10.0.1.1", "10.0.1.2", wgPublicKey1.String())

	state = StateWithVTEP(state, remoteA, "10.0.1.1", false, remoteClusterAHostMAC, proto.IPPoolType_NONE, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithWGEP(state, remoteA, "10.0.1.2", false, wgPublicKey2.String(), proto.IPPoolType_NONE, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "10.0.1.1", "10.0.1.2", wgPublicKey2.String())

	return state
}()

var multipleTunnelEndpointsOverlapAcrossTypesWithoutPoolsBetweenLocalAndRemoteA = func() State {
	state := empty.withName("multipleTunnelEndpointsOverlapAcrossTypesWithoutPoolsBetweenLocalAndRemoteA")

	state = StateWithVTEP(state, local, "10.0.1.1", true, localClusterHostMAC, proto.IPPoolType_NONE, localClusterHost, localClusterHostIPAddr)
	state = StateWithWGEP(state, local, "10.0.1.2", true, wgPublicKey1.String(), proto.IPPoolType_NONE, localClusterHost, localClusterHostIPAddr)
	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "10.0.1.1", "10.0.1.2", wgPublicKey1.String())

	state = StateWithVTEP(state, remoteA, "10.0.1.2", false, remoteClusterAHostMAC, proto.IPPoolType_NONE, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithWGEP(state, remoteA, "10.0.1.1", false, wgPublicKey2.String(), proto.IPPoolType_NONE, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "10.0.1.2", "10.0.1.1", wgPublicKey2.String())

	return state
}()

var multipleTunnelEndpointsDisjointWithoutPoolsBetweenLocalAndRemoteA = func() State {
	state := empty.withName("multipleTunnelEndpointsDisjointWithoutPoolsBetweenLocalAndRemoteA")

	state = StateWithVTEP(state, local, "10.0.1.1", true, localClusterHostMAC, proto.IPPoolType_NONE, localClusterHost, localClusterHostIPAddr)
	state = StateWithWGEP(state, local, "10.0.1.2", true, wgPublicKey1.String(), proto.IPPoolType_NONE, localClusterHost, localClusterHostIPAddr)
	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "10.0.1.1", "10.0.1.2", wgPublicKey1.String())

	state = StateWithVTEP(state, remoteA, "10.0.1.3", true, remoteClusterAHostMAC, proto.IPPoolType_NONE, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithWGEP(state, remoteA, "10.0.1.4", true, wgPublicKey2.String(), proto.IPPoolType_NONE, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "10.0.1.3", "10.0.1.4", wgPublicKey2.String())

	return state
}()
