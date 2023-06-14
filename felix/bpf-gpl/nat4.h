// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_NAT4_H__
#define __CALI_NAT4_H__

#include <stddef.h>

#include <linux/if_ether.h>
#include <linux/udp.h>

#include "bpf.h"
#include "skb.h"
#include "routes.h"
#include "nat_types.h"

/* Number of bytes we add to a packet when we do encap. */
#define VXLAN_ENCAP_SIZE	(sizeof(struct ethhdr) + sizeof(struct iphdr) + \
				sizeof(struct udphdr) + sizeof(struct vxlanhdr))

static CALI_BPF_INLINE int vxlan_v4_encap(struct cali_tc_ctx *ctx,  __be32 ip_src, __be32 ip_dst)
{
	int ret;
	__wsum csum;

	__u32 new_hdrsz = sizeof(struct ethhdr) + sizeof(struct iphdr) +
			sizeof(struct udphdr) + sizeof(struct vxlanhdr);

	ret = bpf_skb_adjust_room(ctx->skb, new_hdrsz, BPF_ADJ_ROOM_MAC,
						  BPF_F_ADJ_ROOM_ENCAP_L4_UDP |
						  BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 |
						  BPF_F_ADJ_ROOM_ENCAP_L2(sizeof(struct ethhdr)));

	if (ret) {
		goto out;
	}

	ret = -1;

	if (skb_refresh_validate_ptrs(ctx, new_hdrsz)) {
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("Too short VXLAN encap\n");
		goto out;
	}

	// Note: assuming L2 packet here so this code can't be used on an L3 device.
	struct udphdr *udp = (struct udphdr*) ((void *)ip_hdr(ctx) + IP_SIZE);
	struct vxlanhdr *vxlan = (void *)(udp + 1);
	struct ethhdr *eth_inner = (void *)(vxlan+1);
	struct iphdr *ip_inner = (void*)(eth_inner+1);

	/* Copy the original IP header. Since it is already DNATed, the dest IP is
	 * already set. All we need to do is to change the source IP
	 */
	*ip_hdr(ctx) = *ip_inner;

	/* decrement TTL for the inner IP header. TTL must be > 1 to get here */
	ip_dec_ttl(ip_inner);

	ip_hdr(ctx)->saddr = ip_src;
	ip_hdr(ctx)->daddr = ip_dst;
	ip_hdr(ctx)->tot_len = bpf_htons(bpf_ntohs(ip_hdr(ctx)->tot_len) + new_hdrsz);
	ip_hdr(ctx)->ihl = 5; /* in case there were options in ip_inner */
	ip_hdr(ctx)->check = 0;
	ip_hdr(ctx)->protocol = IPPROTO_UDP;

	udp->source = udp->dest = bpf_htons(VXLAN_PORT);
	udp->len = bpf_htons(bpf_ntohs(ip_hdr(ctx)->tot_len) - sizeof(struct iphdr));

	*((__u8*)&vxlan->flags) = 1 << 3; /* set the I flag to make the VNI valid */
	vxlan->vni = bpf_htonl(CALI_VXLAN_VNI) >> 8; /* it is actually 24-bit, last 8 reserved */

	/* keep eth_inner MACs zeroed, it is useless after decap */
	eth_inner->h_proto = eth_hdr(ctx)->h_proto;

	CALI_DEBUG("vxlan encap %x : %x\n", bpf_ntohl(ip_hdr(ctx)->saddr), bpf_ntohl(ip_hdr(ctx)->daddr));

	/* change the checksums last to avoid pointer access revalidation */

	csum = bpf_csum_diff(0, 0, ctx->ip_header, sizeof(struct iphdr), 0);
	ret = bpf_l3_csum_replace(ctx->skb, ((long) ctx->ip_header) - ((long) skb_start_ptr(ctx->skb)) +
				  offsetof(struct iphdr, check), 0, csum, 0);

out:
	return ret;
}

static CALI_BPF_INLINE int vxlan_v4_decap(struct __sk_buff *skb)
{
	__u32 extra_hdrsz;
	int ret = -1;

	extra_hdrsz = sizeof(struct ethhdr) + sizeof(struct iphdr) +
		sizeof(struct udphdr) + sizeof(struct vxlanhdr);

	ret = bpf_skb_adjust_room(skb, -extra_hdrsz, BPF_ADJ_ROOM_MAC | BPF_F_ADJ_ROOM_FIXED_GSO, 0);

	return ret;
}

static CALI_BPF_INLINE bool vxlan_size_ok(struct cali_tc_ctx *ctx)
{
	return !skb_refresh_validate_ptrs(ctx, UDP_SIZE + sizeof(struct vxlanhdr));
}

static CALI_BPF_INLINE __u32 vxlan_vni(struct cali_tc_ctx *ctx)
{
	struct vxlanhdr *vxlan;

	vxlan = skb_ptr_after(skb, udp_hdr(ctx));

	return bpf_ntohl(vxlan->vni << 8); /* 24-bit field, last 8 reserved */
}

static CALI_BPF_INLINE bool vxlan_vni_is_valid(struct cali_tc_ctx *ctx)
{
	struct vxlanhdr *vxlan;

	vxlan = skb_ptr_after(ctx->skb, udp_hdr(ctx));

	return *((__u8*)&vxlan->flags) & (1 << 3);
}

/* vxlan_attempt_decap_v4 tries to decode the packet as VXLAN and, if it is a BPF-to-BPF
 * program VXLAN packet, does the decap. Returns:
 *
 * 0:  on success (either a packet that doesn't need decap or decap was successful).
 * -1: if the packet was invalid (e.g. too short)
 * -2: if the packet is VXLAN from a Calico host, to this node, but it is not the right VNI.
 */
static CALI_BPF_INLINE int vxlan_attempt_decap_v4(struct cali_tc_ctx *ctx)
{
	/* decap on host ep only if directly for the node */
	CALI_DEBUG("VXLAN tunnel packet to %x (host IP=%x)\n",
		bpf_ntohl(ip_hdr(ctx)->daddr),
		bpf_ntohl(HOST_IP));

	if (!rt_addr_is_local_host(ip_hdr(ctx)->daddr)) {
		goto fall_through;
	}
	if (!vxlan_size_ok(ctx)) {
		/* UDP header said VXLAN but packet wasn't long enough. */
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("Too short\n");
		goto deny;
	}
	if (!vxlan_vni_is_valid(ctx) ) {
		CALI_DEBUG("VXLAN: Invalid VNI\n");
		goto fall_through;
	}
	if (vxlan_vni(ctx) != CALI_VXLAN_VNI) {
		if (rt_addr_is_remote_host(ip_hdr(ctx)->saddr)) {
			/* Not BPF-generated VXLAN packet but it was from a Calico host to this node. */
			CALI_DEBUG("VXLAN: non-tunnel calico\n");
			goto auto_allow;
		}
		/* Not our VNI, not from Calico host. Fall through to policy. */
		CALI_DEBUG("VXLAN: Not our VNI\n");
		goto fall_through;
	}
	if (!rt_addr_is_remote_host(ip_hdr(ctx)->saddr)) {
		CALI_DEBUG("VXLAN with our VNI from unexpected source.\n");
		deny_reason(ctx, CALI_REASON_UNAUTH_SOURCE);
		goto deny;
	}
	if (!vxlan_udp_csum_ok(udp_hdr(ctx))) {
		/* Our VNI but checksum is incorrect (we always use check=0). */
		CALI_DEBUG("VXLAN with our VNI but incorrect checksum.\n");
		deny_reason(ctx, CALI_REASON_UNAUTH_SOURCE);
		goto deny;
	}

	ctx->arpk.ip = ip_hdr(ctx)->saddr;
	ctx->arpk.ifindex = ctx->skb->ifindex;

	/* We update the map straight with the packet data, eth header is
	 * dst:src but the value is src:dst so it flips it automatically
	 * when we use it on xmit.
	 */
	cali_arp_update_elem(&ctx->arpk, eth_hdr(ctx), 0);
	CALI_DEBUG("ARP update for ifindex %d ip %x\n", ctx->arpk.ifindex, bpf_ntohl(ctx->arpk.ip));

	ctx->state->tun_ip = ip_hdr(ctx)->saddr;
	CALI_DEBUG("vxlan decap\n");
	if (vxlan_v4_decap(ctx->skb)) {
		deny_reason(ctx, CALI_REASON_DECAP_FAIL);
		goto deny;
	}

	/* Revalidate the packet after the decap. */
	if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("Too short\n");
		goto deny;
	}

	CALI_DEBUG("vxlan decap origin %x\n", bpf_ntohl(ctx->state->tun_ip));

fall_through:
	return 0;

auto_allow:
	return -2;

deny:
	ctx->fwd.res = TC_ACT_SHOT;
	return -1;
}

#endif /* __CALI_NAT4_H__ */
