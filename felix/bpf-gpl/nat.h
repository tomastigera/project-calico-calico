// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_NAT_H__
#define __CALI_NAT_H__

#ifndef CALI_VXLAN_VNI
#define CALI_VXLAN_VNI 0xca11c0
#endif

#define vxlan_udp_csum_ok(udp) ((udp)->check == 0)

#ifdef IPVER6
#else
#include "nat4.h"
#endif

#define dnat_should_encap() (CALI_F_FROM_HEP && !CALI_F_TUNNEL && !CALI_F_L3_DEV && !CALI_F_NAT_IF)
#define dnat_return_should_encap() (CALI_F_FROM_WEP && !CALI_F_TUNNEL && !CALI_F_L3_DEV && !CALI_F_NAT_IF)
#define dnat_should_decap() (CALI_F_FROM_HEP && !CALI_F_TUNNEL && !CALI_F_L3_DEV && !CALI_F_NAT_IF)

static CALI_BPF_INLINE int is_vxlan_tunnel(struct cali_tc_ctx *ctx, __u16 vxlanport)
{
	return ctx->state->ip_proto == IPPROTO_UDP &&
		ctx->state->dport == vxlanport;
}

#ifdef IPVER6
static CALI_BPF_INLINE int vxlan_attempt_decap(struct cali_tc_ctx *ctx)
{
	ctx->fwd.res = TC_ACT_SHOT;
	return -1;
}
#else
static CALI_BPF_INLINE int vxlan_attempt_decap(struct cali_tc_ctx *ctx)
{
	return vxlan_attempt_decap_v4(ctx);
}
#endif

static CALI_BPF_INLINE bool vxlan_encap_too_big(struct cali_tc_ctx *ctx)
{
	__u32 mtu = TUNNEL_MTU;

	/* RFC-1191: MTU is the size in octets of the largest datagram that
	 * could be forwarded, along the path of the original datagram, without
	 * being fragmented at this router.  The size includes the IP header and
	 * IP data, and does not include any lower-level headers.
	 */
	if (ctx->skb->len > sizeof(struct ethhdr) + mtu) {
		CALI_DEBUG("SKB too long (len=%d) vs limit=%d\n", ctx->skb->len, mtu);
		return true;
	}
	return false;
}

#define EFAULT	14

static CALI_BPF_INLINE int skb_nat_l4_csum(struct cali_tc_ctx *ctx, size_t off,
					   ipv46_addr_t ip_src_from, ipv46_addr_t ip_src_to,
					   ipv46_addr_t ip_dst_from, ipv46_addr_t ip_dst_to,
					   __u16 dport_from, __u16 dport_to,
					   __u16 sport_from, __u16 sport_to,
					   __u64 flags)
{
	int ret = 0;
	struct __sk_buff *skb = ctx->skb;

	/* Write back L4 header. */
	if (ctx->ipheader_len == IP_SIZE) {
		if (ctx->state->ip_proto == IPPROTO_TCP) {
			if (skb_refresh_validate_ptrs(ctx, TCP_SIZE)) {
				deny_reason(ctx, CALI_REASON_SHORT);
				CALI_DEBUG("Too short\n");
				return -EFAULT;
			}
			__builtin_memcpy(((void*)ip_hdr(ctx))+IP_SIZE, ctx->scratch->l4, TCP_SIZE);
		} else {
			if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
				deny_reason(ctx, CALI_REASON_SHORT);
				CALI_DEBUG("Too short\n");
				return -EFAULT;
			}
			__builtin_memcpy(((void*)ip_hdr(ctx))+IP_SIZE, ctx->scratch->l4, UDP_SIZE);
		}
	} else {
		int size = l4_hdr_len(ctx);
		int offset = skb_l4hdr_offset(ctx);

		if (size == 0) {
			CALI_DEBUG("Bad L4 proto\n");
			return -EFAULT;
		}
		if (bpf_skb_store_bytes(ctx->skb, offset, ctx->scratch->l4, size, 0)) {
			CALI_DEBUG("Too short\n");
			return -EFAULT;
		}
	}

	__wsum csum = tcp_hdr(ctx)->check;
	bool csum_update = false;

	if (!ip_equal(ip_src_from, ip_src_to)) {
		CALI_DEBUG("L4 checksum update src IP from %x to %x\n",
				debug_ip(ip_src_from), debug_ip(ip_src_to));

		csum = bpf_csum_diff((__u32*)&ip_src_from, sizeof(ip_src_from), (__u32*)&ip_src_to, sizeof(ip_src_to), csum);
		CALI_DEBUG("bpf_l4_csum_replace(IP): 0x%x\n", csum);
		csum_update = true;
	}
	if (!ip_equal(ip_dst_from, ip_dst_to)) {
		CALI_DEBUG("L4 checksum update dst IP from %x to %x\n",
				debug_ip(ip_dst_from), debug_ip(ip_dst_to));
		csum = bpf_csum_diff((__u32*)&ip_dst_from, sizeof(ip_dst_from), (__u32*)&ip_dst_to, sizeof(ip_dst_to), csum);
		CALI_DEBUG("bpf_l4_csum_replace(IP): 0x%x\n", csum);
		csum_update = true;
	}

	if (csum_update) {
		ret = bpf_l4_csum_replace(skb, off, 0, csum, flags | 0);
	}

	if (sport_from != sport_to) {
		CALI_DEBUG("L4 checksum update sport from %d to %d\n",
				bpf_ntohs(sport_from), bpf_ntohs(sport_to));
		int rc = bpf_l4_csum_replace(skb, off, sport_from, sport_to, flags | 2);
		CALI_DEBUG("bpf_l4_csum_replace(sport): %d\n", rc);
		ret |= rc;
	}
	if (dport_from != dport_to) {
		CALI_DEBUG("L4 checksum update dport from %d to %d\n",
				bpf_ntohs(dport_from), bpf_ntohs(dport_to));
		int rc = bpf_l4_csum_replace(skb, off, dport_from, dport_to, flags | 2);
		CALI_DEBUG("bpf_l4_csum_replace(dport): %d\n", rc);
		ret |= rc;
	}

	return ret;
}

#endif /* __CALI_NAT_H__ */
