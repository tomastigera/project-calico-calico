// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_PARSING6_H__
#define __CALI_PARSING6_H__

static CALI_BPF_INLINE int parse_packet_ip_v6(struct cali_tc_ctx *ctx) {
	__u16 protocol = 0;

	/* We need to make a decision based on Ethernet protocol, however,
	 * the protocol number is not available to XDP programs like TC ones.
	 * In TC programs protocol number is available via skb->protocol.
	 * For that, in XDP programs we need to parse at least up to Ethernet
	 * first, before making any decision. But in TC programs we can make
	 * an initial decision based on Ethernet protocol before parsing packet
	 * for more headers.
	 */
	if (CALI_F_XDP) {
		if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
			deny_reason(ctx, CALI_REASON_SHORT);
			CALI_DEBUG("Too short\n");
			goto deny;
		}
		protocol = bpf_ntohs(eth_hdr(ctx)->h_proto);
	} else {
		protocol = bpf_ntohs(ctx->skb->protocol);
	}

	switch (protocol) {
	case ETH_P_IPV6:
		break;
	default:
		if (CALI_F_WEP) {
			CALI_DEBUG("Unknown ethertype (%x), drop\n", protocol);
			goto deny;
		} else {
			CALI_DEBUG("Unknown ethertype on host interface (%x), allow\n",
									protocol);
			goto allow_no_fib;
		}
	}

	// In TC programs, parse packet and validate its size. This is
	// already done for XDP programs at the beginning of the function.
	if (!CALI_F_XDP) {
		if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
			deny_reason(ctx, CALI_REASON_SHORT);
			CALI_DEBUG("Too short\n");
			goto deny;
		}
	}

#if 0
	CALI_DEBUG("IP id=%d\n",bpf_ntohs(ip_hdr(ctx)->id));
	CALI_DEBUG("IP s=%x d=%x\n", bpf_ntohl(ip_hdr(ctx)->saddr), bpf_ntohl(ip_hdr(ctx)->daddr));
	// Drop malformed IP packets
	if (ip_hdr(ctx)->ihl < 5) {
		CALI_DEBUG("Drop malformed IP packets\n");
		deny_reason(ctx, CALI_REASON_IP_MALFORMED);
		goto deny;
	} else if (ip_hdr(ctx)->ihl > 5) {
		/* Drop packets with IP options from/to WEP.
		 * Also drop packets with IP options if the dest IP is not host IP
		 */
		ctx->ipheader_len = 4 * ip_hdr(ctx)->ihl;
	}
	CALI_DEBUG("IP ihl=%d bytes\n", ctx->ipheader_len);
#endif

	return PARSING_OK_V6;

allow_no_fib:
	return PARSING_ALLOW_WITHOUT_ENFORCING_POLICY;

deny:
	return PARSING_ERROR;
}

static CALI_BPF_INLINE void tc_state_fill_from_iphdr_v6(struct cali_tc_ctx *ctx)
{
	// Fill in source ip
	ctx->state->ip_src  = ip_hdr(ctx)->saddr.in6_u.u6_addr32[0];
	ctx->state->ip_src1 = ip_hdr(ctx)->saddr.in6_u.u6_addr32[1];
	ctx->state->ip_src2 = ip_hdr(ctx)->saddr.in6_u.u6_addr32[2];
	ctx->state->ip_src3 = ip_hdr(ctx)->saddr.in6_u.u6_addr32[3];
	// Fill in dst ip
	ctx->state->ip_dst  = ip_hdr(ctx)->daddr.in6_u.u6_addr32[0];
	ctx->state->ip_dst1 = ip_hdr(ctx)->daddr.in6_u.u6_addr32[1];
	ctx->state->ip_dst2 = ip_hdr(ctx)->daddr.in6_u.u6_addr32[2];
	ctx->state->ip_dst3 = ip_hdr(ctx)->daddr.in6_u.u6_addr32[3];
	// Fill in pre nat ip
	ctx->state->pre_nat_ip_dst  = ip_hdr(ctx)->daddr.in6_u.u6_addr32[0];
	ctx->state->pre_nat_ip_dst1 = ip_hdr(ctx)->daddr.in6_u.u6_addr32[1];
	ctx->state->pre_nat_ip_dst2 = ip_hdr(ctx)->daddr.in6_u.u6_addr32[2];
	ctx->state->pre_nat_ip_dst3 = ip_hdr(ctx)->daddr.in6_u.u6_addr32[3];
	// Fill in other information
	ctx->state->ip_proto = ip_hdr(ctx)->nexthdr;
	ctx->state->ip_size = ip_hdr(ctx)->payload_len;
}

#endif /* __CALI_PARSING6_H__ */
