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


#endif /* __CALI_NAT_H__ */
