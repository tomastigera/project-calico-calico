// Project Calico BPF dataplane programs.
// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_DNS_H__
#define __CALI_DNS_H__

#include "bpf.h"
#include "ringbuf.h"
#include "events.h"
#include "sock.h"
#include "sendrecv.h"

/* Maximum packet length we can copy into the ring buffer.
 * Bounded for BPF verifier safety; covers jumbo frames.
 */
#define DNS_MAX_PLEN 9000

struct dns_scratch_buf {
	struct event_timestamp_header hdr;
	char pkt[DNS_MAX_PLEN];
};

CALI_MAP_V1(cali_dns_scratch,
		BPF_MAP_TYPE_PERCPU_ARRAY,
		__u32, struct dns_scratch_buf,
		1, 0)

static CALI_BPF_INLINE void calico_report_dns(struct cali_tc_ctx *ctx)
{
	int plen = ctx->skb->len;
	if (plen <= 0) {
		return;
	}
	if (plen > DNS_MAX_PLEN) {
		plen = DNS_MAX_PLEN;
	}

	__u32 zero = 0;
	struct dns_scratch_buf *buf = cali_dns_scratch_lookup_elem(&zero);
	if (!buf) {
		return;
	}

	__builtin_memset(&buf->hdr, 0, sizeof(buf->hdr));
	if (CALI_F_L3) {
		buf->hdr.h.type = EVENT_DNS_L3;
	} else {
		buf->hdr.h.type = EVENT_DNS;
	}
	__u64 total = sizeof(struct event_timestamp_header) + plen;
	buf->hdr.h.len = total;
	buf->hdr.timestamp_ns = bpf_ktime_get_ns();

	int err = bpf_skb_load_bytes(ctx->skb, 0, buf->pkt, plen);
	if (err) {
		CALI_DEBUG("bpf_skb_load_bytes error %d\n", err);
		return;
	}

	ringbuf_submit_event(buf, total);
}

static CALI_BPF_INLINE bool calico_check_for_dns(struct cali_tc_ctx *ctx)
{
	bool reported = false;

#ifndef IPVER6
	// Support UDP only; bail for TCP or any other IP protocol.
	if (ctx->state->ip_proto != IPPROTO_UDP) {
		return false;
	}

	ipv46_addr_t dst_ip = ctx->state->ip_dst;
	__be16 dst_port = bpf_htons(ctx->state->dport);

	// For the case where the packet was sent from a socket on this host, get the
	// sending socket's cookie, so we can reverse a DNAT that that socket may have
	// already done.
	__u64 cookie = bpf_get_socket_cookie(ctx->skb);
	if (!cookie) {
		// Expected if the packet was sent from outside the host.  We shouldn't
		// currently see this, because the `calico_check_for_dns` call is guarded
		// by CALI_F_FROM_WEP || CALI_F_TO_HEP.  But this branch can come into
		// play if we have a future requirement for snooping DNS lookups that are
		// originated from another host.  In that case, stick with the dest IP and
		// port that we already have in hand.
		CALI_DEBUG("failed to get socket cookie for possible DNS request\n");
	} else {
		CALI_DEBUG("Got socket cookie 0x%lx for possible DNS\n", cookie);

		// Lookup apparent dst IP and port in cali_v4_srmsg map.  If there's a
		// hit, henceforth use dst IP and port from the map entry.  (Hit implies
		// that a DNAT has already happened, because of CTLB being in use, and now
		// the message has the post-DNAT IP and port.  Miss implies that CTLB
		// isn't in use or DNAT hasn't happened yet; in those cases the message in
		// hand still has the dst IP and port that we need.)
		struct sendrec_key key = {
			.ip	= dst_ip,
			.port	= dst_port,
			.cookie	= cookie,
		};
		struct sendrec_val *revnat = cali_srmsg_lookup_elem(&key);
		if (revnat) {
			CALI_DEBUG("Got cali_v4_srmsg entry\n");
			dst_ip = revnat->ip;
			dst_port = bpf_htons(ctx_port_to_host(revnat->port));
		} else {
			CALI_DEBUG("No cali_v4_srmsg entry\n");
		}
	}
	CALI_DEBUG("Now have dst IP 0x%x port %d\n", debug_ip(dst_ip), bpf_ntohs(dst_port));

	// Compare dst IP and port against 'ipset' for trusted DNS servers.
	struct ip_set_key sip;
	__builtin_memset(&sip, 0, sizeof(sip));
	sip.mask = 32 /* IP prefix length */ + 64 /* Match ID */ + 16 /* Match port */ + 8 /* Match protocol */;
	sip.set_id = bpf_cpu_to_be64(TRUSTED_DNS_SERVERS_ID);
	sip.addr = dst_ip;
	sip.port = bpf_ntohs(dst_port);
	sip.protocol = 17;

	if (cali_ip_sets_lookup_elem(&sip)) {
		CALI_DEBUG("Dst IP/port are trusted for DNS\n");
		// Store 'trusted DNS connection' status in conntrack entry.
		ctx->state->ct_result.flags |= CALI_CT_FLAG_TRUST_DNS;
		// Emit event to pass (presumed) DNS request up to Felix
		// userspace.
		CALI_DEBUG("report probable DNS request\n");
		calico_report_dns(ctx);
		reported = true;
	} else {
		CALI_DEBUG("Dst IP/port are not trusted for DNS\n");
	}

#endif
	return reported;
}

static CALI_BPF_INLINE bool calico_dns_check(struct cali_tc_ctx *ctx)
{
	bool reported = false;
	if (ctx->state->ip_proto == IPPROTO_UDP) {
		// UDP.  We need to recheck this, even when we know that the connection is
		// trusted for DNS, because an ICMP packet can also match the conntrack
		// state for an existing (and trusted) UDP connection.
		if ((ctx->state->ct_result.flags & CALI_CT_FLAG_TRUST_DNS) &&
		    ((ctx->state->ct_result.ifindex_created == ctx->skb->ifindex) ||
		     (ctx->state->ct_result.ifindex_created == CT_INVALID_IFINDEX) ||
		     (ct_result_rc(ctx->state->ct_result.rc) == CALI_CT_ESTABLISHED_BYPASS))) {
			// This is either an inbound response, or an outbound request, on
			// an existing connection that is trusted for DNS information.  A
			// common pattern appears to be for a DNS client to send A and
			// AAAA lookups on (what we perceive as) the same UDP connection,
			// and we want to report both; otherwise when Felix handles the
			// AAAA response it won't be able to calculate a latency.
			//
			// Instead of checking CALI_F_TO/FROM_WEP/HEP, the principle here
			// is to report any packet on a trusted DNS connection when it is
			// passing through the same interface as that where the trusted
			// DNS connection CT state was first created.  Note that this
			// logic works both for responses and subsequent requests.
			//
			// Except... if a response comes through _another_ HEP/WEP
			// interface first, that interface's TC program can set the
			// CALI_SKB_MARK_BYPASS mark on the packet, when it knows that the
			// packet could safely - from a policy perspective - skip all
			// further TC programs.  So if we're in a TC program that's about
			// to do that, we have to report now, as we won't have a chance in
			// the TC program for the interface where the CT state was
			// created.  CALI_SKB_MARK_BYPASS is only used when there is no
			// NAT in the data path (on this host), so we _can_ correctly
			// report the DNS packet from here, as we know the IPs and ports
			// are the same as they would be at the interface that created the
			// CT state.
			CALI_DEBUG("report packet on trusted DNS connection\n");
			calico_report_dns(ctx);
			reported = true;
		} else if ((CALI_F_FROM_WEP || CALI_F_TO_WEP || CALI_F_TO_HEP) &&
			   (ct_result_rc(ctx->state->ct_result.rc) == CALI_CT_NEW) &&
			   !skb_seen(ctx->skb)) {
			// New connection: check if it's to a trusted DNS server.
			// Connection can be outbound, from a local workload or from a
			// host-networked client, or from a host-networked client _to_ a
			// local workload server.
			//
			// We use `skb_seen` here to avoid reporting the same outbound DNS
			// request up to Felix twice, and to avoid marking the CT state at
			// the HEP - if different from the CT state at the WEP - as
			// trusted for DNS.  The CT states _will_ be different if the node
			// is doing an SNAT for outgoing traffic, and in that case, for a
			// DNS lookup from a workload, we only want to handle the packets
			// with the WEP CT state, so that we only get one DNS log per
			// exchange, and with the correct workload details.
			reported = calico_check_for_dns(ctx);
		}
	}

	return reported;
}

#endif /* __CALI_DNS_H__ */
