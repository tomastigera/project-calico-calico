// Project Calico BPF dataplane programs.
// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_EVETNS_H__
#define __CALI_EVETNS_H__

#include "bpf.h"
#include "types.h"
#include "ringbuf.h"
#include "sock.h"
#include "jump.h"
#include "events_type.h"
#include "log.h"

struct event_tcp_stats {
	struct event_header hdr;
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 sport;
	__u16 dport;
	__u32 snd_cwnd;
	__u32 srtt_us;
	__u32 rtt_min;
	__u32 mss_cache;
	__u32 total_retrans;
	__u32 lost_out;
	__u32 icsk_retransmits;
};

static CALI_BPF_INLINE void event_tcp_stats(struct cali_tc_ctx *ctx, struct event_tcp_stats *event) {
	int err = ringbuf_submit_event(event, sizeof(struct event_tcp_stats));
	if (err != 0) {
		CALI_DEBUG("tcp stats: ringbuf_submit_event returns %d\n", err);
	}
}

static CALI_BPF_INLINE void event_flow_log(struct cali_tc_ctx *ctx)
{
#ifndef IPVER6
	ctx->state->eventhdr.type = EVENT_POLICY_VERDICT,
#else
	ctx->state->eventhdr.type = EVENT_POLICY_VERDICT_V6,
#endif
	ctx->state->eventhdr.len = offsetof(struct cali_tc_state, rule_ids) + sizeof(__u64) * MAX_RULE_IDS + sizeof(struct calico_ct_result);

	/* Due to stack space limitations, the begining of the state is structured as the
	 * event and so we can send the data straight without copying in BPF.
	 */
	int err = ringbuf_submit_event(ctx->state, ctx->state->eventhdr.len);

	if (err != 0) {
		CALI_DEBUG("event_flow_log: ringbuf_submit_event returns %d\n", err);
	}
}

#endif /* __CALI_EVETNS_H__ */
