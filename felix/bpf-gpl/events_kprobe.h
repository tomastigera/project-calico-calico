// Project Calico BPF dataplane programs.
// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_EVENTS_KPROBE_H__
#define __CALI_EVENTS_KPROBE_H__

#include "log.h"
#include "bpf.h"
#include "ringbuf.h"
#include "sock.h"
#include "events_type.h"

#define TASK_COMM_LEN 16


struct event_proto_stats {
	struct event_header hdr;
	__u32 pid;
	__u32 proto;
	__u8  saddr[16];
	__u8  daddr[16];
	__u16 sport;
	__u16 dport;
	__u32 bytes;
	__u32 sndBuf;
	__u32 rcvBuf;
	char taskName[TASK_COMM_LEN];
	__u32 isRx;
};

static CALI_BPF_INLINE int event_bpf_stats(__u32 pid,
					      __u8 *saddr, __u16 sport, __u8 *daddr,
					      __u16 dport, __u32 bytes, __u32 proto, __u32 isRx)
{
	struct event_proto_stats event = {
		.hdr.len = sizeof(struct event_proto_stats),
		.hdr.type = EVENT_PROTO_STATS,
		.pid = pid,
		.proto = proto,
		.sport = sport,
		.dport = bpf_ntohs(dport),
		.bytes = bytes,
		.isRx = isRx,
	};

	bpf_get_current_comm(&event.taskName, sizeof(event.taskName));
	__builtin_memcpy(event.saddr, saddr, 16);
	__builtin_memcpy(event.daddr, daddr, 16);
	int err = ringbuf_submit_event(&event, sizeof(event));
	if (err != 0) {
		CALI_DEBUG("event_proto_stats: ringbuf_submit_event returns %d\n", err);
	}

	return err;
}

#endif /* __CALI_EVENTS_KPROBE_H__ */
