// Project Calico BPF dataplane programs.
// Copyright (c) 2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_KPROBE_H__
#define __CALI_KPROBE_H__

#include <linux/in.h>
#include <asm/ptrace.h>

#include "bpf.h"
#include "ringbuf.h"
#include <bpf_tracing.h>

#define SEND_DATA_INTERVAL 10000000000
#define MAX_FILENAME_LENGTH 128
#define MAX_ARG_LENGTH 64
#define MAX_NUM_ARGS 5
struct __attribute__((__packed__)) calico_kprobe_stats_key {
	__u8  saddr[16];
	__u8  daddr[16];
	__u16 sport;
	__u16 dport;
	__u32 pid;
	__u16 proto;
	__u16  dir;
};

struct calico_kprobe_stats_value {
	__u32 bytes;
	__u64	timestamp;
};

CALI_MAP(cali_kpstats, 2,
                BPF_MAP_TYPE_LRU_HASH,
                struct calico_kprobe_stats_key, struct calico_kprobe_stats_value,
                511000, 0)

struct __attribute__((__packed__)) calico_exec_value {
	struct event_header hdr;
	__u32 pid;
	char filename[MAX_FILENAME_LENGTH];
	char args[MAX_NUM_ARGS][MAX_ARG_LENGTH];
};

CALI_MAP(cali_epath, 2,
                BPF_MAP_TYPE_LRU_HASH,
                __u32, struct calico_exec_value,
                64000, 0)

CALI_MAP(cali_exec, 2,
                BPF_MAP_TYPE_PERCPU_ARRAY,
                __u32, struct calico_exec_value,
                1, 0)

static int CALI_BPF_INLINE ip_addr_is_localhost(__u8 *addr) {
	return (addr[12] == 0x7f);
}

static int CALI_BPF_INLINE ip_addr_is_zero(__u8 *addr) {
	__u64 *a64 = (__u64*)addr;

	return (a64[0] == 0 && a64[1] == 0);
}

static int CALI_BPF_INLINE kprobe_collect_stats(struct pt_regs *ctx,
						struct sock_common *sk_cmn,
						__u16 proto,
						int bytes,
						__u16 tx)
{
	__u16 family = 0;
	__u64 ts = 0, diff = 0;
	int ret = 0;
	struct calico_kprobe_stats_value value = {};
	struct calico_kprobe_stats_value *val = NULL;
	struct calico_kprobe_stats_key key = {};
	struct calico_exec_value *exec_value = NULL;

	if (!sk_cmn) {
		return 0;
	}

	bpf_probe_read(&family, 2, &sk_cmn->skc_family);
	if (family == 2 /* AF_INET */) {
		bpf_probe_read(&key.saddr[12], 4, &sk_cmn->skc_rcv_saddr);
		bpf_probe_read(&key.daddr[12], 4, &sk_cmn->skc_daddr);
	} else if (family == 10 /* AF_INET6 */) {
		bpf_probe_read(key.saddr, 16, sk_cmn->skc_v6_rcv_saddr.in6_u.u6_addr8);
		bpf_probe_read(key.daddr, 16, sk_cmn->skc_v6_daddr.in6_u.u6_addr8);
	} else {
		CALI_DEBUG("unknown IP family.Ignoring\n");
		return 0;
	}

	bpf_probe_read(&key.sport, 2, &sk_cmn->skc_num);
	bpf_probe_read(&key.dport, 2, &sk_cmn->skc_dport);

	/* Do not send data when any of src ip,src port, dst ip, dst port is 0 or
	 * dstIP is a localhost. This being the socket data, value of 0 indicates
	 * a socket in listening state. Further data cannot be correlated in felix.
	 * In case of localhost, we do not log any flows to the localhost. Skipping
	 * this will bring down the number of events sent to felix.
	 */
	if (!key.sport || !key.dport || ip_addr_is_zero(key.saddr) || ip_addr_is_zero(key.daddr) ||
			ip_addr_is_localhost(key.daddr)) {
		return 0;
	}

	key.pid = bpf_get_current_pid_tgid() >> 32;
	ts = bpf_ktime_get_ns();
	if (family == 2) {
		// v4Inv6Prefix {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff}
		key.saddr[10] = key.saddr[11] = key.daddr[10] = key.daddr[11] = 0xff;
	}

	key.proto = proto;
	key.dir = !tx;

	val = cali_kpstats_lookup_elem(&key);
	if (val == NULL) {
		value.bytes = bytes;
		/* Felix will see the process path event (including the PID) and
		 * then the BPF stats event (also including the PID) and so
		 * will be able to connect the two events together.
		 */
		exec_value = cali_epath_lookup_elem(&key.pid);
		if (exec_value) {
			int err = ringbuf_submit_event(exec_value, sizeof(struct calico_exec_value));
			if (err) {
				CALI_DEBUG("error sending process path: %d\n", err);
			}
		}
		ret = event_bpf_stats(key.pid, key.saddr, key.sport, key.daddr,
					key.dport, value.bytes, proto, !tx);
		if (ret == 0) {
			/* Set the timestamp only if we managed to send the event.
			 * Otherwise zero timestamp makes the next call to try to send the
			 * event again.
			 */
			value.timestamp = ts;
		}
		ret = cali_kpstats_update_elem(&key, &value, 0);
	} else {
		diff = ts - val->timestamp;
		if (diff >= SEND_DATA_INTERVAL) {
			ret = event_bpf_stats(key.pid, key.saddr, key.sport,
						key.daddr, key.dport, value.bytes, proto, !tx);
			if (ret == 0) {
				/* Update the timestamp only if we managed to send the
				 * event. Otherwise keep the old timestamp so that next
				 * call will try to send the event again.
				 */
				val->timestamp = ts;
			}
		}
		val->bytes += bytes;
	}
	return 0;
}

static int CALI_BPF_INLINE kprobe_stats_body(struct pt_regs *ctx, __u16 proto, __u16 tx, bool is_connect)
{
	int bytes = 0;
	struct sock_common *sk_cmn = NULL;

	sk_cmn = (struct sock_common*)PT_REGS_PARM1(ctx);
	/* In case tcp_cleanup_rbuf, second argument is the number of bytes copied
	 * to user space
	 */
	if (is_connect) {
		bytes = 0;
	} else if (proto == IPPROTO_TCP && !tx) {
		bytes = (int)PT_REGS_PARM2(ctx);
	} else {
		bytes = (int)PT_REGS_PARM3(ctx);
	}
	return kprobe_collect_stats(ctx, sk_cmn, proto, bytes, tx);
}


#endif /* __CALI_KPROBE_H__ */
