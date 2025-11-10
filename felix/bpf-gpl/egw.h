// Project Calico BPF dataplane programs.
// Copyright (c) 2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_EGW_H__
#define __CALI_EGW_H__

#include "bpf.h"


static CALI_BPF_INLINE bool is_egw_health_packet(ipv46_addr_t *ip, __be16 port)
{
#ifndef IPVER6
	struct ip_set_key sip = {
		.mask = 32 /* IP prefix length */ + 64 /* Match ID */ + 16 /* Match port */ + 8 /* Match protocol */,
		.set_id = bpf_cpu_to_be64(EGRESS_GW_HEALTH_ID),
		.addr = *ip,
		.port = port,
		.protocol = 6
	};
	if (cali_ip_sets_lookup_elem(&sip)) {
		return true;
	}
#endif
	return false;
}
#endif

