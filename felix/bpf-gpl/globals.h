// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_GLOBALS_H__
#define __CALI_GLOBALS_H__

struct cali_tc_globals {
	__be32 host_ip;
	__be16 tunnel_mtu;
	__be16 vxlan_port;
	__be32 intf_ip;
	__be32 ext_to_svc_mark;
	__be16 psnat_start;
	__be16 psnat_len;
	__be32 host_tunnel_ip;
	__be32 flags;
	__be32 bpfnatout_idx;
	__be32 bpfnatin_mac0;
	__be16 bpfnatin_mac1;
	__be16 __pad0;
};

enum cali_globals_flags {
	/* CALI_GLOBALS_IPV6_ENABLED is set when IPv6 is enabled by Felix */
	CALI_TC_GLOBALS_IPV6_ENABLED	= 0x1,
	CALI_TC_GLOBALS_REDIRECT_NATIF	= 0x2,
};

struct cali_ctlb_globals {
	__be32 udp_not_seen_timeo;
};

#endif /* __CALI_GLOBALS_H__ */
