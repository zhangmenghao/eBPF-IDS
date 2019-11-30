/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

// The parsing helper functions from the packet01 lesson have moved here
#include "common/parsing_helpers.h"
#include "common/rewrite_helpers.h"

/* Defines xdp_stats_map */
#include "common/xdp_stats_kern_user.h"
#include "common/xdp_stats_kern.h"

#include "common_kern_user.h"

#define MAX_ENTRIES 256
#define MAX_PAYLOAD_DEPTH 100
#define ACCEPTED_STATE 3

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

struct payload {
	__u8 payload;
};

struct bpf_map_def SEC("maps") IDS_state_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(struct match),
	.value_size = sizeof(struct action),
	.max_entries = MAX_ENTRIES,
};

static __always_inline int parse_payload(struct hdr_cursor *nh,
					void *data_end){
	struct payload *pl = nh->pos;
	int i;
	struct match mat;
	mat.state = 0;
	mat.padding = 0;

	#pragma unroll
	for (i = 0; i < MAX_PAYLOAD_DEPTH; i ++){
		if (pl + 1 > data_end){
			break;
		}
		
		mat.chars = pl->payload;
		struct action *act = bpf_map_lookup_elem(&IDS_state_map, &mat);
		if (!act){
			mat.state = 0;
		}
		else if (act->state == ACCEPTED_STATE){
			return XDP_DROP;
		}
		else{
			mat.state = act->state;
		}
		pl ++;

	}
	return XDP_TX;
}

SEC("xdp_IDS")
int xdp_IDS_func(struct xdp_md *ctx){
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;
	__u32 action = XDP_PASS; /* Default action */
	
	//layer 2
	struct ethhdr *eth;
	nh_type = parse_ethhdr(&nh, data_end, &eth);

	//layer 3
	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h;
		nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
	} 
	else if (nh_type == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph;		
		nh_type = parse_iphdr(&nh, data_end, &iph);
	}
	else{
		action = XDP_ABORTED;
	}

	//layer 4
	if (nh_type == IPPROTO_TCP){
		struct tcphdr *tcphdr; 
		if (parse_tcphdr(&nh, data_end, & tcphdr) < 0){
			action = XDP_ABORTED;
		}
		action = parse_payload(&nh, data_end);
	}
	else if (nh_type == IPPROTO_UDP){
		struct udphdr *udphdr; 
		if (parse_udphdr(&nh, data_end, & udphdr) < 0){
			action = XDP_ABORTED;
		}
		action = parse_payload(&nh, data_end);
	}
	else if (nh_type == IPPROTO_ICMPV6){
		struct icmp6hdr *icmp6h;
		nh_type = parse_icmp6hdr(&nh, data_end, &icmp6h);
		if (nh_type != ICMPV6_ECHO_REQUEST){
			action = XDP_ABORTED;
		}
		action = parse_payload(&nh, data_end);
	}
	else if (nh_type == IPPROTO_ICMP){
		struct icmphdr *icmph;
		nh_type = parse_icmphdr(&nh, data_end, &icmph);
		if (nh_type != ICMP_ECHO){
			action = XDP_ABORTED;
		}
		action = parse_payload(&nh, data_end);
	}
	else{
		action = XDP_ABORTED;
	}
	
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx){
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
