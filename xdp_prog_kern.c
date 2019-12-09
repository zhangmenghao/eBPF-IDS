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

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define bpf_printk(fmt, ...)                                    \
({                                                              \
	char ____fmt[] = fmt;                                   \
	bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

#define IDS_INSPECT_STRIDE 1
#define IDS_INSPECT_MAP_SIZE 262144
#define IDS_INSPECT_DEPTH 219

struct bpf_map_def SEC("maps") ids_inspect_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct ids_inspect_map_key),
	.value_size = sizeof(struct ids_inspect_map_value),
	.max_entries = IDS_INSPECT_MAP_SIZE,
};

static __always_inline __u16 inspect_payload(struct hdr_cursor *nh,
											 void *data_end)
{
	// struct ids_inspect_unit *ids_unit = nh->pos;
	ids_inspect_unit *ids_unit = nh->pos;
	struct ids_inspect_map_key ids_map_key;
	struct ids_inspect_map_value *ids_map_value;
	int i;

	ids_map_key.state = 0;
	ids_map_key.padding = 0;

	#pragma unroll
	for (i = 0; i < IDS_INSPECT_DEPTH; i++) {
		if (ids_unit + 1 > data_end) {
			break;
		}
		// memcpy(ids_map_key.unit.unit, ids_unit, IDS_INSPECT_STRIDE);
		// memcpy(&(ids_map_key.unit), ids_unit, IDS_INSPECT_STRIDE);
		ids_map_key.unit = *ids_unit;
		ids_map_value = bpf_map_lookup_elem(&ids_inspect_map, &ids_map_key);
		if (!ids_map_value) {
			/* Default rule: return to the initial state */
			ids_map_key.state = 0;
		} else if (ids_map_value->is_acceptable) {
			/* A pattern is matched */
			return ids_map_value->state;
		} else {
			/* Go to the next state according to DFA */
			ids_map_key.state = ids_map_value->state;
		}
		/* Prepare for next scanning */
		ids_unit += 1;
	}

	return 0;
}

SEC("xdp_ids")
int xdp_ids_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };
	int eth_type, ip_type;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct udphdr *udph;
	struct tcphdr *tcph;
	ids_inspect_state ids_state;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

	eth_type = parse_ethhdr(&nh, data_end, &eth);

	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iph);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ip6h);
	} else {
		goto out;
	}

	if (ip_type == IPPROTO_TCP) {
		if (parse_tcphdr(&nh, data_end, &tcph) < 0) {
			action = XDP_ABORTED;
			goto out;
		} else {
			ids_state = inspect_payload(&nh, data_end);
			if (ids_state > 0) {
				action = XDP_DROP;
				goto out;
			}
		}
	} else if (ip_type == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &udph) < 0) {
			action = XDP_ABORTED;
			goto out;
		} else {
			ids_state = inspect_payload(&nh, data_end);
			if (ids_state > 0) {
				action = XDP_DROP;
				goto out;
			}
		}
	} else {
		goto out;
	}

out:
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx){
	return xdp_stats_record_action(ctx, XDP_PASS);
}

SEC("xdp_drop")
int xdp_drop_func(struct xdp_md *ctx){
	return xdp_stats_record_action(ctx, XDP_DROP);
}

char _license[] SEC("license") = "GPL";
