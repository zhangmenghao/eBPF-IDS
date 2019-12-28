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
#define IDS_INSPECT_MAP_SIZE 16777216
#define IDS_INSPECT_DEPTH 1600

struct bpf_map_def SEC("maps") ids_inspect_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(struct ids_inspect_map_key),
	.value_size = sizeof(struct ids_inspect_map_value),
	.max_entries = IDS_INSPECT_MAP_SIZE,
};

struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 64,  /* Assume netdev has no more than 64 queues */
};

static __always_inline int inspect_payload(struct hdr_cursor *nh,void *data_end)
{
	// struct ids_inspect_unit *ids_unit = nh->pos;
	ids_inspect_unit *ids_unit;
	struct ids_inspect_map_key ids_map_key;
	struct ids_inspect_map_value *ids_map_value;
	int i;

	ids_map_key.state = 0;
	ids_map_key.padding = 0;

	#pragma unroll
	for (i = 0; i < IDS_INSPECT_DEPTH; i++) {
		ids_unit = nh->pos;
		if (ids_unit + 1 > data_end) {
			/* Reach the last byte of the packet */
			return 0;
		}
		// memcpy(ids_map_key.unit.unit, ids_unit, IDS_INSPECT_STRIDE);
		// memcpy(&(ids_map_key.unit), ids_unit, IDS_INSPECT_STRIDE);
		ids_map_key.unit = *ids_unit;
		ids_map_value = bpf_map_lookup_elem(&ids_inspect_map, &ids_map_key);
		if (ids_map_value) {
			/* Go to the next state according to DFA */
			ids_map_key.state = ids_map_value->state;
			if (ids_map_value->flag > 0) {
				/* An acceptable state, return the hit pattern number */
				return ids_map_value->flag;
			}
		}
		/* Prepare for next scanning */
		nh->pos += 1;
	}

	/* The payload is not inspected completely */
	return -1;
}

SEC("xdp_ids")
int xdp_ids_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u32 rx_queue_index = ctx->rx_queue_index;
	int send_to_userspace = 0;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

	if (send_to_userspace) {
		/* A set entry here means that the correspnding queue_id
		 * has an active AF_XDP socket bound to it. */
		action = bpf_redirect_map(&xsks_map, rx_queue_index, 0);
		goto out;
	}

	/* Parse packet */
	struct hdr_cursor nh;
	int eth_type, ip_type;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct udphdr *udph;
	struct tcphdr *tcph;
	int ids_state = 0;

	nh.pos = data;
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
		}
	} else if (ip_type == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &udph) < 0) {
			action = XDP_ABORTED;
			goto out;
		}
	} else {
		goto out;
	}

	ids_state = inspect_payload(&nh, data_end);
	if (ids_state > 0) {
		action = XDP_DROP;
		bpf_printk("The %dth pattern is triggered\n", ids_state);
	}

out:
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return xdp_stats_record_action(ctx, XDP_PASS);
}

SEC("xdp_drop")
int xdp_drop_func(struct xdp_md *ctx)
{
	return xdp_stats_record_action(ctx, XDP_DROP);
}

char _license[] SEC("license") = "GPL";
