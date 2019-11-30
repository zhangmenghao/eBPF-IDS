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

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define IDS_INSPECT_STRIDE 1
#define IDS_INSPECT_MAP_SIZE 256
#define IDS_INSPECT_DEPTH 100

/* IDS Inspect Uit */
typedef __u8 ids_inspect_unit;
// struct ids_inspect_unit {
	// __u8 unit[IDS_INSPECT_STRIDE];
// };

/* IDS Inspect State */
typedef __u16 ids_inspect_state;

/* Key-Value of ids_inspect_map */
struct ids_inspect_map_key {
	ids_inspect_state state;
	ids_inspect_unit unit;
	__u8 padding;
};

struct ids_inspect_map_value {
	__u16 final_state;
	ids_inspect_state state;
};

struct bpf_map_def SEC("maps") tx_port = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps") ids_inspect_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct ids_inspect_map_key),
	.value_size = sizeof(struct ids_inspect_map_value),
	.max_entries = IDS_INSPECT_MAP_SIZE,
};

#define AF_INET 2
#define AF_INET6 10
#define IPV6_FLOWINFO_MASK bpf_htonl(0x0FFFFFFF)

/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = iph->check;
	check += bpf_htons(0x0100);
	iph->check = (__u16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

SEC("xdp_router")
int xdp_router_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params = {};
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	__u16 h_proto;
	__u64 nh_off;
	int rc;
	int action = XDP_PASS;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end) {
		action = XDP_DROP;
		goto out;
	}

	h_proto = eth->h_proto;
	if (h_proto == bpf_htons(ETH_P_IP)) {
		iph = data + nh_off;

		if (iph + 1 > data_end) {
			action = XDP_DROP;
			goto out;
		}

		if (iph->ttl <= 1)
			goto out;

		fib_params.family	= AF_INET;
		fib_params.tos		= iph->tos;
		fib_params.l4_protocol	= iph->protocol;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= bpf_ntohs(iph->tot_len);
		fib_params.ipv4_src	= iph->saddr;
		fib_params.ipv4_dst	= iph->daddr;
	} else if (h_proto == bpf_htons(ETH_P_IPV6)) {
		struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src;
		struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst;

		ip6h = data + nh_off;
		if (ip6h + 1 > data_end) {
			action = XDP_DROP;
			goto out;
		}

		if (ip6h->hop_limit <= 1)
			goto out;

		fib_params.family	= AF_INET6;
		fib_params.flowinfo	= *(__be32 *) ip6h & IPV6_FLOWINFO_MASK;
		fib_params.l4_protocol	= ip6h->nexthdr;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= bpf_ntohs(ip6h->payload_len);
		*src			= ip6h->saddr;
		*dst			= ip6h->daddr;
	} else {
		goto out;
	}

	fib_params.ifindex = ctx->ingress_ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	switch (rc) {
	case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
		if (h_proto == bpf_htons(ETH_P_IP))
			ip_decrease_ttl(iph);
		else if (h_proto == bpf_htons(ETH_P_IPV6))
			ip6h->hop_limit--;

		memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
		action = bpf_redirect_map(&tx_port, fib_params.ifindex, 0);
		break;
	case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
	case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
	case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
		action = XDP_DROP;
		break;
	case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
	case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
	case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
	case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
		/* PASS */
		break;
	}

out:
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

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
		} else if (ids_map_value->final_state) {
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

char _license[] SEC("license") = "GPL";
