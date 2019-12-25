/* SPDX-License-Identifier: GPL-2.0 */

static const char *__doc__ = "An In-Kernel IDS based on XDP\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>
#include <stdbool.h>

#include <locale.h>
#include <poll.h>
#include <unistd.h>
#include <time.h>

#include <sys/resource.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "common/common_params.h"
#include "common/common_user_bpf_xdp.h"
#include "common/common_libbpf.h"
#include "common/common_xsk.h"

#include "common/xdp_stats_kern_user.h"

/* re2dfa and str2dfa library */
#include "common/re2dfa.h"
#include "common/str2dfa.h"

#include "common_kern_user.h"

#define LINE_BUFFER_MAX 160
#define IDS_INSPECT_ARRAY_SIZE 16777216

static const char *ids_inspect_map_name = "ids_inspect_map";
static const char *xsks_map_name = "xsks_map";
static const char *pattern_file_name = \
		// "./patterns/snort2-community-rules-content.txt";
		"./patterns/patterns.txt";
static struct ids_inspect_map_value ids_inspect_array[IDS_INSPECT_ARRAY_SIZE];

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"copy",        no_argument,		NULL, 'c' },
	 "Force copy mode"},

	{{"zero-copy",	 no_argument,		NULL, 'z' },
	 "Force zero-copy mode"},

	{{"queue",       required_argument,	NULL, 'Q' },
	 "Configure the number of interface receive queues for AF_XDP, default=0"},

	{{"poll-mode",	 no_argument,		NULL, 'p' },
	 "Use the poll() API waiting for packets to arrive"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"vv",          no_argument,		NULL, 'v' },
	 "More verbose and detailed output"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static bool global_exit;

/* Follow struct declaration is for fixing the bug of bpf_map_update_elem */
struct ids_inspect_map_update_value {
	struct ids_inspect_map_value value;
	uint8_t padding[8 - sizeof(struct ids_inspect_map_value)];
};

struct stats_poll_arg {
	struct xsk_socket_info **xsk_sockets;
	int xsk_if_queue;
};

/*
 * static int re2dfa2map(char *re_string, int map_fd)
 * {
 *     struct DFA_state *dfa;
 *     struct generic_list state_list;
 *     struct DFA_state **state, *next_state;
 *     struct ids_inspect_map_key map_key;
 *     struct ids_inspect_map_value map_value;
 *     int i_state, n_state;
 * 
 *     // Convert the RE string to DFA first
 *     dfa = re2dfa(re_string);
 *     if (!dfa) {
 *         fprintf(stderr, "ERR: can't convert the RE to DFA\n");
 *         return EXIT_FAIL_RE2DFA;
 *     }
 * 
 *     // Save all state in DFA into a generic list
 *     create_generic_list(struct DFA_state *, &state_list);
 *     generic_list_push_back(&state_list, &dfa);
 *     DFA_traverse(dfa, &state_list);
 * 
 *     // Encode each state
 *     n_state = state_list.length;
 *     state = (struct DFA_state **) state_list.p_dat;
 *     for (i_state = 0; i_state < n_state; i_state++, state++) {
 *         (*state)->state_id = i_state;
 *     }
 * 
 *     // Convert dfa to map
 *     state = (struct DFA_state **) state_list.p_dat;
 *     map_key.padding = 0;
 *     map_value.padding = 0;
 *     for (i_state = 0; i_state < n_state; i_state++, state++) {
 *         int i_trans, n_trans = (*state)->n_transitions;
 *         for (i_trans = 0; i_trans < n_trans; i_trans++) {
 *             next_state = (*state)->trans[i_trans].to;
 *             map_key.state = (*state)->state_id;
 *             map_key.unit = (*state)->trans[i_trans].trans_char;
 *             map_value.state = next_state->state_id;
 *             map_value.flag = next_state->flag;
 *             if (bpf_map_update_elem(map_fd, &map_key, &map_value, 0) < 0) {
 *                 fprintf(stderr,
 *                     "WARN: Failed to update bpf map file: err(%d):%s\n",
 *                     errno, strerror(errno));
 *                 return -1;
 *             } else {
 *                 printf("---------------------------------------------------\n");
 *                 printf(
 *                     "New element is added in to map (%s)\n",
 *                     ids_inspect_map_name);
 *                 printf(
 *                     "Key - state: %d, unit: %c\n",
 *                     map_key.state, map_key.unit);
 *                 printf(
 *                     "Value - flag: %d, state: %d\n",
 *                     map_value.flag, map_value.state);
 *                 printf("---------------------------------------------------\n");
 *             }
 *             printf("Insert match (src_state: %d, chars: %d) and action (dst_state: %d)\n",
 *                       map_key.state, map_key.unit, map_value.state);
 *         }
 *     }
 * 
 *     return 0;
 * }
 * 
 * static int get_number_of_nonblank_lines(const char *source_file) {
 *     FILE *fp;
 *     char buf[LINE_BUFFER_MAX];
 *     int count = 0;
 *     if ((fp = fopen(source_file, "r")) == NULL) {
 *         fprintf(stderr, "ERR: can not open the source file\n");
 *         return 0;
 *     } else {
 *         while (fgets(buf, sizeof(buf), fp)) {
 *             // Skip blank line (only '\n')
 *             if (strlen(buf) > 1) {
 *                 count += 1;
 *             }
 *         }
 *     }
 *     fclose(fp);
 *     return count;
 * }
 * 
 * static int get_pattern_list(const char *source_file, char ***pattern_list) {
 *     FILE *fp;
 *     char buf[LINE_BUFFER_MAX];
 *     char *pattern;
 *     int pattern_len = 0;
 *     int pattern_count = 0;
 * 
 *     if ((fp = fopen(source_file, "r")) == NULL) {
 *         fprintf(stderr, "ERR: can not open pattern source file\n");
 *         return -1;
 *     } else {
 *         memset(buf, 0, LINE_BUFFER_MAX);
 *         while (fgets(buf, sizeof(buf), fp)) {
 *             pattern_len = strchr(buf, '\n') - buf;
 *             if (pattern_len == 0) {
 *                 // Skip blank line (only '\n')
 *                 continue;
 *             }
 *             pattern = (char *)malloc(sizeof(char) * pattern_len);
 *             memset(pattern, 0, pattern_len);
 *             memcpy(pattern, buf, pattern_len);
 *             memset(buf, 0, LINE_BUFFER_MAX);
 *             printf("Get pattern with length %d: %s\n", pattern_len, pattern);
 *             (*pattern_list)[pattern_count++] = pattern;
 *         };
 *     }
 *     printf("Total %d patterns fetched\n", pattern_count);
 *     fclose(fp);
 *     return 0;
 * };
 * 
 * static int str2dfa2map(char **pattern_list, int pattern_number, int map_fd) {
 *     struct dfa_entry *map_entries;
 *     int i_entry, n_entry;
 *     struct ids_inspect_map_key map_key;
 *     struct ids_inspect_map_value map_value;
 * 
 *     // Convert string to DFA first
 *     n_entry = str2dfa(pattern_list, pattern_number, &map_entries);
 *     if (n_entry < 0) {
 *         fprintf(stderr, "ERR: can't convert the String to DFA/Map\n");
 *         return -1;
 *     } else {
 *         printf("Totol %d entries generated from pattern list\n", n_entry);
 *     }
 * 
 *     // Convert dfa to map
 *     map_key.padding = 0;
 *     map_value.padding = 0;
 *     for (i_entry = 0; i_entry < n_entry; i_entry++) {
 *         map_key.state = map_entries[i_entry].key_state;
 *         map_key.unit = map_entries[i_entry].key_unit;
 *         map_value.state = map_entries[i_entry].value_state;
 *         map_value.flag = map_entries[i_entry].value_flag;
 *         if (bpf_map_update_elem(map_fd, &map_key, &map_value, 0) < 0) {
 *             fprintf(stderr,
 *                 "WARN: Failed to update bpf map file: err(%d):%s\n",
 *                 errno, strerror(errno));
 *             return -1;
 *         } else {
 *             printf("---------------------------------------------------\n");
 *             printf(
 *                 "New element is added in to map (%s)\n",
 *                 ids_inspect_map_name);
 *             printf(
 *                 "Key - state: %d, unit: %c\n",
 *                 map_key.state, map_key.unit);
 *             printf(
 *                 "Value - flag: %d, state: %d\n",
 *                 map_value.flag, map_value.state);
 *             printf("---------------------------------------------------\n");
 *         }
 *     }
 *     printf("Total entries are inserted: %d\n", n_entry);
 *     return 0;
 * }
 */

static int dfa2map(int ids_map_fd, struct dfa_struct *dfa)
{
	struct dfa_entry *map_entries = dfa->entries;
	uint32_t i_entry, n_entry = dfa->entry_number;
	int i_cpu, n_cpu = libbpf_num_possible_cpus();
	struct ids_inspect_map_key ids_map_key;
	struct ids_inspect_map_update_value ids_map_values[n_cpu];
	ids_inspect_state value_state;
	accept_state_flag value_flag;
	uint32_t array_index;

	printf("Number of CPUs: %d\n\n", n_cpu);

	/* Initial */
	ids_map_key.padding = 0;
	memset(ids_map_values, 0, sizeof(ids_map_values));
	memset(ids_inspect_array, 0, sizeof(ids_inspect_array));

	/* Convert dfa to map */
	for (i_entry = 0; i_entry < n_entry; i_entry++) {
		ids_map_key.state = map_entries[i_entry].key_state;
		ids_map_key.unit = map_entries[i_entry].key_unit;
		value_state = map_entries[i_entry].value_state;
		value_flag = map_entries[i_entry].value_flag;
		for (i_cpu = 0; i_cpu < n_cpu; i_cpu++) {
			ids_map_values[i_cpu].value.state = value_state;
			ids_map_values[i_cpu].value.flag = value_flag;
		}
		if (bpf_map_update_elem(ids_map_fd,
								&ids_map_key, ids_map_values, 0) < 0) {
			fprintf(stderr,
				"WARN: Failed to update bpf map file: err(%d):%s\n",
				errno, strerror(errno));
			return -1;
		} else {
			if (verbose > 1) {
				printf("---------------------------------------------------\n");
				printf("New element is added in to map (%s)\n",
						ids_inspect_map_name);
				printf("Key - state: %d, unit: %c\n",
						ids_map_key.state, ids_map_key.unit);
				printf("Value - state: %d, flag: %d\n",
						value_state, value_flag);
				printf("---------------------------------------------------\n");
			}
		}
		array_index = *(uint32_t *)&ids_map_key;
		ids_inspect_array[array_index].state = map_entries[i_entry].value_state;
		ids_inspect_array[array_index].flag = map_entries[i_entry].value_flag;
	}
	printf("Total %d entries are inserted\n\n", n_entry);

	return 0;
}

static void *stats_poll(void *arg)
{
	unsigned int interval = 2;
	struct stats_poll_arg *stats_arg = arg;
	struct xsk_socket_info **xsk_sockets = stats_arg->xsk_sockets;
	int i_queue, n_queue = stats_arg->xsk_if_queue;
	static struct stats_record previous_stats = { 0 };

	previous_stats.timestamp = xsk_gettime();

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	while (!global_exit) {
		sleep(interval);
		struct stats_record current_stats = { 0 };
		current_stats.timestamp = xsk_gettime();
		for (i_queue = 0; i_queue < n_queue; i_queue++) {
			current_stats.rx_packets += xsk_sockets[i_queue]->stats.rx_packets;
			current_stats.rx_bytes += xsk_sockets[i_queue]->stats.rx_bytes;
			current_stats.tx_packets += xsk_sockets[i_queue]->stats.tx_packets;
			current_stats.tx_bytes += xsk_sockets[i_queue]->stats.tx_bytes;
		}
		stats_print(&current_stats, &previous_stats);
		previous_stats = current_stats;
	}
	return NULL;
}

static __always_inline int inspect_payload(void *payload, uint16_t payload_len)
{
	ids_inspect_unit *ids_unit = (ids_inspect_unit *)payload;
	struct ids_inspect_map_key ids_map_key;
	struct ids_inspect_map_value *ids_map_value;
	uint32_t array_index;
	int i_unit;

	ids_map_key.state = 0;
	ids_map_key.padding = 0;

	for (i_unit = 0; i_unit < payload_len; i_unit++) {
		ids_map_key.unit = *ids_unit;
		array_index = *(uint32_t *)&ids_map_key;
		ids_map_value = &ids_inspect_array[array_index];
		if (ids_map_value->flag > 0) {
			return ids_map_value->flag;
		}
		ids_map_key.state = ids_map_value->state;
		ids_unit += 1;
	}

	return 0;
}

static bool proc_pkt(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len)
{
	int ret, ip_type;
	uint32_t ids_state, hdr_len = 0;
	uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
	struct ethhdr *eth = (struct ethhdr *) pkt;
	uint32_t tx_idx = 0;


	hdr_len += sizeof(*eth);

	if (len < hdr_len) {
		return false;
	}

	if (ntohs(eth->h_proto) == ETH_P_IP) {
		struct iphdr *iph = (struct iphdr *)(eth + 1);
		ip_type = iph->protocol;
		hdr_len += iph->ihl * 4;
	} else if (ntohs(eth->h_proto) == ETH_P_IPV6) {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
		ip_type = ip6h->nexthdr;
		hdr_len += sizeof(*ip6h);
	} else {
		/* Ignore vlan here currently */
		goto sendpkt;
	}

	if (len < hdr_len) {
		return false;
	}

	if (ip_type == IPPROTO_TCP) {
		struct tcphdr *tcph = (struct tcphdr *)(pkt + hdr_len);
		hdr_len += sizeof(*tcph);
	} else if (ip_type == IPPROTO_UDP) {
		struct udphdr *udph = (struct udphdr *)(pkt + hdr_len);
		hdr_len += sizeof(*udph);
	} else {
		goto sendpkt;
	}

	if (len < hdr_len) {
		return false;
	}

	ids_state = inspect_payload((void *)(pkt + hdr_len), len - hdr_len);

	if (ids_state > 0) {
		if (verbose > 1) {
			printf("---------------------------------------------------\n");
			printf("The %dth pattern is triggered\n", ids_state);
			printf("---------------------------------------------------\n\n");
		}
		/* Drop the packet */
		return false;
	}

sendpkt:
	/* Here we sent the packet out of the receive port. Note that
	 * we allocate one entry and schedule it. Your design would be
	 * faster if you do batch processing/transmission */

	ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
	if (ret != 1) {
		/* No more transmit slots, drop the packet */
		return false;
	}

	xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
	xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;
	xsk_ring_prod__submit(&xsk->tx, 1);
	xsk->outstanding_tx++;

	xsk->stats.tx_bytes += len;
	xsk->stats.tx_packets++;
	return true;
}

static void rx_and_process(struct config *cfg,
						   struct xsk_socket_info **xsk_sockets)
{
	int ret, i_queue, n_queue = cfg->xsk_if_queue;
	struct pollfd fds[n_queue];

	memset(fds, 0, sizeof(fds));
	for (i_queue = 0; i_queue < n_queue; i_queue++) {
		fds[i_queue].fd = xsk_socket__fd(xsk_sockets[i_queue]->xsk);
		fds[i_queue].events = POLLIN;
	}

	while(!global_exit) {
		if (cfg->xsk_poll_mode) {
			ret = poll(fds, n_queue, 0);
			if (ret <= 0) {
				continue;
			}
			for (i_queue = 0; i_queue < n_queue; i_queue++) {
				if (fds[i_queue].revents & POLLIN) {
					handle_receive_packets(xsk_sockets[i_queue], proc_pkt);
				}
			}
		} else {
			for (i_queue = 0; i_queue < n_queue; i_queue++) {
				handle_receive_packets(xsk_sockets[i_queue], proc_pkt);
			}
		}
	}
}

static void exit_application(int signal)
{
	signal = signal;
	global_exit = true;
}

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir = "/sys/fs/bpf";

int main(int argc, char **argv)
{
	int ret, len;
	int ids_map_fd, xsks_map_fd;
	char pin_dir[PATH_MAX];
	struct dfa_struct dfa;
	struct xsk_umem_info **umems;
	struct xsk_socket_info **xsk_sockets;
	pthread_t stats_poll_thread;
	int i_queue;

	struct config cfg = {
		.ifindex = -1,
		.redirect_ifindex = -1,
	};

	/* Global shutdown handler */
	signal(SIGINT, exit_application);

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);
	if (cfg.redirect_ifindex > 0 && cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	printf("\nmap dir: %s\n\n", pin_dir);

	/* Open the maps corresponding to the cfg.ifname interface */
	ids_map_fd = open_bpf_map_file(pin_dir, ids_inspect_map_name, NULL);
	if (ids_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}
	xsks_map_fd = open_bpf_map_file(pin_dir, xsks_map_name, NULL);
	if (xsks_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	/* Convert the string to DFA and map */
	if (str2dfa_fromfile(pattern_file_name, &dfa) < 0) {
		fprintf(stderr, "ERR: can't convert the string to DFA\n");
		return EXIT_FAIL_RE2DFA;
	}
	if (dfa2map(ids_map_fd, &dfa) < 0) {
		fprintf(stderr, "ERR: can't convert the DFA to Map\n");
		return EXIT_FAIL_RE2DFA;
	}

	/* Configure and initialize AF_XDP sockets */
	umems = (struct xsk_umem_info **)
			malloc(sizeof(struct xsk_umem_info *) * cfg.xsk_if_queue);
	xsk_sockets = (struct xsk_socket_info **)
				  malloc(sizeof(struct xsk_socket_info *) * cfg.xsk_if_queue);
	if (!umems || !xsk_sockets) {
		fprintf(stderr, "ERR: can't initialize umems/xsk_sockets for AF_XDP\n");
		return EXIT_FAIL_BPF;
	}
	ret = af_xdp_init(&cfg, xsks_map_fd, umems, xsk_sockets);
	if (ret != 0) {
		fprintf(stderr, "ERR: can't initialize for AF_XDP\n");
		return ret;
	}

	/* Start thread to do statistics display */
	if (verbose) {
		struct stats_poll_arg arg;
		arg.xsk_sockets = xsk_sockets;
		arg.xsk_if_queue = cfg.xsk_if_queue;
		ret = pthread_create(&stats_poll_thread, NULL, stats_poll, &arg);
		if (ret) {
			fprintf(stderr, "ERROR: Failed creating statistics thread "
				"\"%s\"\n", strerror(errno));
			return EXIT_FAILURE;
		}
	}

	/* Receive and count packets than drop them */
	printf("Start to receive and process packets from the data plane...\n\n");
	rx_and_process(&cfg, xsk_sockets);

	/* Cleanup */
	for (i_queue = 0; i_queue < cfg.xsk_if_queue; i_queue++) {
		xsk_socket__delete(xsk_sockets[i_queue]->xsk);
		xsk_umem__delete(umems[i_queue]->umem);
	}
	// xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

	return EXIT_OK;
}
