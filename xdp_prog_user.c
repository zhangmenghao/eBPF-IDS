/* SPDX-License-Identifier: GPL-2.0 */

static const char *__doc__ = "XDP redirect helper\n"
	" - Allows to populate/query tx_port and redirect_params maps\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "common/common_params.h"
#include "common/common_user_bpf_xdp.h"
#include "common/common_libbpf.h"

#include "common/xdp_stats_kern_user.h"

/* re2dfa and str2dfa library */
#include "common/re2dfa.h"
#include "common/str2dfa.h"

/* IDS Inspect Uit */
typedef __u8 ids_inspect_unit;

/* IDS Inspect State */
typedef __u16 ids_inspect_state;

/* Key-Value of ids_inspect_map */
struct ids_inspect_map_key {
	ids_inspect_state state;
	ids_inspect_unit unit;
	__u8 padding;
};

struct ids_inspect_map_value {
	ids_inspect_state state;
	__u8 is_acceptable;
	__u8 padding;
};

static const char *ids_inspect_map_name = "ids_inspect_map";

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"redirect-dev",         required_argument,	NULL, 'r' },
	 "Redirect to device <ifname>", "<ifname>", true},

	{{"src-mac", required_argument, NULL, 'L' },
	 "Source MAC address of <dev>", "<mac>", true },

	{{"dest-mac", required_argument, NULL, 'R' },
	 "Destination MAC address of <redirect-dev>", "<mac>", true },

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static int pattern_list_len = 2;
static char* pattern_list[] = {
	"dog", "cat"
};

/*
static int re2dfa2map(char *re_string, int map_fd)
{
	struct DFA_state *dfa;
	struct generic_list state_list;
	struct DFA_state **state, *next_state;
	struct ids_inspect_map_key map_key;
	struct ids_inspect_map_value map_value;
	int i_state, n_state;

	// Convert the RE string to DFA first 
	dfa = re2dfa(re_string);
	if (!dfa) {
		fprintf(stderr, "ERR: can't convert the RE to DFA\n");
		return EXIT_FAIL_RE2DFA;
	}

	// Save all state in DFA into a generic list 
	create_generic_list(struct DFA_state *, &state_list);
	generic_list_push_back(&state_list, &dfa);
	DFA_traverse(dfa, &state_list);

	// Encode each state 
	n_state = state_list.length;
	state = (struct DFA_state **) state_list.p_dat;
	for (i_state = 0; i_state < n_state; i_state++, state++) {
		(*state)->state_id = i_state;
	}

	// Convert dfa to map 
	state = (struct DFA_state **) state_list.p_dat;
	map_key.padding = 0;
	map_value.padding = 0;
	for (i_state = 0; i_state < n_state; i_state++, state++) {
		int i_trans, n_trans = (*state)->n_transitions;
		for (i_trans = 0; i_trans < n_trans; i_trans++) {
			next_state = (*state)->trans[i_trans].to;
			map_key.state = (*state)->state_id;
			map_key.unit = (*state)->trans[i_trans].trans_char;
			map_value.state = next_state->state_id;
			map_value.is_acceptable = next_state->is_acceptable;
			if (bpf_map_update_elem(map_fd, &map_key, &map_value, 0) < 0) {
				fprintf(stderr,
					"WARN: Failed to update bpf map file: err(%d):%s\n",
					errno, strerror(errno));
			} else {
				printf("---------------------------------------------------\n");
				printf(
					"New element is added in to map (%s)\n",
					ids_inspect_map_name);
				printf(
					"Key - state: %d, unit: %c\n",
					map_key.state, map_key.unit);
				printf(
					"Value - is_acceptable: %d, state: %d\n",
					map_value.is_acceptable, map_value.state);
				printf("---------------------------------------------------\n");
			}
		}
	}

	return 0;
}
*/

static int str2dfa2map(char **pattern_list, int pattern_list_len, int map_fd) {
	struct str2dfa_kv *map_entries;
	int i_entry, n_entry;
	struct ids_inspect_map_key map_key;
	struct ids_inspect_map_value map_value;

	/* Convert string to DFA first */
	n_entry = str2dfa(pattern_list, pattern_list_len, &map_entries);
	if (n_entry < 0) {
		fprintf(stderr, "ERR: can't convert the String to DFA/Map\n");
		return EXIT_FAIL_RE2DFA;
	}

	/* Convert dfa to map */
	map_key.padding = 0;
	map_value.padding = 0;
	for (i_entry = 0; i_entry < n_entry; i_entry++) {
		map_key.state = map_entries[i_entry].key_state;
		map_key.unit = map_entries[i_entry].key_unit;
		map_value.state = map_entries[i_entry].value_state;
		map_value.is_acceptable = map_entries[i_entry].value_is_acceptable;
		if (bpf_map_update_elem(map_fd, &map_key, &map_value, 0) < 0) {
			fprintf(stderr,
				"WARN: Failed to update bpf map file: err(%d):%s\n",
				errno, strerror(errno));
		} else {
			printf("---------------------------------------------------\n");
			printf(
				"New element is added in to map (%s)\n",
				ids_inspect_map_name);
			printf(
				"Key - state: %d, unit: %c\n",
				map_key.state, map_key.unit);
			printf(
				"Value - is_acceptable: %d, state: %d\n",
				map_value.is_acceptable, map_value.state);
			printf("---------------------------------------------------\n");
		}
	}
	return 0;
}

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir = "/sys/fs/bpf";

int main(int argc, char **argv)
{
	int len;
	int map_fd;
	char pin_dir[PATH_MAX];

	struct config cfg = {
		.ifindex = -1,
		.redirect_ifindex = -1,
	};

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

	printf("map dir: %s\n", pin_dir);

	/* Open the ids_inspect_map corresponding to the cfg.ifname interface */
	map_fd = open_bpf_map_file(pin_dir, ids_inspect_map_name, NULL);
	if (map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	/* Convert the RE to DFA and map */
	// char *re_string = "(dog)|(cat)";
	// if (re2dfa2map(re_string, map_fd) < 0) {
		// fprintf(stderr, "ERR: can't convert the RE to DFA/Map\n");
		// return EXIT_FAIL_RE2DFA;
	// }

	/* Convert the string to DFA and map */
	if (str2dfa2map(pattern_list, pattern_list_len, map_fd) < 0) {
		fprintf(stderr, "ERR: can't convert the string to DFA/Map\n");
		return EXIT_FAIL_RE2DFA;
	}

	return EXIT_OK;
}
