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

/* re2dfa library */
#include "common/re2dfa.h"

#include "common_kern_user.h"

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

static int write_match_action_entries(int map_fd, __u16 src_state, 
									char chars, __u16 dst_state){
	struct match mat;
	mat.state = src_state;
	mat.chars = chars;
	struct action act;
	act.state = dst_state;
	if (bpf_map_update_elem(map_fd, &mat, &act, 0) < 0) {
		fprintf(stderr,
			"WARN: Failed to update bpf map file: err(%d):%s\n",
			errno, strerror(errno));
		return -1;
	}

	printf("Insert match (src_state: %d, chars: %d) and action (dst_state: %d)\n", 
		mat.state, mat.chars, act.state);

	return 0;
}

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";

int main(int argc, char **argv)
{
	int len;
	int map_fd;
	bool redirect_map;
	char pin_dir[PATH_MAX];

	struct config cfg = {
		.ifindex   = -1,
		.redirect_ifindex   = -1,
	};

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	redirect_map = (cfg.ifindex > 0) && (cfg.redirect_ifindex > 0);

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


	map_fd = open_bpf_map_file(pin_dir, "IDS_state_map", NULL);
	if (map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	printf("map dir: %s\n", pin_dir);

	if (redirect_map) {
		printf("Err: This should not happens!");
	} else {
		if (write_match_action_entries(map_fd, 0, 'd', 1)){
			fprintf(stderr, "can't write map params\n");
		}
		if (write_match_action_entries(map_fd, 1, 'o', 2)){
			fprintf(stderr, "can't write map_fd params\n");
		}
		if (write_match_action_entries(map_fd, 2, 'g', 3)){
			fprintf(stderr, "can't write map params\n");
		}
		if (write_match_action_entries(map_fd, 1, 'd', 1)){
			fprintf(stderr, "can't write map params\n");
		}
		if (write_match_action_entries(map_fd, 2, 'd', 1)){
			fprintf(stderr, "can't write map params\n");
		}

	}

	return EXIT_OK;
}
