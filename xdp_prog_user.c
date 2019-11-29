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

static int parse_u8(char *str, unsigned char *x)
{
	unsigned long z;

	z = strtoul(str, 0, 16);
	if (z > 0xff)
		return -1;

	if (x)
		*x = z;

	return 0;
}

static int parse_mac(char *str, unsigned char mac[ETH_ALEN])
{
	/* Parse a MAC address in this function and place the
	 * result in the mac array */
	if (parse_u8(str, &mac[0]) < 0)
		return -1;
	if (parse_u8(str + 3, &mac[1]) < 0)
		return -1;
	if (parse_u8(str + 6, &mac[2]) < 0)
		return -1;
	if (parse_u8(str + 9, &mac[3]) < 0)
		return -1;
	if (parse_u8(str + 12, &mac[4]) < 0)
		return -1;
	if (parse_u8(str + 15, &mac[5]) < 0)
		return -1;

	return 0;
}

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir = "/sys/fs/bpf";

int main(int argc, char **argv)
{
	int i, j;
	int len, result;
	int map_fd;
	bool router, ids;
	char pin_dir[PATH_MAX];
	unsigned char src[ETH_ALEN];
	unsigned char dest[ETH_ALEN];

	router = false;
	ids = true;

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

	if (parse_mac(cfg.src_mac, src) < 0) {
		fprintf(stderr, "ERR: can't parse mac address %s\n", cfg.src_mac);
		return EXIT_FAIL_OPTION;
	}

	if (parse_mac(cfg.dest_mac, dest) < 0) {
		fprintf(stderr, "ERR: can't parse mac address %s\n", cfg.dest_mac);
		return EXIT_FAIL_OPTION;
	}

	printf("map dir: %s\n", pin_dir);

	if (ids) {
		/* Open the ids_inspect_map corresponding to the cfg.ifname interface */
		map_fd = open_bpf_map_file(pin_dir, ids_inspect_map_name, NULL);
		if (map_fd < 0) {
			return EXIT_FAIL_BPF;
		} else {
			struct dfaObject targetDFA;
			char *re_string = "(dog)|(cat)|(fish)|(panda)";
			result = re2dfa(re_string, &targetDFA);
			if (result < 0) {
				fprintf(stderr, "ERR: can't convert the RE to DFA\n");
				return EXIT_FAIL_RE2DFA;
			} else {
				printObjectMappedDFA(&targetDFA);
				for (i = 1; i <= targetDFA.newStates; i++) {
					for (j = 0; j <= targetDFA.noOfInputs; j++) {
					}
				}
			}
		}
	} else if (router) {
		/* Open the tx_port map corresponding to the cfg.ifname interface */
		map_fd = open_bpf_map_file(pin_dir, "tx_port", NULL);
		if (map_fd < 0) {
			return EXIT_FAIL_BPF;
		}
		for (i = 1; i < 256; ++i)
			bpf_map_update_elem(map_fd, &i, &i, 0);
	}

	return EXIT_OK;
}
