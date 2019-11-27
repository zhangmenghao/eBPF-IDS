# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := xdp_prog_kern
USER_TARGETS := xdp_prog_user

XDP_C := src/${XDP_TARGETS:=.c}
XDP_OBJ := target/${XDP_TARGETS:=.o}
USER_C := src/${USER_TARGETS:=.c}
USER_OBJ := target/${USER_TARGETS:=.o}
USER_TARGETS := target/${USER_TARGETS}

LIBBPF_DIR = ./ebpf/libbpf/src/
COMMON_DIR = ./common

COPY_LOADER := xdp_loader
COPY_STATS  := xdp_stats
EXTRA_DEPS := $(COMMON_DIR)/parsing_helpers.h

include $(COMMON_DIR)/common.mk
