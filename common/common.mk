# Common Makefile parts for BPF-building with libbpf
# --------------------------------------------------
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
#
# This file should be included from your Makefile like:
#  COMMON_DIR = ../common/
#  include $(COMMON_DIR)/common.mk
#
# It is expected that you define the variables:
#  XDP_TARGETS and USER_TARGETS
# as a space-separated list
#
LLC ?= llc
CLANG ?= clang
CC ?= gcc

ifdef SRC_DIR
XDP_C := $(SRC_DIR)/${XDP_TARGETS:=.c}
USER_C := $(SRC_DIR)/${USER_TARGETS:=.c}
else
XDP_C = ${XDP_TARGETS:=.c}
USER_C := ${USER_TARGETS:=.c}
endif

ifdef TARGET_DIR
XDP_OBJ := $(TARGET_DIR)/${XDP_TARGETS:=.o}
USER_OBJ := $(TARGET_DIR)/${USER_TARGETS:=.o}
USER_TARGETS := $(TARGET_DIR)/${USER_TARGETS}
else
XDP_OBJ = ${XDP_C:.c=.o}
USER_OBJ := ${USER_C:.c=.o}
endif


# Expect this is defined by including Makefile, but define if not
COMMON_DIR ?= ./common/
LIBBPF_DIR ?= ../ebpf/libbpf/src/

# COPY_LOADER ?=
LOADER_DIR ?= $(COMMON_DIR)/xdp_load_and_stats/

OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

# Extend if including Makefile already added some
COMMON_OBJS += $(COMMON_DIR)/common_params.o $(COMMON_DIR)/common_user_bpf_xdp.o

# Create expansions for dependencies
COMMON_H := ${COMMON_OBJS:.o=.h}

EXTRA_DEPS +=

# BPF-prog kern and userspace shares struct via header file:
KERN_USER_H ?= $(wildcard common_kern_user.h)

CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -g
# Extra include for Ubuntu issue #44
CFLAGS += -I/usr/include/x86_64-linux-gnu
CFLAGS += -I./ebpf/headers/
CFLAGS += -I../../ebpf/headers/
LDFLAGS ?= -L$(LIBBPF_DIR)

LIBS = -l:libbpf.a -lelf $(USER_LIBS)

all: llvm-check $(USER_TARGETS) $(XDP_OBJ) $(COPY_LOADER) $(COPY_STATS)

.PHONY: clean $(CLANG) $(LLC)

clean:
	rm -rf $(LIBBPF_DIR)/build
	$(MAKE) -C $(LIBBPF_DIR) clean
	$(MAKE) -C $(COMMON_DIR) clean
	rm -f $(USER_TARGETS) $(XDP_OBJ) $(USER_OBJ) $(COPY_LOADER) $(COPY_STATS)
	rm -f $(XDP_OBJ:.o=.ll)
	rm -f *~
ifdef TARGET_DIR
	rm -rf $(TARGET_DIR)
endif

ifdef COPY_LOADER
$(COPY_LOADER): $(LOADER_DIR)/${COPY_LOADER:=.c} $(COMMON_H)
	make -C $(LOADER_DIR) $(COPY_LOADER)
ifdef TARGET_DIR
	mv $(LOADER_DIR)/$(COPY_LOADER) $(TARGET_DIR)/$(COPY_LOADER)
else
	mv $(LOADER_DIR)/$(COPY_LOADER) $(COPY_LOADER)
endif
endif

ifdef COPY_STATS
$(COPY_STATS): $(LOADER_DIR)/${COPY_STATS:=.c} $(COMMON_H)
	make -C $(LOADER_DIR) $(COPY_STATS)
ifdef TARGET_DIR
	mv $(LOADER_DIR)/$(COPY_STATS) $(TARGET_DIR)/$(COPY_STATS)
else
	mv $(LOADER_DIR)/$(COPY_STATS) $(COPY_STATS)
endif
# Needing xdp_stats imply depending on header files:
EXTRA_DEPS += $(COMMON_DIR)/xdp_stats_kern.h $(COMMON_DIR)/xdp_stats_kern_user.h
endif

# For build dependency on this file, if it gets updated
COMMON_MK = $(COMMON_DIR)/common.mk

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

$(OBJECT_LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all; \
		mkdir -p build; DESTDIR=build $(MAKE) install_headers; \
	fi

# Create dependency: detect if C-file change and touch H-file, to trigger
# target $(COMMON_OBJS)
$(COMMON_H): %.h: %.c
	touch $@

# Detect if any of common obj changed and create dependency on .h-files
$(COMMON_OBJS): %.o: %.h
	make -C $(COMMON_DIR)

ifdef SRC_DIR
$(USER_TARGETS): %: $(USER_C) $(OBJECT_LIBBPF) Makefile $(COMMON_MK) $(COMMON_OBJS) $(KERN_USER_H) $(EXTRA_DEPS)
ifdef TARGET_DIR
	mkdir -p $(TARGET_DIR)
endif
	$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o $@ $(COMMON_OBJS) \
	 $< $(LIBS)
else
$(USER_TARGETS): %: %.c $(OBJECT_LIBBPF) Makefile $(COMMON_MK) $(COMMON_OBJS) $(KERN_USER_H) $(EXTRA_DEPS)
ifdef TARGET_DIR
	mkdir -p $(TARGET_DIR)
endif
	$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o $@ $(COMMON_OBJS) \
	 $< $(LIBS)
endif

ifdef SRC_DIR
$(XDP_OBJ): %.o: $(XDP_C) Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS)
ifdef TARGET_DIR
	mkdir -p $(TARGET_DIR)
endif
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
else
$(XDP_OBJ): %.o: %.c Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS)
ifdef TARGET_DIR
	mkdir -p $(TARGET_DIR)
endif
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
endif
