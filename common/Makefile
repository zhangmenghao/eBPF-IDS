# SPDX-License-Identifier: (GPL-2.0)
CC := gcc

all: common_params.o common_user_bpf_xdp.o common_libbpf.o re2dfa.o str2dfa.o

CFLAGS := -g -Wall

SPEC_FLAGS ?= -I/usr/include/python2.7 -lpython2.7

LIBBPF_DIR = ../ebpf/libbpf/src/
CFLAGS += -I$(LIBBPF_DIR)/build/usr/include/  -I../ebpf/headers
# TODO: Do we need to make libbpf from this make file too?

common_params.o: common_params.c common_params.h
	$(CC) $(CFLAGS) -c -o $@ $<

common_user_bpf_xdp.o: common_user_bpf_xdp.c common_user_bpf_xdp.h
	$(CC) $(CFLAGS) -c -o $@ $<

common_libbpf.o: common_libbpf.c common_libbpf.h
	$(CC) $(CFLAGS) -c -o $@ $<

re2dfa.o: re2dfa.c re2dfa.h
	$(CC) -c -o $@ $<

str2dfa.o: str2dfa.c str2dfa.h str2dfa.py
	$(CC) $(SPEC_FLAGS) -c -o $@ $<

.PHONY: clean

clean:
	rm -f *.o *.pyc
