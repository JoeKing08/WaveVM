# Prefer: make -C ../node_runtime
# Standalone link is incomplete; production binary is ../wavevm_node_runtime
# and historical wavevm_node_slave is produced by packaging scripts from that tree.
CC = gcc
CFLAGS = -Wall -O3 -msse4.2 -I../common_include -pthread
.PHONY: all
all:
	$(MAKE) -C ../node_runtime
