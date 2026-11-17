# Official production binary is ../wavevm_node_runtime; start it with
# ../scripts/wavevm (wvm_ctl + node-runtime).
# Independent wavevm_node_slave is no longer built
# (rollback: ../audit-evidence/legacy-cli-archive-20261117/).
# Prefer: make -C ../node_runtime
CC = gcc
CFLAGS = -Wall -O3 -msse4.2 -I../common_include -pthread
.PHONY: all clean
all:
	$(MAKE) -C ../node_runtime

clean:
	rm -f wavevm_node_slave slave_hybrid_legacy.o
