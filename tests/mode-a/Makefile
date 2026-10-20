CC = gcc
CFLAGS = -Wall -Wextra -Wno-unused-parameter -O2 -I../../common_include
LDFLAGS = -pthread

TESTS = test_two_vm_isolation test_two_vm_context_bind test_targeted_isolation test_worker_failure_isolation

all: $(TESTS)

test_two_vm_isolation: test_two_vm_isolation.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_two_vm_context_bind: test_two_vm_context_bind.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_targeted_isolation: test_targeted_isolation.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TESTS) *.o

.PHONY: all clean

test_worker_failure_isolation: test_worker_failure_isolation.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
