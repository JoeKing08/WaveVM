CC = gcc
CFLAGS = -Wall -Wextra -Wno-unused-parameter -O2 -I../../common_include
LDFLAGS = -pthread

TESTS = test_two_vm_isolation

all: $(TESTS)

test_two_vm_isolation: test_two_vm_isolation.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TESTS) *.o

.PHONY: all clean
