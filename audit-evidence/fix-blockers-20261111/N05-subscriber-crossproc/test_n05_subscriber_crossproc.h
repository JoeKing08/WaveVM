#ifndef TEST_N05_SUBSCRIBER_CROSSPROC_H
#define TEST_N05_SUBSCRIBER_CROSSPROC_H

#include <stdint.h>

/*
 * Shared constants for the N05 true-oracle harness.
 *
 * Chain under test (must be cross-process, not the F07 same-proc hook):
 *   membership mark UNREACHABLE
 *     -> maybe_invalidate_subscribers
 *     -> ctl strong hook (subscriber_invalidate_bridge)
 *     -> transport fanout WVM_ENVELOPE_MSG_INVALIDATE_SUBSCRIBERS (0x0307)
 *     -> directory process applies the payload via
 *        wvm_memory_service_global_invalidate_subscriber_instance
 *        (same function admission_receiver's 0x0307 case calls)
 *     -> planted ACTIVE subscriber becomes STALE
 *
 * The planted lease is a test precondition only. The invalidate path is
 * production code.
 */

#define N05_MAGIC 0x4e303530u /* 'N050' */

#define N05_FAILED_PHYS 7u
#define N05_FAILED_INST 1001ull
#define N05_FAILED_RUNTIME 2001ull

#define N05_DIR_PHYS 11u
#define N05_DIR_INST 1100ull
#define N05_DIR_RUNTIME 2100ull

#define N05_GPA 0ull

struct n05_wire_req {
    uint32_t magic;
    uint32_t message_type;
    uint32_t payload_bytes;
    uint8_t payload[16];
};

struct n05_wire_ack {
    uint32_t magic;
    int32_t status;
    uint32_t stale_count;
    uint32_t directory_pid;
};

#endif
