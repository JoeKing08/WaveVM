#ifndef WAVEVM_MEMORY_H
#define WAVEVM_MEMORY_H

#include <stddef.h>
#include <stdint.h>

#include "wavevm_envelope.h"

#define WVM_MEMORY_PAGE_BYTES 4096U
#define WVM_MEM_READ_PAYLOAD_BYTES 32U
#define WVM_MEM_ACK_HEADER_BYTES 32U
#define WVM_MEM_COMMIT_HEADER_BYTES 44U
#define WVM_MEM_COMMIT_ACK_BYTES 32U
#define WVM_MEM_PUSH_HEADER_BYTES 48U

enum wvm_mem_push_flags {
    WVM_MEM_PUSH_FLAG_FULL = 0x0001U,
};

enum wvm_mem_ack_status {
    WVM_MEM_ACK_SUCCESS = 0,
    WVM_MEM_ACK_STALE = 1,
    WVM_MEM_ACK_NOT_FOUND = 2,
    WVM_MEM_ACK_BACKPRESSURE = 3,
    WVM_MEM_ACK_INTERNAL_FAILURE = 4,
};

enum wvm_mem_commit_ack_status {
    WVM_MEM_COMMIT_ACK_SUCCESS = 0,
    WVM_MEM_COMMIT_ACK_STALE_BASE_VERSION = 1,
    WVM_MEM_COMMIT_ACK_NOT_FOUND = 2,
    WVM_MEM_COMMIT_ACK_BACKPRESSURE = 3,
    WVM_MEM_COMMIT_ACK_INTERNAL_FAILURE = 4,
};

/*
 * The read request carries the complete leaf destination for the response.
 * It deliberately excludes hop state: the directory node runtime resolves
 * the return RouteKey against its admitted immutable snapshot before sending.
 */
struct wvm_mem_read {
    uint64_t gpa;
    uint16_t reply_destination_kind;
    uint64_t reply_destination_scope;
    uint32_t reply_destination_vnode;
    uint64_t reply_node_instance_id;
};

/*
 * A successful read response always carries one full authoritative 4 KiB
 * page. Terminal non-success replies have no page data and version zero.
 * DATA points into the decoded input buffer and is not owned by this object.
 */
struct wvm_mem_ack {
    uint64_t gpa;
    uint64_t version;
    uint16_t status;
    uint32_t directory_physical_node_id;
    uint64_t directory_node_instance_id;
    const uint8_t *data;
    size_t data_bytes;
};

/*
 * DATA points into the decoded input buffer and is not owned by this object.
 * A V1 commit always carries explicit bytes; zero-page compaction remains a
 * future representation optimization and never bypasses base-version checks.
 */
struct wvm_mem_commit {
    uint64_t gpa;
    uint64_t base_version;
    uint16_t offset;
    uint16_t size;
    uint16_t reply_destination_kind;
    uint64_t reply_destination_scope;
    uint32_t reply_destination_vnode;
    uint64_t reply_node_instance_id;
    const uint8_t *data;
    size_t data_bytes;
};

struct wvm_mem_commit_ack {
    uint64_t gpa;
    uint64_t result_version;
    uint16_t status;
    uint32_t directory_physical_node_id;
    uint64_t directory_node_instance_id;
};

/*
 * A directory update is a separate typed operation from the client commit.
 * BASE_VERSION is required for a diff and zero for an authoritative full
 * snapshot.  The directory identity is carried in the payload as well as the
 * envelope so a receiver can reject a push from an old directory instance.
 * DATA points into the decoded input buffer and is not owned by this object.
 */
struct wvm_mem_push {
    uint64_t gpa;
    uint64_t base_version;
    uint64_t version;
    uint16_t offset;
    uint16_t size;
    uint16_t flags;
    uint32_t directory_physical_node_id;
    uint64_t directory_node_instance_id;
    const uint8_t *data;
    size_t data_bytes;
};

int wvm_mem_read_encode(const struct wvm_mem_read *read,
                           uint8_t output[WVM_MEM_READ_PAYLOAD_BYTES],
                           char *error, size_t error_len);
int wvm_mem_read_decode(const uint8_t *input, size_t input_bytes,
                           struct wvm_mem_read *read, char *error,
                           size_t error_len);

int wvm_mem_ack_encode(const struct wvm_mem_ack *ack, uint8_t *output,
                          size_t output_capacity, size_t *output_bytes,
                          char *error, size_t error_len);
int wvm_mem_ack_decode(const uint8_t *input, size_t input_bytes,
                          struct wvm_mem_ack *ack, char *error,
                          size_t error_len);

int wvm_mem_commit_encode(const struct wvm_mem_commit *commit,
                             uint8_t *output, size_t output_capacity,
                             size_t *output_bytes, char *error,
                             size_t error_len);
int wvm_mem_commit_decode(const uint8_t *input, size_t input_bytes,
                             struct wvm_mem_commit *commit, char *error,
                             size_t error_len);

int wvm_mem_commit_ack_encode(
    const struct wvm_mem_commit_ack *ack,
    uint8_t output[WVM_MEM_COMMIT_ACK_BYTES], char *error,
    size_t error_len);
int wvm_mem_commit_ack_decode(
    const uint8_t input[WVM_MEM_COMMIT_ACK_BYTES],
    struct wvm_mem_commit_ack *ack, char *error, size_t error_len);

int wvm_mem_push_encode(const struct wvm_mem_push *push, uint8_t *output,
                        size_t output_capacity, size_t *output_bytes,
                        char *error, size_t error_len);
int wvm_mem_push_decode(const uint8_t *input, size_t input_bytes,
                        struct wvm_mem_push *push, char *error,
                        size_t error_len);

/*
 * Build a response envelope after the directory node runtime resolves the
 * read payload's reply destination from its admitted immutable snapshot.
 * RESOLVED_REPLY_ROUTE must match the read payload exactly and have a fresh
 * zero hop count. The response retains the original operation key; only its
 * message type, forwarding attempt, and outer destination change.
 */
int wvm_mem_ack_envelope_build(
    const struct wvm_envelope *request,
    const struct wvm_envelope_route *resolved_reply_route,
    uint64_t response_delivery_attempt_id, const struct wvm_mem_ack *ack,
    uint8_t *payload_output, size_t payload_output_capacity,
    size_t *payload_output_bytes, struct wvm_envelope *response,
    char *error, size_t error_len);

/*
 * Build one directory commit result. The response copies the complete
 * semantic operation key from REQUEST and targets only the payload's
 * snapshot-resolved reply RouteKey.
 */
int wvm_mem_commit_ack_envelope_build(
    const struct wvm_envelope *request,
    const struct wvm_envelope_route *resolved_reply_route,
    uint64_t response_delivery_attempt_id,
    const struct wvm_mem_commit_ack *ack,
    uint8_t payload_output[WVM_MEM_COMMIT_ACK_BYTES],
    struct wvm_envelope *response, char *error, size_t error_len);


/*
 * Validate the complete semantic payload for V1 memory messages before it
 * crosses the node-runtime/executor boundary. Other message families remain
 * owned by their respective typed adapters.
 */
int wvm_memory_payload_validate(uint16_t message_type,
                                   const uint8_t *payload,
                                   size_t payload_bytes, char *error,
                                   size_t error_len);

#endif /* WAVEVM_MEMORY_H */
