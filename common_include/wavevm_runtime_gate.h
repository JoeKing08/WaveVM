#ifndef WAVEVM_RUNTIME_GATE_H
#define WAVEVM_RUNTIME_GATE_H

#include <stddef.h>
#include <stdint.h>

#include "wavevm_config.h"
#include "wavevm_lifecycle.h"

#define WVM_RUNTIME_MANIFEST_MAX_BYTES (4U * 1024U * 1024U)
/* One QEMU sync channel per vCPU plus fixed memory, push, IRQ, and block
 * channels. The capacity is derived from the shared vCPU limit so it cannot
 * become an accidental smaller VM-size limit. */
#define WVM_RUNTIME_MAX_CONNECTIONS (MAX_VCPUS + 8U)
#define WVM_RUNTIME_MAX_CAPABILITIES 256U
#define WVM_RUNTIME_MAX_DEPENDENCIES WVM_MAX_SLAVES

/*
 * Role bits are the stable projection of enum wvm_manifest_role_type.
 * They are intentionally derived, rather than being independently assigned
 * by launch scripts.
 */
#define WVM_RUNTIME_ROLE_BIT(role) \
    (UINT64_C(1) << ((unsigned)(role) - 1U))

enum wvm_runtime_gate_state {
    WVM_RUNTIME_GATE_EMPTY = 0,
    WVM_RUNTIME_GATE_PREPARED = 1,
    WVM_RUNTIME_GATE_ACTIVE = 2,
    WVM_RUNTIME_GATE_QUIESCING = 3,
};

enum wvm_runtime_connection_state {
    WVM_RUNTIME_CONNECTION_REGISTERED = 1,
    WVM_RUNTIME_CONNECTION_REVOKED = 2,
};

/*
 * Storage for a decoded NodeRuntimeManifest. The manifest owns none of these
 * arrays; callers keep this storage alive for the gate lifetime.
 */
struct wvm_runtime_manifest_storage {
    struct wvm_node_runtime_manifest manifest;
    struct wvm_vcpu_assignment *local_vcpus;
    struct wvm_memory_chunk_assignment *local_memory;
    struct wvm_storage_assignment *local_storage;
    struct wvm_capability_ref *capabilities;
    struct wvm_startup_dependency *dependencies;
};

struct wvm_runtime_registration {
    enum wvm_manifest_role_type connection_role;
    uint32_t vm_id;
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    uint8_t candidate_manifest_digest[WVM_SHA256_DIGEST_BYTES];
    uint64_t local_runtime_instance_id;
    uint64_t caller_process_instance_id;
    uint8_t capability_profile_digest[WVM_SHA256_DIGEST_BYTES];
    char requested_endpoint_name[WVM_LOCAL_NAMESPACE_MAX_BYTES + 1U];
};

struct wvm_runtime_operation {
    uint64_t connection_id;
    uint32_t vm_id;
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    uint8_t candidate_manifest_digest[WVM_SHA256_DIGEST_BYTES];
    struct wvm_route_snapshot_key route_snapshot_key;
    uint8_t activation_fence[WVM_IDENTITY_ID_BYTES];
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
};

struct wvm_runtime_connection {
    uint64_t connection_id;
    enum wvm_manifest_role_type role;
    uint64_t caller_process_instance_id;
    enum wvm_runtime_connection_state state;
};

struct wvm_runtime_gate {
    /* The caller keeps this prepared projection alive for the gate lifetime. */
    struct wvm_node_runtime_manifest *manifest;
    uint32_t local_physical_node_id;
    uint64_t local_node_instance_id;
    enum wvm_runtime_gate_state state;
    uint64_t next_connection_id;
    struct wvm_runtime_connection connections[WVM_RUNTIME_MAX_CONNECTIONS];
};

void wvm_runtime_manifest_storage_init(
    struct wvm_runtime_manifest_storage *storage);
void wvm_runtime_manifest_storage_free(
    struct wvm_runtime_manifest_storage *storage);

/*
 * Load one complete canonical NodeRuntimeManifest record. The loader rejects
 * trailing bytes, oversized records, and records whose nested list counts
 * exceed the bounded V1 limits.
 */
int wvm_runtime_manifest_load_file(
    const char *path, struct wvm_runtime_manifest_storage *storage,
    char *error, size_t error_len);

/*
 * Atomically publish one complete admitted NodeRuntimeManifest.  A local
 * control receiver uses this only after it has accepted an exact
 * PREPARE_MANIFEST/ACTIVATE_MANIFEST transaction; launchers never observe a
 * partially written manifest.
 */
int wvm_runtime_manifest_file_publish(
    const char *path, const struct wvm_node_runtime_manifest *manifest,
    char *error, size_t error_len);

int wvm_runtime_manifest_profile_digest(
    const struct wvm_node_runtime_manifest *manifest,
    uint8_t digest[WVM_SHA256_DIGEST_BYTES], char *error, size_t error_len);

void wvm_runtime_gate_init(struct wvm_runtime_gate *gate);

int wvm_runtime_gate_prepare(
    struct wvm_runtime_gate *gate,
    struct wvm_node_runtime_manifest *manifest,
    uint32_t local_physical_node_id, uint64_t local_node_instance_id,
    char *error, size_t error_len);

/*
 * Bind the activation-fenced projection of an already prepared manifest.
 * Every immutable field must match the prepared projection; only the
 * activation fence may be added by this transition.
 */
int wvm_runtime_gate_bind_activation(
    struct wvm_runtime_gate *gate,
    const struct wvm_node_runtime_manifest *activated_manifest, char *error,
    size_t error_len);

int wvm_runtime_gate_activate(struct wvm_runtime_gate *gate,
                              const uint8_t activation_fence[WVM_IDENTITY_ID_BYTES],
                              char *error, size_t error_len);

/* Abort only the exact, not-yet-activated local prepare projection. */
int wvm_runtime_gate_abort_prepared(
    struct wvm_runtime_gate *gate,
    const struct wvm_node_runtime_manifest *prepared_manifest, char *error,
    size_t error_len);

int wvm_runtime_gate_quiesce(struct wvm_runtime_gate *gate, char *error,
                             size_t error_len);

int wvm_runtime_gate_register(
    struct wvm_runtime_gate *gate,
    const struct wvm_runtime_registration *registration,
    uint64_t *connection_id_out, char *error, size_t error_len);

int wvm_runtime_gate_revoke(struct wvm_runtime_gate *gate,
                            uint64_t connection_id, char *error,
                            size_t error_len);

/* Return non-zero when at least one live connection has the requested role. */
int wvm_runtime_gate_has_registered_role(
    const struct wvm_runtime_gate *gate,
    enum wvm_manifest_role_type role);

/*
 * This is the single local check before a registered QEMU, executor, gateway,
 * sidecar, or kernel binding may submit semantic work.
 */
int wvm_runtime_gate_authorize(
    const struct wvm_runtime_gate *gate,
    const struct wvm_runtime_operation *operation, char *error,
    size_t error_len);

#endif /* WAVEVM_RUNTIME_GATE_H */
