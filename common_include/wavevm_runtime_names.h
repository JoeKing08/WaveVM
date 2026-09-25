#ifndef WAVEVM_RUNTIME_NAMES_H
#define WAVEVM_RUNTIME_NAMES_H

#include <stddef.h>

#include "wavevm_lifecycle.h"

#define WVM_RUNTIME_PATH_MAX 256U
#define WVM_RUNTIME_READY_MAGIC UINT32_C(0x57564d52)
#define WVM_RUNTIME_READY_VERSION 2U

/*
 * All names owned by one admitted VM/node runtime are derived from the same
 * validated namespace.  Callers may choose which endpoint to expose, but
 * they must not derive a second naming scheme from a raw node or VM ID.
 */
struct wvm_runtime_name_set {
    char runtime_socket[WVM_RUNTIME_PATH_MAX];
    char executor_socket[WVM_RUNTIME_PATH_MAX];
    char worker_socket[WVM_RUNTIME_PATH_MAX];
    char monitor_socket[WVM_RUNTIME_PATH_MAX];
    char ready_file[WVM_RUNTIME_PATH_MAX];
    char shm_name[WVM_RUNTIME_PATH_MAX];
    char log_directory[WVM_RUNTIME_PATH_MAX];
    char temporary_directory[WVM_RUNTIME_PATH_MAX];
};

/* Host-local readiness evidence bound to one admitted node manifest. */
struct wvm_runtime_ready_record {
    uint32_t magic;
    uint16_t version;
    uint16_t reserved;
    uint32_t vm_id;
    uint32_t physical_node_id;
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    uint64_t node_instance_id;
    uint8_t candidate_manifest_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t activation_fence[WVM_IDENTITY_ID_BYTES];
    uint64_t owner_pid;
    uint64_t owner_tid;
    uint64_t owner_start_time_ticks;
    char owner_boot_id[37];
};

int wvm_runtime_name_set_derive(
    const struct wvm_local_name_namespace *namespace_value,
    struct wvm_runtime_name_set *names, char *error, size_t error_len);

int wvm_runtime_name_set_validate(const struct wvm_runtime_name_set *names,
                                  char *error, size_t error_len);

int wvm_runtime_ready_publish(
    const struct wvm_node_runtime_manifest *manifest,
    uint64_t node_instance_id, char *error, size_t error_len);

int wvm_runtime_ready_validate(
    const struct wvm_node_runtime_manifest *manifest,
    uint64_t node_instance_id, char *error, size_t error_len);

int wvm_runtime_ready_remove(
    const struct wvm_node_runtime_manifest *manifest, char *error,
    size_t error_len);

#endif /* WAVEVM_RUNTIME_NAMES_H */
