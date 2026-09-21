#ifndef WAVEVM_ADMISSION_SLOT_REGISTRY_H
#define WAVEVM_ADMISSION_SLOT_REGISTRY_H

/*
 * Bounded node-level mapping from an admitted VM identity to one caller-owned
 * receiver slot. The registry owns identity/path selection and slot lifetime;
 * the slot's decode buffers remain caller-owned and preallocated.
 */

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "wavevm_admission_receiver.h"

#define WVM_ADMISSION_SLOT_PATH_MAX 4096U

struct wvm_admission_slot_registry_config {
    struct wvm_admission_receiver *receiver;
    struct wvm_admission_receiver_slot *slots;
    size_t slot_capacity;
    const char *state_directory;
    const char *runtime_directory;
};

struct wvm_admission_slot_registry {
    pthread_mutex_t lock;
    struct wvm_admission_receiver *receiver;
    struct wvm_admission_receiver_slot *slots;
    size_t slot_capacity;
    void *entries;
    char (*runtime_paths)[WVM_ADMISSION_SLOT_PATH_MAX];
    char state_directory[WVM_ADMISSION_SLOT_PATH_MAX];
    char runtime_directory[WVM_ADMISSION_SLOT_PATH_MAX];
    int initialized;
};

int wvm_admission_slot_registry_init(
    struct wvm_admission_slot_registry *registry,
    const struct wvm_admission_slot_registry_config *config, char *error,
    size_t error_len);

void wvm_admission_slot_registry_destroy(
    struct wvm_admission_slot_registry *registry);

/* Signature-compatible resolver for wvm_admission_receiver_config. */
int wvm_admission_slot_registry_resolve(
    void *context, uint32_t vm_id, uint64_t vm_incarnation,
    uint64_t manifest_generation, struct wvm_admission_receiver_slot **slot_out,
    char *error, size_t error_len);

#endif /* WAVEVM_ADMISSION_SLOT_REGISTRY_H */
