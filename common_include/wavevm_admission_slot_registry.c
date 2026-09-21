#include "wavevm_admission_slot_registry.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct registry_entry {
    uint32_t vm_id;
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    int in_use;
    int failed;
};

static void set_error(char *error, size_t error_len, const char *message)
{
    if (error && error_len != 0) {
        (void)snprintf(error, error_len, "%s", message);
    }
}

static int copy_path(char *destination, size_t destination_bytes,
                     const char *source)
{
    int written;

    if (!destination || destination_bytes == 0 || !source || source[0] == '\0') {
        return -1;
    }
    written = snprintf(destination, destination_bytes, "%s", source);
    return written < 0 || (size_t)written >= destination_bytes ? -1 : 0;
}

static int directory_exists(const char *path)
{
    struct stat info;

    return path && stat(path, &info) == 0 && S_ISDIR(info.st_mode);
}

static int identity_matches(const struct registry_entry *entry, uint32_t vm_id,
                            uint64_t vm_incarnation,
                            uint64_t manifest_generation)
{
    return entry && entry->in_use && entry->vm_id == vm_id &&
           entry->vm_incarnation == vm_incarnation &&
           entry->manifest_generation == manifest_generation;
}

int wvm_admission_slot_registry_init(
    struct wvm_admission_slot_registry *registry,
    const struct wvm_admission_slot_registry_config *config, char *error,
    size_t error_len)
{
    struct registry_entry *entries;
    size_t i;

    if (!registry || !config || !config->receiver || !config->slots ||
        config->slot_capacity == 0 ||
        config->slot_capacity > SIZE_MAX / sizeof(*entries) ||
        !directory_exists(config->state_directory) ||
        !directory_exists(config->runtime_directory) ||
        strlen(config->state_directory) >= WVM_ADMISSION_SLOT_PATH_MAX ||
        strlen(config->runtime_directory) >= WVM_ADMISSION_SLOT_PATH_MAX) {
        set_error(error, error_len, "admission slot registry configuration is invalid");
        return -EINVAL;
    }
    memset(registry, 0, sizeof(*registry));
    if (copy_path(registry->state_directory, sizeof(registry->state_directory),
                  config->state_directory) != 0 ||
        copy_path(registry->runtime_directory,
                  sizeof(registry->runtime_directory),
                  config->runtime_directory) != 0 ||
        pthread_mutex_init(&registry->lock, NULL) != 0) {
        set_error(error, error_len, "cannot initialize admission slot registry");
        return -1;
    }
    entries = calloc(config->slot_capacity, sizeof(*entries));
    registry->runtime_paths = calloc(
        config->slot_capacity, sizeof(*registry->runtime_paths));
    if (!entries || !registry->runtime_paths) {
        free(entries);
        free(registry->runtime_paths);
        pthread_mutex_destroy(&registry->lock);
        memset(registry, 0, sizeof(*registry));
        set_error(error, error_len, "cannot allocate admission slot registry");
        return -ENOMEM;
    }
    registry->receiver = config->receiver;
    registry->slots = config->slots;
    registry->slot_capacity = config->slot_capacity;
    registry->entries = entries;
    registry->initialized = 1;
    for (i = 0; i < registry->slot_capacity; i++) {
        wvm_admission_receiver_slot_init(&registry->slots[i]);
    }
    return 0;
}

void wvm_admission_slot_registry_destroy(
    struct wvm_admission_slot_registry *registry)
{
    struct registry_entry *entries;
    size_t i;

    if (!registry) {
        return;
    }
    entries = registry->entries;
    if (registry->initialized) {
        for (i = 0; i < registry->slot_capacity; i++) {
            if (entries && entries[i].in_use) {
                wvm_admission_receiver_slot_close(&registry->slots[i]);
                registry->slots[i].runtime_manifest_path = NULL;
            }
        }
        pthread_mutex_destroy(&registry->lock);
    }
    free(entries);
    free(registry->runtime_paths);
    memset(registry, 0, sizeof(*registry));
}

int wvm_admission_slot_registry_resolve(
    void *context, uint32_t vm_id, uint64_t vm_incarnation,
    uint64_t manifest_generation, struct wvm_admission_receiver_slot **slot_out,
    char *error, size_t error_len)
{
    struct wvm_admission_slot_registry *registry = context;
    struct registry_entry *entries;
    size_t free_index = SIZE_MAX;
    size_t i;
    char state_path[WVM_ADMISSION_SLOT_PATH_MAX];
    int written;

    if (!registry || !registry->initialized || !slot_out || vm_id == 0 ||
        vm_incarnation == 0 || manifest_generation == 0) {
        set_error(error, error_len, "admission slot lookup is invalid");
        return -EINVAL;
    }
    entries = registry->entries;
    pthread_mutex_lock(&registry->lock);
    for (i = 0; i < registry->slot_capacity; i++) {
        if (identity_matches(&entries[i], vm_id, vm_incarnation,
                             manifest_generation)) {
            if (entries[i].failed) {
                pthread_mutex_unlock(&registry->lock);
                set_error(error, error_len,
                          "admission slot requires recovery before reuse");
                return -EIO;
            }
            *slot_out = &registry->slots[i];
            pthread_mutex_unlock(&registry->lock);
            return 0;
        }
        if (!entries[i].in_use && !entries[i].failed && free_index == SIZE_MAX) {
            free_index = i;
        }
    }
    if (free_index == SIZE_MAX) {
        pthread_mutex_unlock(&registry->lock);
        set_error(error, error_len, "admission slot registry is full");
        return -ENOSPC;
    }
    written = snprintf(
        registry->runtime_paths[free_index], WVM_ADMISSION_SLOT_PATH_MAX,
        "%s/vm-%" PRIu32 "-%" PRIu64 "-%" PRIu64 ".manifest",
        registry->runtime_directory, vm_id, vm_incarnation,
        manifest_generation);
    if (written < 0 || (size_t)written >= WVM_ADMISSION_SLOT_PATH_MAX) {
        pthread_mutex_unlock(&registry->lock);
        set_error(error, error_len, "runtime manifest path is too long");
        return -ENAMETOOLONG;
    }
    written = snprintf(state_path, sizeof(state_path),
                       "%s/vm-%" PRIu32 "-%" PRIu64 "-%" PRIu64 ".stage",
                       registry->state_directory, vm_id, vm_incarnation,
                       manifest_generation);
    if (written < 0 || (size_t)written >= sizeof(state_path)) {
        pthread_mutex_unlock(&registry->lock);
        set_error(error, error_len, "participant state path is too long");
        return -ENAMETOOLONG;
    }
    registry->slots[free_index].runtime_manifest_path =
        registry->runtime_paths[free_index];
    entries[free_index].vm_id = vm_id;
    entries[free_index].vm_incarnation = vm_incarnation;
    entries[free_index].manifest_generation = manifest_generation;
    entries[free_index].in_use = 1;
    if (wvm_admission_receiver_slot_open(
            registry->receiver, &registry->slots[free_index], state_path,
            vm_id, vm_incarnation, manifest_generation, error, error_len) != 0) {
        entries[free_index].failed = 1;
        pthread_mutex_unlock(&registry->lock);
        return -EIO;
    }
    *slot_out = &registry->slots[free_index];
    pthread_mutex_unlock(&registry->lock);
    return 0;
}
