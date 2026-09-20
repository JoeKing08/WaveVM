#define _GNU_SOURCE

#include "runtime_profile_publication.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

static int read_profile(int fd, uint8_t **bytes_out, size_t *size_out,
                        struct wvm_node_runtime_profile *profile, char *error,
                        size_t error_len)
{
    struct stat status;
    uint8_t *bytes;
    size_t size, offset = 0;

    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_size <= 0 ||
        status.st_size > WVM_NODE_RUNTIME_PROFILE_MAX_BYTES) {
        snprintf(error, error_len,
                 "runtime profile file is invalid or oversized");
        return -1;
    }
    size = (size_t)status.st_size;
    bytes = malloc(size);
    if (!bytes) {
        return -1;
    }
    while (offset < size) {
        ssize_t count = read(fd, bytes + offset, size - offset);

        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            free(bytes);
            snprintf(error, error_len, "runtime profile read failed");
            return -1;
        }
        offset += (size_t)count;
    }
    if (wvm_node_runtime_profile_decode(bytes, size, profile, error,
                                        error_len) != 0) {
        free(bytes);
        return -1;
    }
    *bytes_out = bytes;
    *size_out = size;
    return 0;
}

static int profile_matches_node(
    const struct wvm_node_runtime_profile *profile,
    const struct wvm_node_record *node, char *error, size_t error_len)
{
    if (!profile || !node ||
        profile->physical_node_id != node->physical_node_id ||
        profile->node_instance_id != node->node_instance_id ||
        profile->inventory_revision != node->inventory.inventory_revision ||
        profile->capability_profile_generation !=
            node->capability.profile_generation) {
        snprintf(error, error_len,
                 "runtime profile differs from registered node revisions");
        return -1;
    }
    return 0;
}

int wvm_ctl_load_runtime_profile(
    const char *state_directory, const struct wvm_node_record *node,
    struct wvm_node_runtime_profile *profile, char *error, size_t error_len)
{
    struct wvm_node_runtime_profile loaded = {0};
    char filename[64];
    uint8_t *bytes = NULL;
    size_t size = 0;
    int dirfd, fd, result = -1;

    if (!state_directory || !node || !profile) {
        return -1;
    }
    snprintf(filename, sizeof(filename), "runtime-profile-%" PRIu32 ".record",
             node->physical_node_id);
    dirfd = open(state_directory, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    if (dirfd < 0) {
        return -1;
    }
    fd = openat(dirfd, filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    close(dirfd);
    if (fd < 0) {
        snprintf(error, error_len,
                 "registered node has no runtime profile publication");
        return -1;
    }
    if (read_profile(fd, &bytes, &size, &loaded, error, error_len) == 0 &&
        profile_matches_node(&loaded, node, error, error_len) == 0) {
        wvm_node_runtime_profile_destroy(profile);
        *profile = loaded;
        memset(&loaded, 0, sizeof(loaded));
        result = 0;
    }
    close(fd);
    free(bytes);
    wvm_node_runtime_profile_destroy(&loaded);
    return result;
}

void wvm_ctl_runtime_profile_set_destroy(
    struct wvm_ctl_runtime_profile_set *set)
{
    size_t i;

    if (!set) {
        return;
    }
    for (i = 0; i < set->profile_count; i++) {
        wvm_node_runtime_profile_destroy(&set->profiles[i]);
    }
    free(set->profiles);
    memset(set, 0, sizeof(*set));
}

int wvm_ctl_load_runtime_profile_set(
    const char *state_directory,
    const struct wvm_membership_controller_capture *capture,
    struct wvm_ctl_runtime_profile_set *set, char *error, size_t error_len)
{
    struct wvm_ctl_runtime_profile_set loaded = {0};
    size_t i;

    if (!state_directory || !capture || !set || !capture->nodes ||
        capture->node_count == 0 ||
        capture->node_count > SIZE_MAX / sizeof(*loaded.profiles)) {
        snprintf(error, error_len,
                 "runtime profiles require a nonempty membership capture");
        return -1;
    }
    loaded.profiles = calloc(capture->node_count, sizeof(*loaded.profiles));
    if (!loaded.profiles) {
        return -1;
    }
    loaded.profile_count = capture->node_count;
    for (i = 0; i < capture->node_count; i++) {
        if (wvm_ctl_load_runtime_profile(
                state_directory, &capture->nodes[i], &loaded.profiles[i],
                error, error_len) != 0) {
            wvm_ctl_runtime_profile_set_destroy(&loaded);
            return -1;
        }
    }
    wvm_ctl_runtime_profile_set_destroy(set);
    *set = loaded;
    return 0;
}

static int persist_profile(const char *directory, uint32_t node_id,
                           const uint8_t *bytes, size_t size, char *error,
                           size_t error_len)
{
    char filename[64], temporary[4096];
    size_t offset = 0;
    int dirfd, fd = -1, result = -1, written;

    snprintf(filename, sizeof(filename), "runtime-profile-%" PRIu32 ".record",
             node_id);
    written = snprintf(temporary, sizeof(temporary),
                       "%s/.runtime-profile-XXXXXX", directory);
    if (written < 0 || (size_t)written >= sizeof(temporary)) {
        return -1;
    }
    dirfd = open(directory, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    if (dirfd < 0) {
        return -1;
    }
    fd = mkostemp(temporary, O_CLOEXEC);
    if (fd < 0) {
        goto out;
    }
    while (offset < size) {
        ssize_t count = write(fd, bytes + offset, size - offset);

        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            goto out;
        }
        offset += (size_t)count;
    }
    if (fsync(fd) != 0 ||
        renameat(AT_FDCWD, temporary, dirfd, filename) != 0 ||
        fsync(dirfd) != 0) {
        goto out;
    }
    result = 0;
out:
    if (result != 0) {
        snprintf(error, error_len, "cannot persist runtime profile: %s",
                 strerror(errno));
    }
    if (fd >= 0) {
        close(fd);
        unlink(temporary);
    }
    close(dirfd);
    return result;
}

int wvm_ctl_publish_runtime_profile(
    const char *state_directory, struct wvm_membership_controller *controller,
    const struct wvm_envelope *request, const struct wvm_member_key *actor,
    struct wvm_control_result *result, char *error, size_t error_len)
{
    struct wvm_node_runtime_profile profile = {0};
    struct wvm_membership_controller_member_status member;
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    int rc = 0;

    if (!result || !request) {
        return -EINVAL;
    }
    memset(result, 0, sizeof(*result));
    memcpy(result->in_reply_to_operation_id, request->operation_id,
           sizeof(result->in_reply_to_operation_id));
    memcpy(result->record_digest, request->semantic_payload_digest,
           sizeof(result->record_digest));
    result->status_code = WVM_CONTROL_RESULT_UNAUTHORIZED_ROLE;
    if (!actor || actor->role_type != WVM_MANIFEST_ROLE_NODE_RUNTIME ||
        actor->role_id != request->origin_physical_node_id ||
        actor->instance_id != request->origin_runtime_instance_id ||
        wvm_member_key_validate(actor, error, error_len) != 0) {
        return 0;
    }
    result->status_code = WVM_CONTROL_RESULT_INVALID_ENVELOPE;
    wvm_envelope_semantic_digest(request->payload, request->payload_bytes,
                                 digest);
    if (request->message_type != WVM_ENVELOPE_MSG_PUBLISH_RUNTIME_PROFILE ||
        request->vm_id || request->vm_incarnation ||
        request->manifest_generation ||
        memcmp(digest, request->semantic_payload_digest, sizeof(digest)) != 0) {
        return 0;
    }
    result->status_code = WVM_CONTROL_RESULT_INVALID_REQUEST;
    if (wvm_node_runtime_profile_decode(request->payload,
                                        request->payload_bytes, &profile,
                                        error, error_len) != 0 ||
        profile.physical_node_id != actor->role_id ||
        profile.node_instance_id != actor->instance_id) {
        goto out;
    }
    result->status_code = WVM_CONTROL_RESULT_STALE_INSTANCE;
    if (wvm_membership_controller_member_status(controller, actor, &member,
                                                 error, error_len) != 0 ||
        member.kind != WVM_MEMBERSHIP_COMPUTE ||
        member.desired_membership_state == WVM_MANIFEST_MEMBER_REMOVED) {
        goto out;
    }
    result->status_code = WVM_CONTROL_RESULT_PRECONDITION_FAILED;
    if (profile.inventory_revision != member.inventory_revision ||
        profile.capability_profile_generation !=
            member.capability.profile_generation) {
        snprintf(error, error_len,
                 "runtime profile does not match registered node revisions");
        goto out;
    }
    if (persist_profile(state_directory, actor->role_id, request->payload,
                        request->payload_bytes, error, error_len) != 0) {
        rc = -EIO;
        goto out;
    }
    result->status_code = WVM_CONTROL_RESULT_SUCCESS;
    result->applied_revision = profile.runtime_profile_generation;
out:
    wvm_node_runtime_profile_destroy(&profile);
    return rc;
}

int wvm_ctl_runtime_profile_publish_command(int argc, char **argv)
{
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    struct ucred credentials;
    socklen_t credential_bytes = sizeof(credentials);
    struct timeval timeout = {.tv_sec = 10};
    struct wvm_node_runtime_profile profile = {0};
    struct wvm_envelope request = {0};
    struct wvm_control_result result;
    char error[256] = {0}, *end;
    uint8_t *bytes = NULL;
    size_t size = 0;
    uint64_t peer_node, peer_instance;
    unsigned long peer_uid;
    int fd = -1, stream = -1, rc = 1;

    if (argc != 10 || strcmp(argv[2], "--socket") ||
        strcmp(argv[4], "--peer") || strcmp(argv[8], "--profile") ||
        strlen(argv[3]) >= sizeof(address.sun_path)) {
        fprintf(stderr,
                "Usage: %s publish-runtime-profile --socket PATH --peer "
                "NODE INSTANCE UID --profile FILE\n",
                argv[0]);
        return 2;
    }
    errno = 0;
    peer_node = strtoull(argv[5], &end, 10);
    if (errno || end == argv[5] || *end || !peer_node ||
        peer_node > UINT32_MAX) {
        return 2;
    }
    errno = 0;
    peer_instance = strtoull(argv[6], &end, 10);
    if (errno || argv[6][0] == '-' || end == argv[6] || *end ||
        !peer_instance) {
        return 2;
    }
    errno = 0;
    peer_uid = strtoul(argv[7], &end, 10);
    if (errno || end == argv[7] || *end || peer_uid != (uid_t)peer_uid) {
        return 2;
    }
    fd = open(argv[9], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 ||
        read_profile(fd, &bytes, &size, &profile, error, sizeof(error)) != 0) {
        goto out;
    }
    stream = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    strcpy(address.sun_path, argv[3]);
    if (stream < 0 ||
        connect(stream, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        getsockopt(stream, SOL_SOCKET, SO_PEERCRED, &credentials,
                   &credential_bytes) != 0 ||
        credential_bytes != sizeof(credentials) ||
        credentials.uid != (uid_t)peer_uid ||
        setsockopt(stream, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) != 0 ||
        setsockopt(stream, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   sizeof(timeout)) != 0) {
        snprintf(error, sizeof(error),
                 "cannot connect to authenticated control peer");
        goto out;
    }
    request.message_type = WVM_ENVELOPE_MSG_PUBLISH_RUNTIME_PROFILE;
    request.origin_physical_node_id = profile.physical_node_id;
    request.origin_runtime_instance_id = profile.node_instance_id;
    if (getrandom(request.operation_id, sizeof(request.operation_id), 0) !=
        sizeof(request.operation_id)) {
        goto out;
    }
    request.delivery_attempt_id = 1;
    request.payload = bytes;
    request.payload_bytes = size;
    wvm_envelope_semantic_digest(bytes, size,
                                 request.semantic_payload_digest);
    if (wvm_control_transport_exchange(
            stream, (uint32_t)peer_node, peer_instance, &request, &result,
            error, sizeof(error)) != 0 ||
        result.status_code != WVM_CONTROL_RESULT_SUCCESS ||
        result.applied_revision != profile.runtime_profile_generation ||
        memcmp(result.record_digest, request.semantic_payload_digest,
               sizeof(result.record_digest)) != 0) {
        if (error[0] == '\0') {
            snprintf(error, sizeof(error),
                     "runtime profile publication rejected (status %u)",
                     result.status_code);
        }
        goto out;
    }
    printf("runtime profile published: node=%" PRIu32 " instance=%" PRIu64
           " generation=%" PRIu64 "\n",
           profile.physical_node_id, profile.node_instance_id,
           profile.runtime_profile_generation);
    rc = 0;
out:
    if (rc) {
        fprintf(stderr, "wvm_ctl: %s\n",
                error[0] ? error : strerror(errno));
    }
    if (fd >= 0) {
        close(fd);
    }
    if (stream >= 0) {
        close(stream);
    }
    free(bytes);
    wvm_node_runtime_profile_destroy(&profile);
    return rc;
}
