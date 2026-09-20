#define _GNU_SOURCE

#include "capability_publication.h"

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

static int report_matches(const struct wvm_capability_report *report,
                          const struct wvm_capability_ref *reference,
                          char *error, size_t error_len)
{
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];

    if (report->profile_generation != reference->profile_generation ||
        wvm_capability_profile_digest(
            reference->physical_node_id, reference->node_instance_id,
            reference->profile_generation, report->records, report->record_count,
            digest, error, error_len) != 0 ||
        memcmp(digest, reference->profile_digest, sizeof(digest)) != 0) {
        snprintf(error, error_len, "capability report differs from registered profile");
        return -1;
    }
    return 0;
}

static int read_report(int fd, uint8_t **bytes_out, size_t *size_out,
                       struct wvm_capability_report *report,
                       char *error, size_t error_len)
{
    struct stat status;
    uint8_t *bytes;
    size_t size, offset = 0;

    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_size <= 0 || status.st_size > WVM_CAPABILITY_REPORT_MAX_BYTES) {
        snprintf(error, error_len, "capability report file is invalid or oversized");
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
            snprintf(error, error_len, "capability report read failed");
            return -1;
        }
        offset += (size_t)count;
    }
    if (wvm_capability_report_decode(bytes, size, report, error, error_len) != 0) {
        free(bytes);
        return -1;
    }
    *bytes_out = bytes;
    *size_out = size;
    return 0;
}

int wvm_ctl_load_capabilities(
    const char *state_directory, const struct wvm_capability_ref *reference,
    struct wvm_capability_report *report, char *error, size_t error_len)
{
    struct wvm_capability_report loaded = {0};
    char filename[64];
    uint8_t *bytes = NULL;
    size_t size;
    int dirfd, fd, result = -1;

    if (!state_directory || !reference || !report) {
        return -1;
    }
    snprintf(filename, sizeof(filename), "capabilities-%" PRIu32 ".record",
             reference->physical_node_id);
    dirfd = open(state_directory, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    if (dirfd < 0) {
        return -1;
    }
    fd = openat(dirfd, filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    close(dirfd);
    if (fd < 0) {
        snprintf(error, error_len, "registered node has no capability publication");
        return -1;
    }
    if (read_report(fd, &bytes, &size, &loaded, error, error_len) == 0 &&
        report_matches(&loaded, reference, error, error_len) == 0) {
        wvm_capability_report_destroy(report);
        *report = loaded;
        memset(&loaded, 0, sizeof(loaded));
        result = 0;
    }
    close(fd);
    free(bytes);
    wvm_capability_report_destroy(&loaded);
    return result;
}

static int capability_record_compare(const void *left_value,
                                     const void *right_value)
{
    const struct wvm_capability_record *left = left_value;
    const struct wvm_capability_record *right = right_value;

    if (left->physical_node_id != right->physical_node_id) {
        return left->physical_node_id < right->physical_node_id ? -1 : 1;
    }
    if (left->node_instance_id != right->node_instance_id) {
        return left->node_instance_id < right->node_instance_id ? -1 : 1;
    }
    if (left->capability_id != right->capability_id) {
        return left->capability_id < right->capability_id ? -1 : 1;
    }
    if (left->provider_instance_id != right->provider_instance_id) {
        return left->provider_instance_id < right->provider_instance_id ? -1
                                                                        : 1;
    }
    return 0;
}

void wvm_ctl_capability_evidence_destroy(
    struct wvm_ctl_capability_evidence *evidence)
{
    size_t i;

    if (!evidence) {
        return;
    }
    for (i = 0; i < evidence->report_count; i++) {
        wvm_capability_report_destroy(&evidence->reports[i]);
    }
    free(evidence->reports);
    free(evidence->records);
    memset(evidence, 0, sizeof(*evidence));
}

int wvm_ctl_load_capability_evidence(
    const char *state_directory,
    const struct wvm_membership_controller_capture *capture,
    struct wvm_ctl_capability_evidence *evidence, char *error,
    size_t error_len)
{
    struct wvm_ctl_capability_evidence loaded = {0};
    size_t record_count = 0, record_offset = 0, i;

    if (!state_directory || !capture || !evidence || !capture->nodes ||
        capture->node_count == 0) {
        snprintf(error, error_len,
                 "capability evidence requires a nonempty membership capture");
        return -1;
    }
    loaded.reports = calloc(capture->node_count, sizeof(*loaded.reports));
    if (!loaded.reports) {
        return -1;
    }
    loaded.report_count = capture->node_count;
    loaded.inventory_revision = capture->nodes[0].inventory.inventory_revision;
    loaded.profile_generation = capture->nodes[0].capability.profile_generation;
    if (loaded.inventory_revision == 0 || loaded.profile_generation == 0) {
        goto invalid;
    }
    for (i = 0; i < capture->node_count; i++) {
        const struct wvm_node_record *node = &capture->nodes[i];

        if (node->inventory.inventory_revision != loaded.inventory_revision ||
            node->capability.profile_generation != loaded.profile_generation ||
            wvm_ctl_load_capabilities(state_directory, &node->capability,
                                      &loaded.reports[i], error,
                                      error_len) != 0 ||
            loaded.reports[i].record_count > SIZE_MAX - record_count) {
            goto invalid;
        }
        record_count += loaded.reports[i].record_count;
    }
    if (record_count == 0 ||
        record_count > SIZE_MAX / sizeof(*loaded.records)) {
        goto invalid;
    }
    loaded.records = calloc(record_count, sizeof(*loaded.records));
    if (!loaded.records) {
        goto invalid;
    }
    loaded.record_count = record_count;
    loaded.record_capacity = record_count;
    for (i = 0; i < loaded.report_count; i++) {
        memcpy(loaded.records + record_offset, loaded.reports[i].records,
               loaded.reports[i].record_count * sizeof(*loaded.records));
        record_offset += loaded.reports[i].record_count;
    }
    qsort(loaded.records, loaded.record_count, sizeof(*loaded.records),
          capability_record_compare);
    for (i = 1; i < loaded.record_count; i++) {
        if (capability_record_compare(&loaded.records[i - 1],
                                      &loaded.records[i]) >= 0) {
            snprintf(error, error_len,
                     "capability evidence contains duplicate record keys");
            goto invalid;
        }
    }
    wvm_ctl_capability_evidence_destroy(evidence);
    *evidence = loaded;
    return 0;

invalid:
    if (error && error_len != 0 && error[0] == '\0') {
        snprintf(error, error_len,
                 "capability evidence does not match one atomic membership snapshot");
    }
    wvm_ctl_capability_evidence_destroy(&loaded);
    return -1;
}

static int persist_report(const char *directory, uint32_t node_id,
                          const uint8_t *bytes, size_t size,
                          char *error, size_t error_len)
{
    char filename[64], temporary[4096];
    size_t offset = 0;
    int dirfd, fd = -1, result = -1, written;

    snprintf(filename, sizeof(filename), "capabilities-%" PRIu32 ".record", node_id);
    written = snprintf(temporary, sizeof(temporary), "%s/.capabilities-XXXXXX", directory);
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
    if (fsync(fd) != 0 || renameat(AT_FDCWD, temporary, dirfd, filename) != 0 ||
        fsync(dirfd) != 0) {
        goto out;
    }
    result = 0;
out:
    if (result != 0) {
        snprintf(error, error_len, "cannot persist capability report: %s", strerror(errno));
    }
    if (fd >= 0) {
        close(fd);
        unlink(temporary);
    }
    close(dirfd);
    return result;
}

int wvm_ctl_publish_capabilities(
    const char *state_directory, struct wvm_membership_controller *controller,
    const struct wvm_envelope *request, const struct wvm_member_key *actor,
    struct wvm_control_result *result, char *error, size_t error_len)
{
    struct wvm_capability_report report = {0};
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
    wvm_envelope_semantic_digest(request->payload, request->payload_bytes, digest);
    if (request->message_type != WVM_ENVELOPE_MSG_PUBLISH_CAPABILITIES ||
        request->vm_id || request->vm_incarnation || request->manifest_generation ||
        memcmp(digest, request->semantic_payload_digest, sizeof(digest)) != 0) {
        return 0;
    }
    result->status_code = WVM_CONTROL_RESULT_INVALID_REQUEST;
    if (wvm_capability_report_decode(request->payload, request->payload_bytes,
                                     &report, error, error_len) != 0) {
        return 0;
    }
    result->status_code = WVM_CONTROL_RESULT_STALE_INSTANCE;
    if (wvm_membership_controller_member_status(controller, actor, &member,
                                                 error, error_len) != 0 ||
        member.desired_membership_state == WVM_MANIFEST_MEMBER_REMOVED) {
        goto out;
    }
    result->status_code = WVM_CONTROL_RESULT_PRECONDITION_FAILED;
    if (report_matches(&report, &member.capability, error, error_len) != 0) {
        goto out;
    }
    if (persist_report(state_directory, actor->role_id, request->payload,
                        request->payload_bytes, error, error_len) != 0) {
        rc = -EIO;
        goto out;
    }
    result->status_code = WVM_CONTROL_RESULT_SUCCESS;
    result->applied_revision = report.profile_generation;
out:
    wvm_capability_report_destroy(&report);
    return rc;
}

int wvm_ctl_capability_publish_command(int argc, char **argv)
{
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    struct ucred credentials;
    socklen_t credential_bytes = sizeof(credentials);
    struct timeval timeout = {.tv_sec = 10};
    struct wvm_capability_report report = {0};
    struct wvm_envelope request = {0};
    struct wvm_control_result result;
    char error[256] = {0}, *end;
    uint8_t *bytes = NULL;
    size_t size = 0;
    uint64_t peer_node, peer_instance;
    unsigned long peer_uid;
    int fd = -1, stream = -1, rc = 1;

    if (argc != 10 || strcmp(argv[2], "--socket") ||
        strcmp(argv[4], "--peer") || strcmp(argv[8], "--report") ||
        strlen(argv[3]) >= sizeof(address.sun_path)) {
        fprintf(stderr, "Usage: %s publish-capabilities --socket PATH --peer NODE INSTANCE UID --report FILE\n", argv[0]);
        return 2;
    }
    errno = 0;
    peer_node = strtoull(argv[5], &end, 10);
    if (errno || end == argv[5] || *end || !peer_node || peer_node > UINT32_MAX) {
        return 2;
    }
    peer_instance = strtoull(argv[6], &end, 10);
    if (errno || argv[6][0] == '-' || end == argv[6] || *end || !peer_instance) {
        return 2;
    }
    peer_uid = strtoul(argv[7], &end, 10);
    if (errno || end == argv[7] || *end || peer_uid != (uid_t)peer_uid) {
        return 2;
    }
    fd = open(argv[9], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || read_report(fd, &bytes, &size, &report, error, sizeof(error)) != 0) {
        goto out;
    }
    stream = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    strcpy(address.sun_path, argv[3]);
    if (stream < 0 ||
        connect(stream, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        getsockopt(stream, SOL_SOCKET, SO_PEERCRED, &credentials, &credential_bytes) != 0 ||
        credential_bytes != sizeof(credentials) || credentials.uid != (uid_t)peer_uid ||
        setsockopt(stream, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        setsockopt(stream, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
        snprintf(error, sizeof(error), "cannot connect to authenticated control peer");
        goto out;
    }
    request.message_type = WVM_ENVELOPE_MSG_PUBLISH_CAPABILITIES;
    request.origin_physical_node_id = report.records[0].physical_node_id;
    request.origin_runtime_instance_id = report.records[0].node_instance_id;
    if (getrandom(request.operation_id, sizeof(request.operation_id), 0) != sizeof(request.operation_id)) {
        goto out;
    }
    request.delivery_attempt_id = 1;
    request.payload = bytes;
    request.payload_bytes = size;
    wvm_envelope_semantic_digest(bytes, size, request.semantic_payload_digest);
    if (wvm_control_transport_exchange(stream, (uint32_t)peer_node, peer_instance,
                                       &request, &result, error, sizeof(error)) != 0) {
        goto out;
    }
    if (result.status_code != WVM_CONTROL_RESULT_SUCCESS ||
        result.applied_revision != report.profile_generation ||
        memcmp(result.record_digest, request.semantic_payload_digest,
               sizeof(result.record_digest)) != 0) {
        snprintf(error, sizeof(error), "capability publication rejected (status %u)", result.status_code);
        goto out;
    }
    printf("capabilities published: node=%" PRIu32 " instance=%" PRIu64 " generation=%" PRIu64 "\n",
           request.origin_physical_node_id, request.origin_runtime_instance_id,
           report.profile_generation);
    rc = 0;
out:
    if (rc) {
        fprintf(stderr, "wvm_ctl: %s\n", error[0] ? error : strerror(errno));
    }
    if (fd >= 0) close(fd);
    if (stream >= 0) close(stream);
    free(bytes);
    wvm_capability_report_destroy(&report);
    return rc;
}
