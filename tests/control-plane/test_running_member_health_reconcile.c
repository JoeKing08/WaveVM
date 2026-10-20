/*
 * goal §1: continuous RUNNING required-member unhealthy -> DEGRADED -> FAILED.
 */
#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "wavevm_control_plane.h"
#include "wavevm_lifecycle.h"
#include "wavevm_membership_controller.h"
#include "wavevm_identity.h"
#include "wavevm_runtime_names.h"
#include "wavevm_lifecycle.h"
#include "wavevm_canonical.h"
#include "wavevm_manifest.h"

struct authorization_context {
    unsigned int calls;
};

static int expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        return 1;
    }
    return 0;
}

static int member_key_equal(const struct wvm_member_key *left,
                            const struct wvm_member_key *right)
{
    return left && right && left->role_type == right->role_type &&
           left->role_id == right->role_id &&
           left->instance_id == right->instance_id;
}

static int authorize_self(
    void *context, enum wvm_membership_controller_authorization_action action,
    const struct wvm_member_key *actor, const struct wvm_member_key *subject,
    char *error, size_t error_len)
{
    struct authorization_context *authorization = context;
    (void)action;
    (void)error;
    (void)error_len;
    if (!authorization || !member_key_equal(actor, subject)) {
        return -1;
    }
    authorization->calls++;
    return 0;
}

static void fill_id(uint8_t id[WVM_IDENTITY_ID_BYTES], uint8_t tag)
{
    memset(id, 0, WVM_IDENTITY_ID_BYTES);
    id[WVM_IDENTITY_ID_BYTES - 1] = tag;
}

int main(void)
{
    char admission_path[] = "/tmp/wavevm-reconcile-adm.XXXXXX";
    char membership_path[] = "/tmp/wavevm-reconcile-memb.XXXXXX";
    char control_path[] = "/tmp/wavevm-reconcile-ctl.XXXXXX";
    char error[256];
    int fd;
    struct wvm_control_plane plane;
    struct wvm_control_plane_entry entries[4];
    struct wvm_control_plane_route_entry route_entries[4];
    struct wvm_vm_namespace_record namespace_records[4];
    struct wvm_vm_namespace_allocator namespace_allocator;
    struct wvm_membership_controller_member_entry members[4];
    struct wvm_membership_controller_route_entry routes[4];
    struct wvm_membership_dependency dependencies[4];
    struct wvm_membership_control_operation operations[8];
    struct wvm_control_plane_membership_config config;
    struct authorization_context authorization = {0};
    struct wvm_admission_transaction_record *tx;
    size_t transitioned = 0;
    int failed = 0;

    fd = mkstemp(admission_path);
    if (fd < 0) {
        perror("mkstemp adm");
        return 1;
    }
    close(fd);
    unlink(admission_path);
    fd = mkstemp(membership_path);
    if (fd < 0) {
        return 1;
    }
    close(fd);
    unlink(membership_path);
    fd = mkstemp(control_path);
    if (fd < 0) {
        return 1;
    }
    close(fd);
    unlink(control_path);

    memset(&plane, 0, sizeof(plane));
    memset(entries, 0, sizeof(entries));
    memset(route_entries, 0, sizeof(route_entries));
    memset(members, 0, sizeof(members));
    memset(routes, 0, sizeof(routes));
    memset(dependencies, 0, sizeof(dependencies));
    memset(operations, 0, sizeof(operations));
    wvm_control_plane_init(&plane, entries, 4);
    wvm_control_plane_set_route_transaction_entries(&plane, route_entries, 4);

    memset(&config, 0, sizeof(config));
    config.members = members;
    config.member_capacity = 4;
    config.routes = routes;
    config.route_capacity = 4;
    config.dependencies = dependencies;
    config.dependency_capacity = 4;
    config.operations = operations;
    config.operation_capacity = 8;
    config.membership_journal_path = membership_path;
    config.control_journal_path = control_path;
    config.authorize = authorize_self;
    config.authorize_context = &authorization;

    wvm_vm_namespace_allocator_init(&namespace_allocator, namespace_records, 4,
                                    1);
    if (expect(wvm_control_plane_configure_membership(&plane, &config, error,
                                                      sizeof(error)) == 0,
               "configure membership") ||
        expect(wvm_control_plane_open_membership(&plane, error, sizeof(error)) ==
                   0,
               "open membership") ||
        expect(wvm_control_plane_open(&plane, admission_path,
                                      &namespace_allocator, error,
                                      sizeof(error)) == 0,
               "open control plane")) {
        fprintf(stderr, "%s\n", error);
        failed = 1;
        goto out;
    }

    /*
     * Seed durable RUNNING without recorded deps. required_members_healthy
     * fail-closes (matched==0 -> unhealthy), so reconcile must DEGRADE then
     * FAIL — proves continuous loop beyond CREATE-return only.
     */

    tx = &plane.entries[0].transaction;
    memset(tx, 0, sizeof(*tx));
    fill_id(tx->request_id, 0x11);
    fill_id(tx->admission_tx_id, 0x22);
    fill_id(tx->manifest_id, 0x33);
    tx->vm_id = 300;
    tx->vm_incarnation = 1;
    tx->manifest_generation = 1;
    tx->route_scope_key.vm_id = 300;
    tx->route_scope_key.vm_incarnation = 1;
    tx->route_scope_key.route_scope_id = 1;
    tx->state = WVM_LIFECYCLE_RUNNING;
    tx->transaction_sequence = 0;
    memset(tx->request_digest, 0x55, sizeof(tx->request_digest));
    tx->has_candidate_manifest_digest = 1;
    memset(tx->candidate_manifest_digest, 0x44,
           sizeof(tx->candidate_manifest_digest));
    tx->has_prepared_route_snapshot_key = 1;
    tx->prepared_route_snapshot_key.scope_key = tx->route_scope_key;
    tx->prepared_route_snapshot_key.topology_revision = 1;
    tx->prepared_route_snapshot_key.route_generation = 1;
    memset(tx->prepared_route_snapshot_key.snapshot_digest, 0x66,
           sizeof(tx->prepared_route_snapshot_key.snapshot_digest));
    plane.entry_count = 1;

    transitioned = 0;
    if (expect(wvm_control_plane_reconcile_required_member_health(
                   &plane, &plane.membership_controller, &transitioned, error,
                   sizeof(error)) == 0 &&
                   transitioned == 1 &&
                   plane.entries[0].transaction.state == WVM_LIFECYCLE_DEGRADED,
               "RUNNING + unhealthy -> durable DEGRADED")) {
        fprintf(stderr, "state=%u transitioned=%zu err=%s\n",
                (unsigned)plane.entries[0].transaction.state, transitioned,
                error);
        failed = 1;
        goto out;
    }

    transitioned = 0;
    if (expect(wvm_control_plane_reconcile_required_member_health(
                   &plane, &plane.membership_controller, &transitioned, error,
                   sizeof(error)) == 0 &&
                   transitioned == 1 &&
                   plane.entries[0].transaction.state == WVM_LIFECYCLE_FAILED,
               "DEGRADED + still unhealthy -> durable FAILED")) {
        fprintf(stderr, "state=%u transitioned=%zu err=%s\n",
                (unsigned)plane.entries[0].transaction.state, transitioned,
                error);
        failed = 1;
        goto out;
    }

    transitioned = 0;
    if (expect(wvm_control_plane_reconcile_required_member_health(
                   &plane, &plane.membership_controller, &transitioned, error,
                   sizeof(error)) == 0 &&
                   transitioned == 0,
               "FAILED is terminal for reconcile")) {
        failed = 1;
        goto out;
    }

    /*
     * A12: required runtime/executor child death — durable runtime manifest
     * whose ready owner is absent must DEGRADE a RUNNING VM (ready-owner probe).
     */
    {
        struct wvm_control_plane_runtime_manifest_entry runtime_entries[2];
        struct wvm_local_name_namespace local_names;
        struct wvm_canonical_builder builder;
        uint8_t local_names_bytes[512];
        uint8_t record[1024];
        uint8_t *rt_bytes = NULL;
        size_t local_names_len = 0;
        size_t rt_len = 0;
        uint8_t dig[WVM_SHA256_DIGEST_BYTES];
        char enc_err[256];
        uint8_t *field_value;

        memset(runtime_entries, 0, sizeof(runtime_entries));
        wvm_control_plane_set_runtime_manifest_entries(&plane, runtime_entries,
                                                       2);
        memset(&local_names, 0, sizeof(local_names));
        snprintf(local_names.namespace_name, sizeof(local_names.namespace_name),
                 "a12reap%x", (unsigned)getpid());
        memset(local_names.derivation_salt_digest, 0xab,
               sizeof(local_names.derivation_salt_digest));
        local_names.name_generation = 1;
        enc_err[0] = '\0';
        if (wvm_local_name_namespace_encode(&local_names, local_names_bytes,
                                            sizeof(local_names_bytes),
                                            &local_names_len, enc_err,
                                            sizeof(enc_err)) != 0) {
            fprintf(stderr, "A12 encode local_names: %s\n", enc_err);
            failed = 1;
            goto out;
        }
        /* Minimal NodeRuntimeManifest (0x101e) with field 15 = local_names. */
        if (wvm_canonical_record_begin(&builder, record, sizeof(record),
                                       WVM_RECORD_NODE_RUNTIME_MANIFEST) != 0 ||
            wvm_canonical_field_reserve(&builder, 15,
                                        (uint32_t)local_names_len,
                                        &field_value) != 0) {
            fprintf(stderr, "A12 build runtime record failed\n");
            failed = 1;
            goto out;
        }
        memcpy(field_value, local_names_bytes, local_names_len);
        if (wvm_canonical_record_finish(&builder, &rt_len) != 0) {
            fprintf(stderr, "A12 finish runtime record failed\n");
            failed = 1;
            goto out;
        }
        rt_bytes = malloc(rt_len);
        if (!rt_bytes) {
            failed = 1;
            goto out;
        }
        memcpy(rt_bytes, record, rt_len);
        memset(dig, 0x44, sizeof(dig));
        runtime_entries[0].record_bytes = rt_bytes;
        runtime_entries[0].record_byte_count = rt_len;
        memcpy(runtime_entries[0].candidate_manifest_digest, dig, sizeof(dig));
        runtime_entries[0].physical_node_id = 1;
        runtime_entries[0].expected_node_instance_id = 9;
        fill_id(runtime_entries[0].reservation_id, 0x74);
        plane.runtime_manifest_entry_count = 1;

        tx = &plane.entries[0].transaction;
        memset(tx, 0, sizeof(*tx));
        fill_id(tx->request_id, 0x81);
        fill_id(tx->admission_tx_id, 0x71);
        fill_id(tx->manifest_id, 0x82);
        tx->vm_id = 400;
        tx->vm_incarnation = 1;
        tx->manifest_generation = 1;
        tx->route_scope_key.vm_id = 400;
        tx->route_scope_key.vm_incarnation = 1;
        tx->route_scope_key.route_scope_id = 1;
        tx->state = WVM_LIFECYCLE_RUNNING;
        tx->has_candidate_manifest_digest = 1;
        memcpy(tx->candidate_manifest_digest, dig, sizeof(dig));
        tx->has_prepared_route_snapshot_key = 1;
        tx->prepared_route_snapshot_key.scope_key = tx->route_scope_key;
        tx->prepared_route_snapshot_key.topology_revision = 1;
        tx->prepared_route_snapshot_key.route_generation = 1;
        memset(tx->prepared_route_snapshot_key.snapshot_digest, 0x75,
               sizeof(tx->prepared_route_snapshot_key.snapshot_digest));
        memset(tx->request_digest, 0x55, sizeof(tx->request_digest));
        plane.entry_count = 1;

        {
            struct wvm_runtime_name_set names;
            char derr[128];
            if (wvm_runtime_name_set_derive(&local_names, &names, derr,
                                            sizeof(derr)) == 0) {
                unlink(names.ready_file);
            }
        }

        transitioned = 0;
        if (expect(wvm_control_plane_reconcile_required_member_health(
                       &plane, &plane.membership_controller, &transitioned,
                       error, sizeof(error)) == 0 &&
                       transitioned == 1 &&
                       plane.entries[0].transaction.state ==
                           WVM_LIFECYCLE_DEGRADED,
                   "A12 RUNNING + dead runtime ready → DEGRADED")) {
            fprintf(stderr, "A12 state=%u transitioned=%zu err=%s\n",
                    (unsigned)plane.entries[0].transaction.state, transitioned,
                    error);
            failed = 1;
            free(rt_bytes);
            runtime_entries[0].record_bytes = NULL;
            goto out;
        }
        free(rt_bytes);
        runtime_entries[0].record_bytes = NULL;
        plane.runtime_manifest_entry_count = 0;
    }

    printf("test_running_member_health_reconcile: PASS\n");
out:
    wvm_control_plane_close_membership(&plane);
    wvm_control_plane_close(&plane);
    unlink(admission_path);
    unlink(membership_path);
    unlink(control_path);
    return failed;
}
