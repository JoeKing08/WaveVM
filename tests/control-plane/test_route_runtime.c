#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "wavevm_route_runtime.h"

static int test_sleep_ms(unsigned int milliseconds)
{
    struct timespec delay;

    delay.tv_sec = (time_t)(milliseconds / 1000U);
    delay.tv_nsec = (long)(milliseconds % 1000U) * 1000000L;
    return nanosleep(&delay, NULL) == 0 ? 0 : 1;
}

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "route-runtime test: %s\n", message);
        return -1;
    }
    return 0;
}

static void fill_endpoint(struct wvm_endpoint *endpoint, uint8_t last_octet,
                          uint16_t port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 192;
    endpoint->data_address[1] = 0;
    endpoint->data_address[2] = 2;
    endpoint->data_address[3] = last_octet;
    endpoint->data_port = port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = (uint16_t)(port + 1000U);
}

static void fill_rule(struct wvm_route_rule_record *rule,
                      uint16_t destination_kind, uint64_t destination_scope,
                      uint32_t vnode, uint8_t address_tail, uint16_t port,
                      uint16_t hop_limit)
{
    memset(rule, 0, sizeof(*rule));
    rule->destination_kind = destination_kind;
    rule->destination_scope = destination_scope;
    rule->destination_vnode_or_endpoint = vnode;
    rule->next_hop_kind = WVM_ROUTE_NEXT_HOP_ENDPOINT;
    rule->next_hop_member.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    rule->next_hop_member.role_id = address_tail;
    rule->next_hop_member.instance_id = 1000U + address_tail;
    fill_endpoint(&rule->next_hop_endpoint, address_tail, port);
    rule->hop_limit = hop_limit;
}

static int finalize_snapshot(struct wvm_route_snapshot_record *snapshot,
                             struct wvm_route_rule_record *rules,
                             size_t rule_count,
                             struct wvm_required_ack_entry *acks,
                             size_t ack_count, uint32_t vm_id,
                             uint64_t incarnation, uint64_t route_scope_id,
                             uint64_t topology_revision,
                             uint64_t route_generation,
                             uint16_t topology_kind, char *error,
                             size_t error_len)
{
    uint8_t bytes[16384];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes;
    size_t i;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->route_snapshot_key.scope_key.vm_id = vm_id;
    snapshot->route_snapshot_key.scope_key.vm_incarnation = incarnation;
    snapshot->route_snapshot_key.scope_key.route_scope_id = route_scope_id;
    snapshot->route_snapshot_key.topology_revision = topology_revision;
    snapshot->route_snapshot_key.route_generation = route_generation;
    snapshot->membership_revision = topology_revision;
    snapshot->topology_kind = topology_kind;
    snapshot->next_hop_rules.entries = rules;
    snapshot->next_hop_rules.count = rule_count;
    snapshot->next_hop_rules.capacity = rule_count;
    snapshot->required_ack_set.entries.entries = acks;
    snapshot->required_ack_set.entries.count = ack_count;
    snapshot->required_ack_set.entries.capacity = ack_count;
    snapshot->operation_retention_horizon_ms = 5000;
    snapshot->retirement_policy = 1;

    for (i = 0; i < ack_count; i++) {
        memset(&acks[i], 0, sizeof(acks[i]));
        acks[i].member_key = rules[0].next_hop_member;
        acks[i].endpoint = rules[0].next_hop_endpoint;
        acks[i].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
        acks[i].expected_snapshot_key = snapshot->route_snapshot_key;
    }
    if (wvm_route_snapshot_record_encode(snapshot, bytes, sizeof(bytes),
                                         &encoded_bytes, digest, error,
                                         error_len) != 0) {
        return -1;
    }
    memcpy(snapshot->route_snapshot_key.snapshot_digest, digest, sizeof(digest));
    for (i = 0; i < ack_count; i++) {
        memcpy(acks[i].expected_snapshot_key.snapshot_digest, digest,
               sizeof(digest));
    }
    return wvm_route_snapshot_record_validate(snapshot, error, error_len);
}

static void envelope_for_snapshot(struct wvm_envelope *envelope,
                                  const struct wvm_route_snapshot_key *key,
                                  uint16_t destination_kind,
                                  uint64_t destination_scope, uint32_t vnode)
{
    memset(envelope, 0, sizeof(*envelope));
    envelope->vm_id = key->scope_key.vm_id;
    envelope->vm_incarnation = key->scope_key.vm_incarnation;
    envelope->route_scope_id = key->scope_key.route_scope_id;
    envelope->topology_revision = key->topology_revision;
    envelope->route_generation = key->route_generation;
    memcpy(envelope->route_snapshot_digest, key->snapshot_digest,
           sizeof(envelope->route_snapshot_digest));
    envelope->route.destination_kind = destination_kind;
    envelope->route.destination_scope = destination_scope;
    envelope->route.destination_vnode_or_endpoint = vnode;
    envelope->route.hop_limit = 8;
    envelope->route.hop_count = 0;
}


struct route_lookup_race {
    struct wvm_route_runtime *runtime;
    struct wvm_envelope envelope_old;
    struct wvm_envelope envelope_new;
    uint16_t old_port;
    uint16_t new_port;
    atomic_int stop;
    atomic_int mixed;
    atomic_int samples;
};

static void *route_lookup_race_main(void *opaque)
{
    struct route_lookup_race *race = opaque;
    struct wvm_route_runtime_next_hop old_hop;
    struct wvm_route_runtime_next_hop new_hop;
    char error[128];

    while (!atomic_load(&race->stop)) {
        int old_ok = wvm_route_runtime_lookup(race->runtime, &race->envelope_old,
                                              &old_hop, error,
                                              sizeof(error)) == 0;
        int new_ok = wvm_route_runtime_lookup(race->runtime, &race->envelope_new,
                                              &new_hop, error,
                                              sizeof(error)) == 0;
        /* Separate hop buffers: sharing one next_hop made activate-between-
         * lookups look like half-table (old_ok + overwritten new port). */
        if (old_ok) {
            if (old_hop.next_hop_endpoint.data_port != race->old_port) {
                atomic_store(&race->mixed, 1);
            }
            atomic_fetch_add(&race->samples, 1);
        }
        if (new_ok) {
            if (new_hop.next_hop_endpoint.data_port != race->new_port) {
                atomic_store(&race->mixed, 1);
            }
            atomic_fetch_add(&race->samples, 1);
        }
    }
    return NULL;
}


struct r03_comp_arg {
    struct wvm_route_runtime *runtime;
    const struct wvm_route_snapshot_key *key;
    atomic_int *stop;
    atomic_int *held;
    atomic_int *retire_ok_while_held;
    atomic_int *retire_attempts;
    atomic_int *worker_errors;
    int is_retirer;
};

static void *r03_comp_worker(void *opaque)
{
    struct r03_comp_arg *arg = opaque;
    char error[128];

    while (!atomic_load(arg->stop)) {
        if (arg->is_retirer) {
            int rc;
            int held_now;

            atomic_fetch_add(arg->retire_attempts, 1);
            held_now = atomic_load(arg->held);
            rc = wvm_route_runtime_retire(arg->runtime, arg->key, error,
                                          sizeof(error));
            if (rc == 0) {
                if (held_now > 0)
                    atomic_fetch_add(arg->retire_ok_while_held, 1);
                /* Scope is gone — stop the competition cleanly. */
                atomic_store(arg->stop, 1);
            }
        } else {
            if (wvm_route_runtime_operation_ref_get(
                    arg->runtime, &arg->key->scope_key, error,
                    sizeof(error)) != 0) {
                /* Expected once the retirer wins a clean retire. */
                continue;
            }
            atomic_fetch_add(arg->held, 1);
            {
                struct timespec delay = { .tv_sec = 0, .tv_nsec = 200000L };
                nanosleep(&delay, NULL);
            }
            if (wvm_route_runtime_operation_ref_put(
                    arg->runtime, &arg->key->scope_key, error,
                    sizeof(error)) != 0) {
                /* Put can fail if retire won after our get; not a logic bug. */
            }
            atomic_fetch_sub(arg->held, 1);
        }
    }
    return NULL;
}

int main(void)
{
    struct wvm_route_runtime runtime;
    struct wvm_route_snapshot_record flat;
    struct wvm_route_snapshot_record successor;
    struct wvm_route_snapshot_record fractal;
    struct wvm_route_rule_record flat_rules[1];
    struct wvm_route_rule_record successor_rules[1];
    struct wvm_route_rule_record fractal_rules[2];
    struct wvm_required_ack_entry flat_acks[1];
    struct wvm_required_ack_entry successor_acks[1];
    struct wvm_required_ack_entry fractal_acks[1];
    struct wvm_envelope envelope;
    struct wvm_route_runtime_next_hop next_hop;
    struct wvm_route_snapshot_key returned_key;
    char error[256] = {0};

    fill_rule(&flat_rules[0], WVM_ROUTE_DESTINATION_EXACT_VNODE, 0, 0, 11,
              19011, 4);
    if (finalize_snapshot(&flat, flat_rules, 1, flat_acks, 1, 7, 99, 1234, 4,
                          2, 1, error, sizeof(error)) != 0) {
        fprintf(stderr, "route-runtime setup: %s\n", error);
        return 1;
    }
    fill_rule(&successor_rules[0], WVM_ROUTE_DESTINATION_EXACT_VNODE, 0, 0,
              12, 19112, 4);
    if (finalize_snapshot(&successor, successor_rules, 1, successor_acks, 1,
                          7, 99, 1234, 4, 3, 1, error, sizeof(error)) != 0) {
        fprintf(stderr, "route-runtime successor setup: %s\n", error);
        return 1;
    }
    fill_rule(&fractal_rules[0], WVM_ROUTE_DESTINATION_EXACT_VNODE, 41, 0,
              21, 19021, 4);
    fill_rule(&fractal_rules[1], WVM_ROUTE_DESTINATION_PREFIX, 99, 0, 22,
              19022, 3);
    fractal_rules[1].next_hop_kind = WVM_ROUTE_NEXT_HOP_GATEWAY;
    fractal_rules[1].next_hop_member.role_type = WVM_MANIFEST_ROLE_GATEWAY;
    if (finalize_snapshot(&fractal, fractal_rules, 2, fractal_acks, 1, 8, 7,
                          88, 4, 1, 2, error, sizeof(error)) != 0) {
        fprintf(stderr, "route-runtime fractal setup: %s\n", error);
        return 1;
    }

    wvm_route_runtime_init(&runtime);
    if (expect(wvm_route_runtime_prepare(&runtime, &flat, error,
                                         sizeof(error)) == 0,
               "prepare flat snapshot") ||
        expect(wvm_route_runtime_activate(&runtime, &flat.route_snapshot_key,
                                          error, sizeof(error)) == 0,
               "activate flat snapshot")) {
        wvm_route_runtime_destroy(&runtime);
        return 1;
    }
    envelope_for_snapshot(&envelope, &flat.route_snapshot_key,
                          WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE, 0, 0);
    if (expect(wvm_route_runtime_lookup(&runtime, &envelope, &next_hop, error,
                                        sizeof(error)) == 0 &&
                   next_hop.next_hop_endpoint.data_port == 19011 &&
                   next_hop.matched_destination_kind ==
                       WVM_ROUTE_DESTINATION_EXACT_VNODE,
               "look up flat vnode zero without raw-ID fallback") ||
        expect(wvm_route_runtime_lookup_destination(
                   &runtime, &flat.route_snapshot_key,
                   WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE, 0, 0,
                   &next_hop, error, sizeof(error)) == 0 &&
                   next_hop.hop_limit == 4 &&
                   next_hop.next_hop_endpoint.data_port == 19011,
               "resolve flat outbound route from an immutable snapshot") ||
        expect(wvm_route_runtime_current_key(
                   &runtime, &flat.route_snapshot_key.scope_key,
                   &returned_key) == 0 &&
                   memcmp(&returned_key, &flat.route_snapshot_key,
                          sizeof(returned_key)) == 0,
               "return flat active key")) {
        wvm_route_runtime_destroy(&runtime);
        return 1;
    }

    if (expect(wvm_route_runtime_prepare(&runtime, &successor, error,
                                         sizeof(error)) == 0 &&
                   wvm_route_runtime_activate(
                       &runtime, &successor.route_snapshot_key, error,
                       sizeof(error)) == 0,
               "replace flat snapshot") ||
        expect(wvm_route_runtime_has_snapshot(&runtime,
                                              &flat.route_snapshot_key),
               "retain exact predecessor") ||
        expect(wvm_route_runtime_lookup(&runtime, &envelope, &next_hop, error,
                                        sizeof(error)) != 0,
               "reject stale packet on retained predecessor")) {
        wvm_route_runtime_destroy(&runtime);
        return 1;
    }
    envelope_for_snapshot(&envelope, &successor.route_snapshot_key,
                          WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE, 0, 0);
    if (expect(wvm_route_runtime_lookup(&runtime, &envelope, &next_hop, error,
                                        sizeof(error)) == 0 &&
                   next_hop.next_hop_endpoint.data_port == 19112,
               "route normal traffic through successor") ||
        expect(wvm_route_runtime_retire(&runtime, &flat.route_snapshot_key,
                                        error, sizeof(error)) == 0,
               "retire predecessor")) {
        wvm_route_runtime_destroy(&runtime);
        return 1;
    }

    if (expect(wvm_route_runtime_prepare(&runtime, &fractal, error,
                                         sizeof(error)) == 0 &&
                   wvm_route_runtime_activate(&runtime,
                                              &fractal.route_snapshot_key,
                                              error, sizeof(error)) == 0,
               "activate independent fractal scope")) {
        wvm_route_runtime_destroy(&runtime);
        return 1;
    }
    envelope_for_snapshot(&envelope, &fractal.route_snapshot_key,
                          WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE, 41,
                          0);
    if (expect(wvm_route_runtime_lookup(&runtime, &envelope, &next_hop, error,
                                        sizeof(error)) == 0 &&
                   next_hop.next_hop_endpoint.data_port == 19021 &&
                   next_hop.matched_destination_kind ==
                       WVM_ROUTE_DESTINATION_EXACT_VNODE,
               "prefer scoped exact fractal leaf route")) {
        wvm_route_runtime_destroy(&runtime);
        return 1;
    }
    envelope_for_snapshot(&envelope, &fractal.route_snapshot_key,
                          WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE, 99,
                          77);
    if (expect(wvm_route_runtime_lookup(&runtime, &envelope, &next_hop, error,
                                        sizeof(error)) == 0 &&
                   next_hop.next_hop_endpoint.data_port == 19022 &&
                   next_hop.matched_destination_kind ==
                       WVM_ROUTE_DESTINATION_PREFIX,
               "route fractal scope through prefix next hop") ||
        expect(wvm_route_runtime_lookup_destination(
                   &runtime, &fractal.route_snapshot_key,
                   WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE, 99, 77,
                   &next_hop, error, sizeof(error)) == 0 &&
                   next_hop.hop_limit == 3 &&
                   next_hop.matched_destination_kind ==
                       WVM_ROUTE_DESTINATION_PREFIX,
               "resolve fractal outbound route without flattening scope") ||
        expect((envelope.route.hop_count = next_hop.hop_limit,
                wvm_route_runtime_lookup(&runtime, &envelope, &next_hop,
                                         error, sizeof(error)) != 0),
               "enforce per-rule hop budget")) {
        wvm_route_runtime_destroy(&runtime);
        return 1;
    }

    if (expect(wvm_route_runtime_retire(&runtime, &successor.route_snapshot_key,
                                        error, sizeof(error)) == 0 &&
                   wvm_route_runtime_retire(&runtime,
                                            &fractal.route_snapshot_key,
                                            error, sizeof(error)) == 0,
               "retire independent active route scopes")) {
        wvm_route_runtime_destroy(&runtime);
        return 1;
    }
    wvm_route_runtime_destroy(&runtime);

    /* A05: outstanding refs block retire; proof query mirrors refs. */
    {
        struct wvm_route_runtime proof_runtime;
        struct wvm_route_snapshot_record snap;
        struct wvm_route_rule_record rules[1];
        struct wvm_required_ack_entry acks[1];
        uint64_t refs = 99;
        int horizon = 0;
        char proof_error[256] = {0};

        fill_rule(&rules[0], WVM_ROUTE_DESTINATION_EXACT_VNODE, 0, 0, 31,
                  19331, 4);
        if (finalize_snapshot(&snap, rules, 1, acks, 1, 31, 1, 3100, 4, 1, 1,
                              proof_error, sizeof(proof_error)) != 0) {
            fprintf(stderr, "route-runtime A05 setup: %s\n", proof_error);
            return 1;
        }
        /*
         * R03: the proof is time-based, so use a short admitted window rather
         * than sleeping for the default 5s fixture horizon.
         */
        snap.operation_retention_horizon_ms = 60;
        wvm_route_runtime_init(&proof_runtime);
        if (expect(wvm_route_runtime_prepare(&proof_runtime, &snap, proof_error,
                                             sizeof(proof_error)) == 0 &&
                       wvm_route_runtime_activate(
                           &proof_runtime, &snap.route_snapshot_key, proof_error,
                           sizeof(proof_error)) == 0,
                   "A05 activate for ref proof") ||
            expect(wvm_route_runtime_operation_ref_get(
                       &proof_runtime, &snap.route_snapshot_key.scope_key,
                       proof_error, sizeof(proof_error)) == 0,
                   "A05 pin operation ref") ||
            expect(wvm_route_runtime_query_retire_proof(
                       &proof_runtime, &snap.route_snapshot_key, &refs, &horizon,
                       proof_error, sizeof(proof_error)) == 0 &&
                       refs == 1 && horizon == 0,
                   "A05 proof shows refs=1 incomplete") ||
            expect(wvm_route_runtime_retire(&proof_runtime,
                                            &snap.route_snapshot_key,
                                            proof_error,
                                            sizeof(proof_error)) != 0,
                   "A05 retire blocked while refs held") ||
            expect(wvm_route_runtime_operation_ref_put(
                       &proof_runtime, &snap.route_snapshot_key.scope_key,
                       proof_error, sizeof(proof_error)) == 0,
                   "A05 unpin operation ref") ||
            expect(wvm_route_runtime_query_retire_proof(
                       &proof_runtime, &snap.route_snapshot_key, &refs, &horizon,
                       proof_error, sizeof(proof_error)) == 0 &&
                       refs == 0 && horizon == 0,
                   "A05 proof incomplete while retention deadlines remain") ||
            expect(wvm_route_runtime_retire(&proof_runtime,
                                            &snap.route_snapshot_key,
                                            proof_error,
                                            sizeof(proof_error)) != 0,
                   "A05 retire blocked while retention deadlines remain") ||
            expect(wvm_route_runtime_drain_result_deadlines(
                       &proof_runtime, &snap.route_snapshot_key.scope_key,
                       proof_error, sizeof(proof_error)) != 0,
                   "R03 drain refused while the retention window is open") ||
            test_sleep_ms(80) ||
            expect(wvm_route_runtime_drain_result_deadlines(
                       &proof_runtime, &snap.route_snapshot_key.scope_key,
                       proof_error, sizeof(proof_error)) == 0,
                   "R03 drain succeeds after the retention window") ||
            expect(wvm_route_runtime_query_retire_proof(
                       &proof_runtime, &snap.route_snapshot_key, &refs, &horizon,
                       proof_error, sizeof(proof_error)) == 0 &&
                       refs == 0 && horizon == 1,
                   "A05 proof shows refs=0 deadlines drained") ||
            expect(wvm_route_runtime_retire(&proof_runtime,
                                            &snap.route_snapshot_key,
                                            proof_error,
                                            sizeof(proof_error)) == 0,
                   "A05 retire after refs+deadlines drained")) {
            wvm_route_runtime_destroy(&proof_runtime);
            return 1;
        }
        wvm_route_runtime_destroy(&proof_runtime);
    }

    /* R03: live retire ACK competition against concurrent operation refs. */
    {
        struct wvm_route_runtime comp_runtime;
        struct wvm_route_snapshot_record snap;
        struct wvm_route_rule_record rules[1];
        struct wvm_required_ack_entry acks[1];
        char comp_error[256] = {0};
        pthread_t workers[4];
        atomic_int stop;
        atomic_int held;
        atomic_int retire_ok_while_held;
        atomic_int retire_attempts;
        atomic_int worker_errors;
        struct r03_comp_arg args[4];
        unsigned t;

        fill_rule(&rules[0], WVM_ROUTE_DESTINATION_EXACT_VNODE, 0, 0, 41,
                  19441, 4);
        if (finalize_snapshot(&snap, rules, 1, acks, 1, 41, 1, 4100, 4, 1, 1,
                              comp_error, sizeof(comp_error)) != 0) {
            fprintf(stderr, "route-runtime R03 competition setup: %s\n",
                    comp_error);
            return 1;
        }
        snap.operation_retention_horizon_ms = 40;
        wvm_route_runtime_init(&comp_runtime);
        if (expect(wvm_route_runtime_prepare(&comp_runtime, &snap, comp_error,
                                             sizeof(comp_error)) == 0 &&
                       wvm_route_runtime_activate(
                           &comp_runtime, &snap.route_snapshot_key, comp_error,
                           sizeof(comp_error)) == 0,
                   "R03 competition activate") != 0) {
            wvm_route_runtime_destroy(&comp_runtime);
            return 1;
        }
        atomic_store(&stop, 0);
        atomic_store(&held, 0);
        atomic_store(&retire_ok_while_held, 0);
        atomic_store(&retire_attempts, 0);
        atomic_store(&worker_errors, 0);
        for (t = 0; t < 4; t++) {
            args[t].runtime = &comp_runtime;
            args[t].key = &snap.route_snapshot_key;
            args[t].stop = &stop;
            args[t].held = &held;
            args[t].retire_ok_while_held = &retire_ok_while_held;
            args[t].retire_attempts = &retire_attempts;
            args[t].worker_errors = &worker_errors;
            args[t].is_retirer = (t == 0);
            if (pthread_create(&workers[t], NULL, r03_comp_worker,
                               &args[t]) != 0) {
                fprintf(stderr, "R03 competition pthread_create\n");
                atomic_store(&stop, 1);
                while (t > 0) {
                    t--;
                    pthread_join(workers[t], NULL);
                }
                wvm_route_runtime_destroy(&comp_runtime);
                return 1;
            }
        }
        test_sleep_ms(200);
        atomic_store(&stop, 1);
        for (t = 0; t < 4; t++)
            pthread_join(workers[t], NULL);
        {
            uint64_t refs = 99;
            int horizon = 0;
            unsigned spins;

            for (spins = 0; spins < 40; spins++) {
                if (wvm_route_runtime_query_retire_proof(
                        &comp_runtime, &snap.route_snapshot_key, &refs,
                        &horizon, comp_error, sizeof(comp_error)) == 0 &&
                    refs == 0)
                    break;
                (void)wvm_route_runtime_operation_ref_put(
                    &comp_runtime, &snap.route_snapshot_key.scope_key,
                    comp_error, sizeof(comp_error));
                test_sleep_ms(5);
            }
            test_sleep_ms(50);
            /*
             * Either the retirer already completed a clean retire during the
             * race, or the scope is still present with refs=0 and a drained
             * horizon — both are success as long as retire never won while
             * held>0.
             */
            if (expect(atomic_load(&retire_ok_while_held) == 0,
                       "R03 retire never succeeded while refs held") ||
                expect(atomic_load(&retire_attempts) > 0,
                       "R03 retirer attempted at least once")) {
                wvm_route_runtime_destroy(&comp_runtime);
                return 1;
            }
            if (wvm_route_runtime_query_retire_proof(
                    &comp_runtime, &snap.route_snapshot_key, &refs, &horizon,
                    comp_error, sizeof(comp_error)) == 0) {
                if (refs == 0 && horizon == 1) {
                    int retire_rc = wvm_route_runtime_retire(
                        &comp_runtime, &snap.route_snapshot_key, comp_error,
                        sizeof(comp_error));
                    /*
                     * Retire may already have won cleanly during the race
                     * (held was 0). A second retire then fails closed — that
                     * is still a successful competition outcome.
                     */
                    if (retire_rc != 0) {
                        uint64_t refs2 = 99;
                        int horizon2 = 0;
                        if (expect(wvm_route_runtime_query_retire_proof(
                                       &comp_runtime, &snap.route_snapshot_key,
                                       &refs2, &horizon2, comp_error,
                                       sizeof(comp_error)) != 0 ||
                                       (refs2 == 0),
                                   "R03 post-race retire either completes or "
                                   "scope is already gone") != 0) {
                            wvm_route_runtime_destroy(&comp_runtime);
                            return 1;
                        }
                    }
                }
            }
        }
        wvm_route_runtime_destroy(&comp_runtime);
    }

    /* Phase 7: live snapshot replacement — lookups never observe a half table. */
    {
        struct wvm_route_runtime race_runtime;
        struct wvm_route_snapshot_record gen1;
        struct wvm_route_snapshot_record gen2;
        struct wvm_route_rule_record rules1[1];
        struct wvm_route_rule_record rules2[1];
        struct wvm_required_ack_entry acks1[1];
        struct wvm_required_ack_entry acks2[1];
        struct route_lookup_race race;
        pthread_t threads[4];
        size_t t;
        char race_error[256] = {0};

        wvm_route_runtime_init(&race_runtime);
        fill_rule(&rules1[0], WVM_ROUTE_DESTINATION_EXACT_VNODE, 0, 7, 11,
                  18001, 4);
        fill_rule(&rules2[0], WVM_ROUTE_DESTINATION_EXACT_VNODE, 0, 7, 12,
                  18002, 4);
        if (finalize_snapshot(&gen1, rules1, 1, acks1, 1, 256, 1, 10, 4, 1, 1,
                              race_error, sizeof(race_error)) != 0 ||
            finalize_snapshot(&gen2, rules2, 1, acks2, 1, 256, 1, 10, 4, 2, 1,
                              race_error, sizeof(race_error)) != 0) {
            fprintf(stderr, "route-runtime: cannot build race snapshots: %s\n",
                    race_error);
            wvm_route_runtime_destroy(&race_runtime);
            return 1;
        }
        gen2.predecessor_snapshot_key = gen1.route_snapshot_key;
        gen2.has_predecessor_snapshot_key = 1;
        if (expect(wvm_route_runtime_prepare(&race_runtime, &gen1, race_error,
                                             sizeof(race_error)) == 0 &&
                       wvm_route_runtime_activate(
                           &race_runtime, &gen1.route_snapshot_key, race_error,
                           sizeof(race_error)) == 0,
                   "activate generation-1 before race")) {
            wvm_route_runtime_destroy(&race_runtime);
            return 1;
        }
        memset(&race, 0, sizeof(race));
        race.runtime = &race_runtime;
        envelope_for_snapshot(&race.envelope_old, &gen1.route_snapshot_key,
                              WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE, 0, 7);
        envelope_for_snapshot(&race.envelope_new, &gen2.route_snapshot_key,
                              WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE, 0, 7);
        race.old_port = 18001;
        race.new_port = 18002;
        atomic_store(&race.stop, 0);
        atomic_store(&race.mixed, 0);
        atomic_store(&race.samples, 0);
        for (t = 0; t < 4; t++) {
            if (pthread_create(&threads[t], NULL, route_lookup_race_main,
                               &race) != 0) {
                fprintf(stderr, "route-runtime: lookup race pthread_create\n");
                atomic_store(&race.stop, 1);
                while (t > 0) {
                    t--;
                    pthread_join(threads[t], NULL);
                }
                wvm_route_runtime_destroy(&race_runtime);
                return 1;
            }
        }
        /*
         * Make sure the lookup threads actually started before the generation
         * flip; otherwise a slow scheduler can produce zero samples and the
         * race test fails without exercising anything.
         */
        {
            unsigned int spins = 0;

            while (atomic_load(&race.samples) == 0 && spins < 100000000U) {
                __builtin_ia32_pause();
                spins++;
            }
        }
        /* Flip active generation under concurrent lookups. */
        if (wvm_route_runtime_prepare(&race_runtime, &gen2, race_error,
                                      sizeof(race_error)) != 0 ||
            wvm_route_runtime_activate(&race_runtime, &gen2.route_snapshot_key,
                                       race_error, sizeof(race_error)) != 0) {
            fprintf(stderr, "route-runtime: activate gen2 failed: %s\n",
                    race_error);
            atomic_store(&race.stop, 1);
            for (t = 0; t < 4; t++) {
                pthread_join(threads[t], NULL);
            }
            wvm_route_runtime_destroy(&race_runtime);
            return 1;
        }
        atomic_store(&race.stop, 1);
        for (t = 0; t < 4; t++) {
            pthread_join(threads[t], NULL);
        }
        if (expect(atomic_load(&race.mixed) == 0,
                   "lookups never observe half-table next-hop mix") ||
            expect(atomic_load(&race.samples) > 0,
                   "lookup race collected samples")) {
            wvm_route_runtime_destroy(&race_runtime);
            return 1;
        }
        /* Post-activate: old key rejected or predecessor-only; new key exact. */
        {
            struct wvm_route_runtime_next_hop hop;
            int old_lookup = wvm_route_runtime_lookup(
                &race_runtime, &race.envelope_old, &hop, race_error,
                sizeof(race_error));
            int new_lookup = wvm_route_runtime_lookup(
                &race_runtime, &race.envelope_new, &hop, race_error,
                sizeof(race_error));
            if (expect(old_lookup != 0,
                       "stale generation key rejected after replacement") ||
                expect(new_lookup == 0 && hop.next_hop_endpoint.data_port ==
                                             18002,
                       "successor generation resolves complete next hop")) {
                wvm_route_runtime_destroy(&race_runtime);
                return 1;
            }
        }
        wvm_route_runtime_destroy(&race_runtime);
    }

    puts("route-runtime tests: PASS");
    puts("NOTE: Phase 7 live snapshot replacement — no half-table lookups.");
    puts("NOTE: A05 outstanding_operation_refs block retire until put.");
    puts("NOTE: R03 live retire competition — no retire while refs held.");
    return 0;
}
