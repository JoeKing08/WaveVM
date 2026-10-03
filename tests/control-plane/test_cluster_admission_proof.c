#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wavevm_control.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "cluster-admission-proof test: %s\n", message);
        return -1;
    }
    return 0;
}

static void fill_digest(uint8_t *digest, uint8_t value)
{
    memset(digest, value, WVM_SHA256_DIGEST_BYTES);
}

static void fill_endpoint(struct wvm_endpoint *endpoint, uint16_t port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address[0] = 10;
    endpoint->data_address[1] = 0;
    endpoint->data_address[2] = 0;
    endpoint->data_address[3] = 1;
    endpoint->data_address_bytes = 4;
    endpoint->data_port = port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_address[0] = 10;
    endpoint->control_address[1] = 0;
    endpoint->control_address[2] = 0;
    endpoint->control_address[3] = 1;
    endpoint->control_address_bytes = 4;
    endpoint->has_control_address = 1;
    endpoint->control_port = (uint16_t)(port + 1);
}

int main(void)
{
    struct wvm_cluster_admission_ack_entry ack_entries[2];
    struct wvm_cluster_admission_ack_entry decoded_entries[2];
    struct wvm_cluster_admission_ack_entry original_second_ack;
    struct wvm_cluster_admission_proof proof;
    struct wvm_cluster_admission_proof decoded;
    uint8_t bytes[4096];
    size_t encoded_bytes;
    size_t full_bytes;
    char error[256] = {0};

    memset(&proof, 0, sizeof(proof));
    proof.operation_id[0] = 1;
    proof.member_key.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    proof.member_key.role_id = 7;
    proof.member_key.instance_id = 11;
    proof.membership_revision = 2;
    proof.topology_revision = 3;
    proof.admission_eligibility_revision = 4;
    fill_digest(proof.canonical_member_record_digest, 0x11);
    fill_digest(proof.capability_evidence_digest, 0x22);
    fill_digest(proof.topology_assignment_digest, 0x33);

    memset(ack_entries, 0, sizeof(ack_entries));
    ack_entries[0].member_key.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    ack_entries[0].member_key.role_id = 7;
    ack_entries[0].member_key.instance_id = 11;
    ack_entries[0].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    fill_endpoint(&ack_entries[0].endpoint, 9000);
    ack_entries[1].member_key.role_type = WVM_MANIFEST_ROLE_GATEWAY;
    ack_entries[1].member_key.role_id = 8;
    ack_entries[1].member_key.instance_id = 12;
    ack_entries[1].role_type = WVM_MANIFEST_ROLE_GATEWAY;
    fill_endpoint(&ack_entries[1].endpoint, 9010);
    original_second_ack = ack_entries[1];
    proof.required_ack_set.entries.entries = ack_entries;
    proof.required_ack_set.entries.count = 2;
    proof.required_ack_set.entries.capacity = 2;

    if (expect(wvm_cluster_admission_proof_validate(&proof, error,
                                                    sizeof(error)) == 0,
               "validate proof") ||
        expect(wvm_cluster_admission_proof_encode(&proof, bytes, sizeof(bytes),
                                                  &encoded_bytes, error,
                                                  sizeof(error)) == 0,
               "encode proof")) {
        return 1;
    }
    full_bytes = encoded_bytes;

    memset(&decoded, 0, sizeof(decoded));
    decoded.required_ack_set.entries.entries = decoded_entries;
    decoded.required_ack_set.entries.capacity = 2;
    if (expect(wvm_cluster_admission_proof_decode(
                   bytes, encoded_bytes, &decoded, error, sizeof(error)) == 0,
               "decode proof") ||
        expect(decoded.member_key.role_id == 7 &&
                   decoded.membership_revision == 2 &&
                   decoded.required_ack_set.entries.count == 2 &&
                   decoded.required_ack_set.entries.entries[1].member_key.role_id ==
                       8,
               "round trip proof with caller-owned ACK storage")) {
        return 1;
    }

    proof.required_ack_set.entries.entries[1].member_key =
        proof.required_ack_set.entries.entries[0].member_key;
    if (expect(wvm_cluster_admission_proof_validate(&proof, error,
                                                    sizeof(error)) != 0,
               "reject duplicate ACK identity")) {
        return 1;
    }
    proof.required_ack_set.entries.entries[1].member_key.role_id = 8;
    proof.operation_id[0] = 0;
    if (expect(wvm_cluster_admission_proof_validate(&proof, error,
                                                    sizeof(error)) != 0,
               "reject zero operation ID")) {
        return 1;
    }

    proof.operation_id[0] = 1;
    proof.required_ack_set.entries.count = 0;
    if (expect(wvm_cluster_admission_proof_validate(&proof, error,
                                                    sizeof(error)) != 0,
               "reject empty ACK set")) {
        return 1;
    }

    proof.required_ack_set.entries.count = 2;
    proof.required_ack_set.entries.entries[1] = original_second_ack;
    if (expect(wvm_cluster_admission_proof_encode(
                   &proof, bytes, full_bytes - 1, &encoded_bytes, error,
                   sizeof(error)) != 0,
               "reject proof buffer smaller than complete record")) {
        return 1;
    }

    if (expect(wvm_cluster_admission_proof_encode(
                   &proof, bytes, sizeof(bytes), &encoded_bytes, error,
                   sizeof(error)) == 0,
               "re-encode proof before truncation test")) {
        fprintf(stderr, "re-encode error: %s\n", error);
        return 1;
    }
    if (expect(wvm_cluster_admission_proof_decode(
                   bytes, encoded_bytes - 1, &decoded, error, sizeof(error)) != 0,
               "reject truncated ACK set outer record")) {
        return 1;
    }

    puts("cluster-admission-proof tests: PASS");
    return 0;
}
