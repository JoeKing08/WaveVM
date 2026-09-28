#ifndef WAVEVM_TLS_CONTROL_CONNECTOR_H
#define WAVEVM_TLS_CONTROL_CONNECTOR_H

#include <stddef.h>

#include "wavevm_control_client.h"

struct wvm_tls_control_connector {
    void *ssl_context;
    void *active_ssl;
    int active_fd;
    uint32_t timeout_ms;
};

/*
 * Bind an authenticated mTLS client connector. The peer certificate must be
 * issued by CA_FILE and its subject CN must be exactly
 * <role>:<role_id>:<instance_id> for the expected member.
 */
int wvm_tls_control_connector_bind(
    struct wvm_tls_control_connector *tls_connector, const char *ca_file,
    const char *certificate_file, const char *private_key_file,
    uint32_t timeout_ms, struct wvm_control_stream_connector *connector,
    char *error, size_t error_len);

void wvm_tls_control_connector_destroy(
    struct wvm_tls_control_connector *tls_connector);

int wvm_tls_control_membership_exchange(
    struct wvm_tls_control_connector *tls_connector,
    const struct wvm_member_key *expected_peer,
    uint32_t peer_physical_node_id, uint64_t peer_runtime_instance_id,
    const struct wvm_endpoint *endpoint, const struct wvm_envelope *request,
    struct wvm_membership_control_result *result, char *error,
    size_t error_len);

/* Extract and validate the authenticated peer identity on a TLS server stream. */
int wvm_tls_control_peer_identity(
    const struct wvm_control_io *io, struct wvm_member_key *member,
    char *error, size_t error_len);

#endif /* WAVEVM_TLS_CONTROL_CONNECTOR_H */
