#ifndef WAVEVM_UNIX_CONTROL_CONNECTOR_H
#define WAVEVM_UNIX_CONTROL_CONNECTOR_H

#include <stddef.h>
#include <sys/types.h>

#include "wavevm_control_client.h"

struct wvm_unix_peer_credentials {
    pid_t process_id;
    uid_t user_id;
    gid_t group_id;
};

typedef int (*wvm_unix_control_authorize_peer_fn)(
    void *opaque, const struct wvm_member_key *expected_peer,
    const struct wvm_unix_peer_credentials *credentials, char *error,
    size_t error_len);

struct wvm_unix_control_connector {
    wvm_unix_control_authorize_peer_fn authorize_peer;
    void *authorize_opaque;
};

/* Bind a local filesystem-socket connector to the generic stream client. */
int wvm_unix_control_connector_bind(
    struct wvm_unix_control_connector *unix_connector,
    wvm_unix_control_authorize_peer_fn authorize_peer, void *authorize_opaque,
    uint32_t timeout_ms, struct wvm_control_stream_connector *connector,
    char *error, size_t error_len);

#endif /* WAVEVM_UNIX_CONTROL_CONNECTOR_H */
