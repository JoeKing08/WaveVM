#ifndef WAVEVM_CTL_CAPABILITY_PUBLICATION_H
#define WAVEVM_CTL_CAPABILITY_PUBLICATION_H

#include "../common_include/wavevm_control_transport.h"

struct wvm_ctl_capability_evidence {
    struct wvm_capability_report *reports;
    size_t report_count;
    struct wvm_capability_record *records;
    size_t record_count;
    size_t record_capacity;
    uint64_t inventory_revision;
    uint64_t profile_generation;
};

int wvm_ctl_publish_capabilities(
    const char *state_directory, struct wvm_membership_controller *controller,
    const struct wvm_envelope *request, const struct wvm_member_key *actor,
    struct wvm_control_result *result, char *error, size_t error_len);

/* Load durable evidence only when it still matches the captured membership. */
int wvm_ctl_load_capabilities(
    const char *state_directory, const struct wvm_capability_ref *reference,
    struct wvm_capability_report *report, char *error, size_t error_len);

/* Load one complete immutable capability view for a membership capture. */
int wvm_ctl_load_capability_evidence(
    const char *state_directory,
    const struct wvm_membership_controller_capture *capture,
    struct wvm_ctl_capability_evidence *evidence, char *error,
    size_t error_len);
void wvm_ctl_capability_evidence_destroy(
    struct wvm_ctl_capability_evidence *evidence);

/* Publish a probe provider's canonical report over an authenticated Unix peer. */
int wvm_ctl_capability_publish_command(int argc, char **argv);

#endif
