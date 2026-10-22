#ifndef WAVEVM_NODE_RUNTIME_KVM_EXECUTION_FETCH_H
#define WAVEVM_NODE_RUNTIME_KVM_EXECUTION_FETCH_H

#include <stddef.h>
#include <stdint.h>

#include "../common_include/wavevm_identity.h"
#include "../common_include/wavevm_memory.h"

/*
 * Production KVM input-side fetch used before KVM_RUN (R06).
 *
 * When the admitted page-cache entry is already CLEAN with a non-zero
 * version, return that version without touching HVA (HVA must already hold
 * the matching bytes from a prior fetch). Otherwise request one remote fault
 * through the installed memory_service, install the authoritative version
 * into the page cache, and copy the returned page bytes into HVA.
 *
 * This is the same sequence slave_hybrid uses for instruction-fetch pages.
 * A successful KVM/TCG instruction result that depends on those HVA bytes is
 * therefore a dependence on remote page content — not a decorative prefetch
 * into a discarded local buffer.
 */
int wvm_kvm_fetch_execution_page(
    uint64_t gpa, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint8_t *hva, uint64_t *version_out, char *error, size_t error_len);

#endif
