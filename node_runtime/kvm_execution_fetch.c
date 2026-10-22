#include "kvm_execution_fetch.h"
#include <stdio.h>

#include <errno.h>
#include <string.h>

#include "kvm_page_cache.h"
#include "memory_service.h"

int wvm_kvm_fetch_execution_page(
    uint64_t gpa, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint8_t *hva, uint64_t *version_out, char *error, size_t error_len)
{
    uint8_t state = WVM_KVM_PAGE_ABSENT;
    uint64_t version = 0;
    uint8_t page[WVM_MEMORY_PAGE_BYTES];
    struct wvm_mem_ack ack;
    int result;

    if (!operation_id || !hva || !version_out) {
        if (error && error_len != 0) {
            snprintf(error, error_len,
                     "kvm execution fetch requires gpa/hva/operation_id");
        }
        return -EINVAL;
    }
    if ((gpa & (WVM_MEMORY_PAGE_BYTES - 1U)) != 0) {
        if (error && error_len != 0) {
            snprintf(error, error_len, "kvm execution fetch GPA not page-aligned");
        }
        return -EINVAL;
    }
    if (!wvm_kvm_page_cache_global_active()) {
        if (error && error_len != 0) {
            snprintf(error, error_len, "kvm page cache is not installed");
        }
        return -ENOTCONN;
    }

    result = wvm_kvm_page_cache_global_lookup(gpa, &state, &version, error,
                                              error_len);
    if (result != 0) {
        return result;
    }
    if (state == WVM_KVM_PAGE_CLEAN && version != 0) {
        *version_out = version;
        return 0;
    }
    if (state == WVM_KVM_PAGE_DIRTY || state == WVM_KVM_PAGE_SUBMITTING) {
        if (error && error_len != 0) {
            snprintf(error, error_len,
                     "kvm execution fetch blocked by dirty page state=%u",
                     (unsigned)state);
        }
        return -EBUSY;
    }

    memset(&ack, 0, sizeof(ack));
    memset(page, 0, sizeof(page));
    result = wvm_memory_service_global_request_fault(
        gpa, operation_id, 1, &ack, page, error, error_len);
    if (result != 0) {
        return result;
    }
    if (ack.status != WVM_MEM_ACK_SUCCESS || ack.version == 0 ||
        ack.data_bytes != WVM_MEMORY_PAGE_BYTES) {
        if (error && error_len != 0) {
            snprintf(error, error_len,
                     "kvm execution fetch ACK status=%u version=%llu bytes=%zu",
                     (unsigned)ack.status, (unsigned long long)ack.version,
                     ack.data_bytes);
        }
        return -EIO;
    }

    result = wvm_kvm_page_cache_global_install_full(gpa, ack.version, error,
                                                    error_len);
    if (result != 0) {
        return result;
    }
    memcpy(hva, page, WVM_MEMORY_PAGE_BYTES);
    *version_out = ack.version;
    return 0;
}
