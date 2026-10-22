/*
 * R06: prove instruction execution depends on remote page content.
 *
 * Production path under test:
 *   wvm_memory_service_global_request_fault
 *     -> wvm_kvm_page_cache_global_install_full
 *     -> memcpy into guest HVA   (wvm_kvm_fetch_execution_page)
 *     -> real KVM_RUN of those bytes
 *
 * Forbidden: mock SUCCESS / decorative prefetch into a discarded buffer /
 * echoing VCPU_EXIT without executing remote-dependent opcodes.
 * Guest OS/SSH remains goal section 7. Mode A gate stays closed.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "kvm_execution_fetch.h"
#include "kvm_page_cache.h"
#include "memory_service.h"
#include "wavevm_membership.h"
#include "wavevm_runtime_dispatch.h"

#define TEST_GPA 0ULL
#define MARKER_A 0x11111111U
#define MARKER_B 0x22222222U

struct remote_state {
    pthread_mutex_t lock;
    pthread_cond_t available;
    int stop;
    int send_count;
    int completion_count;
    uint32_t marker;
    uint64_t version;
    uint64_t completed_gpa;
    uint64_t completed_version;
    uint8_t completed_page[WVM_MEMORY_PAGE_BYTES];
    struct wvm_envelope sent;
    uint8_t sent_payload[WVM_MEM_ACK_HEADER_BYTES + WVM_MEMORY_PAGE_BYTES];
    size_t sent_payload_bytes;
    struct wvm_memory_service *service;
};

static int expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "R06 FAIL: %s\n", msg);
        return -1;
    }
    return 0;
}

static void fill_endpoint(struct wvm_endpoint *endpoint, uint8_t tail,
                          uint16_t port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 192;
    endpoint->data_address[1] = 0;
    endpoint->data_address[2] = 2;
    endpoint->data_address[3] = tail;
    endpoint->data_port = port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = (uint16_t)(port + 1000U);
}

static void fill_rule(struct wvm_route_rule_record *rule, uint64_t scope,
                      uint32_t vnode, uint32_t physical_node_id,
                      uint64_t node_instance_id, uint8_t address_tail)
{
    memset(rule, 0, sizeof(*rule));
    rule->destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    rule->destination_scope = scope;
    rule->destination_vnode_or_endpoint = vnode;
    rule->next_hop_kind = WVM_ROUTE_NEXT_HOP_ENDPOINT;
    rule->next_hop_member.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    rule->next_hop_member.role_id = physical_node_id;
    rule->next_hop_member.instance_id = node_instance_id;
    fill_endpoint(&rule->next_hop_endpoint, address_tail,
                  (uint16_t)(19000U + address_tail));
    rule->hop_limit = 4;
}

static int finalize_snapshot(struct wvm_route_snapshot_record *snapshot,
                             struct wvm_route_rule_record rules[2],
                             struct wvm_required_ack_entry acks[1],
                             char *error, size_t error_len)
{
    uint8_t bytes[4096];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->route_snapshot_key.scope_key.vm_id = 256;
    snapshot->route_snapshot_key.scope_key.vm_incarnation = 7;
    snapshot->route_snapshot_key.scope_key.route_scope_id = 33;
    snapshot->route_snapshot_key.topology_revision = 11;
    snapshot->route_snapshot_key.route_generation = 4;
    snapshot->membership_revision = 3;
    snapshot->topology_kind = WVM_ROUTE_TOPOLOGY_FRACTAL;
    snapshot->next_hop_rules.entries = rules;
    snapshot->next_hop_rules.count = 2;
    snapshot->next_hop_rules.capacity = 2;
    snapshot->required_ack_set.entries.entries = acks;
    snapshot->required_ack_set.entries.count = 1;
    snapshot->required_ack_set.entries.capacity = 1;
    snapshot->operation_retention_horizon_ms = 5000;
    snapshot->retirement_policy = 1;
    memset(acks, 0, sizeof(*acks));
    acks[0].member_key = rules[0].next_hop_member;
    acks[0].endpoint = rules[0].next_hop_endpoint;
    acks[0].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    acks[0].expected_snapshot_key = snapshot->route_snapshot_key;
    if (wvm_route_snapshot_record_encode(snapshot, bytes, sizeof(bytes),
                                         &encoded_bytes, digest, error,
                                         error_len) != 0) {
        return -1;
    }
    memcpy(snapshot->route_snapshot_key.snapshot_digest, digest,
           sizeof(digest));
    memcpy(acks[0].expected_snapshot_key.snapshot_digest, digest,
           sizeof(digest));
    return wvm_route_snapshot_record_validate(snapshot, error, error_len);
}

static void encode_mov_eax_hlt(uint8_t page[WVM_MEMORY_PAGE_BYTES],
                               uint32_t marker)
{
    /* Real-mode default operand size is 16-bit. 0x66 selects 32-bit EAX. */
    memset(page, 0x90, WVM_MEMORY_PAGE_BYTES);
    page[0] = 0x66;
    page[1] = 0xB8;
    memcpy(&page[2], &marker, sizeof(marker));
    page[6] = 0xF4;
}

static int read_page(void *opaque, uint64_t gpa,
                     uint8_t data[WVM_MEMORY_PAGE_BYTES], uint64_t *version_out,
                     char *error, size_t error_len)
{
    (void)opaque;
    (void)gpa;
    (void)error;
    (void)error_len;
    memset(data, 0xa5, WVM_MEMORY_PAGE_BYTES);
    *version_out = 1;
    return 0;
}

static int complete_fault(void *opaque,
                          const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
                          uint64_t gpa, uint64_t version, uint16_t status,
                          uint32_t directory_physical_node_id,
                          uint64_t directory_node_instance_id,
                          const uint8_t *data, size_t data_bytes, char *error,
                          size_t error_len)
{
    struct remote_state *state = opaque;
    int result;

    result = wvm_memory_service_global_complete(
        operation_id, gpa, version, status, directory_physical_node_id,
        directory_node_instance_id, data, data_bytes, error, error_len);
    if (result != 0) {
        return result;
    }
    pthread_mutex_lock(&state->lock);
    state->completion_count++;
    state->completed_gpa = gpa;
    state->completed_version = version;
    if (data_bytes == WVM_MEMORY_PAGE_BYTES && data) {
        memcpy(state->completed_page, data, data_bytes);
    }
    pthread_mutex_unlock(&state->lock);
    return 0;
}

static int commit_page(void *opaque, uint64_t gpa, uint64_t base_version,
                       uint16_t offset, const uint8_t *data, size_t data_bytes,
                       uint64_t *result_version, char *error, size_t error_len)
{
    (void)opaque;
    (void)gpa;
    (void)offset;
    (void)data;
    (void)data_bytes;
    (void)error;
    (void)error_len;
    *result_version = base_version + 1;
    return 0;
}

static int complete_commit(void *opaque,
                           const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
                           uint64_t gpa, uint16_t status,
                           uint64_t result_version,
                           uint32_t directory_physical_node_id,
                           uint64_t directory_node_instance_id, char *error,
                           size_t error_len)
{
    (void)opaque;
    (void)operation_id;
    (void)gpa;
    (void)status;
    (void)result_version;
    (void)directory_physical_node_id;
    (void)directory_node_instance_id;
    (void)error;
    (void)error_len;
    return 0;
}

static int send_memory_envelope(void *opaque,
                                const struct wvm_envelope *envelope,
                                char *error, size_t error_len)
{
    struct remote_state *state = opaque;

    (void)error;
    (void)error_len;
    if (!state || !envelope || !envelope->payload) {
        return -EINVAL;
    }
    if (envelope->payload_bytes > sizeof(state->sent_payload)) {
        return -EOVERFLOW;
    }
    pthread_mutex_lock(&state->lock);
    state->sent = *envelope;
    memcpy(state->sent_payload, envelope->payload, envelope->payload_bytes);
    state->sent_payload_bytes = envelope->payload_bytes;
    state->sent.payload = state->sent_payload;
    state->send_count++;
    pthread_cond_broadcast(&state->available);
    pthread_mutex_unlock(&state->lock);
    return 0;
}

static void *ack_worker(void *opaque)
{
    struct remote_state *state = opaque;
    char error[256];

    for (;;) {
        struct wvm_envelope sent;
        struct wvm_mem_read read_req;
        struct wvm_mem_ack ack;
        struct wvm_envelope_route reply_route;
        struct wvm_envelope response;
        uint8_t remote_page[WVM_MEMORY_PAGE_BYTES];
        uint8_t ack_payload[WVM_MEM_ACK_HEADER_BYTES + WVM_MEMORY_PAGE_BYTES];
        size_t ack_payload_bytes = 0;
        uint32_t marker;
        uint64_t version;
        int stop = 0;
        int have_send = 0;

        pthread_mutex_lock(&state->lock);
        while (!state->stop && state->send_count == 0) {
            pthread_cond_wait(&state->available, &state->lock);
        }
        stop = state->stop;
        if (!stop && state->send_count > 0) {
            sent = state->sent;
            marker = state->marker;
            version = state->version;
            have_send = 1;
            state->send_count = 0;
        }
        pthread_mutex_unlock(&state->lock);
        if (stop) {
            break;
        }
        if (!have_send || sent.message_type != WVM_ENVELOPE_MSG_MEM_READ ||
            !state->service) {
            continue;
        }
        memset(&read_req, 0, sizeof(read_req));
        if (wvm_mem_read_decode(sent.payload, sent.payload_bytes, &read_req,
                                error, sizeof(error)) != 0) {
            fprintf(stderr, "R06 ack_worker decode: %s\n", error);
            continue;
        }
        encode_mov_eax_hlt(remote_page, marker);
        memset(&ack, 0, sizeof(ack));
        ack.gpa = read_req.gpa;
        ack.version = version;
        ack.status = WVM_MEM_ACK_SUCCESS;
        ack.directory_physical_node_id = 99;
        ack.directory_node_instance_id = 202;
        ack.data = remote_page;
        ack.data_bytes = sizeof(remote_page);
        memset(&reply_route, 0, sizeof(reply_route));
        reply_route.destination_kind =
            WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
        reply_route.destination_scope = 41;
        reply_route.destination_vnode_or_endpoint = 0;
        reply_route.hop_limit = 4;
        memset(error, 0, sizeof(error));
        if (wvm_mem_ack_envelope_build(
                &sent, &reply_route, 2, &ack, ack_payload, sizeof(ack_payload),
                &ack_payload_bytes, &response, error, sizeof(error)) != 0 ||
            wvm_memory_service_dispatch(state->service, &response, error,
                                        sizeof(error)) != 0) {
            fprintf(stderr, "R06 ack_worker: %s\n", error);
        }
    }
    return NULL;
}

static void fill_projection(struct wvm_runtime_dispatch_projection *projection,
                            struct wvm_runtime_memory_dispatch *memory,
                            const struct wvm_route_snapshot_key *route_key)
{
    memset(projection, 0, sizeof(*projection));
    memset(projection->candidate_manifest_digest, 0x51,
           sizeof(projection->candidate_manifest_digest));
    projection->vm_id = 256;
    projection->vm_incarnation = 7;
    projection->manifest_generation = 3;
    projection->physical_node_id = 17;
    projection->expected_node_instance_id = 101;
    memset(projection->activation_fence, 0x52,
           sizeof(projection->activation_fence));
    projection->required_route_snapshot_key = *route_key;
    projection->route_topology_kind = WVM_ROUTE_TOPOLOGY_FRACTAL;
    projection->local_primary.destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    projection->local_primary.destination_scope = 41;
    projection->local_primary.destination_vnode = 0;
    fill_endpoint(&projection->local_sidecar_endpoint, 17, 19017);
    projection->memory_dispatch.entries = memory;
    projection->memory_dispatch.count = 1;
    projection->memory_dispatch.capacity = 1;
    memset(memory, 0, sizeof(*memory));
    memory->gpa_start = TEST_GPA;
    memory->bytes = WVM_MEMORY_PAGE_BYTES;
    memory->directory.destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    memory->directory.destination_scope = 99;
    memory->directory.destination_vnode = 1;
    memory->executor = memory->directory;
    memory->directory_physical_node_id = 99;
    memory->directory_node_instance_id = 202;
    memory->consistency_policy = 1;
}

static int run_kvm_marker(uint8_t *hva, uint32_t expected_marker, char *error,
                          size_t error_len)
{
    int kvm_fd = -1;
    int vm_fd = -1;
    int vcpu_fd = -1;
    struct kvm_run *run = MAP_FAILED;
    size_t mmap_size = 0;
    struct kvm_userspace_memory_region region;
    struct kvm_sregs sregs;
    struct kvm_regs regs;
    int result = -1;
    int rc;

    kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm_fd < 0) {
        snprintf(error, error_len, "open /dev/kvm: %s", strerror(errno));
        return -errno;
    }
    if (ioctl(kvm_fd, KVM_GET_API_VERSION, 0) != KVM_API_VERSION) {
        snprintf(error, error_len, "unexpected KVM API version");
        result = -EPROTO;
        goto out;
    }
    vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
    if (vm_fd < 0) {
        snprintf(error, error_len, "KVM_CREATE_VM: %s", strerror(errno));
        result = -errno;
        goto out;
    }
    memset(&region, 0, sizeof(region));
    region.slot = 0;
    region.guest_phys_addr = TEST_GPA;
    region.memory_size = WVM_MEMORY_PAGE_BYTES;
    region.userspace_addr = (uint64_t)(uintptr_t)hva;
    if (ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
        snprintf(error, error_len, "KVM_SET_USER_MEMORY_REGION: %s",
                 strerror(errno));
        result = -errno;
        goto out;
    }
    vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0);
    if (vcpu_fd < 0) {
        snprintf(error, error_len, "KVM_CREATE_VCPU: %s", strerror(errno));
        result = -errno;
        goto out;
    }
    mmap_size = (size_t)ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (mmap_size == 0 || mmap_size == (size_t)-1) {
        snprintf(error, error_len, "KVM_GET_VCPU_MMAP_SIZE failed");
        result = -EIO;
        goto out;
    }
    run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu_fd, 0);
    if (run == MAP_FAILED) {
        snprintf(error, error_len, "mmap kvm_run: %s", strerror(errno));
        result = -errno;
        goto out;
    }
    if (ioctl(vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
        snprintf(error, error_len, "KVM_GET_SREGS: %s", strerror(errno));
        result = -errno;
        goto out;
    }
    sregs.cs.selector = 0;
    sregs.cs.base = 0;
    sregs.cs.limit = 0xffff;
    sregs.ds.selector = 0;
    sregs.ds.base = 0;
    sregs.ds.limit = 0xffff;
    sregs.es.selector = 0;
    sregs.es.base = 0;
    sregs.es.limit = 0xffff;
    sregs.ss.selector = 0;
    sregs.ss.base = 0;
    sregs.ss.limit = 0xffff;
    sregs.cr0 &= ~(1ULL << 31);
    sregs.cr0 &= ~1ULL;
    if (ioctl(vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
        snprintf(error, error_len, "KVM_SET_SREGS: %s", strerror(errno));
        result = -errno;
        goto out;
    }
    memset(&regs, 0, sizeof(regs));
    regs.rflags = 0x2;
    regs.rip = 0;
    regs.rax = 0;
    if (ioctl(vcpu_fd, KVM_SET_REGS, &regs) < 0) {
        snprintf(error, error_len, "KVM_SET_REGS: %s", strerror(errno));
        result = -errno;
        goto out;
    }

    for (int attempt = 0; attempt < 8; attempt++) {
        rc = ioctl(vcpu_fd, KVM_RUN, 0);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            snprintf(error, error_len, "KVM_RUN: %s", strerror(errno));
            result = -errno;
            goto out;
        }
        if (run->exit_reason == KVM_EXIT_HLT) {
            break;
        }
        if (run->exit_reason == KVM_EXIT_INTR) {
            continue;
        }
        snprintf(error, error_len, "unexpected KVM exit_reason=%u",
                 (unsigned)run->exit_reason);
        result = -EIO;
        goto out;
    }
    if (run->exit_reason != KVM_EXIT_HLT) {
        snprintf(error, error_len, "did not reach HLT (exit=%u)",
                 (unsigned)run->exit_reason);
        result = -EIO;
        goto out;
    }
    if (ioctl(vcpu_fd, KVM_GET_REGS, &regs) < 0) {
        snprintf(error, error_len, "KVM_GET_REGS after HLT: %s",
                 strerror(errno));
        result = -errno;
        goto out;
    }
    if ((uint32_t)regs.rax != expected_marker) {
        snprintf(error, error_len,
                 "RAX=0x%x after HLT, expected marker 0x%x",
                 (unsigned)regs.rax, (unsigned)expected_marker);
        result = -EIO;
        goto out;
    }
    result = 0;

out:
    if (run != MAP_FAILED) {
        munmap(run, mmap_size);
    }
    if (vcpu_fd >= 0) {
        close(vcpu_fd);
    }
    if (vm_fd >= 0) {
        close(vm_fd);
    }
    if (kvm_fd >= 0) {
        close(kvm_fd);
    }
    return result;
}

static int fetch_and_execute(struct remote_state *remote, uint8_t *hva,
                             uint32_t marker, uint64_t version, uint8_t op_tag,
                             char *error, size_t error_len)
{
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    uint64_t fetched_version = 0;
    int completions_before;
    int result;
    uint32_t imm;

    pthread_mutex_lock(&remote->lock);
    remote->marker = marker;
    remote->version = version;
    completions_before = remote->completion_count;
    pthread_mutex_unlock(&remote->lock);

    memset(hva, 0xCC, WVM_MEMORY_PAGE_BYTES);
    memset(operation_id, 0, sizeof(operation_id));
    operation_id[0] = op_tag;
    operation_id[15] = 0x06;

    result = wvm_kvm_fetch_execution_page(TEST_GPA, operation_id, hva,
                                          &fetched_version, error, error_len);
    if (result != 0) {
        return result;
    }
    if (fetched_version != version) {
        snprintf(error, error_len, "fetched version %llu != expected %llu",
                 (unsigned long long)fetched_version,
                 (unsigned long long)version);
        return -EIO;
    }
    if (hva[0] != 0x66 || hva[1] != 0xB8 || hva[6] != 0xF4) {
        snprintf(error, error_len,
                 "HVA missing 66 B8 .. F4 after remote fetch (got %02x %02x .. %02x)",
                 hva[0], hva[1], hva[6]);
        return -EIO;
    }
    memcpy(&imm, &hva[2], sizeof(imm));
    if (imm != marker) {
        snprintf(error, error_len, "HVA imm32=0x%x != remote marker 0x%x",
                 (unsigned)imm, (unsigned)marker);
        return -EIO;
    }

    pthread_mutex_lock(&remote->lock);
    if (remote->completion_count <= completions_before ||
        remote->completed_gpa != TEST_GPA ||
        remote->completed_version != version) {
        pthread_mutex_unlock(&remote->lock);
        snprintf(error, error_len, "remote ACK did not complete for this fetch");
        return -EIO;
    }
    memcpy(&imm, &remote->completed_page[2], sizeof(imm));
    if (remote->completed_page[0] != 0x66 ||
        remote->completed_page[1] != 0xB8 || imm != marker) {
        pthread_mutex_unlock(&remote->lock);
        snprintf(error, error_len, "completed remote page bytes mismatch marker");
        return -EIO;
    }
    pthread_mutex_unlock(&remote->lock);

    result = run_kvm_marker(hva, marker, error, error_len);
    return result;
}

int main(void)
{
    struct wvm_route_rule_record rules[2];
    struct wvm_required_ack_entry acks[1];
    struct wvm_route_snapshot_record snapshot;
    struct wvm_route_runtime routes;
    struct wvm_runtime_dispatch_projection projection;
    struct wvm_runtime_memory_dispatch memory;
    struct wvm_memory_service service;
    struct wvm_memory_service_config mem_config;
    struct wvm_kvm_page_cache_config cache_config;
    struct remote_state remote;
    pthread_t ack_thread;
    uint8_t *hva = NULL;
    char error[512] = {0};
    int exit_code = 1;
    int ack_started = 0;
    int cache_installed = 0;
    int mem_installed = 0;

    memset(&remote, 0, sizeof(remote));
    memset(&routes, 0, sizeof(routes));
    memset(&service, 0, sizeof(service));
    if (pthread_mutex_init(&remote.lock, NULL) != 0 ||
        pthread_cond_init(&remote.available, NULL) != 0) {
        fprintf(stderr, "R06 FAIL: pthread init\n");
        return 1;
    }

    fill_rule(&rules[0], 41, 0, 17, 101, 17);
    fill_rule(&rules[1], 99, 1, 99, 202, 99);
    if (expect(finalize_snapshot(&snapshot, rules, acks, error, sizeof(error)) ==
                   0,
               "finalize route snapshot") != 0) {
        fprintf(stderr, "err=%s\n", error);
        goto out;
    }
    wvm_route_runtime_init(&routes);
    if (expect(wvm_route_runtime_prepare(&routes, &snapshot, error,
                                         sizeof(error)) == 0 &&
                   wvm_route_runtime_activate(
                       &routes, &snapshot.route_snapshot_key, error,
                       sizeof(error)) == 0,
               "prepare+activate route runtime") != 0) {
        fprintf(stderr, "err=%s\n", error);
        goto out;
    }
    fill_projection(&projection, &memory, &snapshot.route_snapshot_key);
    if (expect(wvm_runtime_dispatch_projection_validate(
                   &projection, error, sizeof(error)) == 0,
               "validate dispatch projection") != 0) {
        fprintf(stderr, "err=%s\n", error);
        goto out;
    }

    memset(&mem_config, 0, sizeof(mem_config));
    mem_config.dispatch = &projection;
    mem_config.route_runtime = &routes;
    mem_config.local_physical_node_id = 17;
    mem_config.local_node_instance_id = 101;
    mem_config.local_runtime_instance_id = 1001;
    mem_config.completion_timeout_ms = 5000;
    mem_config.read_page = read_page;
    mem_config.commit_page = commit_page;
    mem_config.complete_commit = complete_commit;
    mem_config.complete_fault = complete_fault;
    mem_config.send_envelope = send_memory_envelope;
    mem_config.opaque = &remote;
    if (expect(wvm_memory_service_init(&service, &mem_config, error,
                                       sizeof(error)) == 0,
               "init memory_service") != 0 ||
        expect(wvm_memory_service_global_install(&service, error,
                                                 sizeof(error)) == 0,
               "install global memory_service") != 0) {
        fprintf(stderr, "err=%s\n", error);
        goto out;
    }
    mem_installed = 1;
    remote.service = &service;

    memset(&cache_config, 0, sizeof(cache_config));
    cache_config.vm_id = 256;
    cache_config.vm_incarnation = 7;
    cache_config.max_page_records = 8;
    cache_config.completion_timeout_ms = 5000;
    if (expect(wvm_kvm_page_cache_global_install(&cache_config, error,
                                                 sizeof(error)) == 0,
               "install kvm page cache") != 0) {
        fprintf(stderr, "err=%s\n", error);
        goto out;
    }
    cache_installed = 1;

    if (pthread_create(&ack_thread, NULL, ack_worker, &remote) != 0) {
        fprintf(stderr, "R06 FAIL: ack thread\n");
        goto out;
    }
    ack_started = 1;

    hva = mmap(NULL, WVM_MEMORY_PAGE_BYTES, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (hva == MAP_FAILED) {
        fprintf(stderr, "R06 FAIL: mmap HVA\n");
        hva = NULL;
        goto out;
    }

    if (expect(fetch_and_execute(&remote, hva, MARKER_A, 9, 0xA1, error,
                                 sizeof(error)) == 0,
               "marker A: remote fetch + KVM_RUN => RAX") != 0) {
        fprintf(stderr, "err=%s\n", error);
        goto out;
    }

    if (expect(wvm_kvm_page_cache_global_invalidate(TEST_GPA, error,
                                                    sizeof(error)) == 0,
               "invalidate page for marker B") != 0) {
        fprintf(stderr, "err=%s\n", error);
        goto out;
    }

    if (expect(fetch_and_execute(&remote, hva, MARKER_B, 10, 0xB2, error,
                                 sizeof(error)) == 0,
               "marker B: remote fetch + KVM_RUN => RAX") != 0) {
        fprintf(stderr, "err=%s\n", error);
        goto out;
    }

    puts("R06: remote page bytes -> wvm_kvm_fetch_execution_page -> KVM_RUN");
    puts("     marker A then B: instruction result depends on remote content PASS");
    exit_code = 0;

out:
    if (hva && hva != MAP_FAILED) {
        munmap(hva, WVM_MEMORY_PAGE_BYTES);
    }
    if (ack_started) {
        pthread_mutex_lock(&remote.lock);
        remote.stop = 1;
        pthread_cond_broadcast(&remote.available);
        pthread_mutex_unlock(&remote.lock);
        pthread_join(ack_thread, NULL);
    }
    if (cache_installed) {
        wvm_kvm_page_cache_global_uninstall();
    }
    if (mem_installed) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
    }
    wvm_route_runtime_destroy(&routes);
    pthread_cond_destroy(&remote.available);
    pthread_mutex_destroy(&remote.lock);
    return exit_code;
}
