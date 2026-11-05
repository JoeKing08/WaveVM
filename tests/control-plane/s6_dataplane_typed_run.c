/*
 * §6 live CREATE short-exec via PRODUCTION typed dispatch:
 *   WVM1 VCPU_RUN handoff -> node ingress (flat) or gateway_forward (fractal)
 *   -> executor_bridge -> wvm_executor_runtime_execute_handoff -> Hybrid
 *
 * NOT legacy MSG_VCPU_RUN to Hybrid UDP (that remains component smoke).
 * EXIT reply goes to admitted local_primary/sidecar; this probe proves
 * execution by a guest store into SHM (marker) plus typed-path labels.
 *
 * Usage:
 *   s6_dataplane_typed_run SHM MANIFEST_PATH INGRESS_PORT BACKEND MARKER_HEX
 *                          [GPA=0x2000] [via_gateway=0|1]
 * BACKEND: kvm | tcg
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "wavevm_envelope.h"
#include "wavevm_lifecycle.h"
#include "wavevm_protocol.h"
#include "wavevm_route_delivery.h"
#include "wavevm_runtime_dispatch.h"
#include "wavevm_runtime_gate.h"
#include "wavevm_vcpu_handoff.h"
#include "wavevm_x86_context.h"
#include "wavevm_kvm_state.h"

/* QEMU DESC_* for real-mode TCG segments. */
#define DESC_P_MASK (1u << 15)
#define DESC_S_MASK (1u << 12)
#define DESC_CS_MASK (1u << 11)
#define DESC_R_MASK (1u << 9)
#define DESC_W_MASK (1u << 9)
#define DESC_A_MASK (1u << 8)
#define SEG_FLAGS_CODE16 \
    (DESC_P_MASK | DESC_S_MASK | DESC_CS_MASK | DESC_R_MASK | DESC_A_MASK)
#define SEG_FLAGS_DATA16 (DESC_P_MASK | DESC_S_MASK | DESC_W_MASK | DESC_A_MASK)

struct udp_emit_ctx {
    int fd;
    struct sockaddr_in dest;
};

static int emit_udp_frame(void *opaque, const uint8_t *frame, size_t frame_bytes,
                          char *error, size_t error_len)
{
    struct udp_emit_ctx *ctx = opaque;
    if (sendto(ctx->fd, frame, frame_bytes, MSG_NOSIGNAL,
               (struct sockaddr *)&ctx->dest, sizeof(ctx->dest)) !=
        (ssize_t)frame_bytes) {
        snprintf(error, error_len, "UDP emit failed errno=%d", errno);
        return -1;
    }
    return 0;
}

static void sleep_ms(long ms)
{
    struct timespec d = {.tv_sec = ms / 1000,
                         .tv_nsec = (ms % 1000) * 1000000L};
    while (nanosleep(&d, &d) != 0 && errno == EINTR) {
    }
}

/* Guest: mov eax,imm32; mov [abs32],eax; hlt — proves typed exec via SHM. */
static void plant_guest_store(uint8_t *page, uint32_t marker, uint32_t store_gpa,
                              int tcg_realmode)
{
    memset(page, 0x90, 64);
    if (tcg_realmode) {
        /*
         * 16-bit CS: 0x66 = operand-size (EAX), 0x67 = address-size (abs32).
         * Without 0x67, A3 would take only imm16 and mis-parse the stream.
         */
        page[0] = 0x66;
        page[1] = 0xB8;
        memcpy(&page[2], &marker, 4);
        page[6] = 0x66;
        page[7] = 0x67;
        page[8] = 0xA3;
        memcpy(&page[9], &store_gpa, 4);
        page[13] = 0xF4;
    } else {
        /* Flat 32-bit protected mode (KVM). */
        page[0] = 0xB8;
        memcpy(&page[1], &marker, 4);
        page[5] = 0xA3;
        memcpy(&page[6], &store_gpa, 4);
        page[10] = 0xF4;
    }
}

/*
 * Page-cache RAM snapshot fetches authoritative directory bytes before
 * KVM_RUN. Planting only into SHM is not a versioned commit (memory-
 * consistency: directory owns page bytes). Publish the planted page via
 * production MSG_MEM_WRITE to the node data ingress so the subsequent
 * snapshot installs real instruction bytes instead of implicit zeros.
 */
static int publish_planted_page_to_directory(
    const uint8_t *ram, unsigned long gpa, unsigned directory_port,
    uint32_t vm_id, uint32_t local_vnode)
{
    uint8_t tx[sizeof(struct wvm_header) + sizeof(uint64_t) + WVM_PAGE_BYTES];
    struct wvm_header *hdr = (struct wvm_header *)tx;
    uint64_t *gpa_be;
    struct sockaddr_in dst;
    int sock = -1;
    ssize_t sent;
    uint64_t page_gpa = (uint64_t)gpa & ~(uint64_t)(WVM_PAGE_BYTES - 1U);

    /* Directory/MSG_MEM_WRITE lands on node_runtime_data_port — never the
     * gateway typed-ingress used for vCPU_RUN when via_gateway=1. */
    if (!ram || directory_port == 0 || directory_port > 65535) {
        fprintf(stderr, "publish_planted_page: bad args\n");
        return -1;
    }
    memset(tx, 0, sizeof(tx));
    hdr->magic = htonl(WVM_MAGIC);
    hdr->msg_type = htons(MSG_MEM_WRITE);
    hdr->payload_len = htons((uint16_t)(sizeof(uint64_t) + WVM_PAGE_BYTES));
    if (wvm_header_pack_src(hdr, vm_id, local_vnode) != 0) {
        fprintf(stderr, "publish_planted_page: pack_src failed\n");
        return -1;
    }
    hdr->target_id = htonl(wvm_wire_target(vm_id, local_vnode));
    hdr->req_id = WVM_HTONLL(0x534D505542ULL ^ (uint64_t)getpid()); /* 'SMPUB' */
    hdr->qos_level = 0;
    hdr->flags = (uint8_t)(hdr->flags | WVM_FLAG_NEED_ACK);
    gpa_be = (uint64_t *)(tx + sizeof(*hdr));
    *gpa_be = WVM_HTONLL(page_gpa);
    memcpy(tx + sizeof(*hdr) + sizeof(uint64_t), ram + page_gpa, WVM_PAGE_BYTES);
    hdr->crc32 = 0;
    hdr->crc32 = htonl(calculate_crc32(tx, sizeof(tx)));

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("publish_planted_page socket");
        return -1;
    }
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons((uint16_t)directory_port);
    sent = sendto(sock, tx, sizeof(tx), MSG_NOSIGNAL, (struct sockaddr *)&dst,
                  sizeof(dst));
    close(sock);
    if (sent != (ssize_t)sizeof(tx)) {
        fprintf(stderr, "publish_planted_page: sendto failed sent=%zd errno=%d\n",
                sent, errno);
        return -1;
    }
    printf("published_planted_page gpa=0x%llx bytes=%u directory_port=%u "
           "vm=%u vnode=%u\n",
           (unsigned long long)page_gpa, (unsigned)WVM_PAGE_BYTES, directory_port,
           vm_id, local_vnode);
    /* Directory commit is sync before ACK; allow local PAGE_PUSH to settle. */
    sleep_ms(50);
    return 0;
}

/*
 * Production KVM handoff requires a schema-complete extended state (FPU/
 * LAPIC/events/MP/debug/system MSRs + CPUID). A zeroed architectural-only
 * stub encodes on the wire but fails wvm_kvm_extended_state_validate on the
 * executor — the Oct28 2864-byte probe predated that gate.
 */
static int fill_kvm_prot32(wvm_kvm_context_t *ctx, uint64_t gpa)
{
    struct kvm_sregs sregs;
    struct kvm_enable_cap cap = { .cap = KVM_CAP_SPLIT_IRQCHIP };
    int kvm_fd = -1, vm_fd = -1, cpu_fd = -1;
    int result = -1;

    memset(ctx, 0, sizeof(*ctx));
    cap.args[0] = 24;
    kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm_fd < 0 || (vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0)) < 0 ||
        ioctl(vm_fd, KVM_ENABLE_CAP, &cap) < 0 ||
        (cpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0)) < 0) {
        fprintf(stderr,
                "fill_kvm_prot32: cannot open ephemeral KVM vCPU errno=%d\n",
                errno);
        goto out;
    }
    /* Minimal host-legal CPUID; capture fills the rest of extended state. */
    ctx->cpuid_count = 2;
    ctx->cpuid[0].function = 0;
    ctx->cpuid[0].eax = 1;
    ctx->cpuid[0].ebx = 0x756e6547;
    ctx->cpuid[0].edx = 0x49656e69;
    ctx->cpuid[0].ecx = 0x6c65746e;
    ctx->cpuid[1].function = 1;
    ctx->cpuid[1].eax = 0x663;
    ctx->cpuid[1].edx = (1U << 0) | (1U << 4) | (1U << 5) | (1U << 8) |
                        (1U << 9) | (1U << 11) | (1U << 15) | (1U << 16) |
                        (1U << 23) | (1U << 24) | (1U << 25) | (1U << 26);
    if (wvm_kvm_cpuid_check_host(kvm_fd, ctx) != 0 ||
        wvm_kvm_cpuid_import(cpu_fd, ctx) != 0 ||
        wvm_kvm_extended_state_capture(cpu_fd, ctx) != 0) {
        fprintf(stderr,
                "fill_kvm_prot32: cpuid/extended capture failed errno=%d\n",
                errno);
        goto out;
    }
    ctx->mp_state = KVM_MP_STATE_RUNNABLE;
    ctx->rip = gpa;
    ctx->rsp = gpa + 0x1000;
    ctx->rflags = 0x2;
    memset(&sregs, 0, sizeof(sregs));
    sregs.cs.selector = 0x8;
    sregs.cs.base = 0;
    sregs.cs.limit = 0xffffffffu;
    sregs.cs.type = 0xb;
    sregs.cs.present = 1;
    sregs.cs.dpl = 0;
    sregs.cs.db = 1;
    sregs.cs.s = 1;
    sregs.cs.g = 1;
    sregs.ds = sregs.cs;
    sregs.ds.selector = 0x10;
    sregs.ds.type = 0x3;
    sregs.es = sregs.ds;
    sregs.ss = sregs.ds;
    sregs.fs = sregs.ds;
    sregs.gs = sregs.ds;
    sregs.tr.selector = 0x18;
    sregs.tr.base = 0;
    sregs.tr.limit = 0xffff;
    sregs.tr.type = 0xb;
    sregs.tr.present = 1;
    sregs.tr.s = 0;
    sregs.ldt.unusable = 1;
    sregs.gdt.base = 0;
    sregs.gdt.limit = 0xffff;
    sregs.idt.base = 0;
    sregs.idt.limit = 0xffff;
    sregs.cr0 = 0x60000011ULL;
    sregs.apic_base = 0xfee00900ULL;
    memcpy(ctx->sregs_data, &sregs,
           sizeof(sregs) < sizeof(ctx->sregs_data) ? sizeof(sregs)
                                                   : sizeof(ctx->sregs_data));
    result = 0;
out:
    if (cpu_fd >= 0)
        close(cpu_fd);
    if (vm_fd >= 0)
        close(vm_fd);
    if (kvm_fd >= 0)
        close(kvm_fd);
    return result;
}

static void fill_tcg_realmode(wvm_tcg_context_t *ctx, uint64_t gpa)
{
    int i;
    memset(ctx, 0, sizeof(*ctx));
    ctx->eip = gpa;
    ctx->eflags = 0x2;
    ctx->regs[4] = gpa + 0x1000;
    ctx->cr[0] = 0x60000010ULL;
    ctx->a20_mask = 0xffffffffu;
    for (i = 0; i < 6; i++) {
        ctx->segs[i].base = 0;
        ctx->segs[i].limit = 0xffff;
        ctx->segs[i].selector = 0;
        ctx->segs[i].flags =
            (i == 1) ? SEG_FLAGS_CODE16 : SEG_FLAGS_DATA16;
    }
    ctx->ldt.limit = 0xffff;
    ctx->tr.limit = 0xffff;
    ctx->tr.flags = DESC_P_MASK | (0xbu << 8);
    ctx->gdt_limit = 0xffff;
    ctx->idt_limit = 0xffff;
}

int main(int argc, char **argv)
{
    const char *shm_path;
    const char *manifest_path;
    unsigned ingress_port;
    const char *backend_name;
    unsigned long marker;
    unsigned long gpa = 0x2000;
    int via_gateway = 0;
    char *end = NULL;
    char error[256];
    char dispatch_path[1024];
    char route_path[1024];
    struct wvm_runtime_manifest_storage manifest_storage;
    struct wvm_runtime_dispatch_storage dispatch_storage;
    struct wvm_route_snapshot_file_storage route_storage;
    struct wvm_runtime_dispatch_projection *disp;
    struct wvm_node_runtime_manifest *man;
    uint16_t backend;
    uint8_t context[WVM_X86_CONTEXT_WIRE_HEADER_BYTES + WVM_X86_CONTEXT_MAX_NATIVE_BYTES];
    size_t context_bytes = 0;
    uint64_t fields =
        WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE |
        WVM_VCPU_CONTEXT_FIELD_INTERRUPT_STATE;
    wvm_kvm_context_t kvm_ctx;
    wvm_tcg_context_t tcg_ctx;
    struct wvm_vcpu_handoff_request request;
    uint8_t payload[WVM_VCPU_HANDOFF_REQUEST_HEADER_BYTES +
                    WVM_X86_CONTEXT_WIRE_HEADER_BYTES +
                    WVM_X86_CONTEXT_MAX_NATIVE_BYTES];
    size_t payload_bytes = 0;
    struct wvm_envelope run_env;
    struct udp_emit_ctx emit;
    int sock = -1;
    int shm_fd = -1;
    uint8_t *ram = MAP_FAILED;
    size_t ram_size = 0;
    struct stat st;
    uint32_t store_gpa;
    volatile uint32_t *store_slot;
    int waited;
    int rc = 1;

    if (argc < 6 || argc > 8) {
        fprintf(stderr,
                "usage: %s SHM MANIFEST INGRESS_PORT kvm|tcg MARKER [GPA] "
                "[via_gateway]\n",
                argv[0]);
        return 2;
    }
    shm_path = argv[1];
    manifest_path = argv[2];
    ingress_port = (unsigned)strtoul(argv[3], &end, 10);
    if (!end || *end || ingress_port == 0 || ingress_port > 65535) {
        fprintf(stderr, "bad ingress port\n");
        return 2;
    }
    backend_name = argv[4];
    if (strcmp(backend_name, "kvm") == 0) {
        backend = WVM_VCPU_BACKEND_KVM;
    } else if (strcmp(backend_name, "tcg") == 0) {
        backend = WVM_VCPU_BACKEND_TCG;
    } else {
        fprintf(stderr, "backend must be kvm|tcg\n");
        return 2;
    }
    marker = strtoul(argv[5], &end, 0);
    if (!end || *end || marker > 0xffffffffUL) {
        fprintf(stderr, "bad marker\n");
        return 2;
    }
    if (argc >= 7) {
        gpa = strtoul(argv[6], &end, 0);
        if (!end || *end) {
            fprintf(stderr, "bad gpa\n");
            return 2;
        }
    }
    if (argc >= 8) {
        via_gateway = (int)strtol(argv[7], &end, 10);
        if (!end || *end) {
            fprintf(stderr, "bad via_gateway\n");
            return 2;
        }
    }
    store_gpa = (uint32_t)(gpa + 0x20);

    wvm_runtime_manifest_storage_init(&manifest_storage);
    wvm_runtime_dispatch_storage_init(&dispatch_storage);
    wvm_route_snapshot_file_storage_init(&route_storage);
    error[0] = '\0';

    if (wvm_runtime_manifest_load_file(manifest_path, &manifest_storage, error,
                                       sizeof(error)) != 0) {
        fprintf(stderr, "manifest load: %s\n", error);
        goto out;
    }
    man = &manifest_storage.manifest;
    if (wvm_runtime_dispatch_path_from_manifest(manifest_path, dispatch_path,
                                                sizeof(dispatch_path), error,
                                                sizeof(error)) != 0 ||
        wvm_runtime_dispatch_file_load(dispatch_path, &dispatch_storage, error,
                                       sizeof(error)) != 0) {
        fprintf(stderr, "dispatch load: %s\n", error);
        goto out;
    }
    disp = &dispatch_storage.projection;
    if (wvm_route_snapshot_path_from_manifest(manifest_path, route_path,
                                              sizeof(route_path), error,
                                              sizeof(error)) != 0 ||
        wvm_route_snapshot_file_load(route_path, &route_storage, error,
                                     sizeof(error)) != 0 ||
        wvm_route_snapshot_file_matches(
            &route_storage, &disp->required_route_snapshot_key, error,
            sizeof(error)) != 0) {
        fprintf(stderr, "route load/match: %s\n", error);
        goto out;
    }

    printf("production_typed_dispatch=1\n");
    printf("dispatch_path=typed_WVM1_ingress%s\n",
           via_gateway ? "_via_gateway" : "");
    printf("via_gateway=%d\n", via_gateway);
    printf("ingress_port=%u\n", ingress_port);
    printf("manifest=%s\n", manifest_path);
    printf("node_runtime_data_port=%u\n",
           (unsigned)man->launch_plan.node_runtime_data_port);
    printf("local_executor_service_port=%u\n",
           (unsigned)man->launch_plan.local_executor_service_port);
    printf("vm_id=%u incarnation=%llu generation=%llu\n", man->vm_id,
           (unsigned long long)man->vm_incarnation,
           (unsigned long long)man->manifest_generation);
    printf("local_primary kind=%u scope=%llu vnode=%u\n",
           (unsigned)disp->local_primary.destination_kind,
           (unsigned long long)disp->local_primary.destination_scope,
           (unsigned)disp->local_primary.destination_vnode);
    printf("topology_kind=%u physical_node=%u instance=%llu\n",
           (unsigned)disp->route_topology_kind,
           (unsigned)disp->physical_node_id,
           (unsigned long long)disp->expected_node_instance_id);
    {
        const struct wvm_runtime_cpu_dispatch *cpu0 =
            wvm_runtime_dispatch_find_cpu(disp, 0);
        if (!cpu0) {
            fprintf(stderr, "dispatch has no cpu[0] executor placement\n");
            goto out;
        }
        printf("cpu0_executor kind=%u scope=%llu vnode=%u\n",
               (unsigned)cpu0->executor.destination_kind,
               (unsigned long long)cpu0->executor.destination_scope,
               (unsigned)cpu0->executor.destination_vnode);
    }
    if (!via_gateway &&
        ingress_port != man->launch_plan.node_runtime_data_port) {
        fprintf(stderr,
                "ingress_port %u != launch_plan.node_runtime_data_port %u "
                "(refusing direct_executor_udp confusion)\n",
                ingress_port,
                (unsigned)man->launch_plan.node_runtime_data_port);
        goto out;
    }
    if (ingress_port == man->launch_plan.local_executor_service_port) {
        fprintf(stderr,
                "refusing Hybrid executor_service_port %u — that is "
                "direct_executor_udp smoke, not production typed ingress\n",
                ingress_port);
        goto out;
    }

    shm_fd = open(shm_path, O_RDWR);
    if (shm_fd < 0 || fstat(shm_fd, &st) != 0 ||
        st.st_size < (off_t)(gpa + 64)) {
        fprintf(stderr, "shm open/size failed\n");
        goto out;
    }
    ram_size = (size_t)st.st_size;
    ram = mmap(NULL, ram_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (ram == MAP_FAILED) {
        perror("mmap shm");
        goto out;
    }
    store_slot = (volatile uint32_t *)(ram + store_gpa);
    *store_slot = 0;
    plant_guest_store(ram + gpa, (uint32_t)marker, store_gpa,
                      backend == WVM_VCPU_BACKEND_TCG);
    printf("code_at_gpa=0x%lx store_gpa=0x%x marker=0x%lx\n", gpa, store_gpa,
           marker);
    /*
     * KVM page-cache snapshot would otherwise fault-materialize implicit
     * directory zeros over this SHM plant. Publish first (same page as
     * code+store at 0x2000/0x2020).
     */
    if (publish_planted_page_to_directory(
            ram, gpa, (unsigned)man->launch_plan.node_runtime_data_port,
            man->vm_id, disp->local_primary.destination_vnode) != 0) {
        fprintf(stderr, "directory publish of planted page failed\n");
        goto out;
    }

    if (backend == WVM_VCPU_BACKEND_KVM) {
        if (fill_kvm_prot32(&kvm_ctx, gpa) != 0) {
            fprintf(stderr, "kvm context fill failed\n");
            goto out;
        }
        if (wvm_x86_context_encode(backend, fields, &kvm_ctx, sizeof(kvm_ctx),
                                   context, sizeof(context), &context_bytes,
                                   error, sizeof(error)) != 0) {
            fprintf(stderr, "kvm context encode: %s\n", error);
            goto out;
        }
    } else {
        fill_tcg_realmode(&tcg_ctx, gpa);
        if (wvm_x86_context_encode(backend, fields, &tcg_ctx, sizeof(tcg_ctx),
                                   context, sizeof(context), &context_bytes,
                                   error, sizeof(error)) != 0) {
            fprintf(stderr, "tcg context encode: %s\n", error);
            goto out;
        }
    }

    memset(&request, 0, sizeof(request));
    request.protocol_version = WVM_VCPU_HANDOFF_REQUEST_VERSION;
    request.backend = backend;
    request.context_schema_version = WVM_VCPU_CONTEXT_SCHEMA_X86;
    request.memory_fence_result = WVM_VCPU_MEMORY_FENCE_SUCCEEDED;
    request.vm_id = man->vm_id;
    request.vm_incarnation = man->vm_incarnation;
    request.manifest_generation = man->manifest_generation;
    request.origin_physical_node_id = disp->physical_node_id;
    request.origin_runtime_instance_id = disp->expected_node_instance_id;
    request.vcpu_index = 0;
    {
        const struct wvm_runtime_cpu_dispatch *cpu0 =
            wvm_runtime_dispatch_find_cpu(disp, 0);
        if (!cpu0) {
            fprintf(stderr, "missing cpu0 for handoff destination\n");
            goto out;
        }
        /* Production path (vcpu_coordinator): dest=cpu executor, reply=local_primary */
        request.destination_executor_id = cpu0->executor.destination_vnode;
        request.reply_destination_kind = disp->local_primary.destination_kind;
        request.reply_destination_scope = disp->local_primary.destination_scope;
        request.reply_destination_vnode = disp->local_primary.destination_vnode;
    }
    request.handoff_sequence = 0x53660001ULL ^ (uint64_t)getpid();
    if (request.handoff_sequence == 0)
        request.handoff_sequence = 1;
    request.memory_fence_id = 0xFE56CE56ULL ^ (uint64_t)man->vm_id;
    if (request.memory_fence_id == 0)
        request.memory_fence_id = 99;
    request.local_interrupt_watermark = 1;
    request.device_event_watermark = 1;
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        request.operation_id[0] = 0x56;
        request.operation_id[1] = 0x54; /* 'T' */
        request.operation_id[2] = (uint8_t)(man->vm_id & 0xff);
        request.operation_id[3] = (uint8_t)((man->vm_id >> 8) & 0xff);
        request.operation_id[12] = (uint8_t)(ts.tv_nsec & 0xff);
        request.operation_id[13] = (uint8_t)((ts.tv_nsec >> 8) & 0xff);
        request.operation_id[14] = (uint8_t)(getpid() & 0xff);
        request.operation_id[15] = 0xA1;
    }
    request.context_valid_fields = fields;
    request.context = context;
    request.context_bytes = context_bytes;
    if (wvm_vcpu_handoff_request_encode(&request, payload, sizeof(payload),
                                        &payload_bytes, error,
                                        sizeof(error)) != 0) {
        fprintf(stderr, "handoff encode: %s\n", error);
        goto out;
    }

    memset(&run_env, 0, sizeof(run_env));
    run_env.message_type = WVM_ENVELOPE_MSG_VCPU_RUN;
    run_env.vm_id = man->vm_id;
    run_env.vm_incarnation = man->vm_incarnation;
    run_env.manifest_generation = man->manifest_generation;
    run_env.origin_physical_node_id = request.origin_physical_node_id;
    run_env.origin_runtime_instance_id = request.origin_runtime_instance_id;
    memcpy(run_env.operation_id, request.operation_id,
           sizeof(run_env.operation_id));
    run_env.delivery_attempt_id = 1;
    run_env.route_scope_id =
        disp->required_route_snapshot_key.scope_key.route_scope_id;
    run_env.topology_revision =
        disp->required_route_snapshot_key.topology_revision;
    run_env.route_generation =
        disp->required_route_snapshot_key.route_generation;
    memcpy(run_env.route_snapshot_digest,
           disp->required_route_snapshot_key.snapshot_digest,
           sizeof(run_env.route_snapshot_digest));
    {
        const struct wvm_runtime_cpu_dispatch *cpu0 =
            wvm_runtime_dispatch_find_cpu(disp, 0);
        if (!cpu0) {
            fprintf(stderr, "missing cpu0 for envelope route\n");
            goto out;
        }
        /* Envelope targets admitted executor (same as resolve_route(cpu->executor)) */
        run_env.route.destination_kind = cpu0->executor.destination_kind;
        run_env.route.destination_scope = cpu0->executor.destination_scope;
        run_env.route.destination_vnode_or_endpoint =
            cpu0->executor.destination_vnode;
    }
    run_env.route.hop_limit = 4;
    run_env.route.hop_count = 0;
    run_env.payload = payload;
    run_env.payload_bytes = payload_bytes;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        goto out;
    }
    memset(&emit, 0, sizeof(emit));
    emit.fd = sock;
    emit.dest.sin_family = AF_INET;
    emit.dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    emit.dest.sin_port = htons((uint16_t)ingress_port);
    if (wvm_envelope_emit_network_frames(&run_env, emit_udp_frame, &emit, error,
                                         sizeof(error)) != 0) {
        fprintf(stderr, "emit WVM1 VCPU_RUN: %s\n", error);
        goto out;
    }
    printf("sent_typed_vcpu_run ingress_port=%u payload_bytes=%zu\n",
           ingress_port, payload_bytes);

    /* Guest store is the honest execution proof (EXIT goes to sidecar). */
    for (waited = 0; waited < 5000; waited += 20) {
        if (*store_slot == (uint32_t)marker)
            break;
        sleep_ms(20);
    }
    if (*store_slot != (uint32_t)marker) {
        fprintf(stderr,
                "guest SHM store timeout: got=0x%x want=0x%lx "
                "(typed path did not complete guest store)\n",
                *store_slot, marker);
        goto out;
    }
    printf("guest_shm_store=PASS marker=0x%lx store_gpa=0x%x waited_ms=%d\n",
           marker, store_gpa, waited);
    printf("typed_short_exec=PASS backend=%s via_gateway=%d\n", backend_name,
           via_gateway);
    printf("not=direct_Hybrid_UDP_VCPU_RUN\n");
    printf("not=PASS_COMPONENT_SMOKE\n");
    rc = 0;

out:
    if (ram != MAP_FAILED)
        munmap(ram, ram_size);
    if (shm_fd >= 0)
        close(shm_fd);
    if (sock >= 0)
        close(sock);
    wvm_route_snapshot_file_storage_free(&route_storage);
    wvm_runtime_dispatch_storage_free(&dispatch_storage);
    wvm_runtime_manifest_storage_free(&manifest_storage);
    return rc;
}
