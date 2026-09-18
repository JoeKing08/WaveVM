
#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/module.h"
#include "qapi/error.h"
#include "qapi/qapi-builtin-visit.h"
#include "sysemu/accel.h"
#include "sysemu/cpus.h"
#include "sysemu/cpu-timers.h"
#include "sysemu/sysemu.h"
#include "qom/object.h"
#include "hw/boards.h"
#include "qemu/option.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/socket.h> 
#include <netinet/in.h>
#include <sys/un.h>
#include <errno.h>
#include "qemu/thread.h"
#include "sysemu/tcg.h"
#include "sysemu/kvm.h" 
#include "sysemu/kvm_int.h"
#include "../kvm/kvm-cpus.h"
#include "tcg/tcg.h"
#include "linux/kvm.h"
#include "exec/cpu-common.h"
#include "exec/address-spaces.h"
#include "exec/exec-all.h"
#include "cpu.h"
#include "hw/i386/apic.h"
#include "hw/i386/apic_internal.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include "../../../common_include/wavevm_protocol.h"
#include "../../../common_include/wavevm_ioctl.h"
#include "../../../common_include/wavevm_executor_session.h"
#include "../../../common_include/wavevm_vcpu_handoff.h"
#include "../../../common_include/wavevm_x86_context.h"
#include "wavevm-accel.h"
#include "wavevm-runtime-registration.h"

// 引用相关模块
extern void wavevm_user_mem_init(void *ram_ptr, size_t ram_size);
extern void wavevm_setup_memory_region(MemoryRegion *mr, uint64_t size, int fd);
extern void wvm_tcg_get_state(CPUState *cpu, wvm_tcg_context_t *ctx);
extern void wvm_tcg_set_state(CPUState *cpu, wvm_tcg_context_t *ctx);
extern void wvm_set_ttl_interval(int ms);
extern void wvm_register_volatile_ram(uint64_t gpa, uint64_t size);
extern int wavevm_user_mem_flush_slave_dirty_sync(void);
extern void wvm_apply_remote_push(uint16_t msg_type, void *payload);
extern void wavevm_start_vcpu_thread(CPUState *cpu);
extern void wavevm_register_ram_block(void *hva, uint64_t size, uint64_t gpa);
static void wavevm_sync_topology(int dev_fd);
static int write_all(int fd, const void *buf, size_t len);

#define WVM_TCG_INTERRUPT_SYNC_MASK \
    (CPU_INTERRUPT_HARD | CPU_INTERRUPT_HALT | \
     CPU_INTERRUPT_TGT_EXT_0 | CPU_INTERRUPT_TGT_EXT_1 | \
     CPU_INTERRUPT_TGT_EXT_2 | CPU_INTERRUPT_TGT_EXT_3 | \
     CPU_INTERRUPT_TGT_EXT_4 | CPU_INTERRUPT_TGT_INT_0 | \
     CPU_INTERRUPT_TGT_INT_1 | CPU_INTERRUPT_TGT_INT_2)

/*
 * A remote TCG slice can consume a master-owned LAPIC IRQ only when the
 * master transfers both the LAPIC snapshot and its pending HARD indication.
 * Other interrupt_request bits remain local lifecycle/control state.
 */
#define WVM_TCG_REMOTE_IRQ_FORWARD_MASK CPU_INTERRUPT_HARD

int g_wvm_local_split = 0;
static bool g_wvm_split_explicit = false;
static bool g_wvm_mode_explicit = false;
static void *g_primary_ram_hva = NULL;
static uint64_t g_primary_ram_size = 0;
static bool g_user_mem_inited = false;
static uint64_t g_user_ram_size_hint = 0;
static bool g_wvm_kvm_bootstrap_done = false;
static AccelState *g_wvm_kvm_accel = NULL;
static bool g_wvm_tcg_bootstrap_done = false;

typedef struct {
    CPUState *cpu;
    unsigned int delay_us;
    uint64_t generation;
} WaveVMTcgKickCtx;

static pthread_once_t g_slave_exec_once = PTHREAD_ONCE_INIT;
static QemuMutex g_slave_exec_lock;
static QemuCond g_slave_exec_req_cond;
static QemuCond g_slave_exec_done_cond;
static QemuMutex g_tcg_kick_lock;
static uint64_t g_tcg_kick_generation;
static bool g_slave_exec_pending;
static bool g_slave_exec_done;
static struct wvm_ipc_cpu_run_req g_slave_exec_req;
static struct wvm_ipc_cpu_run_ack g_slave_exec_ack;

static void wavevm_slave_apply_tcg_identity(CPUState *cpu, uint32_t vcpu_index)
{
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    X86CPU *x86_cpu = X86_CPU(cpu);

    x86_cpu->apic_id = vcpu_index;
    if (x86_cpu->apic_state) {
        APICCommonState *apic = APIC_COMMON(x86_cpu->apic_state);
        uint64_t apicbase = cpu_get_apic_base(x86_cpu->apic_state);

        apic->initial_apic_id = vcpu_index;
        apic->id = (uint8_t)vcpu_index;
        if (vcpu_index == 0) {
            apicbase |= MSR_IA32_APICBASE_BSP;
        } else {
            apicbase &= ~MSR_IA32_APICBASE_BSP;
        }
        cpu_set_apic_base(x86_cpu->apic_state, apicbase);
    }
#else
    (void)cpu;
    (void)vcpu_index;
#endif
}

static void wavevm_slave_prepare_tcg_slice(CPUState *cpu,
                                           const struct wvm_ipc_cpu_run_req *req)
{
    /*
     * A slave TCG vCPU is a remote compute slice, not the authority for the
     * guest's device model.  Lifecycle and interrupt bits queued on the slave's
     * local QEMU CPU object are therefore host-local noise; importing or
     * consuming them can reset a valid remote AP context back to the slave's
     * own firmware path.  Preserve only a HARD IRQ explicitly transferred by
     * the master: its matching LAPIC snapshot was imported with the context,
     * so the slave can consume it when guest IF becomes enabled.
     */
    cpu->stop = false;
    cpu->exception_index = -1;
    cpu->interrupt_request = req->ctx.tcg.interrupt_request &
                             WVM_TCG_REMOTE_IRQ_FORWARD_MASK;
    qatomic_mb_set(&cpu->exit_request, 0);
    qatomic_mb_set(&cpu->icount_decr_ptr->u16.high, 0);
    if (!req->ctx.tcg.halted) {
        cpu->halted = 0;
    }
}

static void wavevm_log_slave_timer_state(CPUState *cpu,
                                         const char *phase,
                                         unsigned int seq)
{
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    X86CPU *x86cpu = X86_CPU(cpu);
    APICCommonState *apic;
    int64_t now;
    int64_t deadline;
    uint64_t timer_time = UINT64_MAX;
    int highest_irr = -1;

    if (!x86cpu->apic_state) {
        fprintf(stderr,
                "[WaveVM-TIMER] phase=%s seq=%u cpu=%d no-apic int=0x%x\n",
                phase, seq, cpu->cpu_index,
                (unsigned)cpu->interrupt_request);
        return;
    }

    apic = APIC_COMMON(x86cpu->apic_state);
    now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    deadline = qemu_clock_deadline_ns_all(QEMU_CLOCK_VIRTUAL,
                                          QEMU_TIMER_ATTR_ALL);
    if (apic->timer) {
        timer_time = timer_expire_time_ns(apic->timer);
    }
    highest_irr = apic_get_highest_priority_irr(x86cpu->apic_state);

    fprintf(stderr,
            "[WaveVM-TIMER] phase=%s seq=%u cpu=%d now=%" PRIi64
            " deadline=%" PRIi64 " apic_next=%" PRIi64
            " apic_expiry=%" PRIi64 " timer=%" PRIu64
            " pending=%d initial=%u lvt=0x%x irr=%d int=0x%x halted=%d\n",
            phase, seq, cpu->cpu_index, now, deadline,
            apic->next_time, apic->timer_expiry, timer_time,
            apic->timer ? timer_pending(apic->timer) : 0,
            apic->initial_count, apic->lvt[APIC_LVT_TIMER],
            highest_irr, (unsigned)cpu->interrupt_request, cpu->halted);
#else
    (void)cpu;
    (void)phase;
    (void)seq;
#endif
}

static bool wavevm_tcg_ctx_is_reset_vector(const wvm_tcg_context_t *ctx)
{
    return ctx->eip == 0xfff0 &&
           ctx->segs[R_CS].selector == 0xf000 &&
           ctx->cr[0] == 0x60000010 &&
           ctx->cr[3] == 0 &&
           ctx->efer == 0;
}

static bool wavevm_tcg_ack_regressed_to_reset(const wvm_tcg_context_t *req,
                                              const wvm_tcg_context_t *ack)
{
    return !wavevm_tcg_ctx_is_reset_vector(req) &&
           wavevm_tcg_ctx_is_reset_vector(ack);
}

/* ---- Async vCPU-run worker (V33g fix: unblock net thread) ----
 * V33n fix: worker no longer writes to socket directly.
 * Instead it stores the result and signals the net thread via SIGUSR2.
 * Net thread sends MSG_VCPU_EXIT — single-writer on socket, preserving
 * message ordering and avoiding TCP stream corruption.
 */
#include <signal.h>
#include <pthread.h>

#define WVM_VCPU_DONE_SIGNAL  SIGUSR2

typedef struct {
    QemuMutex lock;
    QemuCond  has_work;
    QemuCond  work_taken;
    bool      pending;          /* net thread set → worker clears */
    bool      initialized;
    /* result: worker stores ack here, net thread reads when done */
    struct wvm_ipc_cpu_run_ack result_ack;
    volatile int done;          /* atomic: worker sets 1, net thread clears 0 */
    pthread_t net_thread_id;    /* for pthread_kill wakeup */
    /* request fields */
    struct wvm_ipc_cpu_run_req req;
    bool      compact_ctx;
    bool      mode_tcg;
    uint32_t  resp_source_id;   /* network order: slave/responder */
    uint32_t  resp_target_id;   /* network order: original requester */
    uint64_t  resp_req_id;      /* network order */
} WvmVcpuRunWorker;

static WvmVcpuRunWorker g_vcpu_run_worker;

#define WVM_VCPU_ACK_CACHE_SIZE 64
typedef struct {
    uint64_t req_id;
    uint8_t data[sizeof(struct wvm_header) + sizeof(struct wvm_ipc_cpu_run_ack)];
    int len;
    bool valid;
    bool in_flight;
} WvmVcpuAckCacheEntry;

static WvmVcpuAckCacheEntry g_vcpu_ack_cache[WVM_VCPU_ACK_CACHE_SIZE];
static QemuMutex g_vcpu_ack_cache_lock;
static pthread_once_t g_vcpu_ack_cache_once = PTHREAD_ONCE_INIT;

static void wavevm_vcpu_ack_cache_init(void)
{
    qemu_mutex_init(&g_vcpu_ack_cache_lock);
}

/*
 * MSG_VCPU_RUN is not idempotent: retrying the same req_id must not execute
 * the guest CPU twice.  This helper implements single-flight semantics:
 * - completed duplicate: replay cached MSG_VCPU_EXIT
 * - in-flight duplicate: drop it and wait for the original execution
 * - first arrival: mark in-flight and let caller execute it
 */
static bool wavevm_vcpu_run_cache_handle(int fd, uint64_t req_id)
{
    pthread_once(&g_vcpu_ack_cache_once, wavevm_vcpu_ack_cache_init);
    qemu_mutex_lock(&g_vcpu_ack_cache_lock);

    for (int i = 0; i < WVM_VCPU_ACK_CACHE_SIZE; i++) {
        WvmVcpuAckCacheEntry *e = &g_vcpu_ack_cache[i];
        if (e->req_id != req_id || (!e->valid && !e->in_flight)) {
            continue;
        }
        if (e->valid && e->len > 0) {
            send(fd, e->data, e->len, 0);
        }
        qemu_mutex_unlock(&g_vcpu_ack_cache_lock);
        return true;
    }

    int slot = req_id % WVM_VCPU_ACK_CACHE_SIZE;
    if (g_vcpu_ack_cache[slot].in_flight) {
        for (int i = 0; i < WVM_VCPU_ACK_CACHE_SIZE; i++) {
            if (!g_vcpu_ack_cache[i].in_flight) {
                slot = i;
                break;
            }
        }
    }

    WvmVcpuAckCacheEntry *e = &g_vcpu_ack_cache[slot];
    e->req_id = req_id;
    e->len = 0;
    e->valid = false;
    e->in_flight = true;
    qemu_mutex_unlock(&g_vcpu_ack_cache_lock);
    return false;
}

static void wavevm_vcpu_ack_cache_store(uint64_t req_id, const void *data, int len)
{
    if (len <= 0 || len > (int)sizeof(g_vcpu_ack_cache[0].data)) {
        return;
    }
    pthread_once(&g_vcpu_ack_cache_once, wavevm_vcpu_ack_cache_init);
    qemu_mutex_lock(&g_vcpu_ack_cache_lock);
    WvmVcpuAckCacheEntry *e = NULL;

    for (int i = 0; i < WVM_VCPU_ACK_CACHE_SIZE; i++) {
        if (g_vcpu_ack_cache[i].req_id == req_id &&
            (g_vcpu_ack_cache[i].in_flight || g_vcpu_ack_cache[i].valid)) {
            e = &g_vcpu_ack_cache[i];
            break;
        }
    }
    if (!e) {
        e = &g_vcpu_ack_cache[req_id % WVM_VCPU_ACK_CACHE_SIZE];
    }

    memcpy(e->data, data, len);
    e->len = len;
    e->req_id = req_id;
    e->valid = true;
    e->in_flight = false;
    qemu_mutex_unlock(&g_vcpu_ack_cache_lock);
}

static void wvm_sigusr2_handler(int sig) {
    /* no-op: sole purpose is to interrupt recvmmsg with EINTR */
    (void)sig;
}

/* Forward declaration — defined later in file */
int wavevm_slave_submit_cpu_run(const struct wvm_ipc_cpu_run_req *req,
                                struct wvm_ipc_cpu_run_ack *ack);

static void wavevm_slave_exec_sync_init(void)
{
    qemu_mutex_init(&g_slave_exec_lock);
    qemu_cond_init(&g_slave_exec_req_cond);
    qemu_cond_init(&g_slave_exec_done_cond);
    qemu_mutex_init(&g_tcg_kick_lock);
    g_tcg_kick_generation = 0;
    g_slave_exec_pending = false;
    g_slave_exec_done = false;
    memset(&g_slave_exec_req, 0, sizeof(g_slave_exec_req));
    memset(&g_slave_exec_ack, 0, sizeof(g_slave_exec_ack));
}

/* ---- V33n: Async vCPU-run worker thread ----
 * Receives MSG_VCPU_RUN requests from net thread, calls the blocking
 * wavevm_slave_submit_cpu_run(), stores the result and wakes the net
 * thread via SIGUSR2.  The net thread sends MSG_VCPU_EXIT on the socket
 * (single-writer guarantee).
 */
static void *wavevm_vcpu_run_worker_fn(void *arg)
{
    WvmVcpuRunWorker *w = (WvmVcpuRunWorker *)arg;
    fprintf(stderr, "[WaveVM-Slave] vCPU-run worker thread started\n");

    while (1) {
        struct wvm_ipc_cpu_run_req req;

        /* Wait for net thread to hand off a MSG_VCPU_RUN */
        qemu_mutex_lock(&w->lock);
        while (!w->pending) {
            qemu_cond_wait(&w->has_work, &w->lock);
        }
        memcpy(&req, &w->req, sizeof(req));
        w->pending = false;
        qemu_cond_signal(&w->work_taken);   /* tell net thread slot is free */
        qemu_mutex_unlock(&w->lock);

        /* Blocking call — this is fine, we're on a dedicated thread */
        struct wvm_ipc_cpu_run_ack full_ack;
        memset(&full_ack, 0, sizeof(full_ack));
        wavevm_slave_submit_cpu_run(&req, &full_ack);

        /* Store result for net thread to pick up */
        memcpy(&w->result_ack, &full_ack, sizeof(full_ack));
        __atomic_store_n(&w->done, 1, __ATOMIC_RELEASE);

        /* Wake net thread from recvmmsg via SIGUSR2 → EINTR */
        pthread_kill(w->net_thread_id, WVM_VCPU_DONE_SIGNAL);
    }
    return NULL;
}

static void wavevm_vcpu_run_worker_init(void)
{
    WvmVcpuRunWorker *w = &g_vcpu_run_worker;
    if (w->initialized) return;

    /* Install SIGUSR2 handler (must not be SIG_IGN — need EINTR) */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = wvm_sigusr2_handler;
    sa.sa_flags = 0;  /* no SA_RESTART — we want recvmmsg to get EINTR */
    sigaction(WVM_VCPU_DONE_SIGNAL, &sa, NULL);

    qemu_mutex_init(&w->lock);
    qemu_cond_init(&w->has_work);
    qemu_cond_init(&w->work_taken);
    w->pending = false;
    w->done = 0;
    w->net_thread_id = pthread_self();  /* called from net thread */
    w->initialized = true;

    QemuThread worker_thread;
    qemu_thread_create(&worker_thread, "wvm-vcpu-run",
                        wavevm_vcpu_run_worker_fn, w,
                        QEMU_THREAD_DETACHED);
    fprintf(stderr, "[WaveVM-Slave] vCPU-run worker initialized (net_tid=%lu)\n",
            (unsigned long)w->net_thread_id);
}

/* V33n: Net thread sends MSG_VCPU_EXIT when worker signals completion.
 * Called from net thread only — single-writer guarantee on master_sock. */
static void wavevm_net_send_vcpu_exit(int master_sock, WvmVcpuRunWorker *w)
{
    struct wvm_ipc_cpu_run_ack *ack = &w->result_ack;
    uint8_t resp_buf[sizeof(struct wvm_header) + sizeof(struct wvm_ipc_cpu_run_ack)];
    struct wvm_header *rhdr = (struct wvm_header *)resp_buf;
    void *rpayload = resp_buf + sizeof(struct wvm_header);
    int resp_len;

    memset(rhdr, 0, sizeof(*rhdr));
    rhdr->magic = htonl(WVM_MAGIC);
    rhdr->msg_type = htons(MSG_VCPU_EXIT);
    rhdr->mode_tcg = w->mode_tcg ? 1 : 0;
    rhdr->slave_id = w->resp_source_id;
    rhdr->target_id = w->resp_target_id;
    rhdr->req_id = w->resp_req_id;

    if (w->compact_ctx) {
        if (w->mode_tcg) {
            memcpy(rpayload, &ack->ctx.tcg, sizeof(ack->ctx.tcg));
            rhdr->payload_len = htons(sizeof(ack->ctx.tcg));
            resp_len = sizeof(struct wvm_header) + sizeof(ack->ctx.tcg);
        } else {
            memcpy(rpayload, &ack->ctx.kvm, sizeof(ack->ctx.kvm));
            rhdr->payload_len = htons(sizeof(ack->ctx.kvm));
            resp_len = sizeof(struct wvm_header) + sizeof(ack->ctx.kvm);
        }
    } else {
        memcpy(rpayload, ack, sizeof(*ack));
        rhdr->payload_len = htons(sizeof(*ack));
        resp_len = sizeof(struct wvm_header) + sizeof(*ack);
    }
    rhdr->crc32 = 0;
    rhdr->crc32 = htonl(calculate_crc32(resp_buf, resp_len));
    wavevm_vcpu_ack_cache_store(WVM_NTOHLL(rhdr->req_id), resp_buf, resp_len);
    {
        static int __worker_ack = 0;
        if (__worker_ack < 20) {
            fprintf(stderr,
                    "[WaveVM-Slave] worker ack send mode=%u status=%d compact=%d len=%d\n",
                    w->mode_tcg ? 1 : 0, ack->status,
                    w->compact_ctx ? 1 : 0, resp_len);
            __worker_ack++;
        }
    }

    if (send(master_sock, resp_buf, resp_len, 0) < 0) {
        perror("[WaveVM-Slave] net-thread send MSG_VCPU_EXIT");
    }
}

static void *wavevm_tcg_kick_thread(void *opaque)
{
    WaveVMTcgKickCtx *ctx = opaque;
    static unsigned int kick_log_count;
    bool fired = false;
    uint64_t current_generation;

    g_usleep(ctx->delay_us);
    qemu_mutex_lock(&g_tcg_kick_lock);
    current_generation = g_tcg_kick_generation;
    if (ctx->generation == g_tcg_kick_generation) {
        cpu_exit(ctx->cpu);
        qemu_cpu_kick(ctx->cpu);
        fired = true;
    }
    if (fired && ((kick_log_count++ % 1000) == 0)) {
        fprintf(stderr,
                "[WaveVM-TCG-KICK] cpu=%d gen=%llu current=%llu "
                "exit=%d int=0x%x icount_high=%d\n",
                ctx->cpu->cpu_index,
                (unsigned long long)ctx->generation,
                (unsigned long long)current_generation,
                qatomic_read(&ctx->cpu->exit_request),
                (unsigned)ctx->cpu->interrupt_request,
                (int)qatomic_read(&ctx->cpu->icount_decr_ptr->u16.high));
    }
    qemu_mutex_unlock(&g_tcg_kick_lock);
    g_free(ctx);
    return NULL;
}

/*
 * WaveVM CpusAccel callbacks -- aligned with standard TCG MTTCG ops.
 * kick_vcpu_thread and handle_interrupt are essential for the VM
 * lifecycle (vm_start, pause, resume) and interrupt delivery to work.
 */
static void wavevm_kick_vcpu_thread(CPUState *cpu)
{
    cpu_exit(cpu);
    cpus_kick_thread(cpu);
}

static void wavevm_handle_interrupt(CPUState *cpu, int mask)
{
    bool need_lock = !qemu_mutex_iothread_locked();
    int old_mask;

    if (need_lock) {
        qemu_mutex_lock_iothread();
    }

    old_mask = cpu->interrupt_request;
    cpu->interrupt_request |= mask;

    /*
     * If called from iothread context, wake the target cpu in
     * case it is halted.
     */
    if (!qemu_cpu_is_self(cpu)) {
        qemu_cpu_kick(cpu);
    } else {
        qatomic_set(&cpu_neg(cpu)->icount_decr.u16.high, -1);
        if (icount_enabled() && !cpu->can_do_io &&
            (mask & ~old_mask) != 0) {
            cpu_abort(cpu, "Raised interrupt while not in I/O function");
        }
    }

    if (need_lock) {
        qemu_mutex_unlock_iothread();
    }
}

static int64_t wavevm_get_virtual_clock(void)
{
    return cpu_get_clock();
}

static int64_t wavevm_get_elapsed_ticks(void)
{
    return cpu_get_ticks();
}


/* TCG-safe wrappers: only call KVM sync functions when KVM is active */
static void wavevm_synchronize_post_reset(CPUState *cpu)
{
    if (kvm_enabled()) {
        kvm_cpu_synchronize_post_reset(cpu);
    }
}

static void wavevm_synchronize_post_init(CPUState *cpu)
{
    if (kvm_enabled()) {
        kvm_cpu_synchronize_post_init(cpu);
    }
}

static void wavevm_synchronize_state(CPUState *cpu)
{
    if (kvm_enabled()) {
        kvm_cpu_synchronize_state(cpu);
    }
}

static void wavevm_synchronize_pre_loadvm(CPUState *cpu)
{
    if (kvm_enabled()) {
        kvm_cpu_synchronize_pre_loadvm(cpu);
    }
}

static const CpusAccel wavevm_cpus = {
    .create_vcpu_thread = wavevm_start_vcpu_thread,
    .kick_vcpu_thread   = wavevm_kick_vcpu_thread,
    .handle_interrupt   = wavevm_handle_interrupt,
    .get_virtual_clock  = wavevm_get_virtual_clock,
    .get_elapsed_ticks        = wavevm_get_elapsed_ticks,
    .synchronize_post_reset   = wavevm_synchronize_post_reset,
    .synchronize_post_init    = wavevm_synchronize_post_init,
    .synchronize_state        = wavevm_synchronize_state,
    .synchronize_pre_loadvm   = wavevm_synchronize_pre_loadvm,
};

static void wavevm_slave_import_ctx(CPUState *cpu,
                                    const struct wvm_ipc_cpu_run_req *req,
                                    bool local_is_tcg)
{
        if (req->mode_tcg == local_is_tcg) {
            if (local_is_tcg) {
                wvm_tcg_set_state(cpu, (wvm_tcg_context_t *)&req->ctx.tcg);
            } else {
                struct kvm_regs kregs;
                struct kvm_sregs ksregs;
                struct kvm_lapic_state klapic;
                struct kvm_vcpu_events kev;
                struct kvm_mp_state mp;
                const wvm_kvm_context_t *kctx = &req->ctx.kvm;
            kregs.rax = kctx->rax; kregs.rbx = kctx->rbx; kregs.rcx = kctx->rcx;
            kregs.rdx = kctx->rdx; kregs.rsi = kctx->rsi; kregs.rdi = kctx->rdi;
            kregs.rsp = kctx->rsp; kregs.rbp = kctx->rbp;
            kregs.r8  = kctx->r8;  kregs.r9  = kctx->r9;  kregs.r10 = kctx->r10;
            kregs.r11 = kctx->r11; kregs.r12 = kctx->r12; kregs.r13 = kctx->r13;
            kregs.r14 = kctx->r14; kregs.r15 = kctx->r15;
            kregs.rip = kctx->rip; kregs.rflags = kctx->rflags;
            memcpy(&ksregs, kctx->sregs_data, sizeof(ksregs));
                if (kctx->lapic_valid) {
                    memcpy(&klapic, kctx->lapic_data, sizeof(klapic));
                    kvm_vcpu_ioctl(cpu, KVM_SET_LAPIC, &klapic);
                }
                if (kctx->vcpu_events_valid) {
                    memcpy(&kev, kctx->vcpu_events_data, sizeof(kev));
                    kvm_vcpu_ioctl(cpu, KVM_SET_VCPU_EVENTS, &kev);
                }
                if (kctx->mp_state_valid) {
                    mp.mp_state = kctx->mp_state;
                    kvm_vcpu_ioctl(cpu, KVM_SET_MP_STATE, &mp);
                }
                kvm_vcpu_ioctl(cpu, KVM_SET_SREGS, &ksregs);
                kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &kregs);
            }
    } else if (local_is_tcg) {
        wvm_tcg_context_t t_ctx;
        struct kvm_regs kregs;
        struct kvm_sregs ksregs;
        kregs.rax = req->ctx.kvm.rax; kregs.rbx = req->ctx.kvm.rbx; kregs.rcx = req->ctx.kvm.rcx;
        kregs.rdx = req->ctx.kvm.rdx; kregs.rsi = req->ctx.kvm.rsi; kregs.rdi = req->ctx.kvm.rdi;
        kregs.rsp = req->ctx.kvm.rsp; kregs.rbp = req->ctx.kvm.rbp;
        kregs.r8  = req->ctx.kvm.r8;  kregs.r9  = req->ctx.kvm.r9;  kregs.r10 = req->ctx.kvm.r10;
        kregs.r11 = req->ctx.kvm.r11; kregs.r12 = req->ctx.kvm.r12; kregs.r13 = req->ctx.kvm.r13;
        kregs.r14 = req->ctx.kvm.r14; kregs.r15 = req->ctx.kvm.r15;
        kregs.rip = req->ctx.kvm.rip; kregs.rflags = req->ctx.kvm.rflags;
        memcpy(&ksregs, req->ctx.kvm.sregs_data, sizeof(ksregs));
        wvm_translate_kvm_to_tcg(&kregs, &ksregs, &t_ctx);
        wvm_tcg_set_state(cpu, &t_ctx);
    } else {
        struct kvm_regs kregs;
        struct kvm_sregs ksregs;
        kvm_vcpu_ioctl(cpu, KVM_GET_SREGS, &ksregs);
        wvm_translate_tcg_to_kvm((wvm_tcg_context_t *)&req->ctx.tcg, &kregs, &ksregs);
        kvm_vcpu_ioctl(cpu, KVM_SET_SREGS, &ksregs);
        kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &kregs);
    }
}

static void wavevm_slave_export_ctx(CPUState *cpu,
                                    const struct wvm_ipc_cpu_run_req *req,
                                    struct wvm_ipc_cpu_run_ack *ack,
                                    bool local_is_tcg)
{
    ack->status = 0;
    ack->mode_tcg = req->mode_tcg;

        if (req->mode_tcg == local_is_tcg) {
            if (local_is_tcg) {
                wvm_tcg_get_state(cpu, &ack->ctx.tcg);
                ack->ctx.tcg.exit_reason = cpu->exception_index;
                ack->ctx.tcg.halted = cpu->halted ? 1 : 0;
                if (req->mode_tcg) {
                    /*
                     * Return an unconsumed master HARD IRQ.  The slave starts
                     * each slice with no local lifecycle noise, so this cannot
                     * leak helper-process wakeups back to the master.
                     */
                    ack->ctx.tcg.interrupt_request =
                        cpu->interrupt_request &
                        WVM_TCG_REMOTE_IRQ_FORWARD_MASK;
                } else {
                    ack->ctx.tcg.interrupt_request =
                        cpu->interrupt_request & WVM_TCG_INTERRUPT_SYNC_MASK;
                }
            } else {
                struct kvm_regs kregs;
                struct kvm_sregs ksregs;
                struct kvm_lapic_state klapic;
                struct kvm_vcpu_events kev;
                struct kvm_mp_state mp;
                wvm_kvm_context_t *kctx = &ack->ctx.kvm;
                kvm_vcpu_ioctl(cpu, KVM_GET_REGS, &kregs);
                kvm_vcpu_ioctl(cpu, KVM_GET_SREGS, &ksregs);
                if (kvm_vcpu_ioctl(cpu, KVM_GET_LAPIC, &klapic) >= 0) {
                    memcpy(kctx->lapic_data, &klapic, sizeof(klapic));
                    kctx->lapic_valid = 1;
                } else {
                    kctx->lapic_valid = 0;
                }
                if (kvm_vcpu_ioctl(cpu, KVM_GET_VCPU_EVENTS, &kev) >= 0) {
                    memcpy(kctx->vcpu_events_data, &kev, sizeof(kev));
                    kctx->vcpu_events_valid = 1;
                } else {
                    kctx->vcpu_events_valid = 0;
                }
                if (kvm_vcpu_ioctl(cpu, KVM_GET_MP_STATE, &mp) >= 0) {
                    kctx->mp_state = mp.mp_state;
                    kctx->mp_state_valid = 1;
                } else {
                    kctx->mp_state_valid = 0;
                }
                kctx->rax = kregs.rax; kctx->rbx = kregs.rbx; kctx->rcx = kregs.rcx;
            kctx->rdx = kregs.rdx; kctx->rsi = kregs.rsi; kctx->rdi = kregs.rdi;
            kctx->rsp = kregs.rsp; kctx->rbp = kregs.rbp;
            kctx->r8  = kregs.r8;  kctx->r9  = kregs.r9;  kctx->r10 = kregs.r10;
            kctx->r11 = kregs.r11; kctx->r12 = kregs.r12; kctx->r13 = kregs.r13;
            kctx->r14 = kregs.r14; kctx->r15 = kregs.r15;
            kctx->rip = kregs.rip; kctx->rflags = kregs.rflags;
            memcpy(kctx->sregs_data, &ksregs, sizeof(ksregs));

            {
                struct kvm_run *run = cpu->kvm_run;
                kctx->exit_reason = run->exit_reason;
                if (run->exit_reason == KVM_EXIT_IO) {
                    kctx->io.direction = run->io.direction;
                    kctx->io.size      = run->io.size;
                    kctx->io.port      = run->io.port;
                    kctx->io.count     = run->io.count;
                    if (run->io.direction == KVM_EXIT_IO_OUT) {
                        size_t io_bytes = run->io.size * run->io.count;
                        if (io_bytes > sizeof(kctx->io.data)) {
                            io_bytes = sizeof(kctx->io.data);
                        }
                        memcpy(kctx->io.data, (uint8_t *)run + run->io.data_offset, io_bytes);
                    }
                } else if (run->exit_reason == KVM_EXIT_MMIO) {
                    kctx->mmio.phys_addr = run->mmio.phys_addr;
                    kctx->mmio.len       = run->mmio.len;
                    kctx->mmio.is_write  = run->mmio.is_write;
                    memcpy(kctx->mmio.data, run->mmio.data, 8);
                }
            }
        }
    } else if (local_is_tcg) {
        wvm_tcg_context_t t_ctx;
        struct kvm_regs kregs;
        struct kvm_sregs ksregs;
        wvm_tcg_get_state(cpu, &t_ctx);
        memcpy(&ksregs, req->ctx.kvm.sregs_data, sizeof(ksregs));
        wvm_translate_tcg_to_kvm(&t_ctx, &kregs, &ksregs);
        ack->ctx.kvm.rax = kregs.rax; ack->ctx.kvm.rbx = kregs.rbx; ack->ctx.kvm.rcx = kregs.rcx;
        ack->ctx.kvm.rdx = kregs.rdx; ack->ctx.kvm.rsi = kregs.rsi; ack->ctx.kvm.rdi = kregs.rdi;
        ack->ctx.kvm.rsp = kregs.rsp; ack->ctx.kvm.rbp = kregs.rbp;
        ack->ctx.kvm.r8  = kregs.r8;  ack->ctx.kvm.r9  = kregs.r9;  ack->ctx.kvm.r10 = kregs.r10;
        ack->ctx.kvm.r11 = kregs.r11; ack->ctx.kvm.r12 = kregs.r12; ack->ctx.kvm.r13 = kregs.r13;
        ack->ctx.kvm.r14 = kregs.r14; ack->ctx.kvm.r15 = kregs.r15;
        ack->ctx.kvm.rip = kregs.rip; ack->ctx.kvm.rflags = kregs.rflags;
        ack->ctx.kvm.exit_reason = t_ctx.exit_reason;
        memcpy(ack->ctx.kvm.sregs_data, &ksregs, sizeof(ksregs));
    } else {
        struct kvm_regs kregs;
        struct kvm_sregs ksregs;
        kvm_vcpu_ioctl(cpu, KVM_GET_REGS, &kregs);
        kvm_vcpu_ioctl(cpu, KVM_GET_SREGS, &ksregs);
        wvm_translate_kvm_to_tcg(&kregs, &ksregs, &ack->ctx.tcg);
        ack->ctx.tcg.exit_reason = cpu->kvm_run->exit_reason;
        ack->ctx.tcg.halted = (cpu->kvm_run->exit_reason == KVM_EXIT_HLT) ? 1 : 0;
        ack->ctx.tcg.interrupt_request = 0;
    }
}

int wavevm_slave_submit_cpu_run(const struct wvm_ipc_cpu_run_req *req,
                                struct wvm_ipc_cpu_run_ack *ack)
{
    pthread_once(&g_slave_exec_once, wavevm_slave_exec_sync_init);

    qemu_mutex_lock(&g_slave_exec_lock);
    while (g_slave_exec_pending) {
        qemu_cond_wait(&g_slave_exec_done_cond, &g_slave_exec_lock);
    }

    memcpy(&g_slave_exec_req, req, sizeof(g_slave_exec_req));
    memset(&g_slave_exec_ack, 0, sizeof(g_slave_exec_ack));
    g_slave_exec_done = false;
    g_slave_exec_pending = true;
    qemu_cond_signal(&g_slave_exec_req_cond);

    while (!g_slave_exec_done) {
        qemu_cond_wait(&g_slave_exec_done_cond, &g_slave_exec_lock);
    }

    memcpy(ack, &g_slave_exec_ack, sizeof(*ack));
    qemu_mutex_unlock(&g_slave_exec_lock);
    return ack->status;
}

static int wavevm_session_parse_u64(const char *name, uint64_t *value)
{
    const char *text = getenv(name);
    char *end = NULL;
    unsigned long long parsed;

    if (!text || !*text || !value) {
        return -1;
    }
    errno = 0;
    parsed = strtoull(text, &end, 10);
    /* Accept zero as valid; only reject parse errors or trailing garbage */
    if (errno != 0 || !end || *end != '\0') {
        return -1;
    }
    *value = (uint64_t)parsed;
    return 0;
}

static int wavevm_session_authorize_request(
    const struct wvm_vcpu_handoff_request *request)
{
    uint64_t vm_id;
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    uint64_t executor_id;
    uint64_t vcpu_index;

    if (!request || request->backend != WVM_VCPU_BACKEND_TCG ||
        wavevm_session_parse_u64("WVM_VM_ID", &vm_id) != 0 ||
        wavevm_session_parse_u64("WVM_VM_INCARNATION", &vm_incarnation) != 0 ||
        wavevm_session_parse_u64("WVM_MANIFEST_GENERATION",
                                 &manifest_generation) != 0 ||
        wavevm_session_parse_u64("WVM_EXECUTOR_ID", &executor_id) != 0 ||
        wavevm_session_parse_u64("WVM_EXECUTOR_VCPU_INDEX", &vcpu_index) != 0 ||
        request->vm_id != vm_id || request->vm_incarnation != vm_incarnation ||
        request->manifest_generation != manifest_generation ||
        request->destination_executor_id != executor_id ||
        request->vcpu_index != vcpu_index) {
        return -1;
    }
    return 0;
}

static int wavevm_session_request_to_legacy(
    const struct wvm_vcpu_handoff_request *request,
    struct wvm_ipc_cpu_run_req *legacy_request, char *error, size_t error_len)
{
    uint64_t context_fields = 0;

    if (!request || !legacy_request ||
        request->backend != WVM_VCPU_BACKEND_TCG) {
        return -1;
    }
    memset(legacy_request, 0, sizeof(*legacy_request));
    legacy_request->mode_tcg = 1;
    legacy_request->slave_id = WVM_NODE_AUTO_ROUTE;
    legacy_request->vcpu_index = request->vcpu_index;
    if (wvm_x86_context_decode(
            WVM_VCPU_BACKEND_TCG, request->context, request->context_bytes,
            &context_fields, &legacy_request->ctx.tcg,
            sizeof(legacy_request->ctx.tcg), error, error_len) != 0 ||
        context_fields != request->context_valid_fields) {
        return -1;
    }
    return 0;
}

static uint16_t wavevm_session_tcg_exit_class(
    const struct wvm_ipc_cpu_run_ack *ack)
{
    if (ack->ctx.tcg.halted) {
        return WVM_VCPU_EXIT_HALTED;
    }
    if (ack->ctx.tcg.interrupt_request != 0) {
        return WVM_VCPU_EXIT_INTERRUPT;
    }
    return WVM_VCPU_EXIT_BUDGET;
}

static int wavevm_session_result_from_ack(
    const struct wvm_vcpu_handoff_request *request,
    const struct wvm_ipc_cpu_run_ack *ack, uint8_t *context,
    size_t context_capacity, struct wvm_vcpu_handoff_result *result,
    char *error, size_t error_len)
{
    size_t context_bytes = 0;

    if (!request || !ack || !context || !result) {
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->protocol_version = WVM_VCPU_HANDOFF_RESULT_VERSION;
    result->backend = WVM_VCPU_BACKEND_TCG;
    result->vm_id = request->vm_id;
    result->vm_incarnation = request->vm_incarnation;
    result->manifest_generation = request->manifest_generation;
    result->origin_physical_node_id = request->origin_physical_node_id;
    result->origin_runtime_instance_id = request->origin_runtime_instance_id;
    result->vcpu_index = request->vcpu_index;
    result->handoff_sequence = request->handoff_sequence;
    result->context_schema_version = request->context_schema_version;
    result->context_valid_fields = 0;
    memcpy(result->operation_id, request->operation_id,
           sizeof(result->operation_id));

    if (ack->status != 0) {
        result->status = WVM_VCPU_HANDOFF_RESULT_EXECUTOR_FAILURE;
        result->exit_class = WVM_VCPU_EXIT_EXECUTOR_ERROR;
        return 0;
    }
    if (wvm_x86_context_encode(
            WVM_VCPU_BACKEND_TCG, request->context_valid_fields,
            &ack->ctx.tcg, sizeof(ack->ctx.tcg), context, context_capacity,
            &context_bytes, error, error_len) != 0) {
        return -1;
    }
    result->status = WVM_VCPU_HANDOFF_RESULT_SUCCESS;
    result->exit_class = wavevm_session_tcg_exit_class(ack);
    result->context_valid_fields = request->context_valid_fields;
    result->context = context;
    result->context_bytes = context_bytes;
    return 0;
}

static void *wavevm_executor_session_thread(void *opaque)
{
    WaveVMAccelState *state = opaque;
    uint8_t *frame = g_malloc(WVM_EXECUTOR_SESSION_MAX_FRAME_BYTES);
    uint8_t *context = g_malloc(WVM_VCPU_HANDOFF_MAX_RESULT_CONTEXT_BYTES);
    uint8_t *result_payload =
        g_malloc(WVM_VCPU_HANDOFF_MAX_RESULT_CONTEXT_BYTES +
                 WVM_VCPU_HANDOFF_RESULT_HEADER_BYTES);

    if (!frame || !context || !result_payload) {
        g_free(frame);
        g_free(context);
        g_free(result_payload);
        return NULL;
    }

    while (state->executor_session_fd >= 0) {
        ssize_t received = recv(state->executor_session_fd, frame,
                                WVM_EXECUTOR_SESSION_MAX_FRAME_BYTES, 0);
        uint16_t message_type = 0;
        const uint8_t *payload = NULL;
        size_t payload_bytes = 0;
        struct wvm_vcpu_handoff_request request;
        struct wvm_vcpu_handoff_result result;
        struct wvm_ipc_cpu_run_req legacy_request;
        struct wvm_ipc_cpu_run_ack legacy_ack;
        char error[256] = {0};
        size_t result_payload_bytes = 0;
        uint8_t response[WVM_EXECUTOR_SESSION_MAX_FRAME_BYTES];
        size_t response_bytes = 0;

        if (received == 0 || (received < 0 && errno != EINTR)) {
            break;
        }
        if (received < 0) {
            continue;
        }
        if (wvm_executor_session_decode(
                frame, (size_t)received, &message_type, &payload,
                &payload_bytes, error, sizeof(error)) != 0 ||
            message_type != WVM_EXECUTOR_SESSION_VCPU_RUN ||
            wvm_vcpu_handoff_request_decode(
                payload, payload_bytes, &request, error, sizeof(error)) != 0 ||
            wavevm_session_authorize_request(&request) != 0 ||
            wavevm_session_request_to_legacy(
                &request, &legacy_request, error, sizeof(error)) != 0) {
            /* Send error response before closing */
            fprintf(stderr, "[WaveVM-TCG-Session] Request validation failed: %s\n",
                    error[0] ? error : "unknown error");
            close(state->executor_session_fd);
            state->executor_session_fd = -1;
            break;
        }

        memset(&legacy_ack, 0, sizeof(legacy_ack));
        wavevm_slave_submit_cpu_run(&legacy_request, &legacy_ack);
        if (wavevm_session_result_from_ack(
                &request, &legacy_ack, context,
                WVM_VCPU_HANDOFF_MAX_RESULT_CONTEXT_BYTES, &result, error,
                sizeof(error)) != 0 ||
            wvm_vcpu_handoff_result_encode(
                &result, result_payload,
                WVM_VCPU_HANDOFF_MAX_RESULT_CONTEXT_BYTES +
                    WVM_VCPU_HANDOFF_RESULT_HEADER_BYTES,
                &result_payload_bytes, error, sizeof(error)) != 0 ||
            wvm_executor_session_encode(
                WVM_EXECUTOR_SESSION_VCPU_EXIT, result_payload,
                result_payload_bytes, response, sizeof(response),
                &response_bytes, error, sizeof(error)) != 0 ||
            send(state->executor_session_fd, response, response_bytes,
                 MSG_NOSIGNAL) != (ssize_t)response_bytes) {
            break;
        }
    }

    g_free(frame);
    g_free(context);
    g_free(result_payload);
    return NULL;
}

void wavevm_slave_vcpu_loop(CPUState *cpu)
{
    pthread_once(&g_slave_exec_once, wavevm_slave_exec_sync_init);

    /*
     * Slave QEMU is started with -S because execution is driven by the
     * master's CPU_RUN requests.  That also skips vm_start(), which normally
     * enables the VM clock.  Keep the externally controlled vCPU loop, but
     * enable the clock primitives required by guest timers and APIC IRQs.
     */
    qemu_mutex_lock_iothread();
    cpu_enable_ticks();
    qemu_clock_enable(QEMU_CLOCK_VIRTUAL, true);
    fprintf(stderr,
            "[WaveVM-Slave] helper clock enabled virtual=%" PRIi64
            " deadline=%" PRIi64 "\n",
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
            qemu_clock_deadline_ns_all(QEMU_CLOCK_VIRTUAL,
                                       QEMU_TIMER_ATTR_ALL));
    qemu_mutex_unlock_iothread();

    fprintf(stderr, "[WaveVM-Slave] vCPU service loop online cpu=%d\n", cpu->cpu_index);

    while (!cpu->unplug) {
        struct wvm_ipc_cpu_run_req req;
        struct wvm_ipc_cpu_run_ack ack;
        bool local_is_tcg = !kvm_enabled();
        int exec_ret = -1;
        int dirty_flush_ret = 0;

        qemu_mutex_lock(&g_slave_exec_lock);
        while (!g_slave_exec_pending && !cpu->unplug) {
            qemu_cond_wait(&g_slave_exec_req_cond, &g_slave_exec_lock);
        }
        if (cpu->unplug) {
            qemu_mutex_unlock(&g_slave_exec_lock);
            break;
        }
        memcpy(&req, &g_slave_exec_req, sizeof(req));
        qemu_mutex_unlock(&g_slave_exec_lock);
        static unsigned int run_log_count;
        bool log_run = run_log_count++ < 20;
        if (log_run) {
            fprintf(stderr, "[WaveVM-Slave] vCPU got req mode_tcg=%u cpu=%d guest_vcpu=%u\n",
                    (unsigned)req.mode_tcg, cpu->cpu_index,
                    (unsigned)req.vcpu_index);
            if (req.mode_tcg) {
                fprintf(stderr,
                        "[WaveVM-Slave] TCG req eip=0x%llx cs=0x%x "
                        "cr0=0x%llx cr3=0x%llx efer=0x%llx "
                        "oldex=%d int=0x%x halted=%u\n",
                        (unsigned long long)req.ctx.tcg.eip,
                        (unsigned)req.ctx.tcg.segs[R_CS].selector,
                        (unsigned long long)req.ctx.tcg.cr[0],
                        (unsigned long long)req.ctx.tcg.cr[3],
                        (unsigned long long)req.ctx.tcg.efer,
                        (int)req.ctx.tcg.old_exception,
                        (unsigned)req.ctx.tcg.interrupt_request,
                        (unsigned)req.ctx.tcg.halted);
            }
        }

        while (!cpu_get_address_space(cpu, 0) && !cpu->unplug) {
            fprintf(stderr, "[WaveVM-Slave] waiting for address space cpu=%d\n", cpu->cpu_index);
            g_usleep(1000);
        }
        if (cpu->unplug) {
            break;
        }

        qemu_mutex_lock_iothread();
        if (local_is_tcg && req.mode_tcg) {
            wavevm_slave_apply_tcg_identity(cpu, req.vcpu_index);
        }
        wavevm_slave_import_ctx(cpu, &req, local_is_tcg);
        if (local_is_tcg && req.mode_tcg) {
            wavevm_slave_prepare_tcg_slice(cpu, &req);
        } else {
            cpu->stop = false;
            cpu->exception_index = -1;
            if (!(local_is_tcg && req.mode_tcg && req.ctx.tcg.halted)) {
                cpu->halted = 0;
            }
        }

        if (local_is_tcg) {
            static unsigned int exec_log_count;
            unsigned int exec_seq = exec_log_count++;
            bool log_exec = exec_seq < 24 || (exec_seq % 1000) == 0;
            X86CPU *x86cpu = X86_CPU(cpu);
            CPUX86State *env = &x86cpu->env;
            target_ulong entry_rip = env->eip;
            target_ulong entry_rsp = env->regs[R_ESP];
            target_ulong entry_rdi = env->regs[R_EDI];
            target_ulong entry_rax = env->regs[R_EAX];
            target_ulong entry_rflags = cpu_compute_eflags(env);
            WaveVMTcgKickCtx *kick = g_new0(WaveVMTcgKickCtx, 1);
            QemuThread kick_thread;
            uint64_t kick_generation;
            kick->cpu = cpu;
            kick->delay_us = 50000;  /* V31b: 50ms per burst (was 5ms), gives slave
                                       * enough time to fetch pages via UDP before
                                       * being kicked out of cpu_exec */
            /* The imported TCG state must be visible before cpu_exec_start().
             * Otherwise a freshly spawned slave can enter the run boundary with
             * its reset-vector state and overwrite the remote AP context. */
            qatomic_mb_set(&cpu->exit_request, 0);
            cpu_exec_start(cpu);
            qemu_mutex_lock(&g_tcg_kick_lock);
            kick_generation = ++g_tcg_kick_generation;
            kick->generation = kick_generation;
            qemu_mutex_unlock(&g_tcg_kick_lock);

            qemu_thread_create(&kick_thread, "wvm-tcg-kick",
                               wavevm_tcg_kick_thread, kick,
                               QEMU_THREAD_DETACHED);
            if (log_run || log_exec) {
                uint8_t code[16] = {0};
                uint32_t lock_word = 0;
                int code_ret = cpu_memory_rw_debug(cpu, entry_rip,
                                                   code, sizeof(code), 0);
                int lock_ret = cpu_memory_rw_debug(cpu, entry_rdi,
                                                   (uint8_t *)&lock_word,
                                                   sizeof(lock_word), 0);

                fprintf(stderr,
                        "[WaveVM-Slave] TCG ip cpu=%d seq=%u rip=%#lx "
                        "rsp=%#lx rdi=%#lx rax=%#lx lock=%#x/lr=%d "
                        "rflags=%#lx int=0x%x read=%d bytes=",
                        cpu->cpu_index, exec_seq,
                        (unsigned long)entry_rip,
                        (unsigned long)entry_rsp,
                        (unsigned long)entry_rdi,
                        (unsigned long)entry_rax,
                        lock_word, lock_ret,
                        (unsigned long)entry_rflags,
                        (unsigned)cpu->interrupt_request, code_ret);
                if (code_ret == 0) {
                    for (size_t i = 0; i < sizeof(code); i++) {
                        fprintf(stderr, "%02x", code[i]);
                    }
                }
                fprintf(stderr, "\n");
            }
            if (log_exec) {
                wavevm_log_slave_timer_state(cpu, "pre", exec_seq);
            }
            wavevm_tcg_log_stack(cpu, "slave-pre-exec");
            qemu_mutex_unlock_iothread();
            if (log_run || log_exec) {
                fprintf(stderr,
                        "[WaveVM-Slave] cpu_exec pre cpu=%d seq=%u "
                        "gen=%llu exit=%d int=0x%x icount_high=%d ex=%d\n",
                        cpu->cpu_index, exec_seq,
                        (unsigned long long)kick_generation,
                        qatomic_read(&cpu->exit_request),
                        (unsigned)cpu->interrupt_request,
                        (int)qatomic_read(&cpu->icount_decr_ptr->u16.high),
                        cpu->exception_index);
                fprintf(stderr, "[WaveVM-Slave] cpu_exec enter cpu=%d\n",
                        cpu->cpu_index);
            }
            exec_ret = cpu_exec(cpu);
            wavevm_tcg_log_stack(cpu, "slave-post-exec");
            qemu_mutex_lock(&g_tcg_kick_lock);
            if (kick_generation == g_tcg_kick_generation) {
                g_tcg_kick_generation++;
            }
            qemu_mutex_unlock(&g_tcg_kick_lock);
            if (log_run || log_exec) {
                target_ulong exit_rip = env->eip;
                target_ulong exit_rsp = env->regs[R_ESP];
                target_ulong exit_rdi = env->regs[R_EDI];
                target_ulong exit_rax = env->regs[R_EAX];
                target_ulong exit_rflags = cpu_compute_eflags(env);
                uint32_t lock_word = 0;
                int lock_ret = cpu_memory_rw_debug(cpu, exit_rdi,
                                                   (uint8_t *)&lock_word,
                                                   sizeof(lock_word), 0);

                fprintf(stderr,
                        "[WaveVM-Slave] cpu_exec leave cpu=%d seq=%u ret=%d "
                        "rip=%#lx->%#lx rsp=%#lx->%#lx rflags=%#lx->%#lx "
                        "rdi=%#lx rax=%#lx lock=%#x/lr=%d "
                        "ex=%d halted=%d exit=%d int=0x%x icount_high=%d\n",
                        cpu->cpu_index, exec_seq, exec_ret,
                        (unsigned long)entry_rip,
                        (unsigned long)exit_rip,
                        (unsigned long)entry_rsp,
                        (unsigned long)exit_rsp,
                        (unsigned long)entry_rflags,
                        (unsigned long)exit_rflags,
                        (unsigned long)exit_rdi,
                        (unsigned long)exit_rax,
                        lock_word, lock_ret,
                        cpu->exception_index, cpu->halted,
                        qatomic_read(&cpu->exit_request),
                        (unsigned)cpu->interrupt_request,
                        (int)qatomic_read(&cpu->icount_decr_ptr->u16.high));
            }
            qemu_mutex_lock_iothread();
            cpu_exec_end(cpu);
            if (log_exec) {
                wavevm_log_slave_timer_state(cpu, "post", exec_seq);
            }
            if (exec_ret == EXCP_ATOMIC) {
                qemu_mutex_unlock_iothread();
                cpu_exec_step_atomic(cpu);
                qemu_mutex_lock_iothread();
            }
            qemu_mutex_unlock_iothread();
            dirty_flush_ret = wavevm_user_mem_flush_slave_dirty_sync();
            qemu_mutex_lock_iothread();
        } else {
            /* KVM Slave 执行：复用 QEMU 原生 pre_run/post_run 钩子
             * 保证中断注入、APIC 同步、寄存器推送等不被遗漏。
             * 但不用 kvm_cpu_exec，因为 IO/MMIO 需要转发回 Master。
             */
            int ret;
            struct kvm_run *run = cpu->kvm_run;
            cpu_exec_start(cpu);
            qemu_mutex_unlock_iothread();
            do {
                if (cpu->vcpu_dirty) {
                    kvm_arch_put_registers(cpu, KVM_PUT_RUNTIME_STATE);
                    cpu->vcpu_dirty = false;
                }
                kvm_arch_pre_run(cpu, run);
                ret = kvm_vcpu_ioctl(cpu, KVM_RUN, 0);
                kvm_arch_post_run(cpu, run);
                if (ret == 0) {
                    int reason = run->exit_reason;
                    if (reason == KVM_EXIT_IO || reason == KVM_EXIT_MMIO ||
                        reason == KVM_EXIT_HLT || reason == KVM_EXIT_SHUTDOWN ||
                        reason == KVM_EXIT_FAIL_ENTRY) {
                        break;
                    }
                }
            } while (ret >= 0 || ret == -EINTR);
            qemu_mutex_lock_iothread();
            cpu_exec_end(cpu);
        }

        if (local_is_tcg && (exec_ret == EXCP_HLT || exec_ret == EXCP_HALTED)) {
            cpu->halted = 1;
            cpu->exception_index = exec_ret;
        }

        memset(&ack, 0, sizeof(ack));
        wavevm_slave_export_ctx(cpu, &req, &ack, local_is_tcg);
        if (local_is_tcg && req.mode_tcg && dirty_flush_ret < 0) {
            ack.status = dirty_flush_ret;
        }
        if (local_is_tcg && req.mode_tcg &&
            wavevm_tcg_ack_regressed_to_reset(&req.ctx.tcg, &ack.ctx.tcg)) {
            fprintf(stderr,
                    "[WaveVM-Slave] TCG ack rejected: helper reset-vector "
                    "regression req_eip=0x%llx req_cr3=0x%llx\n",
                    (unsigned long long)req.ctx.tcg.eip,
                    (unsigned long long)req.ctx.tcg.cr[3]);
            ack.status = -EFAULT;
            ack.ctx.tcg = req.ctx.tcg;
        }
        if (log_run && ack.mode_tcg) {
            fprintf(stderr,
                    "[WaveVM-Slave] TCG ack eip=0x%llx cs=0x%x "
                    "cr0=0x%llx cr3=0x%llx efer=0x%llx "
                    "oldex=%d int=0x%x halted=%u exit=%u\n",
                    (unsigned long long)ack.ctx.tcg.eip,
                    (unsigned)ack.ctx.tcg.segs[R_CS].selector,
                    (unsigned long long)ack.ctx.tcg.cr[0],
                    (unsigned long long)ack.ctx.tcg.cr[3],
                    (unsigned long long)ack.ctx.tcg.efer,
                    (int)ack.ctx.tcg.old_exception,
                    (unsigned)ack.ctx.tcg.interrupt_request,
                    (unsigned)ack.ctx.tcg.halted,
                    (unsigned)ack.ctx.tcg.exit_reason);
        }
        qemu_mutex_unlock_iothread();

        qemu_mutex_lock(&g_slave_exec_lock);
        memcpy(&g_slave_exec_ack, &ack, sizeof(ack));
        g_slave_exec_pending = false;
        g_slave_exec_done = true;
        qemu_cond_broadcast(&g_slave_exec_done_cond);
        qemu_mutex_unlock(&g_slave_exec_lock);
    }
}

static int wavevm_auto_split_from_vcpus(int vcpus)
{
    if (vcpus <= 1) {
        return 1;
    }
    if (vcpus == 2) {
        return 1;
    }
    return vcpus / 2;
}

static void wavevm_resolve_split(MachineState *ms)
{
    int vcpus = 1;
    const char *env_split;

    if (ms && ms->smp.cpus > 0) {
        vcpus = ms->smp.cpus;
    }

    if (!g_wvm_split_explicit) {
        env_split = getenv("WVM_LOCAL_SPLIT");
        if (env_split && *env_split) {
            char *endptr = NULL;
            long parsed = strtol(env_split, &endptr, 10);
            if (endptr && *endptr == '\0' && parsed >= 0) {
                g_wvm_local_split = (int)parsed;
            } else {
                g_wvm_local_split = wavevm_auto_split_from_vcpus(vcpus);
            }
        } else {
            g_wvm_local_split = wavevm_auto_split_from_vcpus(vcpus);
        }
    }

    if (g_wvm_local_split < 0) {
        g_wvm_local_split = 0;
    }
    if (g_wvm_local_split > vcpus) {
        g_wvm_local_split = vcpus;
    }
}

void wavevm_apply_split_hint(int split)
{
    int vcpus = 1;

    if (g_wvm_split_explicit || split < 0) {
        return;
    }

    if (current_machine && current_machine->smp.cpus > 0) {
        vcpus = current_machine->smp.cpus;
    }

    g_wvm_local_split = split;
    if (g_wvm_local_split > vcpus) {
        g_wvm_local_split = vcpus;
    }
}

/* [V28 FIX] 坚如磐石的读取函数，处理 Partial Read 和 EINTR */
static int read_exact(int fd, void *buf, size_t len) {
    size_t received = 0;
    char *ptr = (char *)buf;
    
    while (received < len) {
        ssize_t ret = read(fd, ptr + received, len - received);
        
        if (ret > 0) {
            received += ret;
        } else if (ret == 0) {
            return -1; // EOF: 对端挂了
        } else {
            if (errno == EINTR) continue; // 信号中断，重试
            return -1; // 真正的错误
        }
    }
    return 0; // 成功读满
}

static bool wavevm_allowed = true;

#define SYNC_WINDOW_SIZE 64

static int connect_to_master_helper_role(uint32_t role);

static int connect_to_master_helper(void) {
    return connect_to_master_helper_role(
        wavevm_qemu_runtime_gate_enabled() ? WVM_IPC_ROLE_SYNC : 0);
}

static int connect_to_master_helper_role(uint32_t role) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    
    // Manifest-gated launches must use a manifest-derived endpoint.
    const char *env_path = wavevm_qemu_runtime_socket_path();
    if (!env_path) {
        fprintf(stderr,
                "[WVM] manifest-derived QEMU socket path is missing\n");
        close(sock);
        return -1;
    }

    strncpy(addr.sun_path, env_path, sizeof(addr.sun_path) - 1);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    if (role != 0) {
        struct wvm_ipc_runtime_registration registration;
        const void *payload = &role;
        size_t payload_size = sizeof(role);
        wvm_ipc_header_t reg_hdr;

        if (wavevm_qemu_runtime_gate_enabled()) {
            if (wavevm_qemu_fill_runtime_registration((uint16_t)role,
                                                      &registration) != 0) {
                fprintf(stderr,
                        "[WVM] runtime gate active but QEMU registration "
                        "identity is incomplete\n");
                close(sock);
                return -1;
            }
            payload = &registration;
            payload_size = sizeof(registration);
        }
        reg_hdr.type = WVM_IPC_TYPE_REGISTER;
        reg_hdr.len = (uint32_t)payload_size;
        if (write_all(sock, &reg_hdr, sizeof(reg_hdr)) < 0 ||
            write_all(sock, payload, payload_size) < 0) {
            close(sock);
            return -1;
        }
    }
    return sock;
}

// Master Mode B (User) 的 IPC 监听线程
static void *wavevm_master_ipc_thread(void *arg) {
    WaveVMAccelState *s = (WaveVMAccelState *)arg;
    
    s->ipc_sock = connect_to_master_helper_role(WVM_IPC_ROLE_SYNC);
    if (s->ipc_sock < 0) {
        fprintf(stderr, "[WVM] Failed to connect IPC socket for IRQ listening.\n");
        return NULL;
    }

    struct wvm_ipc_header_t hdr;
    // IPC invalidation payload may carry a full 4K page plus protocol headers.
    uint8_t payload_buf[WVM_MAX_PACKET_SIZE];

    while (s->sync_thread_running) {
        // [V28 FIX] 使用 read_exact 替代原始 read
        if (read_exact(s->ipc_sock, &hdr, sizeof(hdr)) < 0) {
            // 连接断开或错误，尝试简单的重连或退出
            g_usleep(100000); 
            close(s->ipc_sock);
            s->ipc_sock = connect_to_master_helper_role(WVM_IPC_ROLE_SYNC);
            if (s->ipc_sock < 0) return NULL; // 重连失败则退出
            continue;
        }

        // [V28 FIX] 完整读取 Payload，防止粘包错位
        if (hdr.len > 0) {
            if (hdr.len > sizeof(payload_buf)) {
                fprintf(stderr, "[WVM] IPC Payload too large: %d\n", hdr.len);
                // 严重协议错误，无法恢复同步，必须断开
                close(s->ipc_sock);
                return NULL;
            }
            if (read_exact(s->ipc_sock, payload_buf, hdr.len) < 0) {
                continue; // 读取 Payload 失败
            }
        }

        // 1. 处理中断消息
        if (hdr.type == WVM_IPC_TYPE_IRQ) {
            qemu_mutex_lock_iothread();
            if (kvm_enabled()) {
                 struct kvm_irq_level irq;
                 irq.irq = 16; 
                 irq.level = 1;
                 kvm_vm_ioctl(kvm_state, KVM_IRQ_LINE, &irq);
                 irq.level = 0;
                 kvm_vm_ioctl(kvm_state, KVM_IRQ_LINE, &irq);
            }
            qemu_mutex_unlock_iothread();
        }
        // 2. 处理内存失效 (MESI Invalidate)
        else if (hdr.type == WVM_IPC_TYPE_MEM_WRITE) {
            if (hdr.len < (int)sizeof(struct wvm_ipc_write_req)) continue;
            struct wvm_ipc_write_req *req = (struct wvm_ipc_write_req *)payload_buf;
            // 约定：len=0 表示 Invalidate
            if (req->len == 0) {
                hwaddr len = 4096;
                void *host_addr = cpu_physical_memory_map(req->gpa, &len, 1);
                if (host_addr && len >= 4096) {
                    // KVM 模式下不能用 mprotect(PROT_NONE)，
                    // 否则 EPT 无法解析已被 mprotect 撤销的 HVA 映射，导致 VM Exit 风暴。
                    if (!kvm_enabled()) {
                        mprotect(host_addr, 4096, PROT_NONE);
                    }
                    cpu_physical_memory_unmap(host_addr, len, 1, 0);
                }
            }
        }
        else if (hdr.type == WVM_IPC_TYPE_INVALIDATE) { // Type 6
            if (hdr.len < (int)sizeof(struct wvm_header)) continue;
            // 解包内部的 wvm_header
            struct wvm_header *net_hdr = (struct wvm_header *)payload_buf;
            void *net_payload = payload_buf + sizeof(struct wvm_header);
            uint16_t msg_type = ntohs(net_hdr->msg_type);
            // 处理 Prophet 同步指令
            if (msg_type == MSG_RPC_BATCH_MEMSET) {
                // 1. TCG 模式下最关键的动作：冲刷所有翻译块 (Translation Blocks)
                // 必须在 BQL 锁保护下执行
                qemu_mutex_lock_iothread();
                
                // 冲刷所有缓存的代码。虽然这很重，但对于批量 memset 来说，
                // 它是保证指令一致性的唯一可靠手段。
                tb_flush(first_cpu); 
                
                // 2. 同时也需要更新 User-Mode 的版本号 (调用 user-mem.c)
                wvm_apply_remote_push(msg_type, net_payload);
                
                qemu_mutex_unlock_iothread();
                continue;
            }
            
            // 调用 user-mem 提供的逻辑应用更新
            wvm_apply_remote_push(msg_type, net_payload);
        }
    }
    close(s->ipc_sock);
    return NULL;
}

// Master 模式专用脏页同步线程 (仅 KVM 需此线程，TCG 由 user-mem 处理)
static void *wavevm_dirty_sync_thread(void *arg) {
    WaveVMAccelState *s = (WaveVMAccelState *)arg;
    if (!kvm_enabled()) {
        return NULL;
    }

    s->sync_sock = connect_to_master_helper_role(WVM_IPC_ROLE_SYNC);
    if (s->sync_sock < 0) {
        return NULL;
    }

    /* Keep the thread alive to preserve timing/ordering behavior.
     * Dirty-log harvesting is intentionally disabled in this compatibility path.
     */
    while (s->sync_thread_running) {
        g_usleep(50000);
    }

    close(s->sync_sock);
    return NULL;
}

// Kernel Mode IRQ 监听线程
static void *wavevm_kernel_irq_thread(void *arg) {
    WaveVMAccelState *s = (WaveVMAccelState *)arg;
    uint32_t irq_num;
    
    while (1) {
        // 陷入内核等待，直到收到 UDP 中断包
        if (ioctl(s->dev_fd, IOCTL_WAIT_IRQ, &irq_num) == 0) {
            qemu_mutex_lock_iothread();
            // 注入中断 (Pulse)
            if (kvm_enabled()) {
                 struct kvm_irq_level irq;
                 irq.irq = irq_num; // 例如 16
                 irq.level = 1;
                 kvm_vm_ioctl(kvm_state, KVM_IRQ_LINE, &irq);
                 irq.level = 0;
                 kvm_vm_ioctl(kvm_state, KVM_IRQ_LINE, &irq);
            }
            qemu_mutex_unlock_iothread();
        } else {
            // 出错或退出
            break;
        }
    }
    return NULL;
}

// Validate GPA range against actual QEMU RAM mapping (handles discontiguous RAM segments).
static bool wavevm_gpa_range_valid(uint64_t gpa, uint32_t len, bool is_write)
{
    hwaddr map_len = len;
    void *host_addr = cpu_physical_memory_map(gpa, &map_len, is_write ? 1 : 0);
    if (!host_addr || map_len < len) {
        if (host_addr) {
            cpu_physical_memory_unmap(host_addr, map_len, is_write ? 1 : 0, 0);
        }
        return false;
    }
    cpu_physical_memory_unmap(host_addr, map_len, is_write ? 1 : 0, 0);
    return true;
}

// Slave 网络处理线程 (支持 KVM 和 TCG 双模)
static void *wavevm_slave_net_thread(void *arg) {
    WaveVMAccelState *s = (WaveVMAccelState *)arg;
    #define BATCH_SIZE 64
    #define MAX_PKT_SIZE 8192

    struct mmsghdr msgs[BATCH_SIZE] = {0};
    struct iovec iovecs[BATCH_SIZE] = {0};
    uint8_t *buffers = g_malloc(BATCH_SIZE * MAX_PKT_SIZE);
    struct sockaddr_in addrs[BATCH_SIZE] = {0};

    for (int i = 0; i < BATCH_SIZE; i++) {
        iovecs[i].iov_base = buffers + i * MAX_PKT_SIZE;
        iovecs[i].iov_len = MAX_PKT_SIZE;
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &addrs[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
    }

    /* Detect kernel module presence — determines async (Mode A) vs sync (Mode B)
     * for MSG_VCPU_RUN handling. Mode B sync path avoids cross-node IPI deadlock
     * caused by async worker holding vCPU while net thread can't deliver IPIs. */
    bool local_kernel_mode = (access("/dev/wavevm", R_OK | W_OK) == 0);

    printf("[WaveVM-Slave] Network Loop Active (Engine: %s, FD: %d, vcpu_dispatch: %s).\n",
           kvm_enabled() ? "KVM" : "TCG", s->master_sock,
           local_kernel_mode ? "async" : "sync");

    WvmVcpuRunWorker *w = &g_vcpu_run_worker;

    while (1) {
        /* V33n: check if worker completed vCPU execution before blocking */
        if (w->initialized && __atomic_load_n(&w->done, __ATOMIC_ACQUIRE)) {
            wavevm_net_send_vcpu_exit(s->master_sock, w);
            __atomic_store_n(&w->done, 0, __ATOMIC_RELEASE);
        }

        for (int i = 0; i < BATCH_SIZE; i++) {
            msgs[i].msg_hdr.msg_namelen = sizeof(addrs[i]);
            msgs[i].msg_hdr.msg_flags = 0;
            msgs[i].msg_len = 0;
        }
        int retval = recvmmsg(s->master_sock, msgs, BATCH_SIZE,
                              MSG_WAITFORONE, NULL);
        if (retval < 0) {
            if (errno == EINTR) continue;  /* loops back to done-check above */
            perror("recvmmsg");
            break;
        }

        for (int i = 0; i < retval; i++) {
            uint8_t *buf = (uint8_t *)iovecs[i].iov_base;
            int len = msgs[i].msg_len;
            
            if (len >= sizeof(struct wvm_header)) {
                struct wvm_header *hdr = (struct wvm_header *)buf;
                void *payload = buf + sizeof(struct wvm_header);

                // [安全] Magic 校验，丢弃非 WaveVM 包
                if (ntohl(hdr->magic) != WVM_MAGIC) {
                    continue;
                }

                // [字节序] 从网络字节序解码到主机序
                uint16_t msg_type = ntohs(hdr->msg_type);
                uint16_t pkt_payload_len = ntohs(hdr->payload_len);
                int actual_payload = len - sizeof(struct wvm_header);

                // [安全] 报文实际长度 vs 头部声明长度一致性校验
                if (pkt_payload_len > actual_payload) {
                    continue; // 截断包，丢弃
                }

                // 1. 内存写 (Master -> Slave)
                if (msg_type == MSG_MEM_WRITE) {
                    qemu_mutex_lock_iothread();
                    if (pkt_payload_len > 8 && actual_payload >= pkt_payload_len) {
                        uint64_t gpa = WVM_NTOHLL(*(uint64_t *)payload);
                        uint32_t data_len = pkt_payload_len - 8;
                        void *data_ptr = (uint8_t *)payload + 8;
                        bool gpa_ok = wavevm_gpa_range_valid(gpa, data_len, true);
                        if (gpa_ok) {
                            cpu_physical_memory_write(gpa, data_ptr, data_len);
                        }
                    }
                    qemu_mutex_unlock_iothread();
                    hdr->msg_type = htons(MSG_MEM_ACK);
                    hdr->payload_len = 0;
                    hdr->crc32 = 0;
                    hdr->crc32 = htonl(calculate_crc32(buf, sizeof(struct wvm_header)));
                    if (write_all(s->master_sock, buf, sizeof(struct wvm_header)) < 0) {
                        perror("[WaveVM-Slave] send MSG_MEM_ACK");
                    }
                }
                // 2. 内存读 (Master -> Slave)
                else if (msg_type == MSG_MEM_READ) {
                    if (pkt_payload_len < 8) continue; // 至少需要 8 字节的 gpa
                    uint64_t gpa = WVM_NTOHLL(*(uint64_t *)payload);
                    uint32_t read_len = 4096;
                    qemu_mutex_lock_iothread();
                    bool gpa_ok = wavevm_gpa_range_valid(gpa, read_len, false);
                    if (!gpa_ok) {
                        qemu_mutex_unlock_iothread();
                        hdr->msg_type = htons(MSG_MEM_ACK);
                        hdr->payload_len = 0;
                        hdr->crc32 = 0;
                        hdr->crc32 = htonl(calculate_crc32(buf, sizeof(struct wvm_header)));
                        if (write_all(s->master_sock, buf, sizeof(struct wvm_header)) < 0) {
                            perror("[WaveVM-Slave] send short MSG_MEM_ACK");
                        }
                        continue;
                    }
                    if (sizeof(struct wvm_header) + read_len <= MAX_PKT_SIZE) {
                        cpu_physical_memory_read(gpa, payload, read_len);
                        qemu_mutex_unlock_iothread();
                        hdr->msg_type = htons(MSG_MEM_ACK);
                        hdr->payload_len = htons(read_len);
                        hdr->crc32 = 0;
                        hdr->crc32 = htonl(calculate_crc32(buf, sizeof(struct wvm_header) + read_len));
                        if (write_all(s->master_sock, buf, sizeof(struct wvm_header) + read_len) < 0) {
                            perror("[WaveVM-Slave] send MSG_MEM_ACK payload");
                        }
                    } else {
                        qemu_mutex_unlock_iothread();
                    }
                }
                // 3. 远程执行 (Master -> Slave) — V33g: async handoff to worker
                else if (msg_type == MSG_VCPU_RUN) {
                    struct wvm_ipc_cpu_run_req local_req;
                    struct wvm_ipc_cpu_run_req *req = NULL;
                    bool compact_ctx_payload = false;
                    uint64_t run_req_id = WVM_NTOHLL(hdr->req_id);

                    /* Backward compatibility: some senders put only context in payload. */
                    if (actual_payload >= (int)sizeof(struct wvm_ipc_cpu_run_req)) {
                        req = (struct wvm_ipc_cpu_run_req *)payload;
                    } else {
                        memset(&local_req, 0, sizeof(local_req));
                        local_req.mode_tcg = hdr->mode_tcg ? 1 : 0;
                        local_req.slave_id = ntohl(hdr->slave_id);

                        if (hdr->mode_tcg) {
                            if (actual_payload < (int)sizeof(wvm_tcg_context_t)) {
                                continue;
                            }
                            memcpy(&local_req.ctx.tcg, payload, sizeof(wvm_tcg_context_t));
                        } else {
                            if (actual_payload < (int)sizeof(wvm_kvm_context_t)) {
                                continue;
                            }
                            memcpy(&local_req.ctx.kvm, payload, sizeof(wvm_kvm_context_t));
                        }
                        req = &local_req;
                        compact_ctx_payload = true;
                    }

                    if (wavevm_vcpu_run_cache_handle(s->master_sock, run_req_id)) {
                        continue;
                    }

                    if (local_kernel_mode) {
                        /* Mode A: async worker — net thread must stay free for
                         * MSG_MEM_WRITE while vCPU executes (kernel page_mkwrite path) */
                        wavevm_vcpu_run_worker_init();

                        qemu_mutex_lock(&w->lock);
                        while (w->pending) {
                            qemu_cond_wait(&w->work_taken, &w->lock);
                        }
                        memcpy(&w->req, req, sizeof(w->req));
                        w->compact_ctx = compact_ctx_payload;
                        w->mode_tcg = hdr->mode_tcg ? 1 : 0;
                        w->resp_source_id = hdr->target_id;
                        w->resp_target_id = hdr->slave_id;
                        w->resp_req_id = hdr->req_id;
                        w->pending = true;
                        qemu_cond_signal(&w->has_work);
                        qemu_mutex_unlock(&w->lock);
                    } else {
                        /* Mode B: sync path — execute vCPU on net thread directly.
                         * This ensures IPI delivery (smp_call_function / flush_tlb_all)
                         * works correctly because vCPU exit and message processing
                         * are serialized on the same thread. */
                        struct wvm_ipc_cpu_run_ack full_ack;
                        memset(&full_ack, 0, sizeof(full_ack));
                        wavevm_slave_submit_cpu_run(req, &full_ack);
                        if (compact_ctx_payload) {
                            if (hdr->mode_tcg) {
                                memcpy(payload, &full_ack.ctx.tcg, sizeof(full_ack.ctx.tcg));
                                hdr->payload_len = htons(sizeof(full_ack.ctx.tcg));
                                msgs[i].msg_len = sizeof(struct wvm_header) + sizeof(full_ack.ctx.tcg);
                            } else {
                                memcpy(payload, &full_ack.ctx.kvm, sizeof(full_ack.ctx.kvm));
                                hdr->payload_len = htons(sizeof(full_ack.ctx.kvm));
                                msgs[i].msg_len = sizeof(struct wvm_header) + sizeof(full_ack.ctx.kvm);
                            }
                        } else {
                            memcpy(payload, &full_ack, sizeof(full_ack));
                            hdr->payload_len = htons(sizeof(full_ack));
                            msgs[i].msg_len = sizeof(struct wvm_header) + sizeof(full_ack);
                        }
                        hdr->msg_type = htons(MSG_VCPU_EXIT);
                        {
                            uint32_t req_source = hdr->slave_id;
                            uint32_t req_target = hdr->target_id;
                            hdr->slave_id = req_target;
                            hdr->target_id = req_source;
                        }
                        hdr->crc32 = 0;
                        hdr->crc32 = htonl(calculate_crc32(buf, msgs[i].msg_len));
                        wavevm_vcpu_ack_cache_store(run_req_id, buf, msgs[i].msg_len);
                        if (write_all(s->master_sock, buf, msgs[i].msg_len) < 0) {
                            perror("[WaveVM-Slave] send MSG_VCPU_EXIT");
                        }
                    }
                } else if (msg_type == MSG_PING) {
                    // [FIX] 透传 PING 给 Gateway/Master，由真正的 Owner 回复 ACK
                    if (write_all(s->master_sock, buf, sizeof(struct wvm_header)) < 0) {
                        perror("[WaveVM-Slave] send MSG_PING");
                    }
                }
            }
            msgs[i].msg_len = 0; 
        }
    }
    g_free(buffers);
    return NULL;
}

static int wavevm_init_machine_kernel(WaveVMAccelState *s, MachineState *ms) {
    struct wvm_ioctl_context_caps caps;
    fprintf(stderr, "[WaveVM-QEMU] KERNEL MODE: Connecting to /dev/wavevm...\n");
    s->dev_fd = open("/dev/wavevm", O_RDWR);
    if (s->dev_fd < 0) return -errno;
    if (wavevm_qemu_query_kernel_caps(s->dev_fd, &caps) < 0) {
        fprintf(stderr,
                "[WaveVM-QEMU] /dev/wavevm lacks the required context-bound "
                "accelerator ABI\n");
        close(s->dev_fd);
        s->dev_fd = -1;
        return -ENOTSUP;
    }
    {
        int bind_result = wavevm_qemu_bind_kernel_context(s->dev_fd);
        if (bind_result < 0) {
            fprintf(stderr,
                    "[WaveVM-QEMU] manifest-bound kernel context bind "
                    "failed: %s\n",
                    strerror(-bind_result));
            close(s->dev_fd);
            s->dev_fd = -1;
            return bind_result;
        }
    }
    wavevm_setup_memory_region(ms->ram, ms->ram_size, s->dev_fd);
    // 启动线程
    qemu_thread_create(&s->irq_thread, "wvm-k-irq", wavevm_kernel_irq_thread, s, QEMU_THREAD_DETACHED);
    return 0;
}

static int wavevm_init_machine_user(WaveVMAccelState *s, MachineState *ms) {
    // Slave Mode Check (FD Inheritance)
    char *env_cmd = getenv("WVM_SOCK_CMD");
    const char *env_session = getenv("WVM_EXECUTOR_SESSION_FD");

    s->executor_session_fd = -1;
    if (env_session && *env_session) {
        char *end = NULL;
        long parsed = strtol(env_session, &end, 10);

        if (!end || *end != '\0' || parsed < 0 || parsed > INT_MAX) {
            return -EINVAL;
        }
        s->executor_session_fd = (int)parsed;
    }
    
    if (env_cmd) {
        // [Slave Mode]
        s->master_sock = atoi(env_cmd); // Use CMD socket for control loop
    } else {
        // [Master Mode]
        // 读取环境变量以支持单机多实例
        const char *shm_path = getenv("WVM_SHM_FILE");
        if (!shm_path) {
            fprintf(stderr,
                    "WaveVM: manifest-derived SHM name is missing\n");
            return -EINVAL;
        }

        int shm_fd = shm_open(shm_path, O_CREAT | O_RDWR, 0666);
        if (shm_fd < 0) {
            fprintf(stderr, "WaveVM: Failed to open SHM file '%s': %s\n", shm_path, strerror(errno));
            exit(1);
        }
        
        // 确保文件大小足够 (Daemon 应该已经 truncate 过了，这里是双保险)
        if (ftruncate(shm_fd, ms->ram_size) < 0) {
            perror("ftruncate");
            close(shm_fd);
            exit(1);
        }

        wavevm_setup_memory_region(ms->ram, ms->ram_size, shm_fd);
        close(shm_fd);
        
        // [FIX-G4] IPC 监听线程必须无条件启动 (KVM + TCG 都需要接收 Invalidate)
        // dirty_sync_thread 仅 KVM 需要 (TCG 由 user-mem harvester 处理)
        s->sync_thread_running = true;

        // [FIX-F1] 初始化 Block IO 持久连接状态
        s->block_io_sock = -1;
        qemu_mutex_init(&s->block_io_lock);

        qemu_thread_create(&s->ipc_thread, "wvm-ipc-rx", wavevm_master_ipc_thread, s, QEMU_THREAD_DETACHED);
        if (kvm_enabled()) {
            qemu_thread_create(&s->sync_thread, "wvm-sync", wavevm_dirty_sync_thread, s, QEMU_THREAD_DETACHED);
        }
    }
        
    g_user_ram_size_hint = ms->ram_size;
    // 初始化拦截信号。某些机型在此时 ms->ram 仍可能为空，需做兜底查找。
    void *ram_ptr = NULL;
    if (ms->ram && memory_region_is_ram(ms->ram)) {
        ram_ptr = memory_region_get_ram_ptr(ms->ram);
    } else {
        MemoryRegionSection sec = memory_region_find(get_system_memory(), 0, ms->ram_size ? ms->ram_size : 1);
        if (sec.mr && memory_region_is_ram(sec.mr)) {
            ram_ptr = memory_region_get_ram_ptr(sec.mr) + sec.offset_within_region;
        }
    }
    if (!ram_ptr && g_primary_ram_hva) {
        ram_ptr = g_primary_ram_hva;
    }
    if (ram_ptr) {
        wavevm_user_mem_init(ram_ptr, g_primary_ram_size ? g_primary_ram_size : ms->ram_size);
        g_user_mem_inited = true;
    } else {
        // 某些机型在该回调时序下 RAM block 尚未注册；在 region_add 首块时补初始化。
        error_report("WaveVM: defer user mem init until first RAM block is registered");
    }

    return 0;
}

static struct wvm_ioctl_mem_layout global_layout;

static bool wavevm_user_mode_enabled(void)
{
    if (!current_machine || !current_machine->accelerator) {
        return false;
    }
    return WAVEVM_ACCEL(current_machine->accelerator)->mode == WVM_MODE_USER;
}

static bool wavevm_trackable_ram_section(const MemoryRegionSection *section)
{
    MemoryRegion *mr = section->mr;

    return mr &&
           memory_region_is_ram(mr) &&
           !memory_region_is_ram_device(mr) &&
           !memory_region_is_rom(mr) &&
           !memory_region_is_romd(mr);
}

static void wavevm_region_add(MemoryListener *listener, MemoryRegionSection *section) {
    if (!wavevm_trackable_ram_section(section)) return;

    uint64_t start_gpa = section->offset_within_address_space;
    uint64_t size = int128_get64(section->size);
    void *hva = memory_region_get_ram_ptr(section->mr) + section->offset_within_region;
    
    if (size < 4096) return;

    // 记录到本地表
    if (global_layout.count < 32) {
        for (int i = 0; i < global_layout.count; i++) {
            if (global_layout.slots[i].start == start_gpa &&
                global_layout.slots[i].size == size) {
                fprintf(stderr,
                        "[WaveVM] dedup region_add gpa=%#llx size=%#llx count=%d\n",
                        (unsigned long long)start_gpa,
                        (unsigned long long)size,
                        global_layout.count);
                return;
            }
        }
        global_layout.slots[global_layout.count].start = start_gpa;
        global_layout.slots[global_layout.count].size = size;
        global_layout.count++;
        fprintf(stderr,
                "[WaveVM] region_add gpa=%#llx size=%#llx count=%d\n",
                (unsigned long long)start_gpa,
                (unsigned long long)size,
                global_layout.count);

        /* User-mem fault hook is only valid in user mode. */
        if (wavevm_user_mode_enabled()) {
            extern void wavevm_register_ram_block(void *hva, uint64_t size, uint64_t gpa);
            wavevm_register_ram_block(hva, size, start_gpa);
        }

        /* [FIX] BIOS shadow sync for shared-memory backed RAM.
         *
         * When QEMU remaps the BIOS area (0xE0000-0xFFFFF) from ROM (pc.bios)
         * to RAM (ram0) during PAM shadow, the new RAM region's HVA contains
         * the correct BIOS code (QEMU copies it internally), but the SHM
         * backing file still has zeros at those offsets.  Slave nodes that
         * mmap the SHM file will see zeros instead of BIOS code, causing
         * triple faults when APs try to execute the SIPI trampoline or when
         * the BSP re-enters the BIOS area after PAM reconfiguration.
         *
         * Fix: when a RAM region overlapping 0xC0000-0xFFFFF is added,
         * memcpy the HVA content into the SHM shadow at the corresponding
         * offset.  This is a one-time copy that ensures BIOS shadow data
         * is visible to all processes sharing the SHM file.
         */
        if (wavevm_user_mode_enabled()) {
            extern void wavevm_sync_bios_shadow(uint64_t gpa, uint64_t size, void *hva);
            uint64_t bios_start = 0xC0000;
            uint64_t bios_end   = 0x100000;
            uint64_t region_end = start_gpa + size;
            if (start_gpa < bios_end && region_end > bios_start) {
                wavevm_sync_bios_shadow(start_gpa, size, hva);
            }
        }

        if (start_gpa == 0 && !g_primary_ram_hva) {
            g_primary_ram_hva = hva;
            g_primary_ram_size = size;
        }
        if (wavevm_user_mode_enabled() && start_gpa == 0 && !g_user_mem_inited) {
            wavevm_user_mem_init(hva, g_user_ram_size_hint ? g_user_ram_size_hint : size);
            g_user_mem_inited = true;
        }

        /* [FIX] Mode A: 每次新增 RAM block 都实时同步给内核模块，
         * 修复 wavevm_init_machine 中 wavevm_sync_topology 先于 RAM 创建的时序问题。
         * 若不实时同步，wvm_fault_handler 的 g_mem_slots 为空 → VM_FAULT_SIGBUS → exit=17。 */
        if (!wavevm_user_mode_enabled()) {
            WaveVMAccelState *ws = WAVEVM_ACCEL(current_machine->accelerator);
            if (ws->dev_fd >= 0) {
                wavevm_sync_topology(ws->dev_fd);
            }
        }
    }
}

// 关键：在虚拟机启动完成前，将拓扑同步给内核
static void wavevm_sync_topology(int dev_fd) {
    if (ioctl(dev_fd, IOCTL_SET_MEM_LAYOUT, &global_layout) < 0) {
        perror("[WVM] Failed to sync memory layout to kernel (continue)");
    }
}

// 监听器结构体
static MemoryListener wavevm_mem_listener = {
    .region_add = wavevm_region_add,
};

static int wavevm_init_machine(MachineState *ms) {
    WaveVMAccelState *s = WAVEVM_ACCEL(ms->accelerator);
    bool has_wvm_dev = wavevm_qemu_kernel_accel_usable();
    const char *disable_auto_kvm = getenv("WVM_DISABLE_AUTO_KVM");
    bool auto_kvm_enabled = !(disable_auto_kvm && atoi(disable_auto_kvm) == 1);
    char *role = getenv("WVM_ROLE");
    bool is_slave = (role && strcmp(role, "SLAVE") == 0);

    if (!g_wvm_mode_explicit) {
        if (is_slave) {
            s->mode = WVM_MODE_USER;
        } else {
            s->mode = has_wvm_dev ? WVM_MODE_KERNEL : WVM_MODE_USER;
        }
    }

    if (s->mode == WVM_MODE_KERNEL && !has_wvm_dev) {
        return -1;
    }

    int ret = 0;

    wavevm_resolve_split(ms);

    memory_listener_register(&wavevm_mem_listener, &address_space_memory);

    if (!g_wvm_kvm_bootstrap_done) {
        AccelClass *kvm_ac;
        AccelState *saved_accel;
        const char *mode_str = (s->mode == WVM_MODE_USER) ? "user" : "kernel";

        g_wvm_kvm_bootstrap_done = true;
        if (!auto_kvm_enabled) {
            fprintf(stderr, "[WaveVM] Auto-KVM disabled by WVM_DISABLE_AUTO_KVM=1 (mode=%s)\n",
                    mode_str);
        } else if (access("/dev/kvm", R_OK | W_OK) == 0) {
            kvm_ac = accel_find("kvm");
            if (kvm_ac && kvm_ac->init_machine) {
                g_wvm_kvm_accel = ACCEL(object_new(ACCEL_CLASS_NAME("kvm")));
                if (g_wvm_kvm_accel) {
#ifdef CONFIG_KVM
                    kvm_allowed = true;
#endif
                    saved_accel = ms->accelerator;
                    ms->accelerator = g_wvm_kvm_accel;
                    ret = kvm_ac->init_machine(ms);
                    ms->accelerator = saved_accel;

                    if (ret == 0) {
                        cpus_register_accel(&wavevm_cpus);
                        fprintf(stderr, "[WaveVM] KVM bootstrap OK (mode=%s), keep wavevm vCPU control (kvm_enabled=%d)\n",
                                mode_str, kvm_enabled() ? 1 : 0);
                    } else {
#ifdef CONFIG_KVM
                        kvm_allowed = false;
#endif
                        object_unref(OBJECT(g_wvm_kvm_accel));
                        g_wvm_kvm_accel = NULL;
                        ret = 0;
                        fprintf(stderr, "[WaveVM] KVM bootstrap failed (mode=%s), stay on TCG path\n",
                                mode_str);
                    }
                }
            }
        } else {
            fprintf(stderr, "[WaveVM] /dev/kvm not available (mode=%s), stay on TCG path\n",
                    mode_str);
        }
    }

    if (!kvm_enabled() && !g_wvm_tcg_bootstrap_done) {
        g_wvm_tcg_bootstrap_done = true;
#ifdef CONFIG_TCG
        tcg_allowed = true;
#endif
        tcg_exec_init(0);
    }

    if (s->mode == WVM_MODE_KERNEL) ret = wavevm_init_machine_kernel(s, ms);
    else ret = wavevm_init_machine_user(s, ms);
    if (ret < 0) return ret;

    // 只要是 Slave (无论 KVM 还是 TCG)，都启动网络处理线程
    // 这样 TCG Slave 也能接收 CPU 任务和内存请求
    if (is_slave) {
        // Now safe to run net thread in TCG mode because it uses a separate socket
        printf("[WaveVM] Starting Slave Net Thread on FD %d...\n", s->master_sock);
        qemu_thread_create(&s->net_thread, "wvm-slave-net", wavevm_slave_net_thread, s, QEMU_THREAD_DETACHED);
        if (s->executor_session_fd >= 0) {
            qemu_thread_create(&s->executor_session_thread,
                               "wvm-executor-session",
                               wavevm_executor_session_thread, s,
                               QEMU_THREAD_DETACHED);
        }
        // 暂停主 vCPU 线程，控制权移交给 net_thread 驱动
        if (current_cpu) { current_cpu->stop = true; current_cpu->halted = true; }
    }

    if (s->mode == WVM_MODE_KERNEL) {
        wavevm_sync_topology(s->dev_fd); 
    }
    return 0;
}

static char *wavevm_get_mode(Object *obj, Error **errp)
{
    WaveVMAccelState *s = WAVEVM_ACCEL(obj);
    return g_strdup(s->mode == WVM_MODE_USER ? "user" : "kernel");
}

static void wavevm_set_mode(Object *obj, const char *value, Error **errp)
{
    WaveVMAccelState *s = WAVEVM_ACCEL(obj);
    if (g_strcmp0(value, "user") == 0) {
        s->mode = WVM_MODE_USER;
        g_wvm_mode_explicit = true;
        return;
    }
    if (g_strcmp0(value, "kernel") == 0) {
        s->mode = WVM_MODE_KERNEL;
        g_wvm_mode_explicit = true;
        return;
    }
    error_setg(errp, "Invalid mode '%s' (expected 'kernel' or 'user')", value);
}

static void wavevm_set_split(Object *obj, Visitor *v, const char *name, void *opaque, Error **errp) {
    uint32_t value; if (!visit_type_uint32(v, name, &value, errp)) return;
    g_wvm_local_split = value;
    g_wvm_split_explicit = true;
}
static void wavevm_get_split(Object *obj, Visitor *v, const char *name, void *opaque, Error **errp) {
    uint32_t value = g_wvm_local_split; visit_type_uint32(v, name, &value, errp);
}
static void wavevm_set_ttl(Object *obj, Visitor *v, const char *name, void *opaque, Error **errp) {
    uint32_t value;
    if (!visit_type_uint32(v, name, &value, errp)) return;
    wvm_set_ttl_interval((int)value);
}
static void wavevm_get_ttl(Object *obj, Visitor *v, const char *name, void *opaque, Error **errp) {
    // Getter implementation usually needed for QOM but can be stubbed if write-only intent
    // keeping it simple
    uint32_t val = 0; 
    visit_type_uint32(v, name, &val, errp);
}
static void wavevm_set_watch(Object *obj, Visitor *v, const char *name, void *opaque, Error **errp) {
    char *value;
    if (!visit_type_str(v, name, &value, errp)) return;
    
    // 解析格式: "0xC0000000:16M;0x800000000:128K"
    // 使用副本进行分割，防止破坏原字符串
    char *dup = g_strdup(value);
    char *saveptr;
    char *token = strtok_r(dup, ";", &saveptr);
    
    while (token) {
        uint64_t gpa = 0;
        uint64_t size_bytes = 0;
        uint64_t size_val = 0;
        char unit = 0;
        
        // sscanf 解析 hex:size+unit
        if (sscanf(token, "%lx:%lu%c", &gpa, &size_val, &unit) >= 2) {
            size_bytes = size_val;
            if (unit == 'M' || unit == 'm') size_bytes *= 1024 * 1024;
            else if (unit == 'G' || unit == 'g') size_bytes *= 1024 * 1024 * 1024;
            else if (unit == 'K' || unit == 'k') size_bytes *= 1024;
            
            wvm_register_volatile_ram(gpa, size_bytes);
        }
        token = strtok_r(NULL, ";", &saveptr);
    }
    g_free(dup);
    g_free(value);
}
static void wavevm_get_watch(Object *obj, Visitor *v, const char *name, void *opaque, Error **errp) {
    char *val = g_strdup("");
    visit_type_str(v, name, &val, errp);
    g_free(val);
}
static void wavevm_accel_init(Object *obj) {
    WaveVMAccelState *s = WAVEVM_ACCEL(obj);
    s->mode = WVM_MODE_KERNEL;
}
static void wavevm_accel_class_init(ObjectClass *oc, void *data) {
    AccelClass *ac = ACCEL_CLASS(oc);

    ac->name = "wavevm";
    ac->init_machine = wavevm_init_machine;
    ac->allowed = &wavevm_allowed;

    cpus_register_accel(&wavevm_cpus);

    object_class_property_add_str(oc, "mode", wavevm_get_mode, wavevm_set_mode);
    object_class_property_set_description(oc, "mode",
        "Execution mode: 'kernel' or 'user'");

    object_class_property_add(oc, "split", "int",
        wavevm_get_split, wavevm_set_split,
        NULL, NULL);
    object_class_property_set_description(oc, "split",
        "Number of vCPUs to run locally (Tier 1)");

    object_class_property_add(oc, "watch", "string",
        wavevm_get_watch, wavevm_set_watch,
        NULL, NULL);
    object_class_property_set_description(oc, "watch",
        "List of volatile RAM ranges (e.g. 0xC0000:16M)");

    #ifndef CONFIG_USER_ONLY
    #endif
}
static const TypeInfo wavevm_accel_type = {
    .name = TYPE_WAVEVM_ACCEL, .parent = TYPE_ACCEL, .instance_size = sizeof(WaveVMAccelState),
    .class_init = wavevm_accel_class_init, .instance_init = wavevm_accel_init,
};
static void wavevm_type_init(void) { type_register_static(&wavevm_accel_type); }
type_init(wavevm_type_init);

// [Helper] 健壮写：处理 EINTR 和 EAGAIN
static int write_all(int fd, const void *buf, size_t len) {
    size_t written = 0;
    const char *ptr = buf;
    while (written < len) {
        ssize_t ret = write(fd, ptr + written, len - written);
        if (ret < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd = { .fd = fd, .events = POLLOUT };
                poll(&pfd, 1, 100); // Wait 100ms
                continue;
            }
            return -1;
        }
        written += ret;
    }
    return 0;
}

// [Helper] 健壮读：处理 EINTR 和 EAGAIN
static int read_all(int fd, void *buf, size_t len) {
    size_t received = 0;
    char *ptr = buf;
    while (received < len) {
        ssize_t ret = read(fd, ptr + received, len - received);
        if (ret < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd = { .fd = fd, .events = POLLIN };
                poll(&pfd, 1, 100); 
                continue;
            }
            return -1;
        }
        if (ret == 0) return -1; // EOF (Daemon died)
        received += ret;
    }
    return 0;
}

// [V29 Prophet Core] 同步 RPC 发送
// 返回 0 成功，-1 失败
int wvm_send_rpc_sync(uint16_t msg_type, void *payload, size_t len) {
    WaveVMAccelState *s = WAVEVM_ACCEL(current_machine->accelerator);
    int fd = -1;
    int needs_close = 0;

    // 1. 获取连接 FD
    if (s->mode == WVM_MODE_USER) {
        char *role = getenv("WVM_ROLE");
        // Slave: 复用 CMD 通道
        if (role && strcmp(role, "SLAVE") == 0) {
            fd = s->master_sock; 
        } else {
            // Master: 复用 Sync 通道或新建
            if (s->sync_sock > 0) fd = s->sync_sock;
            else { fd = connect_to_master_helper(); needs_close = 1; }
        }
    } else {
        return -1; // Kernel Mode 不支持此路径
    }

    if (fd < 0) return -1;

    // 2. 构造数据包 (IPC头 + WVM头 + Payload)
    size_t wvm_pkt_len = sizeof(struct wvm_header) + len;
    size_t total_size = sizeof(struct wvm_ipc_header_t) + wvm_pkt_len;
    
    uint8_t *buffer = g_malloc(total_size);
    if (!buffer) { if (needs_close) close(fd); return -1; }

    struct wvm_ipc_header_t *ipc_hdr = (struct wvm_ipc_header_t *)buffer;
    ipc_hdr->type = 99; // WVM_IPC_TYPE_RPC_PASSTHROUGH
    ipc_hdr->len = wvm_pkt_len;

    struct wvm_header *hdr = (struct wvm_header *)(buffer + sizeof(struct wvm_ipc_header_t));
    hdr->magic = htonl(WVM_MAGIC);
    hdr->msg_type = htons(msg_type);
    hdr->payload_len = htons(len);
    hdr->slave_id = 0; 
    hdr->req_id = WVM_HTONLL(SYNC_MAGIC); // "SYNC" Magic
    hdr->qos_level = 1; 
    hdr->crc32 = 0; 

    if (len > 0) memcpy(buffer + sizeof(struct wvm_ipc_header_t) + sizeof(struct wvm_header), payload, len);

    // 3. 发送指令
    if (write_all(fd, buffer, total_size) < 0) {
        g_free(buffer); if (needs_close) close(fd); return -1;
    }
    g_free(buffer);

    // 4. [BLOCKING] 等待 ACK
    // 10秒超时，防止 Daemon 执行 memset 耗时过长或崩溃
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int ret = poll(&pfd, 1, 10000); 
    
    if (ret > 0 && (pfd.revents & POLLIN)) {
        uint8_t ack_byte;
        if (read_all(fd, &ack_byte, 1) == 0) {
            if (needs_close) close(fd);
            return 0; // Success
        }
    }

    if (needs_close) close(fd);
    return -1; // Fail/Timeout
}

// -----------------------------------------------------------
// [V30 BLOCK IO FINAL] 分布式存储 IPC 发送实现 (Thread-Safe)
// -----------------------------------------------------------

// 结构体必须与 Daemon 端严格对齐 (Packed 13 Bytes)
struct wvm_ipc_block_req {
    uint64_t lba;
    uint32_t len;
    uint8_t  is_write;
    uint8_t  data[0];
} __attribute__((packed));

/*
 * [物理意图] 将 virtio-blk 的 IO 请求序列化并通过 IPC 管道发送给 Master Daemon。
 * [关键逻辑] 封装 WVM_IPC_TYPE_BLOCK_IO 消息头，如果是写操作则携带 Payload。
 * [后果] 这是存储拦截的"出口"。没有它，wavevm-block-hook.c 拦截下来的 IO 请求就烂在肚子里了。
 */
int wvm_send_ipc_block_io(uint64_t lba, void *buf, uint32_t len, int is_write) {
    WaveVMAccelState *s = WAVEVM_ACCEL(current_machine->accelerator);

    // 1. Slave 模式不直接发起存储请求
    char *role = getenv("WVM_ROLE");
    if (role && strcmp(role, "SLAVE") == 0) {
        return -1;
    }

    // [FIX-F1] 使用持久 IPC 连接，避免每次 Block IO 都 connect() -> Master pthread_create()
    // 旧代码每次调用 connect_to_master_helper() 创建新连接，Master 侧每个 accept()
    // 都 spawn 新线程，5000 IOPS 下秒创 5000 线程导致系统崩溃。
    // 修复方案：保持一条持久连接，用 mutex 序列化请求。Block IO 本身是同步等待的，
    // 串行化不会额外降低吞吐，反而消除了连接建立/销毁开销。
    qemu_mutex_lock(&s->block_io_lock);

    // 惰性初始化 + 断线重连
    if (s->block_io_sock < 0) {
        s->block_io_sock = connect_to_master_helper();
        if (s->block_io_sock < 0) {
            qemu_mutex_unlock(&s->block_io_lock);
            return -1;
        }
    }

    int fd = s->block_io_sock;

    // 2. 计算包大小
    size_t meta_size = sizeof(struct wvm_ipc_block_req);
    size_t payload_len = meta_size + (is_write ? len : 0);
    size_t total_size = sizeof(struct wvm_ipc_header_t) + payload_len;

    // 3. 分配缓冲区
    uint8_t *buffer = g_malloc(total_size);
    if (!buffer) {
        qemu_mutex_unlock(&s->block_io_lock);
        return -1;
    }

    // 4. 填充头部
    struct wvm_ipc_header_t *ipc_hdr = (struct wvm_ipc_header_t *)buffer;
    ipc_hdr->type = WVM_IPC_TYPE_BLOCK_IO; // Type 7
    ipc_hdr->len = payload_len;

    // 5. 填充请求体
    struct wvm_ipc_block_req *req = (struct wvm_ipc_block_req *)(buffer + sizeof(struct wvm_ipc_header_t));
    req->lba = lba;
    req->len = len;
    req->is_write = (uint8_t)is_write;

    if (is_write && buf) {
        memcpy(req->data, buf, len);
    }

    // 6. 原子发送
    int ret = 0;
    if (write_all(fd, buffer, total_size) < 0) {
        ret = -1;
    }

    // 7. 等待 Daemon 的同步确认与数据回传
    uint8_t ack_byte;
    if (ret == 0 && (read_all(fd, &ack_byte, 1) < 0 || ack_byte == 0)) {
        ret = -1;
    } else if (ret == 0 && !is_write && buf && len > 0) {
        if (read_all(fd, buf, len) < 0) {
            ret = -1;
        }
    }

    g_free(buffer);

    // [FIX-F1] 如果通信失败，关闭连接以便下次重建（断线重连）
    if (ret < 0) {
        close(s->block_io_sock);
        s->block_io_sock = -1;
    }

    qemu_mutex_unlock(&s->block_io_lock);
    return ret;
}
