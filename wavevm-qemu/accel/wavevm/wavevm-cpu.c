
#include "qemu/osdep.h"
#include "qemu-common.h"
#include "cpu.h"
#include "sysemu/cpus.h"
#include "sysemu/hw_accel.h"
#include "sysemu/kvm.h" 
#include "sysemu/runstate.h"
#include "qapi/error.h"
#include "linux/kvm.h"
#include <signal.h>
#include <time.h>
#include <sys/syscall.h>
#include "hw/boards.h"
#include "qemu/main-loop.h"
#include "exec/address-spaces.h"
#include "exec/cpu-all.h"
#include "hw/i386/apic.h"
#include "../kvm/kvm-cpus.h"
#include "../../../common_include/wavevm_protocol.h" 
#include "../../../common_include/wavevm_config.h"
#include "../../../common_include/wavevm_ioctl.h"
#include "wavevm-accel.h"
#include "wavevm-runtime-registration.h"
#include "qemu/thread.h"
#include "qemu/guest-random.h"
#include "tcg/tcg.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <limits.h>

extern void wavevm_apply_split_hint(int split);

// Per-vCPU Socket Pool to eliminate lock contention
static int *g_vcpu_socks = NULL;
static int g_configured_vcpus = 0;
static int g_wvm_debug_once = 0;

/* No-op signal handler for SIGRTMIN (HALT-WAKE safety timer).
 * Must be a real handler (not SIG_IGN) so the signal sets
 * signal_pending and can interrupt KVM_RUN. */
static void wvm_halt_wake_nop_handler(int sig) { (void)sig; }

/* [FIX] Track per-AP SIPI trampoline completion.
 * After SIPI, APs must run the BIOS trampoline LOCALLY first (to increment
 * the SMP CPU counter in shared memory and HLT). Only after this initial
 * local run should APs be dispatched to remote slaves.
 * ap_did_local_sipi[cpu_index] = 1 means trampoline is done. */
#define MAX_VCPUS 64
static int ap_did_local_sipi[MAX_VCPUS] = {0};
static int ap_did_os_sipi[MAX_VCPUS] = {0};
static gint64 ap_halt_probe_us[MAX_VCPUS] = {0};
/*
 * s23g3: remote KVM never populated run->io.data_offset (no local KVM_RUN on
 * that vCPU). IO-IN replay must stash device bytes here; the next remote SEND
 * copies from this buffer instead of (run + garbage data_offset) — which
 * segfaulted qemu under dual-yes (dmesg 15:03:15).
 */
static uint8_t g_wavevm_pending_io_data[MAX_VCPUS][64];
static size_t g_wavevm_pending_io_len[MAX_VCPUS];
static uint8_t g_wavevm_pending_io_valid[MAX_VCPUS];

/* HLT exit with an injected LAPIC timer/interrupt needs one local KVM
 * re-entry so the pending event can be consumed instead of being replayed
 * as the same HLT loop again. */
static int ap_hlt_pending_irq[MAX_VCPUS] = {0};
/* After remote WVM_EXIT_PREEMPT, run one bounded local kvm_cpu_exec so FE
 * in-kernel LAPIC can deliver timer ticks (slave has no irqchip). */
static int ap_kvm_preempt_drain[MAX_VCPUS] = {0};
/* Set true only when wavevm_remote_exec completed a real remote RPC
 * (kernel IOCTL or user-mode socket path). HALT-WAKE / SIPI / probe
 * early-returns must NOT inflate remote_done (s23g6 soft delta root). */
static bool g_wavevm_remote_rpc_ok[MAX_VCPUS];


static void wavevm_try_import_split_from_peer(int sock)
{
#ifdef SO_PEERCRED
    struct ucred cred;
    socklen_t cred_len = sizeof(cred);
    char path[64];
    FILE *fp;
    char envbuf[8192];
    size_t n;
    size_t i = 0;

    if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0) {
        return;
    }

    snprintf(path, sizeof(path), "/proc/%ld/environ", (long)cred.pid);
    fp = fopen(path, "rb");
    if (!fp) {
        return;
    }

    n = fread(envbuf, 1, sizeof(envbuf) - 1, fp);
    fclose(fp);
    if (n == 0) {
        return;
    }
    envbuf[n] = '\0';

    while (i < n) {
        char *kv = &envbuf[i];
        size_t kv_len = strnlen(kv, n - i);

        if (kv_len == 0) {
            i++;
            continue;
        }

        if (strncmp(kv, "WVM_LOCAL_SPLIT=", 16) == 0) {
            char *endptr = NULL;
            long parsed = strtol(kv + 16, &endptr, 10);
            if (endptr && *endptr == '\0' && parsed >= 0 && parsed <= INT_MAX) {
                wavevm_apply_split_hint((int)parsed);
            }
            break;
        }

        i += kv_len + 1;
    }
#else
    (void)sock;
#endif
}

static int write_full(int fd, const void *buf, size_t len);

static int connect_to_master_helper_role(uint32_t role)
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    const char *env_path;

    if (sock < 0) {
        return -1;
    }

    env_path = wavevm_qemu_runtime_socket_path();
    if (!env_path) {
        fprintf(stderr,
                "[WaveVM-CPU] manifest-derived QEMU socket path is missing\n");
        close(sock);
        return -1;
    }

    strncpy(addr.sun_path, env_path, sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    if (role != 0) {
        struct wvm_ipc_runtime_registration registration;
        const void *payload = &role;
        size_t payload_size = sizeof(role);
        wvm_ipc_header_t registration_header;

        if (wavevm_qemu_runtime_gate_enabled()) {
            if (wavevm_qemu_fill_runtime_registration(
                    (uint16_t)role, &registration) != 0) {
                fprintf(stderr,
                        "[WaveVM-CPU] runtime registration identity is "
                        "incomplete\n");
                close(sock);
                return -1;
            }
            payload = &registration;
            payload_size = sizeof(registration);
        }
        registration_header.type = WVM_IPC_TYPE_REGISTER;
        registration_header.len = (uint32_t)payload_size;
        if (write_full(sock, &registration_header,
                       sizeof(registration_header)) < 0 ||
            write_full(sock, payload, payload_size) < 0) {
            close(sock);
            return -1;
        }
    }
    wavevm_try_import_split_from_peer(sock);
    return sock;
}

static int connect_to_master_helper(void)
{
    return connect_to_master_helper_role(
        wavevm_qemu_runtime_gate_enabled() ? WVM_IPC_ROLE_SYNC : 0);
}

static int write_full(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int read_full(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

// TCG Helper Declarations (Defined in wavevm-tcg.c)
extern void wvm_tcg_get_state(CPUState *cpu, wvm_tcg_context_t *ctx);
extern void wvm_tcg_set_state(CPUState *cpu, wvm_tcg_context_t *ctx);
extern void wvm_tcg_set_master_ack_state(CPUState *cpu,
                                         wvm_tcg_context_t *ctx,
                                         const wvm_tcg_context_t *sent);
extern void wavevm_slave_vcpu_loop(CPUState *cpu);
typedef struct WVMHandoffDirtyJournal WVMHandoffDirtyJournal;
extern int wavevm_user_mem_ipc_push_fence(int ipc_fd, uint64_t timeout_us);
extern int wavevm_user_mem_tcg_shm_coherent(void);
/*
 * SHM join makes RAM visible across FE/helper without page copies.
 * Minimum contract (baseline §16 / vcpu-handoff §8.1): concurrent BSP-local +
 * AP-remote is the MAIN normal path when SHM-coherent; Section 15 force_local
 * is exceptional bounded softlock/NEED_LOCAL coverage only (not normal, must
 * not dominate remote accounting). NOT full upstream QEMU MTTCG perf.
 * Opt-out STW: WVM_TCG_SHM_CONCURRENT=0.
 */
static int wavevm_tcg_shm_allow_concurrent(void)
{
    const char *env;

    if (!wavevm_user_mem_tcg_shm_coherent()) {
        return 0;
    }
    /*
     * V1 Minimum (baseline §16 / §8.1): coherent SHM defaults to concurrent
     * MAIN path. Softlock/IPI uses exceptional per-vCPU force_local hold
     * (30s/90s/25s) + NEED_LOCAL — not boot sticky, must not dominate.
     * Opt-out knobs: WVM_TCG_SHM_CONCURRENT / WVM_TCG_DISABLE_FORCE_LOCAL.
     */
    env = getenv("WVM_TCG_SHM_CONCURRENT");
    if (env && env[0] != '\0') {
        return atoi(env) != 0 ? 1 : 0;
    }
    return 1;
}
extern int wavevm_user_mem_flush_dirty_to_ipc(int ipc_fd,
                                              WVMHandoffDirtyJournal **journal_out);
extern void wavevm_user_mem_finish_handoff_dirty(WVMHandoffDirtyJournal *journal,
                                                 int commit_ok);
extern int wavevm_user_mem_sync_page(uint64_t gpa);
extern uint64_t wavevm_user_mem_debug_read_u64(uint64_t gpa, uint64_t offset,
                                               int *ok);

/*
 * Remote TCG workers execute architectural CPU state, but master-side APIC/PIC
 * runtime events can arrive while this vCPU thread is blocked waiting for the
 * ACK. Importing a remote ACK must not erase those local wake sources. INIT
 * and SIPI are intentionally excluded: WaveVM handles the TCG AP lifecycle
 * with a dedicated master-side SIPI path, and replaying those bits after a
 * remote ACK can restart/poison an already-booted AP.
 */
#define WVM_TCG_MASTER_IRQ_PRESERVE_MASK \
    (CPU_INTERRUPT_HARD | CPU_INTERRUPT_HALT | CPU_INTERRUPT_POLL | \
     CPU_INTERRUPT_SMI | CPU_INTERRUPT_NMI | CPU_INTERRUPT_MCE | \
     CPU_INTERRUPT_VIRQ | CPU_INTERRUPT_TPR)

/*
 * A master HARD IRQ can remain pending while guest IF is disabled.  Transfer
 * it with the LAPIC context so a remote slice can consume it once IF opens;
 * do not blindly replay it after the ACK.
 */
/*
 * G3/concurrent: guest stop_machine, RCU stall NMI, and normal HARD must
 * reach the remote helper. Keeping only HARD left CPU#1 wedged under
 * concurrent SHM (rcu_sched stalls + "Sending NMI from CPU 0 to CPUs 1").
 */
#define WVM_TCG_REMOTE_IRQ_FORWARD_MASK \
    (CPU_INTERRUPT_HARD | CPU_INTERRUPT_NMI | CPU_INTERRUPT_SMI | \
     CPU_INTERRUPT_MCE | CPU_INTERRUPT_VIRQ)

static void wavevm_tcg_arm_need_local(CPUState *cpu, uint64_t rip);

static void wavevm_tcg_import_remote_ack(CPUState *cpu,
                                         wvm_tcg_context_t *ctx,
                                         const wvm_tcg_context_t *sent,
                                         uint32_t forwarded_irq)
{
    uint32_t master_irq =
        cpu->interrupt_request & WVM_TCG_MASTER_IRQ_PRESERVE_MASK;

    wvm_tcg_set_master_ack_state(cpu, ctx, sent);

    /*
     * The ACK carries the forwarded HARD bit if the remote CPU could not
     * consume it.  Preserve only master-side events that were not handed to
     * the remote slice.
     */
    cpu->interrupt_request |= master_irq & ~forwarded_irq;
    cpu->halted = ctx->halted ? 1 : 0;

    if (ctx->exit_reason == WVM_TCG_EXCP_NEED_LOCAL) {
        wavevm_tcg_arm_need_local(cpu, (uint64_t)ctx->eip);
        /* Clear halt so the local burst can re-enter cpu_exec. */
        cpu->halted = 0;
    }
}

static pthread_once_t g_wavevm_tcg_region_once = PTHREAD_ONCE_INIT;
static QemuMutex g_wavevm_tcg_slice_lock;
static QemuCond g_wavevm_tcg_slice_cond;
static int g_wavevm_tcg_local_active;
static bool g_wavevm_tcg_remote_pending;
static bool g_wavevm_tcg_remote_active;
static bool g_wavevm_tcg_local_handoff;
/* Under STW: after remote same-RIP spin, require this many additional local
 * slice completions before remote may reclaim (attach23: 30x ...8a62a7 ACK
 * → e1000 Tx Hang; attach19 escaped at max run 8).
 * attach25: slice-count alone failed (HLT/idle cpu_exec returns drain prefer
 * without guest progress). Also keep a MONOTONIC wall-clock floor. */
static int g_wavevm_tcg_local_prefer;
static int64_t g_wavevm_tcg_local_prefer_until_ns;
/* G3: short helper quanta under spin/prefer only. Bounded wall window
 * compresses remote_active hold time — never force-all-local for boot. */
static int64_t g_wavevm_tcg_short_budget_until_ns;
/* G3 attribution: remote vs local completions (and rare force_local uses). */
static uint64_t g_wavevm_tcg_remote_done[MAX_VCPUS];
static uint64_t g_wavevm_tcg_local_done[MAX_VCPUS];
static uint64_t g_wavevm_tcg_force_local_used[MAX_VCPUS];
/* attach26: prefer-BSP alone left remote AP spinning at same RIP while FE
 * blocked in unix_stream_data_wait (serial stuck ~20KB). When same-RIP
 * persists, force that vCPU onto local cpu_exec for a budget of slices so
 * BSP+AP interleave in-process (MTTCG) instead of STW remote IPC. */
static int g_wavevm_tcg_force_local[MAX_VCPUS];
static uint64_t g_wavevm_tcg_force_local_rip[MAX_VCPUS];
/* Concurrent spin: wall-clock hold AP local (renew on spin; ignore RIP wobble). */
static bool g_wavevm_tcg_force_local_hold[MAX_VCPUS];
static int64_t g_wavevm_tcg_force_local_hold_until_ns[MAX_VCPUS];
static int64_t g_wavevm_tcg_force_local_hold_armed_ns[MAX_VCPUS];
static int64_t g_wavevm_tcg_spin_arm_cooldown_until_ns[MAX_VCPUS];
/* During hold: allow 1 remote probe every N local forced slices so concurrent
 * remote_done keeps advancing (Minimum: force_local must not dominate). */
static uint32_t g_wavevm_tcg_force_local_hold_ticks[MAX_VCPUS];
static int g_wavevm_tcg_need_local_repeat[MAX_VCPUS];
static uint64_t g_wavevm_tcg_need_local_last_rip[MAX_VCPUS];
#ifndef WVM_TCG_FORCE_LOCAL_DUTY_N
#define WVM_TCG_FORCE_LOCAL_DUTY_N 6
#endif
/* Shared with FE slice_budget_us pairing (see wavevm_tcg_slice_budget_us). */
static int g_wavevm_tcg_spin_count[MAX_VCPUS];

static void wavevm_tcg_note_remote_done(CPUState *cpu)
{
    int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
    uint64_t n = ++g_wavevm_tcg_remote_done[ci];

    /* s23g6: denser cadence so smoke-window G9 sees progress (was <=8|%64,
     * which hid honest remotes 9..63 as remote_done_delta=0). */
    if ((n <= 32) || (n % 16) == 0) {
        fprintf(stderr,
                "[WVM-TCG-STATS] cpu=%d remote_done=%llu local_done=%llu "
                "force_local_used=%llu\n",
                cpu->cpu_index,
                (unsigned long long)g_wavevm_tcg_remote_done[ci],
                (unsigned long long)g_wavevm_tcg_local_done[ci],
                (unsigned long long)g_wavevm_tcg_force_local_used[ci]);
    }
}

static void wavevm_tcg_note_local_done(CPUState *cpu)
{
    int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
    uint64_t n = ++g_wavevm_tcg_local_done[ci];

    if ((n <= 4) || (n % 256) == 0) {
        fprintf(stderr,
                "[WVM-TCG-STATS] cpu=%d remote_done=%llu local_done=%llu "
                "force_local_used=%llu\n",
                cpu->cpu_index,
                (unsigned long long)g_wavevm_tcg_remote_done[ci],
                (unsigned long long)g_wavevm_tcg_local_done[ci],
                (unsigned long long)g_wavevm_tcg_force_local_used[ci]);
    }
}

static bool wavevm_tcg_prefer_active(void);

static bool wavevm_tcg_has_runnable_local_peer(CPUState *owner);
static bool wavevm_tcg_has_local_peer(CPUState *owner);
static void wavevm_tcg_kick_runnable_local_peers(CPUState *owner);
static void wavevm_tcg_kick_all_local_peers(CPUState *owner);

static int64_t wavevm_tcg_mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}



static void wavevm_tcg_clear_force_local_if_progress(CPUState *cpu)
{
    int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
    uint64_t rip;
    CPUX86State *env;
    int64_t now;
    /* Concurrent spin hold: 30s slice, renew while same RIP, hard cap 90s. */
    const int64_t hold_slice_ns = 8000000000LL;  /* s23g6: was 30s */
    const int64_t hold_max_ns = 30000000000LL; /* s23g6: was 90s */

    now = wavevm_tcg_mono_ns();
    /* Expire concurrent wall-clock hold; RIP wobble must not clear it early. */
    if (g_wavevm_tcg_force_local_hold[ci]) {
        if (g_wavevm_tcg_force_local_hold_until_ns[ci] != 0 &&
            now >= g_wavevm_tcg_force_local_hold_until_ns[ci]) {
            env = &X86_CPU(cpu)->env;
            rip = env->eip;
            /*
             * g3g9m: 5s hold reached login but e1000 Reset @guest~63s once
             * hold expired mid-softlock (remote_spin_backoff only runs on
             * remote ACK, so hold was not renewed while AP was local).
             * Renew while still on the armed RIP (or spin still elevated),
             * capped from first arm — not a boot-duration sticky.
             */
            if (g_wavevm_tcg_force_local_hold_armed_ns[ci] != 0 &&
                (now - g_wavevm_tcg_force_local_hold_armed_ns[ci]) < hold_max_ns &&
                (rip == g_wavevm_tcg_force_local_rip[ci] ||
                 g_wavevm_tcg_spin_count[ci] >= 4)) {
                int64_t renew = now + hold_slice_ns;
                int64_t cap = g_wavevm_tcg_force_local_hold_armed_ns[ci] +
                              hold_max_ns;
                if (renew > cap) {
                    renew = cap;
                }
                if (renew > now) {
                    g_wavevm_tcg_force_local_hold_until_ns[ci] = renew;
                    fprintf(stderr,
                            "[WVM-TCG-FORCE-LOCAL] event=renew cpu=%d rip=%#llx "
                            "slice_ms=8000 remaining_cap_ms=%lld "
                            "armed_age_ms=%lld\n",
                            cpu->cpu_index, (unsigned long long)rip,
                            (long long)((cap - now) / 1000000LL),
                            (long long)((now -
                                g_wavevm_tcg_force_local_hold_armed_ns[ci]) /
                                1000000LL));
                    return;
                }
            }
            g_wavevm_tcg_force_local_hold[ci] = false;
            g_wavevm_tcg_force_local_hold_until_ns[ci] = 0;
            g_wavevm_tcg_force_local_hold_armed_ns[ci] = 0;
            g_wavevm_tcg_force_local_hold_ticks[ci] = 0;
            g_wavevm_tcg_need_local_repeat[ci] = 0;
            g_wavevm_tcg_need_local_last_rip[ci] = 0;
            g_wavevm_tcg_force_local[ci] = 0;
            g_wavevm_tcg_force_local_rip[ci] = 0;
            /* Prevent immediate re-arm so G9 can observe remote_done delta. */
            g_wavevm_tcg_spin_count[ci] = 0;
            g_wavevm_tcg_spin_arm_cooldown_until_ns[ci] =
                now + 12000000000LL; /* s23g6: was 25s */
            fprintf(stderr,
                    "[WVM-TCG-FORCE-LOCAL] event=hard_cap_expiry cpu=%d "
                    "rip=%#llx hard_cap_ms=30000 cooldown_ms=12000\n",
                    cpu->cpu_index, (unsigned long long)rip);
        }
        return;
    }
    if (g_wavevm_tcg_force_local[ci] <= 0) {
        return;
    }
    env = &X86_CPU(cpu)->env;
    rip = env->eip;
    if (g_wavevm_tcg_force_local_rip[ci] != 0 &&
        rip != g_wavevm_tcg_force_local_rip[ci]) {
        g_wavevm_tcg_force_local[ci] = 0;
        g_wavevm_tcg_force_local_rip[ci] = 0;
    }
}

static bool wavevm_tcg_force_local_disabled(void)
{
    const char *env = getenv("WVM_TCG_DISABLE_FORCE_LOCAL");
    return env && env[0] != '\0' && env[0] != '0';
}

/*
 * Remote TCG hit device MMIO/PIO on a -nodefaults helper. Run a short burst of
 * local cpu_exec so FE device models complete the access, then resume remote.
 * Budget clears on RIP progress — not a boot-duration sticky.
 */
static void wavevm_tcg_arm_need_local(CPUState *cpu, uint64_t rip)
{
    int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
    const int budget = 128;
    static unsigned log_count;

    if (wavevm_tcg_force_local_disabled()) {
        if (log_count++ < 32) {
            fprintf(stderr,
                    "[WVM-TCG-NEED-LOCAL] cpu=%d rip=%#llx FORCE_LOCAL disabled; "
                    "device bounce unavailable\n",
                    cpu->cpu_index, (unsigned long long)rip);
        }
        return;
    }
    /*
     * Count consecutive NEED_LOCAL on the same RIP even when prior budget was
     * cleared by clear_if_progress after a single local slice (device loop).
     */
    if (g_wavevm_tcg_need_local_last_rip[ci] == rip) {
        g_wavevm_tcg_need_local_repeat[ci]++;
    } else {
        g_wavevm_tcg_need_local_repeat[ci] = 1;
        g_wavevm_tcg_need_local_last_rip[ci] = rip;
    }
    if (g_wavevm_tcg_force_local[ci] < budget) {
        g_wavevm_tcg_force_local[ci] = budget;
    }
    g_wavevm_tcg_force_local_rip[ci] = rip;
    /*
     * Repeated NEED_LOCAL on the same RIP means device-bounce thrash: escalate
     * to a short wall hold (still duty-cycled; still bounded by 90s cap).
     */
    if (g_wavevm_tcg_need_local_repeat[ci] >= 2) {
        int64_t now_arm = wavevm_tcg_mono_ns();
        int64_t hold_until = now_arm + 4000000000LL; /* s23g6: was 10s */
        const int64_t hold_max_ns = 30000000000LL; /* s23g6: was 90s */
        if (!g_wavevm_tcg_force_local_hold[ci] ||
            g_wavevm_tcg_force_local_hold_armed_ns[ci] == 0) {
            g_wavevm_tcg_force_local_hold_armed_ns[ci] = now_arm;
            g_wavevm_tcg_force_local_hold_ticks[ci] = 0;
        }
        g_wavevm_tcg_force_local_hold[ci] = true;
        {
            int64_t cap = g_wavevm_tcg_force_local_hold_armed_ns[ci] + hold_max_ns;
            if (hold_until > cap) {
                hold_until = cap;
            }
        }
        if (hold_until > g_wavevm_tcg_force_local_hold_until_ns[ci]) {
            g_wavevm_tcg_force_local_hold_until_ns[ci] = hold_until;
        }
    }
    if (log_count++ < 64) {
        fprintf(stderr,
                "[WVM-TCG-NEED-LOCAL] cpu=%d rip=%#llx arm force_local=%d "
                "repeat=%d hold=%d\n",
                cpu->cpu_index, (unsigned long long)rip,
                g_wavevm_tcg_force_local[ci],
                g_wavevm_tcg_need_local_repeat[ci],
                g_wavevm_tcg_force_local_hold[ci] ? 1 : 0);
    }
}

/*
 * FE→helper STW pairing: ask helper for a shorter cpu_exec quantum when the
 * master needs BSP airtime. 0 lets helper pick its default (SHM vs UDP).
 * This compresses remote_active hold time during blocking ACK wait — the
 * actual mutual-starve window — without enabling unsafe SHM concurrency.
 */
static uint32_t wavevm_tcg_slice_budget_us(CPUState *cpu)
{
    int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
    int spin = g_wavevm_tcg_spin_count[ci];

    if (wavevm_tcg_shm_allow_concurrent()) {
        /*
         * Concurrent: no STW. Helper default ~50ms is OK in steady state
         * (g3g9e: always-10ms thrash-hung AP). Under same-RIP spin or an
         * armed NEED_LOCAL/force budget, shrink the quantum so IPIs and the
         * next force_local consume land sooner — not a boot sticky.
         */
        if (g_wavevm_tcg_force_local[ci] > 0 || spin >= 8) {
            return 5000;
        }
        if (spin >= 4) {
            return 10000;
        }
        return 0;
    }
    /*
     * G3: when a local peer exists, always compress remote_active hold so
     * FE/device progress is not starved by 50ms remote slices — without
     * rewriting admitted remote placement via boot-duration force_local.
     */
    if (wavevm_tcg_has_local_peer(cpu)) {
        if (spin >= 8 || wavevm_tcg_prefer_active()) {
            return 3000;
        }
        if (spin >= 4 || g_wavevm_tcg_force_local[ci] > 0) {
            return 5000;
        }
        return 8000;
    }
    if (spin >= 8) {
        return 5000;
    }
    if (spin >= 4 || wavevm_tcg_prefer_active() ||
        g_wavevm_tcg_force_local[ci] > 0 ||
        (g_wavevm_tcg_short_budget_until_ns != 0 &&
         wavevm_tcg_mono_ns() < g_wavevm_tcg_short_budget_until_ns)) {
        return 8000;
    }
    if (spin >= 2) {
        return 12000;
    }
    return 0;
}

static bool wavevm_tcg_consume_force_local(CPUState *cpu)
{
    int ci;
    bool divert;

    if (wavevm_tcg_force_local_disabled()) {
        return false;
    }
    ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
    /*
     * NEED_LOCAL device bounce + concurrent same-RIP spin hold.
     * Hold is exceptional softlock coverage (vcpu-handoff §8.1): keep mostly
     * local for interleaving, but duty-cycle remote probes so remote_done
     * advances and force_local does not dominate the main concurrent path.
     * force_local_used counts only actual remote→local diversions.
     */
    /* Mirror remote_rpc_policy without depending on ops (declared later). */
    divert = (cpu->cpu_index >= g_wvm_local_split);
    if (g_wavevm_tcg_force_local_hold[ci]) {
        int64_t now = wavevm_tcg_mono_ns();
        const int64_t hold_slice_ns = 8000000000LL;  /* s23g6: was 30s */
        const int64_t hold_max_ns = 30000000000LL; /* s23g6: was 90s */
        if (g_wavevm_tcg_force_local_hold_until_ns[ci] == 0 ||
            now < g_wavevm_tcg_force_local_hold_until_ns[ci]) {
            /*
             * Exceptional softlock hold (§8.1): stay fully local for the
             * bounded window. Duty-cycle remote probes during an active
             * softlock re-break IPI/sync (PASS evidence: one 30s hold →
             * boot; duty mid-hold → virtio freeze). Remote resumes after
             * hard_cap/cooldown — concurrency remains the normal path.
             */
            g_wavevm_tcg_force_local_hold_ticks[ci]++;
            if (divert) {
                g_wavevm_tcg_force_local_used[ci]++;
            }
            return true;
        }
        /*
         * Same renew as clear_if_progress: consume is the hot path while AP
         * is local, so it must renew or 30s hard-drops mid-softlock (g3g9n).
         */
        {
            CPUX86State *env = &X86_CPU(cpu)->env;
            uint64_t rip = env->eip;
            if (g_wavevm_tcg_force_local_hold_armed_ns[ci] != 0 &&
                (now - g_wavevm_tcg_force_local_hold_armed_ns[ci]) < hold_max_ns &&
                (rip == g_wavevm_tcg_force_local_rip[ci] ||
                 g_wavevm_tcg_spin_count[ci] >= 4)) {
                int64_t renew = now + hold_slice_ns;
                int64_t cap = g_wavevm_tcg_force_local_hold_armed_ns[ci] +
                              hold_max_ns;
                if (renew > cap) {
                    renew = cap;
                }
                if (renew > now) {
                    g_wavevm_tcg_force_local_hold_until_ns[ci] = renew;
                    g_wavevm_tcg_force_local_hold_ticks[ci]++;
                    if (divert) {
                        g_wavevm_tcg_force_local_used[ci]++;
                    }
                    fprintf(stderr,
                            "[WVM-TCG-FORCE-LOCAL] event=renew cpu=%d rip=%#llx "
                            "slice_ms=8000 remaining_cap_ms=%lld "
                            "armed_age_ms=%lld\n",
                            cpu->cpu_index, (unsigned long long)rip,
                            (long long)((cap - now) / 1000000LL),
                            (long long)((now -
                                g_wavevm_tcg_force_local_hold_armed_ns[ci]) /
                                1000000LL));
                    return true;
                }
            }
        }
        g_wavevm_tcg_force_local_hold[ci] = false;
        g_wavevm_tcg_force_local_hold_until_ns[ci] = 0;
        g_wavevm_tcg_force_local_hold_armed_ns[ci] = 0;
        g_wavevm_tcg_force_local_hold_ticks[ci] = 0;
        g_wavevm_tcg_need_local_repeat[ci] = 0;
        g_wavevm_tcg_need_local_last_rip[ci] = 0;
        g_wavevm_tcg_force_local[ci] = 0;
        g_wavevm_tcg_force_local_rip[ci] = 0;
        g_wavevm_tcg_spin_count[ci] = 0;
        g_wavevm_tcg_spin_arm_cooldown_until_ns[ci] =
            now + 12000000000LL; /* s23g6: was 25s */
        fprintf(stderr,
                "[WVM-TCG-FORCE-LOCAL] event=hard_cap_expiry cpu=%d "
                "hard_cap_ms=30000 cooldown_ms=12000\n",
                cpu->cpu_index);
    }
    if (g_wavevm_tcg_force_local[ci] <= 0) {
        return false;
    }
    g_wavevm_tcg_force_local[ci]--;
    if (divert) {
        g_wavevm_tcg_force_local_used[ci]++;
    }
    return true;
}

static bool wavevm_tcg_prefer_active(void)
{
    if (g_wavevm_tcg_local_prefer > 0) {
        return true;
    }
    if (g_wavevm_tcg_local_prefer_until_ns != 0 &&
        wavevm_tcg_mono_ns() < g_wavevm_tcg_local_prefer_until_ns) {
        return true;
    }
    return false;
}

static void wavevm_tcg_local_slice_enter(void)
{
    qemu_mutex_lock(&g_wavevm_tcg_slice_lock);
    /*
     * Default (incl. SHM-coherent join): stop-the-world around remote slices.
     * Only WVM_TCG_SHM_CONCURRENT=1 allows BSP to keep running during remote AP
     * (experimental; see attach18 Cirros corruption under concurrent SHM).
     */
    if (!wavevm_tcg_shm_allow_concurrent()) {
        while (g_wavevm_tcg_remote_pending || g_wavevm_tcg_remote_active) {
            qemu_cond_wait(&g_wavevm_tcg_slice_cond, &g_wavevm_tcg_slice_lock);
        }
    }
    g_wavevm_tcg_local_active++;
    if (g_wavevm_tcg_local_handoff) {
        g_wavevm_tcg_local_handoff = false;
        qemu_cond_broadcast(&g_wavevm_tcg_slice_cond);
    }
    qemu_mutex_unlock(&g_wavevm_tcg_slice_lock);
}

static void wavevm_tcg_local_slice_leave(void)
{
    qemu_mutex_lock(&g_wavevm_tcg_slice_lock);
    if (g_wavevm_tcg_local_active > 0) {
        g_wavevm_tcg_local_active--;
    }
    if (g_wavevm_tcg_local_active == 0) {
        /*
         * Drain prefer-local budget one completed local slice at a time so
         * remote_slice_enter keeps seeing local_handoff until BSP has run
         * several quanta (see wavevm_tcg_remote_spin_backoff).
         * If slice count hits 0 but wall-clock floor remains, keep handoff
         * so remote cannot reclaim until the deadline (attach25).
         */
        if (g_wavevm_tcg_local_prefer > 0) {
            g_wavevm_tcg_local_prefer--;
        }
        if (g_wavevm_tcg_local_prefer > 0) {
            g_wavevm_tcg_local_handoff = true;
        } else if (g_wavevm_tcg_local_prefer_until_ns != 0 &&
                   wavevm_tcg_mono_ns() < g_wavevm_tcg_local_prefer_until_ns) {
            g_wavevm_tcg_local_prefer = 1;
            g_wavevm_tcg_local_handoff = true;
        } else {
            g_wavevm_tcg_local_prefer_until_ns = 0;
        }
        qemu_cond_broadcast(&g_wavevm_tcg_slice_cond);
    }
    qemu_mutex_unlock(&g_wavevm_tcg_slice_lock);
}

static void wavevm_tcg_remote_slice_enter(CPUState *owner)
{
    CPUState *cpu;

    qemu_mutex_lock(&g_wavevm_tcg_slice_lock);
    if (wavevm_tcg_shm_allow_concurrent()) {
        /*
         * Experimental: SHM-visible RAM + concurrent BSP while remote AP runs.
         * Default path falls through to stop-the-world below.
         */
        while (g_wavevm_tcg_remote_active) {
            qemu_cond_wait(&g_wavevm_tcg_slice_cond, &g_wavevm_tcg_slice_lock);
        }
        g_wavevm_tcg_remote_active = true;
        g_wavevm_tcg_remote_pending = false;
        g_wavevm_tcg_local_handoff = false;
        qemu_mutex_unlock(&g_wavevm_tcg_slice_lock);
        return;
    }
    /*
     * A remote slice must not immediately reclaim execution after it returns:
     * the local peer may be required to release a guest lock observed by the
     * remote vCPU.  Leave remote_pending clear while waiting so that peer can
     * enter cpu_exec().
     *
     * attach24/25: when prefer is set but BSP is HLT/idle, do NOT drop prefer
     * immediately — kick (and clear HLT) so BSP can make progress. Only drop
     * after wake attempts + wall-clock deadline expire.
     */
    {
        int idle_wake = 0;
        for (;;) {
            bool prefer = wavevm_tcg_prefer_active();
            bool peer_run = wavevm_tcg_has_runnable_local_peer(owner);
            bool need_wait = g_wavevm_tcg_remote_active ||
                             g_wavevm_tcg_local_active > 0 ||
                             ((g_wavevm_tcg_local_handoff || prefer) && peer_run);
            if (!need_wait) {
                if (prefer && !peer_run &&
                    wavevm_tcg_has_local_peer(owner) && idle_wake < 24) {
                    qemu_mutex_unlock(&g_wavevm_tcg_slice_lock);
                    wavevm_tcg_kick_all_local_peers(owner);
                    g_usleep(1000);
                    qemu_mutex_lock(&g_wavevm_tcg_slice_lock);
                    idle_wake++;
                    continue;
                }
                break;
            }
            qemu_cond_timedwait(&g_wavevm_tcg_slice_cond,
                                &g_wavevm_tcg_slice_lock, 5);
        }
    }
    if (g_wavevm_tcg_local_handoff) {
        g_wavevm_tcg_local_handoff = false;
    }
    /* Drop prefer only when peer still idle AND wall-clock floor expired. */
    if (wavevm_tcg_prefer_active() &&
        !wavevm_tcg_has_runnable_local_peer(owner) &&
        (g_wavevm_tcg_local_prefer_until_ns == 0 ||
         wavevm_tcg_mono_ns() >= g_wavevm_tcg_local_prefer_until_ns)) {
        g_wavevm_tcg_local_prefer = 0;
        g_wavevm_tcg_local_prefer_until_ns = 0;
    }
    g_wavevm_tcg_remote_pending = true;
    /*
     * Do not wait indefinitely for a local TCG vCPU that is spinning on a
     * lock held by the remote vCPU.  This matches MTTCG's normal atomic
     * rendezvous: request a boundary from active peers, then wait until they
     * have left cpu_exec() before handing the authoritative RAM view remote.
     */
    CPU_FOREACH(cpu) {
        if (cpu != owner && !cpu->unplug) {
            cpu_exit(cpu);
        }
    }
    while (g_wavevm_tcg_local_active > 0 || g_wavevm_tcg_remote_active) {
        qemu_cond_wait(&g_wavevm_tcg_slice_cond, &g_wavevm_tcg_slice_lock);
    }
    g_wavevm_tcg_remote_active = true;
    g_wavevm_tcg_remote_pending = false;
    qemu_mutex_unlock(&g_wavevm_tcg_slice_lock);
}

static void wavevm_tcg_remote_slice_leave(CPUState *owner)
{
    bool handoff_local;

    qemu_mutex_lock(&g_wavevm_tcg_slice_lock);
    g_wavevm_tcg_remote_active = false;
    handoff_local = wavevm_tcg_has_runnable_local_peer(owner);
    g_wavevm_tcg_local_handoff = handoff_local;
    qemu_cond_broadcast(&g_wavevm_tcg_slice_cond);
    qemu_mutex_unlock(&g_wavevm_tcg_slice_lock);

    /*
     * Local vCPU threads can be asleep in qemu_wait_io_event().  The private
     * slice condition is not enough to wake them, so use QEMU's normal kick
     * path.  The local entry path clears the deliberate exit latch before it
     * re-enters cpu_exec().
    */
    if (handoff_local || wavevm_tcg_prefer_active()) {
        wavevm_tcg_kick_all_local_peers(owner);
    }
}

/*
 * STW remote same-RIP spin → prefer local BSP for several slices + wall clock.
 * attach19 PASS max same-RIP run≈8; attach23 FAIL run≈30 @...8a62a7 then
 * e1000 Tx Hang. attach25: prefer=4/8/12 by slice count alone did not stop
 * spin (HLT/idle drains). Lower threshold, stronger budget, MONOTONIC floor;
 * when peer !runnable kick/clear HLT instead of dropping prefer.
 */
static void wavevm_tcg_remote_spin_backoff(CPUState *cpu, uint64_t ack_eip)
{
    static uint64_t last_eip[MAX_VCPUS];
    static unsigned concurrent_force_log;
    int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
    int prefer;
    int hold_ms;
    int64_t until;
    int *spin_count = g_wavevm_tcg_spin_count;
    bool concurrent = wavevm_tcg_shm_allow_concurrent();

    if (ack_eip == 0) {
        return;
    }
    if (ack_eip == last_eip[ci]) {
        spin_count[ci]++;
    } else {
        spin_count[ci] = 1;
        last_eip[ci] = ack_eip;
        /*
         * G3: on RIP change decay residual *spin* force_local. Do NOT clear
         * a budget just armed for this ack_eip (NEED_LOCAL runs before
         * spin_backoff on the same ACK — clearing it here aborted every
         * device-bounce local burst and left repeat stuck at 1).
         * Keep concurrent wall hold across wobble.
         */
        if (!g_wavevm_tcg_force_local_hold[ci] &&
            g_wavevm_tcg_force_local[ci] > 0 &&
            g_wavevm_tcg_force_local_rip[ci] != ack_eip) {
            g_wavevm_tcg_force_local[ci] = 0;
            g_wavevm_tcg_force_local_rip[ci] = 0;
        }
        return;
    }
    /* Earlier than attach19 max-run 8 so BSP gets the lock before freeze. */
    if (spin_count[ci] < 4) {
        return;
    }

    /*
     * Concurrent path (g3g9i): prefer-local cannot pull a remote AP onto FE
     * (remote_slice_enter bypasses prefer). PnP freeze was same-RIP softlock
     * with force_local_used=0 / almost no NEED_LOCAL — guest spinning in RAM
     * waiting on BSP/AP sync, not MMIO/PIO. Arm a bounded per-vCPU local
     * burst on the spinning AP only; RIP progress clears it. Not sticky.
     */
    if (concurrent) {
        /*
         * Minimum §8.1: concurrent remains MAIN. Medium spin → short
         * NEED_LOCAL-style budget only (clears on RIP progress). Wall hold
         * (30s/90s/25s) only at high spin — exceptional softlock coverage.
         */
        /*
         * Cooldown after hard_cap exists so a recovered guest can show remote
         * progress (G9). It must NOT suppress re-arm while the AP is still
         * softlocked (same-RIP spin>=4). Fractal hung evidence: hard_cap →
         * cooldown_suppress spin=4..24 with serial frozen at network/metadata.
         */
        if (!wavevm_tcg_force_local_disabled() && spin_count[ci] >= 4) {
            int64_t now_arm = wavevm_tcg_mono_ns();
            if (g_wavevm_tcg_spin_arm_cooldown_until_ns[ci] != 0 &&
                now_arm < g_wavevm_tcg_spin_arm_cooldown_until_ns[ci]) {
                static int cooldown_lift_log;
                int64_t left = g_wavevm_tcg_spin_arm_cooldown_until_ns[ci] - now_arm;
                g_wavevm_tcg_spin_arm_cooldown_until_ns[ci] = 0;
                if (cooldown_lift_log++ < 32) {
                    fprintf(stderr,
                            "[WVM-TCG-FORCE-LOCAL] event=cooldown_lift_softlock "
                            "cpu=%d spin=%d cleared_remaining_ms=%lld\n",
                            cpu->cpu_index, spin_count[ci],
                            (long long)(left / 1000000LL));
                }
            }
            {
            /* s23g: medium spin (>=4) → short RIP-cleared budget only.
             * Wall hold (30s/90s/25s) only at high spin (>=8) — matches §8.1
             * comment and reduces force_local softlock-window dominance. */
            int force = 32;
            if (spin_count[ci] >= 8) {
                force = 64;
            }
            if (spin_count[ci] >= 16) {
                force = 128;
            }
            g_wavevm_tcg_force_local[ci] = force;
            g_wavevm_tcg_force_local_rip[ci] = ack_eip;
            if (spin_count[ci] >= 8) {
                /*
                 * Exceptional softlock hold (§8.1): full-local for bounded slice.
                 * Mid-hold remote duty re-broke virtio (flat hung evidence);
                 * concurrency resumes after hard_cap/cooldown when spin clears.
                 */
                int64_t hold_until = now_arm + 8000000000LL; /* s23g6: was 30s */
                const int64_t hold_max_ns = 30000000000LL; /* s23g6: was 90s */
                if (!g_wavevm_tcg_force_local_hold[ci] ||
                    g_wavevm_tcg_force_local_hold_armed_ns[ci] == 0) {
                    g_wavevm_tcg_force_local_hold_armed_ns[ci] = now_arm;
                    g_wavevm_tcg_force_local_hold_ticks[ci] = 0;
                }
                g_wavevm_tcg_force_local_hold[ci] = true;
                {
                    int64_t cap = g_wavevm_tcg_force_local_hold_armed_ns[ci] +
                                  hold_max_ns;
                    if (hold_until > cap) {
                        hold_until = cap;
                    }
                }
                if (hold_until > g_wavevm_tcg_force_local_hold_until_ns[ci]) {
                    g_wavevm_tcg_force_local_hold_until_ns[ci] = hold_until;
                }
                if (concurrent_force_log++ < 64) {
                    fprintf(stderr,
                            "[WVM-TCG-SPIN-LOCAL] concurrent cpu=%d rip=%#llx "
                            "spin=%d arm force_local=%d hold_ms=8000 "
                            "hold_full_local=1\n",
                            cpu->cpu_index, (unsigned long long)ack_eip,
                            spin_count[ci], force);
                }
            } else if (concurrent_force_log++ < 64) {
                fprintf(stderr,
                        "[WVM-TCG-SPIN-LOCAL] concurrent cpu=%d rip=%#llx "
                        "spin=%d arm force_local=%d hold_full_local=0 "
                        "(short budget only)\n",
                        cpu->cpu_index, (unsigned long long)ack_eip,
                        spin_count[ci], force);
            }
            }
        }
        return;
    }

    prefer = 16;
    hold_ms = 80;
    if (spin_count[ci] >= 8) {
        prefer = 32;
        hold_ms = 160;
    }
    if (spin_count[ci] >= 16) {
        prefer = 48;
        hold_ms = 320;
    }
    until = wavevm_tcg_mono_ns() + (int64_t)hold_ms * 1000000LL;
    /*
     * STW: prefer-local holds remote reclaim without rewriting placement.
     * force_local only at extreme spin (>=16) with tiny budget — never a
     * boot-duration / all-vCPU sticky window.
     */
    if (!wavevm_tcg_force_local_disabled() && spin_count[ci] >= 16) {
        int force = 8;
        if (spin_count[ci] >= 32) {
            force = 16;
        }
        if (g_wavevm_tcg_force_local[ci] < force) {
            g_wavevm_tcg_force_local[ci] = force;
        }
        g_wavevm_tcg_force_local_rip[ci] = ack_eip;
    }
    qemu_mutex_lock(&g_wavevm_tcg_slice_lock);
    if (g_wavevm_tcg_local_prefer < prefer) {
        g_wavevm_tcg_local_prefer = prefer;
    }
    if (until > g_wavevm_tcg_local_prefer_until_ns) {
        g_wavevm_tcg_local_prefer_until_ns = until;
    }
    /* Brief short-quantum window only (not boot-duration force_local). */
    {
        int64_t short_until = wavevm_tcg_mono_ns() + 250000000LL;
        if (short_until > g_wavevm_tcg_short_budget_until_ns) {
            g_wavevm_tcg_short_budget_until_ns = short_until;
        }
    }
    g_wavevm_tcg_local_handoff = true;
    qemu_cond_broadcast(&g_wavevm_tcg_slice_cond);
    qemu_mutex_unlock(&g_wavevm_tcg_slice_lock);
    {
        static unsigned int log_count;
        if (log_count++ < 24) {
            fprintf(stderr,
                    "[WVM-TCG-STW] cpu=%d prefer-local rip=%#llx spin=%d "
                    "prefer=%d hold_ms=%d force_local=%d\n",
                    cpu->cpu_index, (unsigned long long)ack_eip,
                    spin_count[ci], prefer, hold_ms,
                    g_wavevm_tcg_force_local[ci]);
        }
    }
    wavevm_tcg_kick_all_local_peers(cpu);
}

static void wavevm_tcg_clear_stale_exit(CPUState *cpu)
{
    /*
     * WaveVM deliberately kicks TCG slices out at handoff boundaries.  Before
     * re-entering local TCG, clear only the stale exit latch; real interrupt
     * bits stay in interrupt_request and are still consumed by cpu_exec().
     */
    qatomic_mb_set(&cpu->exit_request, 0);
    if (cpu->icount_decr_ptr) {
        qatomic_mb_set(&cpu->icount_decr_ptr->u16.high, 0);
    }
}

static void wavevm_init_tcg_region_once(void)
{
    /* Enable MTTCG-style region allocation so each vCPU thread gets its
     * own code-gen region.  Without this, tcg_n_regions() returns 1 and
     * only one thread can tcg_register_thread() without asserting.
     *
     * tcg_n_regions() checks mttcg_enabled (not parallel_cpus), so we
     * must set the correct global.  parallel_cpus is also needed for
     * some TCG code-path decisions. */
    extern bool mttcg_enabled;
    extern bool parallel_cpus;
    mttcg_enabled = true;
    parallel_cpus = true;
    qemu_mutex_init(&g_wavevm_tcg_slice_lock);
    qemu_cond_init(&g_wavevm_tcg_slice_cond);
    tcg_region_init();
}

struct wavevm_policy_ops {
    int (*schedule_policy)(int cpu_index);
};

// [Policy] Tiered Scheduling: Local vs Remote
static int remote_rpc_policy(int cpu_index) {
    //不再使用 WVM_LOCAL_CPU_COUNT 宏，而是使用动态变量
    if (cpu_index >= g_wvm_local_split) return 1; // 远程执行
    return 0; // 本地执行
}

static struct wavevm_policy_ops ops = { .schedule_policy = remote_rpc_policy };

static bool wavevm_tcg_has_runnable_local_peer(CPUState *owner)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        if (cpu != owner && !cpu->unplug &&
            ops.schedule_policy(cpu->cpu_index) == 0 && cpu_can_run(cpu)) {
            return true;
        }
    }
    return false;
}

static bool wavevm_tcg_has_local_peer(CPUState *owner)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        if (cpu != owner && !cpu->unplug &&
            ops.schedule_policy(cpu->cpu_index) == 0) {
            return true;
        }
    }
    return false;
}

static void wavevm_tcg_kick_runnable_local_peers(CPUState *owner)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        if (cpu != owner && !cpu->unplug &&
            ops.schedule_policy(cpu->cpu_index) == 0 && cpu_can_run(cpu)) {
            qemu_cpu_kick(cpu);
        }
    }
}

/*
 * Prefer-local wake: kick every local peer, including HLT/idle.
 * Clearing halted lets the thread leave qemu_wait_io_event and enter a
 * local slice; guest idle loops re-HLT harmlessly. Without this, prefer
 * is drained by EXCP_HALTED no-ops or dropped while BSP sleeps (attach25).
 */
static void wavevm_tcg_kick_all_local_peers(CPUState *owner)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        if (cpu == owner || cpu->unplug) {
            continue;
        }
        if (ops.schedule_policy(cpu->cpu_index) != 0) {
            continue;
        }
        if (cpu->halted) {
            cpu->halted = 0;
        }
        cpu_exit(cpu);
        qemu_cpu_kick(cpu);
    }
}

static bool wavevm_valid_io_exit(const struct kvm_run *run)
{
    if (run->io.size != 1 && run->io.size != 2 &&
        run->io.size != 4 && run->io.size != 8) {
        return false;
    }
    if (run->io.count == 0 || run->io.count > 8) {
        return false;
    }
    return true;
}

static bool wavevm_valid_mmio_exit(const struct kvm_run *run)
{
    return run->mmio.len == 1 || run->mmio.len == 2 ||
           run->mmio.len == 4 || run->mmio.len == 8;
}

static inline uint32_t wavevm_lapic_reg32(const struct kvm_lapic_state *lapic, uint32_t off)
{
    uint32_t v = 0;
    if (off + sizeof(v) <= sizeof(lapic->regs)) {
        memcpy(&v, &lapic->regs[off], sizeof(v));
    }
    return v;
}

/* Apply remote KVM LAPIC MMIO against FE in-kernel LAPIC (KVM_GET/SET_LAPIC).
 * address_space_rw cannot program kernel irqchip LAPIC. Returns true if
 * handled (caller must skip generic MMIO replay). */
static bool wavevm_kvm_apply_remote_lapic_mmio(CPUState *cpu,
                                              wvm_kvm_context_t *kctx,
                                              struct kvm_run *run)
{
    hwaddr addr;
    uint32_t off;
    unsigned len;
    struct kvm_lapic_state klapic;
    static int lapic_mmio_dbg;

    if (!kctx || cpu->kvm_fd < 0) {
        return false;
    }
    addr = kctx->mmio.phys_addr;
    if (addr < 0xfee00000ULL || addr >= 0xfee01000ULL) {
        return false;
    }
    off = (uint32_t)(addr - 0xfee00000ULL);
    len = kctx->mmio.len;
    if (len != 1 && len != 2 && len != 4 && len != 8) {
        return false;
    }
    if (ioctl(cpu->kvm_fd, KVM_GET_LAPIC, &klapic) < 0) {
        return false;
    }
    if (kctx->mmio.is_write) {
        if (off + len > sizeof(klapic.regs)) {
            return false;
        }
        memcpy(&klapic.regs[off], kctx->mmio.data, len);
        if (ioctl(cpu->kvm_fd, KVM_SET_LAPIC, &klapic) < 0) {
            return false;
        }
        if (lapic_mmio_dbg++ < 64) {
            fprintf(stderr,
                    "[WVM-LAPIC-MMIO] cpu=%d WR off=0x%03x len=%u data0=0x%02x\n",
                    cpu->cpu_index, off, len, kctx->mmio.data[0]);
        }
    } else {
        uint8_t buf[8];
        memset(buf, 0, sizeof(buf));
        if (off + len <= sizeof(klapic.regs)) {
            memcpy(buf, &klapic.regs[off], len);
        }
        memcpy(kctx->mmio.data, buf, 8);
        if (run) {
            memcpy(run->mmio.data, buf, 8);
            run->mmio.phys_addr = addr;
            run->mmio.len = len;
            run->mmio.is_write = 0;
        }
        if (lapic_mmio_dbg++ < 64) {
            fprintf(stderr,
                    "[WVM-LAPIC-MMIO] cpu=%d RD off=0x%03x len=%u val0=0x%02x\n",
                    cpu->cpu_index, off, len, buf[0]);
        }
    }
    if (run) {
        run->exit_reason = KVM_EXIT_MMIO;
        run->mmio.phys_addr = addr;
        run->mmio.len = len;
        run->mmio.is_write = kctx->mmio.is_write;
    }
    return true;
}

/* Keep local APIC/interrupt state and only import architectural sregs fields. */
static void wavevm_apply_arch_sregs(struct kvm_sregs *dst,
                                    const struct kvm_sregs *src)
{
    dst->cs = src->cs;
    dst->ds = src->ds;
    dst->es = src->es;
    dst->fs = src->fs;
    dst->gs = src->gs;
    dst->ss = src->ss;
    dst->tr = src->tr;
    dst->ldt = src->ldt;
    dst->gdt = src->gdt;
    dst->idt = src->idt;
    dst->cr0 = src->cr0;
    dst->cr2 = src->cr2;
    dst->cr3 = src->cr3;
    dst->cr4 = src->cr4;
    dst->cr8 = src->cr8;
    dst->efer = src->efer;
}

/* 
 * [物理意图] 充当远程 Slave 的“本地代理执行人”。
 * [关键逻辑] 当远程计算节点触发 PIO/MMIO 退出时，Master 在本地 QEMU 中代为执行该 I/O 操作并返回结果。
 * [后果] 解决了 I/O 设备物理位置的透明性。它让 Guest 以为显卡就在本地，即便真实的读写指令是在千里之外执行的。
 */
static void wavevm_handle_io(CPUState *cpu) {
    struct kvm_run *run = cpu->kvm_run;
    uint16_t port = run->io.port;
    void *data = (uint8_t *)run + run->io.data_offset;
    int is_write = (run->io.direction == KVM_EXIT_IO_OUT);

    /* [FIX] 处理 string I/O (REP INS/OUTS)：count 可能 > 1，需逐个迭代 */
    for (uint32_t i = 0; i < run->io.count; i++) {
        address_space_rw(&address_space_io, port, MEMTXATTRS_UNSPECIFIED,
                         data, run->io.size, is_write);
        data = (uint8_t *)data + run->io.size;
    }
}

static void wavevm_handle_mmio(CPUState *cpu) {
    struct kvm_run *run = cpu->kvm_run;
    hwaddr addr = run->mmio.phys_addr;
    void *data = run->mmio.data;

    address_space_rw(&address_space_memory, addr, MEMTXATTRS_UNSPECIFIED,
                     data, run->mmio.len,
                     run->mmio.is_write);
}

static void wavevm_tcg_run_local_wake(CPUState *cpu, X86CPU *x86cpu, int ci)
{
    CPUState *cs = CPU(x86cpu);
    static int local_wake_dbg[MAX_VCPUS] = {0};
    int tr = -1;
    int wake_iters = 0;
    int wake_interrupts = 0;
    const int max_wake_iters = 256;
    bool log_wake = local_wake_dbg[ci] < 20;

    if (log_wake) {
        fprintf(stderr,
                "[WVM-TCG-WAKE] cpu=%d local wake exec intreq=0x%x\n",
                cpu->cpu_index, (unsigned)cs->interrupt_request);
        local_wake_dbg[ci]++;
    }

    qemu_mutex_lock_iothread();
    /*
     * This is a master-side TCG entry for a LAPIC/PIC wakeup.  Follow the
     * native TCG event boundaries: an EXCP_INTERRUPT means another vCPU
     * kicked this thread before the guest reached a stable boundary, while
     * EXCP_ATOMIC requires one exclusive step before execution can resume.
     * Retry those events immediately, without a wall-clock kick.  The bound
     * only prevents an unrelated interrupt storm from monopolising this vCPU;
     * it is not part of guest timing or the distributed protocol.
     */
    while (wake_iters < max_wake_iters) {
        cpu->exception_index = -1;
        wavevm_tcg_clear_stale_exit(cpu);
        qemu_mutex_unlock_iothread();
        cpu_exec_start(cpu);
        tr = cpu_exec(cpu);
        cpu_exec_end(cpu);
        qemu_mutex_lock_iothread();
        wake_iters++;

        if (tr == EXCP_ATOMIC) {
            qemu_mutex_unlock_iothread();
            cpu_exec_step_atomic(cpu);
            qemu_mutex_lock_iothread();
            continue;
        }
        if (tr == EXCP_INTERRUPT) {
            wake_interrupts++;
            sched_yield();
            continue;
        }
        if (tr == EXCP_HLT || tr == EXCP_HALTED || cpu->halted) {
            cpu->halted = 1;
            cpu->exception_index = -1;
            break;
        }
        break;
    }
    if (log_wake) {
        CPUX86State *denv = &x86cpu->env;
        uint32_t eflags = cpu_compute_eflags(denv);

        wavevm_tcg_log_stack(cpu, "master-local-wake");
        fprintf(stderr,
                "[WVM-TCG-WAKE] cpu=%d local wake ret=%d iters=%d "
                "interrupts=%d rip=0x%lx cs=0x%x eflags=0x%x "
                "hflags=0x%x hflags2=0x%x halted=%d intreq=0x%x\n",
                cpu->cpu_index, tr, wake_iters, wake_interrupts,
                (unsigned long)denv->eip,
                (unsigned)denv->segs[R_CS].selector,
                (unsigned)eflags,
                (unsigned)denv->hflags,
                (unsigned)denv->hflags2,
                cpu->halted, (unsigned)cs->interrupt_request);
    }
    qemu_mutex_unlock_iothread();
}

static void wavevm_tcg_deliver_init_sipi(CPUState *cpu, X86CPU *x86cpu)
{
    CPUState *cs = CPU(x86cpu);
    bool had_init = cs->interrupt_request & CPU_INTERRUPT_INIT;

    /*
     * do_cpu_init() enters QEMU's resettable API and must be serialized by
     * the iothread mutex.  wavevm_remote_exec() is intentionally called with
     * that mutex unlocked, so the custom TCG SIPI lifecycle has to take it
     * around the INIT+SIPI pair.
     */
    qemu_mutex_lock_iothread();
    if (had_init) {
        do_cpu_init(x86cpu);
    }
    do_cpu_sipi(x86cpu);  /* sets CS:IP, clears CPU_INTERRUPT_SIPI */
    cpu->exception_index = -1;
    qemu_mutex_unlock_iothread();
}

/* 
 * [物理意图] 实现 CPU 核心的“跨物理节点迁移（Context Serialization）”。
 * [关键逻辑] 将 CPU 的全量寄存器状态、MSR 及时钟计数器进行二进制打包，并发射至远程 Slave。
 * [后果] 实现了算力的透明流动。若序列化逻辑不严谨（如漏掉 rflags），远程执行会立即触发 Guest Kernel Panic。
 */
static void wavevm_remote_exec(CPUState *cpu) {
    // 动态边界检查
    if (cpu->cpu_index >= g_configured_vcpus) return;
    if (cpu->cpu_index < MAX_VCPUS) {
        g_wavevm_remote_rpc_ok[cpu->cpu_index] = false;
    }

    /* [FIX] AP vCPU lifecycle gate:
     * 1. APs start UNINITIALIZED → wait (halted) until BSP sends SIPI.
     * 2. KVM handles SIPI atomically: AP goes UNINITIALIZED → RUNNABLE
     *    (we never see the transient SIPI_RECEIVED state).
     * 3. When AP first becomes RUNNABLE, signal caller to do a LOCAL
     *    kvm_cpu_exec() for the BIOS trampoline (increments SMP counter,
     *    then HLTs). This MUST run locally so shared-memory writes are
     *    visible to the BSP.
     * 4. After trampoline HLT, AP stays parked until OS sends IPI.
     * 5. Once ap_did_local_sipi is set, future dispatches go remote. */
    if (kvm_enabled()) {
        struct kvm_mp_state mp;
        int mp_ret = ioctl(cpu->kvm_fd, KVM_GET_MP_STATE, &mp);
        {
            static int mp_dbg[MAX_VCPUS] = {0};
            int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
            if (mp_dbg[ci] < 30) {
                fprintf(stderr, "[WVM-MP] cpu=%d mp_ret=%d mp_state=%d sipi_done=%d\n",
                        cpu->cpu_index, mp_ret,
                        mp_ret == 0 ? mp.mp_state : -1,
                        (cpu->cpu_index < MAX_VCPUS) ? ap_did_local_sipi[cpu->cpu_index] : -1);
                mp_dbg[ci]++;
            }
        }
        if (mp_ret == 0) {
            if (mp.mp_state != KVM_MP_STATE_RUNNABLE) {
                /* AP is HALTED after OS-SIPI completed: Linux scheduler may
                 * send an IPI to wake it. KVM_GET_MP_STATE does NOT process
                 * pending LAPIC events — only KVM_RUN does. So we must do a
                 * real kvm_cpu_exec to let KVM deliver the wake-up IPI. */
                if (mp.mp_state == KVM_MP_STATE_HALTED &&
                    cpu->cpu_index < MAX_VCPUS &&
                    ap_did_os_sipi[cpu->cpu_index]) {
                    bool hlt_pending_irq = ap_hlt_pending_irq[cpu->cpu_index];

                    if (!hlt_pending_irq &&
                        cpu->interrupt_request == 0 &&
                        !cpu_has_work(cpu)) {
                        gint64 now_us = g_get_monotonic_time();
                        gint64 *last_probe = &ap_halt_probe_us[cpu->cpu_index];

                        /* s23g6: was 5s — blocked wake IPI delivery so dual-yes
                         * never scheduled on AP and remote_done stayed soft. */
                        if (*last_probe != 0 && (now_us - *last_probe) < 250000) {  /* s23g7: keep short probe */
                            cpu->halted = 1;
                            return;
                        }
                        *last_probe = now_us;
                    }

                    /* HALT-WAKE: Pipeline #40 approach with critical fix.
                     *
                     * Use full kvm_cpu_exec() with a bounded timer.
                     * CRITICAL: Do NOT set mp_state to HALTED here!
                     * If we force HALTED, KVM puts the AP directly into
                     * vcpu_block. The LAPIC timer was never armed on the
                     * master's KVM (it was armed on the slave during
                     * OS-SIPI), so vcpu_block has no pending interrupt
                     * to wake on. The AP sleeps until SIGUSR1 with
                     * 0 timer ticks -> RCU stall.
                     *
                     * Instead, set RUNNABLE and let the AP execute its
                     * idle loop naturally: HLT instruction -> KVM handles
                     * HLT internally -> vcpu_block -> LAPIC timer fires
                     * -> timer handler re-arms -> HLT -> ... This keeps
                     * timer ticks flowing continuously.
                     */

                    static int halt_wake_dbg[MAX_VCPUS] = {0};
                    int ci = cpu->cpu_index;

                    if (halt_wake_dbg[ci] < 30) {
                        fprintf(stderr, "[WVM-HALT-WAKE] cpu=%d entering "
                                "kvm_cpu_exec (1s timer) mp_in=%d\n",
                                ci, mp.mp_state);
                    }

                    bool had_wake_source = hlt_pending_irq ||
                                            (cpu->interrupt_request != 0 ||
                                             cpu_has_work(cpu));

                    /* Set RUNNABLE so AP executes idle loop naturally.
                     * The idle loop will HLT, and KVM handles that
                     * internally when kvm_halt_in_kernel() is true. */
                    cpu->halted = 0;
                    {
                        X86CPU *x86cpu = X86_CPU(cpu);
                        x86cpu->env.mp_state = KVM_MP_STATE_RUNNABLE;
                    }

                    /* s23g6: bound local HALT-WAKE tightly (was 5s wall).
                     * Long sticky local exec parked the AP, blocked concurrent
                     * remote MAIN under dual-yes, and inflated remote_done via
                     * early-return attribution. s23g7: 1s timer (was 250ms — too short vs
                     * LAPIC fire-rearm; was 5s — blocked wake). 1s balances
                     * softlock vs IPI. Probe stays 250ms. 250ms was enough for one LAPIC
                     * tick / IPI delivery; then re-evaluate remote. */
                    timer_t hw_timer;
                    struct sigevent sev;
                    memset(&sev, 0, sizeof(sev));
                    sev.sigev_notify = SIGEV_THREAD_ID;
                    sev.sigev_signo = SIGUSR1;
                    sev._sigev_un._tid = syscall(SYS_gettid);
                    int timer_ok = (timer_create(CLOCK_MONOTONIC, &sev,
                                                 &hw_timer) == 0);
                    if (timer_ok) {
                        struct itimerspec its = {0};
                        its.it_value.tv_sec = 1; /* s23g7: 1s (was 250ms; was 5s) */
                        its.it_value.tv_nsec = 0;
                        timer_settime(hw_timer, 0, &its, NULL);
                    }

                    /* kvm_cpu_exec expects iothread locked (it unlocks
                     * before KVM_RUN and relocks after). wavevm_remote_exec
                     * is called with iothread UNlocked, so lock here. */
                    qemu_mutex_lock_iothread();
                    int wr = kvm_cpu_exec(cpu);
                    qemu_mutex_unlock_iothread();

                    if (timer_ok) {
                        struct itimerspec its = {0};
                        timer_settime(hw_timer, 0, &its, NULL);
                        timer_delete(hw_timer);
                    }

                    ioctl(cpu->kvm_fd, KVM_GET_MP_STATE, &mp);
                    if (halt_wake_dbg[ci] < 20) {
                        fprintf(stderr, "[WVM-HALT-WAKE] cpu=%d ret=%d "
                                "mp=%d halted=%d irq=0x%x has_work=%d\n",
                                ci, wr, mp.mp_state, cpu->halted,
                                cpu->interrupt_request, cpu_has_work(cpu));
                        halt_wake_dbg[ci]++;
                    }

                    if (mp.mp_state == KVM_MP_STATE_RUNNABLE ||
                        had_wake_source ||
                        (!cpu->halted && mp.mp_state != KVM_MP_STATE_HALTED)) {
                        /* AP was woken by IPI and is doing real work.
                         * Sync state and dispatch to slave. */
                        if (ci < MAX_VCPUS) {
                            ap_hlt_pending_irq[ci] = 0;
                        }
                        cpu->halted = 0;
                        {
                            X86CPU *x86cpu = X86_CPU(cpu);
                            x86cpu->env.mp_state = KVM_MP_STATE_RUNNABLE;
                        }
                        qemu_mutex_lock_iothread();
                        cpu_synchronize_state(cpu);
                        qemu_mutex_unlock_iothread();
                        /* Fall through to remote dispatch */
                    } else {
                        /* AP is still idle (processed timer ticks but no
                         * real work). Return and retry next iteration. */
                        if (ci < MAX_VCPUS) {
                            ap_hlt_pending_irq[ci] = 0;
                        }
                        cpu->halted = 1;
                        return;
                    }
                } else if (mp.mp_state == KVM_MP_STATE_INIT_RECEIVED &&
                           cpu->cpu_index < MAX_VCPUS &&
                           !ap_did_local_sipi[cpu->cpu_index]) {
                    /* BIOS-SIPI delivery fix (V33p):
                     *
                     * KVM_GET_MP_STATE does NOT process pending LAPIC events.
                     * BSP sends INIT+SIPI via LAPIC ICR, KVM queues the SIPI
                     * on this vCPU, but the state won't transition from
                     * INIT_RECEIVED → RUNNABLE until we enter KVM_RUN.
                     *
                     * Without this, the AP polls mp_state forever seeing
                     * INIT_RECEIVED (value 1), never processing the queued
                     * SIPI. This is an intermittent race: sometimes KVM
                     * processes the SIPI before we start polling (and it
                     * works), sometimes it doesn't (and CPU#N hangs).
                     *
                     * Fix: do a bounded KVM_RUN. KVM will wait for SIPI
                     * in INIT_RECEIVED state. When SIPI arrives, the vCPU
                     * transitions to RUNNABLE and starts executing. We use
                     * a 5s timer to avoid blocking forever if SIPI hasn't
                     * been sent yet (early in boot, BSP may not have reached
                     * the AP bringup code). */

                    static int sipi_wait_dbg[MAX_VCPUS] = {0};
                    int ci = cpu->cpu_index;

                    if (sipi_wait_dbg[ci] < 10) {
                        fprintf(stderr, "[WVM-SIPI-WAIT] cpu=%d INIT_RECEIVED, "
                                "entering KVM_RUN for SIPI delivery\n", ci);
                        sipi_wait_dbg[ci]++;
                    }

                    /* Create per-thread timer: 5s to receive SIPI.
                     * If BSP hasn't sent SIPI yet, we'll time out and retry
                     * on the next iteration. */
                    timer_t sipi_wait_timer;
                    struct sigevent sev;
                    memset(&sev, 0, sizeof(sev));
                    sev.sigev_notify = SIGEV_THREAD_ID;
                    sev.sigev_signo = SIGUSR1;
                    sev._sigev_un._tid = syscall(SYS_gettid);
                    int timer_ok = (timer_create(CLOCK_MONOTONIC, &sev,
                                                 &sipi_wait_timer) == 0);
                    if (timer_ok) {
                        struct itimerspec its = {0};
                        its.it_value.tv_sec = 5;
                        timer_settime(sipi_wait_timer, 0, &its, NULL);
                    }

                    /* KVM_RUN in INIT_RECEIVED state: KVM will wait for
                     * SIPI. When SIPI arrives, AP transitions to RUNNABLE
                     * and executes from the SIPI vector address.
                     *
                     * CRITICAL: Do NOT hold the BQL (iothread lock) here.
                     * BSP needs the BQL to execute kvm_cpu_exec() which
                     * sends the SIPI via LAPIC ICR. If we hold BQL while
                     * waiting for SIPI, BSP can't run → SIPI never sent
                     * → 5s timeout → repeat = livelock. */
                    int wr = ioctl(cpu->kvm_fd, KVM_RUN, 0);

                    if (timer_ok) {
                        struct itimerspec its = {0};
                        timer_settime(sipi_wait_timer, 0, &its, NULL);
                        timer_delete(sipi_wait_timer);
                    }

                    /* Re-check mp_state after KVM_RUN */
                    ioctl(cpu->kvm_fd, KVM_GET_MP_STATE, &mp);

                    if (sipi_wait_dbg[ci] < 20) {
                        fprintf(stderr, "[WVM-SIPI-WAIT] cpu=%d KVM_RUN ret=%d "
                                "mp=%d halted=%d\n", ci, wr, mp.mp_state,
                                cpu->halted);
                        sipi_wait_dbg[ci]++;
                    }

                    if (mp.mp_state == KVM_MP_STATE_RUNNABLE) {
                        /* SIPI delivered, AP is executing (trampoline in
                         * progress). Signal caller to run local trampoline
                         * via the existing 0x10003 path. */
                        fprintf(stderr, "[WVM-SIPI-WAIT] cpu=%d SIPI delivered, "
                                "now RUNNABLE\n", ci);
                        cpu->halted = 1;
                        cpu->exception_index = 0x10003;
                        return;
                    } else if (mp.mp_state == KVM_MP_STATE_HALTED) {
                        /* Trampoline already completed inside our KVM_RUN
                         * (SIPI arrived → executed trampoline → HLT).
                         * Mark trampoline done directly — do NOT signal
                         * 0x10003 or the trampoline would run twice. */
                        fprintf(stderr, "[WVM-SIPI-WAIT] cpu=%d trampoline "
                                "completed inside KVM_RUN, marking done\n", ci);
                        ap_did_local_sipi[ci] = 1;
                        cpu->halted = 1;
                        return;
                    }

                    /* SIPI not yet delivered (timer expired, still
                     * INIT_RECEIVED). Park and retry next iteration. */
                    cpu->halted = 1;
                    return;
                } else {
                    /* AP not yet RUNNABLE (UNINITIALIZED or other pre-SIPI state) */
                    cpu->halted = 1;
                    return;
                }
            }
            /* AP is RUNNABLE. Check if trampoline needs to run locally first. */
            if (cpu->cpu_index < MAX_VCPUS &&
                !ap_did_local_sipi[cpu->cpu_index]) {
                fprintf(stderr, "[WVM-SIPI-LOCAL] cpu=%d first RUNNABLE — signaling local trampoline run\n",
                        cpu->cpu_index);
                cpu->halted = 1;
                cpu->exception_index = 0x10003; /* magic: run trampoline locally */
                return;
            }
        } else {
            fprintf(stderr, "[WVM-MP] cpu=%d KVM_GET_MP_STATE failed! errno=%d\n",
                    cpu->cpu_index, errno);
        }
    } else {
        /* ===== TCG mode AP lifecycle gate =====
         * In TCG mode there is no KVM fd, so we handle SIPI via QEMU's
         * software APIC model.  The flow mirrors the KVM path above:
         *   1. AP starts halted.  BSP sends SIPI → APIC sets
         *      CPU_INTERRUPT_SIPI on the target AP.
         *   2. We detect the pending SIPI here, call do_cpu_sipi() to
         *      initialise CS:IP from the SIPI vector, then run the BIOS
         *      trampoline LOCALLY with cpu_exec().
         *   3. After the trampoline HLTs the AP, we mark
         *      ap_did_local_sipi so future dispatches go remote.
         *   4. For OS-level SIPI (second SIPI after Linux boots), we
         *      similarly run the trampoline locally before remote dispatch.
         */
        int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;

        /*
         * BSP (cpu0) never receives SIPI. The AP pre-SIPI park below used to
         * also catch cpu0, so split=0 (all-PROXY remote) halted forever before
         * the first CPU_RUN (serial=0, no WVM-DBG/HANDOFF). Mark BSP SIPI
         * stages done so it falls through to remote dispatch; APs unchanged.
         */
        if (cpu->cpu_index == 0) {
            ap_did_local_sipi[0] = 1;
            ap_did_os_sipi[0] = 1;
        }

        /* 1. Pre-SIPI: AP still waiting for first SIPI from BIOS */
        if (!ap_did_local_sipi[ci]) {
            X86CPU *x86cpu = X86_CPU(cpu);
            CPUState *cs = CPU(x86cpu);

            if (!(cs->interrupt_request & CPU_INTERRUPT_SIPI)) {
                /* No SIPI yet — stay parked.  Clear POLL to avoid
                 * pointless wake/park cycles (51K+ in previous runs). */
                cs->interrupt_request &= ~CPU_INTERRUPT_POLL;
                cpu->halted = 1;
                return;
            }

            /*
             * Deliver INIT before SIPI, matching QEMU's normal interrupt
             * ordering.  INIT restores the APIC wait-for-SIPI state and
             * preserves a simultaneously pending SIPI for the next step.
             */
            fprintf(stderr, "[WVM-TCG-SIPI] cpu=%d SIPI pending, calling do_cpu_sipi "
                    "(sipi_vector from APIC)\n", cpu->cpu_index);
            wavevm_tcg_deliver_init_sipi(cpu, x86cpu);

            {
                CPUX86State *env = &x86cpu->env;
                fprintf(stderr, "[WVM-TCG-SIPI] cpu=%d after SIPI: cs=0x%x cs.base=0x%lx "
                        "eip=0x%lx cr0=0x%lx\n",
                        cpu->cpu_index,
                        (unsigned)env->segs[R_CS].selector,
                        (unsigned long)env->segs[R_CS].base,
                        (unsigned long)env->eip,
                        (unsigned long)env->cr[0]);
            }

            /* Run BIOS SMP trampoline locally.  The trampoline increments
             * the BSP's AP counter in shared memory, then HLTs.  This MUST
             * run locally so the memory write is visible to BSP.
             * Note: wavevm_remote_exec() is called with iothread UNlocked,
             * so we must lock before the unlock/exec/lock cycle. */
            fprintf(stderr, "[WVM-TCG-SIPI] cpu=%d running BIOS trampoline locally\n",
                    cpu->cpu_index);
            cpu->halted = 0;

            /* Clear any stale interrupts that could interfere with trampoline.
             * POLL and RESET can cause cpu_exec() to return immediately without
             * executing guest code, wasting iterations. */
            {
                CPUState *cs2 = CPU(X86_CPU(cpu));
                cs2->interrupt_request &= ~(CPU_INTERRUPT_POLL |
                                            CPU_INTERRUPT_INIT);
            }

            /* Bounded local execution: up to 500ms for trampoline */
            int tramp_iters = 0;
            const int max_tramp_iters = 100;
            qemu_mutex_lock_iothread();
            while (tramp_iters < max_tramp_iters) {
            qemu_mutex_unlock_iothread();
            wavevm_tcg_clear_stale_exit(cpu);
            cpu_exec_start(cpu);
            int tr = cpu_exec(cpu);
            cpu_exec_end(cpu);
                qemu_mutex_lock_iothread();

                /* EXCP_INTERRUPT (0x10000): another vCPU called cpu_exit()
                 * on us — typically from cpu_exec_step_atomic() when a
                 * sibling AP hits a lock-prefix instruction.  This is
                 * benign; we made no guest progress.  Don't count it. */
                if (tr == EXCP_INTERRUPT) {
                    continue;
                }

                /* EXCP_ATOMIC: lock-prefix instruction needs exclusive
                 * execution (MTTCG stops all other vCPUs for one TB).
                 * SeaBIOS trampoline uses lock inc/xchg for AP counter.
                 * Don't count this as a real iteration. */
                if (tr == EXCP_ATOMIC) {
                    qemu_mutex_unlock_iothread();
                    cpu_exec_step_atomic(cpu);
                    qemu_mutex_lock_iothread();
                    continue;
                }

                tramp_iters++;

                /* Diagnostic: log real iterations (not INTERRUPT/ATOMIC noise) */
                {
                    CPUX86State *denv = &X86_CPU(cpu)->env;
                    CPUState *dcs = CPU(X86_CPU(cpu));
                    fprintf(stderr, "[WVM-TCG-SIPI] cpu=%d iter=%d tr=%d "
                            "eip=0x%lx halted=%d intreq=0x%x\n",
                            cpu->cpu_index, tramp_iters, tr,
                            (unsigned long)denv->eip, cpu->halted,
                            (unsigned)dcs->interrupt_request);
                }

                if (cpu->halted) {
                    fprintf(stderr, "[WVM-TCG-SIPI] cpu=%d trampoline HLTed after %d iters\n",
                            cpu->cpu_index, tramp_iters);
                    break;
                }
                if (tr == EXCP_HLT) {
                    cpu->halted = 1;
                    fprintf(stderr, "[WVM-TCG-SIPI] cpu=%d trampoline EXCP_HLT after %d iters\n",
                            cpu->cpu_index, tramp_iters);
                    break;
                }
                if (tr != EXCP_HALTED && tr != EXCP_HLT) {
                    fprintf(stderr, "[WVM-TCG-SIPI] cpu=%d trampoline unexpected tr=0x%x "
                            "at iter=%d eip=0x%lx\n",
                            cpu->cpu_index, (unsigned)tr, tramp_iters,
                            (unsigned long)(&X86_CPU(cpu)->env)->eip);
                }
            }
            if (tramp_iters >= max_tramp_iters) {
                CPUX86State *denv = &X86_CPU(cpu)->env;
                CPUState *dcs = CPU(X86_CPU(cpu));
                fprintf(stderr, "[WVM-TCG-SIPI] cpu=%d trampoline did not HLT after %d iters, "
                        "forcing halt (eip=0x%lx intreq=0x%x)\n",
                        cpu->cpu_index, max_tramp_iters,
                        (unsigned long)denv->eip,
                        (unsigned)dcs->interrupt_request);
                cpu->halted = 1;
            }

            qemu_mutex_unlock_iothread();  /* restore lock-unheld for caller */
            ap_did_local_sipi[ci] = 1;
            fprintf(stderr, "[WVM-TCG-SIPI] cpu=%d BIOS trampoline done, AP parked\n",
                    cpu->cpu_index);
            return;  /* Don't dispatch yet — wait for OS SIPI */
        }

        /* 2. Post-BIOS-SIPI: AP is parked, waiting for OS INIT+SIPI */
        if (!ap_did_os_sipi[ci]) {
            X86CPU *x86cpu = X86_CPU(cpu);
            CPUState *cs = CPU(x86cpu);

            /* Check for OS-level SIPI (Linux sends INIT+SIPI to APs) */
            if (cs->interrupt_request & CPU_INTERRUPT_SIPI) {
                fprintf(stderr, "[WVM-TCG-SIPI] cpu=%d OS SIPI pending\n", cpu->cpu_index);
                wavevm_tcg_deliver_init_sipi(cpu, x86cpu);

                /* Run OS trampoline locally (Linux SMP init) */
                fprintf(stderr, "[WVM-TCG-SIPI] cpu=%d running OS trampoline locally\n",
                        cpu->cpu_index);
                cpu->halted = 0;

                int tramp_iters = 0;
                const int max_tramp_iters = 500;  /* OS trampoline may be longer */
                qemu_mutex_lock_iothread();
                while (tramp_iters < max_tramp_iters) {
                    qemu_mutex_unlock_iothread();
                    wavevm_tcg_clear_stale_exit(cpu);
                    cpu_exec_start(cpu);
                    int tr = cpu_exec(cpu);
                    cpu_exec_end(cpu);
                    qemu_mutex_lock_iothread();

                    if (tr == EXCP_INTERRUPT) {
                        continue;  /* kicked by sibling's atomic step */
                    }

                    if (tr == EXCP_ATOMIC) {
                        qemu_mutex_unlock_iothread();
                        cpu_exec_step_atomic(cpu);
                        qemu_mutex_lock_iothread();
                        continue;
                    }

                    tramp_iters++;

                    if (cpu->halted || tr == EXCP_HLT) {
                        CPUX86State *denv = &x86cpu->env;
                        cpu->halted = 1;
                        fprintf(stderr,
                                "[WVM-TCG-SIPI] cpu=%d OS trampoline done after %d iters "
                                "tr=%d rip=0x%lx cs=0x%x cr0=0x%lx efer=0x%lx "
                                "rsp=0x%lx intreq=0x%x hflags=0x%x hflags2=0x%x mp=%d\n",
                                cpu->cpu_index, tramp_iters, tr,
                                (unsigned long)denv->eip,
                                (unsigned)denv->segs[R_CS].selector,
                                (unsigned long)denv->cr[0],
                                (unsigned long)denv->efer,
                                (unsigned long)denv->regs[R_ESP],
                                (unsigned)cs->interrupt_request,
                                (unsigned)denv->hflags,
                                (unsigned)denv->hflags2,
                                denv->mp_state);
                        break;
                    }
                    if (tr != EXCP_HALTED && tr != EXCP_HLT) {
                        fprintf(stderr, "[WVM-TCG-SIPI] cpu=%d OS trampoline unexpected tr=0x%x "
                                "at iter=%d\n", cpu->cpu_index, (unsigned)tr, tramp_iters);
                    }
                }
                if (tramp_iters >= max_tramp_iters) {
                    CPUX86State *denv = &x86cpu->env;
                    fprintf(stderr,
                            "[WVM-TCG-SIPI] cpu=%d OS trampoline timeout after %d iters "
                            "rip=0x%lx cs=0x%x cr0=0x%lx efer=0x%lx "
                            "rsp=0x%lx intreq=0x%x hflags=0x%x hflags2=0x%x mp=%d\n",
                            cpu->cpu_index, max_tramp_iters,
                            (unsigned long)denv->eip,
                            (unsigned)denv->segs[R_CS].selector,
                            (unsigned long)denv->cr[0],
                            (unsigned long)denv->efer,
                            (unsigned long)denv->regs[R_ESP],
                            (unsigned)cs->interrupt_request,
                            (unsigned)denv->hflags,
                            (unsigned)denv->hflags2,
                            denv->mp_state);
                    cpu->halted = 1;
                }

                ap_did_os_sipi[ci] = 1;
                fprintf(stderr, "[WVM-TCG-SIPI] cpu=%d OS trampoline done, ready for remote dispatch\n",
                        cpu->cpu_index);
                qemu_mutex_unlock_iothread();  /* restore lock-unheld for caller */
                return;
            }

            /* No OS SIPI yet — AP stays parked.
             * Only SIPI can advance the AP to the next stage.
             * Ignore POLL/HARD interrupts here — they cause
             * useless wake-up storms (28K+ per run). */
            {
                X86CPU *x86cpu = X86_CPU(cpu);
                CPUState *cs = CPU(x86cpu);
                cs->interrupt_request &= ~CPU_INTERRUPT_POLL;
            }
            cpu->halted = 1;
            return;
        }

        /* 3. Both SIPIs done.  Match QEMU's TCG halt handling before deciding
         * whether to send the context remote.  POLL is a local APIC polling
         * hint; it must be consumed on the master-side LAPIC first so it can
         * turn into a real interrupt_request bit if an IRQ is pending. */
        if (cpu->halted) {
            X86CPU *x86cpu = X86_CPU(cpu);
            CPUState *cs = CPU(x86cpu);

            if (cs->interrupt_request & CPU_INTERRUPT_POLL) {
                qemu_mutex_lock_iothread();
                apic_poll_irq(x86cpu->apic_state);
                cs->interrupt_request &= ~CPU_INTERRUPT_POLL;
                qemu_mutex_unlock_iothread();
            }

            if (!cpu_has_work(cpu)) {
                return;
            }

            /*
             * HARD/POLL wakeups depend on the master-side LAPIC/PIC device
             * state to pick the actual interrupt vector.  The remote TCG
             * context only carries CPU architectural state, so dispatching a
             * freshly-woken halted AP directly to a slave loses that vector and
             * replays the same HLT.  Consume the wake locally, then let later
             * runnable compute bursts go remote.
             */
            wavevm_tcg_run_local_wake(cpu, x86cpu, ci);
            /* A local wake that returns to HLT has a stable architectural
             * state on the master. Keep it parked here so the next LAPIC
             * event wakes it locally; only a runnable state is handed back
             * to the remote TCG worker. */
            if (cpu->halted ||
                ((cs->interrupt_request &
                  (CPU_INTERRUPT_HARD | CPU_INTERRUPT_POLL)) &&
                 cpu_has_work(cpu))) {
                if (!cpu->halted) {
                    sched_yield();
                }
                return;
            }
        }

        /*
         * A runnable TCG AP may also carry a pending master-side HARD/POLL.
         * Do not serialize those bits to a slave; the slave cannot derive the
         * interrupt vector without the master's local APIC/PIC device state.
         */
        {
            X86CPU *x86cpu = X86_CPU(cpu);
            CPUState *cs = CPU(x86cpu);

            if (cs->interrupt_request & CPU_INTERRUPT_POLL) {
                qemu_mutex_lock_iothread();
                apic_poll_irq(x86cpu->apic_state);
                cs->interrupt_request &= ~CPU_INTERRUPT_POLL;
                qemu_mutex_unlock_iothread();
            }
            if ((cs->interrupt_request & CPU_INTERRUPT_HARD) &&
                cpu_has_work(cpu)) {
                wavevm_tcg_run_local_wake(cpu, x86cpu, ci);
                if (cpu->halted ||
                    ((cs->interrupt_request &
                      (CPU_INTERRUPT_HARD | CPU_INTERRUPT_POLL)) &&
                     cpu_has_work(cpu))) {
                    if (!cpu->halted) {
                        sched_yield();
                    }
                    return;
                }
            }
        }
    }

    /* Log first remote dispatches after SIPI wake */
    {
        static int remote_dbg[MAX_VCPUS] = {0};
        int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
        if (remote_dbg[ci] < 10) {
            if (kvm_enabled()) {
                struct kvm_regs dbg_kr;
                struct kvm_sregs dbg_sr;
                ioctl(cpu->kvm_fd, KVM_GET_REGS, &dbg_kr);
                ioctl(cpu->kvm_fd, KVM_GET_SREGS, &dbg_sr);
                fprintf(stderr, "[WVM-REMOTE] cpu=%d dispatch #%d rip=0x%llx cs=0x%x "
                        "cr0=0x%llx cr3=0x%llx efer=0x%llx rsp=0x%llx\n",
                        cpu->cpu_index, remote_dbg[ci],
                        (unsigned long long)dbg_kr.rip,
                        dbg_sr.cs.selector,
                        (unsigned long long)dbg_sr.cr0,
                        (unsigned long long)dbg_sr.cr3,
                        (unsigned long long)dbg_sr.efer,
                        (unsigned long long)dbg_kr.rsp);
            } else {
                X86CPU *x86cpu = X86_CPU(cpu);
                CPUX86State *env = &x86cpu->env;
                fprintf(stderr, "[WVM-REMOTE] cpu=%d dispatch #%d rip=0x%lx cs=0x%x "
                        "cr0=0x%lx cr3=0x%lx efer=0x%lx rsp=0x%lx oldex=%d\n",
                        cpu->cpu_index, remote_dbg[ci],
                        (unsigned long)env->eip,
                        (unsigned)env->segs[R_CS].selector,
                        (unsigned long)env->cr[0],
                        (unsigned long)env->cr[3],
                        (unsigned long)env->efer,
                        (unsigned long)env->regs[R_ESP],
                        env->old_exception);
            }
            remote_dbg[ci]++;
        }
    }

    int vcpu_sock = g_vcpu_socks[cpu->cpu_index];
    if (!g_wvm_debug_once) {
        g_wvm_debug_once = 1;
        fprintf(stderr, "[WVM-DBG] cpu=%d kvm_enabled=%d vcpu_sock=%d split=%d\n",
                cpu->cpu_index, kvm_enabled(), vcpu_sock, g_wvm_local_split);
    }
    
    // 如果没有 socket (说明是 Kernel Mode), 走 IOCTL 路径
    if (vcpu_sock < 0) { 
        WaveVMAccelState *s = WAVEVM_ACCEL(current_machine->accelerator);
        if (s->mode != WVM_MODE_KERNEL) {
            g_usleep(1000); // 异常状态，非 Kernel 且无 Socket
            return;
        }

        // 1. 准备请求结构体
        struct wvm_ipc_cpu_run_req req;
        struct wvm_ipc_cpu_run_ack ack = {0};
        wvm_tcg_context_t sent_tcg;
        uint32_t forwarded_irq = 0;
        memset(&req, 0, sizeof(req));
        memset(&sent_tcg, 0, sizeof(sent_tcg));
        
        req.slave_id = WVM_NODE_AUTO_ROUTE;
        req.vcpu_index = cpu->cpu_index;

        // 2. 序列化 CPU 状态
        if (kvm_enabled()) {
            struct kvm_regs kregs;
            struct kvm_sregs ksregs;
            cpu_synchronize_state(cpu);
            ioctl(cpu->kvm_fd, KVM_GET_REGS, &kregs);
            ioctl(cpu->kvm_fd, KVM_GET_SREGS, &ksregs);

            req.mode_tcg = 0;
            req.ctx.kvm.rax = kregs.rax; req.ctx.kvm.rbx = kregs.rbx; req.ctx.kvm.rcx = kregs.rcx;
            req.ctx.kvm.rdx = kregs.rdx; req.ctx.kvm.rsi = kregs.rsi; req.ctx.kvm.rdi = kregs.rdi;
            req.ctx.kvm.rsp = kregs.rsp; req.ctx.kvm.rbp = kregs.rbp;
            req.ctx.kvm.r8  = kregs.r8;  req.ctx.kvm.r9  = kregs.r9;  req.ctx.kvm.r10 = kregs.r10;
            req.ctx.kvm.r11 = kregs.r11; req.ctx.kvm.r12 = kregs.r12; req.ctx.kvm.r13 = kregs.r13;
            req.ctx.kvm.r14 = kregs.r14; req.ctx.kvm.r15 = kregs.r15;
            req.ctx.kvm.rip = kregs.rip; req.ctx.kvm.rflags = kregs.rflags;
            memcpy(req.ctx.kvm.sregs_data, &ksregs, sizeof(ksregs));
        } else {
            req.mode_tcg = 1;
            wvm_tcg_get_state(cpu, &req.ctx.tcg);
            req.ctx.tcg.slice_budget_us = wavevm_tcg_slice_budget_us(cpu);
            sent_tcg = req.ctx.tcg;
            forwarded_irq = sent_tcg.interrupt_request &
                            WVM_TCG_REMOTE_IRQ_FORWARD_MASK;
        }

        // 3. 陷入内核 (Trap into Kernel)
        // 这一步会阻塞，直到远程执行完毕并返回结果
        {
            static int dbg_kp_cnt = 0;
            if (dbg_kp_cnt < 20) {
                fprintf(stderr, "[WVM-DBG] kernel path cpu=%d target=%u mode_tcg=%u "
                        "rip=%#llx\n",
                        cpu->cpu_index, req.slave_id, req.mode_tcg,
                        (unsigned long long)req.ctx.kvm.rip);
                dbg_kp_cnt++;
            }
        }
        struct wvm_ioctl_remote_run remote_run;
        memset(&remote_run, 0, sizeof(remote_run));
        remote_run.req = req;
        int ret = ioctl(s->dev_fd, IOCTL_WVM_REMOTE_RUN, &remote_run);

        if (ret < 0) {
            static int dbg_fail_cnt = 0;
            if (dbg_fail_cnt < 10) {
                fprintf(stderr, "[WVM-DBG] IOCTL_WVM_REMOTE_RUN failed cpu=%d: %s\n",
                        cpu->cpu_index, strerror(errno));
                dbg_fail_cnt++;
            }
            return;
        }
        if (cpu->cpu_index < MAX_VCPUS) {
            g_wavevm_remote_rpc_ok[cpu->cpu_index] = true;
        }

        // 4. Read the explicit Mode A ioctl response container.
        ack = remote_run.ack;

        if (ack.mode_tcg) {
            wavevm_tcg_import_remote_ack(cpu, &ack.ctx.tcg, &sent_tcg,
                                         forwarded_irq);
        } else {
            struct kvm_regs kregs;
            struct kvm_sregs ksregs;
            wvm_kvm_context_t *kctx = &ack.ctx.kvm;

            kregs.rax = kctx->rax; kregs.rbx = kctx->rbx; kregs.rcx = kctx->rcx; 
            kregs.rdx = kctx->rdx; kregs.rsi = kctx->rsi; kregs.rdi = kctx->rdi;
            kregs.rsp = kctx->rsp; kregs.rbp = kctx->rbp;
            kregs.r8 = kctx->r8;   kregs.r9 = kctx->r9;   kregs.r10 = kctx->r10; 
            kregs.r11 = kctx->r11; kregs.r12 = kctx->r12; kregs.r13 = kctx->r13;
            kregs.r14 = kctx->r14; kregs.r15 = kctx->r15;
            kregs.rip = kctx->rip; kregs.rflags = kctx->rflags;
            
            ioctl(cpu->kvm_fd, KVM_GET_SREGS, &ksregs);
            wavevm_apply_arch_sregs(&ksregs, (const struct kvm_sregs *)kctx->sregs_data);
            ioctl(cpu->kvm_fd, KVM_SET_SREGS, &ksregs);
            ioctl(cpu->kvm_fd, KVM_SET_REGS, &kregs);
            
            struct kvm_run *run = cpu->kvm_run;
            run->exit_reason = kctx->exit_reason;

            if (kctx->exit_reason == KVM_EXIT_IO) {
                uint16_t port = kctx->io.port;
                int is_write = (kctx->io.direction == KVM_EXIT_IO_OUT);
                uint8_t io_buf[64];
                size_t io_bytes = (size_t)kctx->io.size * kctx->io.count;
                if (io_bytes > sizeof(kctx->io.data)) io_bytes = sizeof(kctx->io.data);
                if (io_bytes > sizeof(io_buf)) io_bytes = sizeof(io_buf);
                if (is_write) {
                    memcpy(io_buf, kctx->io.data, io_bytes);
                }
                run->io.direction = kctx->io.direction;
                run->io.size      = kctx->io.size;
                run->io.port      = kctx->io.port;
                run->io.count     = kctx->io.count;
                if (kctx->io.size != 1 && kctx->io.size != 2 &&
                    kctx->io.size != 4 && kctx->io.size != 8) { return; }
                if (kctx->io.count == 0 || kctx->io.count > 8) { return; }
                qemu_mutex_lock_iothread();
                for (uint32_t i = 0; i < kctx->io.count; i++) {
                    address_space_rw(&address_space_io, port, MEMTXATTRS_UNSPECIFIED,
                                     io_buf + i * kctx->io.size, kctx->io.size, is_write);
                }
                qemu_mutex_unlock_iothread();
                if (!is_write) {
                    memcpy(kctx->io.data, io_buf, io_bytes);
                    if (run->io.data_offset >= sizeof(struct kvm_run) &&
                        run->io.data_offset + io_bytes <= 12288) {
                        memcpy((uint8_t *)run + run->io.data_offset, io_buf, io_bytes);
                    }
                }
            } 
            else if (kctx->exit_reason == KVM_EXIT_MMIO) {
                uint8_t mmio_buf[8];
                hwaddr addr = kctx->mmio.phys_addr;
                int mmio_wr = kctx->mmio.is_write;
                unsigned len = kctx->mmio.len;
                if (len != 1 && len != 2 && len != 4 && len != 8) { return; }
                if ((addr >= 0xfee00000ULL && addr < 0xfee01000ULL) &&
                    wavevm_kvm_apply_remote_lapic_mmio(cpu, kctx, run)) {
                    /* FE LAPIC programmed via KVM_SET_LAPIC. */
                } else {
                    if (mmio_wr) {
                        memcpy(mmio_buf, kctx->mmio.data, len);
                    }
                    qemu_mutex_lock_iothread();
                    address_space_rw(&address_space_memory, addr, MEMTXATTRS_UNSPECIFIED,
                                     mmio_buf, len, mmio_wr);
                    qemu_mutex_unlock_iothread();
                    if (!mmio_wr) {
                        memcpy(kctx->mmio.data, mmio_buf, len);
                        memcpy(run->mmio.data, mmio_buf, len);
                    }
                    run->mmio.phys_addr = addr;
                    run->mmio.len = len;
                    run->mmio.is_write = mmio_wr;
                }
            }
            else if (kctx->exit_reason == KVM_EXIT_MMIO) {
                run->mmio.phys_addr = kctx->mmio.phys_addr;
                run->mmio.len       = kctx->mmio.len;
                run->mmio.is_write  = kctx->mmio.is_write;
                memcpy(run->mmio.data, kctx->mmio.data, 8);
                if (!wavevm_valid_mmio_exit(run)) {
                    return;
                }
                qemu_mutex_lock_iothread();
                wavevm_handle_mmio(cpu);
                qemu_mutex_unlock_iothread();
            }
        }
        return; 
    }

    // 准备发送缓冲区
    struct wvm_ipc_header_t ipc_hdr = {
        .type = WVM_IPC_TYPE_CPU_RUN,
        .len = sizeof(struct wvm_ipc_cpu_run_req),
    };
    struct wvm_ipc_cpu_run_req req;
    struct wvm_ipc_cpu_run_ack ack;
    WVMHandoffDirtyJournal *dirty_journal = NULL;
    bool tcg_slice_active = false;
    memset(&req, 0, sizeof(req));
    memset(&ack, 0, sizeof(ack));

    req.slave_id = WVM_NODE_AUTO_ROUTE;
    req.vcpu_index = cpu->cpu_index;

    // 1. 序列化 CPU 状态 (Serialization)
    if (kvm_enabled()) {
        struct kvm_regs kregs;
        struct kvm_sregs ksregs;
        cpu_synchronize_state(cpu);
        ioctl(cpu->kvm_fd, KVM_GET_REGS, &kregs);
        ioctl(cpu->kvm_fd, KVM_GET_SREGS, &ksregs);

        /* [DIAG] Dump first 16 bytes at trampoline GPA + full regs for AP */
        if (cpu->cpu_index > 0) {
            static int memdump_count[MAX_VCPUS] = {0};
            int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
            if (memdump_count[ci] < 5) {
                uint8_t mem16[16];
                hwaddr gpa = (hwaddr)ksregs.cs.base + kregs.rip;
                cpu_physical_memory_read(gpa, mem16, 16);
                fprintf(stderr, "[MASTER-MEM] cpu=%d GPA=0x%llx bytes:"
                        " %02x %02x %02x %02x %02x %02x %02x %02x"
                        " %02x %02x %02x %02x %02x %02x %02x %02x\n",
                        cpu->cpu_index, (unsigned long long)gpa,
                        mem16[0],mem16[1],mem16[2],mem16[3],
                        mem16[4],mem16[5],mem16[6],mem16[7],
                        mem16[8],mem16[9],mem16[10],mem16[11],
                        mem16[12],mem16[13],mem16[14],mem16[15]);
                fprintf(stderr, "[MASTER-REGS] cpu=%d rip=0x%llx cs=0x%x cs_base=0x%llx "
                        "cr0=0x%llx efer=0x%llx rdx=0x%llx rsp=0x%llx\n",
                        cpu->cpu_index,
                        (unsigned long long)kregs.rip,
                        ksregs.cs.selector,
                        (unsigned long long)ksregs.cs.base,
                        (unsigned long long)ksregs.cr0,
                        (unsigned long long)ksregs.efer,
                        (unsigned long long)kregs.rdx,
                        (unsigned long long)kregs.rsp);
                memdump_count[ci]++;
            }
        }

        req.mode_tcg = 0;

        wvm_kvm_context_t *kctx = &req.ctx.kvm;
        kctx->rax = kregs.rax; kctx->rbx = kregs.rbx; kctx->rcx = kregs.rcx;
        kctx->rdx = kregs.rdx; kctx->rsi = kregs.rsi; kctx->rdi = kregs.rdi;
        kctx->rsp = kregs.rsp; kctx->rbp = kregs.rbp;
        kctx->r8  = kregs.r8;  kctx->r9  = kregs.r9;  kctx->r10 = kregs.r10;
        kctx->r11 = kregs.r11; kctx->r12 = kregs.r12; kctx->r13 = kregs.r13;
        kctx->r14 = kregs.r14; kctx->r15 = kregs.r15;
        kctx->rip = kregs.rip; kctx->rflags = kregs.rflags;
        memcpy(kctx->sregs_data, &ksregs, sizeof(ksregs));
        {
            struct kvm_lapic_state klapic;
            if (ioctl(cpu->kvm_fd, KVM_GET_LAPIC, &klapic) >= 0) {
                memcpy(kctx->lapic_data, &klapic, sizeof(klapic));
                kctx->lapic_valid = 1;
            } else {
                kctx->lapic_valid = 0;
            }
        }
        {
            struct kvm_vcpu_events kev;
            if (ioctl(cpu->kvm_fd, KVM_GET_VCPU_EVENTS, &kev) >= 0) {
                memcpy(kctx->vcpu_events_data, &kev, sizeof(kev));
                kctx->vcpu_events_valid = 1;
            } else {
                kctx->vcpu_events_valid = 0;
            }
        }
        {
            struct kvm_fpu fpu;
            if (ioctl(cpu->kvm_fd, KVM_GET_FPU, &fpu) >= 0) {
                memcpy(kctx->fpu_data, &fpu, sizeof(fpu));
                kctx->fpu_valid = 1;
            } else {
                kctx->fpu_valid = 0;
            }
        }
        {
            struct kvm_xcrs xcrs;
            if (ioctl(cpu->kvm_fd, KVM_GET_XCRS, &xcrs) >= 0) {
                memcpy(kctx->xcrs_data, &xcrs, sizeof(xcrs));
                kctx->xcrs_valid = 1;
            } else {
                kctx->xcrs_valid = 0;
            }
        }
        {
            struct kvm_mp_state mp;
            if (ioctl(cpu->kvm_fd, KVM_GET_MP_STATE, &mp) >= 0) {
                kctx->mp_state = mp.mp_state;
                kctx->mp_state_valid = 1;
            } else {
                kctx->mp_state_valid = 0;
            }
        }

        /* [V30 TSC 同步] 读取 master 本地 TSC 并携带到 slave，
         * slave 执行完后会把更新后的 TSC 带回来。
         * 避免 master/slave 之间 TSC 不同步导致 kvmclock 算出负 delta。 */
        {
            /* s23g5: also sync GS_BASE/APIC_BASE/SYSCALL MSRs — dual-yes DF */
            struct {
                struct kvm_msrs info;
                struct kvm_msr_entry entries[9];
            } msr_data;
            memset(&msr_data, 0, sizeof(msr_data));
            msr_data.info.nmsrs = 9;
            msr_data.entries[0].index = 0x10;        /* MSR_IA32_TSC */
            msr_data.entries[1].index = 0x6e0;       /* MSR_IA32_TSCDEADLINE */
            msr_data.entries[2].index = 0xC0000102;  /* MSR_KERNEL_GS_BASE */
            msr_data.entries[3].index = 0xC0000101;  /* MSR_GS_BASE */
            msr_data.entries[4].index = 0x1b;        /* IA32_APIC_BASE */
            msr_data.entries[5].index = 0xC0000081;  /* STAR */
            msr_data.entries[6].index = 0xC0000082;  /* LSTAR */
            msr_data.entries[7].index = 0xC0000083;  /* CSTAR */
            msr_data.entries[8].index = 0xC0000084;  /* SFMASK */
            if (ioctl(cpu->kvm_fd, KVM_GET_MSRS, &msr_data) >= 0) {
                kctx->tsc_value = msr_data.entries[0].data;
                kctx->tsc_deadline = msr_data.entries[1].data;
                kctx->kernel_gs_base = msr_data.entries[2].data;
                kctx->tsc_valid = 1;
                kctx->gs_base = msr_data.entries[3].data;
                kctx->apic_base = msr_data.entries[4].data;
                kctx->star = msr_data.entries[5].data;
                kctx->lstar = msr_data.entries[6].data;
                kctx->cstar = msr_data.entries[7].data;
                kctx->sfmask = msr_data.entries[8].data;
                kctx->msr_ext_valid = 0x7; /* gs|apic|syscall */
            } else {
                kctx->tsc_valid = 0;
                kctx->msr_ext_valid = 0;
            }
        }

        /* [FIX] 携带上一轮 IO/MMIO 处理结果：
         * 若上次远程执行触发了 IO IN 或 MMIO READ，Master 已在本地
         * wavevm_handle_io/mmio 中将设备读结果填入 run->io.data / mmio.data。
         * Slave 需要这些数据在下次 KVM_RUN 时完成未决的 IO 指令。 */
        struct kvm_run *run = cpu->kvm_run;
        kctx->exit_reason = run->exit_reason;
        if (run->exit_reason == KVM_EXIT_IO) {
            int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
            kctx->io.direction = run->io.direction;
            kctx->io.size      = run->io.size;
            kctx->io.port      = run->io.port;
            kctx->io.count     = run->io.count;
            if (run->io.direction == KVM_EXIT_IO_IN) {
                size_t io_bytes = (size_t)run->io.size * run->io.count;
                if (io_bytes > sizeof(kctx->io.data)) io_bytes = sizeof(kctx->io.data);
                /*
                 * s23g3: never memcpy from (run + data_offset) unless the
                 * offset is inside the kvm_run mmap. Remote AP path left
                 * data_offset uninitialized → qemu segfault under dual-yes.
                 */
                if (g_wavevm_pending_io_valid[ci]) {
                    size_t n = g_wavevm_pending_io_len[ci];
                    if (n > io_bytes) n = io_bytes;
                    memcpy(kctx->io.data, g_wavevm_pending_io_data[ci], n);
                    if (n < io_bytes) {
                        memset(kctx->io.data + n, 0, io_bytes - n);
                    }
                    g_wavevm_pending_io_valid[ci] = 0;
                    g_wavevm_pending_io_len[ci] = 0;
                } else if (run->io.data_offset >= sizeof(struct kvm_run) &&
                           run->io.data_offset + io_bytes <= 12288) {
                    memcpy(kctx->io.data,
                           (uint8_t *)run + run->io.data_offset, io_bytes);
                } else {
                    static int io_send_bad[MAX_VCPUS];
                    memset(kctx->io.data, 0, io_bytes);
                    if (io_send_bad[ci]++ < 20) {
                        fprintf(stderr,
                                "[WVM-IO-SEND] cpu=%d MISSING IN data "
                                "port=0x%x off=%llu (zeroed)\n",
                                cpu->cpu_index, kctx->io.port,
                                (unsigned long long)run->io.data_offset);
                    }
                }
                {
                    static int io_send_dbg[MAX_VCPUS] = {0};
                    if (io_send_dbg[ci] < 40) {
                        fprintf(stderr,
                                "[WVM-IO-SEND] cpu=%d port=0x%x dir=%u size=%u count=%u data0=0x%02x\n",
                                cpu->cpu_index,
                                kctx->io.port,
                                kctx->io.direction,
                                kctx->io.size,
                                kctx->io.count,
                                kctx->io.data[0]);
                        io_send_dbg[ci]++;
                    }
                }
            }
        } else if (run->exit_reason == KVM_EXIT_MMIO) {
            kctx->mmio.phys_addr = run->mmio.phys_addr;
            kctx->mmio.len       = run->mmio.len;
            kctx->mmio.is_write  = run->mmio.is_write;
            if (!run->mmio.is_write) {
                memcpy(kctx->mmio.data, run->mmio.data, 8);
            }
        }
    } else {
        req.mode_tcg = 1;
        wvm_tcg_get_state(cpu, &req.ctx.tcg);
        /* STW pairing: shorter helper quantum under spin/prefer (see protocol). */
        req.ctx.tcg.slice_budget_us = wavevm_tcg_slice_budget_us(cpu);
    }

    {
        static int send_dbg[MAX_VCPUS] = {0};
        int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
        if (!req.mode_tcg && send_dbg[ci] < 20) {
            fprintf(stderr,
                    "[WVM-SEND] cpu=%d rip=0x%llx rax=0x%llx rdx=0x%llx mp_valid=%u mp=%u lapic=%u vcpu_events=%u tsc=%u\n",
                    cpu->cpu_index,
                    (unsigned long long)req.ctx.kvm.rip,
                    (unsigned long long)req.ctx.kvm.rax,
                    (unsigned long long)req.ctx.kvm.rdx,
                    req.ctx.kvm.mp_state_valid,
                    req.ctx.kvm.mp_state,
                    req.ctx.kvm.lapic_valid,
                    req.ctx.kvm.vcpu_events_valid,
                    req.ctx.kvm.tsc_valid);
            send_dbg[ci]++;
        }
    }

    if (req.mode_tcg) {
        int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
        static int handoff_dbg[MAX_VCPUS] = {0};
        wavevm_tcg_remote_slice_enter(cpu);
        tcg_slice_active = true;
        if (wavevm_user_mem_tcg_shm_coherent()) {
            if (handoff_dbg[ci] < 20) {
                fprintf(stderr,
                        "[WVM-TCG-HANDOFF] cpu=%d SHM-coherent skip flush/fence "
                        "fd=%d slice_budget_us=%u spin=%d\n",
                        cpu->cpu_index, vcpu_sock,
                        (unsigned)req.ctx.tcg.slice_budget_us,
                        g_wavevm_tcg_spin_count[
                            cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0]);
            }
        } else {
        if (handoff_dbg[ci] < 20) {
            fprintf(stderr, "[WVM-TCG-HANDOFF] cpu=%d flush begin fd=%d\n",
                    cpu->cpu_index, vcpu_sock);
        }
        int flush_ret = wavevm_user_mem_flush_dirty_to_ipc(vcpu_sock,
                                                           &dirty_journal);
        if (handoff_dbg[ci] < 20) {
            fprintf(stderr, "[WVM-TCG-HANDOFF] cpu=%d flush done fd=%d ret=%d\n",
                    cpu->cpu_index, vcpu_sock, flush_ret);
        }
        if (flush_ret < 0) {
            wavevm_user_mem_finish_handoff_dirty(dirty_journal, 0);
            wavevm_tcg_remote_slice_leave(cpu);
            return;
        }
        /*
         * Handoff dirty commits publish PAGE_PUSH to helpers asynchronously.
         * Always fence on the same vcpu_sock (even when this flush committed 0
         * pages): prior async APPLY may still be in flight, and attach15 hung
         * after syslogd with FE in unix_stream_data_wait while only slave
         * fences were observed. Skipping fence on flush_ret==0 left master
         * CPU_RUN racing stale remote pages.
         */
        {
            int fence_ret = wavevm_user_mem_ipc_push_fence(vcpu_sock, 5000000ULL);
            if (handoff_dbg[ci] < 20) {
                fprintf(stderr,
                        "[WVM-TCG-HANDOFF] cpu=%d push-fence fd=%d ret=%d flush=%d\n",
                        cpu->cpu_index, vcpu_sock, fence_ret, flush_ret);
            }
            if (fence_ret < 0) {
                fprintf(stderr,
                        "[WVM-TCG-HANDOFF] cpu=%d push-fence failed ret=%d flush=%d\n",
                        cpu->cpu_index, fence_ret, flush_ret);
                wavevm_user_mem_finish_handoff_dirty(dirty_journal, 0);
                wavevm_tcg_remote_slice_leave(cpu);
                return;
            }
        }
        } /* !shm_coherent */
        {
            static int cr3_dbg[MAX_VCPUS] = {0};
            if (cr3_dbg[ci] < 20) {
                int ok = 0;
                uint64_t pml4e508 =
                    wavevm_user_mem_debug_read_u64(req.ctx.tcg.cr[3], 0xfe0, &ok);
                fprintf(stderr,
                        "[WVM-TCG-CR3] cpu=%d cr3=0x%llx pml4e508=0x%llx ok=%d\n",
                        cpu->cpu_index,
                        (unsigned long long)req.ctx.tcg.cr[3],
                        (unsigned long long)pml4e508,
                        ok);
                cr3_dbg[ci]++;
            }
        }
        wavevm_tcg_log_stack(cpu, "master-pre-send");
        handoff_dbg[ci]++;
    }

    // 2. IPC 发送 (wvm_ipc_header + wvm_ipc_cpu_run_req)
    int tcg_ipc_dbg_ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
    static int tcg_ipc_dbg[MAX_VCPUS] = {0};
    if (req.mode_tcg && tcg_ipc_dbg[tcg_ipc_dbg_ci] < 20) {
        fprintf(stderr, "[WVM-TCG-IPC] cpu=%d write CPU_RUN begin fd=%d\n",
                cpu->cpu_index, vcpu_sock);
    }
    if (write_full(vcpu_sock, &ipc_hdr, sizeof(ipc_hdr)) < 0) {
        if (req.mode_tcg) {
            fprintf(stderr, "[WVM-TCG-IPC] cpu=%d write header failed fd=%d errno=%d\n",
                    cpu->cpu_index, vcpu_sock, errno);
            wavevm_user_mem_finish_handoff_dirty(dirty_journal, 0);
            if (tcg_slice_active) {
                wavevm_tcg_remote_slice_leave(cpu);
            }
        }
        return;
    }
    if (write_full(vcpu_sock, &req, sizeof(req)) < 0) {
        if (req.mode_tcg) {
            fprintf(stderr, "[WVM-TCG-IPC] cpu=%d write payload failed fd=%d errno=%d\n",
                    cpu->cpu_index, vcpu_sock, errno);
            wavevm_user_mem_finish_handoff_dirty(dirty_journal, 0);
            if (tcg_slice_active) {
                wavevm_tcg_remote_slice_leave(cpu);
            }
        }
        return;
    }

    // 3. IPC 接收 ACK (阻塞本线程，不影响其他 vCPU)
    if (req.mode_tcg && tcg_ipc_dbg[tcg_ipc_dbg_ci] < 20) {
        fprintf(stderr, "[WVM-TCG-IPC] cpu=%d write CPU_RUN done, wait ack fd=%d\n",
                cpu->cpu_index, vcpu_sock);
        tcg_ipc_dbg[tcg_ipc_dbg_ci]++;
    }
    if (read_full(vcpu_sock, &ack, sizeof(ack)) < 0) {
        if (req.mode_tcg) {
            fprintf(stderr, "[WVM-TCG-IPC] cpu=%d read ack failed fd=%d errno=%d\n",
                    cpu->cpu_index, vcpu_sock, errno);
            wavevm_user_mem_finish_handoff_dirty(dirty_journal, 0);
            if (tcg_slice_active) {
                wavevm_tcg_remote_slice_leave(cpu);
            }
        }
        return;
    }
    /* s23g6: socket CPU_RUN round-trip completed — count as remote RPC. */
    if (cpu->cpu_index < MAX_VCPUS) {
        g_wavevm_remote_rpc_ok[cpu->cpu_index] = true;
    }
    if (ack.status < 0) {
        int sync_ret = 0;
        if (ack.error_gpa != 0) {
            sync_ret = wavevm_user_mem_sync_page(ack.error_gpa);
        }
        if (req.mode_tcg) {
            wavevm_user_mem_finish_handoff_dirty(dirty_journal, 0);
            fprintf(stderr,
                    "[WVM-TCG-IPC] cpu=%d ack status=%d mode=%u error_gpa=%#llx sync_ret=%d\n",
                    cpu->cpu_index, ack.status, ack.mode_tcg,
                    (unsigned long long)ack.error_gpa, sync_ret);
            if (tcg_slice_active) {
                wavevm_tcg_remote_slice_leave(cpu);
            }
            return;
        }
        /*
         * s23g2: KVM MEMORY_FAILURE. vcpu_service maps handoff MEMORY_FAILURE
         * to status=-EFAULT and historically returns a *zeroed* ACK (no CPU
         * ctx). Importing that zeros the AP (FAIL_ENTRY storm). Only fall
         * through to import when the ACK carries a live architectural ctx
         * (cr0!=0). Otherwise sync error_gpa and retry next iteration.
         */
        {
            const struct kvm_sregs *ks =
                (const struct kvm_sregs *)ack.ctx.kvm.sregs_data;
            int ctx_live = (ks->cr0 != 0) || (ack.ctx.kvm.rip != 0);
            static int kvm_mf_dbg[MAX_VCPUS];
            int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
            if (kvm_mf_dbg[ci] < 40) {
                fprintf(stderr,
                        "[WVM-KVM-IPC] cpu=%d MEMORY_FAILURE status=%d "
                        "error_gpa=%#llx sync_ret=%d exit=%u rip=%#llx "
                        "cr0=%#llx ctx_live=%d\n",
                        cpu->cpu_index, ack.status,
                        (unsigned long long)ack.error_gpa, sync_ret,
                        ack.ctx.kvm.exit_reason,
                        (unsigned long long)ack.ctx.kvm.rip,
                        (unsigned long long)ks->cr0, ctx_live);
                kvm_mf_dbg[ci]++;
            }
            if (!ctx_live) {
                return;
            }
        }
        /* fall through to deserialize + exit handling */
    }
    if (req.mode_tcg) {
        wavevm_user_mem_finish_handoff_dirty(dirty_journal, 1);
    }

    // 4. 反序列化 CPU 状态
    if (ack.mode_tcg) {
        uint32_t forwarded_irq =
            req.ctx.tcg.interrupt_request &
            WVM_TCG_REMOTE_IRQ_FORWARD_MASK;
        if (cpu->cpu_index > 0 &&
            ((uint64_t)ack.ctx.tcg.eip >= 0xffffffff80000000ULL ||
             (uint64_t)ack.ctx.tcg.eip < 0x10000ULL)) {
            static unsigned int ack_stack_ctx_count;
            if (ack_stack_ctx_count++ < 64) {
                fprintf(stderr,
                        "[WVM-TCG-STACK-CTX] phase=master-ack cpu=%d "
                        "rip=%#llx rsp=%#llx\n",
                        cpu->cpu_index,
                        (unsigned long long)ack.ctx.tcg.eip,
                        (unsigned long long)ack.ctx.tcg.regs[R_ESP]);
            }
        }
        wavevm_tcg_import_remote_ack(cpu, &ack.ctx.tcg, &req.ctx.tcg,
                                     forwarded_irq);
        wavevm_tcg_log_stack(cpu, "master-post-import");
        if (tcg_slice_active) {
            wavevm_tcg_remote_slice_leave(cpu);
            tcg_slice_active = false;
            wavevm_tcg_remote_spin_backoff(cpu,
                                          (uint64_t)ack.ctx.tcg.eip);
        }
    } else {
        if (tcg_slice_active) {
            wavevm_tcg_remote_slice_leave(cpu);
            tcg_slice_active = false;
        }
        struct kvm_regs kregs;
        struct kvm_sregs ksregs;
        wvm_kvm_context_t *kctx = &ack.ctx.kvm;

        /* Log remote dispatch results for debugging AP SMP bringup */
        {
            static int ack_dbg[MAX_VCPUS] = {0};
            int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
            if (ack_dbg[ci] < 30) {
                fprintf(stderr, "[WVM-ACK] cpu=%d ack#%d exit=%d rip=0x%llx cs_sel=0x%x "
                        "cr0=0x%llx status=%d",
                        cpu->cpu_index, ack_dbg[ci], kctx->exit_reason,
                        (unsigned long long)kctx->rip,
                        ((struct kvm_sregs *)kctx->sregs_data)->cs.selector,
                        (unsigned long long)((struct kvm_sregs *)kctx->sregs_data)->cr0,
                        ack.status);
                if (kctx->exit_reason == 2 /* KVM_EXIT_IO */) {
                    fprintf(stderr, " io_port=0x%x io_dir=%d io_sz=%d",
                            kctx->io.port, kctx->io.direction, kctx->io.size);
                } else if (kctx->exit_reason == 6 /* KVM_EXIT_MMIO */) {
                    fprintf(stderr, " mmio_addr=0x%llx mmio_wr=%d mmio_len=%d",
                            (unsigned long long)kctx->mmio.phys_addr,
                            kctx->mmio.is_write, kctx->mmio.len);
                }
                fprintf(stderr, "\n");
                ack_dbg[ci]++;
            }
        }
        if (kctx->exit_reason == KVM_EXIT_HLT) {
            static int hlt_ack_dbg[MAX_VCPUS] = {0};
            int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
            if (hlt_ack_dbg[ci] < 20) {
                const struct kvm_vcpu_events *kev =
                    (const struct kvm_vcpu_events *)kctx->vcpu_events_data;
                fprintf(stderr,
                        "[WVM-HLT-LAPIC] cpu=%d lapic=%u mp_valid=%u mp=%u vcpu_events=%u int_inj=%u int_nr=%u int_soft=%u int_shadow=%u exc_pend=%u nmi_pend=%u",
                        cpu->cpu_index,
                        kctx->lapic_valid,
                        kctx->mp_state_valid,
                        kctx->mp_state_valid ? kctx->mp_state : 0xffffffffu,
                        kctx->vcpu_events_valid,
                        kctx->vcpu_events_valid ? kev->interrupt.injected : 0,
                        kctx->vcpu_events_valid ? kev->interrupt.nr : 0,
                        kctx->vcpu_events_valid ? kev->interrupt.soft : 0,
                        kctx->vcpu_events_valid ? kev->interrupt.shadow : 0,
                        kctx->vcpu_events_valid ? kev->exception.pending : 0,
                        kctx->vcpu_events_valid ? kev->nmi.pending : 0);
                if (kctx->lapic_valid) {
                    const struct kvm_lapic_state *lapic =
                        (const struct kvm_lapic_state *)kctx->lapic_data;
                    fprintf(stderr,
                            " lvt=0x%08x init=0x%08x cur=0x%08x div=0x%08x svr=0x%08x",
                            wavevm_lapic_reg32(lapic, 0x320),
                            wavevm_lapic_reg32(lapic, 0x380),
                            wavevm_lapic_reg32(lapic, 0x390),
                            wavevm_lapic_reg32(lapic, 0x3e0),
                            wavevm_lapic_reg32(lapic, 0x0f0));
                }
                fprintf(stderr, "\n");
                hlt_ack_dbg[ci]++;
            }
        }

        kregs.rax = kctx->rax; kregs.rbx = kctx->rbx; kregs.rcx = kctx->rcx;
        kregs.rdx = kctx->rdx; kregs.rsi = kctx->rsi; kregs.rdi = kctx->rdi;
        kregs.rsp = kctx->rsp; kregs.rbp = kctx->rbp;
        kregs.r8 = kctx->r8;   kregs.r9 = kctx->r9;   kregs.r10 = kctx->r10;
        kregs.r11 = kctx->r11; kregs.r12 = kctx->r12; kregs.r13 = kctx->r13;
        kregs.r14 = kctx->r14; kregs.r15 = kctx->r15;
        kregs.rip = kctx->rip; kregs.rflags = kctx->rflags;
        if (kctx->lapic_valid) {
            struct kvm_lapic_state klapic;
            memcpy(&klapic, kctx->lapic_data, sizeof(klapic));
            ioctl(cpu->kvm_fd, KVM_SET_LAPIC, &klapic);
        }
        if (kctx->vcpu_events_valid) {
            struct kvm_vcpu_events kev;
            memcpy(&kev, kctx->vcpu_events_data, sizeof(kev));
            ioctl(cpu->kvm_fd, KVM_SET_VCPU_EVENTS, &kev);
        }
        if (kctx->fpu_valid) {
            struct kvm_fpu fpu;
            memcpy(&fpu, kctx->fpu_data, sizeof(fpu));
            ioctl(cpu->kvm_fd, KVM_SET_FPU, &fpu);
        }
        if (kctx->xcrs_valid) {
            struct kvm_xcrs xcrs;
            memcpy(&xcrs, kctx->xcrs_data, sizeof(xcrs));
            ioctl(cpu->kvm_fd, KVM_SET_XCRS, &xcrs);
        }
        if (kctx->mp_state_valid) {
            struct kvm_mp_state mp = { .mp_state = kctx->mp_state };
            ioctl(cpu->kvm_fd, KVM_SET_MP_STATE, &mp);
        }
        ioctl(cpu->kvm_fd, KVM_GET_SREGS, &ksregs);
        wavevm_apply_arch_sregs(&ksregs, (const struct kvm_sregs *)kctx->sregs_data);
        ioctl(cpu->kvm_fd, KVM_SET_SREGS, &ksregs);
        ioctl(cpu->kvm_fd, KVM_SET_REGS, &kregs);

        /* [V30 TSC 同步] 将 slave 端执行后的 TSC 值写回 master 本地 vCPU。
         * 没有这一步，master 本地 KVM 的 TSC 停留在 dispatch 前的旧值，
         * 而 kvmclock 用 TSC delta 计算 wall time，旧值导致负 delta
         * 产生 ~UINT64_MAX ns 的时间戳，Guest 内核 hang。 */
        if (kctx->tsc_valid) {
            struct {
                struct kvm_msrs info;
                struct kvm_msr_entry entries[9];
            } msr_data;
            int n = 3;
            memset(&msr_data, 0, sizeof(msr_data));
            msr_data.entries[0].index = 0x10;       /* MSR_IA32_TSC */
            msr_data.entries[0].data  = kctx->tsc_value;
            msr_data.entries[1].index = 0x6e0;      /* MSR_IA32_TSCDEADLINE */
            msr_data.entries[1].data  = kctx->tsc_deadline;
            msr_data.entries[2].index = 0xC0000102;  /* MSR_KERNEL_GS_BASE */
            msr_data.entries[2].data  = kctx->kernel_gs_base;
            /* s23g5: extend when slave/FE filled msr_ext_valid */
            if (kctx->msr_ext_valid & 0x1) {
                msr_data.entries[n].index = 0xC0000101; /* GS_BASE */
                msr_data.entries[n].data  = kctx->gs_base;
                n++;
            }
            if (kctx->msr_ext_valid & 0x2) {
                msr_data.entries[n].index = 0x1b; /* APIC_BASE */
                msr_data.entries[n].data  = kctx->apic_base;
                n++;
            }
            if (kctx->msr_ext_valid & 0x4) {
                msr_data.entries[n].index = 0xC0000081;
                msr_data.entries[n].data  = kctx->star;
                n++;
                msr_data.entries[n].index = 0xC0000082;
                msr_data.entries[n].data  = kctx->lstar;
                n++;
                msr_data.entries[n].index = 0xC0000083;
                msr_data.entries[n].data  = kctx->cstar;
                n++;
                msr_data.entries[n].index = 0xC0000084;
                msr_data.entries[n].data  = kctx->sfmask;
                n++;
            }
            msr_data.info.nmsrs = n;
            ioctl(cpu->kvm_fd, KVM_SET_MSRS, &msr_data);
        }

        // 5. Replay IO/MMIO
        struct kvm_run *run = cpu->kvm_run;
        run->exit_reason = kctx->exit_reason;

        if (kctx->exit_reason == KVM_EXIT_IO) {
            /* [FIX] Direct IO replay using kctx->io.data -- bypass run->io.data_offset
             * which is uninitialized for remote vCPUs (never did local KVM_RUN). */
            uint16_t port = kctx->io.port;
            int is_write = (kctx->io.direction == KVM_EXIT_IO_OUT);
            uint8_t io_buf[64];
            size_t io_bytes = (size_t)kctx->io.size * kctx->io.count;
            if (io_bytes > sizeof(kctx->io.data)) io_bytes = sizeof(kctx->io.data);
            if (io_bytes > sizeof(io_buf)) io_bytes = sizeof(io_buf);
            if (is_write) {
                memcpy(io_buf, kctx->io.data, io_bytes);
            }
            run->io.direction = kctx->io.direction;
            run->io.size      = kctx->io.size;
            run->io.port      = kctx->io.port;
            run->io.count     = kctx->io.count;
            if (kctx->io.size != 1 && kctx->io.size != 2 &&
                kctx->io.size != 4 && kctx->io.size != 8) { return; }
            if (kctx->io.count == 0 || kctx->io.count > 8) { return; }
            qemu_mutex_lock_iothread();
            for (uint32_t i = 0; i < kctx->io.count; i++) {
                address_space_rw(&address_space_io, port, MEMTXATTRS_UNSPECIFIED,
                                 io_buf + i * kctx->io.size, kctx->io.size, is_write);
            }
            qemu_mutex_unlock_iothread();
            /* IO IN: copy device response for next request serialization */
            if (!is_write) {
                static int io_replay_dbg[MAX_VCPUS] = {0};
                int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
                if (io_replay_dbg[ci] < 40) {
                    fprintf(stderr,
                            "[WVM-IO-REPLAY] cpu=%d port=0x%x size=%u count=%u data0=0x%02x\n",
                            cpu->cpu_index, port, kctx->io.size, kctx->io.count,
                            io_buf[0]);
                    io_replay_dbg[ci]++;
                }
                memcpy(kctx->io.data, io_buf, io_bytes);
                /* Stash for next remote SEND — data_offset is unset on remote vCPUs. */
                if (io_bytes > sizeof(g_wavevm_pending_io_data[ci])) {
                    io_bytes = sizeof(g_wavevm_pending_io_data[ci]);
                }
                memcpy(g_wavevm_pending_io_data[ci], io_buf, io_bytes);
                g_wavevm_pending_io_len[ci] = io_bytes;
                g_wavevm_pending_io_valid[ci] = 1;
                if (run->io.data_offset < sizeof(struct kvm_run) ||
                    run->io.data_offset + io_bytes > 12288) {
                    /* Point into the kvm_run mmap page so a future local path
                     * that trusts data_offset stays safe too. */
                    run->io.data_offset = sizeof(struct kvm_run);
                }
                if (run->io.data_offset >= sizeof(struct kvm_run) &&
                    run->io.data_offset + io_bytes <= 12288) {
                    memcpy((uint8_t *)run + run->io.data_offset, io_buf, io_bytes);
                }
            }
        } 
        else if (kctx->exit_reason == KVM_EXIT_MMIO) {
            uint8_t mmio_buf[8];
            hwaddr addr = kctx->mmio.phys_addr;
            int mmio_wr = kctx->mmio.is_write;
            unsigned len = kctx->mmio.len;
            bool lapic_mmio = (addr >= 0xfee00000ULL && addr < 0xfee01000ULL);
            if (len != 1 && len != 2 && len != 4 && len != 8) { return; }
            if (lapic_mmio &&
                wavevm_kvm_apply_remote_lapic_mmio(cpu, kctx, run)) {
                /* FE in-kernel LAPIC updated; skip address_space_rw. */
            } else {
                if (mmio_wr) {
                    memcpy(mmio_buf, kctx->mmio.data, len);
                }
                if (lapic_mmio) {
                    static int lapic_replay_dbg[MAX_VCPUS];
                    int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
                    if (lapic_replay_dbg[ci] < 80) {
                        fprintf(stderr,
                                "[WVM-MMIO-REPLAY] cpu=%d pa=0x%llx wr=%d len=%u data=0x",
                                cpu->cpu_index,
                                (unsigned long long)addr,
                                mmio_wr, len);
                        for (int bi = (int)len - 1; bi >= 0; bi--) {
                            fprintf(stderr, "%02x", kctx->mmio.data[bi]);
                        }
                        fprintf(stderr, "\n");
                        lapic_replay_dbg[ci]++;
                    }
                }
                qemu_mutex_lock_iothread();
                address_space_rw(&address_space_memory, addr, MEMTXATTRS_UNSPECIFIED,
                                 mmio_buf, len, mmio_wr);
                qemu_mutex_unlock_iothread();
                if (!mmio_wr) {
                    memcpy(kctx->mmio.data, mmio_buf, len);
                    memcpy(run->mmio.data, mmio_buf, len);
                }
                run->mmio.phys_addr = addr;
                run->mmio.len = len;
                run->mmio.is_write = mmio_wr;
            }
        }
        else if (kctx->exit_reason == WVM_EXIT_PREEMPT) {
            X86CPU *x86cpu = X86_CPU(cpu);
            int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
            cpu->halted = 0;
            cpu->exception_index = 0;
            x86cpu->env.mp_state = KVM_MP_STATE_RUNNABLE;
            {
                struct kvm_mp_state run_mp = { .mp_state = KVM_MP_STATE_RUNNABLE };
                ioctl(cpu->kvm_fd, KVM_SET_MP_STATE, &run_mp);
            }
            /* s23g: remote AP busy-preempt → one bounded FE local drain so
             * in-kernel LAPIC ticks reach the guest (slave has no irqchip). */
            if (cpu->cpu_index > 0) {
                ap_kvm_preempt_drain[ci] = 1;
            }
        }
        /* [FIX] HLT: halt the vCPU so QEMU waits for timer interrupt.
         *
         * But if the slave already returned a pending injected interrupt
         * (for example, a No-IRQCHIP LAPIC timer synthesized into
         * vcpu_events.interrupt), forcing HALTED here would immediately
         * bury that wake source again. Keep the vCPU RUNNABLE in that case
         * so the next local KVM entry can consume the interrupt. */
        else if (kctx->exit_reason == KVM_EXIT_HLT) {
            int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
            bool keep_pending_irq = false;
            bool lapic_timer_expired = false;

            /*
             * s23g4: interrupt.nr alone is NOT a pending inject (stale field).
             * Only injected/nmi/exception.pending count. Separately: slave has
             * no irqchip, so a remote HLT ACK with LAPIC timer cur==0 means the
             * tick already fired on the bounced LAPIC image — FE must drain
             * local kvm_cpu_exec so in-kernel irqchip can inject. Without that
             * drain, keep_pending via stale nr kept AP RUNNABLE and re-remotely
             * spun HLT forever (pass3: cur=0, zero WVM-KVM-DRAIN, login MISSING).
             */
            if (kctx->vcpu_events_valid) {
                const struct kvm_vcpu_events *kev =
                    (const struct kvm_vcpu_events *)kctx->vcpu_events_data;
                keep_pending_irq = kev->interrupt.injected ||
                                   kev->nmi.pending ||
                                   kev->exception.pending ||
                                   kev->exception.injected;
            }
            if (kctx->lapic_valid) {
                const struct kvm_lapic_state *lapic =
                    (const struct kvm_lapic_state *)kctx->lapic_data;
                uint32_t lvt = wavevm_lapic_reg32(lapic, 0x320);
                uint32_t init = wavevm_lapic_reg32(lapic, 0x380);
                uint32_t cur = wavevm_lapic_reg32(lapic, 0x390);
                uint32_t svr = wavevm_lapic_reg32(lapic, 0x0f0);
                /* LVT mask=bit16; SVR software-enable=bit8; cur==0 + init!=0 => fired */
                if ((svr & 0x100) && !(lvt & 0x10000) && init != 0 && cur == 0) {
                    lapic_timer_expired = true;
                }
            }

            if (keep_pending_irq || lapic_timer_expired) {
                X86CPU *x86cpu = X86_CPU(cpu);
                cpu->halted = 0;
                cpu->exception_index = 0;
                x86cpu->env.mp_state = KVM_MP_STATE_RUNNABLE;
                if (ci < MAX_VCPUS) {
                    ap_hlt_pending_irq[ci] = 1;
                    /* Main loop consumes ap_kvm_preempt_drain for local exec. */
                    if (cpu->cpu_index > 0) {
                        ap_kvm_preempt_drain[ci] = 1;
                    }
                }
                {
                    struct kvm_mp_state run_mp = { .mp_state = KVM_MP_STATE_RUNNABLE };
                    ioctl(cpu->kvm_fd, KVM_SET_MP_STATE, &run_mp);
                }
                {
                    static int hlt_drain_dbg[MAX_VCPUS];
                    if (ci < MAX_VCPUS && hlt_drain_dbg[ci] < 24) {
                        fprintf(stderr,
                                "[WVM-HLT-DRAIN-ARM] cpu=%d inj=%d lapic_exp=%d\n",
                                cpu->cpu_index,
                                keep_pending_irq ? 1 : 0,
                                lapic_timer_expired ? 1 : 0);
                        hlt_drain_dbg[ci]++;
                    }
                }
            } else {
                if (ci < MAX_VCPUS) {
                    ap_hlt_pending_irq[ci] = 0;
                }
                cpu->halted = 1;
                cpu->exception_index = EXCP_HLT;
                {
                    struct kvm_mp_state halt_mp = { .mp_state = KVM_MP_STATE_HALTED };
                    ioctl(cpu->kvm_fd, KVM_SET_MP_STATE, &halt_mp);
                }
            }
        }
    }
}

/* 
 * [物理意图] 重新定义 vCPU 的“心脏跳动规律”。
 * [关键逻辑] 拦截标准的 KVM_RUN 循环，根据调度策略决定本轮指令是交给本地 KVM 还是进行远程上下文序列化。
 * [后果] 这是超级虚拟机的总节拍器。它保证了在异构算力环境下，vCPU 能够平滑地在本地与远程之间切换执行流。
 */
/*
 * WaveVM vCPU thread function -- aligned with standard QEMU MTTCG skeleton.
 *
 * Key difference from vanilla MTTCG: the scheduling branch that routes
 * vCPUs to either local cpu_exec() or remote wavevm_remote_exec() based
 * on g_wvm_local_split.  Everything else (iothread lock discipline,
 * cpu_exec_start/end, exit_request, qemu_wait_io_event every iteration)
 * follows the standard QEMU pattern so that vm_start()/resume_all_vcpus()
 * and the full VM lifecycle management work correctly.
 */
static void *wavevm_cpu_thread_fn(void *arg) {
    CPUState *cpu = arg;
    char *role = getenv("WVM_ROLE");
    bool is_slave = (role && strcmp(role, "SLAVE") == 0);

    rcu_register_thread();
    /*
     * Register TCG context for all vCPUs.  With mttcg_enabled=true
     * (set in wavevm_init_tcg_region_once), tcg_n_regions() returns
     * max_cpus so every thread gets its own code-gen region.
     * Even "remote" APs need this because they run SIPI trampolines
     * locally via cpu_exec() before being dispatched to slaves.
     */
    if (!kvm_enabled()) {
        tcg_register_thread();
    }

    qemu_mutex_lock_iothread();
    qemu_thread_get_self(cpu->thread);
    cpu->thread_id = qemu_get_thread_id();
    cpu->can_do_io = 1;
    current_cpu = cpu;
    cpu_thread_signal_created(cpu);
    qemu_guest_random_seed_thread_part2(cpu->random_seed);

    /* Slave: hand off to dedicated slave loop (holds its own lock discipline) */
    if (is_slave) {
        qemu_mutex_unlock_iothread();
        wavevm_slave_vcpu_loop(cpu);
        goto out;
    }

    /* KVM bootstrap for this vCPU (if KVM is the underlying engine) */
    if (kvm_enabled()) {
        kvm_init_vcpu(cpu, &error_fatal);
        kvm_init_cpu_signals(cpu);
        cpu_synchronize_state(cpu);
    }

    /*
     * Trigger an exit from the first cpu_exec() call so we cycle through
     * qemu_wait_io_event() and properly synchronize with vm_start().
     */
    cpu->exit_request = 1;

    static int bsp_dbg_count = 0;
    static int bsp_cant_run_count = 0;
    /*
     * Main vCPU loop -- mirrors tcg_cpu_thread_fn (MTTCG) structure.
     * The iothread lock is held at the top of every iteration.
     */
    do {
        if (cpu_can_run(cpu)) {
            /* Remote vCPU: forward to Slave via RPC */
            bool force_local = wavevm_tcg_consume_force_local(cpu);
            if (ops.schedule_policy(cpu->cpu_index) == 1 && !force_local) {
                qemu_mutex_unlock_iothread();
                wavevm_remote_exec(cpu);
                /* s23g6: count only real remote RPC, not HALT-WAKE/SIPI park. */
                if (cpu->cpu_index < MAX_VCPUS &&
                    g_wavevm_remote_rpc_ok[cpu->cpu_index]) {
                    wavevm_tcg_note_remote_done(cpu);
                }
                qemu_mutex_lock_iothread();
                /*
                 * s23g KVM busy-AP timer drain: after remote preempt the AP
                 * stays RUNNABLE. Slave has no irqchip, so briefly run local
                 * kvm_cpu_exec (10ms bound) so FE in-kernel LAPIC can deliver
                 * ticks / consume bounced LAPIC programming. Avoids dual-yes
                 * softlock/SSH-drop under sustained remote busy.
                 */
                /* s23g5: if remote left AP mid-kernel (CPL!=3), force a
                 * bounded local drain so SWAPGS/GS stay coherent before the
                 * next remote bounce (dual-yes DF with user RSP at error_entry). */
                if (kvm_enabled() && !cpu->halted && cpu->cpu_index > 0 &&
                    cpu->cpu_index < MAX_VCPUS) {
                    struct kvm_sregs sr_cpl;
                    if (ioctl(cpu->kvm_fd, KVM_GET_SREGS, &sr_cpl) == 0 &&
                        (sr_cpl.cs.selector & 3) != 3) {
                        ap_kvm_preempt_drain[cpu->cpu_index] = 1;
                    }
                }
                if (kvm_enabled() && !cpu->halted && cpu->cpu_index > 0 &&
                    cpu->cpu_index < MAX_VCPUS &&
                    (ap_kvm_preempt_drain[cpu->cpu_index] ||
                     ap_hlt_pending_irq[cpu->cpu_index])) {
                    int ci = cpu->cpu_index;
                    timer_t drain_timer;
                    struct sigevent sev;
                    int timer_ok;
                    static int drain_dbg;
                    int cpl3_need = 0;
                    int drain_rounds = 0;
                    struct kvm_sregs sr_chk;

                    if (ioctl(cpu->kvm_fd, KVM_GET_SREGS, &sr_chk) == 0 &&
                        (sr_chk.cs.selector & 3) != 3) {
                        cpl3_need = 1;
                    }

                    ap_kvm_preempt_drain[ci] = 0;
                    ap_hlt_pending_irq[ci] = 0;
                    {
                        X86CPU *x86cpu = X86_CPU(cpu);
                        x86cpu->env.mp_state = KVM_MP_STATE_RUNNABLE;
                    }
                    memset(&sev, 0, sizeof(sev));
                    sev.sigev_notify = SIGEV_THREAD_ID;
                    sev.sigev_signo = SIGUSR1;
                    sev._sigev_un._tid = syscall(SYS_gettid);
                    timer_ok = (timer_create(CLOCK_MONOTONIC, &sev,
                                             &drain_timer) == 0);
                    if (timer_ok) {
                        struct itimerspec its = {0};
                        /* 10ms normal; 50ms when draining mid-kernel to CPL3 */
                        if (cpl3_need) {
                            its.it_value.tv_nsec = 50000000L;
                        } else {
                            its.it_value.tv_nsec = 10000000L;
                        }
                        timer_settime(drain_timer, 0, &its, NULL);
                    }
                    if (drain_dbg++ < 32) {
                        fprintf(stderr,
                                "[WVM-KVM-DRAIN] cpu=%d bounded local "
                                "kvm_cpu_exec after preempt/hlt cpl3=%d\n",
                                ci, cpl3_need);
                    }
                    /* Up to 5 short rounds until CPL3 or halt (still bounded). */
                    do {
                        (void)kvm_cpu_exec(cpu);
                        drain_rounds++;
                        if (cpu->halted || !cpl3_need) {
                            break;
                        }
                        if (ioctl(cpu->kvm_fd, KVM_GET_SREGS, &sr_chk) == 0 &&
                            (sr_chk.cs.selector & 3) == 3) {
                            break;
                        }
                    } while (drain_rounds < 5 && timer_ok);
                    if (timer_ok) {
                        struct itimerspec its = {0};
                        timer_settime(drain_timer, 0, &its, NULL);
                        timer_delete(drain_timer);
                    }
                    /* Stay RUNNABLE for next remote unless HLT parked us. */
                    if (!cpu->halted) {
                        X86CPU *x86cpu = X86_CPU(cpu);
                        struct kvm_mp_state run_mp = {
                            .mp_state = KVM_MP_STATE_RUNNABLE
                        };
                        x86cpu->env.mp_state = KVM_MP_STATE_RUNNABLE;
                        ioctl(cpu->kvm_fd, KVM_SET_MP_STATE, &run_mp);
                    }
                }
                /* [FIX] If remote exec returned HLT, wait for timer interrupt.
                 * Release iothread lock so main loop can process PIT timers.
                 * PIT fires at ~18.2Hz; poll every 1ms for interrupt_request. */
                if (cpu->halted) {
                    /* Check if remote_exec signaled first-RUNNABLE for local trampoline */
                    if (cpu->exception_index == 0x10003) {
                        cpu->exception_index = 0;
                        cpu->halted = 0;
                        /* AP just became RUNNABLE after SIPI. Run the BIOS SMP
                         * trampoline LOCALLY so the AP can:
                         * - Increment the BSP's AP counter in shared memory
                         * - Park itself with HLT
                         * After this, ap_did_local_sipi is set so future
                         * dispatches go to the remote slave. */
                        fprintf(stderr, "[WVM-SIPI] cpu=%d doing LOCAL kvm_cpu_exec for SIPI trampoline\n",
                                cpu->cpu_index);
                        /* Sync QEMU's internal mp_state from KVM before exec.
                         * Without this, kvm_arch_put_registers would push stale
                         * UNINITIALIZED and overwrite KVM's RUNNABLE state. */
                        {
                            X86CPU *x86cpu = X86_CPU(cpu);
                            x86cpu->env.mp_state = KVM_MP_STATE_RUNNABLE;
                        }
                        cpu_synchronize_state(cpu);
                        /* Two-phase SIPI trampoline execution:
                         * Phase 1: kvm_cpu_exec runs partial trampoline, returns
                         *          EXCP_INTERRUPT (signal preemption). AP has NOT
                         *          completed yet — SMP counter not incremented.
                         * Phase 2: kvm_cpu_exec continues trampoline, AP increments
                         *          counter and HLTs. But KVM_RUN blocks forever on
                         *          HLT. Use timer_create(SIGEV_THREAD_ID) to send
                         *          SIGUSR1 (SIG_IPI) to THIS thread after 2s,
                         *          kicking KVM_RUN out. Then check mp_state. */
                        {
                            /* Phase 1 */
                            int sipi_r = kvm_cpu_exec(cpu);
                            struct kvm_mp_state mp = {0};
                            ioctl(cpu->kvm_fd, KVM_GET_MP_STATE, &mp);
                            fprintf(stderr, "[WVM-SIPI] cpu=%d phase1 ret=%d halted=%d kvm_mp=%d\n",
                                    cpu->cpu_index, sipi_r, cpu->halted, mp.mp_state);

                            if (!cpu->halted && mp.mp_state != KVM_MP_STATE_HALTED) {
                                /* Phase 2: create per-thread timer to kick us out */
                                timer_t sipi_timer;
                                struct sigevent sev;
                                memset(&sev, 0, sizeof(sev));
                                sev.sigev_notify = SIGEV_THREAD_ID;
                                sev.sigev_signo = SIGUSR1;
                                sev._sigev_un._tid = syscall(SYS_gettid);
                                if (timer_create(CLOCK_MONOTONIC, &sev, &sipi_timer) == 0) {
                                    struct itimerspec its = {0};
                                    its.it_value.tv_sec = 2;
                                    timer_settime(sipi_timer, 0, &its, NULL);

                                    fprintf(stderr, "[WVM-SIPI] cpu=%d phase2 entering kvm_cpu_exec with 2s timer\n",
                                            cpu->cpu_index);
                                    int sipi_r2 = kvm_cpu_exec(cpu);

                                    /* Disarm and delete timer */
                                    memset(&its, 0, sizeof(its));
                                    timer_settime(sipi_timer, 0, &its, NULL);
                                    timer_delete(sipi_timer);

                                    ioctl(cpu->kvm_fd, KVM_GET_MP_STATE, &mp);
                                    fprintf(stderr, "[WVM-SIPI] cpu=%d phase2 ret=%d halted=%d kvm_mp=%d\n",
                                            cpu->cpu_index, sipi_r2, cpu->halted, mp.mp_state);
                                } else {
                                    fprintf(stderr, "[WVM-SIPI] cpu=%d timer_create failed errno=%d\n",
                                            cpu->cpu_index, errno);
                                }
                            }

                            /* Park the AP */
                            if (!cpu->halted) {
                                if (mp.mp_state == KVM_MP_STATE_HALTED) {
                                    cpu->halted = 1;
                                    fprintf(stderr, "[WVM-SIPI] cpu=%d KVM HALTED, parking AP\n",
                                            cpu->cpu_index);
                                } else {
                                    /* Trampoline should be done by now (2s is plenty).
                                     * Force halt as last resort. */
                                    struct kvm_mp_state halt_mp = { .mp_state = KVM_MP_STATE_HALTED };
                                    ioctl(cpu->kvm_fd, KVM_SET_MP_STATE, &halt_mp);
                                    cpu->halted = 1;
                                    fprintf(stderr, "[WVM-SIPI] cpu=%d force-halted after phase2 (mp was %d)\n",
                                            cpu->cpu_index, mp.mp_state);
                                }
                            } else {
                                fprintf(stderr, "[WVM-SIPI] cpu=%d naturally halted\n", cpu->cpu_index);
                            }
                        }
                        /* Mark trampoline as done */
                        if (cpu->cpu_index < MAX_VCPUS) {
                            ap_did_local_sipi[cpu->cpu_index] = 1;
                        }
                        continue;
                    }
                    /* Check MP state: AP in SIPI-wait should stay halted
                     * until SIPI is delivered. */
                    if (kvm_enabled()) {
                        struct kvm_mp_state mp;
                        ioctl(cpu->kvm_fd, KVM_GET_MP_STATE, &mp);

                        if (mp.mp_state != KVM_MP_STATE_RUNNABLE &&
                            cpu->cpu_index < MAX_VCPUS &&
                            ap_did_local_sipi[cpu->cpu_index] &&
                            !ap_did_os_sipi[cpu->cpu_index]) {
                            /* AP is HALTED after BIOS trampoline, waiting for
                             * Linux's INIT+SIPI. KVM_GET_MP_STATE alone may not
                             * reliably process pending LAPIC events on all host
                             * kernels. Use real KVM_RUN: in HALTED state, KVM
                             * efficiently waits for interrupt (like HLT). When
                             * INIT+SIPI arrives, KVM processes it, transitions
                             * to RUNNABLE, and starts executing the OS trampoline.
                             * Use a timer to bound the wait. */
                            static int os_sipi_dbg = 0;
                            if (os_sipi_dbg < 10) {
                                fprintf(stderr, "[OS-SIPI] cpu=%d entering kvm_cpu_exec "
                                        "for OS SIPI (mp=%d)\n",
                                        cpu->cpu_index, mp.mp_state);
                                os_sipi_dbg++;
                            }

                            /* Sync QEMU mp_state from KVM before exec */
                            {
                                X86CPU *x86cpu = X86_CPU(cpu);
                                x86cpu->env.mp_state = mp.mp_state;
                            }

                            /* Create per-thread timer: 5s to receive INIT+SIPI
                             * and complete the Linux AP bringup. */
                            timer_t os_sipi_timer;
                            struct sigevent sev;
                            memset(&sev, 0, sizeof(sev));
                            sev.sigev_notify = SIGEV_THREAD_ID;
                            sev.sigev_signo = SIGUSR1;
                            sev._sigev_un._tid = syscall(SYS_gettid);

                            if (timer_create(CLOCK_MONOTONIC, &sev, &os_sipi_timer) == 0) {
                                struct itimerspec its = {0};
                                its.it_value.tv_sec = 5;
                                timer_settime(os_sipi_timer, 0, &its, NULL);

                                /* Run AP: KVM_RUN in HALTED state waits for
                                 * interrupt. INIT+SIPI wakes it, AP executes
                                 * Linux trampoline locally until HLT or timer. */
                                cpu->halted = 0;
                                int os_r = kvm_cpu_exec(cpu);

                                /* Disarm and delete timer */
                                memset(&its, 0, sizeof(its));
                                timer_settime(os_sipi_timer, 0, &its, NULL);
                                timer_delete(os_sipi_timer);

                                ioctl(cpu->kvm_fd, KVM_GET_MP_STATE, &mp);
                                if (os_sipi_dbg < 20) {
                                    fprintf(stderr, "[OS-SIPI] cpu=%d kvm_cpu_exec ret=%d "
                                            "halted=%d mp=%d\n",
                                            cpu->cpu_index, os_r,
                                            cpu->halted, mp.mp_state);
                                    os_sipi_dbg++;
                                }

                                if (mp.mp_state == KVM_MP_STATE_RUNNABLE) {
                                    /* AP woke up but didn't HLT yet — needs more
                                     * execution. Loop kvm_cpu_exec with timer. */
                                    struct itimerspec its2 = {0};
                                    its2.it_value.tv_sec = 5;
                                    if (timer_create(CLOCK_MONOTONIC, &sev, &os_sipi_timer) == 0) {
                                        timer_settime(os_sipi_timer, 0, &its2, NULL);
                                        int os_r2 = kvm_cpu_exec(cpu);
                                        memset(&its2, 0, sizeof(its2));
                                        timer_settime(os_sipi_timer, 0, &its2, NULL);
                                        timer_delete(os_sipi_timer);
                                        ioctl(cpu->kvm_fd, KVM_GET_MP_STATE, &mp);
                                        fprintf(stderr, "[OS-SIPI] cpu=%d phase2 ret=%d "
                                                "halted=%d mp=%d\n",
                                                cpu->cpu_index, os_r2,
                                                cpu->halted, mp.mp_state);
                                    }
                                }

                                /* Park the AP after OS trampoline */
                                if (mp.mp_state == KVM_MP_STATE_HALTED) {
                                    cpu->halted = 1;
                                    if (cpu->cpu_index < MAX_VCPUS)
                                        ap_did_os_sipi[cpu->cpu_index] = 1;
                                    fprintf(stderr, "[OS-SIPI] cpu=%d OS trampoline done, "
                                            "AP parked (HALTED). Ready for remote dispatch.\n",
                                            cpu->cpu_index);
                                } else if (mp.mp_state == KVM_MP_STATE_RUNNABLE) {
                                    /* AP is still running — dispatch remotely */
                                    cpu->halted = 0;
                                    if (cpu->cpu_index < MAX_VCPUS)
                                        ap_did_os_sipi[cpu->cpu_index] = 1;
                                    fprintf(stderr, "[OS-SIPI] cpu=%d OS trampoline RUNNABLE, "
                                            "switching to remote dispatch\n",
                                            cpu->cpu_index);
                                    {
                                        X86CPU *x86cpu = X86_CPU(cpu);
                                        x86cpu->env.mp_state = KVM_MP_STATE_RUNNABLE;
                                    }
                                    cpu_synchronize_state(cpu);
                                } else {
                                    /* Timer expired, no SIPI received */
                                    cpu->halted = 1;
                                    fprintf(stderr, "[OS-SIPI] cpu=%d timer expired, "
                                            "no OS SIPI (mp=%d)\n",
                                            cpu->cpu_index, mp.mp_state);
                                }
                            } else {
                                fprintf(stderr, "[OS-SIPI] cpu=%d timer_create failed "
                                        "errno=%d, fallback to poll\n",
                                        cpu->cpu_index, errno);
                                qemu_mutex_unlock_iothread();
                                g_usleep(10000);
                                qemu_mutex_lock_iothread();
                            }
                            continue;
                        }

                        if (mp.mp_state == KVM_MP_STATE_RUNNABLE) {
                            /* INIT+SIPI delivered! AP should now run the OS
                             * SMP trampoline. Unhalt for remote dispatch. */
                            cpu->halted = 0;
                            fprintf(stderr, "[WVM-WAKE] cpu=%d woken by OS SIPI "
                                    "(mp_state now RUNNABLE)\n", cpu->cpu_index);
                            {
                                X86CPU *x86cpu = X86_CPU(cpu);
                                x86cpu->env.mp_state = KVM_MP_STATE_RUNNABLE;
                            }
                            cpu_synchronize_state(cpu);
                            continue;
                        } else if (cpu->cpu_index < MAX_VCPUS &&
                                   ap_did_local_sipi[cpu->cpu_index] &&
                                   ap_did_os_sipi[cpu->cpu_index] &&
                                   mp.mp_state == KVM_MP_STATE_HALTED) {
                            /* Post-OS-SIPI idle APs should use QEMU's normal
                             * halted wakeup path. Spinning here on MP state
                             * can miss kick/interrupt driven wakeups and trap
                             * the AP in a HALT-WAKE loop forever. */
                            cpu->halted = 1;
                        } else {
                            /* Still waiting (non-KVM or pre-BIOS-SIPI) */
                            static int poll_dbg = 0;
                            if (poll_dbg < 20) {
                                fprintf(stderr, "[WVM-POLL] cpu=%d halted mp_state=%d "
                                        "(waiting for RUNNABLE)\n",
                                        cpu->cpu_index, mp.mp_state);
                                poll_dbg++;
                            }
                            qemu_mutex_unlock_iothread();
                            g_usleep(10000);
                            qemu_mutex_lock_iothread();
                            continue;
                        }
                    }
                    /* AP is halted (from remote HLT or local trampoline HLT).
                     * Stay parked until an external interrupt (IPI) wakes it.
                     * This is the normal AP parking state after BIOS SMP init. */
                    {
                    /* In TCG mode, also wake on SIPI/INIT (software APIC
                     * delivers these as interrupt_request bits, not via
                     * KVM MP state).  KVM path: only HARD|POLL needed
                     * (SIPI is handled by KVM MP state transitions above).
                     * TCG path: POLL is useless for parked APs — it just
                     * polls the APIC which has no pending IRQs for APs. */
                    uint32_t wake_mask = CPU_INTERRUPT_HARD;
                    if (kvm_enabled()) {
                        wake_mask |= CPU_INTERRUPT_POLL;
                    } else {
                        wake_mask |= CPU_INTERRUPT_SIPI | CPU_INTERRUPT_INIT;
                    }
                    if (cpu->interrupt_request & wake_mask) {
                        cpu->halted = 0;
                        fprintf(stderr, "[WVM-WAKE] cpu=%d woken by interrupt (irq=0x%x)\n",
                                cpu->cpu_index, cpu->interrupt_request);
                    } else {
                        /*
                         * No interrupt: stay halted, but still enter QEMU's
                         * normal wait path so queued run_on_cpu work and
                         * kicks are processed while the AP is parked.
                         */
                        qemu_wait_io_event(cpu);
                        continue;
                    }
                    }
                }
            }
            /* Local vCPU: 复用 QEMU 原生 kvm_cpu_exec()
             * 包含完整的 kvm_arch_pre_run (中断注入/APIC 同步)、
             * kvm_arch_post_run (状态回收)、kvm_arch_put_registers
             * (脏寄存器推送) 以及全部 exit reason 处理。
             */
            else if (kvm_enabled()) {
                if (bsp_dbg_count < 20) {
                    fprintf(stderr, "[BSP-DBG] cpu=%d iter=%d halted=%d stop=%d exit_req=%d run->exit=%d\n",
                            cpu->cpu_index, bsp_dbg_count, cpu->halted, cpu->stop,
                            cpu->exit_request, cpu->kvm_run ? cpu->kvm_run->exit_reason : -1);
                }
                int r = kvm_cpu_exec(cpu);
                if (bsp_dbg_count < 200) {
                    struct kvm_regs bsp_kr;
                    struct kvm_sregs bsp_sr;
                    ioctl(cpu->kvm_fd, KVM_GET_REGS, &bsp_kr);
                    ioctl(cpu->kvm_fd, KVM_GET_SREGS, &bsp_sr);
                    fprintf(stderr, "[BSP-DBG] cpu=%d iter=%d ret=%d rip=0x%llx cs=0x%x/0x%llx rfl=0x%llx rax=0x%llx halted=%d\n",
                            cpu->cpu_index, bsp_dbg_count, r,
                            (unsigned long long)bsp_kr.rip,
                            bsp_sr.cs.selector, (unsigned long long)bsp_sr.cs.base,
                            (unsigned long long)bsp_kr.rflags,
                            (unsigned long long)bsp_kr.rax,
                            cpu->halted);
                    bsp_dbg_count++;
                }
                if (r == EXCP_DEBUG) {
                    cpu_handle_guest_debug(cpu);
                }
            } else {
                /* TCG local execution */
                int r;
                int ci = cpu->cpu_index < MAX_VCPUS ? cpu->cpu_index : 0;
                static int local_tcg_dbg[MAX_VCPUS];
                int dbg = local_tcg_dbg[ci];
                qemu_mutex_unlock_iothread();
                wavevm_tcg_local_slice_enter();
                wavevm_tcg_clear_stale_exit(cpu);
                cpu_exec_start(cpu);
                r = cpu_exec(cpu);
                cpu_exec_end(cpu);
                wavevm_tcg_local_slice_leave();
                wavevm_tcg_note_local_done(cpu);
                wavevm_tcg_clear_force_local_if_progress(cpu);
                qemu_mutex_lock_iothread();

                if (dbg < 80 || (dbg < 2000 && (dbg % 200) == 0)) {
                    X86CPU *x86cpu = X86_CPU(cpu);
                    CPUX86State *env = &x86cpu->env;
                    uint32_t lock_word = 0;
                    int lock_ret = cpu_memory_rw_debug(cpu, env->regs[R_EDI],
                                                       (uint8_t *)&lock_word,
                                                       sizeof(lock_word), 0);
                    fprintf(stderr,
                            "[WVM-TCG-LOCAL] cpu=%d n=%d ret=%d rip=0x%lx cs=0x%x "
                            "cr0=0x%lx rdi=0x%lx rax=0x%lx lock=0x%x/lr=%d "
                            "halted=%d intreq=0x%x exit_req=%d\n",
                            cpu->cpu_index, dbg, r,
                            (unsigned long)env->eip,
                            (unsigned)env->segs[R_CS].selector,
                            (unsigned long)env->cr[0],
                            (unsigned long)env->regs[R_EDI],
                            (unsigned long)env->regs[R_EAX],
                            lock_word, lock_ret,
                            cpu->halted,
                            (unsigned)cpu->interrupt_request,
                            cpu->exit_request);
                }
                if (dbg < 2000) {
                    local_tcg_dbg[ci] = dbg + 1;
                }

                switch (r) {
                case EXCP_DEBUG:
                    cpu_handle_guest_debug(cpu);
                    break;
                case EXCP_HALTED:
                    break;
                case EXCP_ATOMIC:
                    qemu_mutex_unlock_iothread();
                    wavevm_tcg_local_slice_enter();
                    cpu_exec_step_atomic(cpu);
                    wavevm_tcg_local_slice_leave();
                    qemu_mutex_lock_iothread();
                    break;
                default:
                    break;
                }
            }
        }

        qatomic_mb_set(&cpu->exit_request, 0);
        qemu_wait_io_event(cpu);
    } while (!cpu->unplug || cpu_can_run(cpu));

    if (kvm_enabled() && cpu->kvm_fd >= 0) {
        kvm_destroy_vcpu(cpu);
    }
    cpu_thread_signal_destroyed(cpu);
    qemu_mutex_unlock_iothread();
out:
    rcu_unregister_thread();
    return NULL;
}

/* 
 * [物理意图] 为每个逻辑核心开辟专属的“高速公路（Per-vCPU Socket Pool）”。
 * [关键逻辑] 在 vCPU 创建瞬间建立独立的 IPC 通道，彻底消除多核并发时的 Socket 锁竞争。
 * [后果] 实现了算力的线性扩展能力。这是 V30 支撑一亿核心的关键，保证了 vCPU 数量增加时通信延迟不上升。
 */
void wavevm_start_vcpu_thread(CPUState *cpu) {
    char thread_name[VCPU_THREAD_NAME_SIZE];
    WaveVMAccelState *s = WAVEVM_ACCEL(current_machine->accelerator);
    char *role = getenv("WVM_ROLE");

    static pthread_mutex_t g_init_lock = PTHREAD_MUTEX_INITIALIZER;

    if (!kvm_enabled()) {
        pthread_once(&g_wavevm_tcg_region_once, wavevm_init_tcg_region_once);
    }
    
    // 双重检查锁定 (Double-Checked Locking) 优化性能，或者直接加锁也行（毕竟只执行一次）
    if (!g_vcpu_socks) {
        pthread_mutex_lock(&g_init_lock);
        // 再次检查，防止在等待锁的过程中已被其他线程初始化
        if (!g_vcpu_socks) {
            g_configured_vcpus = (current_machine && current_machine->smp.cpus > 0) ?
                                 current_machine->smp.cpus : 1;
            
            g_vcpu_socks = g_malloc0(sizeof(int) * g_configured_vcpus);
            for (int i = 0; i < g_configured_vcpus; i++) {
                g_vcpu_socks[i] = -1;
            }
        }
        pthread_mutex_unlock(&g_init_lock);
    }

    if (s->mode == WVM_MODE_USER && !(role && strcmp(role, "SLAVE") == 0)) {
        // 动态边界检查
        if (cpu->cpu_index < g_configured_vcpus) {
            g_vcpu_socks[cpu->cpu_index] = connect_to_master_helper();
            if (g_vcpu_socks[cpu->cpu_index] < 0) {
                fprintf(stderr, "vCPU %d failed to connect master!\n", cpu->cpu_index);
                exit(1);
            }
        }
    } else {
        // Kernel 模式和 Slave 模式不使用此机制
        g_vcpu_socks[cpu->cpu_index] = -1; 
    }
    
    cpu->thread = g_malloc0(sizeof(QemuThread));
    cpu->halt_cond = g_malloc0(sizeof(QemuCond));
    qemu_cond_init(cpu->halt_cond);
    
    snprintf(thread_name, VCPU_THREAD_NAME_SIZE, "CPU %d/WVM", cpu->cpu_index);
    
    qemu_thread_create(cpu->thread, thread_name, wavevm_cpu_thread_fn, cpu, QEMU_THREAD_JOINABLE);
}
