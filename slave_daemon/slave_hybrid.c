/*
 * [IDENTITY] Slave Hybrid - The Execution Muscle
 * ---------------------------------------------------------------------------
 * 物理角色：远程节点上的"计算代理"。
 * 职责边界：
 * 1. 托管 KVM/TCG 上下文执行，将 IO/MMIO 退出转发回 Master。
 * 2. 实现 MPSC 脏页收割队列，将 Slave 端的写入异步同步给 Master。
 * 3. 驱动三通道 (CMD/REQ/PUSH) 隔离协议，防止网络拥塞。
 * 
 * [性能红线]
 * - 脏页收割频率严禁低于 1ms，否则 Master 端的读缓存失效太久。
 * - 严禁在 KVM_RUN 路径上引入同步网络等待。
 * ---------------------------------------------------------------------------
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <inttypes.h>
#include <linux/kvm.h>
#include <errno.h>
#include <sched.h>
#include <sys/wait.h>
#include <poll.h>
#include <sys/stat.h>
#include <time.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include "uthash.h"
#include "slave_vfio.h"

#include "../common_include/wavevm_protocol.h"
#include "../common_include/wavevm_block_chunk_store.h"
#include "../common_include/wavevm_ioctl.h"
#include "../common_include/wavevm_runtime_gate.h"
#include "../common_include/wavevm_executor_abi.h"
#include "../common_include/wavevm_executor_session.h"
#include "../common_include/wavevm_vcpu_handoff.h"
#include "../common_include/wavevm_x86_context.h"
#include "../node_runtime/executor_runtime.h"
#include "../node_runtime/kvm_page_cache.h"
#include "../node_runtime/kvm_execution_fetch.h"
#include "../node_runtime/memory_service.h"
#include "../node_runtime/runtime_context.h"

/* The unified node runtime owns this flag.  The weak definition keeps the
 * standalone executor linkable while the strong runtime definition is used
 * when master and executor share one process image. */
#if defined(__GNUC__)
__attribute__((weak))
#endif
volatile sig_atomic_t g_shutdown_requested = 0;

static void executor_request_process_shutdown(const char *why)
{
    fprintf(stderr, "[Hybrid] requesting process shutdown: %s\n",
            why ? why : "unknown");
    fflush(stderr);
    g_shutdown_requested = 1;
}


// --- 全局配置变量 ---
static int g_service_port = 9000;
static int g_nonblock_recv = 0;
/* KVM worker UDP fd — shutdown/poke unblocks recvmmsg on STOP (R4). */
static volatile sig_atomic_t g_kvm_worker_sock = -1;
static long g_num_cores = 0;
static int *g_tcg_session_fds;
/* Parent-owned FD to slave TCG push channel for post-install PAGE_PUSH. */
static int g_tcg_install_notify_fd = -1;
static int g_tcg_install_notify_owned = 0;
static pid_t *g_tcg_helper_pids;
static volatile int g_tcg_proxy_listening;
static int *g_tcg_proxy_socks;
static long g_tcg_proxy_sock_capacity;
static long g_tcg_proxy_sock_count;
static pthread_mutex_t g_tcg_proxy_sock_lock = PTHREAD_MUTEX_INITIALIZER;

/* G4: correlate PUSH_BARRIER cookies with PUSH_BARRIER_ACK from helpers. */
static pthread_mutex_t g_push_barrier_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_push_barrier_cond = PTHREAD_COND_INITIALIZER;
static uint64_t g_push_barrier_next = 1;
static uint64_t g_push_barrier_active_cookie = 0;
static int g_push_barrier_expect = 0;
static int g_push_barrier_got = 0;

static void mark_push_barrier_done(uint64_t cookie)
{
    pthread_mutex_lock(&g_push_barrier_lock);
    if (cookie == g_push_barrier_active_cookie && g_push_barrier_expect > 0) {
        g_push_barrier_got++;
        pthread_cond_broadcast(&g_push_barrier_cond);
    }
    pthread_mutex_unlock(&g_push_barrier_lock);
}

static uint64_t push_barrier_begin(int expect_count)
{
    uint64_t cookie;

    pthread_mutex_lock(&g_push_barrier_lock);
    cookie = g_push_barrier_next++;
    g_push_barrier_active_cookie = cookie;
    g_push_barrier_expect = expect_count > 0 ? expect_count : 1;
    g_push_barrier_got = 0;
    pthread_mutex_unlock(&g_push_barrier_lock);
    return cookie;
}

static int wait_for_push_barrier_cookie(uint64_t cookie, uint64_t timeout_us)
{
    struct timespec ts;

    if (timeout_us == 0) {
        timeout_us = 5000000ULL;
    }
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += (time_t)(timeout_us / 1000000ULL);
    ts.tv_nsec += (long)((timeout_us % 1000000ULL) * 1000ULL);
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&g_push_barrier_lock);
    while (!(g_push_barrier_active_cookie == cookie &&
             g_push_barrier_got >= g_push_barrier_expect)) {
        int rc = pthread_cond_timedwait(&g_push_barrier_cond,
                                        &g_push_barrier_lock, &ts);
        if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&g_push_barrier_lock);
            return -ETIMEDOUT;
        }
    }
    pthread_mutex_unlock(&g_push_barrier_lock);
    return 0;
}


/*
 * §6 / production: MSG_VCPU_RUN is request/reply. Track the external requester
 * so MSG_VCPU_EXIT from the local QEMU helper returns to that client instead of
 * only the NAT gateway (which may already be locked to the master). Do not let
 * VCPU_RUN itself lock the gateway — that would steal MEM upstream from master.
 */
#define TCG_PENDING_VCPU_REPLY_SLOTS 64
typedef struct {
    uint64_t req_id;
    struct sockaddr_in client;
    int valid;
} tcg_pending_vcpu_reply_t;
static tcg_pending_vcpu_reply_t g_tcg_pending_vcpu_reply[TCG_PENDING_VCPU_REPLY_SLOTS];
static pthread_mutex_t g_tcg_pending_vcpu_reply_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * N3: capacity + identity contract for VCPU_RUN reply demux.
 * Returns 0 on success, -1 if table full or req_id already owned by a
 * different client (no silent overwrite). Same client may refresh.
 */
static int tcg_pending_vcpu_reply_put(uint64_t req_id,
                                      const struct sockaddr_in *client)
{
    int i;
    int free_slot = -1;
    if (!client) {
        return -1;
    }
    pthread_mutex_lock(&g_tcg_pending_vcpu_reply_lock);
    for (i = 0; i < TCG_PENDING_VCPU_REPLY_SLOTS; i++) {
        if (g_tcg_pending_vcpu_reply[i].valid &&
            g_tcg_pending_vcpu_reply[i].req_id == req_id) {
            /* Same req_id: only same client may refresh; else refuse. */
            if (g_tcg_pending_vcpu_reply[i].client.sin_addr.s_addr ==
                    client->sin_addr.s_addr &&
                g_tcg_pending_vcpu_reply[i].client.sin_port ==
                    client->sin_port) {
                g_tcg_pending_vcpu_reply[i].client = *client;
                pthread_mutex_unlock(&g_tcg_pending_vcpu_reply_lock);
                return 0;
            }
            pthread_mutex_unlock(&g_tcg_pending_vcpu_reply_lock);
            return -1;
        }
        if (!g_tcg_pending_vcpu_reply[i].valid && free_slot < 0) {
            free_slot = i;
        }
    }
    if (free_slot < 0) {
        /* Full: refuse — never silently drop an in-flight requester. */
        pthread_mutex_unlock(&g_tcg_pending_vcpu_reply_lock);
        return -1;
    }
    g_tcg_pending_vcpu_reply[free_slot].req_id = req_id;
    g_tcg_pending_vcpu_reply[free_slot].client = *client;
    g_tcg_pending_vcpu_reply[free_slot].valid = 1;
    pthread_mutex_unlock(&g_tcg_pending_vcpu_reply_lock);
    return 0;
}

/* Peek without clearing — clear only after reply send succeeds (N3). */
static int tcg_pending_vcpu_reply_peek(uint64_t req_id,
                                       struct sockaddr_in *out)
{
    int i;
    int found = 0;
    if (!out) {
        return 0;
    }
    pthread_mutex_lock(&g_tcg_pending_vcpu_reply_lock);
    for (i = 0; i < TCG_PENDING_VCPU_REPLY_SLOTS; i++) {
        if (g_tcg_pending_vcpu_reply[i].valid &&
            g_tcg_pending_vcpu_reply[i].req_id == req_id) {
            *out = g_tcg_pending_vcpu_reply[i].client;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_tcg_pending_vcpu_reply_lock);
    return found;
}

static void tcg_pending_vcpu_reply_clear(uint64_t req_id)
{
    int i;
    pthread_mutex_lock(&g_tcg_pending_vcpu_reply_lock);
    for (i = 0; i < TCG_PENDING_VCPU_REPLY_SLOTS; i++) {
        if (g_tcg_pending_vcpu_reply[i].valid &&
            g_tcg_pending_vcpu_reply[i].req_id == req_id) {
            g_tcg_pending_vcpu_reply[i].valid = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_tcg_pending_vcpu_reply_lock);
}

static int g_ram_mb = 1024;
static uint64_t g_slave_ram_size = 1024UL * 1024 * 1024;
static int g_base_id = 0;
static uint32_t g_slave_vm_id = 0;

/* G1: echo FULL_VMID identity so master RX can recover u32 vm_id.
 * s23g13: callers pass req AFTER ntoh_header() (host-order epoch/slave_id/
 * target_id/req_id). Re-encode epoch to wire (network) order here. */
static void wvm_ack_copy_assoc(struct wvm_header *ack,
                               const struct wvm_header *req)
{
    if (!ack || !req)
        return;
    if (req->flags & WVM_FLAG_FULL_VMID) {
        ack->flags = (uint8_t)(ack->flags | WVM_FLAG_FULL_VMID);
        ack->epoch = htonl(req->epoch); /* req host-order → wire */
    }
}

/* G1: nonzero vm_id always FULL_VMID; never 8-bit pack for production VMs. */
static void wvm_slave_pack_src(struct wvm_header *hdr)
{
    if (!hdr)
        return;
    (void)wvm_header_pack_src(hdr, g_slave_vm_id, (uint32_t)g_base_id);
}

#define VCPU_EXIT_CACHE_SIZE 4096
#define VCPU_EXIT_CACHE_MAX_PACKET (sizeof(struct wvm_header) + sizeof(struct wvm_ipc_cpu_run_ack))

typedef struct {
    uint64_t req_id;
    uint32_t requester;
    int in_flight;
    int valid;
    size_t len;
    uint8_t data[VCPU_EXIT_CACHE_MAX_PACKET];
} vcpu_exit_cache_entry_t;

static vcpu_exit_cache_entry_t g_vcpu_exit_cache[VCPU_EXIT_CACHE_SIZE];
static pthread_mutex_t g_vcpu_exit_cache_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int slot;
    uint64_t guest_phys_addr;
    uint64_t size;
    uint8_t *hva;
    uint32_t flags;
    bool track_dirty;
} wvm_kvm_slot_t;

#define WVM_KVM_MAX_MEMSLOTS 32
#define WVM_KVM_MAX_VCPUS    WVM_CPU_ROUTE_TABLE_SIZE

static wvm_kvm_slot_t g_kvm_slots[WVM_KVM_MAX_MEMSLOTS];
static int g_kvm_slot_count = 0;
static uint8_t *g_kvm_reserved_hva = NULL;
static size_t g_kvm_reserved_size = 0;
// 用于通知 IRQ 线程 Master 地址已就绪
static pthread_cond_t g_master_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t g_master_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_master_ready = 0;
static struct sockaddr_in g_master_addr;
static char *g_vfio_config_path = NULL; 
static int g_executor_ctrl_port = 9001;
static const struct wvm_runtime_manifest_storage *
    g_executor_manifest_storage_ptr;
static struct wvm_runtime_gate *g_executor_runtime_gate_ptr;
static uint64_t g_executor_connection_id;
static int g_wvm_dev_fd = -1;
static int g_kernel_context_bind_failed = 0;
static int g_executor_local_only = 0;
static volatile sig_atomic_t g_executor_runtime_ready;
static pthread_mutex_t g_executor_handoff_id_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_executor_handoff_id;
static uint64_t g_executor_completed_fence_id;

/*
 * The local typed executor session reuses the execution core below without
 * making it know about sockets. Network workers leave this unset and retain
 * their existing reply path; typed sessions capture the completed ACK here.
 */
struct local_executor_capture {
    struct wvm_ipc_cpu_run_ack *ack;
    int completed;
};

static __thread struct local_executor_capture *t_local_executor_capture;

static int capture_local_executor_ack(
    const struct wvm_ipc_cpu_run_ack *ack)
{
    if (!t_local_executor_capture || !t_local_executor_capture->ack ||
        !ack) {
        return 0;
    }
    *t_local_executor_capture->ack = *ack;
    t_local_executor_capture->completed = 1;
    return 1;
}

void handle_kvm_run_stateless(int sockfd, struct sockaddr_in *client,
                              struct wvm_header *hdr, void *payload,
                              int vcpu_id);

enum executor_startup_state {
    EXECUTOR_STARTING = 0,
    EXECUTOR_READY = 1,
    EXECUTOR_FAILED = 2,
};

static pthread_mutex_t g_executor_startup_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_executor_startup_changed = PTHREAD_COND_INITIALIZER;
/*
 * Start in STARTING so a concurrent wait_ready from node-runtime cannot
 * observe the pre-thread FAILED sentinel and abort before this role runs.
 */
static enum executor_startup_state g_executor_startup_state = EXECUTOR_STARTING;

#define g_executor_manifest_storage (*g_executor_manifest_storage_ptr)
#define g_executor_runtime_gate (*g_executor_runtime_gate_ptr)

static void executor_publish_startup_state(enum executor_startup_state state)
{
    pthread_mutex_lock(&g_executor_startup_lock);
    g_executor_startup_state = state;
    g_executor_runtime_ready = state == EXECUTOR_READY;
    pthread_cond_broadcast(&g_executor_startup_changed);
    pthread_mutex_unlock(&g_executor_startup_lock);
}

int wvm_executor_runtime_wait_ready(void)
{
    pthread_mutex_lock(&g_executor_startup_lock);
    while (g_executor_startup_state == EXECUTOR_STARTING) {
        pthread_cond_wait(&g_executor_startup_changed,
                          &g_executor_startup_lock);
    }
    if (g_executor_startup_state == EXECUTOR_READY) {
        pthread_mutex_unlock(&g_executor_startup_lock);
        return 0;
    }
    pthread_mutex_unlock(&g_executor_startup_lock);
    return -EIO;
}

// --- KVM_RUN slice preemption (thread-directed) ---
static __thread struct kvm_run *t_kvm_run = NULL;
static __thread volatile sig_atomic_t t_kvm_alarm_fired = 0;
static int g_kvm_immediate_exit = 0;

static int executor_runtime_gate_init(
    const struct wvm_node_runtime_context *runtime)
{
    struct wvm_runtime_registration registration;
    uint8_t profile_digest[WVM_SHA256_DIGEST_BYTES];
    char error[256] = {0};

    if (!runtime || !runtime->manifest_storage ||
        !runtime->manifest || !runtime->runtime_gate ||
        runtime->manifest != &runtime->manifest_storage->manifest ||
        runtime->manifest->vm_id == 0 ||
        runtime->manifest->vm_id != g_slave_vm_id ||
        runtime->runtime_gate->manifest != runtime->manifest ||
        runtime->runtime_gate->state != WVM_RUNTIME_GATE_ACTIVE) {
        fprintf(stderr, "[RuntimeGate] executor context is not admitted\n");
        return -1;
    }
    /*
     * An admitted executor is reached through its local node-runtime bridge.
     * It must not expose the legacy UDP service as a cross-node endpoint.
     */
    g_executor_local_only = 1;
    g_executor_manifest_storage_ptr = runtime->manifest_storage;
    g_executor_runtime_gate_ptr = runtime->runtime_gate;
    if (wvm_runtime_manifest_profile_digest(
            &g_executor_manifest_storage.manifest, profile_digest, error,
            sizeof(error)) != 0) {
        fprintf(stderr, "[RuntimeGate] executor rejected manifest: %s\n",
                error[0] ? error : "invalid capability profile");
        g_executor_manifest_storage_ptr = NULL;
        g_executor_runtime_gate_ptr = NULL;
        return -1;
    }

    memset(&registration, 0, sizeof(registration));
    registration.connection_role = WVM_MANIFEST_ROLE_EXECUTOR;
    registration.vm_id = g_executor_manifest_storage.manifest.vm_id;
    registration.vm_incarnation =
        g_executor_manifest_storage.manifest.vm_incarnation;
    registration.manifest_generation =
        g_executor_manifest_storage.manifest.manifest_generation;
    memcpy(registration.candidate_manifest_digest,
           g_executor_manifest_storage.manifest.candidate_manifest_digest,
           sizeof(registration.candidate_manifest_digest));
    registration.local_runtime_instance_id = runtime->node_instance_id;
    registration.caller_process_instance_id = (uint64_t)getpid();
    memcpy(registration.capability_profile_digest, profile_digest,
           sizeof(registration.capability_profile_digest));
    snprintf(registration.requested_endpoint_name,
             sizeof(registration.requested_endpoint_name), "%s",
             g_executor_manifest_storage.manifest.local_names.namespace_name);
    if (wvm_runtime_gate_register(&g_executor_runtime_gate, &registration,
                                  &g_executor_connection_id, error,
                                  sizeof(error)) != 0) {
        fprintf(stderr, "[RuntimeGate] executor registration rejected: %s\n",
                error[0] ? error : "registration mismatch");
        g_executor_manifest_storage_ptr = NULL;
        g_executor_runtime_gate_ptr = NULL;
        return -1;
    }
    fprintf(stderr,
            "[RuntimeGate] executor registered connection=%" PRIu64 "\n",
            g_executor_connection_id);
    return 0;
}

static int executor_bind_kernel_context(void)
{
    struct wvm_ioctl_context_bind request;
    uint8_t profile_digest[WVM_KERNEL_DIGEST_BYTES];
    char error[256] = {0};
    if (g_wvm_dev_fd < 0 || !g_executor_manifest_storage_ptr ||
        !g_executor_runtime_gate_ptr) {
        return 0;
    }
    if (!g_executor_manifest_storage.manifest.has_activation_fence ||
        wvm_runtime_manifest_profile_digest(
            &g_executor_manifest_storage.manifest, profile_digest, error,
            sizeof(error)) != 0) {
        fprintf(stderr,
                "[KernelContext] executor manifest has no valid "
                "activation/profile identity: %s\n",
                error[0] ? error : "invalid manifest");
        return -1;
    }

    memset(&request, 0, sizeof(request));
    request.magic = WVM_KERNEL_CONTEXT_MAGIC;
    request.version = WVM_KERNEL_CONTEXT_ABI_VERSION;
    request.vm_id = g_executor_manifest_storage.manifest.vm_id;
    request.physical_node_id =
        g_executor_manifest_storage.manifest.physical_node_id;
    request.node_instance_id =
        g_executor_manifest_storage.manifest.expected_node_instance_id;
    if (request.node_instance_id == 0) {
        fprintf(stderr,
                "[KernelContext] executor expected_node_instance_id is zero\n");
        return -1;
    }
    request.vm_incarnation =
        g_executor_manifest_storage.manifest.vm_incarnation;
    request.manifest_generation =
        g_executor_manifest_storage.manifest.manifest_generation;
    memcpy(request.candidate_manifest_digest,
           g_executor_manifest_storage.manifest.candidate_manifest_digest,
           sizeof(request.candidate_manifest_digest));
    memcpy(request.capability_profile_digest, profile_digest,
           sizeof(request.capability_profile_digest));
    memcpy(request.activation_fence,
           g_executor_manifest_storage.manifest.activation_fence,
           sizeof(request.activation_fence));
    {
        const struct wvm_route_snapshot_key *rk =
            &g_executor_manifest_storage.manifest.required_route_snapshot_key;
        request.route_snapshot_key.scope_key.vm_id = rk->scope_key.vm_id;
        request.route_snapshot_key.scope_key.vm_incarnation =
            rk->scope_key.vm_incarnation;
        request.route_snapshot_key.scope_key.route_scope_id =
            rk->scope_key.route_scope_id;
        request.route_snapshot_key.topology_revision = rk->topology_revision;
        request.route_snapshot_key.route_generation = rk->route_generation;
        memcpy(request.route_snapshot_key.snapshot_digest, rk->snapshot_digest,
               sizeof(request.route_snapshot_key.snapshot_digest));
    }

    if (ioctl(g_wvm_dev_fd, IOCTL_WVM_BIND_CONTEXT, &request) < 0) {
        fprintf(stderr,
                "[KernelContext] executor Mode A context bind failed: "
                "errno=%d (%s)\n",
                errno, strerror(errno));
        return -1;
    }
    fprintf(stderr,
            "[KernelContext] executor bound VM=%u incarnation=%" PRIu64
            " node=%u instance=%" PRIu64 "\n",
            request.vm_id, request.vm_incarnation, request.physical_node_id,
            request.node_instance_id);
    return 0;
}

static void kvm_alarm_handler(int sig) {
    (void)sig;
    t_kvm_alarm_fired = 1;
    /*
     * KVM_CAP_IMMEDIATE_EXIT is the native way to interrupt KVM_RUN.  The
     * signal remains necessary on older hosts, where it is expected to make
     * the ioctl return EINTR instead.
     */
    if (g_kvm_immediate_exit && t_kvm_run) {
        __atomic_store_n(&t_kvm_run->immediate_exit, 1, __ATOMIC_RELEASE);
    }
}

// MPSC 队列数据结构

// 任务单元：封装一个需要同步的脏页
typedef struct {
    uint64_t gpa;
    struct wvm_kvm_memory_slice *slice;
    struct wvm_kvm_dirty_page dirty;
    uint8_t  data[4096];
} dirty_page_task_t;

// MPSC 环形队列
#define MPSC_QUEUE_SIZE 8192 // [FIX-F2] 扩容 1024->8192 (32MB)，减少溢出概率
static dirty_page_task_t* g_mpsc_queue[MPSC_QUEUE_SIZE];
static volatile uint32_t g_mpsc_head = 0;
static volatile uint32_t g_mpsc_tail = 0;

// 用于保护队列的互斥锁（生产者侧使用）和用于唤醒消费者的条件变量
static pthread_mutex_t g_mpsc_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_mpsc_cond = PTHREAD_COND_INITIALIZER;
static pthread_t g_dirty_sender_thread;
static int g_dirty_sender_started = 0;
static int g_dirty_sender_stopping = 0;
static int g_dirty_sender_failure = 0;

#define BATCH_SIZE 32
static int g_kvm_available = 0;

typedef struct {
    uint64_t chunk_id;
    int fd;
    time_t last_access;
    UT_hash_handle hh;
} chunk_fd_entry_t;

static chunk_fd_entry_t *g_fd_cache = NULL;
static pthread_mutex_t g_fd_lock = PTHREAD_MUTEX_INITIALIZER;
#define MAX_OPEN_CHUNKS 1024

// 存储辅助函数
static int get_chunk_fd_safe(uint64_t chunk_id) {
    chunk_fd_entry_t *entry;
    pthread_mutex_lock(&g_fd_lock);
    
    HASH_FIND(hh, g_fd_cache, &chunk_id, sizeof(uint64_t), entry);
    if (entry) {
        entry->last_access = time(NULL);
        // Move to front (LRU) implemented by deletion/re-addition in simple uthash, or utilize extra list
        pthread_mutex_unlock(&g_fd_lock);
        return entry->fd;
    }

    // LRU Eviction: 如果满了，删除最旧的 (简化为删头节点)
    if (HASH_COUNT(g_fd_cache) >= MAX_OPEN_CHUNKS) {
        chunk_fd_entry_t *el, *tmp;
        HASH_ITER(hh, g_fd_cache, el, tmp) {
            close(el->fd);
            HASH_DEL(g_fd_cache, el);
            free(el);
            break; // Evict one
        }
    }

    // 物理打开：确保目录存在 (WVM_STORAGE_CHUNK_DIR overrides for tests)
    char path[512];
    const char *chunk_dir = getenv("WVM_STORAGE_CHUNK_DIR");
    if (!chunk_dir || !chunk_dir[0])
        chunk_dir = "/var/lib/wavevm/chunks";
    snprintf(path, sizeof(path), "%s/c_%" PRIu64 ".bin", chunk_dir, chunk_id);
    
    // [V31 PHY] 使用 O_DIRECT 绕过 Page Cache，直接落盘
    int fd = open(path, O_RDWR | O_CREAT | O_DIRECT, 0644);
    if (fd < 0) {
        // Fallback: 如果文件系统不支持 O_DIRECT (如 tmpfs)，回退到普通模式
        if (errno == EINVAL) fd = open(path, O_RDWR | O_CREAT, 0644);
        if (fd < 0) {
            pthread_mutex_unlock(&g_fd_lock);
            return -1;
        }
    }

    entry = malloc(sizeof(chunk_fd_entry_t));
    if (!entry) {
        close(fd);
        pthread_mutex_unlock(&g_fd_lock);
        return -1;
    }
    entry->chunk_id = chunk_id;
    entry->fd = fd;
    entry->last_access = time(NULL);
    HASH_ADD(hh, g_fd_cache, chunk_id, sizeof(uint64_t), entry);
    
    pthread_mutex_unlock(&g_fd_lock);
    return fd;
}

/* 
 * [物理意图] 实现具备“阻塞感知”能力的可靠 UDP 发送，作为 Slave 到 Master 的数据回传通道。
 * [关键逻辑] 实时监测 socket 缓冲区状态，当网络拥塞（EAGAIN）时执行毫秒级退避重试，而非暴力丢包。
 * [后果] 这是 Slave 端状态回传的生命线。若无此机制，高频的中断或脏页同步会冲垮网络，导致 Master 端逻辑断层。
 */
static int robust_sendto(int fd, const void *buf, size_t len, struct sockaddr_in *dest) {
    int retries = 0;
    struct pollfd pfd = { .fd = fd, .events = POLLOUT };

    while (retries < 100) { // 设定最大尝试次数，防止网络彻底断开时死循环
        ssize_t sent = sendto(fd, buf, len, MSG_DONTWAIT, (struct sockaddr*)dest, sizeof(*dest));
        
        if (sent > 0) return 0; // 发送成功

        if (sent == 0) { retries++; continue; } /* sendto 返回 0：零长度包，计入重试 */

        if (sent < 0) {
            if (errno == EINTR) continue; // 被信号中断，立即重试
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
                // 缓冲区满，挂起等待 5ms 
                poll(&pfd, 1, 5);
                retries++;
                continue;
            }
            return -1; // 致命错误
        }
    }
    return -ETIMEDOUT;
}

static uint32_t vcpu_exit_cache_idx(uint64_t req_id, uint32_t requester) {
    return (uint32_t)(((req_id * 11400714819323198485ull) ^ requester) %
                      VCPU_EXIT_CACHE_SIZE);
}

static int vcpu_exit_cache_begin(int fd, struct sockaddr_in *client,
                                 uint64_t req_id, uint32_t requester) {
    uint32_t idx = vcpu_exit_cache_idx(req_id, requester);

    pthread_mutex_lock(&g_vcpu_exit_cache_lock);
    vcpu_exit_cache_entry_t *e = &g_vcpu_exit_cache[idx];
    if ((e->valid || e->in_flight) &&
        e->req_id == req_id &&
        e->requester == requester) {
        if (e->valid && e->len > 0) {
            uint8_t replay[VCPU_EXIT_CACHE_MAX_PACKET];
            size_t len = e->len;
            memcpy(replay, e->data, len);
            pthread_mutex_unlock(&g_vcpu_exit_cache_lock);
            robust_sendto(fd, replay, len, client);
            return 1;
        }
        pthread_mutex_unlock(&g_vcpu_exit_cache_lock);
        return 1; /* duplicate while original execution is still running */
    }

    memset(e, 0, sizeof(*e));
    e->req_id = req_id;
    e->requester = requester;
    e->in_flight = 1;
    pthread_mutex_unlock(&g_vcpu_exit_cache_lock);
    return 0;
}

static void vcpu_exit_cache_complete(uint64_t req_id, uint32_t requester,
                                     const void *packet, size_t len) {
    if (!packet || len == 0 || len > VCPU_EXIT_CACHE_MAX_PACKET) return;

    uint32_t idx = vcpu_exit_cache_idx(req_id, requester);
    pthread_mutex_lock(&g_vcpu_exit_cache_lock);
    vcpu_exit_cache_entry_t *e = &g_vcpu_exit_cache[idx];
    if (e->in_flight && e->req_id == req_id && e->requester == requester) {
        memcpy(e->data, packet, len);
        e->len = len;
        e->valid = 1;
        e->in_flight = 0;
    }
    pthread_mutex_unlock(&g_vcpu_exit_cache_lock);
}

/* 
 * [物理意图] 将 Slave 端的“物理硬件中断”注入到分布式虚拟化总线中。
 * [关键逻辑] 监听本地物理 GPU 的 eventfd，一旦触发，立即封装为 MSG_VFIO_IRQ 并发送至 Master 的 Fast Lane。
 * [后果] 实现了分布式 I/O 的闭环。它让远在千里之外的物理显卡中断，能在 100µs 内“瞬移”到 Master 节点的 vCPU 中。
 */
void *vfio_irq_thread_adapter(void *arg) {
    pthread_mutex_lock(&g_master_mutex);
    while (!g_master_ready && !g_shutdown_requested) {
        pthread_cond_wait(&g_master_cond, &g_master_mutex);
    }
    if (g_shutdown_requested) {
        pthread_mutex_unlock(&g_master_mutex);
        return NULL;
    }
    struct sockaddr_in target = g_master_addr;
    pthread_mutex_unlock(&g_master_mutex);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("[Slave] Failed to create IRQ socket");
        return NULL;
    }

    printf("[Slave] IRQ Forwarder Connected to Master %s:%d\n", 
           inet_ntoa(target.sin_addr), ntohs(target.sin_port));

    // 调用 slave_vfio.c 中的核心轮询逻辑
    wvm_vfio_poll_irqs(sock, &target);
    
    close(sock);
    return NULL;
}

// CPU 核心数探测
int get_allowed_cores() {
    char *env_override = getenv("WVM_CORE_OVERRIDE");
    if (env_override) {
        int val = atoi(env_override);
        if (val > 0) {
            printf("[Hybrid] CPU Cores forced by Env: %d\n", val);
            return val;
        }
    }

    long quota = -1;
    long period = 100000; 

    FILE *fp = fopen("/sys/fs/cgroup/cpu.max", "r");
    if (fp) {
        char buf[64];
        if (fscanf(fp, "%63s %ld", buf, &period) >= 1) {
            if (strcmp(buf, "max") != 0) quota = atol(buf);
        }
        fclose(fp);
    }

    if (quota <= 0) {
        fp = fopen("/sys/fs/cgroup/cpu/cpu.cfs_quota_us", "r");
        if (fp) {
            if (fscanf(fp, "%ld", &quota) != 1) quota = -1;
            fclose(fp);
        }
        fp = fopen("/sys/fs/cgroup/cpu/cpu.cfs_period_us", "r");
        if (fp) {
            long p;
            if (fscanf(fp, "%ld", &p) == 1) period = p;
            fclose(fp);
        }
    }

    int logical_cores = 0;
    if (quota > 0 && period > 0) {
        logical_cores = (int)((quota + period - 1) / period);
        printf("[Hybrid] Container Quota Detected: %ld / %ld = %d Cores\n", quota, period, logical_cores);
    } else {
        logical_cores = (int)sysconf(_SC_NPROCESSORS_ONLN);
        printf("[Hybrid] Using Physical Cores: %d\n", logical_cores);
    }

    if (logical_cores <= 0) logical_cores = 1;
    return logical_cores;
}

// 辅助：头部转本机序
static void ntoh_header(struct wvm_header *hdr) {
    hdr->magic = ntohl(hdr->magic);
    hdr->msg_type = ntohs(hdr->msg_type);
    hdr->payload_len = ntohs(hdr->payload_len);
    hdr->slave_id = ntohl(hdr->slave_id);
    hdr->target_id = ntohl(hdr->target_id);
    hdr->req_id = WVM_NTOHLL(hdr->req_id);
    hdr->epoch = ntohl(hdr->epoch);
}

// ==========================================
// [Fast Path] KVM Engine (V28 Fixed)
// ==========================================

static int g_kvm_fd = -1;
static int g_vm_fd = -1;
static uint8_t *g_phy_ram = NULL;

/* NUMA node info for memslot setup (populated by WVM_NUMA_MAP) */
#define WVM_NUMA_MAX_NODES 16
static struct {
    uint64_t gpa;
    uint64_t size;
} g_numa_nodes[WVM_NUMA_MAX_NODES];
static int g_numa_node_count = 0;
static __thread int t_vcpu_fd = -1;
static __thread int t_vcpu_id = -1;
static struct {
    int fd;
    struct kvm_run *run;
} g_kvm_vcpus[WVM_KVM_MAX_VCPUS];
static pthread_mutex_t g_kvm_vcpu_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_spinlock_t g_master_lock;
static int g_wvm_device_ram_mapping = 0;
static int g_vcpu_init_debug_once = 0;

#define WVM_PAGE_SIZE            4096ULL
#define WVM_KVM_IDMAP_ADDR       0xfffbc000ULL
#define WVM_KVM_TSS_ADDR         0xfffbd000ULL
#define WVM_KVM_RESERVED_SIZE    0x2000ULL /* IDMAP + TSS pages */

static int ensure_kvm_page_snapshot(
    const struct wvm_header *hdr, uint64_t gpa, uint8_t *hva,
    uint64_t *version_out);
static int prepare_kvm_execution_snapshot(
    const struct wvm_header *hdr, const wvm_kvm_context_t *context,
    uint64_t *error_gpa_out);

static uint8_t *wvm_gpa_to_hva(uint64_t gpa)
{
    for (int i = 0; i < g_kvm_slot_count; i++) {
        const wvm_kvm_slot_t *slot = &g_kvm_slots[i];
        if (gpa >= slot->guest_phys_addr &&
            gpa < slot->guest_phys_addr + slot->size) {
            return slot->hva + (gpa - slot->guest_phys_addr);
        }
    }
    return NULL;
}

static inline int wvm_gpa_page_valid(uint64_t gpa)
{
    uint8_t *hva = wvm_gpa_to_hva(gpa);
    if (!hva) return 0;
    /* Require the whole page to fit in a single slot. */
    return wvm_gpa_to_hva(gpa + (WVM_PAGE_SIZE - 1)) != NULL;
}

static int wvm_kvm_add_memslot(int vm_fd, int slot_id,
                              uint64_t guest_phys_addr, uint64_t size,
                              uint8_t *hva, uint32_t flags, bool track_dirty)
{
    struct kvm_userspace_memory_region region;

    if (size == 0) {
        return 0;
    }
    if ((guest_phys_addr & (WVM_PAGE_SIZE - 1)) ||
        (size & (WVM_PAGE_SIZE - 1)) ||
        (((uintptr_t)hva) & (WVM_PAGE_SIZE - 1))) {
        fprintf(stderr, "[Hybrid] memslot alignment invalid gpa=%#llx size=%#llx hva=%p\n",
                (unsigned long long)guest_phys_addr,
                (unsigned long long)size,
                (void*)hva);
        return -1;
    }

    memset(&region, 0, sizeof(region));
    region.slot = (uint32_t)slot_id;
    region.flags = flags;
    region.guest_phys_addr = guest_phys_addr;
    region.memory_size = size;
    region.userspace_addr = (uint64_t)hva;

    if (ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
        perror("[Hybrid] KVM_SET_USER_MEMORY_REGION failed");
        fprintf(stderr, "[Hybrid] memslot=%d gpa=%#llx size=%#llx hva=%p\n",
                slot_id,
                (unsigned long long)guest_phys_addr,
                (unsigned long long)size,
                (void*)hva);
        return -1;
    }

    if (g_kvm_slot_count < (int)(sizeof(g_kvm_slots) / sizeof(g_kvm_slots[0]))) {
        g_kvm_slots[g_kvm_slot_count].slot = slot_id;
        g_kvm_slots[g_kvm_slot_count].guest_phys_addr = guest_phys_addr;
        g_kvm_slots[g_kvm_slot_count].size = size;
        g_kvm_slots[g_kvm_slot_count].hva = hva;
        g_kvm_slots[g_kvm_slot_count].flags = flags;
        g_kvm_slots[g_kvm_slot_count].track_dirty = track_dirty;
        g_kvm_slot_count++;
    }

    return 0;
}

/* 
 * [物理意图] 在远程节点初始化硬件虚拟化容器（KVM），为“算力托管”圈定物理内存边界。
 * [关键逻辑] 创建 KVM 虚拟机实例，利用 mmap 映射大页内存，并根据是否有内核模块（Mode A）选择最优路径。
 * [后果] 确立了远程执行的基石。若初始化失败，Slave 将无法使用硬件加速，只能回退到慢速的 TCG 模拟模式。
 */
/*
 * A no-root TCG executor still needs the guest RAM page that QEMU maps via
 * memory-backend-file.  Previously an absent /dev/kvm returned before this
 * mapping, so the executor could not install the remote page it fetched.
 */
static int map_tcg_guest_ram_from_shm(void)
{
    const char *shm_path = getenv("WVM_SHM_FILE");
    struct stat st;
    int fd;

    if (!shm_path || !shm_path[0] || g_slave_ram_size == 0) {
        return -1;
    }
    fd = shm_open(shm_path, O_RDWR, 0);
    if (fd < 0) {
        fprintf(stderr, "[Hybrid] TCG guest RAM shm_open %s: %s\n",
                shm_path, strerror(errno));
        return -1;
    }
    if (fstat(fd, &st) != 0 ||
        (uint64_t)st.st_size < g_slave_ram_size) {
        if (ftruncate(fd, (off_t)g_slave_ram_size) != 0) {
            fprintf(stderr, "[Hybrid] TCG guest RAM ftruncate: %s\n",
                    strerror(errno));
            close(fd);
            return -1;
        }
    }
    g_phy_ram = mmap(NULL, g_slave_ram_size, PROT_READ | PROT_WRITE,
                     MAP_SHARED, fd, 0);
    close(fd);
    if (g_phy_ram == MAP_FAILED) {
        g_phy_ram = NULL;
        fprintf(stderr, "[Hybrid] TCG guest RAM mmap: %s\n",
                strerror(errno));
        return -1;
    }
    fprintf(stderr,
            "[Hybrid] TCG guest RAM mapped path=/dev/shm/%s bytes=%llu\n",
            shm_path, (unsigned long long)g_slave_ram_size);
    return 0;
}

uint8_t *wvm_executor_guest_ram_base(void)
{
    return (g_phy_ram && g_phy_ram != MAP_FAILED) ? g_phy_ram : NULL;
}

void init_kvm_global() {
    const char *force_tcg = getenv("WVM_FORCE_TCG");
    if (force_tcg && atoi(force_tcg) == 1) {
        fprintf(stderr, "[Hybrid] WVM_FORCE_TCG=1, skip KVM init.\n");
        g_kvm_available = 0;
        (void)map_tcg_guest_ram_from_shm();
        return;
    }

    g_kvm_fd = open("/dev/kvm", O_RDWR);
    if (g_kvm_fd < 0) {
        g_kvm_available = 0;
        (void)map_tcg_guest_ram_from_shm();
        return;
    }

    {
        /*
         * Negotiated profile decides device use: bits==0 stay Mode B entirely
         * (no open/bind/use). bits!=0 must meet context contract; BIND failure
         * fail-closes the accelerator path.
         */
        const uint64_t kernel_bits =
            g_executor_manifest_storage_ptr
                ? g_executor_manifest_storage.manifest.negotiated_profile
                      .kernel_accelerator_bits
                : 0;
        if (kernel_bits == 0) {
            g_wvm_dev_fd = -1;
        } else {
            g_wvm_dev_fd = open("/dev/wavevm", O_RDWR);
            if (g_wvm_dev_fd >= 0 && executor_bind_kernel_context() != 0) {
                close(g_wvm_dev_fd);
                g_wvm_dev_fd = -1;
                g_kernel_context_bind_failed = 1;
                return;
            }
        }
    }
    
    /*
     * WVM_NUMA_MAP describes the complete guest physical address space.
     * It takes precedence over the device mapping: /dev/wavevm remains open
     * for Mode A control/dirty-page semantics, while each slave must still
     * see every guest RAM region when it executes a remote vCPU.
     */
    const char *numa_map = getenv("WVM_NUMA_MAP");
    if (g_wvm_dev_fd >= 0 && !numa_map) {
        printf("[Hybrid] KVM: Detected /dev/wavevm. Enabling On-Demand Paging (Fast Path).\n");
        g_phy_ram = mmap(NULL, g_slave_ram_size, PROT_READ|PROT_WRITE, MAP_SHARED, g_wvm_dev_fd, 0);
        if (g_phy_ram != MAP_FAILED) {
            g_wvm_device_ram_mapping = 1;
        }
    } else {
        /* [FIX] NUMA-aware multi-SHM mapping.
         * WVM_NUMA_MAP="size_mb:shm_path,size_mb:shm_path,..."
         * Entries are ordered by GPA. Each slave maps ALL regions so the
         * full guest physical address space is accessible.
         * Falls back to WVM_SHM_FILE (single region at GPA 0) if unset. */
        if (numa_map) {
            /* --- Phase 1: parse entries, compute total size --- */
            /* Parse WVM_NUMA_MAP: "gpa_hex:size_mb:shm_path,..."
             * e.g. "0:2048:/wvm_fract_node0,100000000:1024:/wvm_fract_node1"
             * gpa_hex = guest physical address in hex (no 0x prefix)
             * size_mb = region size in MB
             * shm_path = POSIX SHM name for shm_open() */
            #define WVM_NUMA_MAX_NODES 16
            struct { uint64_t gpa; uint64_t size; char path[256]; } nodes[WVM_NUMA_MAX_NODES];
            int n_nodes = 0;
            uint64_t va_end = 0; /* highest GPA + size = total VA needed */
            {
                char buf[2048];
                strncpy(buf, numa_map, sizeof(buf) - 1);
                buf[sizeof(buf) - 1] = 0;
                char *saveptr = NULL;
                for (char *tok = strtok_r(buf, ",", &saveptr);
                     tok && n_nodes < WVM_NUMA_MAX_NODES;
                     tok = strtok_r(NULL, ",", &saveptr))
                {
                    /* Parse "gpa_hex:size_mb:shm_path" */
                    char *c1 = strchr(tok, ':');
                    if (!c1) continue;
                    *c1 = 0;
                    char *c2 = strchr(c1 + 1, ':');
                    if (!c2) continue;
                    *c2 = 0;
                    uint64_t gpa = strtoull(tok, NULL, 16);
                    uint64_t sz_mb = (uint64_t)atol(c1 + 1);
                    const char *path = c2 + 1;
                    if (sz_mb == 0 || !path[0]) continue;
                    nodes[n_nodes].gpa = gpa;
                    nodes[n_nodes].size = sz_mb * 1024ULL * 1024ULL;
                    strncpy(nodes[n_nodes].path, path, sizeof(nodes[n_nodes].path) - 1);
                    nodes[n_nodes].path[sizeof(nodes[n_nodes].path) - 1] = 0;
                    uint64_t end = gpa + nodes[n_nodes].size;
                    if (end > va_end) va_end = end;
                    /* Store in global for memslot setup */
                    g_numa_nodes[n_nodes].gpa = gpa;
                    g_numa_nodes[n_nodes].size = nodes[n_nodes].size;
                    n_nodes++;
                }
            }
            if (n_nodes > 0 && va_end > 0) {
                /* Reserve contiguous VA covering [0, va_end), then
                 * MAP_FIXED each SHM at its correct GPA offset. */
                g_phy_ram = mmap(NULL, va_end,
                                 PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (g_phy_ram && g_phy_ram != MAP_FAILED) {
                    int ok = 1;
                    for (int i = 0; i < n_nodes; i++) {
                        int fd = shm_open(nodes[i].path, O_CREAT | O_RDWR, 0666);
                        if (fd < 0) {
                            fprintf(stderr, "[Hybrid] NUMA: shm_open(%s) failed: %s\n",
                                    nodes[i].path, strerror(errno));
                            ok = 0; break;
                        }
                        ftruncate(fd, nodes[i].size);
                        void *m = mmap(g_phy_ram + nodes[i].gpa, nodes[i].size,
                                       PROT_READ | PROT_WRITE,
                                       MAP_SHARED | MAP_FIXED, fd, 0);
                        close(fd);
                        if (m == MAP_FAILED) {
                            fprintf(stderr, "[Hybrid] NUMA: mmap(%s, %llu MB at GPA 0x%llx) failed: %s\n",
                                    nodes[i].path,
                                    (unsigned long long)(nodes[i].size / (1024*1024)),
                                    (unsigned long long)nodes[i].gpa, strerror(errno));
                            ok = 0; break;
                        }
                        fprintf(stderr, "[Hybrid] NUMA: node %d  %s  %llu MB  GPA [0x%llx, 0x%llx)\n",
                                i, nodes[i].path,
                                (unsigned long long)(nodes[i].size / (1024*1024)),
                                (unsigned long long)nodes[i].gpa,
                                (unsigned long long)(nodes[i].gpa + nodes[i].size));
                    }
                    if (ok) {
                        g_slave_ram_size = va_end;
                        g_numa_node_count = n_nodes;
                        fprintf(stderr, "[Hybrid] NUMA: %d nodes mapped, VA range 0x%llx\n",
                                n_nodes, (unsigned long long)va_end);
                    } else {
                        munmap(g_phy_ram, va_end);
                        g_phy_ram = NULL;
                    }
                }
            }
            #undef WVM_NUMA_MAX_NODES
        }

        /* Legacy single-SHM fallback */
        if (!g_phy_ram || g_phy_ram == MAP_FAILED) {
            const char *shm_path = getenv("WVM_SHM_FILE");
            if (shm_path) {
                printf("[Hybrid] KVM: Using SHM File: %s\n", shm_path);
                int shm_fd = shm_open(shm_path, O_CREAT | O_RDWR, 0666);
                if (shm_fd >= 0) {
                    ftruncate(shm_fd, g_slave_ram_size);
                    g_phy_ram = mmap(NULL, g_slave_ram_size, PROT_READ|PROT_WRITE, MAP_SHARED, shm_fd, 0);
                    close(shm_fd);
                }
            }
        }

        // 如果以上都失败，回退到匿名内存
        if (!g_phy_ram || g_phy_ram == MAP_FAILED) {
            printf("[Hybrid] KVM: Using Anonymous RAM.\n");
            g_phy_ram = mmap(NULL, g_slave_ram_size, PROT_READ|PROT_WRITE,
                             MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        }
    }

    if (g_phy_ram == MAP_FAILED) { perror("mmap ram"); exit(1); }

    madvise(g_phy_ram, g_slave_ram_size, MADV_HUGEPAGE);
    // [V28 Fix] 不要 MADV_RANDOM，保持默认，让 KVM 能够利用 THP
    
    g_vm_fd = ioctl(g_kvm_fd, KVM_CREATE_VM, 0);
    if (g_vm_fd < 0) { close(g_kvm_fd); g_kvm_fd = -1; return; }

    /* Do NOT create IRQCHIP on the slave.  On GCP nested virt (kernel 6.14),
     * having two KVM VMs with in-kernel IRQCHIP causes L1 hypervisor
     * conflicts that break the master's AP bringup:
     *   Pipeline #70: IRQCHIP ret=0 → APs stuck at mp_state=1
     *   Pipeline #73: IRQCHIP ret=0 → recursive page fault during SMP init
     *   Pipeline #71-72: IRQCHIP failed (EINVAL) → APs boot fine
     *
     * Without IRQCHIP, LAPIC MMIO (0xfee00xxx) exits to userspace.  We
     * intercept these in the KVM_RUN loop with proper register emulation
     * (APIC ID from dispatch context, etc.) instead of returning zeros. */
    ioctl(g_vm_fd, KVM_SET_TSS_ADDR, WVM_KVM_TSS_ADDR);
    {
        __u64 map_addr = WVM_KVM_IDMAP_ADDR;
        ioctl(g_vm_fd, KVM_SET_IDENTITY_MAP_ADDR, &map_addr);
    }
    fprintf(stderr, "[Slave] No IRQCHIP (avoiding nested virt conflict)\n");

    for (int i = 0; i < WVM_KVM_MAX_VCPUS; i++) {
        g_kvm_vcpus[i].fd = -1;
        g_kvm_vcpus[i].run = NULL;
    }
    g_kvm_immediate_exit =
        ioctl(g_kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_IMMEDIATE_EXIT) > 0;
    fprintf(stderr, "[Slave KVM] immediate_exit=%d numa_nodes=%d device_ram=%d\n",
            g_kvm_immediate_exit, g_numa_node_count,
            g_wvm_device_ram_mapping);

    g_kvm_slot_count = 0;

    /* Map a dedicated 2-page reserved window for KVM IDMAP/TSS. */
    g_kvm_reserved_size = (size_t)WVM_KVM_RESERVED_SIZE;
    g_kvm_reserved_hva = mmap(NULL, g_kvm_reserved_size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_kvm_reserved_hva == MAP_FAILED) {
        perror("[Hybrid] mmap reserved");
        g_kvm_reserved_hva = NULL;
        close(g_vm_fd);
        g_vm_fd = -1;
        close(g_kvm_fd);
        g_kvm_fd = -1;
        return;
    }

    /* --- KVM Memslot Setup ---
     * When NUMA mapping is active, create per-node memslots to avoid
     * mapping PROT_NONE gaps in the VA space. Otherwise, use legacy
     * single-region layout. */
    if (g_numa_node_count > 0) {
        /* NUMA mode: one memslot per node, plus IDMAP reserved slot */
        int slot_id = 0;
        for (int ni = 0; ni < g_numa_node_count; ni++) {
            uint64_t ngpa = g_numa_nodes[ni].gpa;
            uint64_t nsz  = g_numa_nodes[ni].size;
            uint64_t nend = ngpa + nsz;

            /* If this node spans the IDMAP reserved area, split around it */
            uint64_t idmap_start = WVM_KVM_IDMAP_ADDR;
            uint64_t idmap_end   = WVM_KVM_IDMAP_ADDR + WVM_KVM_RESERVED_SIZE;

            if (ngpa < idmap_start && nend > idmap_end) {
                /* Part before IDMAP */
                uint64_t sz1 = idmap_start - ngpa;
                wvm_kvm_add_memslot(g_vm_fd, slot_id++, ngpa, sz1,
                                    g_phy_ram + ngpa, KVM_MEM_LOG_DIRTY_PAGES, true);
                /* Part after IDMAP */
                uint64_t sz2 = nend - idmap_end;
                wvm_kvm_add_memslot(g_vm_fd, slot_id++, idmap_end, sz2,
                                    g_phy_ram + idmap_end, KVM_MEM_LOG_DIRTY_PAGES, true);
            } else if (ngpa < idmap_start && nend > idmap_start) {
                /* Ends in IDMAP region */
                uint64_t sz1 = idmap_start - ngpa;
                wvm_kvm_add_memslot(g_vm_fd, slot_id++, ngpa, sz1,
                                    g_phy_ram + ngpa, KVM_MEM_LOG_DIRTY_PAGES, true);
            } else if (ngpa >= idmap_start && ngpa < idmap_end) {
                /* Starts in IDMAP region */
                if (nend > idmap_end) {
                    uint64_t sz2 = nend - idmap_end;
                    wvm_kvm_add_memslot(g_vm_fd, slot_id++, idmap_end, sz2,
                                        g_phy_ram + idmap_end, KVM_MEM_LOG_DIRTY_PAGES, true);
                }
            } else {
                /* No overlap with IDMAP */
                wvm_kvm_add_memslot(g_vm_fd, slot_id++, ngpa, nsz,
                                    g_phy_ram + ngpa, KVM_MEM_LOG_DIRTY_PAGES, true);
            }
            fprintf(stderr, "[Hybrid] NUMA memslot: node %d GPA [0x%llx, 0x%llx)\n",
                    ni, (unsigned long long)ngpa, (unsigned long long)nend);
        }

        /* IDMAP/TSS reserved slot */
        wvm_kvm_add_memslot(g_vm_fd, slot_id++, WVM_KVM_IDMAP_ADDR,
                            WVM_KVM_RESERVED_SIZE, g_kvm_reserved_hva, 0, false);

        /* BIOS ROM slot: only if not already covered by a node memslot.
         * GPA 0xFFFF0000-0xFFFFFFFF maps to g_phy_ram + 0xF0000.
         * Skip if any node covers this GPA range. */
        int bios_covered = 0;
        for (int ni = 0; ni < g_numa_node_count; ni++) {
            if (g_numa_nodes[ni].gpa <= 0xFFFF0000ULL &&
                g_numa_nodes[ni].gpa + g_numa_nodes[ni].size > 0xFFFF0000ULL) {
                bios_covered = 1;
                break;
            }
        }
        if (!bios_covered && g_numa_nodes[0].size >= 0x100000ULL) {
            uint64_t bios_gpa  = 0xFFFF0000ULL;
            uint64_t bios_size = 0x10000ULL;
            if (wvm_kvm_add_memslot(g_vm_fd, slot_id++, bios_gpa, bios_size,
                                    g_phy_ram + 0xF0000, 0, false) < 0) {
                fprintf(stderr, "[Hybrid] BIOS ROM slot failed\n");
            } else {
                fprintf(stderr, "[Hybrid] BIOS ROM slot: GPA [0x%llx, 0x%llx)\n",
                        (unsigned long long)bios_gpa,
                        (unsigned long long)(bios_gpa + bios_size));
            }
        }
    } else {
        /* Legacy single-region memslot layout */
        uint64_t low_size = g_slave_ram_size;
        if (low_size > WVM_KVM_IDMAP_ADDR) {
            low_size = WVM_KVM_IDMAP_ADDR;
        }
        if (wvm_kvm_add_memslot(g_vm_fd, 0, 0, low_size, g_phy_ram,
                                KVM_MEM_LOG_DIRTY_PAGES, true) < 0) {
            close(g_vm_fd); g_vm_fd = -1; close(g_kvm_fd); g_kvm_fd = -1; return;
        }
        if (wvm_kvm_add_memslot(g_vm_fd, 2, WVM_KVM_IDMAP_ADDR, WVM_KVM_RESERVED_SIZE,
                                g_kvm_reserved_hva, 0, false) < 0) {
            close(g_vm_fd); g_vm_fd = -1; close(g_kvm_fd); g_kvm_fd = -1; return;
        }
        uint64_t hole_end = WVM_KVM_IDMAP_ADDR + WVM_KVM_RESERVED_SIZE;
        if (g_slave_ram_size > hole_end) {
            uint64_t high_size = g_slave_ram_size - hole_end;
            if (wvm_kvm_add_memslot(g_vm_fd, 1, hole_end, high_size, g_phy_ram + hole_end,
                                    KVM_MEM_LOG_DIRTY_PAGES, true) < 0) {
                close(g_vm_fd); g_vm_fd = -1; close(g_kvm_fd); g_kvm_fd = -1; return;
            }
        }
        if (g_slave_ram_size >= 0x100000ULL) {
            uint64_t bios_gpa  = 0xFFFF0000ULL;
            uint64_t bios_size = 0x10000ULL;
            if (wvm_kvm_add_memslot(g_vm_fd, 3, bios_gpa, bios_size,
                                    g_phy_ram + 0xF0000, 0, false) < 0) {
                fprintf(stderr, "[Hybrid] BIOS ROM slot failed\n");
            } else {
                fprintf(stderr, "[Hybrid] BIOS ROM slot 3: GPA [0x%llx, 0x%llx) -> HVA %p\n",
                        (unsigned long long)bios_gpa,
                        (unsigned long long)(bios_gpa + bios_size),
                        (void*)(g_phy_ram + 0xF0000));
            }
        }
    }

    g_kvm_available = 1;
    pthread_spin_init(&g_master_lock, 0);

    printf("[Hybrid] KVM Hardware Acceleration Active (RAM: %d MB).\n", g_ram_mb);
}

void init_thread_local_vcpu(int vcpu_id) {
    if (vcpu_id < 0 || vcpu_id >= WVM_KVM_MAX_VCPUS) {
        fprintf(stderr, "[Slave VCPU Init] invalid guest vcpu=%d\n", vcpu_id);
        return;
    }
    if (t_vcpu_fd >= 0 && t_vcpu_id == vcpu_id) return;
    if (__sync_bool_compare_and_swap(&g_vcpu_init_debug_once, 0, 1)) {
        fprintf(stderr, "[Slave VCPU Init] enter vm=%d kvm=%d req_vcpu=%d\n",
                g_vm_fd, g_kvm_fd, vcpu_id);
    }
    if (g_vm_fd < 0 || g_kvm_fd < 0) {
        fprintf(stderr, "[Slave VCPU Init] invalid fds vm=%d kvm=%d vcpu=%d\n",
                g_vm_fd, g_kvm_fd, vcpu_id);
        return;
    }

    pthread_mutex_lock(&g_kvm_vcpu_lock);
    if (g_kvm_vcpus[vcpu_id].fd >= 0 && g_kvm_vcpus[vcpu_id].run) {
        t_vcpu_fd = g_kvm_vcpus[vcpu_id].fd;
        t_kvm_run = g_kvm_vcpus[vcpu_id].run;
        t_vcpu_id = vcpu_id;
        pthread_mutex_unlock(&g_kvm_vcpu_lock);
        return;
    }

    t_vcpu_fd = ioctl(g_vm_fd, KVM_CREATE_VCPU, vcpu_id);
    if (t_vcpu_fd < 0) {
        fprintf(stderr, "[Slave VCPU Init] KVM_CREATE_VCPU failed vcpu=%d errno=%d\n",
                vcpu_id, errno);
        pthread_mutex_unlock(&g_kvm_vcpu_lock);
        return;
    }
    int mmap_size = ioctl(g_kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (mmap_size <= 0) {
        fprintf(stderr, "[Slave VCPU Init] KVM_GET_VCPU_MMAP_SIZE failed errno=%d\n", errno);
        close(t_vcpu_fd);
        t_vcpu_fd = -1;
        pthread_mutex_unlock(&g_kvm_vcpu_lock);
        return;
    }
    t_kvm_run = mmap(NULL, mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED, t_vcpu_fd, 0);
    if (t_kvm_run == MAP_FAILED) {
        fprintf(stderr, "[Slave VCPU Init] vcpu mmap failed errno=%d\n", errno);
        close(t_vcpu_fd);
        t_vcpu_fd = -1;
        t_kvm_run = NULL;
        pthread_mutex_unlock(&g_kvm_vcpu_lock);
        return;
    }
    g_kvm_vcpus[vcpu_id].fd = t_vcpu_fd;
    g_kvm_vcpus[vcpu_id].run = t_kvm_run;
    t_vcpu_id = vcpu_id;
    fprintf(stderr, "[Slave VCPU Init] guest_vcpu=%d fd=%d run=%p\n",
            vcpu_id, t_vcpu_fd, (void *)t_kvm_run);
    pthread_mutex_unlock(&g_kvm_vcpu_lock);
}

// [FIX] Thread-Local 缓存，避免高频 malloc/free
static __thread unsigned long *t_dirty_bitmap_cache = NULL;
static __thread size_t t_dirty_bitmap_size = 0;

/* [FIX-F2] 紧急内联发送：当 MPSC 队列已满或 malloc 失败时，阻塞式直接发送脏页。
 * 这是最后的安全网——绝不能在 KVM_GET_DIRTY_LOG 已清除硬件 dirty bit 后丢弃页面。
 * 性能会下降（阻塞 vCPU 所在线程），但数据不会丢失。
 */
static __thread int t_emergency_sock = -1;

static void emergency_send_dirty_page(uint64_t gpa, const uint8_t *hva) {
    if (t_emergency_sock < 0) {
        t_emergency_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (t_emergency_sock < 0) {
            fprintf(stderr, "[FIX-F2] FATAL: cannot create emergency socket, dirty page 0x%"
                    PRIx64 " LOST\n", gpa);
            return;
        }
    }

    uint8_t tx_buf[sizeof(struct wvm_header) + 8 + 4096];
    memset(tx_buf, 0, sizeof(struct wvm_header));
    struct wvm_header *wh = (struct wvm_header *)tx_buf;
    size_t total_len = sizeof(tx_buf);

    wh->magic = htonl(WVM_MAGIC);
    wh->msg_type = htons(MSG_MEM_WRITE);
    wh->payload_len = htons(8 + 4096);
    wvm_slave_pack_src(wh);
    wh->target_id = htonl(WVM_NODE_AUTO_ROUTE);
    wh->req_id = 0;
    wh->qos_level = 0;

    uint64_t net_gpa = WVM_HTONLL(gpa);
    memcpy(tx_buf + sizeof(*wh), &net_gpa, 8);
    memcpy(tx_buf + sizeof(*wh) + 8, hva, 4096);

    wh->crc32 = 0;
    wh->crc32 = htonl(calculate_crc32(tx_buf, total_len));

    // [FIX-M2] 加锁读取 g_master_addr，防止与 RX 线程竞争
    struct sockaddr_in master_snap;
    pthread_spin_lock(&g_master_lock);
    master_snap = g_master_addr;
    pthread_spin_unlock(&g_master_lock);
    robust_sendto(t_emergency_sock, tx_buf, total_len, &master_snap);
}

static int submit_typed_dirty_page(dirty_page_task_t *task)
{
    struct wvm_mem_commit_ack ack;
    char error[256] = {0};
    uint16_t status = WVM_MEM_COMMIT_ACK_INTERNAL_FAILURE;
    uint64_t result_version = 0;
    int request_result;

    if (!task || !task->slice) {
        return -EINVAL;
    }
    memset(&ack, 0, sizeof(ack));
    request_result = wvm_memory_service_global_request_commit(
        task->dirty.gpa, task->dirty.base_version, 0, task->data,
        WVM_MEMORY_PAGE_BYTES, task->dirty.operation_id,
        task->dirty.delivery_attempt_id, &ack, error, sizeof(error));
    if (request_result == 0) {
        status = ack.status;
        result_version = ack.result_version;
    }
    if (request_result != 0 ||
        wvm_kvm_memory_slice_complete_dirty(
            task->slice, &task->dirty, status, result_version, error,
            sizeof(error)) != 0) {
        fprintf(stderr,
                "[KVM cache] dirty commit failed GPA=%#" PRIx64
                " base=%#" PRIx64 " status=%u result=%d reason=%s\n",
                task->dirty.gpa, task->dirty.base_version, (unsigned)status,
                request_result, error[0] ? error : "commit rejected");
        g_dirty_sender_failure = 1;
        return -1;
    }
    return 0;
}

/* 
 * [物理意图] 充当远程执行节点的“脏页回写引擎”，实现计算与同步的解耦。
 * [关键逻辑] 作为 MPSC 队列的唯一消费者，将各个 vCPU 产生的脏页任务（Dirty Pages）进行有序的异步网络发送。
 * [后果] 它解决了“同步锁死”问题。vCPU 可以在执行完指令后立即继续，无需等待网络 ACK，极大提升了远程主频。
 */
void* dirty_sync_sender_thread(void* arg) {
    printf("[SenderThread] KVM Dirty Page Sender is running.\n");
    
    // 这个 socket 只用于发送，所以不需要 bind
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("SenderThread socket");
        return NULL;
    }

    while (1) {
        pthread_mutex_lock(&g_mpsc_lock);

        // 如果队列为空，则阻塞等待；STOP 时排空后退出。
        while (g_mpsc_head == g_mpsc_tail && !g_dirty_sender_stopping) {
            pthread_cond_wait(&g_mpsc_cond, &g_mpsc_lock);
        }
        if (g_dirty_sender_stopping && g_mpsc_head == g_mpsc_tail) {
            pthread_mutex_unlock(&g_mpsc_lock);
            break;
        }

        // 从队列头部取出一个任务
        uint32_t current_head = g_mpsc_head;
        dirty_page_task_t* task = g_mpsc_queue[current_head];
        g_mpsc_head = (current_head + 1) % MPSC_QUEUE_SIZE;
        
        pthread_mutex_unlock(&g_mpsc_lock);
        
        if (task && task->slice) {
            (void)submit_typed_dirty_page(task);
            free(task);
            continue;
        }

        // Legacy fallback for a non-admitted standalone executor.
        uint8_t tx_buf[sizeof(struct wvm_header) + 8 + 4096];
        memset(tx_buf, 0, sizeof(struct wvm_header)); // [FIX] 清零 header 区域，防止 epoch/flags 等字段含垃圾值
        struct wvm_header *wh = (struct wvm_header *)tx_buf;
        size_t total_len = sizeof(tx_buf);

        wh->magic = htonl(WVM_MAGIC);
        wh->msg_type = htons(MSG_MEM_WRITE);
        wh->payload_len = htons(8 + 4096);
        wvm_slave_pack_src(wh);
        wh->target_id = htonl(WVM_NODE_AUTO_ROUTE); // [V31 Fix] 本地通信标记，防止 Master vm_id 过滤误杀
        wh->req_id = 0;
        wh->qos_level = 0;

        uint64_t net_gpa = WVM_HTONLL(task->gpa);
        memcpy(tx_buf + sizeof(*wh), &net_gpa, 8);
        memcpy(tx_buf + sizeof(*wh) + 8, task->data, 4096);

        wh->crc32 = 0;
        wh->crc32 = htonl(calculate_crc32(tx_buf, total_len));

        // [FIX-M2] 加锁快照 g_master_addr，防止与 RX 线程竞争
        struct sockaddr_in master_snap;
        pthread_spin_lock(&g_master_lock);
        master_snap = g_master_addr;
        pthread_spin_unlock(&g_master_lock);
        // 使用 robust_sendto 发送，它内部包含了反压处理逻辑
        robust_sendto(sockfd, tx_buf, total_len, &master_snap);
        
        // 任务完成，释放内存
        free(task);
    }
    
    close(sockfd);
    return NULL;
}

/*
 * R1: the KVM dirty sender is the last producer that can still reference the
 * page cache/memory service.  STOP must stop and join it after the KVM worker
 * quiesces, and must fail the executor if any queued dirty commit failed.
 */
static int stop_dirty_sender_thread(void)
{
    if (!g_dirty_sender_started) {
        return 0;
    }
    pthread_mutex_lock(&g_mpsc_lock);
    g_dirty_sender_stopping = 1;
    pthread_cond_broadcast(&g_mpsc_cond);
    pthread_mutex_unlock(&g_mpsc_lock);
    pthread_join(g_dirty_sender_thread, NULL);
    g_dirty_sender_started = 0;
    if (g_dirty_sender_failure) {
        fprintf(stderr,
                "[SenderThread] STOP incomplete: dirty commit failure\n");
        return -1;
    }
    return 0;
}

static void typed_handoff_result_from_request(
    const struct wvm_vcpu_handoff_request *request, uint16_t status,
    struct wvm_vcpu_handoff_result *result)
{
    memset(result, 0, sizeof(*result));
    result->protocol_version = WVM_VCPU_HANDOFF_RESULT_VERSION;
    result->status = status;
    result->exit_class =
        status == WVM_VCPU_HANDOFF_RESULT_MEMORY_FAILURE
            ? WVM_VCPU_EXIT_MEMORY_ERROR
            : status == WVM_VCPU_HANDOFF_RESULT_EXECUTOR_FAILURE
                  ? WVM_VCPU_EXIT_EXECUTOR_ERROR
                  : WVM_VCPU_EXIT_NONE;
    result->backend = request->backend;
    result->vm_id = request->vm_id;
    result->vm_incarnation = request->vm_incarnation;
    result->manifest_generation = request->manifest_generation;
    result->origin_physical_node_id = request->origin_physical_node_id;
    result->origin_runtime_instance_id = request->origin_runtime_instance_id;
    result->vcpu_index = request->vcpu_index;
    result->handoff_sequence = request->handoff_sequence;
    memcpy(result->operation_id, request->operation_id,
           sizeof(result->operation_id));
    result->context_schema_version = request->context_schema_version;
}

static uint16_t typed_exit_class_from_legacy_ack(
    const struct wvm_vcpu_handoff_request *request,
    const struct wvm_ipc_cpu_run_ack *ack)
{
    if (request->backend == WVM_VCPU_BACKEND_TCG) {
        if (ack->ctx.tcg.halted) {
            return WVM_VCPU_EXIT_HALTED;
        }
        if (ack->ctx.tcg.interrupt_request != 0) {
            return WVM_VCPU_EXIT_INTERRUPT;
        }
        return WVM_VCPU_EXIT_BUDGET;
    }
    if (ack->ctx.kvm.exit_reason == KVM_EXIT_HLT) {
        return WVM_VCPU_EXIT_HALTED;
    }
    if (ack->ctx.kvm.exit_reason == KVM_EXIT_IO) {
        return WVM_VCPU_EXIT_PIO;
    }
    if (ack->ctx.kvm.exit_reason == KVM_EXIT_MMIO) {
        return WVM_VCPU_EXIT_MMIO;
    }
    return WVM_VCPU_EXIT_BUDGET;
}

static void typed_handoff_ids(uint64_t *request_id, uint64_t *fence_id)
{
    pthread_mutex_lock(&g_executor_handoff_id_lock);
    if (++g_executor_handoff_id == 0) {
        ++g_executor_handoff_id;
    }
    if (++g_executor_completed_fence_id == 0) {
        ++g_executor_completed_fence_id;
    }
    *request_id = g_executor_handoff_id;
    *fence_id = g_executor_completed_fence_id;
    pthread_mutex_unlock(&g_executor_handoff_id_lock);
}

static int execute_tcg_executor_session(
    const struct wvm_vcpu_handoff_request *request,
    struct wvm_vcpu_handoff_result *result, uint8_t *result_context,
    size_t result_context_capacity, char *error, size_t error_len)
{
    uint8_t request_payload[WVM_EXECUTOR_SESSION_MAX_FRAME_BYTES];
    uint8_t frame[WVM_EXECUTOR_SESSION_MAX_FRAME_BYTES];
    uint8_t response[WVM_EXECUTOR_SESSION_MAX_FRAME_BYTES];
    const uint8_t *payload = NULL;
    size_t request_payload_bytes = 0;
    size_t frame_bytes = 0;
    size_t response_bytes;
    size_t payload_bytes = 0;
    uint16_t message_type = 0;
    struct wvm_vcpu_handoff_result decoded_result;
    int fd;
    ssize_t sent;

    if (!request || !result || !result_context ||
        result_context_capacity < WVM_VCPU_HANDOFF_MAX_RESULT_CONTEXT_BYTES ||
        !g_tcg_session_fds || request->vcpu_index >= (uint32_t)g_num_cores ||
        g_tcg_session_fds[request->vcpu_index] < 0) {
        if (error && error_len != 0) {
            snprintf(error, error_len,
                     "TCG executor session is not available for vCPU");
        }
        return -EAGAIN;
    }
    fd = g_tcg_session_fds[request->vcpu_index];
    if (wvm_vcpu_handoff_request_encode(
            request, request_payload, sizeof(request_payload),
            &request_payload_bytes, error, error_len) != 0 ||
        wvm_executor_session_encode(
            WVM_EXECUTOR_SESSION_VCPU_RUN, request_payload,
            request_payload_bytes, frame, sizeof(frame), &frame_bytes, error,
            error_len) != 0) {
        return -EPROTO;
    }
    sent = send(fd, frame, frame_bytes, MSG_NOSIGNAL);
    if (sent != (ssize_t)frame_bytes) {
        if (error && error_len != 0) {
            snprintf(error, error_len, "cannot submit TCG executor session");
        }
        return sent < 0 ? -errno : -EIO;
    }

    /* Poll with total deadline per vcpu-handoff.md contract (30s) */
    int attempts = 0;
    const int max_attempts = 300; /* 30 seconds at 100ms intervals */
    for (;;) {
        struct pollfd descriptor = {.fd = fd, .events = POLLIN};
        int poll_result = poll(&descriptor, 1, 100);

        if (g_shutdown_requested) {
            return -ESHUTDOWN;
        }
        if (poll_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }
        if (poll_result == 0) {
            if (++attempts >= max_attempts) {
                if (error && error_len != 0) {
                    snprintf(error, error_len,
                             "TCG executor session timeout (no response in 30s)");
                }
                return -ETIMEDOUT;
            }
            continue;
        }
        if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            if (error && error_len != 0) {
                snprintf(error, error_len,
                         "TCG executor session closed before its result");
            }
            return -EPIPE;
        }
        response_bytes = recv(fd, response, sizeof(response), 0);
        if (response_bytes < 0 && errno == EINTR) {
            continue;
        }
        if (response_bytes <= 0) {
            return response_bytes == 0 ? -EPIPE : -errno;
        }
        break;
    }

    if (wvm_executor_session_decode(
            response, response_bytes, &message_type, &payload, &payload_bytes,
            error, error_len) != 0 ||
        message_type != WVM_EXECUTOR_SESSION_VCPU_EXIT ||
        wvm_vcpu_handoff_result_decode(
            payload, payload_bytes, &decoded_result, error, error_len) != 0 ||
        wvm_vcpu_handoff_result_validate_request(
            request, &decoded_result, error, error_len) != 0) {
        if (error && error_len != 0 && error[0] == '\0') {
            snprintf(error, error_len,
                     "TCG executor session result is invalid");
        }
        return -EPROTO;
    }
    if (decoded_result.context_bytes > result_context_capacity) {
        if (error && error_len != 0) {
            snprintf(error, error_len,
                     "TCG executor session result context is too large");
        }
        return -EOVERFLOW;
    }
    *result = decoded_result;
    if (decoded_result.context_bytes != 0) {
        memcpy(result_context, decoded_result.context,
               decoded_result.context_bytes);
        result->context = result_context;
    } else {
        result->context = NULL;
    }
    return 0;
}

/*
 * R06 / A3: Map the executor's guest RAM page, either through the KVM
 * memslot table or through the TCG g_phy_ram mapping.  QEMU in TCG mode
 * maps the same WVM_SHM_FILE, so filling this page before the session
 * VCPU_RUN makes the guest fetch remote bytes rather than zeros.
 */
static uint8_t *executor_guest_page_hva(uint64_t gpa)
{
    uint8_t *hva;

    if ((gpa & (WVM_PAGE_SIZE - 1U)) != 0) {
        return NULL;
    }
    hva = wvm_gpa_to_hva(gpa);
    if (hva) {
        return hva;
    }
    if (g_phy_ram && g_phy_ram != MAP_FAILED &&
        gpa <= g_slave_ram_size - WVM_MEMORY_PAGE_BYTES) {
        return g_phy_ram + gpa;
    }
    return NULL;
}

/*
 * A3: Fetch the authoritative remote page and install it into the
 * executor's guest RAM before the typed executor runs.  The old path only
 * placed the ACK bytes in a temporary buffer and discarded them, so a TCG
 * guest could not execute the remote page.  Keeping the ENOTCONN behavior
 * for an uninstalled memory service preserves the R06 fail-closed rule.
 *
 * This is deliberately not a synthetic fence: ack.version is the version
 * returned by the production memory service/directory store.
 */

/*
 * After SHM install, QEMU still has version 0 and (as slave) PROT_NONE/RW
 * without a directory version.  MSG_PAGE_PUSH_FULL sets version and queues
 * PROT_READ so the guest store can SIGSEGV into the writable list and the
 * production flush_slave path can typed-commit.  G4: PAGE_PUSH+PUSH_BARRIER
 * go through the proxy sock; PUSH_BARRIER_ACK demux marks the cookie — no
 * sleep-claimed success.
 */
int wavevm_proxy_push_to_local_helpers(uint16_t msg_type, void *payload, int len);
int wavevm_proxy_barrier_local_helpers(uint64_t timeout_us);
static int notify_tcg_page_installed(uint64_t gpa, uint64_t version,
                                     const uint8_t *page)
{
    struct wvm_full_page_push full;
    int pr;
    int br;

    if (!page || version == 0) {
        return 0;
    }

    /*
     * G4: PAGE_PUSH + PUSH_BARRIER via proxy sock (helpers connect(push→proxy)).
     * ACK demux marks cookies; never sleep-claim success.
     */
    memset(&full, 0, sizeof(full));
    full.gpa = WVM_HTONLL(gpa);
    full.version = WVM_HTONLL(version);
    memcpy(full.data, page, WVM_MEMORY_PAGE_BYTES);
    pr = wavevm_proxy_push_to_local_helpers(MSG_PAGE_PUSH_FULL, &full,
                                            (int)sizeof(full));
    if (pr < 0) {
        fprintf(stderr,
                "[Executor] TCG install PAGE_PUSH failed gpa=%#llx ret=%d\n",
                (unsigned long long)gpa, pr);
        return pr;
    }
    br = wavevm_proxy_barrier_local_helpers(5000000ULL);
    if (br != 0) {
        fprintf(stderr,
                "[Executor] TCG install barrier failed gpa=%#llx ret=%d\n",
                (unsigned long long)gpa, br);
        return br;
    }
    fprintf(stderr,
            "[Executor] TCG install notify applied gpa=%#llx version=%#llx "
            "(barrier ack)\n",
            (unsigned long long)gpa, (unsigned long long)version);
    return 0;
}


static int ensure_remote_memory_side_effect(
    const struct wvm_node_runtime_context *runtime,
    const struct wvm_vcpu_handoff_request *request, char *error,
    size_t error_len)
{
    const struct wvm_runtime_dispatch_projection *dispatch;
    size_t i;

    if (!runtime || !runtime->dispatch || !request) {
        return 0;
    }
    dispatch = runtime->dispatch;
    if (!dispatch->memory_dispatch.entries ||
        dispatch->memory_dispatch.count == 0) {
        return 0;
    }
    for (i = 0; i < dispatch->memory_dispatch.count; i++) {
        const struct wvm_runtime_memory_dispatch *entry =
            &dispatch->memory_dispatch.entries[i];
        uint8_t op[WVM_IDENTITY_ID_BYTES];
        struct wvm_mem_ack ack;
        uint8_t page[WVM_MEMORY_PAGE_BYTES];
        uint8_t *guest_page;
        int result;
        size_t z;
        int all_zero = 1;

        if (entry->directory_physical_node_id == 0) {
            continue;
        }
        if (entry->directory_physical_node_id == runtime->physical_node_id &&
            entry->directory_node_instance_id == runtime->node_instance_id) {
            continue;
        }
        memcpy(op, request->operation_id, sizeof(op));
        op[0] ^= 0xA5;
        for (z = 0; z < sizeof(op); z++) {
            if (op[z] != 0) {
                all_zero = 0;
                break;
            }
        }
        if (all_zero) {
            op[15] = 0xA5;
        }
        memset(&ack, 0, sizeof(ack));
        result = wvm_memory_service_global_request_fault(
            entry->gpa_start, op, 1, &ack, page, error, error_len);
        if (result == -ENOTCONN) {
            /*
             * R06: do not fake prefetch success. Absence of memory service
             * means this side-effect path cannot prove remote dependence.
             * Return ENOTCONN so callers skip the decorative prefetch rather
             * than claiming a remote memory fence.
             */
            if (error && error_len != 0) {
                snprintf(error, error_len,
                         "remote memory side effect unavailable (no memory service)");
            }
            return -ENOTCONN;
        }
        if (result != 0) {
            return result;
        }
        if (ack.status != WVM_MEM_ACK_SUCCESS ||
            ack.data_bytes != WVM_MEMORY_PAGE_BYTES) {
            if (error && error_len != 0) {
                snprintf(error, error_len,
                         "remote memory side effect status=%u bytes=%zu",
                         (unsigned)ack.status, ack.data_bytes);
            }
            return -EIO;
        }
        guest_page = executor_guest_page_hva(entry->gpa_start);
        if (guest_page) {
            memcpy(guest_page, page, WVM_MEMORY_PAGE_BYTES);
            __sync_synchronize();
            fprintf(stderr,
                    "[Executor] installed remote page gpa=%#llx version=%#llx "
                    "bytes=%zu hva=%p first=%02x%02x%02x%02x\n",
                    (unsigned long long)entry->gpa_start,
                    (unsigned long long)ack.version,
                    (size_t)ack.data_bytes, (void *)guest_page,
                    page[0], page[1], page[2], page[3]);
            /*
             * Production TCG dirty self-emit: tell QEMU the installed page's
             * directory version and arm PROT_READ so the guest store is
             * tracked and flushed via wavevm_user_mem_flush_slave_dirty_sync.
             */
            (void)notify_tcg_page_installed(entry->gpa_start, ack.version, page);
        } else {
            fprintf(stderr,
                    "[Executor] remote page gpa=%#llx has no local guest RAM "
                    "mapping; fetch not installable\n",
                    (unsigned long long)entry->gpa_start);
        }
        return 0;
    }
    return 0;
}

int wvm_executor_runtime_bind_admitted(
    const struct wvm_node_runtime_context *runtime, char *error,
    size_t error_len)
{
    long i;

    if (!runtime || !runtime->manifest_storage || !runtime->manifest ||
        !runtime->runtime_gate || !runtime->dispatch ||
        runtime->executor_service_port == 0 ||
        runtime->executor_worker_count == 0 ||
        runtime->manifest->vm_id == 0) {
        if (error && error_len != 0) {
            snprintf(error, error_len,
                     "executor bind requires an admitted runtime context");
        }
        return -EINVAL;
    }
    g_slave_vm_id = runtime->manifest->vm_id;
    g_service_port = (int)runtime->executor_service_port;
    g_num_cores = (long)runtime->executor_worker_count;
    g_base_id = (int)runtime->local_primary_vnode;
    g_executor_ctrl_port = (int)runtime->executor_control_port;
    g_ram_mb = (int)(runtime->local_memory_bytes / (1024ULL * 1024ULL));
    if (g_ram_mb <= 0) {
        g_ram_mb = 64;
    }
    g_slave_ram_size = runtime->local_memory_bytes;
    free(g_tcg_helper_pids);
    g_tcg_helper_pids = NULL;
    free(g_tcg_session_fds);
    g_tcg_session_fds =
        malloc(sizeof(*g_tcg_session_fds) * (size_t)g_num_cores);
    if (!g_tcg_session_fds) {
        if (error && error_len != 0) {
            snprintf(error, error_len, "cannot allocate TCG session table");
        }
        return -ENOMEM;
    }
    for (i = 0; i < g_num_cores; i++) {
        g_tcg_session_fds[i] = -1;
    }
    if (executor_runtime_gate_init(runtime) != 0) {
        free(g_tcg_session_fds);
        g_tcg_session_fds = NULL;
        g_num_cores = 0;
        if (error && error_len != 0 && error[0] == '\0') {
            snprintf(error, error_len, "executor runtime gate rejected bind");
        }
        return -EPERM;
    }
    return 0;
}

int wvm_executor_runtime_attach_tcg_session(uint32_t vcpu_index,
                                           int session_fd)
{
    if (!g_tcg_session_fds || session_fd < 0 ||
        vcpu_index >= (uint32_t)g_num_cores) {
        return -EINVAL;
    }
    if (g_tcg_session_fds[vcpu_index] >= 0) {
        close(g_tcg_session_fds[vcpu_index]);
    }
    g_tcg_session_fds[vcpu_index] = session_fd;
    return 0;
}

void wvm_executor_runtime_publish_ready(void)
{
    executor_publish_startup_state(EXECUTOR_READY);
}


void wvm_executor_runtime_set_tcg_install_notify_fd(int fd)
{
    if (g_tcg_install_notify_owned && g_tcg_install_notify_fd >= 0 &&
        g_tcg_install_notify_fd != fd) {
        close(g_tcg_install_notify_fd);
    }
    g_tcg_install_notify_fd = fd;
    g_tcg_install_notify_owned = 0;
}

void wvm_executor_runtime_unbind(void)
{
    long i;

    executor_publish_startup_state(EXECUTOR_STARTING);
    g_executor_runtime_ready = 0;
    g_executor_manifest_storage_ptr = NULL;
    g_executor_runtime_gate_ptr = NULL;
    g_executor_local_only = 0;
    if (g_tcg_session_fds) {
        for (i = 0; i < g_num_cores; i++) {
            if (g_tcg_session_fds[i] >= 0) {
                close(g_tcg_session_fds[i]);
                g_tcg_session_fds[i] = -1;
            }
        }
        free(g_tcg_session_fds);
        g_tcg_session_fds = NULL;
    }
    free(g_tcg_helper_pids);
    g_tcg_helper_pids = NULL;
    if (g_tcg_install_notify_owned && g_tcg_install_notify_fd >= 0) {
        close(g_tcg_install_notify_fd);
    }
    g_tcg_install_notify_fd = -1;
    g_tcg_install_notify_owned = 0;
    g_num_cores = 0;
    g_service_port = 0;
    g_slave_vm_id = 0;
}

/*
 * This is the sole node-runtime to executor entry point. The executor may
 * temporarily retain its loopback worker transport while KVM and TCG
 * mechanics converge, but neither the bridge nor the fabric sees a legacy
 * header or a composite raw identifier.
 */
int wvm_executor_runtime_execute_handoff(
    void *opaque, const struct wvm_vcpu_handoff_request *request,
    struct wvm_vcpu_handoff_result *result, uint8_t *result_context,
    size_t result_context_capacity, char *error, size_t error_len)
{
    const struct wvm_node_runtime_context *runtime = opaque;
    struct wvm_ipc_cpu_run_req local_request;
    struct wvm_ipc_cpu_run_ack local_ack;
    struct wvm_header header;
    struct sockaddr_in executor_address;
    struct pollfd pollfd;
    uint8_t packet[sizeof(header) + sizeof(local_request)];
    uint8_t response[sizeof(struct wvm_header) + sizeof(local_ack)];
    void *decoded_context;
    const void *legacy_context;
    size_t legacy_bytes;
    size_t encoded_context_bytes = 0;
    uint64_t context_fields = 0;
    uint64_t request_id;
    uint64_t fence_id;
    ssize_t sent;
    int fd;
    struct sockaddr_in local_client;
    struct wvm_header local_header;
    struct local_executor_capture local_capture;
    uint8_t local_payload[sizeof(local_ack)];
    int remote_memory_result;

    if (!request || !result || !result_context ||
        result_context_capacity < WVM_VCPU_HANDOFF_MAX_RESULT_CONTEXT_BYTES ||
        !g_executor_runtime_ready ||
        !g_executor_manifest_storage_ptr || !g_executor_runtime_gate_ptr ||
        g_service_port <= 0 || request->vm_id != g_slave_vm_id ||
        request->vm_incarnation !=
            g_executor_manifest_storage.manifest.vm_incarnation ||
        request->manifest_generation !=
            g_executor_manifest_storage.manifest.manifest_generation ||
        (request->backend != WVM_VCPU_BACKEND_TCG &&
         request->backend != WVM_VCPU_BACKEND_KVM)) {
        if (error && error_len != 0) {
            snprintf(error, error_len,
                     "typed executor is not ready for this admitted handoff");
        }
        return -EAGAIN;
    }

    /*
     * R06: decorative prefetch is optional. ENOTCONN means the memory service
     * is not installed — skip without claiming a remote-memory fence. Real
     * dependence must come from the executor fault/commit path.
     */
    remote_memory_result =
        ensure_remote_memory_side_effect(runtime, request, error, error_len);
    if (remote_memory_result == -ENOTCONN) {
        if (error && error_len)
            error[0] = '\0';
    } else if (remote_memory_result != 0) {
        typed_handoff_result_from_request(
            request, WVM_VCPU_HANDOFF_RESULT_MEMORY_FAILURE, result);
        return 0;
    }

    memset(&local_request, 0, sizeof(local_request));
    memset(&local_ack, 0, sizeof(local_ack));
    local_request.mode_tcg = request->backend == WVM_VCPU_BACKEND_TCG;
    local_request.slave_id = WVM_NODE_AUTO_ROUTE;
    local_request.vcpu_index = request->vcpu_index;
    legacy_bytes = wvm_x86_context_legacy_bytes(request->backend);
    decoded_context = request->backend == WVM_VCPU_BACKEND_TCG
                          ? (void *)&local_request.ctx.tcg
                          : (void *)&local_request.ctx.kvm;
    if (legacy_bytes == 0 ||
        wvm_x86_context_decode(
            request->backend, request->context, request->context_bytes,
            &context_fields, decoded_context, legacy_bytes, error,
            error_len) != 0 ||
        context_fields != request->context_valid_fields) {
        if (error && error_len != 0 && error[0] == '\0') {
            snprintf(error, error_len,
                     "typed executor handoff context does not match schema");
        }
        return -EPROTO;
    }

    typed_handoff_ids(&request_id, &fence_id);

    if (request->backend == WVM_VCPU_BACKEND_TCG) {
        if (execute_tcg_executor_session(
                request, result, result_context, result_context_capacity,
                error, error_len) != 0) {
            return -EIO;
        }
        if (result->status == WVM_VCPU_HANDOFF_RESULT_SUCCESS) {
            result->produced_memory_fence_id = fence_id;
        }
        return 0;
    }

    /*
     * KVM is already an in-process executor on this node. Keep its
     * asynchronous bridge worker, but invoke the execution core directly so
     * the admitted typed handoff never becomes a legacy UDP frame.
     */
    if (request->backend == WVM_VCPU_BACKEND_KVM && g_kvm_available) {
        memset(&local_header, 0, sizeof(local_header));
        local_header.magic = WVM_MAGIC;
        local_header.msg_type = MSG_VCPU_RUN;
        local_header.payload_len = sizeof(local_request);
        local_header.slave_id = g_base_id;
        local_header.target_id = g_base_id;
        local_header.req_id = request_id;
        local_header.mode_tcg = 0;
        memset(&local_client, 0, sizeof(local_client));
        local_client.sin_family = AF_INET;
        local_client.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        local_client.sin_port = htons((uint16_t)g_service_port);
        memset(&local_capture, 0, sizeof(local_capture));
        local_capture.ack = &local_ack;
        memset(local_payload, 0, sizeof(local_payload));
        memcpy(local_payload, &local_request, sizeof(local_request));
        t_local_executor_capture = &local_capture;
        handle_kvm_run_stateless(-1, &local_client, &local_header,
                                  local_payload, (int)request->vcpu_index);
        t_local_executor_capture = NULL;
        if (!local_capture.completed) {
            if (error && error_len != 0) {
                snprintf(error, error_len,
                         "typed KVM executor returned without a completion");
            }
            return -EIO;
        }
        goto typed_ack_ready;
    }

    memset(&header, 0, sizeof(header));
    header.magic = htonl(WVM_MAGIC);
    header.msg_type = htons(MSG_VCPU_RUN);
    header.payload_len = htons(sizeof(local_request));
    /* The internal loopback worker needs a local correlation endpoint only. */
    header.slave_id = htonl((uint32_t)g_base_id);
    header.target_id = htonl((uint32_t)g_base_id);
    header.req_id = WVM_HTONLL(request_id);
    header.mode_tcg = (uint8_t)local_request.mode_tcg;
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), &local_request, sizeof(local_request));

    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        if (error && error_len != 0) {
            snprintf(error, error_len, "cannot open local executor transport");
        }
        return -errno;
    }
    memset(&executor_address, 0, sizeof(executor_address));
    executor_address.sin_family = AF_INET;
    executor_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    executor_address.sin_port = htons((uint16_t)g_service_port);
    if (connect(fd, (const struct sockaddr *)&executor_address,
                sizeof(executor_address)) != 0) {
        int connection_error = errno;

        close(fd);
        if (error && error_len != 0) {
            snprintf(error, error_len, "cannot connect local executor transport");
        }
        return -connection_error;
    }
    sent = send(fd, packet, sizeof(packet), MSG_NOSIGNAL);
    if (sent != (ssize_t)sizeof(packet)) {
        int send_error = sent < 0 ? errno : EIO;

        close(fd);
        if (error && error_len != 0) {
            snprintf(error, error_len, "cannot submit typed executor handoff");
        }
        return -send_error;
    }

    pollfd.fd = fd;
    pollfd.events = POLLIN;
    for (;;) {
        ssize_t received;
        const struct wvm_header *response_header;

        if (g_shutdown_requested) {
            close(fd);
            return -ESHUTDOWN;
        }
        if (poll(&pollfd, 1, 100) < 0) {
            if (errno == EINTR) {
                continue;
            }
            {
                int poll_error = errno;

                close(fd);
                return -poll_error;
            }
        }
        if ((pollfd.revents & POLLIN) == 0) {
            continue;
        }
        received = recv(fd, response, sizeof(response), 0);
        if (received != (ssize_t)sizeof(response)) {
            continue;
        }
        response_header = (const struct wvm_header *)response;
        if (ntohl(response_header->magic) != WVM_MAGIC ||
            ntohs(response_header->msg_type) != MSG_VCPU_EXIT ||
            ntohs(response_header->payload_len) != sizeof(local_ack) ||
            WVM_NTOHLL(response_header->req_id) != request_id) {
            continue;
        }
        memcpy(&local_ack, response + sizeof(*response_header),
               sizeof(local_ack));
        close(fd);
        break;
    }

typed_ack_ready:
    if (local_ack.mode_tcg != local_request.mode_tcg) {
        if (error && error_len != 0) {
            snprintf(error, error_len,
                     "local executor replied with a different backend");
        }
        return -EPROTO;
    }
    if (local_ack.status != 0 &&
        local_ack.status != WVM_CPU_RUN_STATUS_MEMORY_FAILURE) {
        typed_handoff_result_from_request(
            request, WVM_VCPU_HANDOFF_RESULT_EXECUTOR_FAILURE, result);
        return 0;
    }

    /*
     * s23g2: MEMORY_FAILURE must still carry the post-run CPU context when
     * the local executor filled it. Stripping context here forced FE into
     * zeroed-ACK import / silent drop and hung dual-yes under KVM.
     */
    legacy_context = request->backend == WVM_VCPU_BACKEND_TCG
                         ? (const void *)&local_ack.ctx.tcg
                         : (const void *)&local_ack.ctx.kvm;
    if (wvm_x86_context_encode(
            request->backend, request->context_valid_fields, legacy_context,
            wvm_x86_context_legacy_bytes(request->backend), result_context,
            result_context_capacity, &encoded_context_bytes, error,
            error_len) != 0) {
        return -EPROTO;
    }
    if (local_ack.status == WVM_CPU_RUN_STATUS_MEMORY_FAILURE) {
        typed_handoff_result_from_request(
            request, WVM_VCPU_HANDOFF_RESULT_MEMORY_FAILURE, result);
        result->error_gpa = local_ack.error_gpa;
    } else {
        typed_handoff_result_from_request(request, WVM_VCPU_HANDOFF_RESULT_SUCCESS,
                                          result);
        result->produced_memory_fence_id = fence_id;
    }
    result->exit_class = typed_exit_class_from_legacy_ack(request, &local_ack);
    result->context_valid_fields = request->context_valid_fields;
    result->context = result_context;
    result->context_bytes = encoded_context_bytes;
    return 0;
}

/* 
 * [物理意图] 在 Slave 硬件上“瞬间复活”来自 Master 的 CPU 寄存器上下文并执行。
 * [关键逻辑] 1. 注入寄存器状态；2. 启动硬件 KVM_RUN；3. 拦截 MMIO 退出；4. 导出最新状态并回传。
 * [后果] 这是分布式计算的“肌肉”。它让 Master 节点能像调用本地函数一样，将指令流分发到全网任意节点执行。
 */
void handle_kvm_run_stateless(int sockfd, struct sockaddr_in *client, struct wvm_header *hdr, void *payload, int vcpu_id) {
    struct wvm_ipc_cpu_run_req *req = (struct wvm_ipc_cpu_run_req *)payload;
    struct wvm_ipc_cpu_run_req req_copy;
    if (!req) return;
    /* The reply is written back into the request payload.  Keep the request
     * in a separate object: otherwise ack->status overwrites req->mode_tcg
     * and the context export reads an ACK that aliases its own input. */
    req_copy = *req;
    req = &req_copy;
    /*
     * The receive worker is only a transport thread.  The guest execution
     * identity is carried by the request envelope and must not be inferred
     * from the worker/socket that happened to receive the datagram.
     */
    int guest_vcpu_id = (req->vcpu_index < WVM_KVM_MAX_VCPUS)
                            ? (int)req->vcpu_index
                            : vcpu_id;
    uint64_t run_req_id = hdr->req_id;
    uint32_t requester = hdr->slave_id;
    if (!t_local_executor_capture &&
        vcpu_exit_cache_begin(sockfd, client, run_req_id, requester)) {
        return;
    }
    { static int __run=0;
      if (__run < 10) {
          fprintf(stderr, "[VCPU-RUN] mode=%u vcpu=%d req=%llu src=%s:%u target=%u slave=%u\n",
                  req->mode_tcg, guest_vcpu_id, (unsigned long long)hdr->req_id,
                  inet_ntoa(client->sin_addr), ntohs(client->sin_port),
                  (unsigned)ntohl(hdr->target_id), (unsigned)ntohl(hdr->slave_id));
          __run++;
      }
    }

    // 对“空上下文探针”走快速 ACK，避免在 KVM_RUN 中无意义阻塞。
    // 仅匹配明显空输入，不影响真实执行上下文。
    const wvm_kvm_context_t zero_kvm = {0};
    bool kvm_empty = !req->mode_tcg &&
                     memcmp(&req->ctx.kvm, &zero_kvm, sizeof(zero_kvm)) == 0;
    if (kvm_empty) {
        struct wvm_header ack_hdr;
        memset(&ack_hdr, 0, sizeof(ack_hdr));
        ack_hdr.magic = htonl(WVM_MAGIC);
        ack_hdr.msg_type = htons(MSG_VCPU_EXIT);
        ack_hdr.payload_len = htons(sizeof(struct wvm_ipc_cpu_run_ack));
        /* ACK must originate from this slave node and target the requester. */
        wvm_slave_pack_src(&ack_hdr);
        ack_hdr.target_id = htonl(hdr->slave_id);  /* s23g13: hdr host-order after ntoh_header */
        wvm_ack_copy_assoc(&ack_hdr, hdr);
        ack_hdr.req_id = WVM_HTONLL(hdr->req_id);

        struct wvm_ipc_cpu_run_ack ack;
        memset(&ack, 0, sizeof(ack));
        ack.status = 0;
        ack.mode_tcg = req->mode_tcg;
        if (req->mode_tcg) {
            memcpy(&ack.ctx.tcg, &req->ctx.tcg, sizeof(req->ctx.tcg));
        } else {
            memcpy(&ack.ctx.kvm, &req->ctx.kvm, sizeof(req->ctx.kvm));
        }

        uint8_t tx[sizeof(ack_hdr) + sizeof(ack)];
        memcpy(tx, &ack_hdr, sizeof(ack_hdr));
        memcpy(tx + sizeof(ack_hdr), &ack, sizeof(ack));
        if (capture_local_executor_ack(&ack)) {
            return;
        }
        struct wvm_header *tx_hdr = (struct wvm_header *)tx;
        tx_hdr->crc32 = 0;
        tx_hdr->crc32 = htonl(calculate_crc32(tx, sizeof(tx)));
        vcpu_exit_cache_complete(run_req_id, requester, tx, sizeof(tx));
        ssize_t sret = sendto(sockfd, tx, sizeof(tx), 0, (struct sockaddr*)client, sizeof(*client));
        fprintf(stderr, "[Slave FastAck] ret=%zd errno=%d mode=%u req=%llu dst=%s:%u\n",
                sret, (sret < 0) ? errno : 0, req->mode_tcg,
                (unsigned long long)hdr->req_id, inet_ntoa(client->sin_addr), ntohs(client->sin_port));
        return;
    }

    if (t_vcpu_fd < 0 || t_vcpu_id != guest_vcpu_id) {
        init_thread_local_vcpu(guest_vcpu_id);
    }
    if (t_vcpu_fd < 0 || !t_kvm_run || t_kvm_run == MAP_FAILED) {
        struct wvm_header ack_hdr;
        memset(&ack_hdr, 0, sizeof(ack_hdr));
        ack_hdr.magic = htonl(WVM_MAGIC);
        ack_hdr.msg_type = htons(MSG_VCPU_EXIT);
        ack_hdr.payload_len = htons(sizeof(struct wvm_ipc_cpu_run_ack));
        /* ACK must originate from this slave node and target the requester. */
        wvm_slave_pack_src(&ack_hdr);
        ack_hdr.target_id = htonl(hdr->slave_id);  /* s23g13: hdr host-order after ntoh_header */
        wvm_ack_copy_assoc(&ack_hdr, hdr);
        ack_hdr.req_id = WVM_HTONLL(hdr->req_id);

        struct wvm_ipc_cpu_run_ack ack;
        memset(&ack, 0, sizeof(ack));
        ack.status = -1;
        ack.mode_tcg = req->mode_tcg;
        if (req->mode_tcg) {
            memcpy(&ack.ctx.tcg, &req->ctx.tcg, sizeof(req->ctx.tcg));
        } else {
            memcpy(&ack.ctx.kvm, &req->ctx.kvm, sizeof(req->ctx.kvm));
        }

        uint8_t tx[sizeof(ack_hdr) + sizeof(ack)];
        memcpy(tx, &ack_hdr, sizeof(ack_hdr));
        memcpy(tx + sizeof(ack_hdr), &ack, sizeof(ack));
        if (capture_local_executor_ack(&ack)) {
            return;
        }
        struct wvm_header *tx_hdr = (struct wvm_header *)tx;
        tx_hdr->crc32 = 0;
        tx_hdr->crc32 = htonl(calculate_crc32(tx, sizeof(tx)));
        vcpu_exit_cache_complete(run_req_id, requester, tx, sizeof(tx));
        ssize_t sret = sendto(sockfd, tx, sizeof(tx), 0, (struct sockaddr*)client, sizeof(*client));
        fprintf(stderr, "[Slave ErrorAck] vcpu init failed ret=%zd errno=%d req=%llu dst=%s:%u\n",
                sret, (sret < 0) ? errno : 0,
                (unsigned long long)hdr->req_id, inet_ntoa(client->sin_addr), ntohs(client->sin_port));
        return;
    }
    struct kvm_regs kregs; struct kvm_sregs ksregs;
    // 1. 读取当前 sregs，供直通路径或转换路径继续使用
    ioctl(t_vcpu_fd, KVM_GET_SREGS, &ksregs); 

    // 2. 只有不一样的时候才转换！
    if (req->mode_tcg) {
        // TCG 对 KVM：转换计算
        wvm_translate_tcg_to_kvm(&req->ctx.tcg, &kregs, &ksregs);
    } else {
        // KVM 对 KVM：零转换直通
        wvm_kvm_context_t *ctx = &req->ctx.kvm;
        kregs.rax = ctx->rax; kregs.rbx = ctx->rbx; kregs.rcx = ctx->rcx; kregs.rdx = ctx->rdx;
        kregs.rsi = ctx->rsi; kregs.rdi = ctx->rdi; kregs.rsp = ctx->rsp; kregs.rbp = ctx->rbp;
        kregs.r8  = ctx->r8;  kregs.r9  = ctx->r9;  kregs.r10 = ctx->r10; kregs.r11 = ctx->r11;
        kregs.r12 = ctx->r12; kregs.r13 = ctx->r13; kregs.r14 = ctx->r14; kregs.r15 = ctx->r15;
        kregs.rip = ctx->rip; kregs.rflags = ctx->rflags;

        /* Keep local APIC/interrupt state and only import architectural sregs. */
        struct kvm_sregs *remote_sregs = (struct kvm_sregs *)ctx->sregs_data;
        ksregs.cs = remote_sregs->cs;
        ksregs.ds = remote_sregs->ds;
        ksregs.es = remote_sregs->es;
        ksregs.fs = remote_sregs->fs;
        ksregs.gs = remote_sregs->gs;
        ksregs.ss = remote_sregs->ss;
        ksregs.tr = remote_sregs->tr;
        ksregs.ldt = remote_sregs->ldt;
        ksregs.gdt = remote_sregs->gdt;
        ksregs.idt = remote_sregs->idt;
        ksregs.cr0 = remote_sregs->cr0;
        ksregs.cr2 = remote_sregs->cr2;
        ksregs.cr3 = remote_sregs->cr3;
        ksregs.cr4 = remote_sregs->cr4;
        ksregs.cr8 = remote_sregs->cr8;
        ksregs.efer = remote_sregs->efer;
    }

    /* [FIX] Lazy BIOS ROM load: on first request, if BIOS area is empty,
     * load directly from bios.bin file. No timing dependency on QEMU. */
    {
        static volatile int bios_copied = 0;
        if (!bios_copied) {
            uint32_t *bc = (uint32_t *)(g_phy_ram + 0xFFFF0);
            if (bc[0] == 0) {
                /* Try loading from bios.bin file (last 64KB = physical 0xF0000-0xFFFFF) */
                const char *bios_paths[] = {
                    getenv("WVM_BIOS_FILE"),
                    "/workspaces/WaveVM_Frontier-X/wavevm-qemu/pc-bios/bios.bin",
                    "/usr/share/seabios/bios.bin",
                    NULL
                };
                int loaded = 0;
                for (int i = 0; i < 3 && !loaded; i++) {
                    if (!bios_paths[i]) continue;
                    FILE *bf = fopen(bios_paths[i], "rb");
                    if (bf) {
                        fseek(bf, 0, SEEK_END);
                        long bsz = ftell(bf);
                        /* Read last 64KB of BIOS image -> physical 0xF0000 */
                        long off = (bsz > 0x10000) ? (bsz - 0x10000) : 0;
                        long rdsz = (bsz > 0x10000) ? 0x10000 : bsz;
                        fseek(bf, off, SEEK_SET);
                        size_t rd = fread(g_phy_ram + 0xF0000, 1, rdsz, bf);
                        fclose(bf);
                        if (rd == (size_t)rdsz) {
                            fprintf(stderr, "[Hybrid] BIOS ROM loaded from %s (%ld bytes at 0xF0000): reset=%08x\n",
                                    bios_paths[i], rdsz, *(uint32_t*)(g_phy_ram + 0xFFFF0));
                            loaded = 1;
                        }
                    }
                }
                if (!loaded) {
                    fprintf(stderr, "[Hybrid] WARN: BIOS ROM area empty and no bios.bin found!\n");
                }
            }
            bios_copied = 1;
        }
    }

    /* SET_REGS first, then SET_MP_STATE.
     * KVM_SET_MP_STATE(RUNNABLE) on a fresh vCPU can trigger an internal
     * reset that wipes registers. Setting regs FIRST then MP state avoids
     * this. We MUST set RUNNABLE every time because the previous KVM_RUN
     * may have left the vCPU in HALTED state (guest executed HLT). */
    {
        int sr_ret = ioctl(t_vcpu_fd, KVM_SET_SREGS, &ksregs);
        int rr_ret = ioctl(t_vcpu_fd, KVM_SET_REGS, &kregs);
        /* Always set MP_STATE to RUNNABLE before KVM_RUN.
         * If the previous execution ended with HLT, the vCPU is now in
         * HALTED state and KVM_RUN would immediately return KVM_EXIT_HLT
         * without executing any guest code. */
        {
            struct kvm_mp_state mps = { .mp_state = 0 }; /* RUNNABLE */
            int mp_ret = ioctl(t_vcpu_fd, KVM_SET_MP_STATE, &mps);
            static __thread int mp_dbg = 0;
            if (mp_dbg < 5) {
                fprintf(stderr, "[DBG-MP] KVM_SET_MP_STATE(RUNNABLE) ret=%d errno=%d vcpu_fd=%d\n",
                        mp_ret, (mp_ret < 0) ? errno : 0, t_vcpu_fd);
                mp_dbg++;
            }
        }
        /* Re-set regs AFTER mp_state in case the transition wiped them */
        sr_ret = ioctl(t_vcpu_fd, KVM_SET_SREGS, &ksregs);
        rr_ret = ioctl(t_vcpu_fd, KVM_SET_REGS, &kregs);
        static int set_dbg = 0;
        if (set_dbg < 10) {
            /* Verify registers actually stuck by reading back */
            struct kvm_regs kr_verify;
            struct kvm_sregs ks_verify;
            ioctl(t_vcpu_fd, KVM_GET_REGS, &kr_verify);
            ioctl(t_vcpu_fd, KVM_GET_SREGS, &ks_verify);
            fprintf(stderr, "[DBG-SET] SET sr=%d rr=%d | VERIFY rip=0x%llx cs_base=0x%llx cs_sel=0x%x rflags=0x%llx\n",
                    sr_ret, rr_ret,
                    (unsigned long long)kr_verify.rip,
                    (unsigned long long)ks_verify.cs.base,
                    (unsigned)ks_verify.cs.selector,
                    (unsigned long long)kr_verify.rflags);
            set_dbg++;
        }
    }

    /* [V30 TSC 同步] 将 master 传来的 TSC 值注入 slave 本地 vCPU，
     * 确保 slave KVM_RUN 期间 guest 读到的 TSC 与 master 侧一致。 */
    if (!req->mode_tcg && req->ctx.kvm.tsc_valid) {
        /* s23g5: GS_BASE/APIC_BASE/SYSCALL when msr_ext_valid set by FE */
        struct {
            struct kvm_msrs info;
            struct kvm_msr_entry entries[9];
        } msr_data;
        int n = 3;
        memset(&msr_data, 0, sizeof(msr_data));
        msr_data.entries[0].index = 0x10;       /* MSR_IA32_TSC */
        msr_data.entries[0].data  = req->ctx.kvm.tsc_value;
        msr_data.entries[1].index = 0x6e0;      /* MSR_IA32_TSCDEADLINE */
        msr_data.entries[1].data  = req->ctx.kvm.tsc_deadline;
        msr_data.entries[2].index = 0xC0000102;  /* MSR_KERNEL_GS_BASE */
        msr_data.entries[2].data  = req->ctx.kvm.kernel_gs_base;
        if (req->ctx.kvm.msr_ext_valid & 0x1) {
            msr_data.entries[n].index = 0xC0000101;
            msr_data.entries[n].data  = req->ctx.kvm.gs_base;
            n++;
        }
        if (req->ctx.kvm.msr_ext_valid & 0x2) {
            msr_data.entries[n].index = 0x1b;
            msr_data.entries[n].data  = req->ctx.kvm.apic_base;
            n++;
        }
        if (req->ctx.kvm.msr_ext_valid & 0x4) {
            msr_data.entries[n].index = 0xC0000081;
            msr_data.entries[n].data  = req->ctx.kvm.star;
            n++;
            msr_data.entries[n].index = 0xC0000082;
            msr_data.entries[n].data  = req->ctx.kvm.lstar;
            n++;
            msr_data.entries[n].index = 0xC0000083;
            msr_data.entries[n].data  = req->ctx.kvm.cstar;
            n++;
            msr_data.entries[n].index = 0xC0000084;
            msr_data.entries[n].data  = req->ctx.kvm.sfmask;
            n++;
        }
        msr_data.info.nmsrs = n;
        ioctl(t_vcpu_fd, KVM_SET_MSRS, &msr_data);
    }

    /*
     * Establish the input side of the KVM handoff before KVM_RUN. KVM does
     * not surface guest read faults to this userspace executor, so a missing
     * instruction-fetch page must be resolved before the vCPU can execute.
     * Keep this slice open through dirty-page capture and write-back below.
     */
    struct wvm_kvm_memory_slice *memory_slice = NULL;
    int memory_fence_status = 0;
    uint64_t memory_error_gpa = 0;
    int execution_window_active = 0;
    if (!req->mode_tcg && wvm_kvm_page_cache_global_active()) {
        char cache_error[256] = {0};

        /*
         * s23g2: SHM-backed guest RAM (!g_wvm_device_ram_mapping) is already
         * coherent with FE. The typed page-cache fence fails on GPAs dirtied
         * outside the execution snapshot; vcpu_service then maps
         * MEMORY_FAILURE → status=-EFAULT with a *zeroed* ACK (no CPU ctx),
         * which FE must not import. Skip the typed slice under SHM so remote
         * KVM ACKs carry real state (dual-yes hang fix).
         */
        if (!g_wvm_device_ram_mapping) {
            static int shm_fence_dbg;
            if (shm_fence_dbg++ < 8) {
                fprintf(stderr,
                        "[KVM cache] SHM coherent — skip typed memory "
                        "slice fence\n");
            }
        } else if (wvm_kvm_memory_slice_global_begin(
                       &memory_slice, cache_error, sizeof(cache_error)) != 0) {
            memory_fence_status = WVM_CPU_RUN_STATUS_MEMORY_FAILURE;
            if (cache_error[0] != '\0') {
                fprintf(stderr,
                        "[KVM cache] cannot begin execution slice: %s\n",
                        cache_error);
            }
        } else if (prepare_kvm_execution_snapshot(
                       hdr, &req->ctx.kvm, &memory_error_gpa) != 0) {
            memory_fence_status = WVM_CPU_RUN_STATUS_MEMORY_FAILURE;
            fprintf(stderr,
                    "[KVM cache] execution input snapshot failed GPA=%#llx\n",
                    (unsigned long long)memory_error_gpa);
        } else if (wvm_kvm_execution_global_begin(
                       cache_error, sizeof(cache_error)) != 0) {
            memory_fence_status = WVM_CPU_RUN_STATUS_MEMORY_FAILURE;
            fprintf(stderr, "[KVM cache] cannot begin execution window: %s\n",
                    cache_error[0] ? cache_error : "busy");
        } else {
            execution_window_active = 1;
        }
    }

    /* [DBG] Print RAW incoming ctx BEFORE assignment */
    {
        static int dbg_raw = 0;
        if (dbg_raw < 50) {
            wvm_kvm_context_t *rctx = &req->ctx.kvm;
            struct kvm_sregs *rs = (struct kvm_sregs *)rctx->sregs_data;
            uint64_t gpa = rs->cs.base + rctx->rip;
            fprintf(stderr, "[DBG-RAW] req=%llu rip=0x%llx rax=0x%llx rdx=0x%llx cs_base=0x%llx cs_sel=0x%x exit=%u\n",
                (unsigned long long)hdr->req_id,
                (unsigned long long)rctx->rip,
                (unsigned long long)rctx->rax,
                (unsigned long long)rctx->rdx,
                (unsigned long long)rs->cs.base,
                (unsigned)rs->cs.selector,
                (unsigned)rctx->exit_reason);
            /* [DIAG] Dump 16 bytes from SHM at trampoline GPA */
            if (g_phy_ram && gpa + 16 <= 0x80000000ULL) {
                uint8_t *p = g_phy_ram + gpa;
                fprintf(stderr, "[SLAVE-MEM] GPA=0x%llx bytes:"
                        " %02x %02x %02x %02x %02x %02x %02x %02x"
                        " %02x %02x %02x %02x %02x %02x %02x %02x\n",
                        (unsigned long long)gpa,
                        p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
                        p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15]);
            }
            dbg_raw++;
        }
    }

    /* [DBG] Print registers before KVM_RUN for first 10 requests */
    {
        static int dbg_count = 0;
        if (dbg_count < 10) {
            wvm_kvm_context_t *dctx = &req->ctx.kvm;
            fprintf(stderr, "[DBG-REGS] req=%llu rip=0x%llx cs_base=0x%llx cs_sel=0x%x rflags=0x%llx rax=0x%llx exit=%u io_port=0x%x io_dir=%u io_sz=%u\n",
                (unsigned long long)hdr->req_id,
                (unsigned long long)kregs.rip,
                (unsigned long long)ksregs.cs.base,
                (unsigned)ksregs.cs.selector,
                (unsigned long long)kregs.rflags,
                (unsigned long long)kregs.rax,
                (unsigned)dctx->exit_reason,
                (unsigned)dctx->io.port,
                (unsigned)dctx->io.direction,
                (unsigned)dctx->io.size);
            dbg_count++;
        }
    }

    /* [FIX] 恢复上一轮 IO IN / MMIO READ 的设备读结果：
     * Master 已在本地执行 address_space_rw 读取设备并填入 kctx->io.data / mmio.data，
     * 需要写回 t_kvm_run 以便 KVM_RUN 完成未决 IO 指令。 */
    if (!req->mode_tcg) {
        wvm_kvm_context_t *rctx = &req->ctx.kvm;
        if (rctx->exit_reason == KVM_EXIT_IO &&
            rctx->io.direction == KVM_EXIT_IO_IN) {
            t_kvm_run->exit_reason = KVM_EXIT_IO;
            t_kvm_run->io.direction = rctx->io.direction;
            t_kvm_run->io.size      = rctx->io.size;
            t_kvm_run->io.port      = rctx->io.port;
            t_kvm_run->io.count     = rctx->io.count;
            size_t io_bytes = (size_t)rctx->io.size * rctx->io.count;
            if (io_bytes > sizeof(rctx->io.data)) io_bytes = sizeof(rctx->io.data);
            uint8_t *io_ptr = (uint8_t *)t_kvm_run + t_kvm_run->io.data_offset;
            memcpy(io_ptr, rctx->io.data, io_bytes);
        } else if (rctx->exit_reason == KVM_EXIT_MMIO &&
                   !rctx->mmio.is_write) {
            t_kvm_run->exit_reason = KVM_EXIT_MMIO;
            t_kvm_run->mmio.phys_addr = rctx->mmio.phys_addr;
            t_kvm_run->mmio.len       = rctx->mmio.len;
            t_kvm_run->mmio.is_write  = 0;
            memcpy(t_kvm_run->mmio.data, rctx->mmio.data, 8);
        }
    }

    /*
     * Do not short-circuit guest HLT.  A bounded KVM_RUN is a host-side
     * scheduling preemption, not a guest halt, and is returned as
     * WVM_EXIT_PREEMPT below.
     */

    int ret = -EIO;

    if (memory_fence_status != 0) {
        /*
         * Never enter KVM with an unresolved input snapshot. The transport
         * status tells the requester to retry after resynchronization.
         */
        t_kvm_run->exit_reason = WVM_EXIT_PREEMPT;
        goto kvm_run_done;
    }

    /* --- Thread-directed alarm: 50ms timeout for KVM_RUN --- */
    t_kvm_alarm_fired = 0;
    struct sigaction sa_new, sa_old;
    memset(&sa_new, 0, sizeof(sa_new));
    sa_new.sa_handler = kvm_alarm_handler;
    sa_new.sa_flags = 0; /* no SA_RESTART so ioctl gets EINTR */
    sigaction(SIGALRM, &sa_new, &sa_old);

    timer_t ktimer;
    struct sigevent sev;
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_THREAD_ID;
    sev._sigev_un._tid = (pid_t)syscall(__NR_gettid);
    sev.sigev_signo = SIGALRM;
    timer_create(CLOCK_MONOTONIC, &sev, &ktimer);

    struct itimerspec its = {
        .it_value = { .tv_sec = 0, .tv_nsec = 50000000 }, /* 50ms */
        .it_interval = { 0, 0 }
    };
    timer_settime(ktimer, 0, &its, NULL);

    for (;;) {
        if (g_shutdown_requested) {
            ret = -EINTR;
            break;
        }
        if (g_kvm_immediate_exit) {
            __atomic_store_n(&t_kvm_run->immediate_exit, 0, __ATOMIC_RELEASE);
        }
        ret = ioctl(t_vcpu_fd, KVM_RUN, 0);
        if (ret == 0 && t_kvm_run->exit_reason == KVM_EXIT_MMIO) {
            /* Intercept LAPIC MMIO (0xfee00000-0xfee00fff).  Without in-kernel
             * LAPIC bound to this vCPU these exit to userspace.  Emulate
             * critical registers (especially APIC ID) so the guest kernel
             * doesn't get confused about which CPU it's running on. */
            uint64_t pa = t_kvm_run->mmio.phys_addr;
            if (pa >= 0xfee00000ULL && pa < 0xfee01000ULL) {
                uint32_t reg_off = (uint32_t)(pa - 0xfee00000ULL);
                static int lapic_dbg = 0;
                if (lapic_dbg < 50) {
                    fprintf(stderr, "[Slave-LAPIC] vcpu=%d %s reg=0x%03x len=%u data=0x",
                            guest_vcpu_id,
                            t_kvm_run->mmio.is_write ? "WR" : "RD",
                            reg_off, t_kvm_run->mmio.len);
                    for (int bi = t_kvm_run->mmio.len - 1; bi >= 0; bi--)
                        fprintf(stderr, "%02x", t_kvm_run->mmio.data[bi]);
                    fprintf(stderr, "\n");
                    lapic_dbg++;
                }
                /*
                 * No in-kernel irqchip on slave: identity/status READs stay
                 * local to avoid ICR-poll thrash. WRITES (timer/LVT/ICR/TPR/
                 * EOI/...) and non-identity READs bounce to FE as KVM_EXIT_MMIO
                 * so the master's real LAPIC (KVM_SET_LAPIC) sees programming.
                 * Dual-yes hang root: stubbing timer writes left remote AP
                 * without ticks under sustained busy.
                 */
                if (!t_kvm_run->mmio.is_write) {
                    uint32_t val = 0;
                    int stub = 1;
                    switch (reg_off) {
                    case 0x020: /* APIC ID */
                        val = ((uint32_t)guest_vcpu_id) << 24;
                        break;
                    case 0x030: /* APIC Version */
                        val = 0x50014;
                        break;
                    case 0x0D0: /* LDR */
                        val = (1U << (guest_vcpu_id & 7)) << 24;
                        break;
                    case 0x0E0: /* DFR */
                        val = 0xFFFFFFFFU;
                        break;
                    case 0x0F0: /* SVR */
                        val = 0x1FF;
                        break;
                    case 0x300: /* ICR low -- delivery status=idle */
                        val = 0;
                        break;
                    default:
                        stub = 0;
                        break;
                    }
                    if (stub) {
                        memcpy(t_kvm_run->mmio.data, &val, sizeof(val));
                        if (t_kvm_run->mmio.len < 4)
                            memset(t_kvm_run->mmio.data + t_kvm_run->mmio.len, 0,
                                   8 - t_kvm_run->mmio.len);
                        if (t_kvm_alarm_fired) break;
                        continue;
                    }
                    /* Non-identity read: fall through to FE bounce. */
                    break;
                }
                /* LAPIC write: bounce to FE (do not stub). */
                break;
            }
            if (wvm_vfio_intercept_mmio(
                    t_kvm_run->mmio.phys_addr,
                    t_kvm_run->mmio.data,
                    t_kvm_run->mmio.len,
                    t_kvm_run->mmio.is_write)) {
                if (t_kvm_alarm_fired) break;
                continue;
            }
        }
        if (ret == 0) break; /* normal exit (IO, HLT, etc.) */
        if (ret == -1 && errno == EINTR && !t_kvm_alarm_fired)
            continue; /* signal interrupted, retry */
        break; /* error or alarm fired */
    }

    /* [DBG] Print KVM_RUN result for first 20 requests */
    {
        static int dbg_out = 0;
        if (dbg_out < 20) {
            fprintf(stderr, "[DBG-EXIT] ret=%d exit=%u rip_after=?  io_port=0x%x io_dir=%u io_sz=%u alarm=%d\n",
                ret, (unsigned)t_kvm_run->exit_reason,
                (unsigned)t_kvm_run->io.port,
                (unsigned)t_kvm_run->io.direction,
                (unsigned)t_kvm_run->io.size,
                (int)t_kvm_alarm_fired);
            dbg_out++;
        }
    }

    /* Disarm and clean up */
    memset(&its, 0, sizeof(its));
    timer_settime(ktimer, 0, &its, NULL);
    timer_delete(ktimer);
    sigaction(SIGALRM, &sa_old, NULL);
    if (g_kvm_immediate_exit) {
        __atomic_store_n(&t_kvm_run->immediate_exit, 0, __ATOMIC_RELEASE);
    }

kvm_run_done:
    /* Host slice expiry is preemption, not a guest HLT. */
    if (t_kvm_alarm_fired) {
        fprintf(stderr, "[Slave] KVM_RUN slice expired -- returning preempt exit\n");
        t_kvm_run->exit_reason = WVM_EXIT_PREEMPT;
    }

    /* [DBG] Log KVM_EXIT_INTERNAL_ERROR and SHUTDOWN details */
    if (t_kvm_run->exit_reason == 17) {
        static int dbg_ie = 0;
        if (dbg_ie < 20) {
            fprintf(stderr, "[DBG-INTERR] req=%llu suberror=%u ndata=%u",
                    (unsigned long long)hdr->req_id,
                    t_kvm_run->internal.suberror, t_kvm_run->internal.ndata);
            for (uint32_t di = 0; di < t_kvm_run->internal.ndata && di < 8; di++)
                fprintf(stderr, " d[%u]=%llx", di, (unsigned long long)t_kvm_run->internal.data[di]);
            fprintf(stderr, "\n");
            struct kvm_regs kr2; struct kvm_sregs ks2;
            ioctl(t_vcpu_fd, KVM_GET_REGS, &kr2);
            ioctl(t_vcpu_fd, KVM_GET_SREGS, &ks2);
            fprintf(stderr, "[DBG-INTERR] rip=0x%llx rflags=0x%llx cs=0x%x cs_base=0x%llx cr0=0x%llx cr4=0x%llx efer=0x%llx\n",
                    (unsigned long long)kr2.rip, (unsigned long long)kr2.rflags,
                    ks2.cs.selector, (unsigned long long)ks2.cs.base,
                    (unsigned long long)ks2.cr0, (unsigned long long)ks2.cr4,
                    (unsigned long long)ks2.efer);
            dbg_ie++;
        }
    }
    if (t_kvm_run->exit_reason == 9) { /* KVM_EXIT_FAIL_ENTRY */
        static int dbg_fe = 0;
        if (dbg_fe < 10) {
            fprintf(stderr,
                    "[DBG-FAIL_ENTRY] req=%llu hardware_failure=0x%llx rip=0x%llx\n",
                    (unsigned long long)hdr->req_id,
                    (unsigned long long)t_kvm_run->fail_entry.hardware_entry_failure_reason,
                    (unsigned long long)req->ctx.kvm.rip);
            dbg_fe++;
        }
    }
    if (t_kvm_run->exit_reason == 8) {
        fprintf(stderr, "[DBG-SHUTDOWN] req=%llu -- triple fault!\n",
                (unsigned long long)hdr->req_id);
        struct kvm_regs kr2; struct kvm_sregs ks2;
        ioctl(t_vcpu_fd, KVM_GET_REGS, &kr2);
        ioctl(t_vcpu_fd, KVM_GET_SREGS, &ks2);
        fprintf(stderr, "[DBG-SHUTDOWN] after: rip=0x%llx rsp=0x%llx rflags=0x%llx\n",
                (unsigned long long)kr2.rip, (unsigned long long)kr2.rsp,
                (unsigned long long)kr2.rflags);
        fprintf(stderr, "[DBG-SHUTDOWN] after: cs=0x%x/0x%llx ds=0x%x ss=0x%x\n",
                ks2.cs.selector, (unsigned long long)ks2.cs.base,
                ks2.ds.selector, ks2.ss.selector);
        fprintf(stderr, "[DBG-SHUTDOWN] after: cr0=0x%llx cr3=0x%llx cr4=0x%llx efer=0x%llx\n",
                (unsigned long long)ks2.cr0, (unsigned long long)ks2.cr3,
                (unsigned long long)ks2.cr4, (unsigned long long)ks2.efer);
        fprintf(stderr, "[DBG-SHUTDOWN] after: idt_base=0x%llx idt_limit=0x%x gdt_base=0x%llx gdt_limit=0x%x\n",
                (unsigned long long)ks2.idt.base, ks2.idt.limit,
                (unsigned long long)ks2.gdt.base, ks2.gdt.limit);
        /* Dump what we SET before KVM_RUN (the incoming state from QEMU) */
        wvm_kvm_context_t *sctx = &req->ctx.kvm;
        struct kvm_sregs *in_s = (struct kvm_sregs *)sctx->sregs_data;
        fprintf(stderr, "[DBG-SHUTDOWN] input: rip=0x%llx rsp=0x%llx rflags=0x%llx exit=%u\n",
                (unsigned long long)sctx->rip, (unsigned long long)sctx->rsp,
                (unsigned long long)sctx->rflags, sctx->exit_reason);
        fprintf(stderr, "[DBG-SHUTDOWN] input: cs=0x%x/0x%llx ds=0x%x ss=0x%x\n",
                in_s->cs.selector, (unsigned long long)in_s->cs.base,
                in_s->ds.selector, in_s->ss.selector);
        fprintf(stderr, "[DBG-SHUTDOWN] input: cr0=0x%llx cr3=0x%llx cr4=0x%llx efer=0x%llx\n",
                (unsigned long long)in_s->cr0, (unsigned long long)in_s->cr3,
                (unsigned long long)in_s->cr4, (unsigned long long)in_s->efer);
        fprintf(stderr, "[DBG-SHUTDOWN] input: idt_base=0x%llx idt_limit=0x%x gdt_base=0x%llx gdt_limit=0x%x\n",
                (unsigned long long)in_s->idt.base, in_s->idt.limit,
                (unsigned long long)in_s->gdt.base, in_s->gdt.limit);
        /* Check BIOS integrity at 0xFFFF0 */
        fprintf(stderr, "[DBG-SHUTDOWN] bios@0xFFFF0=%08x bios@0xF0000=%08x\n",
                *(uint32_t*)(g_phy_ram + 0xFFFF0),
                *(uint32_t*)(g_phy_ram + 0xF0000));
    }

    /*
     * A full WVM_NUMA_MAP uses shared-memory RAM even in Mode A.  Keep the
     * device open for control/ioctl handling, but harvest KVM dirty pages
     * whenever RAM is not actually backed by /dev/wavevm.
     */
    if (!g_wvm_device_ram_mapping && memory_fence_status == 0) {
        // [V28.5 FIXED] KVM Dirty Log Sync (Full Implementation)
        // 完整实现：获取位图 -> 遍历 -> 封包 -> 发送
        struct kvm_dirty_log log = { .slot = 0 };
        size_t nbits_per_long = sizeof(unsigned long) * 8;

        for (int sidx = 0; sidx < g_kvm_slot_count; sidx++) {
            const wvm_kvm_slot_t *slot = &g_kvm_slots[sidx];
            if (!slot->track_dirty) {
                continue;
            }

            /* Slot-local dirty bitmap. */
            uint64_t pages = slot->size / WVM_PAGE_SIZE;
            size_t bitmap_size = (size_t)(((pages + nbits_per_long - 1) / nbits_per_long) * sizeof(unsigned long));
            if (bitmap_size == 0) {
                continue;
            }

            if (!t_dirty_bitmap_cache || t_dirty_bitmap_size < bitmap_size) {
                if (t_dirty_bitmap_cache) free(t_dirty_bitmap_cache);
                t_dirty_bitmap_cache = malloc(bitmap_size);
                t_dirty_bitmap_size = bitmap_size;
            }
            if (!t_dirty_bitmap_cache) {
                perror("malloc dirty bitmap");
                memory_fence_status = WVM_CPU_RUN_STATUS_MEMORY_FAILURE;
                break;
            }

            log.slot = slot->slot;
            log.dirty_bitmap = t_dirty_bitmap_cache;
            memset(log.dirty_bitmap, 0, bitmap_size);

            if (ioctl(g_vm_fd, KVM_GET_DIRTY_LOG, &log) != 0) {
                /* F7: capture failure must not allow successful handoff/fence. */
                memory_fence_status = WVM_CPU_RUN_STATUS_MEMORY_FAILURE;
                break;
            }

            unsigned long *p = (unsigned long *)log.dirty_bitmap;
            uint64_t num_longs = bitmap_size / sizeof(unsigned long);

            for (uint64_t i = 0; i < num_longs; i++) {
                if (p[i] == 0) continue;

                for (size_t b = 0; b < nbits_per_long; b++) {
                    if ((p[i] >> b) & 1) {
                        uint64_t gpa = slot->guest_phys_addr +
                                       (i * nbits_per_long + b) * WVM_PAGE_SIZE;
                        /* F7: hardware dirty bit already cleared by GET_DIRTY_LOG;
                         * skipping without MEMORY_FAILURE would lose dirty state
                         * and still allow a successful handoff/fence. */
                        if (gpa >= g_slave_ram_size) {
                            memory_fence_status =
                                WVM_CPU_RUN_STATUS_MEMORY_FAILURE;
                            break;
                        }

                        uint8_t *hva = wvm_gpa_to_hva(gpa);
                        if (!hva) {
                            memory_fence_status =
                                WVM_CPU_RUN_STATUS_MEMORY_FAILURE;
                            break;
                        }

                        struct wvm_kvm_dirty_page dirty;
                        dirty_page_task_t *task;

                        memset(&dirty, 0, sizeof(dirty));
                        if (memory_slice &&
                            wvm_kvm_memory_slice_capture_dirty(
                                memory_slice, gpa, &dirty, NULL, 0) != 0) {
                            /*
                             * s23g2: Page was dirtied during the KVM slice but
                             * never admitted as CLEAN in the execution
                             * snapshot (no typed clean base). Under
                             * device-backed RAM that is a hard fence failure.
                             * Under SHM-backed RAM the bytes are already
                             * visible to FE via the shared mapping; failing
                             * the whole handoff makes FE drop the ACK
                             * (status=MEMORY_FAILURE) and re-dispatch the
                             * same stale RIP forever — the KVM dual-yes hang.
                             */
                            if (g_wvm_device_ram_mapping) {
                                wvm_kvm_memory_slice_fail(
                                    memory_slice, gpa, NULL, 0);
                                memory_fence_status =
                                    WVM_CPU_RUN_STATUS_MEMORY_FAILURE;
                                continue;
                            }
                            {
                                static int shm_skip_dbg;
                                if (shm_skip_dbg++ < 30) {
                                    fprintf(stderr,
                                            "[KVM cache] SHM skip typed dirty "
                                            "GPA=%#" PRIx64
                                            " (no clean base; shared RAM)\n",
                                            gpa);
                                }
                            }
                            continue;
                        }
                        task = malloc(sizeof(dirty_page_task_t));
                        if (!task) {
                            if (memory_slice) {
                                dirty_page_task_t emergency;

                                memset(&emergency, 0, sizeof(emergency));
                                emergency.slice = memory_slice;
                                emergency.dirty = dirty;
                                emergency.gpa = gpa;
                                memcpy(emergency.data, hva, 4096);
                                submit_typed_dirty_page(&emergency);
                            } else {
                                emergency_send_dirty_page(gpa, hva);
                            }
                            continue;
                        }

                        task->gpa = gpa;
                        task->slice = memory_slice;
                        task->dirty = dirty;
                        memcpy(task->data, hva, 4096);

                        /* [FIX] next_tail 计算和满队检查必须在锁内。
                         * 旧代码在锁外读 g_mpsc_tail 算 next_tail，多线程下
                         * 两个线程会算出相同的 next_tail 并覆盖同一个槽位。
                         * 当前 total_threads=1 不会触发，但扩展并发后必崩。
                         */
                        pthread_mutex_lock(&g_mpsc_lock);
                        uint32_t next_tail = (g_mpsc_tail + 1) % MPSC_QUEUE_SIZE;
                        if (next_tail == g_mpsc_head) {
                            pthread_mutex_unlock(&g_mpsc_lock);
                            // Queue pressure uses the same typed commit path.
                            if (task->slice) {
                                submit_typed_dirty_page(task);
                            } else {
                                emergency_send_dirty_page(gpa, hva);
                            }
                            free(task);
                            continue;
                        }
                        g_mpsc_queue[g_mpsc_tail] = task;
                        g_mpsc_tail = next_tail;
                        pthread_mutex_unlock(&g_mpsc_lock);

                        pthread_cond_signal(&g_mpsc_cond);
                    }
                }
            }
        }
    }
    if (memory_slice) {
        int slice_success = 0;
        uint64_t error_gpa = 0;
        char cache_error[256] = {0};

        if (wvm_kvm_memory_slice_seal(
                memory_slice, cache_error, sizeof(cache_error)) != 0 ||
            wvm_kvm_memory_slice_wait(
                memory_slice, &slice_success, &error_gpa, cache_error,
                sizeof(cache_error)) != 0 ||
            !slice_success) {
            memory_fence_status = WVM_CPU_RUN_STATUS_MEMORY_FAILURE;
            if (error_gpa != 0) {
                memory_error_gpa = error_gpa;
            }
            fprintf(stderr,
                    "[KVM cache] slice commit failed GPA=%#" PRIx64
                    " reason=%s\n",
                    error_gpa, cache_error[0] ? cache_error : "resync required");
        }
        wvm_kvm_memory_slice_destroy(memory_slice);
        memory_slice = NULL;
    }
    if (execution_window_active) {
        wvm_kvm_execution_global_end();
        execution_window_active = 0;
    }
    // 导出寄存器状态并回包
    ioctl(t_vcpu_fd, KVM_GET_REGS, &kregs); ioctl(t_vcpu_fd, KVM_GET_SREGS, &ksregs);
    
    /* [DBG] Print registers AFTER KVM_RUN (what we send back) */
    {
        static int dbg_ack = 0;
        if (dbg_ack < 15) {
            fprintf(stderr, "[DBG-ACK] req=%llu rip=0x%llx cs_base=0x%llx cs_sel=0x%x rflags=0x%llx exit=%u\n",
                (unsigned long long)hdr->req_id,
                (unsigned long long)kregs.rip,
                (unsigned long long)ksregs.cs.base,
                (unsigned)ksregs.cs.selector,
                (unsigned long long)kregs.rflags,
                (unsigned)t_kvm_run->exit_reason);
            dbg_ack++;
        }
    }
    
    struct wvm_header ack_hdr;
    memset(&ack_hdr, 0, sizeof(ack_hdr));
    ack_hdr.magic = htonl(WVM_MAGIC);              
    ack_hdr.msg_type = htons(MSG_VCPU_EXIT);       
    ack_hdr.payload_len = htons(sizeof(struct wvm_ipc_cpu_run_ack));
    /* ACK must originate from this slave node and target the requester. */
    wvm_slave_pack_src(&ack_hdr);
    ack_hdr.target_id = htonl(hdr->slave_id);  /* s23g13: hdr host-order after ntoh_header */
    wvm_ack_copy_assoc(&ack_hdr, hdr);
    ack_hdr.req_id = WVM_HTONLL(hdr->req_id);
    
    struct wvm_ipc_cpu_run_ack *ack = (struct wvm_ipc_cpu_run_ack *)payload;
    ack->status = memory_fence_status;
    ack->error_gpa = memory_error_gpa;
    ack->mode_tcg = req->mode_tcg;
    if (req->mode_tcg) {
        wvm_translate_kvm_to_tcg(&kregs, &ksregs, &ack->ctx.tcg);
        ack->ctx.tcg.exit_reason = t_kvm_run->exit_reason;
        ack->ctx.tcg.halted = (t_kvm_run->exit_reason == KVM_EXIT_HLT) ? 1 : 0;
        ack->ctx.tcg.interrupt_request = 0;
    } else {
        wvm_kvm_context_t *ack_kctx = &ack->ctx.kvm;
        ack_kctx->rax = kregs.rax; ack_kctx->rbx = kregs.rbx; ack_kctx->rcx = kregs.rcx; ack_kctx->rdx = kregs.rdx;
        ack_kctx->rsi = kregs.rsi; ack_kctx->rdi = kregs.rdi; ack_kctx->rsp = kregs.rsp; ack_kctx->rbp = kregs.rbp;
        ack_kctx->r8  = kregs.r8;  ack_kctx->r9  = kregs.r9;  ack_kctx->r10 = kregs.r10; ack_kctx->r11 = kregs.r11;
        ack_kctx->r12 = kregs.r12; ack_kctx->r13 = kregs.r13; ack_kctx->r14 = kregs.r14; ack_kctx->r15 = kregs.r15;
        ack_kctx->rip = kregs.rip; ack_kctx->rflags = kregs.rflags;
        memcpy(ack_kctx->sregs_data, &ksregs, sizeof(ksregs));
        ack_kctx->exit_reason = t_kvm_run->exit_reason;

        /* [V30 TSC 同步] 读回 slave 端 KVM_RUN 后的 TSC，带回 master。
         * slave 执行期间 TSC 自然递增，master 需要这个更新后的值来
         * 保持 kvmclock 的单调性。 */
        {
            /* s23g5: return GS_BASE/APIC_BASE/SYSCALL with TSC */
            struct {
                struct kvm_msrs info;
                struct kvm_msr_entry entries[9];
            } msr_data;
            memset(&msr_data, 0, sizeof(msr_data));
            msr_data.info.nmsrs = 9;
            msr_data.entries[0].index = 0x10;       /* MSR_IA32_TSC */
            msr_data.entries[1].index = 0x6e0;      /* MSR_IA32_TSCDEADLINE */
            msr_data.entries[2].index = 0xC0000102;  /* MSR_KERNEL_GS_BASE */
            msr_data.entries[3].index = 0xC0000101;  /* MSR_GS_BASE */
            msr_data.entries[4].index = 0x1b;        /* IA32_APIC_BASE */
            msr_data.entries[5].index = 0xC0000081;  /* STAR */
            msr_data.entries[6].index = 0xC0000082;  /* LSTAR */
            msr_data.entries[7].index = 0xC0000083;  /* CSTAR */
            msr_data.entries[8].index = 0xC0000084;  /* SFMASK */
            if (ioctl(t_vcpu_fd, KVM_GET_MSRS, &msr_data) >= 0) {
                ack_kctx->tsc_value = msr_data.entries[0].data;
                ack_kctx->tsc_deadline = msr_data.entries[1].data;
                ack_kctx->kernel_gs_base = msr_data.entries[2].data;
                ack_kctx->tsc_valid = 1;
                ack_kctx->gs_base = msr_data.entries[3].data;
                ack_kctx->apic_base = msr_data.entries[4].data;
                ack_kctx->star = msr_data.entries[5].data;
                ack_kctx->lstar = msr_data.entries[6].data;
                ack_kctx->cstar = msr_data.entries[7].data;
                ack_kctx->sfmask = msr_data.entries[8].data;
                ack_kctx->msr_ext_valid = 0x7;
            } else {
                ack_kctx->tsc_valid = 0;
                ack_kctx->msr_ext_valid = 0;
            }
        }

        if (t_kvm_run->exit_reason == KVM_EXIT_IO) {
            ack_kctx->io.direction = t_kvm_run->io.direction;
            ack_kctx->io.size = t_kvm_run->io.size;
            ack_kctx->io.port = t_kvm_run->io.port;
            ack_kctx->io.count = t_kvm_run->io.count;
            if (t_kvm_run->io.direction == KVM_EXIT_IO_OUT) {
                size_t io_bytes = (size_t)t_kvm_run->io.size * t_kvm_run->io.count;
                if (io_bytes > sizeof(ack_kctx->io.data)) io_bytes = sizeof(ack_kctx->io.data);
                memcpy(ack_kctx->io.data, (uint8_t*)t_kvm_run + t_kvm_run->io.data_offset, io_bytes);
            }
        } else if (t_kvm_run->exit_reason == KVM_EXIT_MMIO) {
            ack_kctx->mmio.phys_addr = t_kvm_run->mmio.phys_addr;
            ack_kctx->mmio.len = t_kvm_run->mmio.len;
            ack_kctx->mmio.is_write = t_kvm_run->mmio.is_write;
            memcpy(ack_kctx->mmio.data, t_kvm_run->mmio.data, 8);
        }
    }

    uint8_t tx[sizeof(ack_hdr) + sizeof(*ack)];
    memcpy(tx, &ack_hdr, sizeof(ack_hdr));
    memcpy(tx+sizeof(ack_hdr), ack, sizeof(*ack));
    if (capture_local_executor_ack(ack)) {
        return;
    }
    struct wvm_header *tx_hdr = (struct wvm_header *)tx;
    tx_hdr->crc32 = 0;
    tx_hdr->crc32 = htonl(calculate_crc32(tx, sizeof(tx)));
    vcpu_exit_cache_complete(run_req_id, requester, tx, sizeof(tx));
    ssize_t sret = sendto(sockfd, tx, sizeof(tx), 0, (struct sockaddr*)client, sizeof(*client));
    fprintf(stderr, "[Slave Ack] ret=%zd errno=%d req=%llu dst=%s:%u exit=%u port=0x%x dir=%u sz=%u\n",
            sret, (sret < 0) ? errno : 0, (unsigned long long)hdr->req_id,
            inet_ntoa(client->sin_addr), ntohs(client->sin_port), t_kvm_run->exit_reason, t_kvm_run->io.port, t_kvm_run->io.direction, t_kvm_run->io.size);
}

/* 
 * [物理意图] 充当远程页面的“受控提供者”，响应来自 Master/Directory 的 MESI 指令。
 * [关键逻辑] 处理 INVALIDATE（失效本地页）、DOWNGRADE（权限降级）及 READ（数据提取），操作本地物理页。
 * [后果] 保证了 Slave 侧物理内存与全网真理的一致。若响应失败，Slave 会持有一份陈旧的数据副本，导致计算错误。
 */
static void build_kvm_snapshot_operation_id(
    const struct wvm_header *hdr, uint64_t gpa,
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES])
{
    uint64_t request_id = hdr ? WVM_NTOHLL(hdr->req_id) : 0;
    uint64_t source_id = hdr ? (uint64_t)ntohl(hdr->slave_id) : 0;

    if (request_id == 0) {
        request_id = gpa ^ (source_id << 32) ^ (uint64_t)g_slave_vm_id;
        if (request_id == 0) {
            request_id = 1;
        }
    }
    memcpy(operation_id, &request_id, sizeof(request_id));
    memcpy(operation_id + sizeof(request_id), &gpa, sizeof(gpa));
}

static int ensure_kvm_page_snapshot(
    const struct wvm_header *hdr, uint64_t gpa, uint8_t *hva,
    uint64_t *version_out)
{
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    char error[256] = {0};
    int result;

    if (!hva || !version_out) {
        return -EINVAL;
    }
    build_kvm_snapshot_operation_id(hdr, gpa, operation_id);
    /*
     * R06: production fetch path shared with the micro KVM evidence harness.
     * Instruction bytes land in HVA before KVM_RUN; execution therefore
     * depends on remote page content, not on a discarded prefetch buffer.
     */
    result = wvm_kvm_fetch_execution_page(gpa, operation_id, hva, version_out,
                                          error, sizeof(error));
    if (result != 0 && error[0] != '\0') {
        fprintf(stderr, "[KVM cache] execution page fetch GPA=%#llx: %s\n",
                (unsigned long long)gpa, error);
    }
    return result;
}

static int ensure_kvm_execution_page(
    const struct wvm_header *hdr, uint64_t gpa, uint64_t *error_gpa_out)
{
    uint64_t version = 0;
    uint8_t *hva;

    gpa &= ~(WVM_PAGE_SIZE - 1U);
    if (error_gpa_out) {
        *error_gpa_out = gpa;
    }
    if (!wvm_gpa_page_valid(gpa) || !(hva = wvm_gpa_to_hva(gpa))) {
        return -EFAULT;
    }
    return ensure_kvm_page_snapshot(hdr, gpa, hva, &version);
}

static int read_kvm_snapshot_u64(
    const struct wvm_header *hdr, uint64_t gpa, uint64_t *value_out,
    uint64_t *error_gpa_out)
{
    uint8_t *hva;
    int result;

    if (!value_out || (gpa & (sizeof(uint64_t) - 1U)) != 0 ||
        (gpa & (WVM_PAGE_SIZE - 1U)) >
            WVM_PAGE_SIZE - sizeof(uint64_t)) {
        return -EINVAL;
    }
    result = ensure_kvm_execution_page(
        hdr, gpa, error_gpa_out);
    if (result != 0) {
        return result;
    }
    hva = wvm_gpa_to_hva(gpa);
    if (!hva) {
        return -EFAULT;
    }
    memcpy(value_out, hva, sizeof(*value_out));
    return 0;
}

static int read_kvm_snapshot_u32(
    const struct wvm_header *hdr, uint64_t gpa, uint32_t *value_out,
    uint64_t *error_gpa_out)
{
    uint8_t *hva;
    int result;

    if (!value_out || (gpa & (sizeof(uint32_t) - 1U)) != 0 ||
        (gpa & (WVM_PAGE_SIZE - 1U)) >
            WVM_PAGE_SIZE - sizeof(uint32_t)) {
        return -EINVAL;
    }
    result = ensure_kvm_execution_page(
        hdr, gpa, error_gpa_out);
    if (result != 0) {
        return result;
    }
    hva = wvm_gpa_to_hva(gpa);
    if (!hva) {
        return -EFAULT;
    }
    memcpy(value_out, hva, sizeof(*value_out));
    return 0;
}

static int translate_kvm_linear_to_gpa(
    const struct wvm_header *hdr, const struct kvm_sregs *sregs,
    uint64_t linear, uint64_t *gpa_out, uint64_t *error_gpa_out)
{
    const uint64_t page_mask = UINT64_C(0x000ffffffffff000);
    const uint64_t present = UINT64_C(1);
    const uint64_t large_page = UINT64_C(1) << 7;
    uint64_t entry;
    uint64_t table;
    int result;

    if (!sregs || !gpa_out) {
        return -EINVAL;
    }
    if ((sregs->cr0 & (UINT64_C(1) << 31)) == 0) {
        *gpa_out = linear;
        return 0;
    }

    if ((sregs->efer & (UINT64_C(1) << 10)) != 0) {
        int levels = (sregs->cr4 & (UINT64_C(1) << 12)) != 0 ? 5 : 4;

        table = sregs->cr3 & page_mask;
        for (int level = levels; level > 0; level--) {
            uint64_t index = (linear >> (12 + 9 * (level - 1))) & 0x1ffU;

            result = read_kvm_snapshot_u64(
                hdr, table + index * sizeof(uint64_t), &entry,
                error_gpa_out);
            if (result != 0 || (entry & present) == 0) {
                return result != 0 ? result : -ENOENT;
            }
            if ((level == 3 || level == 2) && (entry & large_page) != 0) {
                unsigned int page_shift = 12U + 9U * (unsigned int)(level - 1);
                uint64_t base_mask =
                    ~(UINT64_MAX >> (64U - page_shift));

                *gpa_out = (entry & page_mask & base_mask) |
                           (linear & ~base_mask);
                return 0;
            }
            table = entry & page_mask;
        }
        *gpa_out = table | (linear & (WVM_PAGE_SIZE - 1U));
        return 0;
    }

    if ((sregs->cr4 & (UINT64_C(1) << 5)) != 0) {
        uint64_t pdpt_index = (linear >> 30) & 0x3U;
        uint64_t pd_index = (linear >> 21) & 0x1ffU;
        uint64_t pt_index = (linear >> 12) & 0x1ffU;

        table = sregs->cr3 & ~UINT64_C(0x1f);
        result = read_kvm_snapshot_u64(
            hdr, table + pdpt_index * sizeof(uint64_t), &entry,
            error_gpa_out);
        if (result != 0 || (entry & present) == 0) {
            return result != 0 ? result : -ENOENT;
        }
        table = entry & page_mask;
        result = read_kvm_snapshot_u64(
            hdr, table + pd_index * sizeof(uint64_t), &entry,
            error_gpa_out);
        if (result != 0 || (entry & present) == 0) {
            return result != 0 ? result : -ENOENT;
        }
        if ((entry & large_page) != 0) {
            *gpa_out = (entry & UINT64_C(0x000fffffffe00000)) |
                       (linear & UINT64_C(0x1fffff));
            return 0;
        }
        table = entry & page_mask;
        result = read_kvm_snapshot_u64(
            hdr, table + pt_index * sizeof(uint64_t), &entry,
            error_gpa_out);
        if (result != 0 || (entry & present) == 0) {
            return result != 0 ? result : -ENOENT;
        }
        *gpa_out = (entry & page_mask) |
                   (linear & (WVM_PAGE_SIZE - 1U));
        return 0;
    }

    {
        uint32_t pde;
        uint32_t pte;
        uint64_t pd_index = (linear >> 22) & 0x3ffU;
        uint64_t pt_index = (linear >> 12) & 0x3ffU;

        table = sregs->cr3 & UINT64_C(0xfffff000);
        result = read_kvm_snapshot_u32(
            hdr, table + pd_index * sizeof(uint32_t), &pde,
            error_gpa_out);
        if (result != 0 || (pde & present) == 0) {
            return result != 0 ? result : -ENOENT;
        }
        if ((pde & large_page) != 0) {
            *gpa_out = ((uint64_t)pde & UINT64_C(0xffc00000)) |
                       (linear & UINT64_C(0x3fffff));
            return 0;
        }
        table = (uint64_t)pde & UINT64_C(0xfffff000);
        result = read_kvm_snapshot_u32(
            hdr, table + pt_index * sizeof(uint32_t), &pte,
            error_gpa_out);
        if (result != 0 || (pte & present) == 0) {
            return result != 0 ? result : -ENOENT;
        }
        *gpa_out = ((uint64_t)pte & UINT64_C(0xfffff000)) |
                   (linear & (WVM_PAGE_SIZE - 1U));
    }
    return 0;
}

static int prepare_kvm_execution_snapshot(
    const struct wvm_header *hdr, const wvm_kvm_context_t *context,
    uint64_t *error_gpa_out)
{
    const struct kvm_sregs *sregs;
    uint64_t linear;
    uint64_t gpa;
    int result;

    if (error_gpa_out) {
        *error_gpa_out = 0;
    }
    if (!context ||
        sizeof(*sregs) > sizeof(context->sregs_data)) {
        return -EINVAL;
    }
    sregs = (const struct kvm_sregs *)context->sregs_data;
    if (context->rip > UINT64_MAX - sregs->cs.base) {
        return -EOVERFLOW;
    }
    linear = sregs->cs.base + context->rip;

    /*
     * x86 instructions are at most 15 bytes. Resolve both possible fetch
     * pages and all page-table levels used to derive them before KVM_RUN.
     */
    for (uint64_t offset = 0; offset <= 15; offset += 15) {
        if (linear > UINT64_MAX - offset) {
            return -EOVERFLOW;
        }
        result = translate_kvm_linear_to_gpa(
            hdr, sregs, linear + offset, &gpa, error_gpa_out);
        if (result != 0) {
            return result;
        }
        result = ensure_kvm_execution_page(hdr, gpa, error_gpa_out);
        if (result != 0) {
            return result;
        }
    }
    return 0;
}

void handle_kvm_mem(int sockfd, struct sockaddr_in *client, struct wvm_header *hdr, void *payload) {
    uint16_t type = ntohs(hdr->msg_type);
    uint16_t payload_len = ntohs(hdr->payload_len);
    uint64_t gpa;

    if (type == MSG_INVALIDATE || type == MSG_DOWNGRADE) {
        gpa = hdr->target_gpa; // ntoh_header 已将 union req_id/target_gpa 转为 host order
    } else {
        if (payload_len < 8) return;
        // [FIX] 安全读取 Payload 中的 GPA
        gpa = wvm_get_u64_unaligned(payload);
    }

    if (gpa >= g_slave_ram_size) return;
    if (!wvm_gpa_page_valid(gpa)) return;
    uint8_t *hva = wvm_gpa_to_hva(gpa);
    if (!hva) return;

    if (type == MSG_MEM_ACK || type == MSG_PAGE_PUSH_FULL) {
        struct wvm_mem_ack_payload *snapshot =
            (struct wvm_mem_ack_payload *)payload;
        int install_result;

        if (!wvm_kvm_page_cache_global_active() ||
            payload_len < sizeof(*snapshot) ||
            WVM_NTOHLL(snapshot->gpa) != gpa) {
            return;
        }
        install_result = wvm_kvm_page_cache_global_install_full(
            gpa, WVM_NTOHLL(snapshot->version), NULL, 0);
        if (install_result == 0) {
            memcpy(hva, snapshot->data, WVM_MEMORY_PAGE_BYTES);
        }
        return;
    }

    if (type == MSG_PAGE_PUSH_DIFF) {
        struct wvm_diff_log *diff = (struct wvm_diff_log *)payload;
        uint16_t offset;
        uint16_t data_bytes;
        int zero_page;
        int apply_result;

        if (!wvm_kvm_page_cache_global_active() ||
            payload_len < sizeof(*diff)) {
            return;
        }
        offset = ntohs(diff->offset);
        data_bytes = ntohs(diff->size);
        if (WVM_NTOHLL(diff->gpa) != gpa ||
            sizeof(*diff) + data_bytes > payload_len ||
            offset + data_bytes > WVM_MEMORY_PAGE_BYTES) {
            return;
        }
        zero_page = (hdr->flags & WVM_FLAG_ZERO) != 0;
        apply_result = wvm_kvm_page_cache_global_apply_diff(
            gpa, WVM_NTOHLL(diff->version), offset, data_bytes, zero_page,
            NULL, 0);
        if (apply_result == 0) {
            if (zero_page) {
                memset(hva, 0, WVM_MEMORY_PAGE_BYTES);
            } else if (data_bytes != 0) {
                memcpy(hva + offset, diff->data, data_bytes);
            }
        }
        return;
    }

    if (type == MSG_MEM_READ) {
        uint8_t page_state = WVM_KVM_PAGE_ABSENT;
        uint64_t page_version = 0;

        if (wvm_kvm_page_cache_global_active()) {
            if (ensure_kvm_page_snapshot(
                    hdr, gpa, hva, &page_version) != 0 ||
                wvm_kvm_page_cache_global_lookup(
                    gpa, &page_state, &page_version, NULL, 0) != 0 ||
                page_state != WVM_KVM_PAGE_CLEAN || page_version == 0) {
                return;
            }
        }
        struct wvm_header ack_hdr;
        memset(&ack_hdr, 0, sizeof(ack_hdr));
        ack_hdr.magic = htonl(WVM_MAGIC);
        ack_hdr.msg_type = htons(MSG_MEM_ACK);
        ack_hdr.payload_len = htons(
            wvm_kvm_page_cache_global_active()
                ? sizeof(struct wvm_mem_ack_payload)
                : WVM_MEMORY_PAGE_BYTES);
        wvm_slave_pack_src(&ack_hdr);
        ack_hdr.target_id = htonl(hdr->slave_id);  /* s23g13: hdr host-order after ntoh_header */
        wvm_ack_copy_assoc(&ack_hdr, hdr);
        ack_hdr.req_id = WVM_HTONLL(hdr->req_id);

        uint8_t tx[sizeof(ack_hdr) + sizeof(struct wvm_mem_ack_payload)];
        memcpy(tx, &ack_hdr, sizeof(ack_hdr));
        if (wvm_kvm_page_cache_global_active()) {
            struct wvm_mem_ack_payload *ack =
                (struct wvm_mem_ack_payload *)(tx + sizeof(ack_hdr));

            ack->gpa = WVM_HTONLL(gpa);
            ack->version = WVM_HTONLL(page_version);
            memcpy(ack->data, hva, WVM_MEMORY_PAGE_BYTES);
        } else {
            memcpy(tx + sizeof(ack_hdr), hva, WVM_MEMORY_PAGE_BYTES);
        }
        struct wvm_header *tx_hdr = (struct wvm_header *)tx;
        tx_hdr->crc32 = 0;
        size_t tx_bytes = sizeof(ack_hdr) +
                          (wvm_kvm_page_cache_global_active()
                               ? sizeof(struct wvm_mem_ack_payload)
                               : WVM_MEMORY_PAGE_BYTES);
        tx_hdr->payload_len = htons((uint16_t)(tx_bytes - sizeof(ack_hdr)));
        tx_hdr->crc32 = htonl(calculate_crc32(tx, tx_bytes));
        robust_sendto(sockfd, tx, tx_bytes, client);
    }
    else if (type == MSG_MEM_WRITE) {
        if (payload_len >= 8+4096) {
            if (wvm_kvm_page_cache_global_active()) {
                int invalidate_result =
                    wvm_kvm_page_cache_global_invalidate(gpa, NULL, 0);
                if (invalidate_result == -EBUSY) {
                    return;
                }
            }
            memcpy(hva, (uint8_t*)payload+8, 4096);
        }
    }
    else if (type == MSG_INVALIDATE) {
        if (wvm_kvm_page_cache_global_active()) {
            int invalidate_result =
                wvm_kvm_page_cache_global_invalidate(gpa, NULL, 0);
            if (invalidate_result == -EBUSY) {
                return;
            }
        }
        if (g_kvm_available) {
            memset(hva, 0, 4096); /* KVM: 不能 MADV_DONTNEED，会破坏 memslot 物理页 */
        } else {
            madvise(hva, 4096, MADV_DONTNEED);
        }
    }
    else if (type == MSG_DOWNGRADE) {
        if (payload_len < 16) return;
        
        // [FIX] 安全读取 Payload 中的复杂数据
        uint64_t requester_u64 = wvm_get_u64_unaligned(payload);
        uint64_t orig_req_id;
        memcpy(&orig_req_id, (uint8_t*)payload + 8, 8); // 已经是网络序，直接考

        uint32_t target_node = (uint32_t)requester_u64;

        struct wvm_header wb_hdr = {
            .magic = htonl(WVM_MAGIC), .msg_type = htons(MSG_WRITE_BACK),
            .payload_len = htons(8 + 4096),
            .slave_id = htonl(target_node),
            .target_id = htonl(hdr->slave_id),
            .req_id = orig_req_id,
            .qos_level = 0
        };

        uint8_t tx[sizeof(wb_hdr) + 8 + 4096];
        memcpy(tx, &wb_hdr, sizeof(wb_hdr));
        *(uint64_t*)(tx + sizeof(wb_hdr)) = WVM_HTONLL(gpa);
        memcpy(tx + sizeof(wb_hdr) + 8, hva, 4096);
        struct wvm_header *tx_hdr = (struct wvm_header *)tx;
        tx_hdr->crc32 = 0;
        tx_hdr->crc32 = htonl(calculate_crc32(tx, sizeof(tx)));

        if (robust_sendto(sockfd, tx, sizeof(tx), client) == 0) {
            // 只有确保网络层已经接纳了这个包，才敢擦除本地物理内存
            if (g_kvm_available) {
                memset(hva, 0, 4096);
            } else {
                madvise(hva, 4096, MADV_DONTNEED);
            }
        } else {
            // 如果发不出去，宁可让 Master 稍后重试，也不要擦除数据
            //fprintf(stderr, "[WVM-Slave] Critical: Failed to send back data for GPA %lx, aborting unmap\n", gpa);
        }
    }
    else if (type == MSG_FETCH_AND_INVALIDATE) {
        // [FIX] 边界检查：需要至少 16 字节 payload（8 target + 8 req_id）
        if (hdr->payload_len < 16) return;
        // [FIX] 安全读取
        uint64_t tmp_target = wvm_get_u64_unaligned(payload);
        uint32_t target_node = (uint32_t)tmp_target;

        uint64_t orig_req_id;
        memcpy(&orig_req_id, (uint8_t*)payload + 8, 8);

        if (gpa < g_slave_ram_size && wvm_gpa_page_valid(gpa)) {
            struct wvm_header wb_hdr;
            memset(&wb_hdr, 0, sizeof(wb_hdr));
            wb_hdr.magic = htonl(WVM_MAGIC);
            wb_hdr.msg_type = htons(MSG_WRITE_BACK);
            wb_hdr.payload_len = htons(8 + 4096);
            wb_hdr.slave_id = htonl(target_node);
            wb_hdr.target_id = htonl(hdr->slave_id);
            wb_hdr.req_id = orig_req_id;
            wb_hdr.qos_level = 0;

            uint8_t tx[sizeof(struct wvm_header) + 8 + 4096];
            memcpy(tx, &wb_hdr, sizeof(wb_hdr));

            uint64_t net_gpa = WVM_HTONLL(gpa);
            memcpy(tx + sizeof(wb_hdr), &net_gpa, 8);
            memcpy(tx + sizeof(wb_hdr) + 8, hva, 4096);

            struct wvm_header *tx_hdr = (struct wvm_header *)tx;
            tx_hdr->crc32 = 0;
            tx_hdr->crc32 = htonl(calculate_crc32(tx, sizeof(tx)));

            if (robust_sendto(sockfd, tx, sizeof(tx), client) == 0) {
                // 同上
                if (g_kvm_available) {
                    memset(hva, 0, 4096);
                } else {
                    madvise(hva, 4096, MADV_DONTNEED);
                }
            }
        }
    }
}


static void handle_block_io_send_ack(int sockfd, struct sockaddr_in *client,
                                       struct wvm_header *hdr, int error);

/* R02: small semantic operation cache for MSG_BLOCK_TYPED dedup (per executor).
 *
 * A retry of a successful READ must observe the original bytes, not just the
 * original status: the initiator correlates a replay by operation id and
 * expects the same completion payload.  The wire reply is therefore retained
 * verbatim (already encoded) and re-sent unchanged.
 *
 * Retention is bounded.  When the budget is exhausted the oldest replay
 * buffers are released, but the operation/status record stays so duplicate
 * requests are still deduplicated; a duplicate whose replay buffer was
 * released falls back to the status-only completion instead of re-reading the
 * backend and pretending the fresh bytes are the original result.
 */
#define WVM_BLOCK_OP_CACHE_SLOTS 128
#define WVM_BLOCK_OP_CACHE_REPLAY_BUDGET (8u * 1024u * 1024u)
struct wvm_block_op_cache_entry {
    uint64_t operation_id;
    uint32_t operation;
    uint32_t status;
    uint8_t digest[32];
    uint8_t *reply;          /* verbatim wire reply; owned by the cache */
    uint32_t reply_len;
    uint64_t store_order;
    int occupied;
};
static struct wvm_block_op_cache_entry g_block_op_cache[WVM_BLOCK_OP_CACHE_SLOTS];
static size_t g_block_op_cache_reply_bytes;
static uint64_t g_block_op_cache_store_order;
static pthread_mutex_t g_block_op_cache_lock = PTHREAD_MUTEX_INITIALIZER;

static struct wvm_block_op_cache_entry *block_op_cache_lookup(uint64_t op_id)
{
    struct wvm_block_op_cache_entry *e =
        &g_block_op_cache[op_id % WVM_BLOCK_OP_CACHE_SLOTS];
    if (e->occupied && e->operation_id == op_id)
        return e;
    return NULL;
}

/* Caller holds g_block_op_cache_lock. */
static void block_op_cache_drop_reply_locked(struct wvm_block_op_cache_entry *e)
{
    if (!e->reply)
        return;
    free(e->reply);
    e->reply = NULL;
    if (g_block_op_cache_reply_bytes >= e->reply_len)
        g_block_op_cache_reply_bytes -= e->reply_len;
    else
        g_block_op_cache_reply_bytes = 0;
    e->reply_len = 0;
}

/* Caller holds g_block_op_cache_lock. */
static void block_op_cache_release_locked(struct wvm_block_op_cache_entry *e)
{
    block_op_cache_drop_reply_locked(e);
    memset(e, 0, sizeof(*e));
}

/* Caller holds g_block_op_cache_lock. */
static void block_op_cache_reserve_locked(size_t bytes)
{
    if (bytes > WVM_BLOCK_OP_CACHE_REPLAY_BUDGET)
        return;
    while (g_block_op_cache_reply_bytes + bytes >
           WVM_BLOCK_OP_CACHE_REPLAY_BUDGET) {
        struct wvm_block_op_cache_entry *oldest = NULL;
        int i;

        for (i = 0; i < WVM_BLOCK_OP_CACHE_SLOTS; i++) {
            struct wvm_block_op_cache_entry *e = &g_block_op_cache[i];
            if (e->occupied && e->reply &&
                (!oldest || e->store_order < oldest->store_order))
                oldest = e;
        }
        if (!oldest)
            return;
        block_op_cache_drop_reply_locked(oldest);
    }
}

static void block_op_cache_store(uint64_t op_id, uint32_t operation,
                                 uint32_t status, const uint8_t digest[32],
                                 const uint8_t *reply, uint32_t reply_len)
{
    struct wvm_block_op_cache_entry *e =
        &g_block_op_cache[op_id % WVM_BLOCK_OP_CACHE_SLOTS];

    block_op_cache_release_locked(e);
    e->operation_id = op_id;
    e->operation = operation;
    e->status = status;
    if (digest)
        memcpy(e->digest, digest, 32);
    else
        memset(e->digest, 0, 32);

    if (reply && reply_len && reply_len <= WVM_MAX_PACKET_SIZE) {
        block_op_cache_reserve_locked(reply_len);
        if (g_block_op_cache_reply_bytes + reply_len <=
            WVM_BLOCK_OP_CACHE_REPLAY_BUDGET) {
            uint8_t *copy = malloc(reply_len);
            if (copy) {
                memcpy(copy, reply, reply_len);
                e->reply = copy;
                e->reply_len = reply_len;
                g_block_op_cache_reply_bytes += reply_len;
            }
        }
    }
    e->store_order = ++g_block_op_cache_store_order;
    e->occupied = 1;
}

/*
 * R02: the ACK must carry the request's wire identity unchanged.  The receive
 * path converted the request header to host order, so every multi-byte field
 * needs exactly one conversion here.  Copying the raw struct and then fixing
 * only magic/type/length byte-swapped req_id, slave_id, target_id and epoch,
 * which broke request/result correlation on the initiator.
 */
static void block_typed_init_ack_header(struct wvm_header *out,
                                        const struct wvm_header *request,
                                        size_t payload_len)
{
    memset(out, 0, sizeof(*out));
    out->magic = htonl(WVM_MAGIC);
    out->msg_type = htons(MSG_BLOCK_ACK);
    out->payload_len = htons((uint16_t)payload_len);
    out->slave_id = htonl(request->slave_id);
    out->target_id = htonl(request->target_id);
    out->req_id = WVM_HTONLL(request->req_id);
    out->qos_level = request->qos_level;
    out->flags = (uint8_t)(request->flags & (uint8_t)~WVM_FLAG_ERROR);
    out->mode_tcg = request->mode_tcg;
    out->node_state = request->node_state;
    out->epoch = htonl(request->epoch);
}

static void handle_block_typed_phys(int sockfd, struct sockaddr_in *client,
                                    struct wvm_header *hdr, void *payload,
                                    uint16_t payload_len)
{
    struct wvm_typed_block_request *req;
    char err[128];
    int rc = 0;
    uint32_t status = 0;
    struct wvm_block_op_cache_entry *cached;
    const uint8_t *reply_bytes = NULL;
    uint8_t *reply_allocation = NULL;
    uint32_t reply_bytes_len = 0;

    if (payload_len < sizeof(*req)) {
        handle_block_io_send_ack(sockfd, client, hdr, 1);
        return;
    }
    req = (struct wvm_typed_block_request *)payload;

    pthread_mutex_lock(&g_block_op_cache_lock);
    cached = block_op_cache_lookup(req->operation_id);
    if (cached &&
        memcmp(cached->digest, req->semantic_payload_digest, 32) == 0 &&
        cached->operation == req->operation) {
        status = cached->status;
        if (cached->reply && cached->reply_len) {
            /*
             * Replay the retained semantic payload (READ data), not the old
             * datagram.  Correlation fields belong to this request: a retry
             * carries a fresh transport id, while the operation id and the
             * result bytes stay the same.
             */
            uint32_t replay_len = cached->reply_len;
            size_t wire_len = sizeof(struct wvm_header) + replay_len;
            uint8_t *wire = malloc(wire_len);
            if (wire) {
                struct wvm_header *rh = (struct wvm_header *)wire;
                block_typed_init_ack_header(rh, hdr, replay_len);
                memcpy(wire + sizeof(*rh), cached->reply, replay_len);
                rh->crc32 = 0;
                rh->crc32 = htonl(calculate_crc32(wire, wire_len));
            }
            pthread_mutex_unlock(&g_block_op_cache_lock);
            if (wire) {
                robust_sendto(sockfd, wire, wire_len, client);
                free(wire);
            } else {
                handle_block_io_send_ack(sockfd, client, hdr, status != 0);
            }
            return;
        }
        pthread_mutex_unlock(&g_block_op_cache_lock);
        handle_block_io_send_ack(sockfd, client, hdr, status != 0);
        return;
    }
    pthread_mutex_unlock(&g_block_op_cache_lock);

    if (req->operation == WVM_BLOCK_OP_WRITE) {
        size_t need = (size_t)req->sector_count * 512;
        int fua = (req->flags & (WVM_BLOCK_FLAG_FUA | WVM_BLOCK_FLAG_SYNC)) != 0;
        if (req->payload_bytes != need ||
            payload_len < sizeof(*req) + need) {
            handle_block_io_send_ack(sockfd, client, hdr, 1);
            return;
        }
        rc = wvm_block_chunk_write(req->lba_512, req->sector_count, req->data,
                                   need, fua, err, sizeof(err));
        status = rc != 0;
        /* Data-bearing ACK not required for WRITE. */
        handle_block_io_send_ack(sockfd, client, hdr, status);
    } else if (req->operation == WVM_BLOCK_OP_READ) {
        size_t need = (size_t)req->sector_count * 512;
        size_t resp_len;
        uint8_t *tx;
        size_t out_bytes = 0;
        struct wvm_header *rh;
        struct wvm_block_payload *rp;

        /*
         * The completion length is a u16 and the whole reply must stay inside
         * one datagram.  Reject an oversized read before sizing the buffer
         * instead of truncating payload_len or allocating unbounded memory.
         */
        if (req->sector_count == 0 ||
            need > WVM_MAX_PACKET_SIZE - sizeof(struct wvm_header) -
                       sizeof(struct wvm_block_payload)) {
            handle_block_io_send_ack(sockfd, client, hdr, 1);
            return;
        }

        resp_len = sizeof(struct wvm_header) +
                   sizeof(struct wvm_block_payload) + need;
        tx = malloc(resp_len);
        if (!tx) {
            handle_block_io_send_ack(sockfd, client, hdr, 1);
            return;
        }
        rh = (struct wvm_header *)tx;
        rp = (struct wvm_block_payload *)(tx + sizeof(*rh));
        block_typed_init_ack_header(rh, hdr,
                                    sizeof(struct wvm_block_payload) + need);
        rp->lba = WVM_HTONLL(req->lba_512);
        rp->count = htonl(req->sector_count);
        rp->padding = 0;
        rc = wvm_block_chunk_read(req->lba_512, req->sector_count, rp->data,
                                  need, &out_bytes, err, sizeof(err));
        if (rc != 0) {
            free(tx);
            handle_block_io_send_ack(sockfd, client, hdr, 1);
            status = 1;
        } else {
            rh->crc32 = 0;
            rh->crc32 = htonl(calculate_crc32(tx, resp_len));
            robust_sendto(sockfd, tx, resp_len, client);
            /*
             * Retain this completion payload for duplicate replay; the cache
             * makes its own copy and this reference is released after the
             * store.  The header is rebuilt per request so a retry keeps its
             * own transport correlation.
             */
            reply_allocation = tx;
            reply_bytes = tx + sizeof(struct wvm_header);
            reply_bytes_len = (uint32_t)(resp_len - sizeof(struct wvm_header));
            status = 0;
        }
    } else if (req->operation == WVM_BLOCK_OP_FLUSH) {
        if (req->sector_count == 0)
            rc = wvm_block_chunk_flush_all(err, sizeof(err));
        else
            rc = wvm_block_chunk_flush_range(req->lba_512, req->sector_count,
                                             err, sizeof(err));
        status = rc != 0;
        handle_block_io_send_ack(sockfd, client, hdr, status);
    } else {
        handle_block_io_send_ack(sockfd, client, hdr, 1);
        status = 1;
    }

    pthread_mutex_lock(&g_block_op_cache_lock);
    block_op_cache_store(req->operation_id, req->operation, status,
                         req->semantic_payload_digest, reply_bytes,
                         reply_bytes_len);
    pthread_mutex_unlock(&g_block_op_cache_lock);
    free(reply_allocation);
}

static void handle_block_io_send_ack(int sockfd, struct sockaddr_in *client,
                                       struct wvm_header *hdr, int error)
{
    hdr->msg_type = htons(MSG_BLOCK_ACK);
    hdr->payload_len = htons(0);
    hdr->magic = htonl(WVM_MAGIC);
    hdr->slave_id = htonl(hdr->slave_id);
    hdr->target_id = htonl(hdr->target_id);
    /* A07: echo the single request op id unchanged for correlation. */
    hdr->req_id = WVM_HTONLL(hdr->req_id);
    hdr->epoch = htonl(hdr->epoch);
    if (error)
        hdr->flags |= WVM_FLAG_ERROR;
    else
        hdr->flags &= (uint8_t)~WVM_FLAG_ERROR;
    hdr->crc32 = 0;
    hdr->crc32 = htonl(calculate_crc32(hdr, sizeof(*hdr)));
    sendto(sockfd, hdr, sizeof(*hdr), 0, (struct sockaddr *)client,
           sizeof(*client));
}

/*
 * A09: production path uses shared wvm_block_chunk_store (cross-boundary with
 * control-plane oracles). A08: every failure returns ERROR ACK — never silent.
 * A07: req_id is the sole in-flight block op correlation on this path.
 */
static void handle_block_io_phys(int sockfd, struct sockaddr_in *client,
                                 struct wvm_header *hdr, void *payload)
{
    struct wvm_block_payload *blk = (struct wvm_block_payload *)payload;
    uint64_t lba = WVM_NTOHLL(blk->lba);
    uint32_t count = ntohl(blk->count);
    uint32_t data_len;
    char err[128];
    int rc;

    if (hdr->msg_type != MSG_BLOCK_FLUSH) {
        if (count == 0 || count > (64U << 20) / 512) {
            handle_block_io_send_ack(sockfd, client, hdr, 1);
            return;
        }
    } else if (count > (64U << 20) / 512) {
        handle_block_io_send_ack(sockfd, client, hdr, 1);
        return;
    }
    data_len = count * 512;

    if (hdr->msg_type == MSG_BLOCK_WRITE) {
        uint16_t actual_pl = hdr->payload_len;
        void *aligned_buf = NULL;

        if (actual_pl < sizeof(struct wvm_block_payload) ||
            data_len > actual_pl - sizeof(struct wvm_block_payload)) {
            handle_block_io_send_ack(sockfd, client, hdr, 1);
            return;
        }
        if (posix_memalign(&aligned_buf, 4096, data_len) != 0) {
            handle_block_io_send_ack(sockfd, client, hdr, 1);
            return;
        }
        memcpy(aligned_buf, blk->data, data_len);
        {
            int fua = (hdr->flags & (WVM_FLAG_BLOCK_FUA | WVM_FLAG_BLOCK_SYNC)) != 0;
            rc = wvm_block_chunk_write(lba, count, aligned_buf, data_len, fua,
                                       err, sizeof(err));
        }
        free(aligned_buf);
        handle_block_io_send_ack(sockfd, client, hdr, rc != 0);
        return;
    }

    if (hdr->msg_type == MSG_BLOCK_READ) {
        size_t resp_len = sizeof(struct wvm_header) +
                          sizeof(struct wvm_block_payload) + data_len;
        uint8_t *tx = malloc(resp_len);
        void *aligned_buf = NULL;
        size_t out_bytes = 0;

        if (!tx || posix_memalign(&aligned_buf, 4096, data_len) != 0) {
            free(tx);
            handle_block_io_send_ack(sockfd, client, hdr, 1);
            return;
        }
        rc = wvm_block_chunk_read(lba, count, aligned_buf, data_len, &out_bytes,
                                  err, sizeof(err));
        if (rc != 0) {
            free(aligned_buf);
            free(tx);
            handle_block_io_send_ack(sockfd, client, hdr, 1);
            return;
        }
        {
            struct wvm_header *rh = (struct wvm_header *)tx;
            struct wvm_block_payload *rp =
                (struct wvm_block_payload *)(tx + sizeof(*hdr));

            *rh = *hdr;
            rh->msg_type = htons(MSG_BLOCK_ACK);
            rh->payload_len =
                htons(sizeof(struct wvm_block_payload) + data_len);
            rh->magic = htonl(WVM_MAGIC);
            rh->slave_id = htonl(hdr->slave_id);
            rh->target_id = htonl(hdr->target_id);
            rh->req_id = WVM_HTONLL(hdr->req_id);
            rh->epoch = htonl(hdr->epoch);
            rh->flags &= (uint8_t)~WVM_FLAG_ERROR;
            rp->lba = blk->lba;
            rp->count = blk->count;
            memcpy(rp->data, aligned_buf, data_len);
            rh->crc32 = 0;
            rh->crc32 = htonl(calculate_crc32(tx, resp_len));
            robust_sendto(sockfd, tx, resp_len, client);
        }
        free(aligned_buf);
        free(tx);
        return;
    }

    if (hdr->msg_type == MSG_BLOCK_FLUSH) {
        /*
         * R02 flush domain:
         *   count==0 + no LBA intent from guest FLUSH → flush_all under identity
         *   count>0  → every chunk touched by [lba, lba+count) (FUA follow-up)
         * Legacy FUA follow-up now always passes sector_count from master.
         */
        int any_err = 0;
        if (count == 0 && lba == 0 &&
            (hdr->flags & (WVM_FLAG_BLOCK_FUA | WVM_FLAG_BLOCK_SYNC)) == 0) {
            /* Guest-wide FLUSH (typed OP_FLUSH often uses lba=0,count=0). */
            any_err = wvm_block_chunk_flush_all(err, sizeof(err)) != 0;
        } else {
            any_err = wvm_block_chunk_flush_range(
                          lba, count == 0 ? 1 : count, err, sizeof(err)) != 0;
        }
        handle_block_io_send_ack(sockfd, client, hdr, any_err);
        return;
    }

    handle_block_io_send_ack(sockfd, client, hdr, 1);
}

/* 
 * [物理意图] Slave 节点的“任务分发中心”，负责监听并调度来自全网的 RPC 指令。
 * [关键逻辑] 绑定多播/复用端口，利用 recvmmsg 批量捕获包头，根据消息类型分流至执行引擎或内存处理程序。
 * [后果] 它是 Slave 节点的总入口。其效率直接决定了 Slave 对 Master 请求的“首包响应时间（TTFB）”。
 */

static void kvm_wake_worker_sock(void)
{
    int sock;
    int worker;
    struct sockaddr_in addr;
    uint8_t poke = 0;
    long i;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)g_service_port);
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        for (i = 0; i < 16; i++) {
            (void)sendto(sock, &poke, 1, 0, (struct sockaddr *)&addr,
                         sizeof(addr));
        }
        close(sock);
    }
    worker = (int)__atomic_load_n(&g_kvm_worker_sock, __ATOMIC_ACQUIRE);
    if (worker >= 0) {
        (void)shutdown(worker, SHUT_RDWR);
    }
}

void* kvm_worker_thread(void *arg) {
    long core = (long)arg;
    int s = socket(AF_INET, SOCK_DGRAM, 0); int opt=1; setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    struct sockaddr_in a = {
        .sin_family = AF_INET,
        .sin_addr.s_addr =
            htonl(g_executor_local_only ? INADDR_LOOPBACK : INADDR_ANY),
        .sin_port = htons(g_service_port)
    };
    if (s < 0 || bind(s, (struct sockaddr*)&a, sizeof(a)) != 0) {
        fprintf(stderr, "[SLAVE-BIND] port=%d failed errno=%d\n", g_service_port, errno);
        if (core == 0) {
            executor_publish_startup_state(EXECUTOR_FAILED);
        }
        if (s >= 0) {
            close(s);
        }
        return NULL;
    } else if (core == 0) {
        fprintf(stderr, "[SLAVE-BIND] port=%d ok\n", g_service_port);
    }
    /* Publish fd so STOP can unblock MSG_WAITFORONE recvmmsg. */
    __atomic_store_n(&g_kvm_worker_sock, s, __ATOMIC_RELEASE);
    
    // Worker 0 初始化 VFIO
    if (core == 0 && g_vfio_config_path) {
        wvm_vfio_init(g_vfio_config_path);
    }
    
    struct mmsghdr msgs[BATCH_SIZE] = {0};
    struct iovec iov[BATCH_SIZE] = {0};
    struct sockaddr_in c[BATCH_SIZE] = {0};
    uint8_t *rx_pool = calloc(BATCH_SIZE, WVM_MAX_PACKET_SIZE);
    if (!rx_pool) {
        perror("[SLAVE-RX] alloc rx_pool");
        if (core == 0) {
            executor_publish_startup_state(EXECUTOR_FAILED);
        }
        close(s);
        return NULL;
    }
    for(int i=0;i<BATCH_SIZE;i++) { iov[i].iov_base=rx_pool + (size_t)i * WVM_MAX_PACKET_SIZE; iov[i].iov_len=WVM_MAX_PACKET_SIZE; msgs[i].msg_hdr.msg_iov=&iov[i]; msgs[i].msg_hdr.msg_iovlen=1; msgs[i].msg_hdr.msg_name=&c[i]; msgs[i].msg_hdr.msg_namelen=sizeof(c[i]); }
    if (core == 0) {
        executor_publish_startup_state(EXECUTOR_READY);
    }

    while(!g_shutdown_requested) {
        for (int i = 0; i < BATCH_SIZE; i++) {
            msgs[i].msg_hdr.msg_namelen = sizeof(c[i]);
            msgs[i].msg_hdr.msg_flags = 0;
            msgs[i].msg_len = 0;
        }
        int recv_flags = g_nonblock_recv ? MSG_DONTWAIT : MSG_WAITFORONE;
        int n = recvmmsg(s, msgs, BATCH_SIZE, recv_flags, NULL);
        if (n<=0) {
            if (g_shutdown_requested) break;
            if (g_nonblock_recv && (errno == EAGAIN || errno == EWOULDBLOCK)) usleep(100);
            continue;
        }
        for(int i=0;i<n;i++) {
            uint8_t *pkt = (uint8_t *)iov[i].iov_base;
            struct wvm_header *h = (struct wvm_header*)pkt;
            if (h->magic != htonl(WVM_MAGIC)) continue;

            { static int __dbg=0;
              if (__dbg < 10) {
                  char ipbuf[16] = {0};
                  inet_ntop(AF_INET, &c[i].sin_addr, ipbuf, sizeof(ipbuf));
                  uint16_t raw_type = ntohs(h->msg_type);
                  fprintf(stderr, "[SLAVE-RX] src=%s:%u len=%u type=%u target=%u slave=%u\n",
                          ipbuf, (unsigned)ntohs(c[i].sin_port),
                          (unsigned)msgs[i].msg_len, (unsigned)raw_type,
                          (unsigned)ntohl(h->target_id), (unsigned)ntohl(h->slave_id));
                  __dbg++;
              }
            }
            { static int __big=0;
              if (__big < 10 && msgs[i].msg_len >= 200) {
                  char ipbuf[16] = {0};
                  inet_ntop(AF_INET, &c[i].sin_addr, ipbuf, sizeof(ipbuf));
                  uint16_t raw_type = ntohs(h->msg_type);
                  fprintf(stderr, "[SLAVE-RX-BIG] src=%s:%u len=%u type=%u\n",
                          ipbuf, (unsigned)ntohs(c[i].sin_port),
                          (unsigned)msgs[i].msg_len, (unsigned)raw_type);
                  __big++;
              }
            }
            
            pthread_spin_lock(&g_master_lock);
            int addr_changed = (g_master_addr.sin_port != c[i].sin_port || g_master_addr.sin_addr.s_addr != c[i].sin_addr.s_addr);
            g_master_addr = c[i];
            pthread_spin_unlock(&g_master_lock);

            // [FIX-M1] mutex 操作移到 spinlock 外部，防止持 spinlock 时阻塞
            if (addr_changed) {
                pthread_mutex_lock(&g_master_mutex);
                if (!g_master_ready) {
                    g_master_ready = 1;
                    pthread_cond_broadcast(&g_master_cond);
                }
                pthread_mutex_unlock(&g_master_mutex);
            }

            uint16_t type = ntohs(h->msg_type);
            ntoh_header(h);
            int actual_payload = msgs[i].msg_len - (int)sizeof(struct wvm_header);
            if (actual_payload < 0 || h->payload_len > (uint16_t)actual_payload) {
                continue;
            }

            if (type == MSG_VCPU_RUN) {
                struct wvm_ipc_cpu_run_req local_req;
                struct wvm_ipc_cpu_run_req *run_req = NULL;
                void *net_payload_ptr = pkt + sizeof(struct wvm_header);

                memset(&local_req, 0, sizeof(local_req));

                if (h->payload_len >= sizeof(struct wvm_ipc_cpu_run_req)) {
                    memcpy(&local_req, net_payload_ptr, sizeof(local_req));
                    run_req = &local_req;
                } else {
                    local_req.mode_tcg = h->mode_tcg ? 1 : 0;
                    local_req.slave_id = h->slave_id;

                    if (local_req.mode_tcg) {
                        if (h->payload_len >= sizeof(wvm_tcg_context_t)) {
                            memcpy(&local_req.ctx.tcg, net_payload_ptr, sizeof(wvm_tcg_context_t));
                        }
                    } else {
                        if (h->payload_len >= sizeof(wvm_kvm_context_t)) {
                            memcpy(&local_req.ctx.kvm, net_payload_ptr, sizeof(wvm_kvm_context_t));
                        }
                    }
                    run_req = &local_req;
                }

                handle_kvm_run_stateless(s, &c[i], h, run_req, (int)core);
            }
            else if (type == MSG_BLOCK_TYPED) {
                /*
                 * R02: ntoh_header() above already converted payload_len to
                 * host order.  Converting again byte-swapped the length, so
                 * the handler either rejected a valid request or believed in
                 * a length larger than the received datagram.
                 */
                handle_block_typed_phys(s, &c[i], h, pkt + sizeof(*h),
                                       h->payload_len);
            }
            else if (type == MSG_BLOCK_WRITE || type == MSG_BLOCK_READ || type == MSG_BLOCK_FLUSH) {
                // 存储入口
                handle_block_io_phys(s, &c[i], h, pkt+sizeof(*h));
            }
            else handle_kvm_mem(s, &c[i], h, pkt+sizeof(*h));
        }
    }
    free(rx_pool);
    __atomic_store_n(&g_kvm_worker_sock, -1, __ATOMIC_RELEASE);
    close(s);
    return NULL;
}

// ==========================================
// [Fixed Path] TCG Proxy Engine (Tri-Channel)
// ==========================================

// 三通道地址表
typedef struct {
    struct sockaddr_in cmd_addr;  // 控制流
    struct sockaddr_in req_addr;  // 内存请求 (Slave -> Master -> Slave)
    struct sockaddr_in push_addr; // 内存推送 (Master -> Slave)
} slave_endpoint_t;

static slave_endpoint_t *tcg_endpoints = NULL; 
static struct sockaddr_in g_upstream_gateway = {0};
static volatile int g_gateway_init_done = 0;
static volatile int g_gateway_known = 0;

static int is_local_tcg_endpoint_port(uint16_t port_net)
{
    uint16_t port = ntohs(port_net);
    for (long i = 0; i < g_num_cores; i++) {
        if (port == ntohs(tcg_endpoints[i].cmd_addr.sin_port) ||
            port == ntohs(tcg_endpoints[i].req_addr.sin_port) ||
            port == ntohs(tcg_endpoints[i].push_addr.sin_port)) {
            return 1;
        }
    }
    return 0;
}

/* 
 * [物理意图] 在不支持 KVM 的环境下，通过多进程模拟实现“多核算力聚合”。
 * [关键逻辑] 为每个逻辑核心孵化一个独立的 QEMU-TCG 实例，并通过环境变量注入“三通道” Socket 句柄。
 * [后果] 提供了极致的兼容性。即便是在廉价的 ARM 树莓派或锁定内核的容器里，也能作为 Slave 贡献算力。
 */
static int spawn_tcg_processes(int base_id) {
    printf("[Hybrid] Spawning %ld QEMU-TCG instances (Tri-Channel Isolation)...\n", g_num_cores);
    const char *qemu_bin = getenv("WVM_TCG_QEMU_BIN");
    if (!qemu_bin || !*qemu_bin) {
        qemu_bin = "qemu-system-x86_64";
    }
    
    tcg_endpoints = malloc(sizeof(slave_endpoint_t) * g_num_cores);
    if (!tcg_endpoints) { perror("malloc endpoints"); return -1; }
    g_tcg_session_fds = malloc(sizeof(*g_tcg_session_fds) * g_num_cores);
    if (!g_tcg_session_fds) { perror("malloc executor sessions"); free(tcg_endpoints); tcg_endpoints = NULL; return -1; }
    free(g_tcg_helper_pids);
    g_tcg_helper_pids = malloc(sizeof(*g_tcg_helper_pids) * g_num_cores);
    if (!g_tcg_helper_pids) {
        perror("malloc helper pids");
        free(g_tcg_session_fds);
        g_tcg_session_fds = NULL;
        free(tcg_endpoints);
        tcg_endpoints = NULL;
        return -1;
    }
    for (long i = 0; i < g_num_cores; i++) {
        g_tcg_session_fds[i] = -1;
        g_tcg_helper_pids[i] = -1;
    }
    
    /*
     * Keep inherited TCG endpoint ports inside the 16-bit TCP/UDP range.
     * The old 256-stride formula overflowed for ports like 19205 and could
     * silently wrap through htons(), leaving the proxy sending to a port that
     * the child failed to bind.
     */
    int internal_base = 20000 + (g_service_port % 512) * 64;
    char ram_str[32];
    snprintf(ram_str, sizeof(ram_str), "%d", g_ram_mb);

    /*
     * TCG helper QEMU must expose a guest physical layout compatible with the
     * master VM whose vCPU state it executes.  Keep the historical per-node
     * size as the default, but allow the launch environment to mirror a q35
     * high-memory layout when the cluster topology requires it.
     */
    const char *tcg_machine = getenv("WVM_TCG_QEMU_MACHINE");
    const char *tcg_ram_mb = getenv("WVM_TCG_QEMU_MEM_MB");
    const char *tcg_datadir = getenv("WVM_TCG_QEMU_DATADIR");
    if (!tcg_ram_mb || !*tcg_ram_mb) {
        tcg_ram_mb = ram_str;
    }

    for (long i = 0; i < g_num_cores; i++) {
        int port_cmd  = internal_base + i * 3 + 0;
        int port_req  = internal_base + i * 3 + 1;
        int port_push = internal_base + i * 3 + 2;
        
        tcg_endpoints[i].cmd_addr.sin_family = AF_INET;
        tcg_endpoints[i].cmd_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        tcg_endpoints[i].cmd_addr.sin_port = htons(port_cmd);

        tcg_endpoints[i].req_addr.sin_family = AF_INET;
        tcg_endpoints[i].req_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        tcg_endpoints[i].req_addr.sin_port = htons(port_req);

        tcg_endpoints[i].push_addr.sin_family = AF_INET;
        tcg_endpoints[i].push_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        tcg_endpoints[i].push_addr.sin_port = htons(port_push);

        {
            pid_t parent_pid = getpid();
            int session_pair[2];
            pid_t child_pid;

            if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
                           session_pair) != 0) {
                perror("[Hybrid] create executor session");
                return -1;
            }

            child_pid = fork();
            if (child_pid == 0) {
            close(session_pair[0]);
            if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 ||
                getppid() != parent_pid) {
                _exit(127);
            }
            int sock_cmd = socket(AF_INET, SOCK_DGRAM, 0);
            struct sockaddr_in addr_cmd = { .sin_family=AF_INET, .sin_addr.s_addr=htonl(INADDR_LOOPBACK), .sin_port=htons(port_cmd) };
            if (sock_cmd < 0 || bind(sock_cmd, (struct sockaddr*)&addr_cmd, sizeof(addr_cmd)) != 0) {
                perror("[Hybrid] bind cmd socket");
                _exit(127);
            }

            int sock_req = socket(AF_INET, SOCK_DGRAM, 0);
            struct sockaddr_in addr_req = { .sin_family=AF_INET, .sin_addr.s_addr=htonl(INADDR_LOOPBACK), .sin_port=htons(port_req) };
            if (sock_req < 0 || bind(sock_req, (struct sockaddr*)&addr_req, sizeof(addr_req)) != 0) {
                perror("[Hybrid] bind req socket");
                _exit(127);
            }

            int sock_push = socket(AF_INET, SOCK_DGRAM, 0);
            struct sockaddr_in addr_push = { .sin_family=AF_INET, .sin_addr.s_addr=htonl(INADDR_LOOPBACK), .sin_port=htons(port_push) };
            if (sock_push < 0 || bind(sock_push, (struct sockaddr*)&addr_push, sizeof(addr_push)) != 0) {
                perror("[Hybrid] bind push socket");
                _exit(127);
            }

            struct sockaddr_in proxy = { .sin_family=AF_INET, .sin_addr.s_addr=htonl(INADDR_LOOPBACK), .sin_port=htons(g_service_port) };
            connect(sock_cmd, (struct sockaddr*)&proxy, sizeof(proxy));
            connect(sock_req, (struct sockaddr*)&proxy, sizeof(proxy));
            connect(sock_push, (struct sockaddr*)&proxy, sizeof(proxy));

            char fd_c[16], fd_r[16], fd_p[16];
            int f;
            f=fcntl(sock_cmd, F_GETFD); f&=~FD_CLOEXEC; fcntl(sock_cmd, F_SETFD, f);
            f=fcntl(sock_req, F_GETFD); f&=~FD_CLOEXEC; fcntl(sock_req, F_SETFD, f);
            f=fcntl(sock_push, F_GETFD); f&=~FD_CLOEXEC; fcntl(sock_push, F_SETFD, f);
            f=fcntl(session_pair[1], F_GETFD); f&=~FD_CLOEXEC; fcntl(session_pair[1], F_SETFD, f);
            
            snprintf(fd_c, 16, "%d", sock_cmd);
            snprintf(fd_r, 16, "%d", sock_req);
            snprintf(fd_p, 16, "%d", sock_push);

            setenv("WVM_SOCK_CMD", fd_c, 1);
            setenv("WVM_SOCK_REQ", fd_r, 1);  
            setenv("WVM_SOCK_PUSH", fd_p, 1); 
            setenv("WVM_ROLE", "SLAVE", 1);
            /*
             * TCG PROXY helpers must stay on the TCG cpu_exec path. Auto-KVM
             * bootstrap otherwise makes kvm_enabled() true and the service loop
             * routes mode_tcg=1 requests into KVM_RUN (hang / wrong backend).
             */
            setenv("WVM_DISABLE_AUTO_KVM", "1", 1);
            /*
             * R05: each TCG helper is a single-vCPU, -nodefaults process so the
             * page-install path may briefly raise PROT_WRITE without a concurrent
             * guest writer. Advertise that invariant to the QEMU helper.
             */
            setenv("WVM_SLAVE_VCPU_COUNT", "1", 1);
            char session_fd_str[16];
            snprintf(session_fd_str, sizeof(session_fd_str), "%d",
                     session_pair[1]);
            setenv("WVM_EXECUTOR_SESSION_FD", session_fd_str, 1);
            char executor_id_str[32];
            snprintf(executor_id_str, sizeof(executor_id_str), "%d", base_id);
            setenv("WVM_EXECUTOR_ID", executor_id_str, 1);
            char vcpu_index_str[32];
            snprintf(vcpu_index_str, sizeof(vcpu_index_str), "%ld", i);
            setenv("WVM_EXECUTOR_VCPU_INDEX", vcpu_index_str, 1);
            char id_str[32];
            snprintf(id_str, sizeof(id_str), "%u", wvm_wire_target(g_slave_vm_id, base_id + i));
            setenv("WVM_SLAVE_ID", id_str, 1);

            const char *shm_path = getenv("WVM_SHM_FILE");
            if (shm_path) {
                setenv("WVM_SHM_FILE", shm_path, 1);
            }

            cpu_set_t cpuset; CPU_ZERO(&cpuset); CPU_SET(i, &cpuset); sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
            
            char *qemu_argv[20];
            int ai = 0;

            qemu_argv[ai++] = (char *)qemu_bin;
            if (tcg_datadir && *tcg_datadir) {
                qemu_argv[ai++] = "-L";
                qemu_argv[ai++] = (char *)tcg_datadir;
            }
            qemu_argv[ai++] = "-accel";
            qemu_argv[ai++] = "wavevm";
            if (tcg_machine && *tcg_machine) {
                qemu_argv[ai++] = "-machine";
                qemu_argv[ai++] = (char *)tcg_machine;
            }
            qemu_argv[ai++] = "-m";
            qemu_argv[ai++] = (char *)tcg_ram_mb;
            qemu_argv[ai++] = "-nographic";
            qemu_argv[ai++] = "-S";
            qemu_argv[ai++] = "-nodefaults";
            qemu_argv[ai++] = "-smp";
            qemu_argv[ai++] = "1";
            qemu_argv[ai] = NULL;

            execvp(qemu_bin, qemu_argv);
            perror("[Hybrid] execlp qemu");
            _exit(127);
            }
            if (child_pid < 0) {
                perror("[Hybrid] fork qemu");
                close(session_pair[0]);
                close(session_pair[1]);
                return -1;
            }
            close(session_pair[1]);
            g_tcg_session_fds[i] = session_pair[0];
            g_tcg_helper_pids[i] = child_pid;
        }
    }
    /*
     * Required helpers must stay alive before EXECUTOR_READY. A missing QEMU
     * binary or immediate helper exit leaves the executor STARTING/FAILED so
     * CREATE_VM cannot forge RUNNING. Session FDs alone are not readiness.
     */
    usleep(100000);
    for (long i = 0; i < g_num_cores; i++) {
        int status = 0;
        pid_t waited;

        if (g_tcg_session_fds[i] < 0 || g_tcg_helper_pids[i] <= 0) {
            fprintf(stderr,
                    "[Hybrid] TCG helper slot %ld missing session/pid\n", i);
            return -1;
        }
        waited = waitpid(g_tcg_helper_pids[i], &status, WNOHANG);
        if (waited == g_tcg_helper_pids[i]) {
            fprintf(stderr,
                    "[Hybrid] TCG helper pid=%d exited before READY status=%d\n",
                    (int)g_tcg_helper_pids[i], status);
            g_tcg_helper_pids[i] = -1;
            return -1;
        }
        if (waited < 0 && errno != ECHILD) {
            perror("[Hybrid] waitpid helper");
            return -1;
        }
    }
    /*
     * Production TCG dirty self-emit: executor notify FD -> helper push port
     * so ensure_remote_memory_side_effect can PAGE_PUSH the installed version.
     * GATE/RUNTIME_SOCKET are inherited from node_runtime/main for typed commit.
     */
    if (tcg_endpoints && g_num_cores > 0) {
        int notify_fd = socket(AF_INET, SOCK_DGRAM, 0);

        if (notify_fd >= 0) {
            if (connect(notify_fd,
                        (struct sockaddr *)&tcg_endpoints[0].push_addr,
                        sizeof(tcg_endpoints[0].push_addr)) == 0) {
                if (g_tcg_install_notify_owned &&
                    g_tcg_install_notify_fd >= 0) {
                    close(g_tcg_install_notify_fd);
                }
                g_tcg_install_notify_fd = notify_fd;
                g_tcg_install_notify_owned = 1;
                fprintf(stderr,
                        "[Hybrid] TCG install notify fd=%d -> push port %u\n",
                        notify_fd,
                        (unsigned)ntohs(tcg_endpoints[0].push_addr.sin_port));
            } else {
                close(notify_fd);
            }
        }
    }
    return 0;
}

/*
 * Same-node V1 publish cannot use Wavelet broadcast (enqueue drops g_my_node_id).
 * Deliver PAGE_PUSH/FORCE_SYNC directly to every local TCG helper push UDP port
 * so remote PROXY vCPUs observe master handoff dirty commits.
 */
int wavevm_proxy_push_to_local_helpers(uint16_t msg_type, void *payload, int len)
{
    uint8_t *pkt;
    struct wvm_header *hdr;
    size_t pkt_len;
    int fd = -1;
    long i;
    int sent = 0;

    if (!payload || len <= 0 || !tcg_endpoints || g_num_cores <= 0) {
        return 0;
    }
    if (len > 65535 - (int)sizeof(struct wvm_header)) {
        return -EINVAL;
    }

    /*
     * Helpers connect(push_sock → proxy g_service_port). Kernel drops UDP
     * from any other source. Must sendto from a registered proxy sockfd so
     * the datagram appears to come from the connected peer (same as the
     * Wavelet→proxy PAGE_PUSH forward path).
     */
    pthread_mutex_lock(&g_tcg_proxy_sock_lock);
    if (g_tcg_proxy_socks && g_tcg_proxy_sock_count > 0) {
        fd = g_tcg_proxy_socks[0];
    }
    pthread_mutex_unlock(&g_tcg_proxy_sock_lock);
    if (fd < 0) {
        return -ENOTCONN;
    }

    pkt_len = sizeof(struct wvm_header) + (size_t)len;
    pkt = malloc(pkt_len);
    if (!pkt) {
        return -ENOMEM;
    }
    hdr = (struct wvm_header *)pkt;
    memset(hdr, 0, sizeof(*hdr));
    hdr->magic = htonl(WVM_MAGIC);
    hdr->msg_type = htons(msg_type);
    hdr->payload_len = htons((uint16_t)len);
    wvm_slave_pack_src(hdr);
    hdr->target_id = hdr->slave_id;
    hdr->qos_level =
        (msg_type == MSG_PAGE_PUSH_FULL || msg_type == MSG_FORCE_SYNC) ? 0 : 1;
    memcpy(pkt + sizeof(*hdr), payload, (size_t)len);

    for (i = 0; i < g_num_cores; i++) {
        if (sendto(fd, pkt, pkt_len, MSG_NOSIGNAL,
                   (struct sockaddr *)&tcg_endpoints[i].push_addr,
                   sizeof(tcg_endpoints[i].push_addr)) == (ssize_t)pkt_len) {
            sent++;
        }
    }
    free(pkt);

    {
        static int log_count;
        if (log_count < 40) {
            fprintf(stderr,
                    "[Hybrid] local-helper push type=%u len=%d cores=%ld sent=%d fd=%d\n",
                    (unsigned)msg_type, len, g_num_cores, sent, fd);
            log_count++;
        }
    }
    return sent > 0 ? 0 : -EIO;
}

/*
 * After a batch of local-helper PAGE_PUSHes, give the push listener time to
 * APPLY + lazy-RO flush. Production UDP ACKs do not return to the proxy on a
 * correlated FD (same as notify_tcg_page_installed), so we send a framed
 * PUSH_BARRIER then sleep past the 100ms poll interval.
 */
int wavevm_proxy_barrier_local_helpers(uint64_t timeout_us)
{
    uint8_t barrier_pkt[sizeof(wvm_ipc_header_t) + sizeof(uint64_t)];
    wvm_ipc_header_t *bhdr;
    uint64_t cookie;
    int fd = -1;
    long i;
    int sent = 0;
    int br;

    if (!tcg_endpoints || g_num_cores <= 0) {
        return 0;
    }

    pthread_mutex_lock(&g_tcg_proxy_sock_lock);
    if (g_tcg_proxy_socks && g_tcg_proxy_sock_count > 0) {
        fd = g_tcg_proxy_socks[0];
    }
    pthread_mutex_unlock(&g_tcg_proxy_sock_lock);
    if (fd < 0) {
        return -ENOTCONN;
    }

    /*
     * G4: one cookie for the batch; each helper ACKs after APPLY+lazy-RO.
     * Wait for sent ACKs via proxy RX demux — never usleep-claim success.
     */
    cookie = push_barrier_begin((int)g_num_cores);

    memset(barrier_pkt, 0, sizeof(barrier_pkt));
    bhdr = (wvm_ipc_header_t *)barrier_pkt;
    bhdr->type = WVM_IPC_TYPE_PUSH_BARRIER;
    bhdr->len = (uint32_t)sizeof(cookie);
    memcpy(barrier_pkt + sizeof(*bhdr), &cookie, sizeof(cookie));

    for (i = 0; i < g_num_cores; i++) {
        if (sendto(fd, barrier_pkt, sizeof(barrier_pkt), MSG_NOSIGNAL,
                   (struct sockaddr *)&tcg_endpoints[i].push_addr,
                   sizeof(tcg_endpoints[i].push_addr)) ==
            (ssize_t)sizeof(barrier_pkt)) {
            sent++;
        }
    }
    if (sent <= 0) {
        return -EIO;
    }
    if (sent != (int)g_num_cores) {
        pthread_mutex_lock(&g_push_barrier_lock);
        if (g_push_barrier_active_cookie == cookie) {
            g_push_barrier_expect = sent;
        }
        pthread_mutex_unlock(&g_push_barrier_lock);
    }

    br = wait_for_push_barrier_cookie(cookie,
                                      timeout_us ? timeout_us : 5000000ULL);
    {
        static int log_count;
        if (log_count < 40) {
            fprintf(stderr,
                    "[Hybrid] local-helper barrier cores=%ld sent=%d "
                    "cookie=%llu wait=%d\n",
                    g_num_cores, sent, (unsigned long long)cookie, br);
            log_count++;
        }
    }
    return br;
}


static void tcg_proxy_sock_register(int sockfd)
{
    pthread_mutex_lock(&g_tcg_proxy_sock_lock);
    if (g_tcg_proxy_socks && g_tcg_proxy_sock_count < g_tcg_proxy_sock_capacity &&
        sockfd >= 0) {
        g_tcg_proxy_socks[g_tcg_proxy_sock_count++] = sockfd;
    }
    pthread_mutex_unlock(&g_tcg_proxy_sock_lock);
}

static void tcg_proxy_sock_unregister(int sockfd)
{
    long i;

    pthread_mutex_lock(&g_tcg_proxy_sock_lock);
    for (i = 0; i < g_tcg_proxy_sock_count; i++) {
        if (g_tcg_proxy_socks[i] == sockfd) {
            g_tcg_proxy_socks[i] = g_tcg_proxy_socks[g_tcg_proxy_sock_count - 1];
            g_tcg_proxy_sock_count--;
            break;
        }
    }
    pthread_mutex_unlock(&g_tcg_proxy_sock_lock);
}

static void tcg_wake_and_close_proxy_socks(void)
{
    long i;
    int sock;
    struct sockaddr_in addr;
    uint8_t poke = 0;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)g_service_port);
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        for (i = 0; i < 16; i++) {
            (void)sendto(sock, &poke, 1, 0, (struct sockaddr *)&addr,
                         sizeof(addr));
        }
        close(sock);
    }

    /* shutdown unblocks recvmmsg; owning proxy threads close the fds. */
    pthread_mutex_lock(&g_tcg_proxy_sock_lock);
    for (i = 0; i < g_tcg_proxy_sock_count; i++) {
        if (g_tcg_proxy_socks[i] >= 0) {
            (void)shutdown(g_tcg_proxy_socks[i], SHUT_RDWR);
        }
    }
    pthread_mutex_unlock(&g_tcg_proxy_sock_lock);
}

static void tcg_reap_remaining_helpers(void)
{
    long i;

    if (!g_tcg_helper_pids || g_num_cores <= 0) {
        return;
    }
    for (i = 0; i < g_num_cores; i++) {
        if (g_tcg_helper_pids[i] > 0) {
            (void)kill(g_tcg_helper_pids[i], SIGTERM);
        }
        if (g_tcg_session_fds && g_tcg_session_fds[i] >= 0) {
            close(g_tcg_session_fds[i]);
            g_tcg_session_fds[i] = -1;
        }
    }
    for (i = 0; i < g_num_cores; i++) {
        int status = 0;

        if (g_tcg_helper_pids[i] > 0) {
            (void)waitpid(g_tcg_helper_pids[i], &status, 0);
            g_tcg_helper_pids[i] = -1;
        }
    }
}

void* tcg_proxy_thread(void *arg) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    int opt = 1; setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr =
            htonl(g_executor_local_only ? INADDR_LOOPBACK : INADDR_ANY),
        .sin_port = htons(g_service_port)
    };
    if (sockfd < 0 || bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "[SLAVE-BIND] port=%d failed errno=%d\n", g_service_port, errno);
        executor_publish_startup_state(EXECUTOR_FAILED);
        if (sockfd >= 0) {
            close(sockfd);
        }
        return NULL;
    } else {
        fprintf(stderr, "[SLAVE-BIND] port=%d ok\n", g_service_port);
    }

    struct mmsghdr msgs[BATCH_SIZE] = {0};
    struct iovec iovecs[BATCH_SIZE] = {0};
    struct sockaddr_in src_addrs[BATCH_SIZE] = {0};
    uint8_t *rx_pool = calloc(BATCH_SIZE, WVM_MAX_PACKET_SIZE);
    if (!rx_pool) {
        perror("[Proxy] alloc rx_pool");
        executor_publish_startup_state(EXECUTOR_FAILED);
        close(sockfd);
        return NULL;
    }
    for(int i=0;i<BATCH_SIZE;i++) { iovecs[i].iov_base=rx_pool + (size_t)i * WVM_MAX_PACKET_SIZE; iovecs[i].iov_len=WVM_MAX_PACKET_SIZE; msgs[i].msg_hdr.msg_iov=&iovecs[i]; msgs[i].msg_hdr.msg_iovlen=1; msgs[i].msg_hdr.msg_name=&src_addrs[i]; msgs[i].msg_hdr.msg_namelen=sizeof(src_addrs[i]); }
    /* Listening is not READY: helpers must be verified by the owner thread. */
    tcg_proxy_sock_register(sockfd);
    g_tcg_proxy_listening = 1;

    printf("[Proxy] Tri-Channel NAT Active (CMD/REQ/PUSH) + MESI Support.\n");

    while(!g_shutdown_requested) {
        for (int i = 0; i < BATCH_SIZE; i++) {
            msgs[i].msg_hdr.msg_namelen = sizeof(src_addrs[i]);
            msgs[i].msg_hdr.msg_flags = 0;
            msgs[i].msg_len = 0;
        }
        int recv_flags = g_nonblock_recv ? MSG_DONTWAIT : MSG_WAITFORONE;
        int n = recvmmsg(sockfd, msgs, BATCH_SIZE, recv_flags, NULL);
        if (n <= 0) {
            if (g_shutdown_requested) break;
            if (g_nonblock_recv && (errno == EAGAIN || errno == EWOULDBLOCK)) usleep(100);
            continue;
        }

        for (int i=0; i<n; i++) {
            uint8_t *pkt = (uint8_t *)iovecs[i].iov_base;
            struct wvm_header *hdr = (struct wvm_header *)pkt;
            { static int __dbg=0;
              if (__dbg < 10) {
                  char ipbuf[16] = {0};
                  inet_ntop(AF_INET, &src_addrs[i].sin_addr, ipbuf, sizeof(ipbuf));
                  uint16_t raw_type = ntohs(hdr->msg_type);
                  uint32_t raw_magic = ntohl(hdr->magic);
                  fprintf(stderr, "[SLAVE-RX] src=%s:%u len=%u magic=0x%08x type=%u target=%u slave=%u\n",
                          ipbuf, (unsigned)ntohs(src_addrs[i].sin_port),
                          (unsigned)msgs[i].msg_len, raw_magic, (unsigned)raw_type,
                          (unsigned)ntohl(hdr->target_id), (unsigned)ntohl(hdr->slave_id));
                  __dbg++;
              }
            }
            { static int __big=0;
              if (__big < 10 && msgs[i].msg_len >= 200) {
                  char ipbuf[16] = {0};
                  inet_ntop(AF_INET, &src_addrs[i].sin_addr, ipbuf, sizeof(ipbuf));
                  uint16_t raw_type = ntohs(hdr->msg_type);
                  uint32_t raw_magic = ntohl(hdr->magic);
                  fprintf(stderr, "[SLAVE-RX-BIG] src=%s:%u len=%u magic=0x%08x type=%u\n",
                          ipbuf, (unsigned)ntohs(src_addrs[i].sin_port),
                          (unsigned)msgs[i].msg_len, raw_magic, (unsigned)raw_type);
                  __big++;
              }
            }
                        /*
             * G4: helper PUSH_BARRIER_ACK is an IPC frame (no WVM_MAGIC).
             * Connected UDP write() lands on this proxy sock; demux cookie.
             */
            if (msgs[i].msg_len >= (int)sizeof(wvm_ipc_header_t)) {
                wvm_ipc_header_t *ipc = (wvm_ipc_header_t *)pkt;
                if (ipc->type == WVM_IPC_TYPE_PUSH_BARRIER_ACK &&
                    ipc->len == sizeof(uint64_t) &&
                    msgs[i].msg_len >=
                        (int)(sizeof(*ipc) + sizeof(uint64_t))) {
                    uint64_t ack_cookie;
                    memcpy(&ack_cookie, pkt + sizeof(*ipc),
                           sizeof(ack_cookie));
                    mark_push_barrier_done(ack_cookie);
                    {
                        static int ack_log;
                        if (ack_log < 40) {
                            fprintf(stderr,
                                    "[Proxy] PUSH_BARRIER_ACK cookie=%llu "
                                    "from %s:%u\n",
                                    (unsigned long long)ack_cookie,
                                    inet_ntoa(src_addrs[i].sin_addr),
                                    (unsigned)ntohs(src_addrs[i].sin_port));
                            ack_log++;
                        }
                    }
                    continue;
                }
            }

if (hdr->magic != htonl(WVM_MAGIC)) {
                static int __badmagic;
                if (__badmagic < 8) {
                    fprintf(stderr, "[Proxy] drop bad magic=0x%08x len=%u from %s:%u\n",
                            (unsigned)ntohl(hdr->magic), (unsigned)msgs[i].msg_len,
                            inet_ntoa(src_addrs[i].sin_addr),
                            (unsigned)ntohs(src_addrs[i].sin_port));
                    __badmagic++;
                }
                continue;
            }

            /* In single-host tests gateway packets can also come from 127.0.0.1.
             * Only treat packets from known TCG endpoint ports as local upstream. */
            int from_local_tcg = (src_addrs[i].sin_addr.s_addr == htonl(INADDR_LOOPBACK)) &&
                                 is_local_tcg_endpoint_port(src_addrs[i].sin_port);
            // 1. Upstream (Local QEMU -> Gateway / pending VCPU_EXIT client)
            if (from_local_tcg) {
                // [VFIO Intercept] TCG 模式下的本地显卡拦截
                uint16_t msg_type = ntohs(hdr->msg_type);
                {
                    static int __up;
                    if (__up < 20 && (msg_type == MSG_VCPU_RUN || msg_type == MSG_VCPU_EXIT)) {
                        fprintf(stderr,
                                "[Proxy] UP-local type=%u len=%u from %s:%u\n",
                                (unsigned)msg_type, (unsigned)msgs[i].msg_len,
                                inet_ntoa(src_addrs[i].sin_addr),
                                (unsigned)ntohs(src_addrs[i].sin_port));
                        __up++;
                    }
                }
                int actual_payload = msgs[i].msg_len - (int)sizeof(struct wvm_header);
                uint16_t payload_len = ntohs(hdr->payload_len);
                if (msg_type == MSG_MEM_WRITE) {
                    if (actual_payload >= 8 &&
                        payload_len >= 8 &&
                        payload_len <= (uint16_t)actual_payload) {
                        uint64_t gpa = WVM_NTOHLL(*(uint64_t*)(pkt + sizeof(struct wvm_header)));
                        void *data = pkt + sizeof(struct wvm_header) + 8;
                        int len = payload_len - 8;
                        if (wvm_vfio_intercept_mmio(gpa, data, len, 1)) {
                            hdr->msg_type = htons(MSG_MEM_ACK);
                            hdr->payload_len = htons(0);
                            hdr->crc32 = 0;
                            hdr->crc32 = htonl(calculate_crc32(pkt, sizeof(struct wvm_header)));
                            sendto(sockfd, pkt, sizeof(struct wvm_header), 0,
                                   (struct sockaddr*)&src_addrs[i], sizeof(struct sockaddr_in));
                            continue; 
                        }
                    }
                }
                if (msg_type == MSG_VCPU_EXIT) {
                    struct sockaddr_in reply_client;
                    uint64_t rid = WVM_NTOHLL(hdr->req_id);
                    if (tcg_pending_vcpu_reply_peek(rid, &reply_client)) {
                        ssize_t sent;
                        fprintf(stderr,
                                "[Proxy] VCPU_EXIT demux req_id=0x%llx -> %s:%u len=%u\n",
                                (unsigned long long)rid,
                                inet_ntoa(reply_client.sin_addr),
                                (unsigned)ntohs(reply_client.sin_port),
                                (unsigned)msgs[i].msg_len);
                        sent = sendto(sockfd, pkt, msgs[i].msg_len, 0,
                                      (struct sockaddr *)&reply_client,
                                      sizeof(reply_client));
                        if (sent == (ssize_t)msgs[i].msg_len) {
                            tcg_pending_vcpu_reply_clear(rid);
                        } else {
                            fprintf(stderr,
                                    "[Proxy] VCPU_EXIT demux send failed "
                                    "req_id=0x%llx sent=%zd — keep pending\n",
                                    (unsigned long long)rid, sent);
                        }
                        continue;
                    }
                    fprintf(stderr,
                            "[Proxy] VCPU_EXIT no pending req_id=0x%llx (fwd gateway=%d)\n",
                            (unsigned long long)rid, g_gateway_known);
                }
                
                if (g_gateway_known) 
                    sendto(sockfd, pkt, msgs[i].msg_len, 0, (struct sockaddr*)&g_upstream_gateway, sizeof(struct sockaddr_in));
            }
            // 2. Downstream (Gateway / external -> Local QEMU)
            else {
                uint32_t target_raw = ntohl(hdr->target_id);
                uint16_t msg_type = ntohs(hdr->msg_type);
                {
                    static int __dn;
                    if (__dn < 40) {
                        fprintf(stderr,
                                "[Proxy] DN type=%u len=%u target=0x%x from %s:%u\n",
                                (unsigned)msg_type, (unsigned)msgs[i].msg_len,
                                target_raw, inet_ntoa(src_addrs[i].sin_addr),
                                (unsigned)ntohs(src_addrs[i].sin_port));
                        __dn++;
                    }
                }
                int core_idx = (target_raw != WVM_NODE_AUTO_ROUTE)
                    ? (int)(WVM_GET_NODEID(target_raw) - g_base_id)
                    : 0;

                /* N2: validate target/index BEFORE any tcg_endpoints[] access. */
                if (core_idx < 0 || core_idx >= g_num_cores) {
                    static int __oob;
                    if (__oob < 8) {
                        fprintf(stderr,
                                "[Proxy] drop DN type=%u target=0x%x core_idx=%d "
                                "(out of range num_cores=%ld)\n",
                                (unsigned)msg_type, target_raw, core_idx,
                                (long)g_num_cores);
                        __oob++;
                    }
                    continue;
                }

                /* VCPU_RUN is request/reply: remember client, do not steal gateway. */
                if (msg_type == MSG_VCPU_RUN) {
                    uint64_t rid = WVM_NTOHLL(hdr->req_id);
                    if (tcg_pending_vcpu_reply_put(rid, &src_addrs[i]) != 0) {
                        fprintf(stderr,
                                "[Proxy] VCPU_RUN pending REJECT req_id=0x%llx "
                                "from %s:%u (table full or req_id client conflict)\n",
                                (unsigned long long)rid,
                                inet_ntoa(src_addrs[i].sin_addr),
                                (unsigned)ntohs(src_addrs[i].sin_port));
                        continue; /* do not forward without reply association */
                    }
                    fprintf(stderr,
                            "[Proxy] VCPU_RUN pending req_id=0x%llx from %s:%u "
                            "-> core=%d cmd_port=%u len=%u\n",
                            (unsigned long long)rid,
                            inet_ntoa(src_addrs[i].sin_addr),
                            (unsigned)ntohs(src_addrs[i].sin_port),
                            core_idx,
                            (unsigned)ntohs(tcg_endpoints[core_idx].cmd_addr.sin_port),
                            (unsigned)msgs[i].msg_len);
                } else if (!g_gateway_init_done) {
                    if (__sync_bool_compare_and_swap(&g_gateway_init_done, 0, 1)) {
                        memcpy(&g_upstream_gateway, &src_addrs[i], sizeof(struct sockaddr_in));
                        g_gateway_known = 1;
                        printf("[Proxy] Gateway Locked: %s:%d\n", inet_ntoa(src_addrs[i].sin_addr), ntohs(src_addrs[i].sin_port));
                    }
                }

                // [V28 分流逻辑升级]
                if (msg_type == MSG_MEM_WRITE || msg_type == MSG_MEM_READ ||
                    msg_type == MSG_INVALIDATE || msg_type == MSG_DOWNGRADE || 
                    msg_type == MSG_FETCH_AND_INVALIDATE ||
                    msg_type == MSG_PAGE_PUSH_FULL || 
                    msg_type == MSG_PAGE_PUSH_DIFF || 
                    msg_type == MSG_FORCE_SYNC) {
                     sendto(sockfd, pkt, msgs[i].msg_len, 0,
                          (struct sockaddr*)&tcg_endpoints[core_idx].push_addr, sizeof(struct sockaddr_in));
                }
                else if (msg_type == MSG_MEM_ACK) {
                    uint64_t ack_rid = WVM_NTOHLL(hdr->req_id);
                    // 异步推送 ACK 和 slave dirty-flush 栅栏 ACK 都属于 PUSH 通道。
                    if (ack_rid == ~0ULL || ack_rid == SYNC_MAGIC)
                        sendto(sockfd, pkt, msgs[i].msg_len, 0,
                              (struct sockaddr*)&tcg_endpoints[core_idx].push_addr, sizeof(struct sockaddr_in));
                    else
                        sendto(sockfd, pkt, msgs[i].msg_len, 0,
                              (struct sockaddr*)&tcg_endpoints[core_idx].req_addr, sizeof(struct sockaddr_in));
                }
                else {
                    sendto(sockfd, pkt, msgs[i].msg_len, 0,
                          (struct sockaddr*)&tcg_endpoints[core_idx].cmd_addr, sizeof(struct sockaddr_in));
                }
            }
        }
    }
    tcg_proxy_sock_unregister(sockfd);
    close(sockfd);
    free(rx_pool);
    return NULL;
}

int wavevm_executor_runtime_main(
    const struct wvm_node_runtime_context *runtime) {
    char error[256] = {0};

    /* Publish the transitional state before the node runtime can wait on it. */
    executor_publish_startup_state(EXECUTOR_STARTING);

    if (!runtime || !runtime->manifest || !runtime->dispatch ||
        runtime->physical_node_id == 0 || runtime->manifest->vm_id == 0 ||
        runtime->local_memory_bytes == 0 ||
        runtime->local_memory_bytes % (1024ULL * 1024ULL) != 0 ||
        runtime->executor_worker_count == 0) {
        fprintf(stderr, "[Runtime] admitted executor context is invalid\n");
        executor_publish_startup_state(EXECUTOR_FAILED);
        return 1;
    }

    g_nonblock_recv = (getenv("WVM_NONBLOCK_RECV") != NULL);

    // 启动时自动创建存储目录
    struct stat st = {0};
    if (stat("/var/lib/wavevm", &st) == -1) {
        mkdir("/var/lib/wavevm", 0755);
    }
    if (stat("/var/lib/wavevm/chunks", &st) == -1) {
        mkdir("/var/lib/wavevm/chunks", 0755);
    }
    {
        const char *chunk_dir = getenv("WVM_STORAGE_CHUNK_DIR");
        char cerr[128];
        char identity[192];
        uint32_t device_index = 0;

        if (wvm_block_chunk_store_set_dir(
                chunk_dir && chunk_dir[0] ? chunk_dir
                                          : "/var/lib/wavevm/chunks",
                cerr, sizeof(cerr)) != 0) {
            fprintf(stderr, "[Runtime] chunk store dir: %s\n", cerr);
        }
        /*
         * R02: isolate backends by VM/incarnation/volume identity from the
         * admitted manifest — never share flat c_<chunk>.bin across VMs.
         */
        if (runtime->manifest->local_storage_assignments.count > 0)
            device_index = runtime->manifest->local_storage_assignments.entries[0]
                               .device_index;
        snprintf(identity, sizeof(identity), "vm%u_inc%llu_vol%u",
                 runtime->manifest->vm_id,
                 (unsigned long long)runtime->manifest->vm_incarnation,
                 device_index);
        if (wvm_block_chunk_store_set_identity(identity, cerr, sizeof(cerr)) !=
            0) {
            fprintf(stderr, "[Runtime] chunk identity: %s\n", cerr);
        } else {
            fprintf(stderr, "[Runtime] chunk identity=%s dir=%s\n", identity,
                    wvm_block_chunk_store_dir());
        }
    }
    g_service_port = runtime->executor_service_port;
    g_num_cores = (long)runtime->executor_worker_count;
    g_ram_mb = (int)(runtime->local_memory_bytes / (1024ULL * 1024ULL));
    g_slave_ram_size = runtime->local_memory_bytes;
    g_base_id = (int)runtime->local_primary_vnode;
    g_executor_ctrl_port = runtime->executor_control_port;
    g_slave_vm_id = runtime->manifest->vm_id;
    if (executor_runtime_gate_init(runtime) != 0) {
        executor_publish_startup_state(EXECUTOR_FAILED);
        return 1;
    }

    printf("[Init] WaveVM Hybrid Slave V28.0 (Swarm Edition)\n");
    printf("[Init] Config: Port=%d, Cores=%ld, RAM=%d MB, BaseID=%d, VM=%u\n",
           g_service_port, g_num_cores, g_ram_mb, g_base_id, (unsigned)g_slave_vm_id);

    init_kvm_global();
    if (g_kernel_context_bind_failed) {
        fprintf(stderr,
                "[KernelContext] refusing executor startup after a "
                "manifest/context mismatch\n");
        executor_publish_startup_state(EXECUTOR_FAILED);
        return 1;
    }

    /* Select backend from manifest, not host capability auto-detection */
    enum wvm_manifest_backend admitted_backend =
        g_executor_manifest_storage.manifest.negotiated_profile.backend;
    int use_kvm = 0;

    if (admitted_backend == WVM_MANIFEST_BACKEND_KVM) {
        if (!g_kvm_available) {
            fprintf(stderr,
                    "[Backend] Manifest requires KVM but /dev/kvm is unavailable\n");
            executor_publish_startup_state(EXECUTOR_FAILED);
            return 1;
        }
        use_kvm = 1;
    } else if (admitted_backend == WVM_MANIFEST_BACKEND_TCG) {
        use_kvm = 0;
    } else {
        fprintf(stderr, "[Backend] Unknown manifest backend %d\n", admitted_backend);
        executor_publish_startup_state(EXECUTOR_FAILED);
        return 1;
    }

    if (use_kvm) {
        if (g_executor_local_only) {
            struct wvm_kvm_page_cache_config cache_config;
            uint64_t guest_bytes =
                g_executor_manifest_storage.manifest.launch_plan
                    .guest_total_memory_bytes;

            memset(&cache_config, 0, sizeof(cache_config));
            cache_config.vm_id = g_slave_vm_id;
            cache_config.vm_incarnation =
                g_executor_manifest_storage.manifest.vm_incarnation;
            cache_config.max_page_records =
                (guest_bytes + WVM_MEMORY_PAGE_BYTES - 1U) /
                WVM_MEMORY_PAGE_BYTES;
            cache_config.completion_timeout_ms =
                g_executor_manifest_storage.manifest.launch_plan
                    .consistency_policy.max_commit_latency_ms;
            if (cache_config.max_page_records == 0 ||
                wvm_kvm_page_cache_global_install(
                    &cache_config, error, sizeof(error)) != 0) {
                fprintf(stderr, "[RuntimeGate] cannot install KVM page cache: %s\n",
                        error[0] ? error : "invalid cache configuration");
                executor_publish_startup_state(EXECUTOR_FAILED);
                return 1;
            }
        }
        printf("[Hybrid] Mode: KVM FAST PATH. Listening on %s:%d\n",
               g_executor_local_only ? "127.0.0.1" : "0.0.0.0",
               g_service_port);
        if (pthread_create(&g_dirty_sender_thread, NULL,
                           dirty_sync_sender_thread, NULL) != 0) {
            perror("Failed to create dirty page sender thread");
            executor_publish_startup_state(EXECUTOR_FAILED);
            return 1;
        }
        g_dirty_sender_started = 1;
        // 启动 VFIO IRQ 转发线程
        if (g_vfio_config_path) {
            pthread_t irq_th;
            pthread_create(&irq_th, NULL, vfio_irq_thread_adapter, NULL);
        }
        /* Keep a single KVM worker to avoid vCPU create races on shared VM fd. */
        int total_threads = 1;
        pthread_t *threads = malloc(sizeof(pthread_t) * total_threads);
        if (!threads) {
            executor_publish_startup_state(EXECUTOR_FAILED);
            return 1;
        }
        for (long i = 0; i < total_threads; i++) {
            if (pthread_create(&threads[i], NULL, kvm_worker_thread,
                               (void *)i) != 0) {
                executor_publish_startup_state(EXECUTOR_FAILED);
                free(threads);
                return 1;
            }
        }
        if (wvm_executor_runtime_wait_ready() != 0) {
            executor_request_process_shutdown("kvm wait_ready failed");
        }
        /*
         * Mirror TCG: do not join the worker until shutdown. Worker blocks in
         * recvmmsg(MSG_WAITFORONE); without a poke/shutdown, SIGTERM only
         * flips g_shutdown_requested and the process never exits (R4 STOP).
         */
        while (!g_shutdown_requested) {
            usleep(100000);
        }
        kvm_wake_worker_sock();
        for(long i=0; i<total_threads; i++) pthread_join(threads[i], NULL);
        free(threads);
        __atomic_store_n(&g_kvm_worker_sock, -1, __ATOMIC_RELEASE);
        if (stop_dirty_sender_thread() != 0) {
            return 1;
        }
    } else {
        printf("[Hybrid] Mode: TCG PROXY (Tri-Channel). Listening on %s:%d\n",
               g_executor_local_only ? "127.0.0.1" : "0.0.0.0",
               g_service_port);
        int proxy_threads = g_num_cores / 2; 
        if (proxy_threads < 1) proxy_threads = 1;
        pthread_t *threads = malloc(sizeof(pthread_t) * proxy_threads);
        if (!threads) {
            executor_publish_startup_state(EXECUTOR_FAILED);
            return 1;
        }
        free(g_tcg_proxy_socks);
        g_tcg_proxy_socks = calloc((size_t)proxy_threads, sizeof(*g_tcg_proxy_socks));
        g_tcg_proxy_sock_capacity = proxy_threads;
        g_tcg_proxy_sock_count = 0;
        if (!g_tcg_proxy_socks) {
            executor_publish_startup_state(EXECUTOR_FAILED);
            free(threads);
            return 1;
        }
        for (long si = 0; si < proxy_threads; si++) {
            g_tcg_proxy_socks[si] = -1;
        }
        for (long i = 0; i < proxy_threads; i++) {
            if (pthread_create(&threads[i], NULL, tcg_proxy_thread, NULL) != 0) {
                executor_publish_startup_state(EXECUTOR_FAILED);
                executor_request_process_shutdown("tcg proxy thread create failed");
                free(threads);
                return 1;
            }
        }
        /*
         * Required TCG helpers must be live before EXECUTOR_READY. Proxy listen
         * alone must not forge readiness. Guest E2E attach is still out of scope.
         */
        if (spawn_tcg_processes(g_base_id) != 0) {
            fprintf(stderr,
                    "[Hybrid] required TCG helpers unavailable; not READY\n");
            executor_publish_startup_state(EXECUTOR_FAILED);
            for (long i = 0; i < proxy_threads; i++) {
                pthread_join(threads[i], NULL);
            }
            free(threads);
            return 1;
        }
        for (int wait_i = 0; wait_i < 100 && !g_tcg_proxy_listening; wait_i++) {
            usleep(10000);
        }
        if (!g_tcg_proxy_listening) {
            fprintf(stderr, "[Hybrid] TCG proxy did not listen; not READY\n");
            executor_publish_startup_state(EXECUTOR_FAILED);
            for (long i = 0; i < proxy_threads; i++) {
                pthread_join(threads[i], NULL);
            }
            free(threads);
            return 1;
        }
        executor_publish_startup_state(EXECUTOR_READY);
        fprintf(stderr,
                "[Hybrid] local executor READY with live TCG helpers "
                "(no guest E2E claim)\n");
        while (!g_shutdown_requested) {
            int status;
            pid_t died = waitpid(-1, &status, WNOHANG);

            if (died > 0) {
                fprintf(stderr,
                        "[Hybrid] required TCG helper pid=%d exited status=%d; "
                        "executor leaves READY\n",
                        (int)died, status);
                executor_publish_startup_state(EXECUTOR_FAILED);
                executor_request_process_shutdown(
                    "required TCG helper exited after READY");
                tcg_wake_and_close_proxy_socks();
                tcg_reap_remaining_helpers();
                break;
            }
            if (died < 0 && errno != ECHILD) {
                fprintf(stderr,
                        "[Hybrid] waitpid error errno=%d; requesting shutdown\n",
                        errno);
                executor_request_process_shutdown("TCG helper waitpid error");
                tcg_wake_and_close_proxy_socks();
                tcg_reap_remaining_helpers();
                break;
            }
            usleep(100000);
        }
        if (g_shutdown_requested) {
            tcg_wake_and_close_proxy_socks();
            tcg_reap_remaining_helpers();
        }
        for (long i = 0; i < proxy_threads; i++) {
            pthread_join(threads[i], NULL);
        }
        free(threads);
        free(g_tcg_proxy_socks);
        g_tcg_proxy_socks = NULL;
        g_tcg_proxy_sock_capacity = 0;
        g_tcg_proxy_sock_count = 0;
    }
    return 0;
}
