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
#include "../common_include/wavevm_ioctl.h"
#include "../common_include/wavevm_runtime_gate.h"
#include "../common_include/wavevm_executor_abi.h"
#include "../common_include/wavevm_executor_session.h"
#include "../common_include/wavevm_vcpu_handoff.h"
#include "../common_include/wavevm_x86_context.h"
#include "../node_runtime/executor_runtime.h"
#include "../node_runtime/kvm_page_cache.h"
#include "../node_runtime/memory_service.h"
#include "../node_runtime/runtime_context.h"

/* The unified node runtime owns this flag.  The weak definition keeps the
 * standalone executor linkable while the strong runtime definition is used
 * when master and executor share one process image. */
#if defined(__GNUC__)
__attribute__((weak))
#endif
volatile sig_atomic_t g_shutdown_requested = 0;

// --- 全局配置变量 ---
static int g_service_port = 9000;
static int g_nonblock_recv = 0;
static long g_num_cores = 0;
static int *g_tcg_session_fds;
static int g_ram_mb = 1024;
static uint64_t g_slave_ram_size = 1024UL * 1024 * 1024;
static int g_base_id = 0;
static uint32_t g_slave_vm_id = 0;
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
static enum executor_startup_state g_executor_startup_state = EXECUTOR_FAILED;

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

    if (ioctl(g_wvm_dev_fd, IOCTL_WVM_BIND_CONTEXT, &request) < 0) {
        fprintf(stderr,
                "[KernelContext] executor Mode A context bind failed: "
                "errno=%d (%s)\n",
                errno, strerror(errno));
        return -1;
    }
    fprintf(stderr,
            "[KernelContext] executor bound VM=%u incarnation=%" PRIu64
            " node=%u\n",
            request.vm_id, request.vm_incarnation, request.physical_node_id);
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

    // 物理打开：确保目录存在
    // 生产环境应在启动脚本中 mkdir -p /var/lib/wavevm/chunks
    char path[256];
    snprintf(path, sizeof(path), "/var/lib/wavevm/chunks/c_%" PRIu64 ".bin", chunk_id);
    
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
void init_kvm_global() {
    const char *force_tcg = getenv("WVM_FORCE_TCG");
    if (force_tcg && atoi(force_tcg) == 1) {
        fprintf(stderr, "[Hybrid] WVM_FORCE_TCG=1, skip KVM init.\n");
        g_kvm_available = 0;
        return;
    }

    g_kvm_fd = open("/dev/kvm", O_RDWR);
    if (g_kvm_fd < 0) return; 

    g_wvm_dev_fd = open("/dev/wavevm", O_RDWR);
    if (g_wvm_dev_fd >= 0 && executor_bind_kernel_context() != 0) {
        g_kernel_context_bind_failed = 1;
        close(g_wvm_dev_fd);
        g_wvm_dev_fd = -1;
        return;
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
    wh->slave_id = htonl(WVM_ENCODE_ID(g_slave_vm_id, (uint32_t)g_base_id));
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

static void submit_typed_dirty_page(dirty_page_task_t *task)
{
    struct wvm_mem_commit_ack ack;
    char error[256] = {0};
    uint16_t status = WVM_MEM_COMMIT_ACK_INTERNAL_FAILURE;
    uint64_t result_version = 0;
    int request_result;

    if (!task || !task->slice) {
        return;
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
                "[KVM commit] GPA=%#" PRIx64 " base=%#" PRIx64
                " failed status=%u result=%d reason=%s\n",
                task->dirty.gpa, task->dirty.base_version, (unsigned)status,
                request_result, error[0] ? error : "commit rejected");
    }
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

        // 如果队列为空，则阻塞等待
        while (g_mpsc_head == g_mpsc_tail) {
            pthread_cond_wait(&g_mpsc_cond, &g_mpsc_lock);
        }

        // 从队列头部取出一个任务
        uint32_t current_head = g_mpsc_head;
        dirty_page_task_t* task = g_mpsc_queue[current_head];
        g_mpsc_head = (current_head + 1) % MPSC_QUEUE_SIZE;
        
        pthread_mutex_unlock(&g_mpsc_lock);
        
        if (task && task->slice) {
            submit_typed_dirty_page(task);
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
        wh->slave_id = htonl(WVM_ENCODE_ID(g_slave_vm_id, (uint32_t)g_base_id));
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

    (void)opaque;
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

    memset(&local_request, 0, sizeof(local_request));
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
    if (local_ack.status == WVM_CPU_RUN_STATUS_MEMORY_FAILURE) {
        typed_handoff_result_from_request(
            request, WVM_VCPU_HANDOFF_RESULT_MEMORY_FAILURE, result);
        result->error_gpa = local_ack.error_gpa;
        return 0;
    }
    if (local_ack.status != 0) {
        typed_handoff_result_from_request(
            request, WVM_VCPU_HANDOFF_RESULT_EXECUTOR_FAILURE, result);
        return 0;
    }

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
    typed_handoff_result_from_request(request, WVM_VCPU_HANDOFF_RESULT_SUCCESS,
                                      result);
    result->exit_class = typed_exit_class_from_legacy_ack(request, &local_ack);
    result->produced_memory_fence_id = fence_id;
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
    if (!req) return;
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
        ack_hdr.slave_id = htonl(WVM_ENCODE_ID(g_slave_vm_id, (uint32_t)g_base_id));
        ack_hdr.target_id = hdr->slave_id;  /* already in network byte order */
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
        ack_hdr.slave_id = htonl(WVM_ENCODE_ID(g_slave_vm_id, (uint32_t)g_base_id));
        ack_hdr.target_id = hdr->slave_id;  /* already in network byte order */
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
        struct {
            struct kvm_msrs info;
            struct kvm_msr_entry entries[3];
        } msr_data;
        memset(&msr_data, 0, sizeof(msr_data));
        msr_data.info.nmsrs = 3;
        msr_data.entries[0].index = 0x10;       /* MSR_IA32_TSC */
        msr_data.entries[0].data  = req->ctx.kvm.tsc_value;
        msr_data.entries[1].index = 0x6e0;      /* MSR_IA32_TSCDEADLINE */
        msr_data.entries[1].data  = req->ctx.kvm.tsc_deadline;
        msr_data.entries[2].index = 0xC0000102;  /* MSR_KERNEL_GS_BASE */
        msr_data.entries[2].data  = req->ctx.kvm.kernel_gs_base;
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

        if (g_wvm_device_ram_mapping ||
            wvm_kvm_memory_slice_global_begin(
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
                if (!t_kvm_run->mmio.is_write) {
                    /* Return proper values for critical LAPIC registers. */
                    uint32_t val = 0;
                    switch (reg_off) {
                    case 0x020: /* APIC ID (bits 31:24 = APIC ID in xAPIC) */
                        val = ((uint32_t)guest_vcpu_id) << 24;
                        break;
                    case 0x030: /* APIC Version */
                        val = 0x50014; /* version 0x14, max LVT 5 */
                        break;
                    case 0x0D0: /* Logical Destination Register */
                        val = (1U << (guest_vcpu_id & 7)) << 24;
                        break;
                    case 0x0E0: /* Destination Format Register */
                        val = 0xFFFFFFFFU; /* flat model */
                        break;
                    case 0x0F0: /* Spurious Interrupt Vector Register */
                        val = 0x1FF; /* APIC enabled, vector 0xFF */
                        break;
                    case 0x300: /* ICR low -- delivery status=idle */
                        val = 0;
                        break;
                    default:
                        val = 0;
                        break;
                    }
                    memcpy(t_kvm_run->mmio.data, &val, sizeof(val));
                    if (t_kvm_run->mmio.len < 4)
                        memset(t_kvm_run->mmio.data + t_kvm_run->mmio.len, 0,
                               8 - t_kvm_run->mmio.len);
                }
                /* Check alarm before re-entering KVM_RUN.  Guest may be in a
                 * tight LAPIC polling loop (e.g. ICR delivery status) which
                 * would generate infinite MMIO exits. */
                if (t_kvm_alarm_fired) break;
                continue; /* re-enter KVM_RUN */
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
                continue;
            }

            log.slot = slot->slot;
            log.dirty_bitmap = t_dirty_bitmap_cache;
            memset(log.dirty_bitmap, 0, bitmap_size);

            if (ioctl(g_vm_fd, KVM_GET_DIRTY_LOG, &log) != 0) {
                continue;
            }

            unsigned long *p = (unsigned long *)log.dirty_bitmap;
            uint64_t num_longs = bitmap_size / sizeof(unsigned long);

            for (uint64_t i = 0; i < num_longs; i++) {
                if (p[i] == 0) continue;

                for (size_t b = 0; b < nbits_per_long; b++) {
                    if ((p[i] >> b) & 1) {
                        uint64_t gpa = slot->guest_phys_addr +
                                       (i * nbits_per_long + b) * WVM_PAGE_SIZE;
                        if (gpa >= g_slave_ram_size) continue;

                        uint8_t *hva = wvm_gpa_to_hva(gpa);
                        if (!hva) continue;

                        struct wvm_kvm_dirty_page dirty;
                        dirty_page_task_t *task;

                        memset(&dirty, 0, sizeof(dirty));
                        if (memory_slice &&
                            wvm_kvm_memory_slice_capture_dirty(
                                memory_slice, gpa, &dirty, NULL, 0) != 0) {
                            wvm_kvm_memory_slice_fail(
                                memory_slice, gpa, NULL, 0);
                            memory_fence_status =
                                WVM_CPU_RUN_STATUS_MEMORY_FAILURE;
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
    ack_hdr.slave_id = htonl(WVM_ENCODE_ID(g_slave_vm_id, (uint32_t)g_base_id));
    ack_hdr.target_id = hdr->slave_id;  /* already in network byte order */
    ack_hdr.req_id = WVM_HTONLL(hdr->req_id);
    
    struct wvm_ipc_cpu_run_ack *ack = (struct wvm_ipc_cpu_run_ack *)payload;
    ack->status = memory_fence_status;
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
            struct {
                struct kvm_msrs info;
                struct kvm_msr_entry entries[3];
            } msr_data;
            memset(&msr_data, 0, sizeof(msr_data));
            msr_data.info.nmsrs = 3;
            msr_data.entries[0].index = 0x10;       /* MSR_IA32_TSC */
            msr_data.entries[1].index = 0x6e0;      /* MSR_IA32_TSCDEADLINE */
            msr_data.entries[2].index = 0xC0000102;  /* MSR_KERNEL_GS_BASE */
            if (ioctl(t_vcpu_fd, KVM_GET_MSRS, &msr_data) >= 0) {
                ack_kctx->tsc_value = msr_data.entries[0].data;
                ack_kctx->tsc_deadline = msr_data.entries[1].data;
                ack_kctx->kernel_gs_base = msr_data.entries[2].data;
                ack_kctx->tsc_valid = 1;
            } else {
                ack_kctx->tsc_valid = 0;
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
    uint8_t state = WVM_KVM_PAGE_ABSENT;
    uint64_t version = 0;
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    uint8_t page[WVM_MEMORY_PAGE_BYTES];
    struct wvm_mem_ack ack;
    char error[256] = {0};
    int result;

    if (!hva || !version_out ||
        wvm_kvm_page_cache_global_lookup(
            gpa, &state, &version, error, sizeof(error)) != 0) {
        return -EINVAL;
    }
    if (state == WVM_KVM_PAGE_CLEAN && version != 0) {
        *version_out = version;
        return 0;
    }
    if (state == WVM_KVM_PAGE_DIRTY ||
        state == WVM_KVM_PAGE_SUBMITTING) {
        return -EBUSY;
    }

    build_kvm_snapshot_operation_id(hdr, gpa, operation_id);
    memset(&ack, 0, sizeof(ack));
    result = wvm_memory_service_global_request_fault(
        gpa, operation_id, 1, &ack, page, error, sizeof(error));
    if (result != 0 || ack.status != WVM_MEM_ACK_SUCCESS ||
        ack.version == 0 || ack.data_bytes != WVM_MEMORY_PAGE_BYTES) {
        return result != 0 ? result : -EIO;
    }
    result = wvm_kvm_page_cache_global_install_full(
        gpa, ack.version, error, sizeof(error));
    if (result != 0) {
        return result;
    }
    memcpy(hva, page, WVM_MEMORY_PAGE_BYTES);
    *version_out = ack.version;
    return 0;
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
        ack_hdr.slave_id = htonl(WVM_ENCODE_ID(g_slave_vm_id, (uint32_t)g_base_id));
        ack_hdr.target_id = hdr->slave_id;  /* already in network byte order */
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

static void handle_block_io_phys(int sockfd, struct sockaddr_in *client, struct wvm_header *hdr, void *payload) {
    struct wvm_block_payload *blk = (struct wvm_block_payload *)payload;
    uint64_t lba = WVM_NTOHLL(blk->lba);
    #ifndef WVM_STORAGE_CHUNK_SHIFT
    #define WVM_STORAGE_CHUNK_SHIFT 26
    #endif
    uint32_t count = ntohl(blk->count);
    if (count == 0 || count > (64U << 20) / 512) return; // 防溢出：上限 64MB
    uint32_t data_len = count * 512;
    // [FIX] 验证 count*512 不超过实际 payload 数据（防越界读）
    if (hdr->msg_type == MSG_BLOCK_WRITE) {
        uint16_t actual_pl = hdr->payload_len; // 已被 ntoh_header 转为 host order
        if (actual_pl < sizeof(struct wvm_block_payload)) return; // 防无符号下溢
        if (data_len > actual_pl - sizeof(struct wvm_block_payload)) return;
    }
    
    uint64_t chunk_id = (lba << 9) >> WVM_STORAGE_CHUNK_SHIFT;
    off_t offset = (lba << 9) & ((1UL << WVM_STORAGE_CHUNK_SHIFT) - 1);
    
    int fd = get_chunk_fd_safe(chunk_id);
    if (fd < 0) return; 

    void *aligned_buf = NULL;
    if (hdr->msg_type == MSG_BLOCK_WRITE || hdr->msg_type == MSG_BLOCK_READ) {
        if (posix_memalign(&aligned_buf, 4096, data_len) != 0) return;
    }

    if (hdr->msg_type == MSG_BLOCK_WRITE) {
        memcpy(aligned_buf, blk->data, data_len);
        ssize_t written = pwrite(fd, aligned_buf, data_len, offset);

        hdr->msg_type = htons(MSG_BLOCK_ACK);
        hdr->payload_len = htons(0);
        hdr->magic = htonl(WVM_MAGIC);
        hdr->slave_id = htonl(hdr->slave_id);
        hdr->target_id = htonl(hdr->target_id);
        hdr->req_id = WVM_HTONLL(hdr->req_id);
        hdr->epoch = htonl(hdr->epoch);
        if (written != data_len) {
            hdr->flags |= WVM_FLAG_ERROR;
        }
        
        // [FIX] 发送前必须重算 CRC32
        hdr->crc32 = 0;
        hdr->crc32 = htonl(calculate_crc32(hdr, sizeof(*hdr)));
        sendto(sockfd, hdr, sizeof(*hdr), 0, (struct sockaddr*)client, sizeof(*client));
    
    } else if (hdr->msg_type == MSG_BLOCK_READ) {
        size_t resp_len = sizeof(struct wvm_header) + sizeof(struct wvm_block_payload) + data_len;
        uint8_t *tx = malloc(resp_len);
        if (tx) {
            struct wvm_header *rh = (struct wvm_header*)tx;
            *rh = *hdr;
            rh->msg_type = htons(MSG_BLOCK_ACK);
            rh->payload_len = htons(sizeof(struct wvm_block_payload) + data_len);
            rh->magic = htonl(WVM_MAGIC);
            rh->slave_id = htonl(hdr->slave_id);
            rh->target_id = htonl(hdr->target_id);
            rh->req_id = WVM_HTONLL(hdr->req_id);
            rh->epoch = htonl(hdr->epoch);

            struct wvm_block_payload *rp = (struct wvm_block_payload*)(tx + sizeof(*hdr));
            rp->lba = blk->lba;
            rp->count = blk->count;

            ssize_t r = pread(fd, aligned_buf, data_len, offset);
            if (r > 0) memcpy(rp->data, aligned_buf, r);

            // [FIX] 发送前必须重算 CRC32
            rh->crc32 = 0;
            rh->crc32 = htonl(calculate_crc32(tx, resp_len));
            robust_sendto(sockfd, tx, resp_len, client);
            free(tx);
        }
    } else if (hdr->msg_type == MSG_BLOCK_FLUSH) {
        int ret = fdatasync(fd);
        hdr->msg_type = htons(MSG_BLOCK_ACK);
        hdr->payload_len = htons(0);
        hdr->magic = htonl(WVM_MAGIC);
        hdr->slave_id = htonl(hdr->slave_id);
        hdr->target_id = htonl(hdr->target_id);
        hdr->req_id = WVM_HTONLL(hdr->req_id);
        hdr->epoch = htonl(hdr->epoch);
        if (ret < 0) hdr->flags |= WVM_FLAG_ERROR;

        // [FIX] 发送前必须重算 CRC32
        hdr->crc32 = 0;
        hdr->crc32 = htonl(calculate_crc32(hdr, sizeof(*hdr)));
        sendto(sockfd, hdr, sizeof(*hdr), 0, (struct sockaddr*)client, sizeof(*client));
    }
    
    free(aligned_buf);
}

/* 
 * [物理意图] Slave 节点的“任务分发中心”，负责监听并调度来自全网的 RPC 指令。
 * [关键逻辑] 绑定多播/复用端口，利用 recvmmsg 批量捕获包头，根据消息类型分流至执行引擎或内存处理程序。
 * [后果] 它是 Slave 节点的总入口。其效率直接决定了 Slave 对 Master 请求的“首包响应时间（TTFB）”。
 */
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
            else if (type == MSG_BLOCK_WRITE || type == MSG_BLOCK_READ || type == MSG_BLOCK_FLUSH) {
                // 存储入口
                handle_block_io_phys(s, &c[i], h, pkt+sizeof(*h));
            }
            else handle_kvm_mem(s, &c[i], h, pkt+sizeof(*h));
        }
    }
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
void spawn_tcg_processes(int base_id) {
    printf("[Hybrid] Spawning %ld QEMU-TCG instances (Tri-Channel Isolation)...\n", g_num_cores);
    const char *qemu_bin = getenv("WVM_TCG_QEMU_BIN");
    if (!qemu_bin || !*qemu_bin) {
        qemu_bin = "qemu-system-x86_64";
    }
    
    tcg_endpoints = malloc(sizeof(slave_endpoint_t) * g_num_cores);
    if (!tcg_endpoints) { perror("malloc endpoints"); exit(1); }
    g_tcg_session_fds = malloc(sizeof(*g_tcg_session_fds) * g_num_cores);
    if (!g_tcg_session_fds) { perror("malloc executor sessions"); exit(1); }
    for (long i = 0; i < g_num_cores; i++) {
        g_tcg_session_fds[i] = -1;
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
                continue;
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
            snprintf(id_str, sizeof(id_str), "%u", WVM_ENCODE_ID(g_slave_vm_id, base_id + i));
            setenv("WVM_SLAVE_ID", id_str, 1);

            const char *shm_path = getenv("WVM_SHM_FILE");
            if (shm_path) {
                setenv("WVM_SHM_FILE", shm_path, 1);
            }

            cpu_set_t cpuset; CPU_ZERO(&cpuset); CPU_SET(i, &cpuset); sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
            
            char *qemu_argv[16];
            int ai = 0;

            qemu_argv[ai++] = (char *)qemu_bin;
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
            qemu_argv[ai] = NULL;

            execvp(qemu_bin, qemu_argv);
            perror("[Hybrid] execlp qemu");
            _exit(127);
            }
            if (child_pid < 0) {
                perror("[Hybrid] fork qemu");
                close(session_pair[0]);
                close(session_pair[1]);
                continue;
            }
            close(session_pair[1]);
            g_tcg_session_fds[i] = session_pair[0];
        }
        // parent: sockets are only created in child branch
    }
}

/* 
 * [物理意图] 充当 TCG 实例与 P2P 网络之间的“物理层协议翻译官”。
 * [关键逻辑] 维护 CMD（控制）、REQ（同步请求）、PUSH（异步推送）三通道的路由，并实现 VFIO 的本地拦截。
 * [后果] 解决了模拟模式下的网络竞争问题，通过物理通道隔离，保证了高频内存同步不会阻塞关键的 CPU 控制指令。
 */
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
    executor_publish_startup_state(EXECUTOR_READY);

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
            if (hdr->magic != htonl(WVM_MAGIC)) continue;

            /* In single-host tests gateway packets can also come from 127.0.0.1.
             * Only treat packets from known TCG endpoint ports as local upstream. */
            int from_local_tcg = (src_addrs[i].sin_addr.s_addr == htonl(INADDR_LOOPBACK)) &&
                                 is_local_tcg_endpoint_port(src_addrs[i].sin_port);
            // 1. Upstream (Local QEMU -> Gateway)
            if (from_local_tcg) {
                // [VFIO Intercept] TCG 模式下的本地显卡拦截
                uint16_t msg_type = ntohs(hdr->msg_type);
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
                
                if (g_gateway_known) 
                    sendto(sockfd, pkt, msgs[i].msg_len, 0, (struct sockaddr*)&g_upstream_gateway, sizeof(struct sockaddr_in));
            }
            // 2. Downstream (Gateway -> Local QEMU)
            else {
                if (!g_gateway_init_done) {
                    if (__sync_bool_compare_and_swap(&g_gateway_init_done, 0, 1)) {
                        memcpy(&g_upstream_gateway, &src_addrs[i], sizeof(struct sockaddr_in));
                        g_gateway_known = 1;
                        printf("[Proxy] Gateway Locked: %s:%d\n", inet_ntoa(src_addrs[i].sin_addr), ntohs(src_addrs[i].sin_port));
                    }
                }
                
                uint32_t target_raw = ntohl(hdr->target_id);
                uint16_t msg_type = ntohs(hdr->msg_type);
                int core_idx = (target_raw != WVM_NODE_AUTO_ROUTE)
                    ? (int)(WVM_GET_NODEID(target_raw) - g_base_id)
                    : 0;

                if (core_idx < 0 || core_idx >= g_num_cores) continue;

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
        pthread_t sender_thread_id;
        if (pthread_create(&sender_thread_id, NULL, dirty_sync_sender_thread, NULL) != 0) {
            perror("Failed to create dirty page sender thread");
            executor_publish_startup_state(EXECUTOR_FAILED);
            return 1;
        }
        pthread_detach(sender_thread_id); // 设为分离模式，不需 join
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
            g_shutdown_requested = 1;
        }
        for(long i=0; i<total_threads; i++) pthread_join(threads[i], NULL);
        free(threads);
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
        for (long i = 0; i < proxy_threads; i++) {
            if (pthread_create(&threads[i], NULL, tcg_proxy_thread, NULL) != 0) {
                executor_publish_startup_state(EXECUTOR_FAILED);
                g_shutdown_requested = 1;
                free(threads);
                return 1;
            }
        }
        /* Create the per-vCPU typed sessions before publishing executor
         * readiness, so the bridge cannot accept a TCG handoff without a
         * corresponding helper endpoint. */
        spawn_tcg_processes(g_base_id);
        if (wvm_executor_runtime_wait_ready() != 0) {
            g_shutdown_requested = 1;
            for (long i = 0; i < proxy_threads; i++) {
                pthread_join(threads[i], NULL);
            }
            free(threads);
            return 1;
        }
        while (wait(NULL) > 0);
        g_shutdown_requested = 1;
        for (long i = 0; i < proxy_threads; i++) {
            pthread_join(threads[i], NULL);
        }
        free(threads);
    }
    return 0;
}
