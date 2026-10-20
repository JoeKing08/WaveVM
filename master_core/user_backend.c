/*
 * [IDENTITY] User Backend - The High-Concurrency QoS Bus
 * ---------------------------------------------------------------------------
 * 物理角色：用户态模式下的"消息交换机"。
 * 职责边界：
 * 1. 维护 Fast/Slow 双队列 QoS，保证控制信令 (ACK) 不被数据流淹没。
 * 2. 实现 Slab 风格的包内存池，利用 Thread-aware Hash 消除锁竞争。
 * 3. 驱动收发工作线程，处理聚合解包与 CRC32 卸载计算。
 * 
 * [禁止事项]
 * - 严禁在 rx_thread_loop 中引入慢速系统调用。
 * - 严禁移除 recvmmsg 的批量接收逻辑，否则在高负载下软中断将打死系统。
 * ---------------------------------------------------------------------------
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/sysinfo.h>
#include <stdatomic.h>

#include "unified_driver.h"
#include "../common_include/wavevm_protocol.h"
#include "../common_include/wavevm_ioctl.h"
#include "../common_include/wavevm_membership.h"
#include "../node_runtime/ingress.h"
#include "../node_runtime/runtime_context.h"

extern int wvm_logic_route_snapshot_valid(void);

// --- 配置常量 ---
#define MAX_INFLIGHT_REQS 65536
#define POOL_SHARDS 64
#define SHARD_MASK (POOL_SHARDS - 1)
#define ITEMS_PER_SHARD 1563 
#define POOL_CAP (POOL_SHARDS * ITEMS_PER_SHARD)
#define BATCH_SIZE 64
#define RX_THREAD_COUNT 4
#define LOCAL_SLAVE_REQS 4096

// --- 全局状态 ---
static int g_my_node_id = 0;
extern uint32_t g_my_vm_id;
static const struct wvm_node_runtime_context *g_runtime_context;
static int g_local_port = 0;
static struct sockaddr_in g_gateways[WVM_MAX_GATEWAYS];
static volatile int g_tx_socket = -1;
int g_slave_forward_port = 0;

__attribute__((weak)) int push_to_aggregator(uint32_t slave_id, void *data, int len) {
    if (!data || len <= 0) {
        errno = EINVAL;
        return -EINVAL;
    }

    if (g_tx_socket < 0) {
        errno = EAGAIN;
        return -EAGAIN;
    }

    // [Fix #1] slave_id 可能是 composite ID，解码为裸 node_id 索引 g_gateways[]
    uint32_t raw_id = WVM_GET_NODEID(slave_id);
    if (raw_id >= WVM_MAX_GATEWAYS) {
        errno = EINVAL;
        return -EINVAL;
    }

    // 统一走本地 sidecar 网关，跨节点路由由 sidecar 负责
    struct sockaddr_in *target = &g_gateways[g_my_node_id];  /* always route through local sidecar */
    if (target->sin_port == 0) {
        errno = EHOSTUNREACH;
        return -EHOSTUNREACH;
    }

    { static int __dbg=0; if(__dbg<10 && len>100) { char __ip[16]={0}; inet_ntop(AF_INET,&target->sin_addr,__ip,16); fprintf(stderr,"[PTA-DBG] target=%u raw=%u ip=%s port=%u sock=%d len=%d\n", slave_id, raw_id, __ip, (unsigned)ntohs(target->sin_port), g_tx_socket, len); __dbg++; } }
    { static int __tx=0; if(__tx<10 && len >= (int)sizeof(struct wvm_header)) { struct wvm_header *h=(struct wvm_header*)data; fprintf(stderr,"[TX-HDR] msg=%u len=%u payload=%u target=%u slave=%u req=%llu\n", (unsigned)ntohs(h->msg_type), (unsigned)len, (unsigned)ntohs(h->payload_len), (unsigned)ntohl(h->target_id), (unsigned)ntohl(h->slave_id), (unsigned long long)WVM_NTOHLL(h->req_id)); __tx++; } }
    ssize_t sent = sendto(g_tx_socket, data, len, MSG_DONTWAIT,
                          (struct sockaddr *)target, sizeof(*target));
    { static int __dbg2=0; if(__dbg2<10 && len>100) { fprintf(stderr,"[PTA-DBG] sent=%zd errno=%d\n", sent, (sent<0)?errno:0); __dbg2++; } }
    if (sent == len) {
        return 0;
    }
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return -EAGAIN;
        }
        return -errno;
    }

    errno = EIO;
    return -EIO;
}

// --- 外部引用 ---
extern void *g_shm_ptr; 
extern size_t g_shm_size;
extern uint32_t g_curr_epoch;
extern uint8_t g_my_node_state;
extern void broadcast_irq_to_qemu(void);
extern void wvm_logic_process_packet(struct wvm_header *hdr, void *payload, uint32_t source_node_id);
extern uint32_t wvm_get_directory_node_id(uint64_t gpa);
extern int broadcast_push_to_qemu(uint16_t msg_type, void* payload, int len);
extern void broadcast_raw_packet_to_qemu(const void *packet, size_t len);

// --- 请求ID管理结构 ---
struct u_req_ctx_t {
    void *rx_buffer;
    uint64_t full_id;
    uint32_t max_len; // [FIX-G3] 记录 rx_buffer 的最大可用长度
    volatile int status; // 0=Pending, 1=Done
    pthread_mutex_t lock;
};
static struct u_req_ctx_t g_u_req_ctx[MAX_INFLIGHT_REQS];

struct local_slave_req_t {
    uint64_t req_id;
    uint32_t slave_target;
    int valid;
};
static struct local_slave_req_t g_local_slave_reqs[LOCAL_SLAVE_REQS];
static pthread_mutex_t g_local_slave_req_locks[LOCAL_SLAVE_REQS];

/*
 * TCG slave dirty commits arrive at the local master before they reach the
 * directory.  Keep a small local fence state so a slave-side SYNC PING is
 * acknowledged only after every forwarded commit has received a directory
 * ACK.  This is deliberately scoped to the local slave channel; normal RPC
 * request/response traffic keeps using g_u_req_ctx.
 */
static pthread_mutex_t g_local_commit_fence_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned int g_local_commit_pending;
static int g_local_commit_fence_waiting;
static int g_local_commit_fence_failed;
static uint32_t g_local_commit_fence_target;

static int g_nonblock_recv = 0;
static int g_poll_timeout_ms = 100;   /* [V30 FIX] 默认 100ms，不再是 -1 (无限阻塞) */
static int g_rx_thread_count = 4;
static int g_disable_reuseport = 0;   /* 保留环境变量覆盖能力，但共享 socket 下此项无效 */
static uint64_t g_id_counter = 0;
static int g_shared_rx_sockfd = -1;   /* [V30] 共享 RX socket，thread 0 创建，其余线程共享 */
static _Atomic unsigned int g_typed_ingress_diagnostics[WVM_INGRESS_UNSUPPORTED + 1];

// --- 内存池 (Slab Allocator) ---
typedef struct {
    void *free_list[ITEMS_PER_SHARD];
    int top;
    pthread_spinlock_t lock;
    // 显式 Cache Line Padding：确保每把锁独占缓存行，避免高并发下的 MESI 协议冲突抖动
    uint8_t padding[64 - sizeof(int) - sizeof(pthread_spinlock_t) - sizeof(void*)];
} __attribute__((aligned(64))) pool_shard_t;

static pool_shard_t g_pool_shards[POOL_SHARDS];
static uint8_t *g_pool_buffer = NULL;
static void *g_free_list[POOL_CAP];
static int g_pool_top = -1;

static int u_send_packet(void *data, int len, uint32_t target_id);
static void u_log(const char *fmt, ...);
static pthread_spinlock_t g_pool_lock;

static void report_typed_ingress_result(int status, size_t frame_bytes,
                                        const char *error)
{
    unsigned int occurrence;

    if (status == WVM_INGRESS_ACCEPTED ||
        status == WVM_INGRESS_INCOMPLETE ||
        status < 0 || status > WVM_INGRESS_UNSUPPORTED) {
        return;
    }
    occurrence = atomic_fetch_add_explicit(
        &g_typed_ingress_diagnostics[status], 1, memory_order_relaxed);
    if (occurrence < 8) {
        u_log("[Typed Ingress] status=%d bytes=%zu reason=%s",
              status, frame_bytes, (error && error[0]) ? error : "none");
    }
}

static uint32_t local_slave_req_idx(uint64_t req_id) {
    return (uint32_t)((req_id >> 12) % LOCAL_SLAVE_REQS);
}

static void local_slave_req_track(uint64_t req_id, uint32_t slave_target) {
    if (!WVM_IS_VALID_TARGET(slave_target)) return;

    uint32_t idx = local_slave_req_idx(req_id);
    pthread_mutex_lock(&g_local_slave_req_locks[idx]);
    g_local_slave_reqs[idx].req_id = req_id;
    g_local_slave_reqs[idx].slave_target = slave_target;
    g_local_slave_reqs[idx].valid = 1;
    pthread_mutex_unlock(&g_local_slave_req_locks[idx]);
}

static int local_slave_req_consume(uint64_t req_id, uint32_t slave_target) {
    if (!WVM_IS_VALID_TARGET(slave_target)) return 0;

    int matched = 0;
    uint32_t idx = local_slave_req_idx(req_id);
    pthread_mutex_lock(&g_local_slave_req_locks[idx]);
    if (g_local_slave_reqs[idx].valid &&
        g_local_slave_reqs[idx].req_id == req_id &&
        g_local_slave_reqs[idx].slave_target == slave_target) {
        g_local_slave_reqs[idx].valid = 0;
        matched = 1;
    }
    pthread_mutex_unlock(&g_local_slave_req_locks[idx]);
    return matched;
}

static int send_local_slave_fence_ack(int sockfd, uint32_t slave_target, int ok)
{
    if (g_slave_forward_port <= 0 || sockfd < 0) {
        return -1;
    }

    uint8_t packet[sizeof(struct wvm_header) + 1];
    struct wvm_header *ack = (struct wvm_header *)packet;
    memset(ack, 0, sizeof(*ack));
    ack->magic = htonl(WVM_MAGIC);
    ack->msg_type = htons(MSG_MEM_ACK);
    ack->payload_len = htons(1);
    ack->slave_id = htonl(WVM_ENCODE_ID(g_my_vm_id, (uint32_t)g_my_node_id));
    ack->target_id = htonl(slave_target);
    ack->req_id = WVM_HTONLL(SYNC_MAGIC);
    ack->qos_level = 1;
    ack->flags = ok ? 0 : WVM_FLAG_ERROR;
    ack->epoch = htonl(g_curr_epoch);
    ack->node_state = g_my_node_state;
    packet[sizeof(*ack)] = ok ? 1 : 0;
    ack->crc32 = 0;
    ack->crc32 = htonl(calculate_crc32(packet, sizeof(packet)));

    struct sockaddr_in slave_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(g_slave_forward_port)
    };
    ssize_t sent = sendto(sockfd, packet, sizeof(packet), 0,
                          (struct sockaddr *)&slave_addr,
                          sizeof(slave_addr));
    if (sent != (ssize_t)sizeof(packet)) {
        u_log("[Slave Fence] local ACK failed target=%u ok=%d err=%d",
              (unsigned)slave_target, ok, (sent < 0) ? errno : EIO);
        return -1;
    }
    u_log("[Slave Fence] local ACK target=%u ok=%d pending=0",
          (unsigned)slave_target, ok);
    return 0;
}

static void local_commit_mark_send_failed(void)
{
    pthread_mutex_lock(&g_local_commit_fence_lock);
    if (g_local_commit_pending > 0) {
        g_local_commit_pending--;
    }
    g_local_commit_fence_failed = 1;
    pthread_mutex_unlock(&g_local_commit_fence_lock);
}

static int handle_local_slave_sync_ping(int sockfd, struct wvm_header *hdr)
{
    uint64_t req_id = WVM_NTOHLL(hdr->req_id);
    uint32_t slave_target;
    int send_now = 0;
    int ok = 0;

    if (req_id != SYNC_MAGIC) {
        return 0;
    }

    slave_target = ntohl(hdr->slave_id);
    pthread_mutex_lock(&g_local_commit_fence_lock);
    g_local_commit_fence_target = slave_target;
    if (g_local_commit_pending == 0) {
        ok = !g_local_commit_fence_failed;
        g_local_commit_fence_failed = 0;
        send_now = 1;
    } else {
        g_local_commit_fence_waiting = 1;
    }
    pthread_mutex_unlock(&g_local_commit_fence_lock);

    if (send_now) {
        send_local_slave_fence_ack(sockfd, slave_target, ok);
    }
    return 1;
}

static int consume_local_commit_ack(int sockfd, struct wvm_header *hdr,
                                    void *payload, uint16_t payload_len)
{
    uint64_t req_id = WVM_NTOHLL(hdr->req_id);
    int send_now = 0;
    int ok = 1;
    int fence_ok = 1;
    uint32_t slave_target = 0;

    if (req_id != SYNC_MAGIC) {
        return 0;
    }

    pthread_mutex_lock(&g_local_commit_fence_lock);
    if (g_local_commit_pending == 0) {
        pthread_mutex_unlock(&g_local_commit_fence_lock);
        return 0;
    }

    /*
     * SYNC_MAGIC is carried on the normal MEM_ACK payload path.
     * That payload starts with GPA/version fields, so its first byte is not
     * a success flag.  Only the transport-level error bit is authoritative.
     */
    if (hdr->flags & WVM_FLAG_ERROR) {
        ok = 0;
    }
    if (!ok) {
        g_local_commit_fence_failed = 1;
    }
    g_local_commit_pending--;
    if (g_local_commit_pending == 0 && g_local_commit_fence_waiting) {
        slave_target = g_local_commit_fence_target;
        fence_ok = !g_local_commit_fence_failed;
        g_local_commit_fence_waiting = 0;
        g_local_commit_fence_failed = 0;
        send_now = 1;
    }
    pthread_mutex_unlock(&g_local_commit_fence_lock);

    if (send_now) {
        send_local_slave_fence_ack(sockfd, slave_target, fence_ok);
    }
    return 1;
}

static int maybe_forward_local_slave_commit(uint8_t *packet, int packet_len,
                                            struct wvm_header *hdr,
                                            void *payload, uint16_t payload_len)
{
    uint32_t source_id;
    uint32_t target_id;
    uint32_t dir_node;
    uint64_t gpa;
    int ret;

    if (payload_len < sizeof(struct wvm_diff_log)) {
        return 0;
    }

    source_id = ntohl(hdr->slave_id);
    target_id = ntohl(hdr->target_id);
    if (WVM_GET_NODEID(source_id) != (uint32_t)g_my_node_id ||
        WVM_IS_VALID_TARGET(target_id)) {
        return 0;
    }

    gpa = WVM_NTOHLL(((struct wvm_diff_log *)payload)->gpa);
    dir_node = wvm_get_directory_node_id(gpa);
    if (WVM_GET_NODEID(dir_node) == (uint32_t)g_my_node_id) {
        wvm_logic_process_packet(hdr, payload, source_id);
        return 1;
    }

    /*
     * The slave's packet intentionally uses AUTO_ROUTE because the QEMU
     * process does not own the cluster's DHT view.  Resolve that route at the
     * local master, which does own the authoritative ring.
     */
    hdr->req_id = WVM_HTONLL(SYNC_MAGIC);
    hdr->flags |= WVM_FLAG_NEED_ACK;
    pthread_mutex_lock(&g_local_commit_fence_lock);
    g_local_commit_pending++;
    pthread_mutex_unlock(&g_local_commit_fence_lock);

    ret = u_send_packet(packet, packet_len, dir_node);
    if (ret < 0) {
        local_commit_mark_send_failed();
    }

    {
        static int route_log_count;
        if (route_log_count < 20) {
            u_log("[Slave COMMIT] gpa=%#llx dir=%u ret=%d pending=%u",
                  (unsigned long long)gpa,
                  (unsigned)dir_node,
                  ret,
                  g_local_commit_pending);
            route_log_count++;
        }
    }
    return 1;
}

static int maybe_forward_local_slave_mem_read(uint8_t *packet, int packet_len,
                                              struct wvm_header *hdr,
                                              void *payload, uint16_t payload_len,
                                              uint64_t req_id) {
    if (payload_len < sizeof(uint64_t)) {
        return 0;
    }

    uint64_t gpa = wvm_get_u64_unaligned(payload);
    uint32_t dir_node = wvm_get_directory_node_id(gpa);
    if (WVM_GET_NODEID(dir_node) == (uint32_t)g_my_node_id) {
        return 0;
    }

    uint32_t slave_target = ntohl(hdr->slave_id);
    local_slave_req_track(req_id, slave_target);

    int ret = u_send_packet(packet, packet_len, dir_node);
    {
        static int fwd_log;
        if (__sync_fetch_and_add(&fwd_log, 1) < 40) {
            u_log("[Slave MEM_READ] forward rid=%llu gpa=%#llx owner=%u slave=%u ret=%d",
                  (unsigned long long)req_id,
                  (unsigned long long)gpa,
                  (unsigned)dir_node,
                  (unsigned)slave_target,
                  ret);
        }
    }
    return 1;
}

static int maybe_forward_local_slave_mem_ack(int sockfd, uint8_t *packet, int packet_len,
                                             struct wvm_header *hdr, void *payload,
                                             uint16_t payload_len, uint64_t req_id) {
    if (g_slave_forward_port <= 0 || payload_len < sizeof(struct wvm_mem_ack_payload)) {
        return 0;
    }

    struct wvm_mem_ack_payload *ack_pl = (struct wvm_mem_ack_payload *)payload;
    if (WVM_NTOHLL(ack_pl->gpa) != req_id) {
        return 0;
    }

    uint32_t target = ntohl(hdr->target_id);
    if (!local_slave_req_consume(req_id, target)) {
        return 0;
    }

    struct sockaddr_in slave_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(g_slave_forward_port)
    };
    ssize_t fw = sendto(sockfd, packet, packet_len, 0,
                       (struct sockaddr *)&slave_addr, sizeof(slave_addr));
    if (fw < 0) {
        u_log("[Slave MEM_ACK] forward failed: rid=%llu target=%u dst_port=%d err=%d",
              (unsigned long long)req_id, (unsigned)target,
              g_slave_forward_port, errno);
        return 0;
    }

    u_log("[Slave MEM_ACK] forwarded rid=%llu target=%u dst_port=%d len=%d",
          (unsigned long long)req_id, (unsigned)target,
          g_slave_forward_port, packet_len);
    return 1;
}

static int forward_local_slave_sync_ack(int sockfd, uint8_t *packet, int packet_len,
                                        struct wvm_header *hdr, uint64_t req_id) {
    if (g_slave_forward_port <= 0 || req_id != SYNC_MAGIC) {
        return 0;
    }

    struct sockaddr_in slave_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(g_slave_forward_port)
    };
    ssize_t fw = sendto(sockfd, packet, packet_len, 0,
                       (struct sockaddr *)&slave_addr, sizeof(slave_addr));
    if (fw < 0) {
        u_log("[Slave SyncAck] forward failed target=%u dst_port=%d err=%d",
              (unsigned)ntohl(hdr->target_id), g_slave_forward_port, errno);
        return 0;
    }

    u_log("[Slave SyncAck] forwarded target=%u dst_port=%d len=%d",
          (unsigned)ntohl(hdr->target_id), g_slave_forward_port, packet_len);
    return 1;
}

// --- QoS 发送队列结构 ---
typedef struct tx_node {
    struct tx_node *next;
    uint32_t target_id;
    int len;
    uint8_t data[]; // 柔性数组
} tx_node_t;

typedef struct {
    tx_node_t *head;
    tx_node_t *tail;
    pthread_spinlock_t lock;
    int count;
} tx_queue_t;

static tx_queue_t g_fast_queue;
static tx_queue_t g_slow_queue;
static pthread_cond_t g_tx_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t g_tx_cond_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_tx_thread;

static pthread_mutex_t g_init_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_init_cond = PTHREAD_COND_INITIALIZER;

// --- 辅助函数 ---
static void u_log(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

static int u_is_atomic_context(void) {
    return 0; // 用户态通常不视为原子上下文，除非在信号处理中明确标记
}

static void u_touch_watchdog(void) {
    // 用户态无需喂狗
}

static uint64_t u_get_time_us(void) {
    struct timeval t;
    gettimeofday(&t, NULL);
    return (uint64_t)t.tv_sec * 1000000UL + t.tv_usec;
}

static uint64_t u_time_diff_us(uint64_t start) {
    uint64_t now = u_get_time_us();
    if (now >= start) return now - start;
    // 处理时钟回绕的极端情况
    return 0;
}

static void u_cpu_relax(void) {
    usleep(1);
}

static void u_get_random(uint32_t *val) {
    *val = (uint32_t)rand();
}

static void u_yield_cpu_short_time(void) {
    usleep(100);
}

/* 
 * [物理意图] 预分配大规模分片内存池，彻底消除运行时系统调用延迟。
 * [关键逻辑] 将内存切分为 POOL_SHARDS (64) 个独立分片，利用对齐（Padding）技术规避 CPU 缓存行伪共享。
 * [后果] 若不进行预分配，高频的小包（如 Diff/ACK）会频繁触发内核 brk/mmap 锁竞争，导致 PPS 吞吐量下降一个数量级。
 */
void init_pkt_pool(void) {
    g_pool_buffer = (uint8_t *)calloc(POOL_CAP, POOL_ITEM_SIZE);
    if (!g_pool_buffer) {
        perror("[V29.5 Fatal] Memory Pool Allocation Failure");
        exit(1);
    }

    for (int s = 0; s < POOL_SHARDS; s++) {
        pthread_spin_init(&g_pool_shards[s].lock, PTHREAD_PROCESS_PRIVATE);
        g_pool_shards[s].top = -1;
        for (int i = 0; i < ITEMS_PER_SHARD; i++) {
            // 每一个块都被分配到唯一确定的归属分片，实现真正的分布式管理
            int global_idx = s * ITEMS_PER_SHARD + i;
            g_pool_shards[s].free_list[++g_pool_shards[s].top] = 
                g_pool_buffer + (size_t)global_idx * POOL_ITEM_SIZE;
        }
    }
    printf("[Backend] V29.5 Logic Core Sharded Pool Ready: %d items.\n", POOL_CAP);
}

/* 
 * [物理意图] 高并发下的“零争用”网络包申请。
 * [关键逻辑] 基于 Thread-aware Hash 定位初始分片，并实现“工作窃取（Work-Stealing）”算法：本地分片空闲时尝试从邻居获取。
 * [后果] 这一步是 Mode B 性能的核心。它保证了 128 核服务器在万级并发下，不会因为同一个 malloc 锁产生“串行化自焚”。
 */
static void* u_alloc_packet(size_t size, int atomic) {
    // 超大包降级到 malloc
    if (size > POOL_ITEM_SIZE) {
        if (atomic) return NULL; 
        return malloc(size);
    }

    // 线程感知哈希：利用 pthread_self 的低位进行初始分片选择，极大地分散锁竞争
    unsigned int start_idx = (unsigned int)pthread_self() & SHARD_MASK;

    // 工作窃取（Work-Stealing）：如果本线程对应的分片锁住了或空了，去邻居分片“窃取”
    for (int i = 0; i < POOL_SHARDS; i++) {
        int s_idx = (start_idx + i) & SHARD_MASK;
        pool_shard_t *shard = &g_pool_shards[s_idx];
        void *ptr = NULL;

        if (atomic) {
            // 信号安全路径（Mode B SIGSEGV 调用），严禁阻塞
            if (pthread_spin_trylock(&shard->lock) == 0) {
                if (shard->top >= 0) ptr = shard->free_list[shard->top--];
                pthread_spin_unlock(&shard->lock);
            }
        } else {
            // 标准路径：阻塞等待
            pthread_spin_lock(&shard->lock);
            if (shard->top >= 0) ptr = shard->free_list[shard->top--];
            pthread_spin_unlock(&shard->lock);
        }

        if (ptr) return ptr; // 成功拿到
        
        // 红队优化：原子上下文下，如果试了 4 个分片都拿不到，必须立即返回 NULL，
        // 防止信号处理函数执行时间过长导致 Guest 内核 Panic。
        if (atomic && i > 3) break;
    }
    return NULL;
}

static void u_free_packet(void *ptr) {
    if (!ptr) return;

    size_t pool_total_bytes = (size_t)POOL_CAP * POOL_ITEM_SIZE;
    uintptr_t p_val = (uintptr_t)ptr;
    uintptr_t b_start = (uintptr_t)g_pool_buffer;

    // 逻辑保留：判定内存是否属于池。如果是 malloc 出来的，直接 free
    if (p_val < b_start || p_val >= (b_start + pool_total_bytes)) {
        free(ptr);
        return;
    }

    // 物理反向定位：基于指针地址精确计算它属于哪个分片（Shard）
    // 编译器会自动将常量 POOL_ITEM_SIZE (4200) 优化为乘法+移位，无需担心除法性能
    size_t offset = p_val - b_start;
    int global_idx = (int)(offset / POOL_ITEM_SIZE);
    int shard_idx = global_idx / ITEMS_PER_SHARD;

    // 防御性数学保护
    if (shard_idx >= POOL_SHARDS) shard_idx = SHARD_MASK;
    pool_shard_t *shard = &g_pool_shards[shard_idx];

    // 归还内存。
    // 使用阻塞锁保证内存不发生竞态丢失。
    pthread_spin_lock(&shard->lock);
    if (shard->top < ITEMS_PER_SHARD - 1) {
        shard->free_list[++shard->top] = ptr;
    }
    pthread_spin_unlock(&shard->lock);
}

// --- 驱动接口实现：内存分配 ---
static void* u_alloc_large_table(size_t size) {
    // 使用 mmap 分配大块内存
    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        // 回退到 calloc
        return calloc(1, size);
    }
    return ptr;
}

static void u_free_large_table(void *ptr) {
    // 对于 mmap 的内存，应该用 munmap，但这里未记录 size
    // 鉴于 Directory Table 随进程生命周期存在，这里不执行操作
}

/* 
 * [物理意图] 为分布式事务分配唯一的“身份证（Transaction ID）”。
 * [关键逻辑] 实现基于 Generation（代数）的防止 ABA 机制。即便 ID 发生回绕，过时的包也不会误触发新的请求回调。
 * [后果] 如果没有 ID 追踪，网络乱序回包可能导致 CPU 读到错误的内存快照，产生静默数据破坏（Silent Data Corruption）。
 */
static uint64_t u_alloc_req_id(void *rx_buffer, uint32_t buffer_size) {
    uint64_t id;
    int idx;
    int attempts = 0;

    // 尝试多次获取 ID，避免在高并发下死锁
    while (attempts < MAX_INFLIGHT_REQS * 2) {
        id = __sync_fetch_and_add(&g_id_counter, 1);
        if (id == 0) id = __sync_fetch_and_add(&g_id_counter, 1);

        idx = id % MAX_INFLIGHT_REQS;

        if (pthread_mutex_trylock(&g_u_req_ctx[idx].lock) == 0) {
            if (g_u_req_ctx[idx].rx_buffer == NULL) {
                g_u_req_ctx[idx].rx_buffer = rx_buffer;
                g_u_req_ctx[idx].full_id = id;
                g_u_req_ctx[idx].max_len = buffer_size; // [FIX-G3]
                g_u_req_ctx[idx].status = 0;
                pthread_mutex_unlock(&g_u_req_ctx[idx].lock);
                return id;
            }
            pthread_mutex_unlock(&g_u_req_ctx[idx].lock);
        }
        attempts++;
        if (attempts % 100 == 0) u_yield_cpu_short_time();
    }
    u_log("[CRITICAL] User backend: No free request IDs available!");
    return (uint64_t)-1;
}

static void u_free_req_id(uint64_t id) {
    int idx = id % MAX_INFLIGHT_REQS;
    pthread_mutex_lock(&g_u_req_ctx[idx].lock);
    if (g_u_req_ctx[idx].full_id == id) {
        g_u_req_ctx[idx].rx_buffer = NULL;
        g_u_req_ctx[idx].status = 0;
        // full_id 不清零，保留用于过时包的校验
    }
    pthread_mutex_unlock(&g_u_req_ctx[idx].lock);
}

static int u_check_req_status(uint64_t id) {
    int s = -1;
    uint32_t idx = id % MAX_INFLIGHT_REQS;
    pthread_mutex_lock(&g_u_req_ctx[idx].lock);
    if (g_u_req_ctx[idx].full_id == id) {
        s = g_u_req_ctx[idx].status;
    }
    pthread_mutex_unlock(&g_u_req_ctx[idx].lock);
    return s;
}

static void u_send_packet_async(uint16_t msg_type, void* payload, int len, uint32_t target_id, uint8_t qos) {
    size_t pkt_len = sizeof(struct wvm_header) + len;
    uint8_t *buffer = u_alloc_packet(pkt_len, 1);
    if (!buffer) return;

    struct wvm_header *hdr = (struct wvm_header *)buffer;
    extern int g_my_node_id;
    memset(hdr, 0, sizeof(*hdr));
    hdr->magic = htonl(WVM_MAGIC);
    hdr->msg_type = htons(msg_type);
    hdr->payload_len = htons(len);
    hdr->slave_id = htonl(WVM_ENCODE_ID(g_my_vm_id, g_my_node_id));
    hdr->target_id = htonl(target_id);
    hdr->req_id = 0;
    hdr->qos_level = qos;
    hdr->crc32 = 0;

    if (payload && len > 0) memcpy(buffer + sizeof(*hdr), payload, len);
    
    hdr->crc32 = htonl(calculate_crc32(buffer, pkt_len));

    u_send_packet(buffer, pkt_len, target_id);
    u_free_packet(buffer);
}

// --- 队列操作 ---
static void queue_init(tx_queue_t *q) {
    q->head = q->tail = NULL;
    q->count = 0;
    pthread_spin_init(&q->lock, 0);
}

static tx_node_t* queue_pop(tx_queue_t *q) {
    tx_node_t *node = NULL;
    pthread_spin_lock(&q->lock); 
    if (q->head) {
        node = q->head;
        q->head = node->next;
        if (!q->head) {
            q->tail = NULL;
        }
        q->count--;
    }
    pthread_spin_unlock(&q->lock);
    return node;
}

/* 
 * [物理意图] 实现应用层到物理网卡的“流量整形”与“反向压力”。
 * [关键逻辑] 拦截 Gateway 的返回值：若网关缓冲区溢出，此处执行自适应指数退避，而非暴力丢包。
 * [后果] 这是 P2P 网络在公网环境下的生命线。它防止了节点在网络拥塞时疯狂重传，从而实现“优雅减速”而非“系统坍缩”。
 */
static int raw_send(tx_node_t *node) {
    // [Fix #1] g_gateways 按裸 node_id 索引，g_my_node_id 已经是裸 ID，无需解码
    struct sockaddr_in *target = &g_gateways[g_my_node_id];
    if (target->sin_port == 0 || g_tx_socket < 0) return -1;
    
    // [自治增强]：在发送前强制注入当前的本地 Epoch 和状态
    struct wvm_header *hdr = (struct wvm_header *)node->data;
    // 使用本文件中的轻量状态镜像，避免跨对象链接耦合。

    hdr->epoch = htonl(g_curr_epoch);
    hdr->node_state = g_my_node_state;
    hdr->target_id = htonl(node->target_id);
    
    // 重新计算 CRC（因为 Header 变了）
    hdr->crc32 = 0;
    hdr->crc32 = htonl(calculate_crc32(node->data, node->len));
    
    // 感知 Gateway 的反压返回值
    
    int retries = 0;
    while (1) {
        // 调用网关服务
        int res = push_to_aggregator(node->target_id, node->data, node->len);
        
        if (res == 0) return 0; // 成功进入网关缓冲区
        
        if (res == -EBUSY || res == -EAGAIN) {
            // 网关缓冲区满了，必须指数退避重试，绝不能直接丢弃
            retries++;
            if (retries < 100) {
                usleep(10 * retries); 
                continue;
            } else {
                u_log("[Gateway] Severe Congestion for Slave %d, dropping packet", node->target_id);
                return -1;
            }
        }
        return res;
    }
}

/* 
 * [物理意图] 模拟处理器的“严格优先级调度器”，保证控制信号不被数据洪流淹没。
 * [关键逻辑] 维护“快/慢”双车道：Fast Queue（信令/ACK/Diff）拥有绝对抢占权，Slow Queue（全页/VCPU）按配额运行。
 * [后果] 解决了典型的“队首阻塞”问题。若无此分级，一个大块内存同步包会堵死全网的 ACK 确认，导致集群瞬间雪崩（Cascading Failure）。
 */
static void* tx_worker_thread(void *arg) {
    while (1) {
        tx_node_t *node;
        
        // 1. 优先清空 Fast Queue
        while ((node = queue_pop(&g_fast_queue)) != NULL) {
            struct wvm_header* hdr = (struct wvm_header*)node->data;
            // 计算 CRC32
            hdr->crc32 = 0;
            hdr->crc32 = htonl(calculate_crc32(node->data, node->len));
            
            raw_send(node);
            u_free_packet(node);
        }

        // 2. 按配额处理 Slow Queue
        int quota = 16;
        while (quota > 0 && (node = queue_pop(&g_slow_queue)) != NULL) {
            struct wvm_header* hdr = (struct wvm_header*)node->data;
            // 计算 CRC32
            hdr->crc32 = 0;
            hdr->crc32 = htonl(calculate_crc32(node->data, node->len));
            
            raw_send(node);
            u_free_packet(node);
            quota--;
            
            // 抢占：如果有快包进入，立即中断慢包处理
            if (g_fast_queue.count > 0) break;
        }

        // 3. 无任务时休眠
        pthread_mutex_lock(&g_tx_cond_lock);
        if (g_fast_queue.count == 0 && g_slow_queue.count == 0) {
            pthread_cond_wait(&g_tx_cond, &g_tx_cond_lock);
        }
        pthread_mutex_unlock(&g_tx_cond_lock);
    }
    return NULL;
}

// --- 驱动接口实现：发送 ---
static int u_send_packet(void *data, int len, uint32_t target_id) {
    if (g_tx_socket < 0) return -1;
    if (g_runtime_context &&
        g_runtime_context->dispatch->route_topology_kind !=
            WVM_ROUTE_TOPOLOGY_FLAT) {
        /*
         * Fractal admitted traffic must enter through the typed node-runtime
         * services.  Sending the old header to the local sidecar would lose
         * its scope and turn a valid route into an accidental raw-vnode hop.
         */
        fprintf(stderr,
                "[Route] refusing legacy packet in typed runtime target=%u\n",
                target_id);
        return -EPROTONOSUPPORT;
    }
    if (g_runtime_context &&
        g_my_vm_id != 0 &&
        (!wvm_logic_route_snapshot_valid() ||
         (WVM_IS_VALID_TARGET(target_id) &&
          WVM_GET_VMID(target_id) != g_my_vm_id))) {
        fprintf(stderr,
                "[Route] refusing packet without matching admitted snapshot "
                "target=%u vm=%u\n",
                target_id, (unsigned)g_my_vm_id);
        return -EPROTO;
    }
    struct wvm_header *hdr = (struct wvm_header *)data;
    tx_queue_t *q;
    int is_atomic = 0;

    // 根据 QoS 级别选择队列
    if (hdr->qos_level == 1) {
        q = &g_fast_queue;
    } else {
        q = &g_slow_queue;
    }
    
    // 分配队列节点
    tx_node_t *node = (tx_node_t *)u_alloc_packet(sizeof(tx_node_t) + len, is_atomic);
    if (!node) return -1;

    node->next = NULL;
    node->target_id = target_id;
    node->len = len;
    memcpy(node->data, data, len);

    // 入队操作
    // 因为 is_atomic=0，这里会执行 pthread_spin_lock (死等直到获取锁)
    // 这保证了高优先级包绝对不会因为锁竞争而丢弃
    pthread_spin_lock(&q->lock);
    if (q->tail) { 
        q->tail->next = node; 
        q->tail = node; 
    } else { 
        q->head = q->tail = node; 
    }
    q->count++;
    pthread_spin_unlock(&q->lock);

    // 唤醒 TX 线程
    pthread_mutex_lock(&g_tx_cond_lock);
    pthread_cond_signal(&g_tx_cond);
    pthread_mutex_unlock(&g_tx_cond_lock);
    return 0;
}

// [FIX] 引用全局设备描述符 (在 main_wrapper.c 中打开 /dev/wavevm)
extern int g_dev_fd; 

/* 
 * [物理意图] 建立用户态感知与内核态加速（Mode A）之间的“配置虫洞”。
 * [关键逻辑] 更新本地路由表的同时，通过 IOCTL 垂直穿透到内核模块，确保 Kernel 直接通信不经过慢速 User-Space。
 * [后果] 实现了真正的“配置一致性”。若穿透失败，内核将向错误的旧 IP 发送数据，导致分布式计算出现逻辑黑洞。
 */
static void u_set_gateway_ip(uint32_t gw_id, uint32_t ip, uint16_t port) {
    // [Fix #1] 入参可能是 composite ID，先解码为裸 node_id 再索引静态数组
    // 这样 vm_id>0 时不会越界 (composite ID = (vm<<24)|node, 可能 > WVM_MAX_GATEWAYS)
    uint32_t raw_node_id = WVM_GET_NODEID(gw_id);

    // 1. 更新用户态表 (供 Daemon 自身通信使用，如 Gossip)
    if (raw_node_id < WVM_MAX_GATEWAYS) {
        g_gateways[raw_node_id].sin_family = AF_INET;
        g_gateways[raw_node_id].sin_addr.s_addr = ip;
        g_gateways[raw_node_id].sin_port = port;
        if (raw_node_id < 4) {
            char ipbuf[16] = {0};
            inet_ntop(AF_INET, &g_gateways[raw_node_id].sin_addr, ipbuf, sizeof(ipbuf));
            fprintf(stderr, "[GW-SET] id=%u ip=%s port=%u\n",
                    raw_node_id, ipbuf, (unsigned)ntohs(g_gateways[raw_node_id].sin_port));
        }
    }

    // 2. [Fix #4] Mode A 内核路径对齐：传给内核的 gw_id 也用裸 node_id
    // 内核模块 wavevm.ko 的路由表按裸 node_id 索引，不理解 composite 编码
    if (g_dev_fd > 0) {
        struct wvm_ioctl_gateway args;
        args.gw_id = raw_node_id;  // [Fix #4] 解码后下发内核
        args.ip = ip;     // 此时已经是网络序
        args.port = port; // 此时已经是网络序

        if (ioctl(g_dev_fd, IOCTL_SET_GATEWAY, &args) < 0) {
            perror("[Daemon] Failed to sync dynamic route to kernel");
        }
    }
}

// Deprecated in V29 logic core, but stub provided
static void u_fetch_page(uint64_t gpa, void *buf) {
    memset(buf, 0, 4096);
}

static void u_invalidate_local(uint64_t gpa) {
    // No-op for user backend, logic core handles this
}

extern uint64_t wvm_logic_get_page_version(uint64_t gpa);

/* 
 * [物理意图] 充当本地物理内存的“分布式 DMA 控制器”。
 * [关键逻辑] 响应远程读请求，从共享内存（SHM）中提取数据，并强制附加 Logic Core 维护的最新的版本号（Version）。
 * [后果] 提供了真理的来源。这是 Wavelet 协议中“拉取（Pull）”链路的终点，保证了 Directory 数据的对外可见性。
 */
static void handle_slave_read(int fd, struct sockaddr_in *dest, struct wvm_header *req) {
    if (!g_shm_ptr) return;

    // 1. 从请求中解析 GPA
    uint64_t gpa = WVM_NTOHLL(*(uint64_t*)(req + 1));
    if (gpa + 4096 > g_shm_size) return;

    // 2. 准备完整的响应包缓冲区 (Header + Payload结构体)
    // 大小 = 24 (Header) + 16 (GPA/Ver) + 4096 (Data) = 4136 字节
    uint8_t tx_buffer[sizeof(struct wvm_header) + sizeof(struct wvm_mem_ack_payload)];
    memset(tx_buffer, 0, sizeof(tx_buffer));

    struct wvm_header *ack_hdr = (struct wvm_header *)tx_buffer;
    struct wvm_mem_ack_payload *ack_pl = (struct wvm_mem_ack_payload *)(tx_buffer + sizeof(struct wvm_header));

    // 3. 填充 Payload (关键！)
    ack_pl->gpa = WVM_HTONLL(gpa);
    // 从 Logic Core 获取当前权威版本号，这对于 V29 的订阅机制至关重要
    ack_pl->version = WVM_HTONLL(wvm_logic_get_page_version(gpa));
    // 拷贝真正的内存数据
    memcpy(ack_pl->data, (uint8_t*)g_shm_ptr + gpa, 4096);

    // 4. 填充 Header
    ack_hdr->magic = htonl(WVM_MAGIC);
    ack_hdr->msg_type = htons(MSG_MEM_ACK);
    // 注意：payload_len 现在是 4112 字节 (16 + 4096)，而不是 4096！
    ack_hdr->payload_len = htons(sizeof(struct wvm_mem_ack_payload));
    ack_hdr->req_id = req->req_id;
    ack_hdr->slave_id = htonl(WVM_ENCODE_ID(g_my_vm_id, g_my_node_id));
    ack_hdr->target_id = req->slave_id;
    ack_hdr->qos_level = 0; // 慢车道包
    ack_hdr->crc32 = 0;

    // 5. 计算全包 CRC32
    uint32_t c = calculate_crc32(tx_buffer, sizeof(tx_buffer));
    ack_hdr->crc32 = htonl(c);

    // 6. 发送
    sendto(fd, tx_buffer, sizeof(tx_buffer), 0, (struct sockaddr*)dest, sizeof(*dest));
}

// 引用 Logic Core
extern void wvm_logic_update_local_version(uint64_t gpa);
extern void wvm_logic_broadcast_rpc(void *payload_data, int payload_len, uint16_t msg_type);

/* 
 * [物理意图] 执行“语义透传”指令，实现内存状态的“瞬时坍缩”。
 * [关键逻辑] 利用 mprotect(PROT_WRITE) 构建写锁栅栏，在物理 memset 期间暂时禁用读取，确保全网一致性视图。
 * [后果] 这是 WaveVM 突破物理带宽限制的神作。它让 GB 级的内存清零操作在 10µs 内在全网节点同步完成，效率提升万倍。
 */
static void handle_rpc_batch_execution(void *payload, uint32_t payload_len) {
    if (payload_len < sizeof(struct wvm_rpc_batch_memset)) return;

    struct wvm_rpc_batch_memset *batch = (struct wvm_rpc_batch_memset *)payload;
    uint32_t count = ntohl(batch->count);
    uint32_t val = ntohl(batch->val);
    
    // 边界检查：防止 count 过大导致越界读取
    size_t required_len = sizeof(struct wvm_rpc_batch_memset) + count * sizeof(struct wvm_rpc_region);
    if (payload_len < required_len) return;

    struct wvm_rpc_region *regions = (struct wvm_rpc_region *)(batch + 1);
    
    for (uint32_t i = 0; i < count; i++) {
        uint64_t gpa = WVM_NTOHLL(regions[i].gpa);
        uint64_t r_len = WVM_NTOHLL(regions[i].len);
        
        if (gpa + r_len > g_shm_size) continue;
        
        void *host_addr = (uint8_t*)g_shm_ptr + gpa;

        // [PATCH] 原子性增强步骤
        
        // 1. 上“写锁”：将页面权限设为 PROT_WRITE (不可读) 或 PROT_NONE
        // 任何试图在此期间读取该内存的 vCPU 都会触发 Segfault 并被挂起
        // 注意：我们自己也无法读取，但 memset 是只写操作，所以 PROT_WRITE 是安全的
        mprotect(host_addr, r_len, PROT_WRITE);
        
        // 2. 内存屏障
        __sync_synchronize();

        // 3. 执行物理操作 (现在是安全的，因为没人能读)
        memset(host_addr, val, r_len);

        // [FIX] Memory Barrier
        __sync_synchronize(); // Full barrier
        
        // 4. 恢复权限 (恢复为 PROT_READ|PROT_WRITE)
        mprotect(host_addr, r_len, PROT_READ | PROT_WRITE);
        
        // 5. 更新版本号
        for (uint64_t offset = 0; offset < r_len; offset += 4096) {
            wvm_logic_update_local_version(gpa + offset);
        }
    }
    
    broadcast_push_to_qemu(MSG_RPC_BATCH_MEMSET, payload, payload_len);
    
    u_log("[Prophet] Local execution done, sync notification sent to QEMU.");
}

// [IPC Source] 处理来自本地 QEMU 的请求
static void handle_ipc_rpc_passthrough(int qemu_fd, void *data, uint32_t len) {
    if (len < sizeof(struct wvm_header)) return;
    struct wvm_header *hdr = (struct wvm_header *)data;
    uint16_t msg_type = ntohs(hdr->msg_type);
    void *payload = (void*)hdr + sizeof(struct wvm_header);
    uint32_t payload_len = len - sizeof(struct wvm_header);

    if (msg_type == MSG_RPC_BATCH_MEMSET) {
        // 1. 本地执行
        handle_rpc_batch_execution(payload, payload_len);
        
        // 2. [Broadcast] 全网广播 (Source ID = Me)
        hdr->slave_id = htonl(WVM_ENCODE_ID(g_my_vm_id, g_my_node_id));
        wvm_logic_broadcast_rpc(data, len, msg_type);
    }
    
    // 3. [ACK] 解除 QEMU 阻塞
    uint8_t ack = 1;
    write(qemu_fd, &ack, 1);
}

/* 
 * [物理意图] 整个计算节点的“物理入站总线”，负责数据的物理安全与分发。
 * [关键逻辑] 1. recvmmsg 批量聚合：降低中断频率；2. CRC32 强校验：拦截比特翻转；3. Epoch 过滤：隔离旧时代流量。
 * [后果] 这是全网最危险的性能红线。任何在此处的 CPU 浪费（如 malloc）都会导致 PPS 严重掉队，诱发全网重传风暴。
 */
static void* rx_thread_loop(void *arg) {
    long thread_idx = (long)arg;
    int sockfd;

    /* [V30 共享 Socket 架构]
     * Thread 0 创建并 bind socket，其余线程等待后共享同一个 fd。
     * 多线程对同一个 UDP socket 调 recvmmsg 在 Linux 下是安全的：
     * 内核 sk_lock 保证每个 datagram 只被一个线程收到。
     * 这消除了 SO_REUSEPORT 导致的响应路由错乱问题。 */
    if (thread_idx == 0) {
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            perror("RX socket create failed");
            return NULL;
        }

        int flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

        int opt = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        /* 不再使用 SO_REUSEPORT：单 socket 共享模型不需要它 */

        int rcvbuf = 4 * 1024 * 1024; /* 4MB 接收缓冲区，减少高并发丢包 */
        setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

        struct sockaddr_in bind_addr = {
            .sin_family=AF_INET,
            .sin_port=htons(g_local_port),
            .sin_addr.s_addr=INADDR_ANY
        };

        if (bind(sockfd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
            perror("User backend RX bind failed");
            close(sockfd);
            return NULL;
        }
        fprintf(stderr, "[V30-RX] Thread 0: bound port=%u, shared socket fd=%d\n",
                (unsigned)g_local_port, sockfd);

        /* 发布共享 socket 给其他线程和 TX 路径 */
        pthread_mutex_lock(&g_init_lock);
        g_shared_rx_sockfd = sockfd;
        g_tx_socket = sockfd;
        pthread_cond_broadcast(&g_init_cond);
        pthread_mutex_unlock(&g_init_lock);
    } else {
        /* 非 thread-0：等待 thread 0 完成 socket 创建 */
        pthread_mutex_lock(&g_init_lock);
        while (g_shared_rx_sockfd < 0) {
            pthread_cond_wait(&g_init_cond, &g_init_lock);
        }
        sockfd = g_shared_rx_sockfd;
        pthread_mutex_unlock(&g_init_lock);
        fprintf(stderr, "[V30-RX] Thread %ld: sharing socket fd=%d\n", thread_idx, sockfd);
    }

    // recvmmsg 缓冲区
    struct mmsghdr msgs[BATCH_SIZE] = {0};
    struct iovec iovecs[BATCH_SIZE] = {0};
    struct sockaddr_in src_addrs[BATCH_SIZE] = {0};
    uint8_t *buffer_pool = malloc(BATCH_SIZE * WVM_MAX_PACKET_SIZE);

    if (!buffer_pool) {
        perror("RX buffer pool malloc failed");
        return NULL;
    }

    for (int i = 0; i < BATCH_SIZE; i++) {
        iovecs[i].iov_base = buffer_pool + (i * WVM_MAX_PACKET_SIZE);
        iovecs[i].iov_len = WVM_MAX_PACKET_SIZE;
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &src_addrs[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
    }

    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLIN;

    while (1) {
        if (poll(&pfd, 1, g_poll_timeout_ms) <= 0) continue;

        for (int i = 0; i < BATCH_SIZE; i++) {
            msgs[i].msg_hdr.msg_namelen = sizeof(src_addrs[i]);
            msgs[i].msg_hdr.msg_flags = 0;
            msgs[i].msg_len = 0;
        }
        int n = recvmmsg(sockfd, msgs, BATCH_SIZE, MSG_DONTWAIT, NULL);
        if (n <= 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) continue; usleep(100); continue; }

        for (int i = 0; i < n; i++) {        
            uint8_t *base_ptr = (uint8_t *)iovecs[i].iov_base; // 基准地址
            int total_len = msgs[i].msg_len;                   // UDP包总长
            int offset = 0;                                    // 当前游标
            uint32_t src_ip = src_addrs[i].sin_addr.s_addr;    // 源IP

            /*
             * V1 frames are whole UDP datagrams, not legacy aggregate
             * members. They must be consumed before legacy header parsing so
             * a malformed/new V1 frame can never be reinterpreted as a
             * wvm_header. The coordinator role is linked only into the
             * unified node runtime, so every V1 frame has one mandatory
             * ingress path.
             */
            if (total_len >= 4 && base_ptr[0] == 'W' &&
                base_ptr[1] == 'V' && base_ptr[2] == 'M' &&
                base_ptr[3] == '1') {
                char ingress_error[128] = {0};
                int ingress_status = wvm_ingress_handle_datagram_ex(
                    base_ptr, (size_t)total_len, ingress_error,
                    sizeof(ingress_error));
                report_typed_ingress_result(ingress_status,
                                            (size_t)total_len, ingress_error);
                continue;
            }

            // 循环解包：只要剩余数据够一个Header，就继续解析
            while (offset + sizeof(struct wvm_header) <= total_len) {
            
                // 计算当前包头的实际位置
                struct wvm_header *hdr = (struct wvm_header *)(base_ptr + offset);
            
                // 1. 魔数校验 (快速失败，防止处理垃圾数据)
                if (ntohl(hdr->magic) != WVM_MAGIC) {
                    break; // 如果魔数不对，说明后续数据无法对齐，直接丢弃该 UDP 包剩余部分
                }

                // 计算当前这个 WVM 子包的长度
                uint16_t p_len = ntohs(hdr->payload_len);
                int current_pkt_len = sizeof(struct wvm_header) + p_len;

                // 2. 长度越界校验
                if (offset + current_pkt_len > total_len) {
                    break; // 包被截断，丢弃
                }

                // 3. CRC32 校验
                uint32_t received_crc = ntohl(hdr->crc32);
                hdr->crc32 = 0; // 计算前清零
                uint32_t calculated_crc = calculate_crc32((uint8_t*)hdr, current_pkt_len);
            
                uint64_t rid = WVM_NTOHLL(hdr->req_id); // 定义 rid
                uint16_t msg_type = ntohs(hdr->msg_type); // 定义 msg_type

                if (received_crc == calculated_crc) {
                    uint32_t msg_epoch = ntohl(hdr->epoch);
                    if (msg_type == MSG_VCPU_RUN) {
                        static int __rx_vcpu_run = 0;
                        if (__rx_vcpu_run < 20) {
                            u_log("[RX VCPU_RUN] src_port=%u target=%u slave=%u req=%llu p_len=%u",
                                  (unsigned)ntohs(src_addrs[i].sin_port),
                                  (unsigned)ntohl(hdr->target_id),
                                  (unsigned)ntohl(hdr->slave_id),
                                  (unsigned long long)rid,
                                  (unsigned)p_len);
                            __rx_vcpu_run++;
                        }
                    }
                    if (msg_type == MSG_HEARTBEAT) {
                        uint64_t hb_rid = WVM_NTOHLL(hdr->req_id);
                        u_log("[HB RX] src_port=%u src_id=%u target_id=%u epoch=%u local=%u",
                              (unsigned)ntohs(src_addrs[i].sin_port),
                              (unsigned)ntohl(hdr->slave_id),
                              (unsigned)ntohl(hdr->target_id),
                              (unsigned)msg_epoch,
                              (unsigned)g_curr_epoch);
                        u_log("[HB RX] rid=%llu", (unsigned long long)hb_rid);
                    }

                    // [自治策略]：丢弃来自未来的非法包，或处理落后包
                    if (msg_epoch > g_curr_epoch + 5) {
                        if (msg_type == MSG_VCPU_RUN || msg_type == MSG_HEARTBEAT) {
                            u_log("[RX Drop Epoch] msg=%u src_port=%u epoch=%u local=%u",
                                  (unsigned)msg_type, (unsigned)ntohs(src_addrs[i].sin_port),
                                  msg_epoch, g_curr_epoch);
                        }
                        // 跨度过大，可能是由于网络分区（Split-brain）后节点归队
                        // 这种情况下不能处理该包，应等待视图同步
                        offset += current_pkt_len;
                        continue;
                    }
                    // 校验通过，恢复 CRC
                    hdr->crc32 = htonl(received_crc);
                    void *payload = (void*)hdr + sizeof(struct wvm_header);

                    // [Multi-VM] vm_id 过滤：丢弃不属于本 VM 的包
                    {
                        uint32_t target_raw = ntohl(hdr->target_id);
                        if (target_raw != WVM_NODE_AUTO_ROUTE &&
                            WVM_GET_VMID(target_raw) != g_my_vm_id) {
                            offset += current_pkt_len;
                            continue;
                        }
                    }

                    // [路由优先] Slave 业务包必须先分流，不能被 req_id 分支误判为 ACK。
                    // 仅当包不是来自本地 slave 端口时，才转发到 slave 进程处理。
                    int is_slave_service_msg =
                        (msg_type == MSG_VCPU_RUN ||
                         msg_type == MSG_BLOCK_WRITE ||
                         msg_type == MSG_BLOCK_READ ||
                         msg_type == MSG_BLOCK_FLUSH ||
                         /*
                          * R02: the typed block envelope must reach the local
                          * executor exactly like the legacy block messages.
                          * Without this the remote request never enters the
                          * slave dispatch and the initiator only sees a
                          * timeout.
                          */
                         msg_type == MSG_BLOCK_TYPED);
                    int from_local_slave = (ntohs(src_addrs[i].sin_port) == (uint16_t)g_slave_forward_port);

                    if (msg_type == MSG_VCPU_EXIT) {
                        static int __rx_exit = 0;
                        if (__rx_exit < 10) {
                            u_log("[RX VCPU_EXIT] src_port=%u from_local=%d target=%u slave=%u req=%llu",
                                  (unsigned)ntohs(src_addrs[i].sin_port), from_local_slave,
                                  (unsigned)ntohl(hdr->target_id),
                                  (unsigned)ntohl(hdr->slave_id),
                                  (unsigned long long)rid);
                            __rx_exit++;
                        }
                    }

                    if (from_local_slave && msg_type == MSG_COMMIT_DIFF) {
                        if (maybe_forward_local_slave_commit(base_ptr + offset,
                                                              current_pkt_len,
                                                              hdr, payload, p_len)) {
                            offset += current_pkt_len;
                            continue;
                        }
                    }

                    if (from_local_slave && msg_type == MSG_PING &&
                        handle_local_slave_sync_ping(sockfd, hdr)) {
                        offset += current_pkt_len;
                        continue;
                    }

                    if (from_local_slave && msg_type == MSG_MEM_READ && p_len >= sizeof(uint64_t)) {
                        if (maybe_forward_local_slave_mem_read(base_ptr + offset,
                                                               current_pkt_len,
                                                               hdr, payload, p_len,
                                                               rid)) {
                            offset += current_pkt_len;
                            continue;
                        }
                        local_slave_req_track(rid, ntohl(hdr->slave_id));
                    }

                    // 本地 Slave 的执行结果需要回传给真正发起方（跨节点请求场景）。
                    // 新协议下回包目标在 hdr->target_id；旧包可回退到 hdr->slave_id。
                    if (from_local_slave &&
                        (msg_type == MSG_VCPU_EXIT || msg_type == MSG_BLOCK_ACK)) {
                        uint32_t return_target = ntohl(hdr->target_id);
                        uint32_t my_composite_id = WVM_ENCODE_ID(g_my_vm_id, g_my_node_id);
                        // 新协议优先用 target_id；仅当 target_id 无效/自动路由时回退到旧字段。
                        if (!WVM_IS_VALID_TARGET(return_target) ||
                            return_target == WVM_NODE_AUTO_ROUTE) {
                            uint32_t legacy_target = ntohl(hdr->slave_id);
                            if (WVM_IS_VALID_TARGET(legacy_target)) {
                                return_target = legacy_target;
                            }
                        }
                        u_log("[Slave Return] msg=%u src_port=%u rid=%llu return_target=%u",
                              (unsigned)msg_type, (unsigned)ntohs(src_addrs[i].sin_port),
                              (unsigned long long)rid, (unsigned)return_target);
                        if (WVM_IS_VALID_TARGET(return_target) && return_target != my_composite_id) {
                            int rr = u_send_packet(base_ptr + offset, current_pkt_len, return_target);
                            u_log("[Slave Return] forward queued msg=%u rid=%llu target=%u ret=%d len=%d",
                                  (unsigned)msg_type, (unsigned long long)rid,
                                  (unsigned)return_target, rr, current_pkt_len);
                            offset += current_pkt_len;
                            continue;
                        }
                    }

                    if (is_slave_service_msg && !from_local_slave) {
                        struct sockaddr_in slave_addr = {
                            .sin_family = AF_INET,
                            .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
                            .sin_port = htons(g_slave_forward_port)
                        };
                        ssize_t fw = sendto(sockfd, base_ptr + offset, current_pkt_len, 0,
                                           (struct sockaddr*)&slave_addr, sizeof(slave_addr));
                        if (fw < 0) {
                            u_log("[Slave Forward] sendto failed: msg=%u src_port=%u dst_port=%d err=%d",
                                  (unsigned)msg_type, (unsigned)ntohs(src_addrs[i].sin_port),
                                  g_slave_forward_port, errno);
                        } else if (msg_type == MSG_VCPU_RUN) {
                            u_log("[Slave Forward] msg=%u src_port=%u dst_port=%d len=%d",
                                  (unsigned)msg_type, (unsigned)ntohs(src_addrs[i].sin_port),
                                  g_slave_forward_port, current_pkt_len);
                        }
                        offset += current_pkt_len;
                        continue;
                    }

                    // 分发逻辑
                    bool is_response_msg =
                        (msg_type == MSG_MEM_ACK ||
                         msg_type == MSG_VCPU_EXIT ||
                         msg_type == MSG_BLOCK_ACK);

                    if (is_response_msg && rid != (uint64_t)-1 &&
                        (rid != 0 || msg_type == MSG_MEM_ACK)) {
                        if (msg_type == MSG_MEM_ACK && rid == SYNC_MAGIC &&
                            !from_local_slave &&
                            consume_local_commit_ack(sockfd, hdr, payload, p_len)) {
                            offset += current_pkt_len;
                            continue;
                        }

                        // 请求-响应模式 (ACK / EXIT / BLOCK_ACK)
                        uint32_t idx = rid % MAX_INFLIGHT_REQS;
                        bool matched_req_ctx = false;
                        if (msg_type == MSG_VCPU_EXIT) {
                            u_log("[RX VCPU_EXIT] src_port=%u rid=%llu idx=%u p_len=%u",
                                  (unsigned)ntohs(src_addrs[i].sin_port),
                                  (unsigned long long)rid,
                                  (unsigned)idx,
                                  (unsigned)p_len);
                        }
                        pthread_mutex_lock(&g_u_req_ctx[idx].lock);
                        if (msg_type == MSG_VCPU_EXIT) {
                            u_log("[RX VCPU_EXIT] slot idx=%u full_id=%llu has_buf=%d",
                                  (unsigned)idx,
                                  (unsigned long long)g_u_req_ctx[idx].full_id,
                                  g_u_req_ctx[idx].rx_buffer ? 1 : 0);
                        }
                        if (g_u_req_ctx[idx].rx_buffer &&
                            g_u_req_ctx[idx].full_id == rid &&
                            g_u_req_ctx[idx].status == 0) {

                            /*
                             * VCPU_EXIT may carry either a full IPC ack or a
                             * compact CPU context.  The local QEMU IPC always
                             * expects struct wvm_ipc_cpu_run_ack.
                             */
                            if (msg_type == MSG_VCPU_EXIT &&
                                g_u_req_ctx[idx].max_len >= sizeof(struct wvm_ipc_cpu_run_ack) &&
                                (p_len == sizeof(wvm_tcg_context_t) ||
                                 p_len == sizeof(wvm_kvm_context_t))) {
                                struct wvm_ipc_cpu_run_ack *ack =
                                    (struct wvm_ipc_cpu_run_ack *)g_u_req_ctx[idx].rx_buffer;
                                memset(ack, 0, sizeof(*ack));
                                ack->status = 0;
                                ack->mode_tcg = hdr->mode_tcg ? 1 : 0;
                                if (ack->mode_tcg && p_len == sizeof(wvm_tcg_context_t)) {
                                    memcpy(&ack->ctx.tcg, payload, sizeof(wvm_tcg_context_t));
                                } else if (!ack->mode_tcg && p_len == sizeof(wvm_kvm_context_t)) {
                                    memcpy(&ack->ctx.kvm, payload, sizeof(wvm_kvm_context_t));
                                } else {
                                    ack->status = -EINVAL;
                                }
                            } else {
                                // MSG_MEM_ACK 必须保留完整 payload（含 version），
                                // 由上层按各自语义解析，避免版本号在此层被静默丢弃。
                                // [FIX-G3] 截断保护：防止恶意/错乱包溢出 rx_buffer
                                uint32_t copy_len = p_len;
                                if (copy_len > g_u_req_ctx[idx].max_len)
                                    copy_len = g_u_req_ctx[idx].max_len;
                                memcpy(g_u_req_ctx[idx].rx_buffer, payload, copy_len);
                            }
                            g_u_req_ctx[idx].status = 1;
                            matched_req_ctx = true;
                            if (msg_type == MSG_VCPU_EXIT) {
                                u_log("[RX VCPU_EXIT] matched rid=%llu -> status=1",
                                      (unsigned long long)rid);
                            }
                        } else if (msg_type == MSG_VCPU_EXIT) {
                            bool late_dup = (g_u_req_ctx[idx].full_id == rid);
                            if (!late_dup) {
                                u_log("[RX VCPU_EXIT] unmatched rid=%llu idx=%u slot_full_id=%llu has_buf=%d",
                                      (unsigned long long)rid,
                                      (unsigned)idx,
                                      (unsigned long long)g_u_req_ctx[idx].full_id,
                                      g_u_req_ctx[idx].rx_buffer ? 1 : 0);
                            }
                        }
                        pthread_mutex_unlock(&g_u_req_ctx[idx].lock);

                        if (!matched_req_ctx &&
                            msg_type == MSG_MEM_ACK &&
                            rid == SYNC_MAGIC) {
                            if (forward_local_slave_sync_ack(sockfd, base_ptr + offset,
                                                            current_pkt_len, hdr, rid)) {
                                offset += current_pkt_len;
                                continue;
                            }
                            broadcast_raw_packet_to_qemu(base_ptr + offset,
                                                         (size_t)current_pkt_len);
                            offset += current_pkt_len;
                            continue;
                        }

                        if (!matched_req_ctx && msg_type == MSG_MEM_ACK &&
                            maybe_forward_local_slave_mem_ack(sockfd, base_ptr + offset,
                                                              current_pkt_len, hdr, payload,
                                                              p_len, rid)) {
                            offset += current_pkt_len;
                            continue;
                        }

                    } else {
                        // [V29 FINAL FIX] 客户端推送处理逻辑
                        // 如果是推送/失效消息，Daemon 必须自己处理（更新 SHM + 通知 QEMU）
                        // 而不能扔给只懂服务端业务的 logic_core

                        void *payload = base_ptr + offset + sizeof(struct wvm_header);
                        uint16_t p_len = ntohs(hdr->payload_len);
                        if (msg_type == MSG_PAGE_PUSH_FULL) {
                            struct wvm_full_page_push *push = (struct wvm_full_page_push *)payload;
                            uint64_t gpa = WVM_NTOHLL(push->gpa);
                            if (gpa + 4096 <= g_shm_size) {
                                // 1. 更新本地 SHM (成为最新版本)
                                memcpy((uint8_t*)g_shm_ptr + gpa, push->data, 4096);
                            }
                            // 2. 转发给 QEMU (IPC) 以更新版本号/TLB。高 GPA
                            // 可能不在 daemon SHM 中，但 QEMU 的 RAM block 仍能映射。
                            broadcast_push_to_qemu(msg_type, payload, sizeof(struct wvm_full_page_push));
                        } 
                        else if (msg_type == MSG_PAGE_PUSH_DIFF) {
                            struct wvm_diff_log *log = (struct wvm_diff_log *)payload;
                            uint64_t gpa = WVM_NTOHLL(log->gpa);
                            uint16_t off = ntohs(log->offset);
                            uint16_t sz = ntohs(log->size);

                            if (off + sz <= 4096) {
                                if (hdr->flags & WVM_FLAG_ZERO) {
                                    // 零页：清零 SHM，转化为 FULL_PUSH 发给 QEMU
                                    if (gpa + 4096 <= g_shm_size) {
                                        memset((uint8_t*)g_shm_ptr + gpa, 0, 4096);
                                    }
                                    struct wvm_full_page_push fake_full;
                                    fake_full.gpa = log->gpa;
                                    fake_full.version = log->version;
                                    memset(fake_full.data, 0, 4096);
                                    broadcast_push_to_qemu(MSG_PAGE_PUSH_FULL, &fake_full, sizeof(fake_full));
                                } else if (sz > 0) {
                                    // 1. 应用 Diff 到 SHM
                                    if (gpa + off + sz <= g_shm_size) {
                                        memcpy((uint8_t*)g_shm_ptr + gpa + off, log->data, sz);
                                    }
                                    // 2. 转发给 QEMU
                                    broadcast_push_to_qemu(msg_type, payload, sizeof(struct wvm_diff_log) + sz);
                                }
                            }
                        }
                        else if (msg_type == MSG_INVALIDATE || msg_type == MSG_DOWNGRADE || msg_type == MSG_FORCE_SYNC) {
                            // 控制类推送：直接转发给 QEMU 处理
                            // 这里的 payload_len 是网络包里的长度，需要传给 IPC
                            broadcast_push_to_qemu(msg_type, payload, p_len);
                        }
                        /* [FIX] MSG_MEM_READ 不再在此拦截。
                         * 旧代码调用 handle_slave_read 从本地 g_shm_ptr 读取，但 Mode B 下
                         * g_shm_ptr 与 QEMU 的 g_ram_base 不实时同步（自己不接收自己的 PUSH），
                         * 会返回 stale data 并携带新版本号，导致全网一致性崩溃。
                         * 现在让它落入最后的 else { wvm_logic_process_packet } 由 Directory 正确处理。
                         */
                        else if (msg_type == MSG_VFIO_IRQ) {
                            // [FIX] 收到中断包，必须通过 IPC 转发给本地 QEMU
                            broadcast_irq_to_qemu();
                        }
                        else if (msg_type == MSG_RPC_BATCH_MEMSET) {
                            // 收到远程节点的广播 -> 仅执行本地操作
                            // 不需要回复 ACK (广播是 Fire-and-Forget)
                            // 不需要再次广播 (防止风暴)
                           // CRC 校验已在 Loop 开头完成，此处数据安全
                           handle_rpc_batch_execution(payload, p_len);
                       }
                        else {
                            // 其他消息 (DECLARE/COMMIT) 才是给服务端 Logic Core 的
                            uint32_t src_id = ntohl(hdr->slave_id);
                            wvm_logic_process_packet(hdr, payload, src_id);
                        }
                    }
                } else if (msg_type == MSG_VCPU_RUN ||
                           msg_type == MSG_VCPU_EXIT ||
                           msg_type == MSG_BLOCK_ACK) {
                    u_log("[RX CRC Mismatch] msg=%u src_port=%u recv=%08x calc=%08x len=%d",
                          (unsigned)msg_type, (unsigned)ntohs(src_addrs[i].sin_port),
                          received_crc, calculated_crc, current_pkt_len);
                }
    
                // 4. [关键] 指针移动到下一个包
                offset += current_pkt_len;
            }
        }
    }
    free(buffer_pool);
    return NULL;
}

// 供 logic_core 调用
void wvm_notify_kernel_epoch(uint32_t epoch) {
    // g_dev_fd 是打开 /dev/wavevm 的句柄，需要在初始化时保存
    extern int g_dev_fd; 
    if (g_dev_fd > 0) {
        ioctl(g_dev_fd, IOCTL_UPDATE_EPOCH, &epoch);
    }
}

// --- 公共接口定义 ---
struct dsm_driver_ops u_ops = {
    .alloc_large_table = u_alloc_large_table,
    .free_large_table = u_free_large_table,
    .alloc_packet = u_alloc_packet,
    .free_packet = u_free_packet,
    .set_gateway_ip = u_set_gateway_ip,
    .send_packet = u_send_packet,
    .fetch_page = u_fetch_page,
    .invalidate_local = u_invalidate_local,
    .log = u_log,
    .is_atomic_context = u_is_atomic_context,
    .touch_watchdog = u_touch_watchdog,
    .alloc_req_id = u_alloc_req_id,
    .free_req_id = u_free_req_id,
    .get_time_us = u_get_time_us,
    .time_diff_us = u_time_diff_us,
    .check_req_status = u_check_req_status,
    .cpu_relax = u_cpu_relax,
    .get_random = u_get_random,
    .yield_cpu_short_time = u_yield_cpu_short_time,
    .send_packet_async = u_send_packet_async
};

// --- 初始化入口 ---
int user_backend_init(int my_node_id, int port,
                      const struct wvm_node_runtime_context *runtime) {
    if (!runtime || !runtime->manifest || !runtime->dispatch ||
        !runtime->runtime_gate ||
        runtime->runtime_gate->state != WVM_RUNTIME_GATE_ACTIVE ||
        runtime->manifest->vm_id == 0 ||
        runtime->manifest->vm_id != g_my_vm_id) {
        fprintf(stderr, "[WaveVM] user_backend_init: runtime context is invalid\n");
        return -1;
    }
    if (my_node_id < 0 || my_node_id >= WVM_MAX_GATEWAYS) {
        fprintf(stderr, "[WaveVM] user_backend_init: node_id %d out of range [0, %d)\n",
                my_node_id, WVM_MAX_GATEWAYS);
        return -1;
    }
    g_my_node_id = my_node_id;
    g_local_port = port;
    g_runtime_context = runtime;
    srand(time(NULL));
    
    // 初始化本地 Gateway 地址 (默认指向 localhost:9000)
    g_gateways[my_node_id].sin_family = AF_INET;
    g_gateways[my_node_id].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    g_gateways[my_node_id].sin_port = htons(9000); 

    for (uint32_t i = 0; i < 2; i++) {
        if (g_gateways[i].sin_port != 0) {
            char ipbuf[16] = {0};
            inet_ntop(AF_INET, &g_gateways[i].sin_addr, ipbuf, sizeof(ipbuf));
            fprintf(stderr, "[GW-FINAL] id=%u ip=%s port=%u\n",
                    i, ipbuf, (unsigned)ntohs(g_gateways[i].sin_port));
        }
    }

    // 初始化请求上下文锁
    for (int i=0; i<MAX_INFLIGHT_REQS; i++) {
        pthread_mutex_init(&g_u_req_ctx[i].lock, NULL);
    }
    for (int i=0; i<LOCAL_SLAVE_REQS; i++) {
        pthread_mutex_init(&g_local_slave_req_locks[i], NULL);
    }
    
    // 初始化内存池和队列
    init_pkt_pool();
    queue_init(&g_fast_queue);
    queue_init(&g_slow_queue);

    // Test parameters (环境变量可覆盖编译时默认值)
    /* WVM_NONBLOCK_RECV: 已废弃，V30 始终使用 MSG_DONTWAIT */
    /* WVM_DISABLE_REUSEPORT: 已废弃，V30 共享 socket 不再使用 SO_REUSEPORT */
    {
        const char *pt = getenv("WVM_POLL_TIMEOUT_MS");
        if (pt) g_poll_timeout_ms = atoi(pt);
    }
    {
        const char *rc = getenv("WVM_RX_THREAD_COUNT");
        if (rc) { int v = atoi(rc); if (v >= 1 && v <= 16) g_rx_thread_count = v; }
    }
    fprintf(stderr, "[V30-Init] rx_threads=%d poll_timeout=%dms (shared socket)\n",
            g_rx_thread_count, g_poll_timeout_ms);

    // 启动 RX 线程 (根据 CPU 核心数动态调整，这里演示用 4)
    for (long i = 0; i < g_rx_thread_count; i++) {
        pthread_t th;
        if (pthread_create(&th, NULL, rx_thread_loop, (void*)i) != 0) {
            perror("Failed to create RX thread");
            return -1;
        }
        pthread_detach(th);
    }

    // 等待 RX 线程 0 初始化 Socket 并赋值给 g_tx_socket
    pthread_mutex_lock(&g_init_lock);
    while (g_tx_socket < 0) {
        pthread_cond_wait(&g_init_cond, &g_init_lock);
    }
    pthread_mutex_unlock(&g_init_lock);

    // 启动 TX 线程
    if (pthread_create(&g_tx_thread, NULL, tx_worker_thread, NULL) != 0) {
        perror("Failed to create TX thread");
        return -1;
    }
    
    return 0;
}
