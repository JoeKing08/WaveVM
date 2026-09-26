/*
 * [IDENTITY] Gateway Sidecar - The Stateless Router
 * ---------------------------------------------------------------------------
 * 物理角色：网络侧车，无状态包聚合器。
 * 职责边界：
 * 1. 物理路由转发：根据虚拟节点 ID 范围将包投递给下一跳 IP。
 * 2. 流量聚合：合并小包为 MTU 大包，降低全网 PPS 压力。
 * 3. 自学习逻辑：通过捕获入站流量自动更新路由条目。
 * 
 * [禁止事项]
 * - 严禁进行数据深包检测 (DPI) 或 CRC32 校验。
 * - 严禁引入任何动态内存分配 (malloc/free)，必须使用预分配 Buffer。
 * - 严禁持有锁进行网络发送。
 * ---------------------------------------------------------------------------
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h> 
#include <sched.h>
#include <poll.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <time.h>
#include <inttypes.h>

#include "aggregator.h"
#include "../common_include/wavevm_control.h"
#include "../common_include/wavevm_membership.h"
#include "../common_include/wavevm_protocol.h"
#include "../common_include/wavevm_route_runtime.h"
#include "../common_include/wavevm_route_control.h"
#include "../common_include/wavevm_control_owner.h"
#include "../common_include/wavevm_tls_control_connector.h"
#include "../common_include/wavevm_runtime_gate.h"
#include "uthash.h"

#if defined(__x86_64__) || defined(__i386__)
  #define CPU_RELAX() __asm__ volatile("pause" ::: "memory")
#else
  #define CPU_RELAX() sched_yield()
#endif

// A unified, hashable structure for each known downstream node route.
typedef struct {
    uint32_t id;                    // Key for the hash table (slave_id)
    struct sockaddr_in addr;        // Slave's network address, pre-filled
    uint8_t static_pinned;          // 1 when seeded by config/control plane; don't auto-learn overwrite
    slave_buffer_t *buffer;         // Pointer to the aggregation buffer, LAZILY ALLOCATED
    pthread_mutex_t lock;           // Per-node lock for buffer access
    UT_hash_handle hh;              // Makes this structure hashable by uthash
} gateway_node_t;

// --- 全局状态 ---
static gateway_node_t *g_node_map = NULL; // IMPORTANT: Must be initialized to NULL
// [REVISED PATCH] 使用读写锁替代互斥锁，保障数据面性能
static pthread_rwlock_t g_map_lock = PTHREAD_RWLOCK_INITIALIZER; // A global lock to protect the hash map itself (for creation/deletion)
static struct wvm_route_runtime g_route_runtime;
static int g_route_runtime_ready = 0;
static uint32_t g_route_vm_id = 0;
static int g_route_authority_active = 0;
static struct wvm_route_control g_route_control;
static int g_route_control_ready = 0;
static char g_route_control_socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
static uint32_t g_route_control_physical_node_id = 0;
static uint64_t g_route_control_instance_id = 0;
static struct wvm_control_owner g_route_control_owner;
static struct wvm_endpoint g_route_control_network_endpoint;

struct gateway_control_authentication {
    uid_t local_uid;
    struct wvm_member_key controller;
    uint32_t controller_physical_node_id;
    uint64_t controller_runtime_instance_id;
};

static struct gateway_control_authentication g_route_control_authentication;
#define BATCH_SIZE 64
#define WVM_BIG_PKT_THRESHOLD 200
#define WVM_RXQ_DROP_HEARTBEAT (512 * 1024)
#define WVM_HEARTBEAT_MIN_INTERVAL_MS 100

typedef struct packet_node {
    int len;
    struct sockaddr_in src;
    uint8_t *data;
    struct packet_node *next;
} packet_node_t;

typedef struct packet_queue {
    packet_node_t *head;
    packet_node_t *tail;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} packet_queue_t;

static void queue_init(packet_queue_t *q) {
    q->head = NULL;
    q->tail = NULL;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cond, NULL);
}

static void queue_push(packet_queue_t *q, packet_node_t *n) {
    n->next = NULL;
    pthread_mutex_lock(&q->lock);
    if (q->tail) {
        q->tail->next = n;
    } else {
        q->head = n;
    }
    q->tail = n;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);
}

static packet_node_t* queue_pop(packet_queue_t *q) {
    pthread_mutex_lock(&q->lock);
    while (!q->head) {
        pthread_cond_wait(&q->cond, &q->lock);
    }
    packet_node_t *n = q->head;
    q->head = n->next;
    if (!q->head) q->tail = NULL;
    pthread_mutex_unlock(&q->lock);
    return n;
}

static pthread_mutex_t g_hb_lock = PTHREAD_MUTEX_INITIALIZER;

#define HB_TABLE_SIZE 16
typedef struct {
    uint32_t ip;
    uint16_t port;
    uint64_t last_ms;
} hb_slot_t;
static hb_slot_t g_hb_table[HB_TABLE_SIZE];

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static int should_drop_heartbeat(struct sockaddr_in *src) {
    uint32_t ip = src->sin_addr.s_addr;
    uint16_t port = src->sin_port;
    uint64_t now = now_ms();
    int drop = 0;

    pthread_mutex_lock(&g_hb_lock);
    int idx = (int)((ip ^ port) & (HB_TABLE_SIZE - 1));
    for (int i = 0; i < HB_TABLE_SIZE; i++) {
        hb_slot_t *slot = &g_hb_table[(idx + i) & (HB_TABLE_SIZE - 1)];
        if (slot->ip == ip && slot->port == port) {
            if (now - slot->last_ms < WVM_HEARTBEAT_MIN_INTERVAL_MS) {
                drop = 1;
            } else {
                slot->last_ms = now;
            }
            pthread_mutex_unlock(&g_hb_lock);
            return drop;
        }
        if (slot->ip == 0) {
            slot->ip = ip;
            slot->port = port;
            slot->last_ms = now;
            pthread_mutex_unlock(&g_hb_lock);
            return 0;
        }
    }
    // Table full; overwrite the hashed slot.
    hb_slot_t *slot = &g_hb_table[idx];
    drop = (now - slot->last_ms < WVM_HEARTBEAT_MIN_INTERVAL_MS);
    slot->ip = ip;
    slot->port = port;
    slot->last_ms = now;
    pthread_mutex_unlock(&g_hb_lock);
    return drop;
}

static struct sockaddr_in g_upstream_addr; // The address of the upstream gateway or master
static volatile int g_primary_socket = -1; 
static int g_upstream_tx_socket = -1;
static int g_local_port = 0;
int g_ctrl_port = 0; // 供应给 wavevm_gateway

static int g_is_single_core = 0;
static volatile uint64_t g_rx_small_count = 0;
static volatile uint64_t g_rx_big_count = 0;
static int g_allowed_cpus = 0;
static int g_force_single_rx = 0;
static int g_disable_reuseport = 0;
static int g_use_recvfrom = 0;
static int g_nonblock_recv = 0;
static int g_force_single_fd = 0;
static int g_multi_queue = 1;

#define WVM_TX_BATCH_SIZE 32U
#define WVM_TX_QUEUE_CAPACITY 8192U
#define WVM_TX_HIGH_BURST 8U

/*
 * V1 frames are individually checksummed envelopes and cannot be concatenated
 * into the legacy aggregation buffer.  The gateway still needs queueing,
 * QoS, and batched syscalls, so V1 uses a separate bounded MPSC scheduler.
 */
struct tx_item {
    struct tx_item *next;
    struct sockaddr_in destination;
    size_t bytes;
    uint8_t frame[WVM_ENVELOPE_MAX_NETWORK_FRAME_BYTES];
};

struct tx_queue {
    struct tx_item *head;
    struct tx_item *tail;
    size_t count;
    pthread_mutex_t lock;
    pthread_cond_t ready;
};

struct tx_scheduler {
    struct tx_queue high;
    struct tx_queue normal;
    pthread_t thread;
    int socket_fd;
    int started;
};

static struct tx_scheduler g_tx_scheduler = {
    .socket_fd = -1,
};

static int message_is_latency_sensitive(uint16_t message_type)
{
    switch (message_type) {
    case WVM_ENVELOPE_MSG_MEM_READ:
    case WVM_ENVELOPE_MSG_MEM_ACK:
    case WVM_ENVELOPE_MSG_VCPU_RUN:
    case WVM_ENVELOPE_MSG_VCPU_EXIT:
    case WVM_ENVELOPE_MSG_VFIO_IRQ:
    case WVM_ENVELOPE_MSG_BLOCK_ACK:
        return 1;
    default:
        return 0;
    }
}

static void tx_queue_init(struct tx_queue *queue)
{
    memset(queue, 0, sizeof(*queue));
    pthread_mutex_init(&queue->lock, NULL);
    pthread_cond_init(&queue->ready, NULL);
}

static int tx_enqueue(struct tx_item *item, int high_priority)
{
    struct tx_queue *queue =
        high_priority ? &g_tx_scheduler.high : &g_tx_scheduler.normal;
    size_t total_count;

    if (!item || !g_tx_scheduler.started) {
        return -EPIPE;
    }

    /*
     * Lock both queues in a fixed order to enforce one scheduler-wide
     * capacity without introducing a data-plane global routing lock.
     */
    pthread_mutex_lock(&g_tx_scheduler.high.lock);
    pthread_mutex_lock(&g_tx_scheduler.normal.lock);
    total_count = g_tx_scheduler.high.count + g_tx_scheduler.normal.count;
    if (total_count >= WVM_TX_QUEUE_CAPACITY) {
        pthread_mutex_unlock(&g_tx_scheduler.normal.lock);
        pthread_mutex_unlock(&g_tx_scheduler.high.lock);
        return -EAGAIN;
    }
    if (queue->tail) {
        queue->tail->next = item;
    } else {
        queue->head = item;
    }
    queue->tail = item;
    queue->count++;
    /* One scheduler worker waits on the high queue's shared wakeup. */
    pthread_cond_signal(&g_tx_scheduler.high.ready);
    pthread_mutex_unlock(&g_tx_scheduler.normal.lock);
    pthread_mutex_unlock(&g_tx_scheduler.high.lock);
    return 0;
}

static struct tx_item *tx_take_one(unsigned int *high_streak)
{
    struct tx_item *item = NULL;
    struct tx_queue *selected = NULL;

    pthread_mutex_lock(&g_tx_scheduler.high.lock);
    pthread_mutex_lock(&g_tx_scheduler.normal.lock);
    while (!g_tx_scheduler.high.head && !g_tx_scheduler.normal.head) {
        pthread_mutex_unlock(&g_tx_scheduler.normal.lock);
        pthread_cond_wait(&g_tx_scheduler.high.ready,
                          &g_tx_scheduler.high.lock);
        pthread_mutex_lock(&g_tx_scheduler.normal.lock);
    }
    if (g_tx_scheduler.high.head &&
        (!g_tx_scheduler.normal.head ||
         *high_streak < WVM_TX_HIGH_BURST)) {
        selected = &g_tx_scheduler.high;
        (*high_streak)++;
    } else {
        selected = &g_tx_scheduler.normal;
        *high_streak = 0;
    }
    item = selected->head;
    selected->head = item->next;
    if (!selected->head) {
        selected->tail = NULL;
    }
    selected->count--;
    item->next = NULL;
    pthread_mutex_unlock(&g_tx_scheduler.normal.lock);
    pthread_mutex_unlock(&g_tx_scheduler.high.lock);
    return item;
}

static size_t tx_take_batch(struct tx_item *items[WVM_TX_BATCH_SIZE],
                               unsigned int *high_streak)
{
    size_t count = 0;

    items[count++] = tx_take_one(high_streak);
    while (count < WVM_TX_BATCH_SIZE) {
        struct tx_item *item = NULL;

        pthread_mutex_lock(&g_tx_scheduler.high.lock);
        pthread_mutex_lock(&g_tx_scheduler.normal.lock);
        if (g_tx_scheduler.high.head &&
            (!g_tx_scheduler.normal.head ||
             *high_streak < WVM_TX_HIGH_BURST)) {
            item = g_tx_scheduler.high.head;
            g_tx_scheduler.high.head = item->next;
            if (!g_tx_scheduler.high.head) {
                g_tx_scheduler.high.tail = NULL;
            }
            g_tx_scheduler.high.count--;
            (*high_streak)++;
        } else if (g_tx_scheduler.normal.head) {
            item = g_tx_scheduler.normal.head;
            g_tx_scheduler.normal.head = item->next;
            if (!g_tx_scheduler.normal.head) {
                g_tx_scheduler.normal.tail = NULL;
            }
            g_tx_scheduler.normal.count--;
            *high_streak = 0;
        }
        pthread_mutex_unlock(&g_tx_scheduler.normal.lock);
        pthread_mutex_unlock(&g_tx_scheduler.high.lock);
        if (!item) {
            break;
        }
        item->next = NULL;
        items[count++] = item;
    }
    return count;
}

static void tx_send_batch(struct tx_item *items[WVM_TX_BATCH_SIZE],
                             size_t count)
{
    size_t offset = 0;

    while (offset < count) {
        struct mmsghdr messages[WVM_TX_BATCH_SIZE];
        struct iovec iovecs[WVM_TX_BATCH_SIZE];
        size_t remaining = count - offset;
        int sent;
        size_t i;

        memset(messages, 0, sizeof(messages));
        for (i = 0; i < remaining; i++) {
            iovecs[i].iov_base = items[offset + i]->frame;
            iovecs[i].iov_len = items[offset + i]->bytes;
            messages[i].msg_hdr.msg_iov = &iovecs[i];
            messages[i].msg_hdr.msg_iovlen = 1;
            messages[i].msg_hdr.msg_name = &items[offset + i]->destination;
            messages[i].msg_hdr.msg_namelen = sizeof(items[offset + i]->destination);
        }
        sent = sendmmsg(g_tx_scheduler.socket_fd, messages,
                        (unsigned int)remaining, MSG_DONTWAIT);
        if (sent > 0) {
            for (i = 0; i < (size_t)sent; i++) {
                free(items[offset + i]);
            }
            offset += (size_t)sent;
            continue;
        }
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd writable = {
                .fd = g_tx_scheduler.socket_fd,
                .events = POLLOUT,
            };

            /*
             * This is kernel transport backpressure, not a semantic timeout.
             * Waiting for POLLOUT avoids a retry spin and keeps unsent frames
             * in their original order.
             */
            if (poll(&writable, 1, -1) >= 0) {
                continue;
            }
            if (errno == EINTR) {
                continue;
            }
        }
        fprintf(stderr, "[Gateway] V1 transmit failed errno=%d; dropping %zu frames\n",
                errno, remaining);
        while (offset < count) {
            free(items[offset++]);
        }
    }
}

static void *tx_worker(void *opaque)
{
    unsigned int high_streak = 0;

    (void)opaque;
    for (;;) {
        struct tx_item *items[WVM_TX_BATCH_SIZE];
        size_t count = tx_take_batch(items, &high_streak);

        tx_send_batch(items, count);
    }
    return NULL;
}

static int tx_scheduler_start(void)
{
    int flags;

    if (g_tx_scheduler.started) {
        return 0;
    }
    tx_queue_init(&g_tx_scheduler.high);
    tx_queue_init(&g_tx_scheduler.normal);
    g_tx_scheduler.socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_tx_scheduler.socket_fd < 0) {
        return -errno;
    }
    flags = fcntl(g_tx_scheduler.socket_fd, F_GETFL, 0);
    if (flags >= 0) {
        (void)fcntl(g_tx_scheduler.socket_fd, F_SETFL, flags | O_NONBLOCK);
    }
    if (pthread_create(&g_tx_scheduler.thread, NULL, tx_worker, NULL) !=
        0) {
        int result = -errno;

        close(g_tx_scheduler.socket_fd);
        g_tx_scheduler.socket_fd = -1;
        return result;
    }
    pthread_detach(g_tx_scheduler.thread);
    g_tx_scheduler.started = 1;
    return 0;
}

static int parse_u64_env(const char *name, uint64_t *value)
{
    const char *text = getenv(name);
    char *end = NULL;
    unsigned long long parsed;

    if (!text || !*text || !value) {
        return -1;
    }
    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed == 0) {
        return -1;
    }
    *value = (uint64_t)parsed;
    return 0;
}

static int parse_hex_digest_env(const char *name, uint8_t digest[32])
{
    const char *text = getenv(name);
    size_t i;

    if (!text || strlen(text) != 64 || !digest) {
        return -1;
    }
    for (i = 0; i < 32; i++) {
        unsigned int value;

        if (sscanf(text + i * 2U, "%2x", &value) != 1 ||
            value > 0xffU) {
            return -1;
        }
        digest[i] = (uint8_t)value;
    }
    return 0;
}

static inline gateway_node_t* find_node(uint32_t slave_id);
static void learn_route(uint32_t slave_id, struct sockaddr_in *addr);
static int internal_push(int fd, uint32_t slave_id, void *data, int len);

static int count_allowed_cpus(void) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    if (sched_getaffinity(0, sizeof(mask), &mask) != 0) {
        return get_nprocs();
    }
    int count = 0;
    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, &mask)) count++;
    }
    return (count > 0) ? count : get_nprocs();
}

static int pick_allowed_cpu_index(long worker_idx) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    if (sched_getaffinity(0, sizeof(mask), &mask) != 0) {
        return (int)worker_idx;
    }
    int target = (g_allowed_cpus > 0) ? (int)(worker_idx % g_allowed_cpus) : (int)worker_idx;
    int seen = 0;
    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (!CPU_ISSET(i, &mask)) continue;
        if (seen == target) return i;
        seen++;
    }
    return (int)worker_idx;
}

static int get_rxq_bytes(int fd) {
    int bytes = -1;
    if (ioctl(fd, FIONREAD, &bytes) != 0) return -1;
    return bytes;
}

void detect_cpu_env() {
    if (get_nprocs() <= 1) g_is_single_core = 1;
}

static int endpoint_to_sockaddr_in(const struct wvm_endpoint *endpoint,
                                   struct sockaddr_in *address)
{
    if (!endpoint || !address ||
        endpoint->data_transport != WVM_DATA_TRANSPORT_UDP ||
        endpoint->data_address_bytes != 4 || endpoint->data_port == 0) {
        return -1;
    }
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    memcpy(&address->sin_addr.s_addr, endpoint->data_address, 4);
    address->sin_port = htons(endpoint->data_port);
    return 0;
}

static int gateway_forward(int local_fd, const uint8_t *packet,
                              size_t packet_bytes)
{
    struct wvm_envelope envelope;
    struct wvm_route_runtime_next_hop next_hop;
    struct sockaddr_in destination;
    struct tx_item *item = NULL;
    size_t forwarded_bytes = 0;
    char error[256] = {0};

    (void)local_fd;

    if (!g_route_authority_active ||
        wvm_envelope_decode(packet, packet_bytes,
                               WVM_ENVELOPE_TRANSPORT_NETWORK, &envelope,
                               error, sizeof(error)) != 0 ||
        wvm_route_runtime_lookup(&g_route_runtime, &envelope, &next_hop,
                                 error, sizeof(error)) != 0 ||
        endpoint_to_sockaddr_in(&next_hop.next_hop_endpoint, &destination) !=
            0 ||
        wvm_envelope_route_advance(&envelope, error, sizeof(error)) != 0 ||
        !(item = calloc(1, sizeof(*item))) ||
        wvm_envelope_encode(&envelope, WVM_ENVELOPE_TRANSPORT_NETWORK,
                               item->frame, sizeof(item->frame),
                               &forwarded_bytes, error, sizeof(error)) != 0) {
        static unsigned int rejected;

        if (rejected++ < 16U) {
            fprintf(stderr, "[Gateway] rejected V1 frame: %s\n",
                    error[0] ? error : "route endpoint is unsupported");
        }
        free(item);
        return -EPROTO;
    }
    item->destination = destination;
    item->bytes = forwarded_bytes;
    if (tx_enqueue(item, message_is_latency_sensitive(
                                envelope.message_type)) != 0) {
        static unsigned int backpressured;

        if (backpressured++ < 16U) {
            fprintf(stderr, "[Gateway] V1 transmit queue is backpressured\n");
        }
        free(item);
        return -EAGAIN;
    }
    return 0;
}

static inline void gateway_process_packet(int local_fd,
                                          uint8_t *ptr,
                                          int pkt_len,
                                          struct sockaddr_in *src) {
    if (pkt_len >= 4 && ptr[0] == 'W' && ptr[1] == 'V' &&
        ptr[2] == 'M' && ptr[3] == '1') {
        (void)src;
        (void)gateway_forward(local_fd, ptr, (size_t)pkt_len);
        return;
    }
    if (pkt_len < (int)sizeof(struct wvm_header)) return;
    struct wvm_header *hdr = (struct wvm_header *)ptr;
    if (pkt_len >= 200) {
        __sync_fetch_and_add(&g_rx_big_count, 1);
    } else {
        __sync_fetch_and_add(&g_rx_small_count, 1);
    }
    { static int __rx=0;
      if (__rx < 20) {
          fprintf(stderr, "[Gateway] rx len=%u magic=0x%08x\n",
                  (unsigned)pkt_len, (unsigned)ntohl(hdr->magic));
          __rx++;
      }
    }
    { static int __rx_big=0;
      if (__rx_big < 20 && pkt_len >= 200) {
          fprintf(stderr, "[Gateway] rx-big len=%u magic=0x%08x\n",
                  (unsigned)pkt_len, (unsigned)ntohl(hdr->magic));
          __rx_big++;
      }
    }
    if (ntohl(hdr->magic) != WVM_MAGIC) { static int __m=0; if(__m<5){fprintf(stderr,"[TRACE] magic fail\n");__m++;} return; }
    uint16_t msg_type = ntohs(hdr->msg_type);
    { static int __t1=0; if(__t1<10 && pkt_len>=200){fprintf(stderr,"[TRACE] post-magic msg=%u len=%d\n",msg_type,pkt_len);__t1++;} }
    {
        int rxq = get_rxq_bytes(local_fd);
        if (rxq > WVM_RXQ_DROP_HEARTBEAT && pkt_len < WVM_BIG_PKT_THRESHOLD) {
            static int __small_drop = 0;
            if (__small_drop < 20) {
                fprintf(stderr, "[Gateway] drop small pkt len=%d rxq=%d\n", pkt_len, rxq);
                __small_drop++;
            }
            { static int __d=0; if(__d<5 && pkt_len>=200){fprintf(stderr,"[TRACE] rxq-drop len=%d\n",pkt_len);__d++;} }
            return;
        }
    }
    if (msg_type == MSG_HEARTBEAT) {
        int rxq = get_rxq_bytes(local_fd);
        if (rxq > WVM_RXQ_DROP_HEARTBEAT) {
            static int __hb_drop = 0;
            if (__hb_drop < 20) {
                fprintf(stderr, "[Gateway] drop heartbeat rxq=%d\n", rxq);
                __hb_drop++;
            }
            return;
        }
        if (should_drop_heartbeat(src)) {
            static int __hb_rl = 0;
            if (__hb_rl < 20) {
                fprintf(stderr, "[Gateway] drop heartbeat rate-limit\n");
                __hb_rl++;
            }
            return;
        }
    }

    uint32_t source_id = ntohl(hdr->slave_id); // 发送者 ID
    uint32_t target_id = ntohl(hdr->target_id); // 目标 ID（兼容旧逻辑时可能为 AUTO_ROUTE）
    
    // [关键]：只要收到合法的 WVM 包，就学习源路由
    // 排除掉 Upstream (Master/Core) 的 ID，只学习 Downstream (Leaf) 节点
    // 这里可以通过 ID 范围判断，或者简单地全部学习（Upstream 路由更新也无妨）
    if (source_id != WVM_NODE_AUTO_ROUTE) {
        learn_route(source_id, src);
    }

    /*
     * Route by logical destination first. This avoids source-IP based
     * misclassification loops in multi-hop or same-host multi-instance
     * deployments. Fallback to upstream only when no local route exists.
     */
    // [FIX-M7] 当 target_id 无效时不再 fallback 到 source_id，
    // 防止 AUTO_ROUTE 包被回送给发送者形成环路
    { static int __t2=0; if(__t2<10 && pkt_len>=200){fprintf(stderr,"[TRACE] pre-route target=%u src=%u msg=%u valid=%d\n",target_id,source_id,msg_type,(int)WVM_IS_VALID_TARGET(target_id));__t2++;} }
    uint32_t route_id;
    if (WVM_IS_VALID_TARGET(target_id)) {
        route_id = target_id;
    } else {
        // 无有效目标，直接交给 upstream 处理
        int tx_fd = (g_upstream_tx_socket >= 0) ? g_upstream_tx_socket : local_fd;
        sendto(tx_fd, ptr, pkt_len, MSG_DONTWAIT,
               (struct sockaddr*)&g_upstream_addr, sizeof(g_upstream_addr));
        return;
    }

    { static int __pre_push=0;
      if (__pre_push < 30 && pkt_len >= 200) {
          fprintf(stderr, "[GW-PRE-PUSH] route_id=%u target=%u src_id=%u msg=%u len=%d valid=%d\n",
                  route_id, target_id, source_id, msg_type, pkt_len,
                  (int)WVM_IS_VALID_TARGET(target_id));
          __pre_push++;
      }
    }
    int r = internal_push(local_fd, route_id, ptr, pkt_len);
    { static int __post_push=0;
      if (__post_push < 30 && pkt_len >= 200) {
          fprintf(stderr, "[GW-POST-PUSH] route_id=%u r=%d len=%d\n", route_id, r, pkt_len);
          __post_push++;
      }
    }
    if (msg_type == MSG_VCPU_RUN || msg_type == MSG_VCPU_EXIT) {
        static int __gw_dbg = 0;
        if (__gw_dbg < 20) {
            char src_ip[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &src->sin_addr, src_ip, sizeof(src_ip));
            fprintf(stderr, "[Gateway] route msg=%u target=%u route=%u r=%d src=%s:%u\n",
                    (unsigned)msg_type, (unsigned)target_id, (unsigned)route_id, r,
                    src_ip, (unsigned)ntohs(src->sin_port));
            __gw_dbg++;
        }
    }
    if (r < 0) {
        int tx_fd = (g_upstream_tx_socket >= 0) ? g_upstream_tx_socket : local_fd;
        ssize_t sret = sendto(tx_fd, ptr, pkt_len, MSG_DONTWAIT,
                              (struct sockaddr*)&g_upstream_addr, sizeof(g_upstream_addr));
        if (msg_type == MSG_VCPU_RUN || msg_type == MSG_VCPU_EXIT || sret < 0) {
            char src_ip[INET_ADDRSTRLEN] = {0};
            char up_ip[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &src->sin_addr, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, &g_upstream_addr.sin_addr, up_ip, sizeof(up_ip));
            fprintf(stderr, "[Gateway] route->upstream msg=%u src=%s:%u up=%s:%u ret=%zd errno=%d\n",
                    (unsigned)msg_type,
                    src_ip, (unsigned)ntohs(src->sin_port),
                    up_ip, (unsigned)ntohs(g_upstream_addr.sin_port),
                    sret, (sret < 0) ? errno : 0);
        }
    } else if (msg_type == MSG_VCPU_RUN || msg_type == MSG_VCPU_EXIT) {
        gateway_node_t *dst = find_node(route_id);
        char dst_ip[INET_ADDRSTRLEN] = {0};
        unsigned dst_port = 0;
        if (dst) {
            inet_ntop(AF_INET, &dst->addr.sin_addr, dst_ip, sizeof(dst_ip));
            dst_port = (unsigned)ntohs(dst->addr.sin_port);
        }
        fprintf(stderr, "[Gateway] route->local msg=%u route=%u src=%s:%u dst=%s:%u\n",
                (unsigned)msg_type, route_id,
                inet_ntoa(src->sin_addr), (unsigned)ntohs(src->sin_port),
                dst_ip[0] ? dst_ip : "0.0.0.0", dst_port);
    }
}

typedef struct {
    int local_fd;
    packet_queue_t *q;
} gateway_queue_arg_t;

static void* gateway_queue_consumer(void *arg) {
    gateway_queue_arg_t *qa = (gateway_queue_arg_t*)arg;
    for (;;) {
        packet_node_t *n = queue_pop(qa->q);
        if (!n) continue;
        gateway_process_packet(qa->local_fd, n->data, n->len, &n->src);
        free(n->data);
        free(n);
    }
    return NULL;
}


/* 
 * [物理意图] 在纳秒级时间内，从动态哈希表中定位特定虚拟节点的“物理坐标”。
 * [关键逻辑] 使用 uthash 维护 ID 到 IP/Port 的映射。采用“快慢路径分离”：查找走无锁读，创建走写锁保护。
 * [后果] 这是网关转发性能的瓶颈点。若查找效率低下，整个 Pod 内部的内存同步延迟将呈指数级上升。
 *[警告] We perform a lock-free read here. This is ONLY safe because:
       1. The hash table is populated SINGLE-THREADED during initialization.
       2. The hash table is EFFECTIVELY IMMUTABLE during runtime.
       3. NO dynamic node addition/rehashing allows to happen while workers are running.
       DO NOT call HASH_ADD or find_or_create_node after init_aggregator returns!
 */
static inline gateway_node_t* find_node(uint32_t slave_id) {
    gateway_node_t *node = NULL;
    // HASH_FIND is read-only. Safe on immutable table.
    HASH_FIND_INT(g_node_map, &slave_id, node);
    return node;
}

// Helper function to find a node, creating it if it doesn't exist.
static gateway_node_t* find_or_create_node(uint32_t slave_id) {
    gateway_node_t *node = find_node(slave_id);
    if (node) {
        return node;
    }

    // Node not found, need to create it under the global map lock.
    pthread_rwlock_wrlock(&g_map_lock);
    
    // Double-check after acquiring the lock to handle race condition
    HASH_FIND_INT(g_node_map, &slave_id, node);
    if (node == NULL) {
        node = (gateway_node_t*)calloc(1, sizeof(gateway_node_t));
        if (node) {
            node->id = slave_id;
            pthread_mutex_init(&node->lock, NULL);
            node->buffer = NULL; // Buffer is lazily allocated on the first push
            HASH_ADD_INT(g_node_map, id, node);
        } else {
            fprintf(stderr, "[Gateway CRITICAL] Out of memory creating new node entry!\n");
        }
    }
    
    pthread_rwlock_unlock(&g_map_lock);
    return node;
}

static int read_route_snapshot_file(
    const char *path, struct wvm_route_snapshot_record *snapshot,
    struct wvm_route_rule_record *rules, size_t rule_capacity,
    struct wvm_required_ack_entry *ack_entries, size_t ack_capacity,
    char *error, size_t error_len)
{
    struct stat st;
    uint8_t *bytes;
    size_t offset = 0;
    int fd;
    int result = -1;

    if (!path || !snapshot || !rules || rule_capacity == 0 ||
        !ack_entries || ack_capacity == 0 || stat(path, &st) != 0 ||
        st.st_size <= 0 || (uintmax_t)st.st_size > WVM_RUNTIME_MANIFEST_MAX_BYTES) {
        snprintf(error, error_len, "route snapshot file is invalid");
        return -1;
    }
    bytes = malloc((size_t)st.st_size);
    if (!bytes) {
        snprintf(error, error_len, "cannot allocate route snapshot buffer");
        return -1;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(error, error_len, "cannot open route snapshot: %s",
                 strerror(errno));
        free(bytes);
        return -1;
    }
    while (offset < (size_t)st.st_size) {
        ssize_t received = read(fd, bytes + offset,
                                (size_t)st.st_size - offset);

        if (received < 0 && errno == EINTR)
            continue;
        if (received <= 0) {
            snprintf(error, error_len, "cannot read route snapshot: %s",
                     received == 0 ? "unexpected EOF" : strerror(errno));
            goto out;
        }
        offset += (size_t)received;
    }

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->next_hop_rules.entries = rules;
    snapshot->next_hop_rules.capacity = rule_capacity;
    snapshot->required_ack_set.entries.entries = ack_entries;
    snapshot->required_ack_set.entries.capacity = ack_capacity;
    if (wvm_route_snapshot_record_decode(bytes, offset, snapshot, error,
                                         error_len) != 0) {
        goto out;
    }
    result = 0;
out:
    close(fd);
    free(bytes);
    return result;
}

static int init_route_runtime_from_snapshot_file(const char *path)
{
    struct wvm_route_snapshot_record snapshot;
    struct wvm_route_rule_record *rules = NULL;
    struct wvm_required_ack_entry *ack_entries = NULL;
    struct wvm_route_snapshot_key key;
    char error[256] = {0};

    if (!path) {
        fprintf(stderr, "[Gateway] route snapshot path is missing\n");
        return -EINVAL;
    }
    rules = calloc(WVM_ROUTE_RUNTIME_MAX_ENTRIES, sizeof(*rules));
    ack_entries = calloc(WVM_ROUTE_RUNTIME_MAX_ENTRIES, sizeof(*ack_entries));
    if (!rules || !ack_entries) {
        free(rules);
        free(ack_entries);
        return -ENOMEM;
    }
    if (read_route_snapshot_file(
            path, &snapshot, rules, WVM_ROUTE_RUNTIME_MAX_ENTRIES,
            ack_entries, WVM_ROUTE_RUNTIME_MAX_ENTRIES, error,
            sizeof(error)) != 0) {
        fprintf(stderr, "[Gateway] route snapshot rejected: %s\n",
                error[0] ? error : "invalid snapshot");
        free(rules);
        free(ack_entries);
        return -EINVAL;
    }
    key = snapshot.route_snapshot_key;
    if (!g_route_runtime_ready) {
        wvm_route_runtime_init(&g_route_runtime);
        g_route_runtime_ready = 1;
    }
    {
        struct wvm_route_snapshot_key current;

        /*
         * A recovered route-control journal is newer authority than the
         * bootstrap artifact.  Do not regress a live scope by replaying the
         * manifest's initial route snapshot over its durable successor.
         */
        if (wvm_route_runtime_current_key(
                &g_route_runtime, &key.scope_key, &current) == 0) {
            free(rules);
            free(ack_entries);
            g_route_authority_active = 1;
            fprintf(stderr,
                    "[Gateway] retained journal route snapshot vm=%u "
                    "incarnation=%" PRIu64 " scope=%" PRIu64
                    " topology=%" PRIu64 " generation=%" PRIu64 "\n",
                    current.scope_key.vm_id,
                    current.scope_key.vm_incarnation,
                    current.scope_key.route_scope_id,
                    current.topology_revision, current.route_generation);
            return 0;
        }
    }
    if (wvm_route_runtime_prepare(&g_route_runtime, &snapshot, error,
                                  sizeof(error)) != 0 ||
        wvm_route_runtime_activate(&g_route_runtime, &key, error,
                                   sizeof(error)) != 0) {
        fprintf(stderr, "[Gateway] route snapshot activation rejected: %s\n",
                error[0] ? error : "invalid snapshot");
        free(rules);
        free(ack_entries);
        return -EINVAL;
    }
    free(rules);
    free(ack_entries);
    g_route_authority_active = 1;
    fprintf(stderr,
            "[Gateway] active V1 route snapshot vm=%u incarnation=%" PRIu64
            " scope=%" PRIu64 " topology=%" PRIu64 " generation=%" PRIu64
            "\n",
            key.scope_key.vm_id, key.scope_key.vm_incarnation,
            key.scope_key.route_scope_id,
            key.topology_revision, key.route_generation);
    return 0;
}

static int init_route_runtime_from_environment(void)
{
    const char *path = getenv("WVM_RUNTIME_ROUTE_SNAPSHOT_PATH");

    if (path && path[0] != '\0')
        return init_route_runtime_from_snapshot_file(path);
    return 0;
}

static int gateway_parse_role(const char *text,
                              enum wvm_manifest_role_type *role)
{
    if (!text || !role) {
        return -1;
    }
    if (strcmp(text, "node-runtime") == 0) {
        *role = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    } else if (strcmp(text, "gateway") == 0) {
        *role = WVM_MANIFEST_ROLE_GATEWAY;
    } else if (strcmp(text, "executor") == 0) {
        *role = WVM_MANIFEST_ROLE_EXECUTOR;
    } else {
        return -1;
    }
    return 0;
}

static int gateway_member_equal(const struct wvm_member_key *left,
                                const struct wvm_member_key *right)
{
    return left && right && left->role_type == right->role_type &&
           left->role_id == right->role_id &&
           left->instance_id == right->instance_id;
}

static int gateway_parse_u64(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;

    if (!text || !*text || !value) {
        return -1;
    }
    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed == 0) {
        return -1;
    }
    *value = (uint64_t)parsed;
    return 0;
}

static uint16_t control_status_from_error(const char *error);

static int gateway_authenticate_unix(
    void *opaque, int stream_fd, struct wvm_member_key *actor, char *error,
    size_t error_len)
{
    const struct gateway_control_authentication *authentication = opaque;
    struct ucred credentials;
    socklen_t credentials_bytes = sizeof(credentials);

    if (!authentication || !actor || stream_fd < 0 ||
        getsockopt(stream_fd, SOL_SOCKET, SO_PEERCRED, &credentials,
                   &credentials_bytes) != 0 ||
        credentials_bytes != sizeof(credentials) ||
        credentials.uid != authentication->local_uid) {
        if (error && error_len != 0) {
            snprintf(error, error_len,
                     "gateway Unix control peer is not authorized");
        }
        return -EACCES;
    }
    *actor = authentication->controller;
    return 0;
}

static int gateway_authenticate_tls(
    void *opaque, int stream_fd, const struct wvm_control_io *io,
    struct wvm_member_key *actor, char *error, size_t error_len)
{
    const struct gateway_control_authentication *authentication = opaque;
    struct wvm_member_key peer;

    (void)stream_fd;
    if (!authentication || !actor ||
        wvm_tls_control_peer_identity(io, &peer, error, error_len) != 0 ||
        !gateway_member_equal(&peer, &authentication->controller)) {
        if (error && error_len != 0) {
            snprintf(error, error_len,
                     "gateway TLS control peer is not the configured controller");
        }
        return -EACCES;
    }
    *actor = peer;
    return 0;
}

static void gateway_result_init(struct wvm_control_result *result,
                                const struct wvm_envelope *request)
{
    memset(result, 0, sizeof(*result));
    memcpy(result->in_reply_to_operation_id, request->operation_id,
           sizeof(result->in_reply_to_operation_id));
    memcpy(result->record_digest, request->semantic_payload_digest,
           sizeof(result->record_digest));
    result->vm_id = request->vm_id;
    result->vm_incarnation = request->vm_incarnation;
    result->manifest_generation = request->manifest_generation;
    result->route_scope_id = request->route_scope_id;
}

static int gateway_route_key_matches_request(
    const struct wvm_envelope *request,
    const struct wvm_route_snapshot_key *key)
{
    return request && key &&
           request->route_scope_id == key->scope_key.route_scope_id &&
           request->topology_revision == key->topology_revision &&
           request->route_generation == key->route_generation &&
           memcmp(request->route_snapshot_digest, key->snapshot_digest,
                  sizeof(key->snapshot_digest)) == 0;
}

static int gateway_route_control_apply(
    void *context, const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor,
    struct wvm_control_result *result, char *error, size_t error_len)
{
    struct wvm_route_control_result route_result;

    (void)context;
    if (!request || !result) {
        if (error && error_len != 0) {
            snprintf(error, error_len, "gateway route control request is invalid");
        }
        return -EINVAL;
    }
    gateway_result_init(result, request);
    if (!gateway_member_equal(authenticated_actor,
                              &g_route_control_authentication.controller) ||
        request->origin_physical_node_id !=
            g_route_control_authentication.controller_physical_node_id ||
        request->origin_runtime_instance_id !=
            g_route_control_authentication.controller_runtime_instance_id) {
        result->status_code = WVM_CONTROL_RESULT_UNAUTHORIZED_ROLE;
        return 0;
    }
    if (request->message_type != WVM_ENVELOPE_MSG_ROUTE_PREPARE &&
        request->message_type != WVM_ENVELOPE_MSG_ROUTE_COMMIT &&
        request->message_type != WVM_ENVELOPE_MSG_ROUTE_ABORT &&
        request->message_type != WVM_ENVELOPE_MSG_ROUTE_RETIRE) {
        result->status_code = WVM_CONTROL_RESULT_UNSUPPORTED;
        return 0;
    }
    memset(&route_result, 0, sizeof(route_result));
    if (wvm_route_control_apply(&g_route_control, request, &route_result,
                                error, error_len) != 0) {
        result->status_code = control_status_from_error(error);
        return 0;
    }
    if (!gateway_route_key_matches_request(
            request, &route_result.route_snapshot_key)) {
        if (error && error_len != 0) {
            snprintf(error, error_len,
                     "gateway route result does not match request snapshot");
        }
        result->status_code = WVM_CONTROL_RESULT_PRECONDITION_FAILED;
        return 0;
    }
    result->recorded_state = route_result.recorded_state;
    result->applied_revision = route_result.route_snapshot_key.route_generation;
    result->expiry_or_retention_deadline =
        route_result.operation_retention_horizon_ms;
    result->status_code = WVM_CONTROL_RESULT_SUCCESS;
    return 0;
}

static int gateway_parse_control_endpoint(
    struct wvm_endpoint *endpoint, char *error, size_t error_len)
{
    const char *address_text = getenv("WVM_GATEWAY_CONTROL_ADDRESS");
    const char *port_text = getenv("WVM_GATEWAY_CONTROL_PORT");
    const char *data_address_text = getenv("WVM_GATEWAY_DATA_ADDRESS");
    struct in_addr address;
    uint64_t control_port;
    const char *data_address = data_address_text && data_address_text[0]
                                   ? data_address_text
                                   : address_text;

    if (!endpoint || !address_text || !port_text || !data_address ||
        inet_pton(AF_INET, address_text, &address) != 1 ||
        inet_pton(AF_INET, data_address, &address) != 1 ||
        gateway_parse_u64(port_text, &control_port) != 0 ||
        control_port > UINT16_MAX || g_local_port <= 0 ||
        g_local_port > UINT16_MAX) {
        if (error && error_len != 0) {
            snprintf(error, error_len,
                     "gateway TLS control endpoint configuration is invalid");
        }
        return -EINVAL;
    }
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_port = (uint16_t)g_local_port;
    if (inet_pton(AF_INET, data_address, endpoint->data_address) != 1 ||
        inet_pton(AF_INET, address_text, endpoint->control_address) != 1) {
        return -EINVAL;
    }
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->has_control_address = 1;
    endpoint->control_address_bytes = 4;
    endpoint->control_port = (uint16_t)control_port;
    return 0;
}

static int init_route_control_from_environment(void)
{
    const char *journal_path = getenv("WVM_GATEWAY_ROUTE_JOURNAL_PATH");
    const char *socket_path = getenv("WVM_GATEWAY_CONTROL_SOCKET");
    const char *controller_role = getenv("WVM_GATEWAY_CONTROLLER_ROLE");
    const char *controller_id = getenv("WVM_GATEWAY_CONTROLLER_ID");
    const char *controller_instance =
        getenv("WVM_GATEWAY_CONTROLLER_INSTANCE_ID");
    const char *controller_physical_node =
        getenv("WVM_GATEWAY_CONTROLLER_PHYSICAL_NODE_ID");
    const char *controller_runtime_instance =
        getenv("WVM_GATEWAY_CONTROLLER_RUNTIME_INSTANCE_ID");
    const char *tls_ca = getenv("WVM_GATEWAY_CONTROL_CA_FILE");
    const char *tls_certificate = getenv("WVM_GATEWAY_CONTROL_CERTIFICATE_FILE");
    const char *tls_private_key = getenv("WVM_GATEWAY_CONTROL_PRIVATE_KEY_FILE");
    uint64_t parsed_physical_node_id;
    uint64_t parsed_controller_id;
    uint64_t parsed_controller_instance;
    uint64_t parsed_controller_physical_node;
    uint64_t parsed_controller_runtime_instance;
    enum wvm_manifest_role_type parsed_controller_role;
    struct wvm_control_owner_config owner_config;
    char error[256] = {0};
    int tls_configuration_count;

    if (!journal_path || journal_path[0] == '\0' ||
        !socket_path || socket_path[0] == '\0') {
        fprintf(stderr,
                "[Gateway] active route control requires a journal and socket\n");
        return -EINVAL;
    }
    if (!g_route_runtime_ready) {
        wvm_route_runtime_init(&g_route_runtime);
        g_route_runtime_ready = 1;
    }
    {
        char error[256] = {0};

        if (wvm_route_control_open(&g_route_control, &g_route_runtime,
                                   journal_path, error, sizeof(error)) != 0) {
            fprintf(stderr, "[Gateway] route control journal rejected: %s\n",
                    error[0] ? error : "invalid journal");
            return -EINVAL;
        }
    }
    g_route_control_ready = 1;
    if (strlen(socket_path) >= sizeof(g_route_control_socket_path) ||
        parse_u64_env("WVM_GATEWAY_ID", &parsed_physical_node_id) != 0 ||
        parsed_physical_node_id > UINT32_MAX ||
        parse_u64_env("WVM_GATEWAY_INSTANCE_ID",
                      &g_route_control_instance_id) != 0) {
        fprintf(stderr,
                "[Gateway] V1 control listener identity or socket path is "
                "invalid\n");
        wvm_route_control_close(&g_route_control);
        g_route_control_ready = 0;
        return -EINVAL;
    }
    g_route_control_physical_node_id = (uint32_t)parsed_physical_node_id;
    snprintf(g_route_control_socket_path, sizeof(g_route_control_socket_path),
             "%s", socket_path);

    tls_configuration_count = (tls_ca && tls_ca[0] != '\0') +
                              (tls_certificate && tls_certificate[0] != '\0') +
                              (tls_private_key && tls_private_key[0] != '\0');
    if (!controller_role || !controller_id || !controller_instance ||
        !controller_physical_node || !controller_runtime_instance ||
        gateway_parse_role(controller_role, &parsed_controller_role) != 0 ||
        gateway_parse_u64(controller_id, &parsed_controller_id) != 0 ||
        parsed_controller_id > UINT32_MAX ||
        gateway_parse_u64(controller_instance, &parsed_controller_instance) != 0 ||
        gateway_parse_u64(controller_physical_node,
                          &parsed_controller_physical_node) != 0 ||
        parsed_controller_physical_node > UINT32_MAX ||
        gateway_parse_u64(controller_runtime_instance,
                          &parsed_controller_runtime_instance) != 0 ||
        tls_configuration_count != 3 ||
        gateway_parse_control_endpoint(&g_route_control_network_endpoint,
                                       error, sizeof(error)) != 0) {
        fprintf(stderr,
                "[Gateway] active route control requires a complete "
                "authenticated TLS/controller configuration: %s\n",
                error[0] ? error : "invalid controller identity");
        wvm_route_control_close(&g_route_control);
        g_route_control_ready = 0;
        return -EINVAL;
    }
    memset(&g_route_control_authentication, 0,
           sizeof(g_route_control_authentication));
    g_route_control_authentication.local_uid = geteuid();
    g_route_control_authentication.controller.role_type = parsed_controller_role;
    g_route_control_authentication.controller.role_id =
        (uint32_t)parsed_controller_id;
    g_route_control_authentication.controller.instance_id =
        parsed_controller_instance;
    g_route_control_authentication.controller_physical_node_id =
        (uint32_t)parsed_controller_physical_node;
    g_route_control_authentication.controller_runtime_instance_id =
        parsed_controller_runtime_instance;
    memset(&owner_config, 0, sizeof(owner_config));
    owner_config.socket_path = g_route_control_socket_path;
    owner_config.network_endpoint = &g_route_control_network_endpoint;
    owner_config.tls_ca_file = tls_ca;
    owner_config.tls_certificate_file = tls_certificate;
    owner_config.tls_private_key_file = tls_private_key;
    owner_config.socket_mode = S_IRUSR | S_IWUSR;
    owner_config.listen_backlog = 16;
    owner_config.local_physical_node_id = g_route_control_physical_node_id;
    owner_config.local_runtime_instance_id = g_route_control_instance_id;
    owner_config.max_frame_bytes = WVM_CONTROL_TRANSPORT_DEFAULT_MAX_FRAME_BYTES;
    owner_config.authenticate = gateway_authenticate_unix;
    owner_config.authenticate_io = gateway_authenticate_tls;
    owner_config.authenticate_opaque = &g_route_control_authentication;
    owner_config.admission_apply = gateway_route_control_apply;
    owner_config.admission_apply_opaque = &g_route_control;
    if (wvm_control_owner_init(&g_route_control_owner, &owner_config, error,
                               sizeof(error)) != 0 ||
        wvm_control_owner_start(&g_route_control_owner, error,
                                sizeof(error)) != 0) {
        fprintf(stderr, "[Gateway] route control owner failed: %s\n",
                error[0] ? error : "cannot start authenticated listener");
        wvm_control_owner_destroy(&g_route_control_owner);
        wvm_route_control_close(&g_route_control);
        g_route_control_ready = 0;
        return -EINVAL;
    }
    fprintf(stderr,
            "[Gateway] authenticated route control socket=%s port=%u\n",
            g_route_control_socket_path,
            (unsigned)g_route_control_network_endpoint.control_port);
    return 0;
}

/* 
 * [物理意图] 注入“静态初始坐标”，作为 P2P 网络启动时的引航灯。
 * [关键逻辑] 解析配置文件中的 ROUTE 范围指令，一次性预热数千个虚拟节点的路由条目，避免运行时的哈希抖动。
 * [后果] 提供了系统的“初始稳定性”。若配置加载错误，节点启动后的 Gossip 宣告将无法找到正确的上游网关。
 */
static int load_slave_config(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) { perror("Config open"); return -1; }
    
    char line[256];
    int routes_loaded = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        
        char keyword[16];
        // 仅支持 ROUTE 指令
        if (sscanf(line, "%15s", keyword) != 1) continue;
        
        if (strcmp(keyword, "ROUTE") == 0) {
            uint32_t start_id, count;
            char ip_str[64];
            int port;
            
            // 格式: ROUTE <StartVID> <Count> <IP> <Port>
            if (sscanf(line, "%*s %u %u %63s %d", &start_id, &count, ip_str, &port) == 4) {
                // 展开路由聚合
                for (uint32_t i = 0; i < count; i++) {
                    uint32_t current_id = start_id + i;
                    if (g_route_vm_id != 0) {
                        current_id = WVM_ENCODE_ID(g_route_vm_id, current_id);
                    }
                    gateway_node_t *node = find_or_create_node(current_id);
                    if (node) {
                        node->addr.sin_family = AF_INET;
                        node->addr.sin_addr.s_addr = inet_addr(ip_str);
                        node->addr.sin_port = htons(port);
                        node->static_pinned = 1;
                    }
                }
                routes_loaded++;
            }
        }
    }
    fclose(fp);
    printf("[Gateway] Loaded %d route groups.\n", routes_loaded);
    return 0;
}

// Sends a raw datagram to a specific downstream node address.
// [FIX-M8] 快照 node->addr 防止与 learn_route 竞争导致部分读取
static int raw_send_to_downstream(int fd, gateway_node_t *node, void *data, int len) {
    if (!node) return -EHOSTUNREACH;
    struct sockaddr_in addr_snap;
    pthread_mutex_lock(&node->lock);
    addr_snap = node->addr;
    pthread_mutex_unlock(&node->lock);
    if (addr_snap.sin_port == 0) return -EHOSTUNREACH;
    return sendto(fd, data, len, MSG_DONTWAIT, (struct sockaddr*)&addr_snap, sizeof(addr_snap));
}

/* 
 * [物理意图] 将积压的“内存小波”正式投射到物理光纤。
 * [关键逻辑] 检查聚合缓冲区，将多个子包封装为一个 MTU 大小的 UDP 数据包，并执行非阻塞发送。
 * [后果] 它解决了分布式内存的“PPS 爆炸”问题。通过牺牲极微小的延迟换取了巨大的带宽利用率，防止了网卡软中断打死 CPU。
 */
static int flush_buffer(int fd, gateway_node_t *node) {
    if (!node || !node->buffer || node->buffer->current_len == 0) return 0;

    // [FIX] 直接 sendto，不调 raw_send_to_downstream，调用方已持有 node->lock
    // raw_send_to_downstream 内部会再次 lock node->lock 导致递归死锁
    struct sockaddr_in addr_snap = node->addr;
    int ret = (addr_snap.sin_port == 0) ? -EHOSTUNREACH :
              sendto(fd, node->buffer->raw_data, node->buffer->current_len,
                     MSG_DONTWAIT, (struct sockaddr*)&addr_snap, sizeof(addr_snap));

    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return -1; // Network congested, tell caller to keep data.
        }
        // For other fatal errors, we still clear the buffer to prevent resending bad data.
    }

    node->buffer->current_len = 0;
    return 0;
}

/* 
 * [物理意图] 模拟硬件控制器的“指数退避”机制，防止网络雪崩。
 * [关键逻辑] 根据尝试次数执行三级等待：1. CPU 忙等 (pause)；2. 软让权 (nanosleep)；3. 深度睡眠 (usleep)。
 * [后果] 这是针对云环境（如 K8s）的关键优化。它防止了网关在网络拥塞时，通过疯狂轮询耗尽物理 CPU 的配额。
 */
static void smart_backoff(int attempts) {
    // 场景 A: 单核机器 / 极度受限容器
    // 没有任何资本进行忙等，必须立即把 CPU 让给 QEMU 进程
    if (g_is_single_core) {
        sched_yield(); 
        return;
    }

    // 场景 B: 多核高性能机器
    if (attempts < 1000) {
        // 阶段 1: CPU 忙等 (约 1-2us)
        // 保持 CPU 流水线热度，赌网卡马上这就好
        #if defined(__x86_64__) || defined(__i386__)
            __asm__ volatile("pause");
        #elif defined(__aarch64__)
            __asm__ volatile("yield");
        #endif
    } else if (attempts < 2000) {
        // 阶段 2: 软让出 (约 0-10us)
        // nanosleep(0) 会触发调度检查，如果没有更高优先级任务，立即返回
        struct timespec ts = {0, 0};
        nanosleep(&ts, NULL);
    } else {
        // 阶段 3: 认怂 (1ms+)
        // 网络彻底堵死，必须睡久一点防止烧干 CPU Quota
        usleep(1);
    }
}

/* 
 * [物理意图] 实现“零拷贝转发”与“聚合转发”的智能分流。
 * [关键逻辑] 1. 小包入队聚合；2. 超过 MTU 的大包（如全页同步）直接穿透（Passthrough）绕过缓冲区。
 * [后果] 这一步保证了包序的“因果一致性”。它确保了全量更新包不会被后续的小增量包在网关缓冲区内超越。
 */
static int internal_push(int fd, uint32_t slave_id, void *data, int len) {
    // 1. 读锁保护查找，防止与动态路由更新冲突
    pthread_rwlock_rdlock(&g_map_lock);
    gateway_node_t *node = find_node(slave_id);
    if (!node) {
        pthread_rwlock_unlock(&g_map_lock);
        { static int __nf=0; if (__nf < 10) { fprintf(stderr, "[GW-PUSH] node NOT FOUND sid=%u\n", slave_id); __nf++; } }
        return -1;
    }
    
    // 2. 获取节点级互斥锁，随后释放全局读锁
    pthread_mutex_lock(&node->lock);
    pthread_rwlock_unlock(&g_map_lock); 

    // [FIXED] 大包透传逻辑 (Pass-through)
    // 防止缓冲区溢出，并解决大包死循环重试问题
    if (len > MTU_SIZE) {
        // A. 为了保序，必须先冲刷掉 Buffer 里已有的积压数据
        if (node->buffer && node->buffer->current_len > 0) {
            // 尝试冲刷，如果网络拥塞失败，返回 EBUSY 让上层退避重试
            // 不能丢弃旧数据，否则包序会乱
            if (flush_buffer(fd, node) != 0) {
                pthread_mutex_unlock(&node->lock);
                return -EBUSY; 
            }
        }
        
        // B. 缓冲区已空，直接发送大包 (绕过 Buffer)
        pthread_mutex_unlock(&node->lock);
        int ret = raw_send_to_downstream(fd, node, data, len);
        if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return -EBUSY;
        return ret; // 返回发送结果 (可能 EAGAIN)
    }


    // [FIX] VCPU_RUN/EXIT bypass aggregation buffer (latency-sensitive sync RPC)
    // Single RPC packet (740B < MTU 1400) would stall in buffer waiting to fill up
    if (len >= (int)sizeof(struct wvm_header)) {
        struct wvm_header *hdr = (struct wvm_header *)data;
        uint16_t mt = ntohs(hdr->msg_type);
        if (mt == MSG_VCPU_RUN || mt == MSG_VCPU_EXIT) {
            if (node->buffer && node->buffer->current_len > 0) {
                flush_buffer(fd, node);
            }
            pthread_mutex_unlock(&node->lock);
            int vcpu_ret = raw_send_to_downstream(fd, node, data, len);
            { static int __vcpu_push=0;
              if (__vcpu_push < 30) {
                  char dst_ip[16]={0}; unsigned dst_port=0;
                  pthread_mutex_lock(&node->lock);
                  inet_ntop(AF_INET, &node->addr.sin_addr, dst_ip, sizeof(dst_ip));
                  dst_port = ntohs(node->addr.sin_port);
                  pthread_mutex_unlock(&node->lock);
                  fprintf(stderr, "[GW-VCPU-PUSH] sid=%u mt=%u len=%d dst=%s:%u ret=%d errno=%d\n",
                          slave_id, mt, len, dst_ip, dst_port, vcpu_ret, (vcpu_ret<0)?errno:0);
                  __vcpu_push++;
              }
            }
            return vcpu_ret;
        }
    }

    // --- 常规小包聚合逻辑 ---
    
    // Lazy allocation
    if (node->buffer == NULL) {
        node->buffer = (slave_buffer_t*)malloc(sizeof(slave_buffer_t));
        if (node->buffer) {
            node->buffer->current_len = 0;
        } else {
            pthread_mutex_unlock(&node->lock);
            return -ENOMEM;
        }
    }
    
    // 缓冲区满？冲刷。
    if (node->buffer->current_len + len > MTU_SIZE) {
        if (flush_buffer(fd, node) != 0) {
            pthread_mutex_unlock(&node->lock);
            return -EBUSY; 
        }
    }
    
    // 安全拷贝 (此时 len <= MTU 且 buffer 有空间)
    memcpy(node->buffer->raw_data + node->buffer->current_len, data, len);
    node->buffer->current_len += len;

    // 高性能即时冲刷阈值 (85%)
    if (node->buffer->current_len > (MTU_SIZE * 0.85)) {
        flush_buffer(fd, node);
    }

    pthread_mutex_unlock(&node->lock);
    return 0;
}

extern void internal_process_single_packet(struct wvm_header *hdr, uint32_t src_ip);

int push_to_aggregator(uint32_t slave_id, void *data, int len) {
    extern int g_my_node_id;

    if (g_primary_socket < 0) return -1;
    return internal_push(g_primary_socket, slave_id, data, len);
}

void flush_all_buffers(void) {
    gateway_node_t *current_node, *tmp;
    static uint64_t last_big = 0;
    static uint64_t last_small = 0;
    static uint64_t tick = 0;
    static int printed = 0;

    // Low-noise RX visibility (once per ~1s) to verify big packets reach the gateway.
    if ((++tick % 1000) == 0) {
        uint64_t big = g_rx_big_count;
        uint64_t small = g_rx_small_count;
        if (big != last_big || small != last_small || printed < 3) {
            fprintf(stderr, "[Gateway] rx-stats big=%llu small=%llu\n",
                    (unsigned long long)big, (unsigned long long)small);
            last_big = big;
            last_small = small;
            if (printed < 3) printed++;
        }
    }

    if (g_primary_socket < 0) return;

    // [FIX] 必须加读锁保护遍历过程！
    // 虽然 HASH_ITER 本身较慢，但这是保证不崩的唯一方法
    pthread_rwlock_rdlock(&g_map_lock);
    
    HASH_ITER(hh, g_node_map, current_node, tmp) {
        // 注意：这里需要获取节点锁。
        // 锁序：MapLock(Read) -> NodeLock(Mutex) 是安全的，不会死锁
        pthread_mutex_lock(&current_node->lock);
        flush_buffer(g_primary_socket, current_node);
        pthread_mutex_unlock(&current_node->lock);
    }
    
    pthread_rwlock_unlock(&g_map_lock);

}

/* 
 * [物理意图] 实现无中心网络的“身份识别”与“路由热修复”。
 * [关键逻辑] 监听并捕获所有入站流量，自动提取源 ID 与物理 IP。若发现邻居坐标变更，立即更新路由表。
 * [后果] 这是 WaveVM 能够支撑百万节点的奥秘。它不再依赖人工配置，而是通过“谁发包，我认识谁”实现拓扑的自动收敛。
 */
static void learn_route(uint32_t slave_id, struct sockaddr_in *addr) {
    if (g_route_authority_active) {
        return;
    }
    // [FIX] 环境变量禁用 learn_route（用于 L2 等中间网关，防止转发包覆写静态路由）
    static int disabled = -1;
    if (disabled == -1) disabled = (getenv("WVM_GATEWAY_DISABLE_LEARN_ROUTE") != NULL);
    if (disabled) return;

    // 1. 快速检查：如果已有路由且未变，直接返回 (无锁读)
    gateway_node_t *node = NULL;
    pthread_rwlock_rdlock(&g_map_lock);
    HASH_FIND_INT(g_node_map, &slave_id, node);
    if (node) {
        // [FIX] static_pinned no longer blocks learn_route.
        // Sidecar gateways seed static routes pointing upstream (L1A),
        // but local masters announce themselves at runtime.  Without this
        // override the sidecar never learns the real local path and packets
        // loop between sidecar ↔ L1 forever, causing RPC Type-5 timeouts.
        if (node->addr.sin_addr.s_addr == addr->sin_addr.s_addr &&
            node->addr.sin_port == addr->sin_port) {
            pthread_rwlock_unlock(&g_map_lock);
            return; // 路由稳定，无需更新
        }
    }
    pthread_rwlock_unlock(&g_map_lock);

    // 2. 变更或新增：获取写锁进行更新
    // [FIX] trywrlock 防止与 flush_all_buffers 的 rdlock 死锁
    if (pthread_rwlock_trywrlock(&g_map_lock) != 0) {
        // 锁竞争，跳过本次更新，下次包到达时再试
        return;
    }
    // Double check
    HASH_FIND_INT(g_node_map, &slave_id, node);
    if (!node) {
        // [FIX-M9] Do NOT create new route entries via auto-learning.
        // L2 sidecar gateways must only know the nodes in their ROUTE config;
        // creating new entries here would let L2 bypass L1 for cross-node traffic.
        // Only update addresses for nodes that already exist (seeded by config).
        pthread_rwlock_unlock(&g_map_lock);
        return;
    }

    if (node) {
        /*
         * static_pinned routes may only be updated by well-known service ports.
         * Local masters announce from 19100/19200; transit packets often arrive
         * from ephemeral upstream sockets and must not overwrite static routes.
         */
        if (node->static_pinned && ntohs(addr->sin_port) >= 32768) {
            pthread_rwlock_unlock(&g_map_lock);
            return;
        }
        // [FIX-M8] 同时持有 node->lock 保护 addr 写入，与读端保持一致
        pthread_mutex_lock(&node->lock);
        node->addr = *addr;
        pthread_mutex_unlock(&node->lock);
        // printf("[Gateway-Auto] Updated Route Node: %u\n", slave_id);
    }
    pthread_rwlock_unlock(&g_map_lock);
}

/* 
 * [物理意图] 打造一台“软件定义的万兆交换机”。
 * [关键逻辑] 利用 CPU 亲和性将 Worker 绑定到特定核心，配合 recvmmsg 进行零拷贝接收与自学习路由分发。
 * [后果] 这是网关的“物理引擎”。其吞吐能力直接决定了超级虚拟机的总线带宽，必须保持极简逻辑以规避 Cache Miss。
 */
static void* gateway_worker(void *arg) {
    long core_id = (long)arg;
    int local_fd;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    int cpu = pick_allowed_cpu_index(core_id);
    CPU_SET(cpu, &cpuset);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
        fprintf(stderr, "[Gateway] Warning: Could not set CPU affinity for worker %ld (cpu=%d)\n", core_id, cpu);
    }

    local_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (local_fd < 0) {
        perror("[Gateway] Worker socket create failed");
        return NULL;
    }
    {
        int rp = 0;
        socklen_t rpl = sizeof(rp);
        if (getsockopt(local_fd, SOL_SOCKET, SO_REUSEPORT, &rp, &rpl) == 0) {
            fprintf(stderr, "[Gateway] sockfd=%d reuseport=%d\n", local_fd, rp);
        }
    }

    int opt = 1;
    setsockopt(local_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (!g_disable_reuseport) {
        setsockopt(local_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    }
    
    struct sockaddr_in bind_addr = { .sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY, .sin_port = htons(g_local_port) };
    if (bind(local_fd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
        fprintf(stderr, "[Gateway] Worker bind failed port=%u errno=%d\n",
                (unsigned)g_local_port, errno);
        close(local_fd);
        return NULL;
    } else if (core_id == 0) {
        struct sockaddr_in laddr;
        socklen_t laddr_len = sizeof(laddr);
        if (getsockname(local_fd, (struct sockaddr*)&laddr, &laddr_len) == 0) {
            fprintf(stderr, "[Gateway] bind ok port=%u fd=%d local=%s:%u\n",
                    (unsigned)g_local_port,
                    local_fd,
                    inet_ntoa(laddr.sin_addr),
                    (unsigned)ntohs(laddr.sin_port));
        } else {
            fprintf(stderr, "[Gateway] bind ok port=%u fd=%d\n",
                    (unsigned)g_local_port, local_fd);
        }
    }

    if (core_id == 0) {
        g_primary_socket = local_fd;
    }

    struct mmsghdr msgs[BATCH_SIZE] = {0};
    struct iovec iovecs[BATCH_SIZE] = {0};
    struct sockaddr_in src_addrs[BATCH_SIZE] = {0};
    uint8_t *buffer_pool = malloc(BATCH_SIZE * WVM_MAX_PACKET_SIZE);
    if (!buffer_pool) {
        perror("[Gateway] Worker buffer_pool alloc failed");
        close(local_fd);
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

    packet_queue_t q_big, q_small;
    gateway_queue_arg_t qa_big, qa_small;
    pthread_t th_big, th_small;
    int mq_ok = 0;
    if (g_multi_queue) {
        queue_init(&q_big);
        queue_init(&q_small);
        qa_big.local_fd = local_fd; qa_big.q = &q_big;
        qa_small.local_fd = local_fd; qa_small.q = &q_small;
        if (pthread_create(&th_big, NULL, gateway_queue_consumer, &qa_big) == 0 &&
            pthread_create(&th_small, NULL, gateway_queue_consumer, &qa_small) == 0) {
            mq_ok = 1;
        } else {
            fprintf(stderr, "[Gateway] multi-queue init failed, fallback to inline\n");
            mq_ok = 0;
        }
    }

    while (1) {
        if (g_use_recvfrom) {
            socklen_t slen = sizeof(struct sockaddr_in);
            int pkt_len = recvfrom(local_fd, buffer_pool, WVM_MAX_PACKET_SIZE, g_nonblock_recv ? MSG_DONTWAIT : 0,
                                   (struct sockaddr *)&src_addrs[0], &slen);
            if (pkt_len <= 0) {
                if (errno == EINTR) continue;
                if (g_nonblock_recv && (errno == EAGAIN || errno == EWOULDBLOCK)) { usleep(100); continue; }
                if (core_id == 0) {
                    int rxq = get_rxq_bytes(local_fd);
                    fprintf(stderr, "[Gateway] recvfrom err=%d rxq=%d\n", errno, rxq);
                }
                continue;
            }
            if (mq_ok) {
                packet_node_t *n = malloc(sizeof(*n));
                uint8_t *copy = malloc(pkt_len);
                if (n && copy) {
                    memcpy(copy, buffer_pool, pkt_len);
                    n->len = pkt_len;
                    n->data = copy;
                    n->src = src_addrs[0];
                    if (pkt_len >= WVM_BIG_PKT_THRESHOLD) {
                        queue_push(&q_big, n);
                    } else {
                        queue_push(&q_small, n);
                    }
                } else {
                    if (n) free(n);
                    if (copy) free(copy);
                }
            } else {
                gateway_process_packet(local_fd, buffer_pool, pkt_len, &src_addrs[0]);
            }
            continue;
        }

        /* recvmsg writes these fields; restore their input values per batch. */
        for (int i = 0; i < BATCH_SIZE; i++) {
            msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
            msgs[i].msg_hdr.msg_flags = 0;
            msgs[i].msg_len = 0;
        }
        int recv_flags = g_nonblock_recv ? MSG_DONTWAIT : MSG_WAITFORONE;
        int n = recvmmsg(local_fd, msgs, BATCH_SIZE, recv_flags, NULL);
        if (n <= 0) {
            if (errno == EINTR) continue;
                if (g_nonblock_recv && (errno == EAGAIN || errno == EWOULDBLOCK)) { usleep(100); continue; }
            if (core_id == 0) {
                int rxq = get_rxq_bytes(local_fd);
                fprintf(stderr, "[Gateway] recvmmsg err=%d rxq=%d\n", errno, rxq);
            }
            continue; 
        }

        if (mq_ok) {
            for (int i = 0; i < n; i++) {
                uint8_t *ptr = (uint8_t *)iovecs[i].iov_base;
                int pkt_len = msgs[i].msg_len;
                packet_node_t *node = malloc(sizeof(*node));
                uint8_t *copy = malloc(pkt_len);
                if (node && copy) {
                    memcpy(copy, ptr, pkt_len);
                    node->len = pkt_len;
                    node->data = copy;
                    node->src = src_addrs[i];
                    if (pkt_len >= WVM_BIG_PKT_THRESHOLD) {
                        queue_push(&q_big, node);
                    } else {
                        queue_push(&q_small, node);
                    }
                } else {
                    if (node) free(node);
                    if (copy) free(copy);
                }
            }
        } else {
            int big_idx[BATCH_SIZE];
            int small_idx[BATCH_SIZE];
            int nb = 0, ns = 0;
            for (int i = 0; i < n; i++) {
                if ((int)msgs[i].msg_len >= WVM_BIG_PKT_THRESHOLD) {
                    big_idx[nb++] = i;
                } else {
                    small_idx[ns++] = i;
                }
            }
            for (int k = 0; k < nb; k++) {
                int i = big_idx[k];
                uint8_t *ptr = (uint8_t *)iovecs[i].iov_base;
                int pkt_len = msgs[i].msg_len;
                struct sockaddr_in *src = &src_addrs[i];
                gateway_process_packet(local_fd, ptr, pkt_len, src);
            }
            for (int k = 0; k < ns; k++) {
                int i = small_idx[k];
                uint8_t *ptr = (uint8_t *)iovecs[i].iov_base;
                int pkt_len = msgs[i].msg_len;
                struct sockaddr_in *src = &src_addrs[i];
                gateway_process_packet(local_fd, ptr, pkt_len, src);
            }
        }
    }
    free(buffer_pool);
    return NULL;
}

// [PATCH] 新增控制协议定义
typedef struct {
    uint32_t magic;      // 0x57564D43 "WVMC" (WaveVM Control)
    uint16_t op_code;    // 1 = ADD_ROUTE, 2 = DEL_ROUTE
    uint32_t node_id;    // 目标虚拟节点 ID
    uint32_t ip;         // 网络序 IP
    uint16_t port;       // 网络序 Port
} __attribute__((packed)) wvm_gateway_ctrl_pkt;

/* 
 * [物理意图] 提供“上帝视角”的外部干预入口，处理大规模机柜级扩容。
 * [关键逻辑] 在 9001 独立控制端口（可自行配置)上监听 WVMC 指令，通过写锁（Wrlock）强制注入跨 Pod 的联邦路由。
 * [后果] 实现了分形架构的层级级联。通过此接口，自动化运维工具可以将分散的 Pod 编织成一个巨大的戴森球算力网。
 */
void dynamic_add_route(uint32_t node_id, uint32_t ip, uint16_t port) {
    if (g_route_authority_active) {
        fprintf(stderr,
                "[Gateway] rejected legacy dynamic route for active snapshot "
                "node=%u\n", node_id);
        return;
    }
    // 1. 获取写锁 (独占，会暂停所有数据转发微秒级时间)
    pthread_rwlock_wrlock(&g_map_lock);
    
    gateway_node_t *node = NULL;
    HASH_FIND_INT(g_node_map, &node_id, node);
    
    if (!node) {
        node = (gateway_node_t*)calloc(1, sizeof(gateway_node_t));
        if (node) {
            node->id = node_id;
            node->static_pinned = 1;
            pthread_mutex_init(&node->lock, NULL); // 节点内部的Buffer锁保持Mutex
            node->buffer = NULL; 
            HASH_ADD_INT(g_node_map, id, node);
        }
    }
    
    if (node) {
        pthread_mutex_lock(&node->lock);
        node->static_pinned = 1;
        node->addr.sin_family = AF_INET;
        node->addr.sin_addr.s_addr = ip;
        node->addr.sin_port = port;
        pthread_mutex_unlock(&node->lock);
        printf("[Gateway] Route Added/Updated: Node %u -> %s:%d\n", 
               node_id, inet_ntoa(node->addr.sin_addr), ntohs(port));
    }
    
    pthread_rwlock_unlock(&g_map_lock);
    struct timespec ts = {0, 1000}; // 1000 ns = 1 us
    nanosleep(&ts, NULL);
}

// [PATCH] 控制平面监听线程
static void* control_plane_thread(void *arg) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return NULL;
    struct sockaddr_in addr = { 
        .sin_family = AF_INET, 
        .sin_addr.s_addr = INADDR_ANY, 
        .sin_port = htons(g_ctrl_port) 
    };

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[Gateway] FATAL: Control plane bind failed (Port occupied?)");
        exit(1); // 端口冲突直接退出
    }
    
    printf("[Gateway] Control Plane Active on Port %d (Static)\n", g_ctrl_port);
    
    wvm_gateway_ctrl_pkt pkt;
    while (1) {
        ssize_t n = recv(sockfd, &pkt, sizeof(pkt), 0);
        if (n == sizeof(pkt) && ntohl(pkt.magic) == WVM_CTRL_MAGIC) {
            if (ntohs(pkt.op_code) == 1) { // ADD / UPDATE
                dynamic_add_route(ntohl(pkt.node_id), pkt.ip, pkt.port);
            } 
        }
    }
    return NULL;
}

static uint16_t control_status_from_error(const char *error)
{
    if (!error || error[0] == '\0') {
        return WVM_CONTROL_RESULT_INTERNAL_FAILURE;
    }
    if (strstr(error, "unsupported") || strstr(error, "unknown")) {
        return WVM_CONTROL_RESULT_UNSUPPORTED;
    }
    if (strstr(error, "payload") || strstr(error, "record") ||
        strstr(error, "envelope")) {
        return WVM_CONTROL_RESULT_INVALID_REQUEST;
    }
    if (strstr(error, "conflict")) {
        return WVM_CONTROL_RESULT_OPERATION_ID_CONFLICT;
    }
    return WVM_CONTROL_RESULT_PRECONDITION_FAILED;
}

int init_aggregator(int local_port, const char *upstream_ip, int upstream_port, const char *config_path) {
    if (g_primary_socket >= 0) return 0;

    g_local_port = local_port;
    g_force_single_rx = (getenv("WVM_GATEWAY_SINGLE_RX") != NULL);
    g_disable_reuseport = (getenv("WVM_GATEWAY_DISABLE_REUSEPORT") != NULL);
    g_use_recvfrom = (getenv("WVM_GATEWAY_USE_RECVFROM") != NULL);
    g_nonblock_recv = (getenv("WVM_NONBLOCK_RECV") != NULL);
    {
        uint64_t vm_id;

        if (parse_u64_env("WVM_VM_ID", &vm_id) == 0 &&
            vm_id <= UINT32_MAX) {
            g_route_vm_id = (uint32_t)vm_id;
        }
    }
    {
        const char *mq = getenv("WVM_GATEWAY_MULTI_QUEUE");
        if (mq && mq[0] == '0') g_multi_queue = 0;
    }
    if (getenv("WVM_RUNTIME_GATE_ACTIVE") &&
        strcmp(getenv("WVM_RUNTIME_GATE_ACTIVE"), "0") != 0) {
        const char *snapshot_path =
            getenv("WVM_RUNTIME_ROUTE_SNAPSHOT_PATH");

        if (init_route_control_from_environment() != 0 ||
            !snapshot_path || snapshot_path[0] == '\0' ||
            init_route_runtime_from_snapshot_file(snapshot_path) != 0) {
            fprintf(stderr,
                    "[Gateway] active runtime requires a valid route "
                    "snapshot path\n");
            return -EINVAL;
        }
    } else {
        if (load_slave_config(config_path) != 0) return -ENOENT;
        if (init_route_runtime_from_environment() != 0) return -EINVAL;
    }
    if (g_route_authority_active && tx_scheduler_start() != 0) {
        fprintf(stderr, "[Gateway] cannot start V1 transmit scheduler\n");
        return -ENOMEM;
    }

    g_upstream_addr.sin_family = AF_INET;
    g_upstream_addr.sin_addr.s_addr = inet_addr(upstream_ip);
    g_upstream_addr.sin_port = htons(upstream_port); 

    // 单独的 upstream 发送 fd，避免复用 worker 的接收 fd 在某些环境下出现回环发送异常。
    g_upstream_tx_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_upstream_tx_socket < 0) {
        perror("[Gateway] upstream tx socket create failed");
        return -1;
    }
    int tx_flags = fcntl(g_upstream_tx_socket, F_GETFL, 0);
    if (tx_flags >= 0) {
        fcntl(g_upstream_tx_socket, F_SETFL, tx_flags | O_NONBLOCK);
    }

    long num_cores = get_nprocs();
    g_allowed_cpus = count_allowed_cpus();
    // [FIX] Reserve 1 core for main thread (flush_all_buffers loop + control plane).
    // Without this, the last worker's CPU affinity collides with main, causing futex
    // deadlock in internal_push → its SO_REUSEPORT socket accumulates unread packets
    // and ~25% of traffic silently drops.
    long base = (g_allowed_cpus > 0) ? g_allowed_cpus : num_cores;
    long num_workers = (base > 1) ? base - 1 : 1;
    if (g_force_single_rx && num_workers > 1) {
        num_workers = 1;
    }
    g_force_single_fd = (getenv("WVM_GATEWAY_FORCE_SINGLE_FD") != NULL);
    printf("[Gateway] System has %ld cores (allowed=%d). Scaling out %ld RX workers...\n",
           num_cores, g_allowed_cpus, num_workers);
    if (g_disable_reuseport || g_force_single_rx || g_use_recvfrom || g_force_single_fd) {
        printf("[Gateway] Debug RX opts: single=%d disable_reuseport=%d recvfrom=%d single_fd=%d\n",
               g_force_single_rx, g_disable_reuseport, g_use_recvfrom, g_force_single_fd);
    }

    if (g_force_single_fd) {
        // Run a single receiver on the current thread with core_id=0 and prevent other sockets.
        g_force_single_rx = 1;
        g_disable_reuseport = 1;
        gateway_worker((void*)0);
        return 0;
    }
    for (long i = 0; i < num_workers; i++) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, gateway_worker, (void*)i) != 0) {
            perror("[Gateway] Failed to create worker thread");
            return -1;
        }
        pthread_detach(thread);
    }

    detect_cpu_env();
    
    pthread_t ctrl_tid;
    if (!g_route_authority_active &&
        pthread_create(&ctrl_tid, NULL, control_plane_thread, NULL) == 0) {
        pthread_detach(ctrl_tid);
    }

    return 0;}
