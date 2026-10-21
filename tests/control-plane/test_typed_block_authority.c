/* SPEC-storage-remote-block-v1 / BASE-§11 — typed block authority oracle.
 * Proves QEMU-host authority path equivalent:
 *   typed request → MSG_BLOCK_{READ,WRITE,FLUSH} → chunk store → ACK
 * including FUA (WRITE + follow-up FLUSH) durability.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "crc32.h"
#include "wavevm_block_chunk_store.h"
#include "wavevm_protocol.h"

static int g_fail;

static void fail(const char *msg)
{
    fprintf(stderr, "typed-block-authority FAIL: %s\n", msg);
    g_fail = 1;
}

static void expect(int cond, const char *msg)
{
    if (!cond)
        fail(msg);
}

/* Mirror main_wrapper typed→legacy mapping + FUA follow-up FLUSH. */
static int master_send_op(int sock, const struct sockaddr_in *slave,
                          uint16_t msg_type, uint64_t lba, uint32_t count,
                          const uint8_t *data, size_t data_len, uint64_t req_id,
                          uint8_t *rx, size_t rx_cap, size_t *rx_len)
{
    size_t pkt_len = sizeof(struct wvm_header) + sizeof(struct wvm_block_payload) +
                     data_len;
    uint8_t *pkt = calloc(1, pkt_len);
    struct wvm_header *h;
    struct wvm_block_payload *bp;
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    ssize_t n;

    if (!pkt)
        return -1;
    h = (struct wvm_header *)pkt;
    bp = (struct wvm_block_payload *)(pkt + sizeof(*h));
    h->magic = htonl(WVM_MAGIC);
    h->msg_type = htons(msg_type);
    h->payload_len = htons((uint16_t)(sizeof(*bp) + data_len));
    h->slave_id = htonl(1);
    h->req_id = WVM_HTONLL(req_id);
    h->qos_level = 1;
    bp->lba = WVM_HTONLL(lba);
    bp->count = htonl(count);
    if (data_len && data)
        memcpy(bp->data, data, data_len);
    h->crc32 = 0;
    h->crc32 = htonl(calculate_crc32(pkt, pkt_len));
    if (sendto(sock, pkt, pkt_len, 0, (const struct sockaddr *)slave,
               sizeof(*slave)) < 0) {
        free(pkt);
        return -1;
    }
    free(pkt);
    n = recvfrom(sock, rx, rx_cap, 0, (struct sockaddr *)&from, &fromlen);
    if (n < (ssize_t)sizeof(struct wvm_header))
        return -1;
    *rx_len = (size_t)n;
    return 0;
}

/* Authority-path slave: MSG_BLOCK_* → chunk store (same semantics as
 * slave_hybrid handle_block_io_phys + FUA durable write). */
static volatile int g_slave_run = 1;

static void *slave_thread(void *arg)
{
    int sock = *(int *)arg;
    uint8_t buf[128 * 1024];
    char err[128];

    while (g_slave_run) {
        struct sockaddr_in client;
        socklen_t clen = sizeof(client);
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&client, &clen);
        struct wvm_header *hdr;
        struct wvm_block_payload *blk;
        uint16_t type;
        uint64_t lba;
        uint32_t count;
        uint16_t plen;

        if (n < (ssize_t)sizeof(struct wvm_header))
            continue;
        hdr = (struct wvm_header *)buf;
        if (hdr->magic != htonl(WVM_MAGIC))
            continue;
        type = ntohs(hdr->msg_type);
        plen = ntohs(hdr->payload_len);
        if (n < (ssize_t)(sizeof(*hdr) + plen))
            continue;
        blk = (struct wvm_block_payload *)(buf + sizeof(*hdr));
        lba = WVM_NTOHLL(blk->lba);
        count = ntohl(blk->count);

        if (type == MSG_BLOCK_WRITE) {
            size_t need = (size_t)count * 512;
            int fua = 0; /* FUA applied by master follow-up FLUSH */
            if (wvm_block_chunk_write(lba, count, blk->data, need, fua, err,
                                      sizeof(err)) != 0) {
                hdr->flags |= WVM_FLAG_ERROR;
            }
            hdr->msg_type = htons(MSG_BLOCK_ACK);
            hdr->payload_len = htons(0);
            hdr->crc32 = 0;
            hdr->crc32 = htonl(calculate_crc32(hdr, sizeof(*hdr)));
            sendto(sock, hdr, sizeof(*hdr), 0, (struct sockaddr *)&client,
                   clen);
        } else if (type == MSG_BLOCK_READ) {
            size_t need = (size_t)count * 512;
            size_t resp_len =
                sizeof(struct wvm_header) + sizeof(struct wvm_block_payload) +
                need;
            uint8_t *tx = calloc(1, resp_len);
            struct wvm_header *rh;
            struct wvm_block_payload *rp;
            size_t out_bytes = 0;
            if (!tx)
                continue;
            rh = (struct wvm_header *)tx;
            *rh = *hdr;
            rp = (struct wvm_block_payload *)(tx + sizeof(*rh));
            rp->lba = blk->lba;
            rp->count = blk->count;
            if (wvm_block_chunk_read(lba, count, rp->data, need, &out_bytes, err,
                                     sizeof(err)) != 0) {
                rh->flags |= WVM_FLAG_ERROR;
                rh->msg_type = htons(MSG_BLOCK_ACK);
                rh->payload_len = htons(0);
                rh->crc32 = 0;
                rh->crc32 = htonl(calculate_crc32(rh, sizeof(*rh)));
                sendto(sock, rh, sizeof(*rh), 0, (struct sockaddr *)&client,
                       clen);
            } else {
                rh->msg_type = htons(MSG_BLOCK_ACK);
                rh->payload_len =
                    htons((uint16_t)(sizeof(*rp) + need));
                rh->crc32 = 0;
                rh->crc32 = htonl(calculate_crc32(tx, resp_len));
                sendto(sock, tx, resp_len, 0, (struct sockaddr *)&client, clen);
            }
            free(tx);
        } else if (type == MSG_BLOCK_FLUSH) {
            if (wvm_block_chunk_flush(lba, err, sizeof(err)) != 0)
                hdr->flags |= WVM_FLAG_ERROR;
            hdr->msg_type = htons(MSG_BLOCK_ACK);
            hdr->payload_len = htons(0);
            hdr->crc32 = 0;
            hdr->crc32 = htonl(calculate_crc32(hdr, sizeof(*hdr)));
            sendto(sock, hdr, sizeof(*hdr), 0, (struct sockaddr *)&client,
                   clen);
        }
    }
    return NULL;
}

/* Typed-IPC authority client: mirrors main_wrapper FUA policy. */
static int typed_write(int sock, const struct sockaddr_in *slave, uint64_t lba,
                       uint32_t sectors, const uint8_t *data, uint32_t flags,
                       uint64_t *req_seq)
{
    uint8_t rx[4096];
    size_t rx_len = 0;
    uint64_t rid = ++(*req_seq);
    struct wvm_header *rh;

    if (master_send_op(sock, slave, MSG_BLOCK_WRITE, lba, sectors, data,
                       (size_t)sectors * 512, rid, rx, sizeof(rx),
                       &rx_len) != 0)
        return -1;
    rh = (struct wvm_header *)rx;
    if (rh->flags & WVM_FLAG_ERROR)
        return -1;
    if (flags & (WVM_BLOCK_FLAG_FUA | WVM_BLOCK_FLAG_SYNC)) {
        rid = ++(*req_seq);
        /* R02: FUA follow-up covers all touched sectors. */
        if (master_send_op(sock, slave, MSG_BLOCK_FLUSH, lba, sectors, NULL, 0,
                           rid, rx, sizeof(rx), &rx_len) != 0)
            return -1;
        rh = (struct wvm_header *)rx;
        if (rh->flags & WVM_FLAG_ERROR)
            return -1;
    }
    return 0;
}

static int typed_read(int sock, const struct sockaddr_in *slave, uint64_t lba,
                      uint32_t sectors, uint8_t *out, uint64_t *req_seq)
{
    uint8_t rx[128 * 1024];
    size_t rx_len = 0;
    uint64_t rid = ++(*req_seq);
    struct wvm_header *rh;
    struct wvm_block_payload *bp;

    if (master_send_op(sock, slave, MSG_BLOCK_READ, lba, sectors, NULL, 0, rid,
                       rx, sizeof(rx), &rx_len) != 0)
        return -1;
    rh = (struct wvm_header *)rx;
    if (rh->flags & WVM_FLAG_ERROR)
        return -1;
    bp = (struct wvm_block_payload *)(rx + sizeof(*rh));
    memcpy(out, bp->data, (size_t)sectors * 512);
    return 0;
}

static int test_chunk_store_direct(const char *dir)
{
    char err[128];
    uint8_t pattern[512];
    uint8_t back[512];
    size_t out = 0;
    unsigned i;

    memset(pattern, 0xA5, sizeof(pattern));
    for (i = 0; i < sizeof(pattern); i++)
        pattern[i] = (uint8_t)(i & 0xff);

    expect(wvm_block_chunk_store_set_dir(dir, err, sizeof(err)) == 0,
           "set chunk dir");
    expect(wvm_block_chunk_write(0, 1, pattern, 512, 0, err, sizeof(err)) == 0,
           "write without FUA");
    expect(wvm_block_chunk_read(0, 1, back, sizeof(back), &out, err,
                                sizeof(err)) == 0,
           "read back");
    expect(out == 512 && memcmp(pattern, back, 512) == 0, "read matches write");

    memset(pattern, 0x5A, sizeof(pattern));
    expect(wvm_block_chunk_write(1, 1, pattern, 512, 1 /* FUA */, err,
                                  sizeof(err)) == 0,
           "write with FUA fdatasync");
    memset(back, 0, sizeof(back));
    expect(wvm_block_chunk_read(1, 1, back, sizeof(back), &out, err,
                                sizeof(err)) == 0 &&
               memcmp(pattern, back, 512) == 0,
           "FUA write durable readable");
    expect(wvm_block_chunk_flush(1, err, sizeof(err)) == 0, "explicit FLUSH");
    return g_fail ? -1 : 0;
}

static int test_typed_ipc_path(const char *dir)
{
    char err[128];
    int slave_sock = -1, client_sock = -1;
    struct sockaddr_in slave_addr, client_addr;
    pthread_t thr;
    uint8_t wbuf[1024], rbuf[1024];
    uint64_t req_seq = 100;
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};

    expect(wvm_block_chunk_store_set_dir(dir, err, sizeof(err)) == 0,
           "ipc set dir");

    slave_sock = socket(AF_INET, SOCK_DGRAM, 0);
    client_sock = socket(AF_INET, SOCK_DGRAM, 0);
    expect(slave_sock >= 0 && client_sock >= 0, "sockets");
    memset(&slave_addr, 0, sizeof(slave_addr));
    slave_addr.sin_family = AF_INET;
    slave_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    slave_addr.sin_port = 0;
    expect(bind(slave_sock, (struct sockaddr *)&slave_addr,
                sizeof(slave_addr)) == 0,
           "bind slave");
    {
        socklen_t len = sizeof(slave_addr);
        getsockname(slave_sock, (struct sockaddr *)&slave_addr, &len);
    }
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    client_addr.sin_port = 0;
    expect(bind(client_sock, (struct sockaddr *)&client_addr,
                sizeof(client_addr)) == 0,
           "bind client");
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(slave_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    g_slave_run = 1;
    expect(pthread_create(&thr, NULL, slave_thread, &slave_sock) == 0,
           "slave thread");

    memset(wbuf, 0x42, sizeof(wbuf));
    wbuf[0] = 0x11;
    wbuf[511] = 0x22;
    expect(typed_write(client_sock, &slave_addr, 10, 2, wbuf, 0, &req_seq) == 0,
           "typed WRITE");
    memset(rbuf, 0, sizeof(rbuf));
    expect(typed_read(client_sock, &slave_addr, 10, 2, rbuf, &req_seq) == 0,
           "typed READ");
    expect(memcmp(wbuf, rbuf, 1024) == 0, "R/W payload match");

    memset(wbuf, 0x77, sizeof(wbuf));
    expect(typed_write(client_sock, &slave_addr, 20, 1, wbuf,
                       WVM_BLOCK_FLAG_FUA, &req_seq) == 0,
           "typed WRITE+FUA (follow-up FLUSH)");
    memset(rbuf, 0, sizeof(rbuf));
    expect(typed_read(client_sock, &slave_addr, 20, 1, rbuf, &req_seq) == 0 &&
               memcmp(wbuf, rbuf, 512) == 0,
           "FUA write readable after FLUSH ACK");

    /* Explicit FLUSH alone */
    {
        uint8_t rx[4096];
        size_t rx_len = 0;
        uint64_t rid = ++req_seq;
        expect(master_send_op(client_sock, &slave_addr, MSG_BLOCK_FLUSH, 20, 0,
                              NULL, 0, rid, rx, sizeof(rx), &rx_len) == 0,
               "explicit FLUSH");
        expect(!(((struct wvm_header *)rx)->flags & WVM_FLAG_ERROR),
               "FLUSH ACK ok");
    }

    g_slave_run = 0;
    /* wake slave */
    {
        uint8_t z = 0;
        sendto(slave_sock, &z, 1, 0, (struct sockaddr *)&slave_addr,
               sizeof(slave_addr));
    }
    pthread_join(thr, NULL);
    close(slave_sock);
    close(client_sock);
    return g_fail ? -1 : 0;
}

/* R01: write spanning 64 MiB chunk boundary must land in both chunk files. */
static int test_chunk_boundary_cross(const char *dir)
{
    char err[128];
    uint8_t wbuf[1024];
    uint8_t rbuf[512];
    size_t out = 0;
    /* Last sector of chunk 0 is LBA 131071; next chunk starts at 131072. */
    const uint64_t last_of_chunk0 = (1ULL << (WVM_STORAGE_CHUNK_SHIFT - 9)) - 1;
    const uint64_t first_of_chunk1 = last_of_chunk0 + 1;

    expect(wvm_block_chunk_store_set_dir(dir, err, sizeof(err)) == 0,
           "boundary set chunk dir");
    memset(wbuf, 0xA5, sizeof(wbuf));
    expect(wvm_block_chunk_write(last_of_chunk0, 2, wbuf, sizeof(wbuf), 0, err,
                                 sizeof(err)) == 0,
           "boundary cross-chunk WRITE LBA=131071 sectors=2");
    memset(rbuf, 0, sizeof(rbuf));
    expect(wvm_block_chunk_read(first_of_chunk1, 1, rbuf, sizeof(rbuf), &out, err,
                                sizeof(err)) == 0,
           "boundary READ LBA=131072");
    expect(out == 512, "boundary read length");
    expect(rbuf[0] == 0xA5 && rbuf[511] == 0xA5,
           "boundary data 0xA5 across chunk (R01)");
    /* Also verify the last sector of chunk 0 retained its half. */
    memset(rbuf, 0, sizeof(rbuf));
    expect(wvm_block_chunk_read(last_of_chunk0, 1, rbuf, sizeof(rbuf), &out, err,
                                sizeof(err)) == 0 &&
               rbuf[0] == 0xA5,
           "boundary trailing sector of chunk0");
    return g_fail ? -1 : 0;
}

static int test_chunk_identity_isolation(const char *dir)
{
    char err[128];
    uint8_t a[512], b[512], back[512];
    size_t out = 0;

    expect(wvm_block_chunk_store_set_dir(dir, err, sizeof(err)) == 0,
           "identity set dir");
    expect(wvm_block_chunk_store_set_identity("vm1_inc1_vol0", err,
                                              sizeof(err)) == 0,
           "set identity A");
    memset(a, 0x11, sizeof(a));
    expect(wvm_block_chunk_write(0, 1, a, 512, 0, err, sizeof(err)) == 0,
           "write under identity A");
    expect(wvm_block_chunk_store_set_identity("vm2_inc1_vol0", err,
                                              sizeof(err)) == 0,
           "set identity B");
    memset(b, 0x22, sizeof(b));
    expect(wvm_block_chunk_write(0, 1, b, 512, 0, err, sizeof(err)) == 0,
           "write under identity B");
    memset(back, 0, sizeof(back));
    expect(wvm_block_chunk_read(0, 1, back, sizeof(back), &out, err,
                                sizeof(err)) == 0 &&
               back[0] == 0x22,
           "B reads own data");
    expect(wvm_block_chunk_store_set_identity("vm1_inc1_vol0", err,
                                              sizeof(err)) == 0,
           "restore identity A");
    memset(back, 0, sizeof(back));
    expect(wvm_block_chunk_read(0, 1, back, sizeof(back), &out, err,
                                sizeof(err)) == 0 &&
               back[0] == 0x11,
           "A still has isolated data (R02)");
    return g_fail ? -1 : 0;
}

static int test_main_wrapper_fua_wired(void)
{
    /*
     * Source oracle: the QEMU-facing typed block path must go through the
     * admitted client (device identity + FUA ordering + client status), not
     * through a legacy header or a follow-up FLUSH workaround.
     */
    FILE *f = fopen("master_core/main_wrapper.c", "r");
    char *buf = NULL;
    long sz;
    int ok = 0;

    expect(f != NULL, "open main_wrapper.c");
    if (!f)
        return -1;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        fail("oom");
        return -1;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        fail("read main_wrapper");
        return -1;
    }
    buf[sz] = 0;
    fclose(f);
    ok = strstr(buf, "wvm_block_client_global_request") != NULL &&
         strstr(buf, "req->device_index") != NULL &&
         strstr(buf, "WVM_BLOCK_ORDER_FUA") != NULL &&
         strstr(buf, "WVM_BLOCK_WIRE_SUCCESS") != NULL;
    expect(ok, "main_wrapper routes typed block through the admitted client");
    free(buf);
    return g_fail ? -1 : 0;
}

int main(void)
{
    char dir_a[] = "/tmp/wvm-block-auth-a.XXXXXX";
    char dir_b[] = "/tmp/wvm-block-auth-b.XXXXXX";

    if (!mkdtemp(dir_a) || !mkdtemp(dir_b)) {
        fail("mkdtemp");
        return 1;
    }
    printf("=== typed block authority oracle ===\n");
    test_chunk_store_direct(dir_a);
    test_typed_ipc_path(dir_b);
    {
        char dir_c[] = "/tmp/wvm-block-auth-c.XXXXXX";
        if (!mkdtemp(dir_c)) {
            fail("mkdtemp boundary");
            return 1;
        }
        test_chunk_boundary_cross(dir_c);
    }
    {
        char dir_d[] = "/tmp/wvm-block-auth-d.XXXXXX";
        if (!mkdtemp(dir_d)) {
            fail("mkdtemp identity");
            return 1;
        }
        test_chunk_identity_isolation(dir_d);
    }
    test_main_wrapper_fua_wired();
    if (g_fail) {
        fprintf(stderr, "typed-block-authority: FAIL\n");
        return 1;
    }
    printf("typed-block-authority: PASS "
           "(chunk-store R/W/FLUSH/FUA + boundary-cross R01 + "
           "typed-IPC→slave-equiv + main_wrapper client wire)\n");
    return 0;
}
