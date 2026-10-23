/*
 * §6 R1: short instruction on a RUNNING admitted TCG helper (real QEMU -accel wavevm).
 * Writes mov eax,imm32; hlt into shared guest RAM, sends MSG_VCPU_RUN (mode_tcg=1)
 * to the hybrid TCG PROXY UDP port (production path + reply demux), checks EAX in
 * VCPU_EXIT. Also verifies SHM R/W marker.
 *
 * Usage: s6_dataplane_tcg_run SHM_PATH EXECUTOR_PORT VM_ID MARKER_HEX [GPA=0x2000]
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include "wavevm_config.h"
#include "wavevm_protocol.h"
#include "crc32.h"

/* QEMU DESC_* bits (target/i386/cpu.h) for real-mode segments. */
#define DESC_P_MASK   (1u << 15)
#define DESC_S_MASK   (1u << 12)
#define DESC_CS_MASK  (1u << 11)
#define DESC_R_MASK   (1u << 9)
#define DESC_W_MASK   (1u << 9)
#define DESC_A_MASK   (1u << 8)
#define SEG_FLAGS_CODE16 (DESC_P_MASK | DESC_S_MASK | DESC_CS_MASK | DESC_R_MASK | DESC_A_MASK)
#define SEG_FLAGS_DATA16 (DESC_P_MASK | DESC_S_MASK | DESC_W_MASK | DESC_A_MASK)

static void encode_mov_eax_hlt(uint8_t *page, uint32_t marker)
{
    memset(page, 0x90, 64);
    page[0] = 0x66; /* operand-size override → mov eax,imm32 in 16-bit CS */
    page[1] = 0xB8;
    memcpy(&page[2], &marker, sizeof(marker));
    page[6] = 0xF4; /* hlt */
}

static void fill_realmode_tcg(wvm_tcg_context_t *ctx, uint64_t gpa, uint32_t marker)
{
    int i;
    memset(ctx, 0, sizeof(*ctx));
    ctx->eip = gpa;
    ctx->eflags = 0x2;
    ctx->regs[0] = 0; /* EAX */
    ctx->regs[4] = gpa + 0x1000; /* ESP */
    ctx->cr[0] = 0x60000010ULL; /* PE clear */
    ctx->a20_mask = 0xffffffffu;
    ctx->mp_state = 0;
    for (i = 0; i < 6; i++) {
        ctx->segs[i].base = 0;
        ctx->segs[i].limit = 0xffff;
        ctx->segs[i].selector = 0;
        ctx->segs[i].flags = (i == 1) ? SEG_FLAGS_CODE16 : SEG_FLAGS_DATA16; /* CS=1 */
    }
    ctx->ldt.limit = 0xffff;
    ctx->tr.limit = 0xffff;
    ctx->tr.flags = DESC_P_MASK | (0xbu << 8); /* busy TSS16-ish present */
    ctx->gdt_limit = 0xffff;
    ctx->idt_limit = 0xffff;
    (void)marker;
}

int main(int argc, char **argv)
{
    const char *shm_path;
    unsigned port;
    unsigned vm_id;
    unsigned long marker;
    unsigned long gpa = 0x2000;
    char *end = NULL;
    int shm_fd = -1;
    uint8_t *ram = MAP_FAILED;
    size_t ram_size = 0;
    struct stat st;
    int sock = -1;
    struct sockaddr_in dst, src;
    struct wvm_header hdr;
    struct wvm_ipc_cpu_run_req req;
    uint8_t *tx = NULL;
    uint8_t *rx = NULL;
    size_t tx_len, rx_cap;
    ssize_t n;
    struct wvm_header *rh;
    struct wvm_ipc_cpu_run_ack *ack;
    uint32_t got_eax;

    if (argc < 5 || argc > 6) {
        fprintf(stderr,
                "usage: %s SHM_PATH EXECUTOR_PORT VM_ID MARKER_HEX [GPA]\n",
                argv[0]);
        return 2;
    }
    shm_path = argv[1];
    port = (unsigned)strtoul(argv[2], &end, 10);
    if (!end || *end || port == 0 || port > 65535) {
        fprintf(stderr, "bad port\n");
        return 2;
    }
    vm_id = (unsigned)strtoul(argv[3], &end, 10);
    if (!end || *end || vm_id == 0) {
        fprintf(stderr, "bad vm_id\n");
        return 2;
    }
    marker = strtoul(argv[4], &end, 0);
    if (!end || *end || marker > 0xffffffffUL) {
        fprintf(stderr, "bad marker\n");
        return 2;
    }
    if (argc == 6) {
        gpa = strtoul(argv[5], &end, 0);
        if (!end || *end) {
            fprintf(stderr, "bad gpa\n");
            return 2;
        }
    }

    shm_fd = open(shm_path, O_RDWR);
    if (shm_fd < 0) {
        perror("open shm");
        return 1;
    }
    if (fstat(shm_fd, &st) != 0 || st.st_size < (off_t)(gpa + 64)) {
        fprintf(stderr, "shm too small size=%lld\n", (long long)st.st_size);
        close(shm_fd);
        return 1;
    }
    ram_size = (size_t)st.st_size;
    ram = mmap(NULL, ram_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (ram == MAP_FAILED) {
        perror("mmap shm");
        close(shm_fd);
        return 1;
    }

    {
        uint8_t *m = ram + gpa + 32;
        uint8_t before = *m;
        *m = (uint8_t)(0xA5 ^ (marker & 0xff));
        if (*m != (uint8_t)(0xA5 ^ (marker & 0xff))) {
            fprintf(stderr, "shm write verify failed\n");
            return 1;
        }
        printf("shm_rw=ok gpa=0x%lx before=0x%02x after=0x%02x\n", gpa + 32,
               before, *m);
    }

    encode_mov_eax_hlt(ram + gpa, (uint32_t)marker);
    printf("code_at_gpa=0x%lx bytes=%02x %02x %02x%02x%02x%02x %02x\n", gpa,
           ram[gpa], ram[gpa + 1], ram[gpa + 2], ram[gpa + 3], ram[gpa + 4],
           ram[gpa + 5], ram[gpa + 6]);
    /* Ensure visibility before remote QEMU reads the same SHM mapping. */
    __sync_synchronize();

    memset(&req, 0, sizeof(req));
    req.mode_tcg = 1;
    req.slave_id = WVM_ENCODE_ID((uint8_t)vm_id, 0);
    req.vcpu_index = 0;
    fill_realmode_tcg(&req.ctx.tcg, gpa, (uint32_t)marker);

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = htonl(WVM_MAGIC);
    hdr.msg_type = htons(MSG_VCPU_RUN);
    hdr.payload_len = htons(sizeof(req));
    hdr.slave_id = htonl(WVM_ENCODE_ID(99, 1));
    hdr.target_id = htonl(WVM_NODE_AUTO_ROUTE);
    {
        /* Unique per process — QEMU ack-cache must not replay a prior EXIT. */
        uint64_t rid = (0x53640000ULL << 16) ^ ((uint64_t)getpid() << 16) ^
                       (uint64_t)(marker & 0xffffu) ^ ((uint64_t)time(NULL) & 0xffffu);
        if (rid == 0) rid = 0x53645401ULL;
        hdr.req_id = WVM_HTONLL(rid);
        printf("req_id=0x%llx\n", (unsigned long long)rid);
    }
    hdr.qos_level = 1;
    hdr.mode_tcg = 1;

    tx_len = sizeof(hdr) + sizeof(req);
    tx = calloc(1, tx_len);
    rx_cap = sizeof(hdr) + sizeof(struct wvm_ipc_cpu_run_ack) + 64;
    rx = calloc(1, rx_cap);
    if (!tx || !rx) {
        fprintf(stderr, "oom\n");
        return 1;
    }
    memcpy(tx, &hdr, sizeof(hdr));
    memcpy(tx + sizeof(hdr), &req, sizeof(req));
    {
        struct wvm_header *th = (struct wvm_header *)tx;
        th->crc32 = 0;
        th->crc32 = htonl(calculate_crc32(tx, tx_len));
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    memset(&src, 0, sizeof(src));
    src.sin_family = AF_INET;
    src.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    src.sin_port = htons(0);
    if (bind(sock, (struct sockaddr *)&src, sizeof(src)) != 0) {
        perror("bind");
        return 1;
    }
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons((uint16_t)port);

    if (sendto(sock, tx, tx_len, 0, (struct sockaddr *)&dst, sizeof(dst)) !=
        (ssize_t)tx_len) {
        perror("sendto VCPU_RUN");
        return 1;
    }
    printf("sent_vcpu_run bytes=%zu port=%u\n", tx_len, port);

    {
        struct timeval tv = {.tv_sec = 8, .tv_usec = 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    n = recvfrom(sock, rx, rx_cap, 0, NULL, NULL);
    if (n < (ssize_t)(sizeof(*rh) + sizeof(*ack))) {
        fprintf(stderr, "recv VCPU_EXIT failed n=%zd errno=%d\n", n, errno);
        return 1;
    }
    rh = (struct wvm_header *)rx;
    if (ntohl(rh->magic) != WVM_MAGIC || ntohs(rh->msg_type) != MSG_VCPU_EXIT) {
        fprintf(stderr, "bad reply magic/type magic=%08x type=%u\n",
                ntohl(rh->magic), ntohs(rh->msg_type));
        return 1;
    }
    ack = (struct wvm_ipc_cpu_run_ack *)(rx + sizeof(*rh));
    got_eax = (uint32_t)ack->ctx.tcg.regs[0];
    printf("vcpu_exit status=%d mode_tcg=%u eax=0x%x expected=0x%lx halted=%u "
           "eip=0x%llx\n",
           ack->status, ack->mode_tcg, got_eax, marker, ack->ctx.tcg.halted,
           (unsigned long long)ack->ctx.tcg.eip);
    if (ack->status != 0) {
        fprintf(stderr, "VCPU_EXIT status=%d\n", ack->status);
        return 1;
    }
    if (got_eax != (uint32_t)marker) {
        fprintf(stderr, "EAX mismatch (got 0x%x want 0x%lx)\n", got_eax, marker);
        return 1;
    }
    printf("tcg_short_exec=PASS marker=0x%lx\n", marker);
    munmap(ram, ram_size);
    close(shm_fd);
    close(sock);
    free(tx);
    free(rx);
    return 0;
}
