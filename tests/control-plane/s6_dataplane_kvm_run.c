/*
 * §6 R1: short instruction on a RUNNING admitted KVM child.
 * Writes mov eax,imm32; hlt into shared guest RAM, sends non-empty
 * MSG_VCPU_RUN to the child's executor UDP port (production path),
 * checks RAX in VCPU_EXIT ACK. Also verifies SHM R/W marker.
 *
 * Usage: s6_dataplane_kvm_run SHM_PATH EXECUTOR_PORT VM_ID MARKER_HEX [GPA=0x2000]
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
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include "wavevm_config.h"
#include "wavevm_protocol.h"
#include "crc32.h"

static void encode_mov_eax_hlt(uint8_t *page, uint32_t marker)
{
    /* 32-bit protected-mode: mov eax,imm32; hlt */
    memset(page, 0x90, 64);
    page[0] = 0xB8;
    memcpy(&page[1], &marker, sizeof(marker));
    page[5] = 0xF4;
}

static void fill_flat_prot32_sregs(uint8_t sregs_data[512])
{
    /*
     * Flat 32-bit protected mode — more reliable under KVM than real-mode
     * entry (which hit KVM_EXIT_FAIL_ENTRY=9 with unrestricted_guest=Y).
     */
    struct kvm_sregs sregs;
    memset(&sregs, 0, sizeof(sregs));
    sregs.cs.selector = 0x8;
    sregs.cs.base = 0;
    sregs.cs.limit = 0xffffffffu;
    sregs.cs.type = 0xb; /* code, read, accessed */
    sregs.cs.present = 1;
    sregs.cs.dpl = 0;
    sregs.cs.db = 1; /* 32-bit */
    sregs.cs.s = 1;
    sregs.cs.l = 0;
    sregs.cs.g = 1;
    sregs.ds = sregs.cs;
    sregs.ds.selector = 0x10;
    sregs.ds.type = 0x3; /* data, r/w, accessed */
    sregs.es = sregs.ds;
    sregs.ss = sregs.ds;
    sregs.fs = sregs.ds;
    sregs.gs = sregs.ds;
    sregs.tr.selector = 0x18;
    sregs.tr.base = 0;
    sregs.tr.limit = 0xffff;
    sregs.tr.type = 0xb; /* busy 32-bit TSS */
    sregs.tr.present = 1;
    sregs.tr.s = 0;
    sregs.ldt.unusable = 1;
    sregs.gdt.base = 0;
    sregs.gdt.limit = 0xffff;
    sregs.idt.base = 0;
    sregs.idt.limit = 0xffff;
    sregs.cr0 = 0x60000011ULL; /* PE | CD | NW */
    sregs.cr4 = 0;
    sregs.efer = 0;
    memcpy(sregs_data, &sregs, sizeof(sregs) < 512 ? sizeof(sregs) : 512);
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
    uint8_t tx[sizeof(hdr) + sizeof(req)];
    uint8_t rx[sizeof(hdr) + sizeof(struct wvm_ipc_cpu_run_ack) + 64];
    ssize_t n;
    struct wvm_header *rh;
    struct wvm_ipc_cpu_run_ack *ack;
    uint32_t got_rax;

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

    /* Memory R/W proof on SHM (version/dirty surface for cell evidence). */
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
    printf("code_at_gpa=0x%lx bytes=%02x %02x%02x%02x%02x %02x\n", gpa,
           ram[gpa], ram[gpa + 1], ram[gpa + 2], ram[gpa + 3], ram[gpa + 4],
           ram[gpa + 5]);

    memset(&req, 0, sizeof(req));
    req.mode_tcg = 0;
    req.slave_id = WVM_ENCODE_ID((uint8_t)vm_id, 0);
    req.vcpu_index = 0;
    req.ctx.kvm.rax = 0;
    req.ctx.kvm.rbx = 0;
    req.ctx.kvm.rcx = 0;
    req.ctx.kvm.rdx = 0;
    req.ctx.kvm.rsi = 0;
    req.ctx.kvm.rdi = 0;
    req.ctx.kvm.rsp = gpa + 0x1000;
    req.ctx.kvm.rbp = 0;
    req.ctx.kvm.rip = gpa;
    req.ctx.kvm.rflags = 0x2;
    fill_flat_prot32_sregs(req.ctx.kvm.sregs_data);

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = htonl(WVM_MAGIC);
    hdr.msg_type = htons(MSG_VCPU_RUN);
    hdr.payload_len = htons(sizeof(req));
    hdr.slave_id = htonl(WVM_ENCODE_ID(99, 1)); /* probe as foreign requester */
    hdr.target_id = htonl(WVM_NODE_AUTO_ROUTE);
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t rid = 0x536450000000ULL |
                       (((uint64_t)ts.tv_nsec) & 0xffffffULL) |
                       ((((uint64_t)getpid()) & 0xffULL) << 24);
        hdr.req_id = WVM_HTONLL(rid);
        printf("req_id=0x%llx\n", (unsigned long long)rid);
    }
    hdr.qos_level = 1;
    hdr.mode_tcg = 0;

    memcpy(tx, &hdr, sizeof(hdr));
    memcpy(tx + sizeof(hdr), &req, sizeof(req));
    {
        struct wvm_header *th = (struct wvm_header *)tx;
        th->crc32 = 0;
        th->crc32 = htonl(calculate_crc32(tx, sizeof(tx)));
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

    if (sendto(sock, tx, sizeof(tx), 0, (struct sockaddr *)&dst,
               sizeof(dst)) != (ssize_t)sizeof(tx)) {
        perror("sendto VCPU_RUN");
        return 1;
    }

    {
        struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    n = recvfrom(sock, rx, sizeof(rx), 0, NULL, NULL);
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
    {
        uint64_t want = WVM_NTOHLL(((struct wvm_header *)tx)->req_id);
        uint64_t got = WVM_NTOHLL(rh->req_id);
        if (got != want) {
            fprintf(stderr, "reply req_id mismatch want=0x%llx got=0x%llx\n",
                    (unsigned long long)want, (unsigned long long)got);
            return 1;
        }
        printf("reply_req_id_match=1 req_id=0x%llx\n", (unsigned long long)got);
    }
    ack = (struct wvm_ipc_cpu_run_ack *)(rx + sizeof(*rh));
    got_rax = (uint32_t)ack->ctx.kvm.rax;
    printf("vcpu_exit status=%d mode_tcg=%u rax=0x%x expected=0x%lx\n",
           ack->status, ack->mode_tcg, got_rax, marker);
    if (ack->status != 0) {
        fprintf(stderr, "VCPU_EXIT status=%d\n", ack->status);
        return 1;
    }
    if (got_rax != (uint32_t)marker) {
        fprintf(stderr, "RAX mismatch (got 0x%x want 0x%lx) — empty FastAck?\n",
                got_rax, marker);
        return 1;
    }
    printf("kvm_short_exec=PASS marker=0x%lx\n", marker);
    munmap(ram, ram_size);
    close(shm_fd);
    close(sock);
    return 0;
}
