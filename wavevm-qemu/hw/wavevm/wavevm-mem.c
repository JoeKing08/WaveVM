
#include "qemu/osdep.h"
#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "exec/memory.h"
#include "qemu/mmap-alloc.h"
#include "sysemu/kvm.h"

/*
 * Memory Interception for Infinite Scale (V18 - Dirty Log Enabled)
 */

void wavevm_setup_memory_region(MemoryRegion *mr, uint64_t size, int fd) {
    /*
     * Compatibility mode for QEMU 5.2:
     * The RAM region is already initialized by machine creation; reinitializing
     * it with memory_region_init_ram_ptr() can corrupt internal state and crash.
     * Keep existing RAM mapping and let WaveVM hooks operate on that memory.
     */
    (void)mr;
    (void)size;
    (void)fd;
}


/*
 * Attach the user-mode guest RAM to the executor's shared-memory file.  The
 * legacy setup function above is deliberately a no-op because re-running
 * memory_region_init_ram() corrupts QEMU 5.2 state.  Replacing the existing
 * RAMBlock's host mapping with MAP_FIXED is safe after the block is realized:
 * the MemoryRegion keeps its HVA/size, while every guest access now aliases
 * the executor's WVM_SHM_FILE page.  Preserve the reset/BIOS bytes first so
 * this does not turn already-initialized low memory into zeros.
 */
int wavevm_attach_shared_ram_ptr(void *ram, uint64_t size, int fd)
{
    void *shm;
    int dup_fd;

    if (!ram || size == 0 || fd < 0) {
        return -EINVAL;
    }
    dup_fd = dup(fd);
    if (dup_fd < 0) {
        return -errno;
    }
    shm = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, dup_fd, 0);
    if (shm == MAP_FAILED) {
        int err = -errno;
        fprintf(stderr, "[WaveVM-SHM] mmap shared RAM failed: %s\n",
                strerror(errno));
        close(dup_fd);
        return err;
    }
    memcpy(shm, ram, size);
    if (mmap(ram, size, PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_FIXED, dup_fd, 0) == MAP_FAILED) {
        int err = -errno;
        fprintf(stderr, "[WaveVM-SHM] MAP_FIXED guest RAM failed: %s\n",
                strerror(errno));
        munmap(shm, size);
        close(dup_fd);
        return err;
    }
    munmap(shm, size);
    close(dup_fd);
    fprintf(stderr, "[WaveVM-SHM] guest RAM attached gpa=0 size=%#llx hva=%p\n",
            (unsigned long long)size, ram);
    return 0;
}

/*
 * Slave/helper join: map the executor SHM over QEMU's anonymous RAM without
 * copying the zeroed anonymous image into SHM (that would wipe the master's
 * live guest state). Same-host TCG then sees coherent RAM like KVM.
 */
int wavevm_join_shared_ram_ptr(void *ram, uint64_t size, int fd)
{
    int dup_fd;

    if (!ram || size == 0 || fd < 0) {
        return -EINVAL;
    }
    dup_fd = dup(fd);
    if (dup_fd < 0) {
        return -errno;
    }
    if (mmap(ram, size, PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_FIXED, dup_fd, 0) == MAP_FAILED) {
        int err = -errno;
        fprintf(stderr, "[WaveVM-SHM] MAP_FIXED join failed: %s\n",
                strerror(errno));
        close(dup_fd);
        return err;
    }
    close(dup_fd);
    fprintf(stderr,
            "[WaveVM-SHM] guest RAM JOINED (no wipe) gpa=0 size=%#llx hva=%p\n",
            (unsigned long long)size, ram);
    return 0;
}

void wavevm_setup_shared_ram(MemoryRegion *mr, uint64_t size, int fd)
{
    if (!mr) {
        return;
    }
    (void)wavevm_attach_shared_ram_ptr(memory_region_get_ram_ptr(mr), size, fd);
}
