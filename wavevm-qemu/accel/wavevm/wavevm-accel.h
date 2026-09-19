#pragma once

#include "qemu/osdep.h"
#include "qom/object.h"
#include "sysemu/accel.h"
#include "qemu/thread.h"

typedef struct CPUState CPUState;

/*
 * Shared WaveVM accelerator definitions (used across wavevm-*.c files).
 * Keep this header minimal: it only defines the accelerator state and
 * identifiers needed by other compilation units.
 */

#define TYPE_WAVEVM_ACCEL "wavevm-accel"
#define WAVEVM_ACCEL(obj) OBJECT_CHECK(WaveVMAccelState, (obj), TYPE_WAVEVM_ACCEL)

typedef enum {
    WVM_MODE_KERNEL,
    WVM_MODE_USER,
} WvmMode;

typedef struct WaveVMAccelState {
    AccelState parent_obj;
    int dev_fd;
    int sync_sock;
    int ipc_sock;
    WvmMode mode;
    QemuThread sync_thread;
    QemuThread ipc_thread;
    QemuThread irq_thread;
    bool sync_thread_running;
    QemuThread net_thread;
    int master_sock;
    int executor_session_fd;
    QemuThread executor_session_thread;

    /* [FIX-F1] Block IO 持久连接：避免每次 IO 都 connect()+pthread_create() 导致线程爆炸 */
    int block_io_sock;               /* 持久 IPC 连接，-1 = 未初始化 */
    QemuMutex block_io_lock;         /* 序列化 Block IO 请求（同一时刻只允许一个 IO 在途） */

    /* Typed block protocol state */
    uint64_t next_block_operation_id;
    QemuMutex block_operation_id_lock;
} WaveVMAccelState;

extern int g_wvm_local_split;

/* Bounded diagnostic for remote TCG handoff stack visibility. */
void wavevm_tcg_log_stack(CPUState *cpu, const char *phase);
