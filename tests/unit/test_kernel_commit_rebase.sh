#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-kernel-rebase.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT
sed -n '/^static int wvm_rebase_memory_commit(/,/^static int committer_thread_fn(/p' \
    "$repo_root/master_core/kernel_backend.c" | sed '$d' >"$tmpdir/rebase.inc"
cat >"$tmpdir/test.c" <<'EOF'
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wavevm_ioctl.h"
#define GFP_KERNEL 0
#define kfree free
#define kzalloc(bytes, flags) calloc(1, bytes)
static void *kmemdup(const void *p, size_t n, int flags)
{ void *q = malloc(n); (void)flags; if (q) memcpy(q, p, n); return q; }
struct diff_task_t {
    void *context, *pre_image;
    uint64_t gpa;
    struct wvm_ioctl_memory_operation *operation, *intent;
};
static uint64_t version = 8;
static int fail_read;
static int wvm_memory_call(void *ctx, struct wvm_ioctl_memory_operation *op)
{
    (void)ctx;
    assert(op->kind == WVM_KERNEL_MEMORY_READ && op->gpa == 4096);
    if (fail_read) return -ETIMEDOUT;
    memset(op->data, (int)version, sizeof(op->data));
    op->result_version = version;
    op->data_bytes = sizeof(op->data);
    return 0;
}
#include "rebase.inc"
int main(void)
{
    uint8_t pre[4096] = {0};
    struct wvm_ioctl_memory_operation op = {
        .kind = WVM_KERNEL_MEMORY_COMMIT, .base_version = 7,
        .offset = 17, .data_bytes = 3, .data = {91, 0, 92},
    };
    struct diff_task_t task = {.gpa = 4096, .pre_image = pre, .operation = &op};
    assert(wvm_rebase_memory_commit(&task) == 0);
    assert(op.base_version == 8 && op.data_bytes == 4096 && op.offset == 0);
    assert(op.data[17] == 91 && op.data[18] == 8 && op.data[19] == 92);
    assert(!op.operation_id[0] && op.result_version == 0);
    version = 9; /* Another writer wins again: old merged bytes are not ours. */
    assert(wvm_rebase_memory_commit(&task) == 0);
    assert(op.base_version == 9 && op.data[18] == 9 && op.data[3000] == 9);
    assert(op.data[17] == 91 && op.data[19] == 92);
    fail_read = 1;
    assert(wvm_rebase_memory_commit(&task) == -ETIMEDOUT);
    assert(op.base_version == 9 && op.data[18] == 9);
    free(task.intent);
    puts("kernel commit rebase: original write-set / repeated conflict / failed read PASS");
}
EOF
gcc -std=gnu11 -Wall -Wextra -Werror -I"$repo_root/common_include" \
    -I"$tmpdir" "$tmpdir/test.c" -o "$tmpdir/test"
"$tmpdir/test"
