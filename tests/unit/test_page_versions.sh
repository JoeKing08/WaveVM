#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-page-versions.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT
sed -n '/^#define WVM_PAGE_VERSION_BITS/,/^static void safe_log(/p' \
    "$repo_root/wavevm-qemu/accel/wavevm/wavevm-user-mem.c" | sed '$d' \
    >"$tmpdir/page_versions.inc"
cat >"$tmpdir/test.c" <<'EOF'
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#define PAGE_SHIFT 12
#define g_free free
static void *g_malloc0(size_t bytes)
{
    void *p = calloc(1, bytes);
    assert(p);
    return p;
}
#include "page_versions.inc"

static void *writer(void *opaque)
{
    uintptr_t index = (uintptr_t)opaque;
    for (unsigned int page = 0; page < 128; page++) {
        uint64_t gpa = (1ULL << 48) + (page * 4 + index) * 4096;
        set_local_page_version(gpa, index * 128 + page + 1);
    }
    return NULL;
}

int main(void)
{
    uint64_t addresses[] = {0, 1ULL << 32, 1ULL << 40, 1ULL << 63,
                            UINT64_MAX & ~4095ULL};
    pthread_t threads[4];
    for (unsigned int i = 0; i < 5; i++) {
        assert(get_local_page_version(addresses[i]) == 0);
        set_local_page_version(addresses[i], i + 13);
    }
    for (unsigned int i = 0; i < 5; i++)
        assert(get_local_page_version(addresses[i]) == i + 13);
    set_local_page_version(addresses[1], 0);
    assert(get_local_page_version(0) == 13);
    for (uintptr_t i = 0; i < 4; i++)
        assert(pthread_create(&threads[i], NULL, writer, (void *)i) == 0);
    for (unsigned int i = 0; i < 4; i++)
        assert(pthread_join(threads[i], NULL) == 0);
    for (unsigned int i = 0; i < 4; i++)
        for (unsigned int page = 0; page < 128; page++)
            assert(get_local_page_version((1ULL << 48) +
                       (page * 4 + i) * 4096) == i * 128 + page + 1);
    puts("page versions: full-GPA identity / concurrent publication PASS");
}
EOF
gcc -std=gnu11 -Wall -Wextra -Werror -pthread -I"$tmpdir" \
    "$tmpdir/test.c" -o "$tmpdir/test"
"$tmpdir/test"
