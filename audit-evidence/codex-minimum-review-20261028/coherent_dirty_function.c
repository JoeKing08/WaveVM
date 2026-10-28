static int flush_coherent_dirty_bitmap_locked(void *current_snapshot)
{
    int committed = 0;
    int first_error = 0;
    int scanned = 0;
    int budget;
    int max_scan;
    const bool use_commit = wavevm_qemu_runtime_gate_enabled();
    static int cursor_bi;
    static uint64_t cursor_off;
    const char *budget_env;
    int bi_start;
    int passes;

    if (!g_tcg_shm_coherent || !current_snapshot) {
        return 0;
    }
    if (g_block_count <= 0) {
        return 0;
    }

    budget = 32;
    budget_env = getenv("WVM_TCG_COHERENT_DIRTY_BUDGET");
    if (budget_env && budget_env[0] != '\0') {
        int v = atoi(budget_env);
        if (v > 0 && v <= 4096) {
            budget = v;
        }
    }
    /* Scan at most this many pages of bitmap per call (clean checks are cheap
     * but still O(RAM) if unbounded — 8k pages ≈ 32MiB window). */
    max_scan = budget * 256;
    if (max_scan < 4096) {
        max_scan = 4096;
    }
    if (max_scan > 65536) {
        max_scan = 65536;
    }

    if (cursor_bi < 0 || cursor_bi >= g_block_count) {
        cursor_bi = 0;
        cursor_off = 0;
    }

    bi_start = cursor_bi;
    passes = 0;
    while (committed < budget && scanned < max_scan && first_error == 0 &&
           passes < g_block_count + 1) {
        GVMRamBlock *blk = &g_mem_blocks[cursor_bi];
        ram_addr_t ram_base = qemu_ram_addr_from_host((void *)blk->hva_start);
        uint64_t off = cursor_off;

        if (ram_base == RAM_ADDR_INVALID || blk->size < 4096) {
            cursor_bi = (cursor_bi + 1) % g_block_count;
            cursor_off = 0;
            passes++;
            if (cursor_bi == bi_start && cursor_off == 0) {
                break;
            }
            continue;
        }

        while (off + 4096 <= blk->size && committed < budget &&
               scanned < max_scan && first_error == 0) {
            ram_addr_t ra = ram_base + off;
            uint64_t gpa;
            void *hva;
            uint64_t base_version;
            int commit_ret;

            scanned++;
            if (!cpu_physical_memory_test_and_clear_dirty(
                    ra, 4096, DIRTY_MEMORY_MIGRATION)) {
                off += 4096;
                continue;
            }
            gpa = blk->gpa_start + off;
            hva = (void *)(blk->hva_start + off);
            if (get_local_page_version(gpa) == 0 && is_page_all_zero(hva)) {
                /* Match master handoff: skip implicit zero dirty bits. */
                off += 4096;
                continue;
            }
            memcpy(current_snapshot, hva, 4096);
            if (use_commit) {
                struct wvm_mem_commit_ack ack;

                base_version = get_local_page_version(gpa);
                if (base_version == 0) {
                    base_version = 1;
                }
                if (t_com_sock < 0) {
                    t_com_sock = internal_connect_master();
                }
                commit_ret = request_commit_on_fd(
                    t_com_sock, gpa, base_version, 0, current_snapshot,
                    WVM_MEMORY_PAGE_BYTES, &ack);
                if (commit_ret == -ENOENT || commit_ret == -ESTALE) {
                    struct wvm_mem_ack mat_ack;
                    uint8_t mat_page[WVM_MEMORY_PAGE_BYTES];
                    int mat_ret = request_page_over_ipc(gpa, &mat_ack, mat_page);
                    if (mat_ret == 0 &&
                        ack_status_to_errno(mat_ack.status) == 0 &&
                        mat_ack.version != 0) {
                        base_version = mat_ack.version;
                        /*
                         * No fault-hook pre-image under coherent SHM: commit
                         * the post-store full page against rematerialized base
                         * (create/replace). Prefer fail-closed over silent skip.
                         */
                        commit_ret = request_commit_on_fd(
                            t_com_sock, gpa, base_version, 0, current_snapshot,
                            WVM_MEMORY_PAGE_BYTES, &ack);
                    }
                }
                if (commit_ret != 0) {
                    cpu_physical_memory_set_dirty_range(
                        ra, 4096, 1 << DIRTY_MEMORY_MIGRATION);
                    first_error = commit_ret;
                    break;
                }
                set_local_page_version(gpa, ack.result_version);
            } else {
                uint64_t ver = get_local_page_version(gpa);
                if (ver == 0) {
                    ver = 1;
                }
                add_to_aggregator(gpa, ver + 1, 0, 4096, current_snapshot, 0);
                set_local_page_version(gpa, ver + 1);
            }
            committed++;
            off += 4096;
        }

        if (off + 4096 > blk->size) {
            cursor_bi = (cursor_bi + 1) % g_block_count;
            cursor_off = 0;
            passes++;
        } else {
            cursor_off = off;
        }
        if (cursor_bi == bi_start && cursor_off == 0 && passes > 0) {
            break;
        }
    }
    if (!use_commit && committed > 0) {
        flush_aggregator();
    }
    return first_error != 0 ? first_error : committed;
}

