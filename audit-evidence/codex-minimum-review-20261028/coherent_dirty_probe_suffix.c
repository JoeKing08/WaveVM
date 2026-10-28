int main(int argc, char **argv) {
    uint8_t snapshot[4096];
    int remaining = 0;
    bool stale = argc > 1 && strcmp(argv[1], "stale") == 0;
    g_mem_blocks[0].hva_start = (uintptr_t)&local_ram[0][0];
    g_mem_blocks[0].size = (stale ? 1 : 33) * 4096;
    for (int i = 0; i < (stale ? 1 : 33); i++) {
        local_versions[i] = directory_versions[i] = 1;
        dirty[i] = true;
        local_ram[i][0] = 1;
    }
    if (stale) {
        directory_versions[0] = 2;
        directory_ram[0][1] = 1;
    }
    int rc = flush_coherent_dirty_bitmap_locked(snapshot);
    for (int i = 0; i < 33; i++) remaining += dirty[i];
    printf("probe=%s return=%d commits=%d remaining_dirty=%d directory_x=%u directory_y=%u\n",
           stale ? "stale" : "budget", rc, commits, remaining,
           directory_ram[0][0], directory_ram[0][1]);
    if (stale) return directory_ram[0][1] == 0 ? 0 : 1;
    return rc == 32 && remaining == 1 ? 0 : 1;
}
