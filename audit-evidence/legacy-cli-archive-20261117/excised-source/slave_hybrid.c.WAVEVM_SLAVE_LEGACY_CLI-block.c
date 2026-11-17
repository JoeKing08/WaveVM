/*
 * F05 / ci_dual_node legacy CLI entry.
 * Production admitted path remains wavevm_executor_runtime_main().
 * Build standalone slave with -DWAVEVM_SLAVE_LEGACY_CLI.
 */
#ifdef WAVEVM_SLAVE_LEGACY_CLI
#include <sys/wait.h>


static int wavevm_legacy_cli_allowed(const char *binary_name)
{
    const char *allow = getenv("WAVEVM_ALLOW_LEGACY_CLI");

    if (allow && allow[0] != '\0' && strcmp(allow, "0") != 0) {
        fprintf(stderr,
                "[LegacyCLI] %s is not the official production entry; "
                "continuing because WAVEVM_ALLOW_LEGACY_CLI is set. "
                "Official entry: scripts/wavevm (wvm_ctl + wavevm_node_runtime).\n",
                binary_name);
        return 1;
    }
    fprintf(stderr,
            "[LegacyCLI] %s is not a supported production entry.\n"
            "The official way to start WaveVM is scripts/wavevm, which launches "
            "ctl_tool/wvm_ctl and wavevm_node_runtime.\n"
            "Independent master/slave CLIs remain in-tree only for historical "
            "non-production harnesses (for example scripts/ci_dual_node.sh).\n"
            "Set WAVEVM_ALLOW_LEGACY_CLI=1 to run this binary anyway.\n",
            binary_name);
    return 0;
}

int main(int argc, char **argv)
{
    char cerr[128];

    if (!wavevm_legacy_cli_allowed("wavevm_node_slave")) {
        return 78;
    }

    g_nonblock_recv = (getenv("WVM_NONBLOCK_RECV") != NULL);
    g_executor_local_only = 0; /* accept local master UDP on dual-node */

    {
        struct stat st = {0};
        if (stat("/var/lib/wavevm", &st) == -1)
            mkdir("/var/lib/wavevm", 0755);
        if (stat("/var/lib/wavevm/chunks", &st) == -1)
            mkdir("/var/lib/wavevm/chunks", 0755);
        if (wvm_block_chunk_store_set_dir("/var/lib/wavevm/chunks", cerr,
                                          sizeof(cerr)) != 0) {
            fprintf(stderr, "[LegacySlave] chunk dir: %s\n", cerr);
        }
    }

    g_num_cores = get_allowed_cores();
    if (argc >= 2)
        g_service_port = atoi(argv[1]);
    if (argc >= 3) {
        g_num_cores = atoi(argv[2]);
        if (g_num_cores <= 0)
            g_num_cores = 1;
    }
    if (argc >= 4) {
        g_ram_mb = atoi(argv[3]);
        if (g_ram_mb <= 0)
            g_ram_mb = 1024;
        g_slave_ram_size = (uint64_t)g_ram_mb * 1024 * 1024;
    }
    if (argc >= 5)
        g_base_id = atoi(argv[4]);
    if (argc >= 6)
        g_executor_ctrl_port = atoi(argv[5]);
    /* argv[6] VM id optional; default 0 for dual-node fract plan */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-vfio") == 0 && i + 1 < argc)
            g_vfio_config_path = argv[i + 1];
    }

    printf("[Init] WaveVM Hybrid Slave V28.0 (Legacy CLI / F05)\n");
    printf("[Init] Config: Port=%d, Cores=%ld, RAM=%d MB, BaseID=%d, VM=%u\n",
           g_service_port, g_num_cores, g_ram_mb, g_base_id,
           (unsigned)g_slave_vm_id);

    init_kvm_global();
    if (g_kernel_context_bind_failed) {
        fprintf(stderr,
                "[KernelContext] refusing legacy executor after context mismatch\n");
        return 1;
    }

    /* F05 dual-node hides /dev/kvm → TCG PROXY. */
    if (g_kvm_available && getenv("WVM_FORCE_TCG") == NULL) {
        printf("[Hybrid] Mode: KVM FAST PATH. Listening on 0.0.0.0:%d\n",
               g_service_port);
        if (pthread_create(&g_dirty_sender_thread, NULL, dirty_sync_sender_thread,
                           NULL) != 0) {
            perror("dirty sender");
            return 1;
        }
        g_dirty_sender_started = 1;
        pthread_t *threads = malloc(sizeof(pthread_t));
        if (!threads)
            return 1;
        if (pthread_create(&threads[0], NULL, kvm_worker_thread, (void *)0) != 0)
            return 1;
        pthread_join(threads[0], NULL);
        free(threads);
    } else {
        printf("[Hybrid] Mode: TCG PROXY (Tri-Channel). Listening on 0.0.0.0:%d\n",
               g_service_port);
        if (spawn_tcg_processes(g_base_id) != 0) {
            fprintf(stderr, "[Hybrid] TCG helpers failed\n");
            return 1;
        }
        sleep(1);
        int proxy_threads = (int)(g_num_cores / 2);
        if (proxy_threads < 1)
            proxy_threads = 1;
        free(g_tcg_proxy_socks);
        g_tcg_proxy_socks =
            calloc((size_t)proxy_threads, sizeof(*g_tcg_proxy_socks));
        g_tcg_proxy_sock_capacity = proxy_threads;
        g_tcg_proxy_sock_count = 0;
        if (!g_tcg_proxy_socks)
            return 1;
        pthread_t *threads = malloc(sizeof(pthread_t) * (size_t)proxy_threads);
        if (!threads)
            return 1;
        for (long i = 0; i < proxy_threads; i++) {
            g_tcg_proxy_socks[i] = -1;
            if (pthread_create(&threads[i], NULL, tcg_proxy_thread, NULL) != 0) {
                fprintf(stderr, "[Hybrid] proxy thread create failed\n");
                return 1;
            }
        }
        /* Keep process alive while helpers run. */
        while (wait(NULL) > 0) {
        }
        for (long i = 0; i < proxy_threads; i++)
            pthread_join(threads[i], NULL);
        free(threads);
    }
    return 0;
}
#endif /* WAVEVM_SLAVE_LEGACY_CLI */
