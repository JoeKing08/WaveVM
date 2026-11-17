#ifdef WAVEVM_MASTER_LEGACY_CLI
/*
 * F05/legacy CLI entry: positional argv used by scripts/ci_dual_node.sh.
 * Built only into master_core/wavevm_node_master (see node_runtime
 * legacy-master target). This is not the admitted node_runtime path;
 * typed V1 memory service is not installed (ENOTCONN falls back to
 * logic_core / UDP as in handle_ipc_fault).
 */
extern void *autonomous_monitor_thread(void *arg);
extern int g_my_node_id;

static struct wvm_resource_plan g_resource_plan;
static int g_resource_plan_ready;

static int parse_legacy_vm_id(const char *text, uint32_t *value)
{
    char *end = NULL;
    unsigned long parsed;

    if (!text || !value) {
        return -1;
    }
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed > UINT32_MAX) {
        return -1;
    }
    *value = (uint32_t)parsed;
    return 0;
}

static void inject_cpu_route_table(void)
{
    const uint32_t *table;
    const uint32_t chunk_size = 1024;
    size_t buf_size;
    struct wvm_ioctl_route_update *payload;
    uint32_t i;

    if (g_dev_fd < 0) {
        return;
    }
    table = wvm_get_cpu_route_table();
    if (!table) {
        return;
    }
    buf_size = sizeof(*payload) + chunk_size * sizeof(uint32_t);
    payload = malloc(buf_size);
    if (!payload) {
        fprintf(stderr, "[CPU-ROUTE] malloc failed\n");
        return;
    }
    for (i = 0; i < WVM_CPU_ROUTE_TABLE_SIZE; i += chunk_size) {
        uint32_t count = chunk_size;

        if (i + count > WVM_CPU_ROUTE_TABLE_SIZE) {
            count = WVM_CPU_ROUTE_TABLE_SIZE - i;
        }
        payload->start_index = i;
        payload->count = count;
        memcpy(payload->entries, &table[i], count * sizeof(uint32_t));
        if (ioctl(g_dev_fd, IOCTL_UPDATE_CPU_ROUTE, payload) < 0) {
            fprintf(stderr, "[CPU-ROUTE] inject failed at %u (errno=%d)\n",
                    i, errno);
            free(payload);
            return;
        }
    }
    fprintf(stderr, "[CPU-ROUTE] injected %u entries\n",
            (unsigned)WVM_CPU_ROUTE_TABLE_SIZE);
    free(payload);
}

static void inject_memory_route_table(void)
{
    const uint32_t *table;
    const uint32_t chunk_size = 1024;
    size_t buf_size;
    struct wvm_ioctl_route_update *payload;
    uint32_t i;

    if (g_dev_fd < 0) {
        return;
    }
    table = wvm_get_memory_route_table();
    if (!table) {
        return;
    }
    buf_size = sizeof(*payload) + chunk_size * sizeof(uint32_t);
    payload = malloc(buf_size);
    if (!payload) {
        fprintf(stderr, "[MEM-ROUTE] malloc failed\n");
        return;
    }
    for (i = 0; i < WVM_MEMORY_ROUTE_TABLE_SIZE; i += chunk_size) {
        uint32_t count = chunk_size;

        if (i + count > WVM_MEMORY_ROUTE_TABLE_SIZE) {
            count = WVM_MEMORY_ROUTE_TABLE_SIZE - i;
        }
        payload->start_index = i;
        payload->count = count;
        memcpy(payload->entries, &table[i], count * sizeof(uint32_t));
        if (ioctl(g_dev_fd, IOCTL_UPDATE_MEMORY_PLACEMENT, payload) < 0) {
            fprintf(stderr, "[MEM-ROUTE] inject failed at %u (errno=%d)\n",
                    i, errno);
            free(payload);
            return;
        }
    }
    fprintf(stderr, "[MEM-ROUTE] injected %u entries\n",
            (unsigned)WVM_MEMORY_ROUTE_TABLE_SIZE);
    free(payload);
}

static void inject_mem_global(uint32_t slot, uint32_t value)
{
    size_t buf_size = sizeof(struct wvm_ioctl_route_update) + sizeof(uint32_t);
    struct wvm_ioctl_route_update *payload;

    if (g_dev_fd < 0) {
        return;
    }
    payload = malloc(buf_size);
    if (!payload) {
        fprintf(stderr, "[MEM-GLOBAL] malloc failed\n");
        return;
    }
    payload->start_index = slot;
    payload->count = 1;
    payload->entries[0] = value;
    if (ioctl(g_dev_fd, IOCTL_UPDATE_MEM_ROUTE, payload) < 0) {
        fprintf(stderr, "[MEM-GLOBAL] inject slot %u failed (errno=%d)\n",
                slot, errno);
    }
    free(payload);
}

static void inject_vm_id(uint32_t vm_id)
{
    if (g_dev_fd < 0) {
        return;
    }
    if (ioctl(g_dev_fd, IOCTL_SET_VM_ID, &vm_id) < 0) {
        fprintf(stderr, "[VM-ID] inject failed (errno=%d)\n", errno);
    }
}

static void load_swarm_config(const char *filename)
{
    char error[256] = {0};
    const struct wvm_resource_vm *vm;

    if (!g_resource_plan_ready) {
        if (wvm_resource_plan_load(filename, &g_resource_plan, error,
                                   sizeof(error)) != 0) {
            fprintf(stderr, "[Config] %s\n", error);
            exit(1);
        }
        g_resource_plan_ready = 1;
    }

    printf("[Config] DHT Ring Size: %u Virtual Nodes (from %u Physical).\n",
           g_resource_plan.total_vnodes, g_resource_plan.node_count);
    for (uint32_t i = 0; i < g_resource_plan.node_count; i++) {
        const struct wvm_resource_node *node = &g_resource_plan.nodes[i];

        for (uint32_t slot = 0; slot < node->dht_slots; slot++) {
            uint32_t vnode = node->vnode_start + slot;
            u_ops.set_gateway_ip(WVM_ENCODE_ID(g_my_vm_id, vnode),
                                 inet_addr(node->ip), htons(node->port));
        }
    }
    wvm_set_mem_mapping(0, g_resource_plan.total_vnodes);

    wvm_clear_cpu_mappings();
    wvm_clear_memory_mappings();
    vm = wvm_resource_plan_get_vm(&g_resource_plan, (uint8_t)g_my_vm_id);
    if (g_resource_plan.vm_count > 0 && !vm) {
        fprintf(stderr, "[Config] VM %u has no resource reservation\n",
                (unsigned)g_my_vm_id);
        exit(1);
    }

    if (vm) {
        for (uint32_t vcpu = 0; vcpu < vm->vcpu_count; vcpu++) {
            wvm_set_cpu_mapping((int)vcpu, vm->vcpu_nodes[vcpu]);
        }
        for (uint32_t chunk = 0; chunk < vm->memory_chunk_count; chunk++) {
            wvm_set_memory_mapping((int)chunk, vm->memory_nodes[chunk]);
        }
        printf("[Config] VM %u placement: %u vCPUs, %u x 1GiB memory chunks (%s).\n",
               (unsigned)g_my_vm_id, vm->vcpu_count,
               vm->memory_chunk_count,
               vm->policy == WVM_RESOURCE_POLICY_COMPACT ? "compact" : "spread");
        return;
    }

    int current_vcpu = 0;
    for (uint32_t i = 0; i < g_resource_plan.node_count; i++) {
        const struct wvm_resource_node *node = &g_resource_plan.nodes[i];

        for (uint32_t core = 0;
             core < node->cpu_capacity &&
             current_vcpu < (int)WVM_CPU_ROUTE_TABLE_SIZE;
             core++) {
            wvm_set_cpu_mapping(current_vcpu++, node->vnode_start);
        }
    }
    for (uint32_t cursor = 0;
         current_vcpu < (int)WVM_CPU_ROUTE_TABLE_SIZE;
         cursor = (cursor + 1) % g_resource_plan.node_count) {
        wvm_set_cpu_mapping(current_vcpu++,
                            g_resource_plan.nodes[cursor].vnode_start);
    }
    printf("[Config] CPU Routing Table Initialized (legacy core-weighted mode).\n");
}

static void load_initial_seeds(const char *config_file)
{
    (void)config_file;

    if (!g_resource_plan_ready) {
        return;
    }

    for (uint32_t i = 0; i < g_resource_plan.node_count; i++) {
        const struct wvm_resource_node *node = &g_resource_plan.nodes[i];
        struct sockaddr_in seed = {0};

        seed.sin_family = AF_INET;
        seed.sin_addr.s_addr = inet_addr(node->ip);
        seed.sin_port = htons(node->port);
        for (uint32_t slot = 0; slot < node->dht_slots; slot++) {
            uint32_t vnode = node->vnode_start + slot;

            if (vnode == (uint32_t)g_my_node_id) {
                continue;
            }
            update_local_topology_view(vnode, 0, NODE_STATE_SHADOW, &seed, 0);
        }
    }
}


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
    if (!wavevm_legacy_cli_allowed("wavevm_node_master")) {
        return 78;
    }
    int stop_result = 0;
    size_t ram_mb;
    int local_port;
    const char *config_file;
    int my_phys_id;
    int my_virtual_id;
    uint32_t my_local_cores;
    uint64_t required_memory_bytes;
    uint32_t total_vnodes;
    const struct wvm_resource_node *my_node;
    const char *shm_path;
    const char *sock_path;
    int listen_fd;
    char error[256];

    signal(SIGPIPE, SIG_IGN);
    if (install_shutdown_handlers() != 0) {
        perror("[Lifecycle] cannot install shutdown handlers");
        return 1;
    }

    if (argc < 7) {
        fprintf(stderr,
                "Usage: %s <RAM_MB> <LOCAL_PORT> <SWARM_CONFIG> <MY_PHYS_ID> "
                "<CTRL_PORT> <SLAVE_PORT> [SYNC_BATCH] [VM_ID]\n",
                argv[0]);
        return 1;
    }

    g_dev_fd = open("/dev/wavevm", O_RDWR);
    if (g_dev_fd < 0) {
        perror("[Warning] Failed to open /dev/wavevm (Kernel Mode disabled?)");
    }

    ram_mb = (size_t)atol(argv[1]);
    g_shm_size = ram_mb * 1024 * 1024;
    local_port = atoi(argv[2]);
    config_file = argv[3];
    my_phys_id = atoi(argv[4]);
    g_ctrl_port = atoi(argv[5]);
    {
        extern int g_slave_forward_port;
        g_slave_forward_port = atoi(argv[6]);
    }
    if (argc >= 8) {
        extern int g_sync_batch_size;
        g_sync_batch_size = atoi(argv[7]);
    }
    if (argc >= 9 && parse_legacy_vm_id(argv[8], &g_my_vm_id) != 0) {
        fprintf(stderr, "[VM-ID] invalid legacy VM id '%s'\n", argv[8]);
        return 1;
    }

    memset(error, 0, sizeof(error));
    if (wvm_resource_plan_load(config_file, &g_resource_plan, error,
                               sizeof(error)) != 0) {
        fprintf(stderr, "[Config] %s\n", error);
        return 1;
    }
    g_resource_plan_ready = 1;
    my_node = wvm_resource_plan_find_node(&g_resource_plan, my_phys_id);
    if (!my_node) {
        fprintf(stderr, "[Fatal] My Physical ID %d not found in config file!\n",
                my_phys_id);
        return 1;
    }
    my_virtual_id = (int)my_node->vnode_start;
    my_local_cores = my_node->cpu_capacity;
    required_memory_bytes = (uint64_t)my_node->memory_mb * 1024U * 1024U;
    total_vnodes = g_resource_plan.total_vnodes;

    printf("[*] WaveVM Swarm V30.0 'Wavelet' Node Daemon (legacy CLI PhysID: %d, VM: %u)\n",
           my_phys_id, (unsigned)g_my_vm_id);

    if (user_backend_init(my_virtual_id, local_port, NULL) != 0) {
        fprintf(stderr, "[-] Failed to init user backend.\n");
        return 1;
    }
    if (wvm_core_init(&u_ops, 0) != 0) {
        fprintf(stderr, "[-] Logic Core init failed.\n");
        return 1;
    }
    load_swarm_config(config_file);

    printf("[+] Starting %d Wavelet Broadcast Engines...\n", NUM_BCAST_WORKERS);
    for (long i = 0; i < NUM_BCAST_WORKERS; i++) {
        pthread_t bcast_tid;
        if (pthread_create(&bcast_tid, NULL, broadcast_worker_thread,
                           (void *)i) != 0) {
            perror("[-] Failed to start broadcast worker thread");
            exit(1);
        }
        pthread_detach(bcast_tid);
    }
    printf("[+] All Wavelet Broadcast Engines started.\n");

    {
        const struct wvm_resource_vm *my_vm =
            wvm_resource_plan_get_vm(&g_resource_plan, (uint8_t)g_my_vm_id);

        if (my_vm) {
            my_local_cores = wvm_resource_plan_local_vcpus(&g_resource_plan,
                                                           (uint8_t)g_my_vm_id,
                                                           my_phys_id);
            required_memory_bytes =
                wvm_resource_plan_local_memory_mb(&g_resource_plan,
                                                  (uint8_t)g_my_vm_id,
                                                  my_phys_id) *
                1024U * 1024U;
        }
    }
    if ((uint64_t)g_shm_size < required_memory_bytes) {
        fprintf(stderr, "\n[FATAL] Resource Mismatch!\n");
        fprintf(stderr, "  Local reservation requires:          %llu bytes\n",
                (unsigned long long)required_memory_bytes);
        fprintf(stderr, "  Launch arg provided:                 %lu MB\n",
                (unsigned long)ram_mb);
        return 1;
    }
    printf("[Check] Resource verified: Alloc %lu MB >= Reservation %llu bytes.\n",
           (unsigned long)ram_mb, (unsigned long long)required_memory_bytes);

    wvm_set_my_node_id(my_virtual_id);
    printf("[Init] Identity Mapped: PhysID %d -> VirtualID %d (Primary)\n",
           my_phys_id, my_virtual_id);
    inject_vm_id(g_my_vm_id);
    inject_mem_global(0, total_vnodes);
    inject_mem_global(1, (uint32_t)my_virtual_id);
    inject_cpu_route_table();
    inject_memory_route_table();
    {
        char split_buf[32];
        snprintf(split_buf, sizeof(split_buf), "%u", my_local_cores);
        setenv("WVM_LOCAL_SPLIT", split_buf, 1);
    }

    shm_path = getenv("WVM_SHM_FILE");
    if (!shm_path || shm_path[0] == '\0') {
        fprintf(stderr, "[System] SHM name is missing (WVM_SHM_FILE)\n");
        return 1;
    }
    printf("[System] Initializing SHM: %s (Size: %lu MB)\n", shm_path,
           (unsigned long)ram_mb);
    shm_unlink(shm_path);
    {
        int shm_fd = shm_open(shm_path, O_CREAT | O_RDWR, 0666);
        if (shm_fd < 0) {
            fprintf(stderr, "[-] Failed to open shm file '%s': %s\n", shm_path,
                    strerror(errno));
            return 1;
        }
        if (ftruncate(shm_fd, g_shm_size) < 0) {
            perror("ftruncate failed");
            close(shm_fd);
            return 1;
        }
        g_shm_ptr = mmap(NULL, g_shm_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                         shm_fd, 0);
        close(shm_fd);
        if (g_shm_ptr == MAP_FAILED) {
            perror("mmap failed");
            return 1;
        }
    }
    printf("[+] Memory Ready at %p\n", g_shm_ptr);

    listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket AF_UNIX failed");
        return 1;
    }
    {
        struct sockaddr_un addr = {0};

        addr.sun_family = AF_UNIX;
        sock_path = getenv("WVM_RUNTIME_SOCKET");
        if (!sock_path || sock_path[0] == '\0') {
            sock_path = getenv("WVM_ENV_SOCK_PATH");
        }
        if (!sock_path || sock_path[0] == '\0' ||
            strlen(sock_path) >= sizeof(addr.sun_path)) {
            fprintf(stderr, "[System] runtime socket path is missing\n");
            close(listen_fd);
            return 1;
        }
        strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
        unlink(sock_path);
        printf("[System] Control Socket: %s\n", sock_path);
        setenv("WVM_ENV_SOCK_PATH", sock_path, 1);
        if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind unix socket failed");
            return 1;
        }
        if (listen(listen_fd, 100) < 0) {
            perror("listen failed");
            return 1;
        }
    }

    printf("[+] WaveVM V29 Node Ready. Waiting for QEMU...\n");
    fflush(stdout);

    {
        pthread_t monitor_tid;

        load_initial_seeds(config_file);
        pthread_create(&monitor_tid, NULL, autonomous_monitor_thread, NULL);
        pthread_detach(monitor_tid);
        printf("[Autonomous] Node started in SHADOW mode. Auto-scaling into cluster...\n");
    }

    g_master_listen_fd = listen_fd;
    while (!g_shutdown_requested) {
        int client_fd = accept(listen_fd, NULL, NULL);
        int current_count;
        pthread_t thread_id;
        int *new_sock;

        if (client_fd < 0) {
            if (errno == EINTR) {
                if (g_shutdown_requested) {
                    break;
                }
                continue;
            }
            perror("accept error");
            sleep(1);
            continue;
        }
        pthread_mutex_lock(&g_client_lock);
        current_count = g_client_count;
        pthread_mutex_unlock(&g_client_lock);
        if (current_count >= MAX_QEMU_CLIENTS) {
            fprintf(stderr,
                    "[IPC] WARN: MAX_QEMU_CLIENTS(%d) reached, rejecting fd=%d\n",
                    MAX_QEMU_CLIENTS, client_fd);
            close(client_fd);
            continue;
        }
        if (track_client_fd(client_fd) != 0) {
            fprintf(stderr,
                    "[IPC] WARN: client handler registry full, rejecting fd=%d\n",
                    client_fd);
            close(client_fd);
            continue;
        }
        new_sock = malloc(sizeof(int));
        if (new_sock) {
            *new_sock = client_fd;
            if (pthread_create(&thread_id, NULL, client_handler,
                               (void *)new_sock) != 0) {
                perror("pthread_create failed");
                release_client_fd(client_fd, 0);
                close(client_fd);
                free(new_sock);
            } else {
                pthread_detach(thread_id);
            }
        } else {
            perror("malloc failed");
            release_client_fd(client_fd, 0);
            close(client_fd);
        }
    }

    fprintf(stderr, "[System] control accept loop ended (shutdown=%d)\n",
            (int)g_shutdown_requested);
    if (stop_and_wait_clients() != 0) {
        stop_result = 1;
    }
    g_master_listen_fd = -1;
    close(listen_fd);
    if (sock_path && sock_path[0] != '\0') {
        unlink(sock_path);
    }
    if (g_shm_ptr && g_shm_ptr != MAP_FAILED) {
        munmap(g_shm_ptr, g_shm_size);
        g_shm_ptr = NULL;
    }
    if (shm_path && shm_path[0] != '\0') {
        shm_unlink(shm_path);
    }
    if (g_dev_fd >= 0) {
        close(g_dev_fd);
        g_dev_fd = -1;
    }
    if (stop_result != 0) {
        fprintf(stderr,
                "[Lifecycle] normal STOP incomplete; returning non-success\n");
        return 1;
    }
    return 0;
}
#endif /* WAVEVM_MASTER_LEGACY_CLI */
