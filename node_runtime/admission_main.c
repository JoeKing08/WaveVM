#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../common_include/wavevm_admission_runtime_agent.h"

enum agent_option {
    OPT_STATE_DIR = 1000,
    OPT_RUNTIME_DIR,
    OPT_SOCKET,
    OPT_NODE_ID,
    OPT_INSTANCE_ID,
    OPT_INVENTORY_REVISION,
    OPT_VCPU_SLOTS,
    OPT_MEMORY_BYTES,
    OPT_CONTROLLER_NODE_ID,
    OPT_CONTROLLER_INSTANCE_ID,
    OPT_CONTROLLER_UID,
    OPT_SLOTS,
    OPT_MAX_VCPUS,
    OPT_MAX_MEMORY_CHUNKS,
    OPT_MAX_STORAGE,
    OPT_MAX_MEMBERS,
    OPT_MAX_LEASES,
};

struct agent_options {
    const char *state_dir;
    const char *runtime_dir;
    const char *socket_path;
    uint64_t node_id;
    uint64_t instance_id;
    uint64_t inventory_revision;
    uint64_t vcpu_slots;
    uint64_t memory_bytes;
    uint64_t controller_node_id;
    uint64_t controller_instance_id;
    uint64_t controller_uid;
    uint64_t slots;
    uint64_t max_vcpus;
    uint64_t max_memory_chunks;
    uint64_t max_storage;
    uint64_t max_members;
    uint64_t max_leases;
};

struct agent_authentication {
    uid_t controller_uid;
    struct wvm_member_key controller;
};

static volatile sig_atomic_t stop_requested;

static void request_stop(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

static void child_exited(int signal_number)
{
    (void)signal_number;
}

static int parse_number(const char *text, uint64_t *output)
{
    char *end;
    unsigned long long value;

    if (!text || !*text || *text == '-' || *text == '+' || !output) {
        return -1;
    }
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        return -1;
    }
    *output = value;
    return 0;
}

static int parse_options(int argc, char **argv, struct agent_options *options)
{
    static const struct option long_options[] = {
        {"state-dir", required_argument, NULL, OPT_STATE_DIR},
        {"runtime-dir", required_argument, NULL, OPT_RUNTIME_DIR},
        {"socket", required_argument, NULL, OPT_SOCKET},
        {"node-id", required_argument, NULL, OPT_NODE_ID},
        {"instance-id", required_argument, NULL, OPT_INSTANCE_ID},
        {"inventory-revision", required_argument, NULL, OPT_INVENTORY_REVISION},
        {"vcpu-slots", required_argument, NULL, OPT_VCPU_SLOTS},
        {"memory-bytes", required_argument, NULL, OPT_MEMORY_BYTES},
        {"controller-node-id", required_argument, NULL, OPT_CONTROLLER_NODE_ID},
        {"controller-instance-id", required_argument, NULL, OPT_CONTROLLER_INSTANCE_ID},
        {"controller-uid", required_argument, NULL, OPT_CONTROLLER_UID},
        {"slots", required_argument, NULL, OPT_SLOTS},
        {"max-vcpus", required_argument, NULL, OPT_MAX_VCPUS},
        {"max-memory-chunks", required_argument, NULL, OPT_MAX_MEMORY_CHUNKS},
        {"max-storage", required_argument, NULL, OPT_MAX_STORAGE},
        {"max-members", required_argument, NULL, OPT_MAX_MEMBERS},
        {"max-leases", required_argument, NULL, OPT_MAX_LEASES},
        {0, 0, 0, 0},
    };
    unsigned int seen = 0;
    int option;

    memset(options, 0, sizeof(*options));
    optind = 2;
    opterr = 0;
    while ((option = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
        uint64_t *number = NULL;
        unsigned int bit;

        if (option < OPT_STATE_DIR || option > OPT_MAX_LEASES) {
            return -1;
        }
        bit = 1U << (option - OPT_STATE_DIR);
        if (seen & bit) {
            return -1;
        }
        seen |= bit;
        switch (option) {
        case OPT_STATE_DIR: options->state_dir = optarg; break;
        case OPT_RUNTIME_DIR: options->runtime_dir = optarg; break;
        case OPT_SOCKET: options->socket_path = optarg; break;
        case OPT_NODE_ID: number = &options->node_id; break;
        case OPT_INSTANCE_ID: number = &options->instance_id; break;
        case OPT_INVENTORY_REVISION: number = &options->inventory_revision; break;
        case OPT_VCPU_SLOTS: number = &options->vcpu_slots; break;
        case OPT_MEMORY_BYTES: number = &options->memory_bytes; break;
        case OPT_CONTROLLER_NODE_ID: number = &options->controller_node_id; break;
        case OPT_CONTROLLER_INSTANCE_ID: number = &options->controller_instance_id; break;
        case OPT_CONTROLLER_UID: number = &options->controller_uid; break;
        case OPT_SLOTS: number = &options->slots; break;
        case OPT_MAX_VCPUS: number = &options->max_vcpus; break;
        case OPT_MAX_MEMORY_CHUNKS: number = &options->max_memory_chunks; break;
        case OPT_MAX_STORAGE: number = &options->max_storage; break;
        case OPT_MAX_MEMBERS: number = &options->max_members; break;
        case OPT_MAX_LEASES: number = &options->max_leases; break;
        default: return -1;
        }
        if ((number && parse_number(optarg, number) != 0) || !*optarg) {
            return -1;
        }
    }
    return optind == argc && seen == ((1U << (OPT_MAX_LEASES - OPT_STATE_DIR + 1)) - 1U) &&
           options->node_id > 0 && options->node_id <= UINT32_MAX &&
           options->instance_id > 0 && options->inventory_revision > 0 &&
           options->vcpu_slots > 0 && options->vcpu_slots <= UINT32_MAX &&
           options->memory_bytes > 0 &&
           options->controller_node_id > 0 &&
           options->controller_node_id <= UINT32_MAX &&
           options->controller_instance_id > 0 &&
           options->controller_uid <= (uint64_t)(uid_t)-1 &&
           options->slots > 0 && options->slots <= SIZE_MAX &&
           options->max_vcpus > 0 && options->max_vcpus <= SIZE_MAX &&
           options->max_memory_chunks > 0 && options->max_memory_chunks <= SIZE_MAX &&
           options->max_storage <= SIZE_MAX &&
           options->max_members > 0 && options->max_members <= SIZE_MAX &&
           options->max_leases > 0 && options->max_leases <= SIZE_MAX ? 0 : -1;
}

static int authenticate_controller(void *opaque, int stream_fd,
                                   struct wvm_member_key *actor, char *error,
                                   size_t error_len)
{
    const struct agent_authentication *authentication = opaque;
    struct ucred credentials;
    socklen_t length = sizeof(credentials);

    if (!authentication || !actor || stream_fd < 0 ||
        getsockopt(stream_fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 ||
        length != sizeof(credentials) || credentials.pid <= 0 ||
        credentials.uid != authentication->controller_uid) {
        if (error && error_len) {
            snprintf(error, error_len, "Unix peer is not the configured controller UID");
        }
        return -EACCES;
    }
    *actor = authentication->controller;
    return 0;
}

int wavevm_admission_agent_main(int argc, char **argv)
{
    struct agent_options options;
    struct agent_authentication authentication;
    struct wvm_admission_runtime_agent_config config;
    struct wvm_admission_runtime_agent agent;
    struct sigaction action = {.sa_handler = request_stop};
    struct sigaction child_action = {.sa_handler = child_exited};
    sigset_t blocked_signals;
    sigset_t previous_signals;
    char route_journal[WVM_ADMISSION_SLOT_PATH_MAX];
    char reservation_journal[WVM_ADMISSION_SLOT_PATH_MAX];
    char runtime_executable[PATH_MAX];
    char error[256] = {0};
    int result = 1;

    if (parse_options(argc, argv, &options) != 0) {
        fprintf(stderr, "Usage: %s agent --state-dir DIR --runtime-dir DIR --socket PATH "
                "--node-id N --instance-id N --inventory-revision N "
                "--vcpu-slots N --memory-bytes N --controller-node-id N "
                "--controller-instance-id N --controller-uid UID --slots N "
                "--max-vcpus N --max-memory-chunks N --max-storage N "
                "--max-members N --max-leases N\n", argv[0]);
        return 2;
    }
    {
        ssize_t executable_bytes = readlink("/proc/self/exe",
                                            runtime_executable,
                                            sizeof(runtime_executable) - 1U);

        if (executable_bytes <= 0 ||
            (size_t)executable_bytes >= sizeof(runtime_executable) - 1U) {
            fprintf(stderr, "[node-runtime] cannot resolve agent executable\n");
            return 1;
        }
        runtime_executable[executable_bytes] = '\0';
    }
    if (snprintf(route_journal, sizeof(route_journal), "%s/route.journal",
                 options.state_dir) >= (int)sizeof(route_journal) ||
        snprintf(reservation_journal, sizeof(reservation_journal),
                 "%s/reservation.journal", options.state_dir) >=
            (int)sizeof(reservation_journal)) {
        fprintf(stderr, "[node-runtime] agent state path is too long\n");
        return 2;
    }
    memset(&authentication, 0, sizeof(authentication));
    authentication.controller_uid = (uid_t)options.controller_uid;
    authentication.controller.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    authentication.controller.role_id = (uint32_t)options.controller_node_id;
    authentication.controller.instance_id = options.controller_instance_id;
    memset(&config, 0, sizeof(config));
    config.runtime_executable = runtime_executable;
    config.socket_path = options.socket_path;
    config.state_directory = options.state_dir;
    config.runtime_directory = options.runtime_dir;
    config.route_journal_path = route_journal;
    config.reservation_journal_path = reservation_journal;
    config.socket_mode = S_IRUSR | S_IWUSR;
    config.listen_backlog = 32;
    config.max_frame_bytes = WVM_CONTROL_TRANSPORT_DEFAULT_MAX_FRAME_BYTES;
    config.slot_capacity = (size_t)options.slots;
    config.max_vcpus = (size_t)options.max_vcpus;
    config.max_memory_chunks = (size_t)options.max_memory_chunks;
    config.max_storage_assignments = (size_t)options.max_storage;
    config.max_members = (size_t)options.max_members;
    config.max_leases_per_requirement = (size_t)options.max_leases;
    config.local_physical_node_id = (uint32_t)options.node_id;
    config.local_node_instance_id = options.instance_id;
    config.inventory_revision = options.inventory_revision;
    config.allocatable_vcpu_slots = (uint32_t)options.vcpu_slots;
    config.allocatable_memory_bytes = options.memory_bytes;
    config.controller_member_key = authentication.controller;
    config.controller_physical_node_id = (uint32_t)options.controller_node_id;
    config.controller_runtime_instance_id = options.controller_instance_id;
    config.authenticate = authenticate_controller;
    config.authenticate_opaque = &authentication;
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0 ||
        sigemptyset(&child_action.sa_mask) != 0 ||
        sigaction(SIGCHLD, &child_action, NULL) != 0 ||
        sigemptyset(&blocked_signals) != 0 ||
        sigaddset(&blocked_signals, SIGINT) != 0 ||
        sigaddset(&blocked_signals, SIGTERM) != 0 ||
        sigaddset(&blocked_signals, SIGCHLD) != 0 ||
        sigprocmask(SIG_BLOCK, &blocked_signals, &previous_signals) != 0) {
        fprintf(stderr, "[node-runtime] cannot install agent signal handlers\n");
        return 1;
    }
    memset(&agent, 0, sizeof(agent));
    if (wvm_admission_runtime_agent_init(&agent, &config, error, sizeof(error)) != 0 ||
        wvm_admission_runtime_agent_start(&agent, error, sizeof(error)) != 0) {
        fprintf(stderr, "[node-runtime] cannot start admission agent: %s\n", error);
        wvm_admission_runtime_agent_destroy(&agent);
        (void)sigprocmask(SIG_SETMASK, &previous_signals, NULL);
        return result;
    }
    while (!stop_requested) {
        (void)sigsuspend(&previous_signals);
        wvm_admission_runtime_agent_reap(&agent);
    }
    result = 0;
    if (wvm_admission_runtime_agent_stop(&agent, error, sizeof(error)) != 0) {
        fprintf(stderr, "[node-runtime] cannot stop admission agent: %s\n", error);
        result = 1;
    }
    wvm_admission_runtime_agent_destroy(&agent);
    (void)sigprocmask(SIG_SETMASK, &previous_signals, NULL);
    return result;
}
