#include <stdio.h>
#include <stdlib.h>
#include "wavevm_runtime_gate.h"
int main(int argc, char **argv)
{
    struct wvm_runtime_manifest_storage s;
    char err[256];
    if (argc != 2)
        return 2;
    wvm_runtime_manifest_storage_init(&s);
    if (wvm_runtime_manifest_load_file(argv[1], &s, err, sizeof(err)) != 0) {
        fprintf(stderr, "%s\n", err);
        return 1;
    }
    printf("node_runtime_data_port=%u\n",
           (unsigned)s.manifest.launch_plan.node_runtime_data_port);
    printf("local_executor_service_port=%u\n",
           (unsigned)s.manifest.launch_plan.local_executor_service_port);
    wvm_runtime_manifest_storage_free(&s);
    return 0;
}
