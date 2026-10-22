/*
 * R04: live QUERY_DIFF_STATUS on a bound Mode A context.
 * Unbound FD => ENOTCONN; after BIND => WKDS v1 with failed_diff_count==0.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "../../common_include/wavevm_ioctl.h"

static int expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "r04-query-diff: %s (errno=%d %s)\n", msg, errno,
                strerror(errno));
        return -1;
    }
    return 0;
}

static void fill_bind(struct wvm_ioctl_context_bind *bind, uint32_t vm_id)
{
    memset(bind, 0, sizeof(*bind));
    bind->magic = WVM_KERNEL_CONTEXT_MAGIC;
    bind->version = WVM_KERNEL_CONTEXT_ABI_VERSION;
    bind->vm_id = vm_id;
    bind->physical_node_id = 1;
    bind->node_instance_id = 1;
    bind->vm_incarnation = 1;
    bind->manifest_generation = 1;
    memset(bind->candidate_manifest_digest, (int)(vm_id & 0xFF),
           WVM_KERNEL_DIGEST_BYTES);
    memset(bind->capability_profile_digest, 0xA4, WVM_KERNEL_DIGEST_BYTES);
    memset(bind->activation_fence, (int)(vm_id & 0xFF), WVM_KERNEL_FENCE_BYTES);
    bind->route_snapshot_key.scope_key.vm_id = vm_id;
    bind->route_snapshot_key.scope_key.vm_incarnation = 1;
    bind->route_snapshot_key.scope_key.route_scope_id = 1;
    bind->route_snapshot_key.topology_revision = 1;
    bind->route_snapshot_key.route_generation = 1;
    memset(bind->route_snapshot_key.snapshot_digest, (int)(vm_id & 0xFF),
           WVM_KERNEL_DIGEST_BYTES);
}

int main(void)
{
    int fd;
    struct wvm_ioctl_context_caps caps;
    struct wvm_ioctl_context_bind bind;
    struct wvm_ioctl_diff_status st;

    fd = open("/dev/wavevm", O_RDWR | O_CLOEXEC);
    if (expect(fd >= 0, "open /dev/wavevm") != 0)
        return 1;

    memset(&st, 0, sizeof(st));
    if (ioctl(fd, IOCTL_WVM_QUERY_DIFF_STATUS, &st) == 0) {
        fprintf(stderr, "r04: unbound QUERY_DIFF_STATUS unexpectedly ok\n");
        close(fd);
        return 1;
    }
    if (expect(errno == ENOTCONN, "unbound => ENOTCONN") != 0) {
        close(fd);
        return 1;
    }
    printf("[OK] unbound QUERY_DIFF_STATUS ENOTCONN\n");

    memset(&caps, 0, sizeof(caps));
    if (expect(ioctl(fd, IOCTL_WVM_QUERY_CAPS, &caps) == 0, "QUERY_CAPS") != 0 ||
        expect((caps.feature_bits & WVM_KERNEL_CAP_CONTEXT_BIND) != 0,
               "CONTEXT_BIND") != 0) {
        close(fd);
        return 1;
    }

    fill_bind(&bind, 0x4104);
    if (expect(ioctl(fd, IOCTL_WVM_BIND_CONTEXT, &bind) == 0, "BIND") != 0) {
        close(fd);
        return 1;
    }
    printf("[OK] bound context vm=%u\n", bind.vm_id);

    memset(&st, 0, sizeof(st));
    if (expect(ioctl(fd, IOCTL_WVM_QUERY_DIFF_STATUS, &st) == 0,
               "bound QUERY_DIFF_STATUS") != 0) {
        close(fd);
        return 1;
    }
    if (expect(st.magic == WVM_KERNEL_DIFF_STATUS_MAGIC, "magic") != 0 ||
        expect(st.version >= WVM_KERNEL_DIFF_STATUS_VERSION, "version") != 0 ||
        expect(st.failed_diff_count == 0, "count==0") != 0 ||
        expect(st.last_failure == 0, "last_failure==0") != 0) {
        fprintf(stderr, "st magic=%u ver=%u fail=%d count=%u\n", st.magic,
                st.version, st.last_failure, st.failed_diff_count);
        close(fd);
        return 1;
    }
    printf("[OK] bound QUERY_DIFF_STATUS magic=WKDS ver=%u count=0\n",
           (unsigned)st.version);

    fill_bind(&bind, 0x4104);
    (void)ioctl(fd, IOCTL_WVM_UNBIND_CONTEXT, &bind);
    close(fd);
    puts("R04 bound-context QUERY_DIFF_STATUS live: PASS");
    return 0;
}
