#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Mirror production wvm_merge_commit_write_set (wavevm-user-mem.c G6). */
static void wvm_merge_commit_write_set(uint8_t *out,
                                       const uint8_t *pre_image,
                                       const uint8_t *ours,
                                       const uint8_t *theirs,
                                       size_t bytes)
{
    size_t i;

    if (!out || !ours || !theirs || bytes == 0) {
        return;
    }
    if (!pre_image) {
        memcpy(out, ours, bytes);
        return;
    }
    for (i = 0; i < bytes; i++) {
        out[i] = (ours[i] != pre_image[i]) ? ours[i] : theirs[i];
    }
}

int main(void)
{
    uint8_t pre[4] = {0, 0, 0, 0};
    uint8_t ours[4] = {1, 0, 0, 0};   /* A wrote x=1 */
    uint8_t theirs[4] = {0, 1, 0, 0}; /* B wrote y=1 on advanced version */
    uint8_t out[4];

    wvm_merge_commit_write_set(out, pre, ours, theirs, 4);
    if (out[0] != 1 || out[1] != 1 || out[2] != 0 || out[3] != 0) {
        fprintf(stderr, "G6 merge FAIL got %u %u %u %u\n",
                out[0], out[1], out[2], out[3]);
        return 1;
    }
    /* Without pre_image must not invent merge — copies ours (caller fail-closed). */
    memset(out, 0xee, sizeof(out));
    wvm_merge_commit_write_set(out, NULL, ours, theirs, 4);
    if (memcmp(out, ours, 4) != 0) {
        fprintf(stderr, "G6 no-pre FAIL\n");
        return 1;
    }
    fprintf(stderr, "G6_MERGE_WRITE_SET PASS out=[%u,%u,%u,%u]\n",
            out[0], out[1], out[2], out[3]);
    /* re-run with merge result for message clarity */
    wvm_merge_commit_write_set(out, pre, ours, theirs, 4);
    fprintf(stderr, "G6_MERGE_BOTH_PRESERVED x=%u y=%u\n", out[0], out[1]);
    return 0;
}
