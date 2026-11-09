#include <stdio.h>
#include <string.h>

/* Mirrors N06 refuse: listener_plan_count must not silently clamp past 64. */
static int expect(int c, const char *m)
{
    if (!c) {
        fprintf(stderr, "test_n06_listener_budget: FAIL %s\n", m);
        return 1;
    }
    return 0;
}

static int compile_overrides(size_t listener_plan_count, size_t *out_count,
                             char *error, size_t error_len)
{
    enum { CAP = 64 };
    size_t n = listener_plan_count;
    size_t override_count = 0;
    size_t i;

    if (n > CAP) {
        snprintf(error, error_len,
                 "N06: listener_plan_count %zu exceeds ingress override "
                 "budget %zu; enlarge workspace or reduce listeners",
                 n, (size_t)CAP);
        return -1;
    }
    for (i = 0; i < n; i++) {
        override_count++;
    }
    *out_count = override_count;
    return 0;
}

int main(void)
{
    size_t count = 0;
    char error[256];
    int failed = 0;

    error[0] = '\0';
    failed |= expect(compile_overrides(64, &count, error, sizeof(error)) == 0 &&
                         count == 64,
                     "64 listeners must be accepted");
    error[0] = '\0';
    failed |= expect(compile_overrides(65, &count, error, sizeof(error)) != 0 &&
                         strstr(error, "N06:") != NULL,
                     "65 listeners must refuse with N06");
    if (failed)
        return 1;
    puts("test_n06_listener_budget: PASS");
    return 0;
}
