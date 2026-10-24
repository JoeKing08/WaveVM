/* N3 isolated contract test for TCG pending VCPU reply table (mirrors slave_hybrid). */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#define TCG_PENDING_VCPU_REPLY_SLOTS 64
typedef struct {
    uint64_t req_id;
    struct sockaddr_in client;
    int valid;
} tcg_pending_vcpu_reply_t;
static tcg_pending_vcpu_reply_t g_tcg_pending_vcpu_reply[TCG_PENDING_VCPU_REPLY_SLOTS];
static pthread_mutex_t g_tcg_pending_vcpu_reply_lock = PTHREAD_MUTEX_INITIALIZER;

static int tcg_pending_vcpu_reply_put(uint64_t req_id,
                                      const struct sockaddr_in *client)
{
    int i;
    int free_slot = -1;
    if (!client) {
        return -1;
    }
    pthread_mutex_lock(&g_tcg_pending_vcpu_reply_lock);
    for (i = 0; i < TCG_PENDING_VCPU_REPLY_SLOTS; i++) {
        if (g_tcg_pending_vcpu_reply[i].valid &&
            g_tcg_pending_vcpu_reply[i].req_id == req_id) {
            if (g_tcg_pending_vcpu_reply[i].client.sin_addr.s_addr ==
                    client->sin_addr.s_addr &&
                g_tcg_pending_vcpu_reply[i].client.sin_port ==
                    client->sin_port) {
                g_tcg_pending_vcpu_reply[i].client = *client;
                pthread_mutex_unlock(&g_tcg_pending_vcpu_reply_lock);
                return 0;
            }
            pthread_mutex_unlock(&g_tcg_pending_vcpu_reply_lock);
            return -1;
        }
        if (!g_tcg_pending_vcpu_reply[i].valid && free_slot < 0) {
            free_slot = i;
        }
    }
    if (free_slot < 0) {
        pthread_mutex_unlock(&g_tcg_pending_vcpu_reply_lock);
        return -1;
    }
    g_tcg_pending_vcpu_reply[free_slot].req_id = req_id;
    g_tcg_pending_vcpu_reply[free_slot].client = *client;
    g_tcg_pending_vcpu_reply[free_slot].valid = 1;
    pthread_mutex_unlock(&g_tcg_pending_vcpu_reply_lock);
    return 0;
}

static int tcg_pending_vcpu_reply_peek(uint64_t req_id,
                                       struct sockaddr_in *out)
{
    int i;
    int found = 0;
    if (!out) {
        return 0;
    }
    pthread_mutex_lock(&g_tcg_pending_vcpu_reply_lock);
    for (i = 0; i < TCG_PENDING_VCPU_REPLY_SLOTS; i++) {
        if (g_tcg_pending_vcpu_reply[i].valid &&
            g_tcg_pending_vcpu_reply[i].req_id == req_id) {
            *out = g_tcg_pending_vcpu_reply[i].client;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_tcg_pending_vcpu_reply_lock);
    return found;
}

static void tcg_pending_vcpu_reply_clear(uint64_t req_id)
{
    int i;
    pthread_mutex_lock(&g_tcg_pending_vcpu_reply_lock);
    for (i = 0; i < TCG_PENDING_VCPU_REPLY_SLOTS; i++) {
        if (g_tcg_pending_vcpu_reply[i].valid &&
            g_tcg_pending_vcpu_reply[i].req_id == req_id) {
            g_tcg_pending_vcpu_reply[i].valid = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_tcg_pending_vcpu_reply_lock);
}

static struct sockaddr_in mk(uint16_t port)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    return a;
}

int main(void)
{
    struct sockaddr_in a, b, out;
    int i;
    int fails = 0;

    a = mk(1000);
    b = mk(2000);

    /* Fill 64 distinct in-flight reqs. */
    for (i = 1; i <= TCG_PENDING_VCPU_REPLY_SLOTS; i++) {
        if (tcg_pending_vcpu_reply_put((uint64_t)i, &a) != 0) {
            fprintf(stderr, "put(%d) unexpectedly failed\n", i);
            fails++;
        }
    }
    /* 65th must refuse (no silent overwrite of slot 0). */
    if (tcg_pending_vcpu_reply_put(999, &a) == 0) {
        fprintf(stderr, "put(65th) should refuse when full\n");
        fails++;
    }
    /* Original req 1 must still map to client a. */
    if (!tcg_pending_vcpu_reply_peek(1, &out) ||
        out.sin_port != a.sin_port) {
        fprintf(stderr, "req 1 overwritten or missing after full-table refuse\n");
        fails++;
    } else {
        printf("full_table_refuse=PASS take(1)_still_a\n");
    }

    /* Same req_id from different client must refuse. */
    memset(g_tcg_pending_vcpu_reply, 0, sizeof(g_tcg_pending_vcpu_reply));
    if (tcg_pending_vcpu_reply_put(42, &a) != 0) {
        fprintf(stderr, "seed put failed\n");
        fails++;
    }
    if (tcg_pending_vcpu_reply_put(42, &b) == 0) {
        fprintf(stderr, "different client overwrite should refuse\n");
        fails++;
    }
    if (!tcg_pending_vcpu_reply_peek(42, &out) || out.sin_port != a.sin_port) {
        fprintf(stderr, "client a lost after conflict put\n");
        fails++;
    } else {
        printf("same_req_different_client_refuse=PASS\n");
    }

    /* Same client refresh ok; clear only after explicit clear. */
    if (tcg_pending_vcpu_reply_put(42, &a) != 0) {
        fprintf(stderr, "same client refresh failed\n");
        fails++;
    }
    tcg_pending_vcpu_reply_clear(42);
    if (tcg_pending_vcpu_reply_peek(42, &out)) {
        fprintf(stderr, "clear did not remove pending\n");
        fails++;
    } else {
        printf("peek_clear=PASS\n");
    }

    if (fails) {
        fprintf(stderr, "N3 FAIL fails=%d\n", fails);
        return 1;
    }
    printf("N3_PENDING_VCPU_REPLY: PASS\n");
    return 0;
}
