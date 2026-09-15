#include "hostmap.h"
#include "platform.h"

#define MAP_SIZE 8192
#define PROBES 8

typedef struct {
    char ip[46];
    char name[HOSTMAP_NAME];
    long long ts;
} MapEntry;

static MapEntry g_map[MAP_SIZE];
static DnsLogEntry g_log[DNSLOG_CAP];
static int g_log_head = 0, g_log_count = 0;
static unsigned long g_log_seq = 0;
static plat_mutex g_lock;
static int g_ready = 0;

void hostmap_init(void)
{
    if (g_ready) return;
    plat_mutex_init(&g_lock);
    g_ready = 1;
}

static unsigned hash_text(const char *s)
{
    unsigned h = 2166136261u;
    for (; *s; s++) h = (h ^ (unsigned char)*s) * 16777619u;
    return h;
}

static const char *canonical(const char *ip)
{
    return !_strnicmp(ip, "::ffff:", 7) && strchr(ip + 7, '.') ? ip + 7 : ip;
}

void hostmap_put(const char *ip, const char *name)
{
    unsigned slot;
    int i, target = -1;
    long long oldest = 0;

    if (!g_ready || !ip || !*ip || !name || !*name) return;
    ip = canonical(ip);
    slot = hash_text(ip) & (MAP_SIZE - 1);

    plat_mutex_lock(&g_lock);
    for (i = 0; i < PROBES; i++) {
        MapEntry *e = &g_map[(slot + i) & (MAP_SIZE - 1)];
        if (!e->ip[0] || !strcmp(e->ip, ip)) {
            target = (int)((slot + i) & (MAP_SIZE - 1));
            break;
        }
        if (target < 0 || e->ts < oldest) {
            target = (int)((slot + i) & (MAP_SIZE - 1));
            oldest = e->ts;
        }
    }
    strcpy_s(g_map[target].ip, sizeof g_map[target].ip, ip);
    strncpy_s(g_map[target].name, sizeof g_map[target].name, name, _TRUNCATE);
    g_map[target].ts = plat_now_ms();
    plat_mutex_unlock(&g_lock);
}

int hostmap_get(const char *ip, char *out, size_t cap)
{
    unsigned slot;
    int i, found = 0;

    if (!g_ready || !ip || !*ip) return 0;
    ip = canonical(ip);
    slot = hash_text(ip) & (MAP_SIZE - 1);

    plat_mutex_lock(&g_lock);
    for (i = 0; i < PROBES; i++) {
        const MapEntry *e = &g_map[(slot + i) & (MAP_SIZE - 1)];
        if (e->ip[0] && !strcmp(e->ip, ip)) {
            strncpy_s(out, cap, e->name, _TRUNCATE);
            found = 1;
            break;
        }
    }
    plat_mutex_unlock(&g_lock);
    return found;
}

void dnslog_add(unsigned long pid, const char *name, int qtype, int status, const char *answer)
{
    DnsLogEntry *e;

    if (!g_ready || !name || !*name) return;
    plat_mutex_lock(&g_lock);
    e = &g_log[(g_log_head + g_log_count) % DNSLOG_CAP];
    if (g_log_count < DNSLOG_CAP) g_log_count++;
    else g_log_head = (g_log_head + 1) % DNSLOG_CAP;

    memset(e, 0, sizeof *e);
    e->id = ++g_log_seq;
    e->ts = plat_now_ms();
    e->pid = pid;
    e->qtype = qtype;
    e->status = status;
    strncpy_s(e->name, sizeof e->name, name, _TRUNCATE);
    if (answer) strncpy_s(e->answer, sizeof e->answer, answer, _TRUNCATE);
    plat_mutex_unlock(&g_lock);
}

int dnslog_copy(DnsLogEntry *out, int cap)
{
    int i, n = 0;

    if (!g_ready) return 0;
    plat_mutex_lock(&g_lock);
    for (i = g_log_count - 1; i >= 0 && n < cap; i--) {
        out[n++] = g_log[(g_log_head + i) % DNSLOG_CAP];
    }
    plat_mutex_unlock(&g_lock);
    return n;
}
