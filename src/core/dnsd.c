#include "dnsd.h"
#include "hostmap.h"
#include "platform.h"

#ifdef _WIN32
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
#else
#include <sys/select.h>
#include <sys/time.h>
#endif

#define DNS_PORT 53
#define SLOTS 1024
#define PKT_MAX 1500
#define TCP_MAX 8192
#define RETRY_MS 800
#define GIVE_UP_MS 4000

typedef struct {
    int used;
    unsigned short orig_id, up_id;
    struct sockaddr_storage client;
    int client_len;
    plat_socket via;
    unsigned char pkt[PKT_MAX];
    int pkt_len;
    long long first_ms, sent_ms;
    int tries;
    int qtype;
    char name[DNSD_NAME];
} Slot;

static Slot g_slots[SLOTS];
static int g_cursor = 0;

static plat_socket g_udp4 = PLAT_BAD_SOCKET, g_udp6 = PLAT_BAD_SOCKET;
static plat_socket g_tcp4 = PLAT_BAD_SOCKET, g_tcp6 = PLAT_BAD_SOCKET;
static plat_socket g_up4 = PLAT_BAD_SOCKET, g_up6 = PLAT_BAD_SOCKET;

static plat_thread g_thread = NULL;
static plat_flag g_running = 0;
static int g_active = 0;

static plat_mutex g_lock;
static int g_lock_ready = 0;

static char g_up[8][46];
static int g_up_count = 0;
static int g_enforce = 1;
static int g_log_allowed = 1;
static unsigned long long g_queries = 0, g_blocked = 0;

static char **g_domains = NULL;
static int g_domain_count = 0, g_domain_cap = 0;
static int *g_index = NULL;
static int g_index_cap = 0;

static void ensure_lock(void)
{
    if (!g_lock_ready) {
        plat_mutex_init(&g_lock);
        g_lock_ready = 1;
    }
}

static unsigned hash_text(const char *s)
{
    unsigned h = 2166136261u;
    for (; *s; s++) h = (h ^ (unsigned char)*s) * 16777619u;
    return h;
}

static void index_insert(int i)
{
    unsigned h = hash_text(g_domains[i]) & (unsigned)(g_index_cap - 1);
    while (g_index[h]) h = (h + 1) & (unsigned)(g_index_cap - 1);
    g_index[h] = i + 1;
}

static void index_rebuild(void)
{
    int cap = 1024, i;
    while (cap < g_domain_count * 2 + 2) cap <<= 1;
    free(g_index);
    g_index = (int *)calloc((size_t)cap, sizeof(int));
    g_index_cap = g_index ? cap : 0;
    if (!g_index) return;
    for (i = 0; i < g_domain_count; i++) index_insert(i);
}

static int index_find(const char *domain)
{
    unsigned h;
    if (!g_index_cap) return -1;
    h = hash_text(domain) & (unsigned)(g_index_cap - 1);
    while (g_index[h]) {
        if (!strcmp(g_domains[g_index[h] - 1], domain)) return g_index[h] - 1;
        h = (h + 1) & (unsigned)(g_index_cap - 1);
    }
    return -1;
}

static int normalize(const char *in, char *out, size_t cap)
{
    size_t n = 0;
    int dot = 0;

    while (*in == ' ' || *in == '\t') in++;
    if (in[0] == '*' && in[1] == '.') in += 2;
    while (*in == '.') in++;
    for (; *in && *in != ' ' && *in != '\t' && *in != '\r' && *in != '\n'; in++) {
        char c = *in;
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_')) return 0;
        if (c == '.') dot = 1;
        if (n + 1 >= cap) return 0;
        out[n++] = c;
    }
    while (n && out[n - 1] == '.') n--;
    out[n] = '\0';
    if (!n || !dot) return 0;
    return strcmp(out, "localhost") != 0 && strcmp(out, "localhost.localdomain") != 0;
}

static int add_locked(const char *domain)
{
    char norm[DNSD_NAME];
    char *copy;

    if (!normalize(domain, norm, sizeof norm)) return 0;
    if (index_find(norm) >= 0) return 0;
    if (g_domain_count == g_domain_cap) {
        int cap = g_domain_cap ? g_domain_cap * 2 : 256;
        char **grown = (char **)realloc(g_domains, sizeof(char *) * (size_t)cap);
        if (!grown) return 0;
        g_domains = grown;
        g_domain_cap = cap;
    }
    copy = (char *)malloc(strlen(norm) + 1);
    if (!copy) return 0;
    strcpy_s(copy, strlen(norm) + 1, norm);
    g_domains[g_domain_count++] = copy;
    if (g_domain_count * 2 >= g_index_cap) index_rebuild();
    else index_insert(g_domain_count - 1);
    return 1;
}

int dnsd_block_add(const char *domain)
{
    int added;
    ensure_lock();
    plat_mutex_lock(&g_lock);
    added = add_locked(domain);
    plat_mutex_unlock(&g_lock);
    return added;
}

int dnsd_block_remove(const char *domain)
{
    char norm[DNSD_NAME];
    int i, removed = 0;

    if (!normalize(domain, norm, sizeof norm)) return 0;
    ensure_lock();
    plat_mutex_lock(&g_lock);
    i = index_find(norm);
    if (i >= 0) {
        free(g_domains[i]);
        g_domains[i] = g_domains[--g_domain_count];
        index_rebuild();
        removed = 1;
    }
    plat_mutex_unlock(&g_lock);
    return removed;
}

int dnsd_block_count(void)
{
    int n;
    ensure_lock();
    plat_mutex_lock(&g_lock);
    n = g_domain_count;
    plat_mutex_unlock(&g_lock);
    return n;
}

int dnsd_is_blocked(const char *name)
{
    char norm[DNSD_NAME];
    const char *p;
    int hit = 0;

    if (!normalize(name, norm, sizeof norm)) return 0;
    ensure_lock();
    plat_mutex_lock(&g_lock);
    for (p = norm; p && *p; ) {
        if (index_find(p) >= 0) {
            hit = 1;
            break;
        }
        p = strchr(p, '.');
        if (p) p++;
    }
    plat_mutex_unlock(&g_lock);
    return hit;
}

static int looks_like_ip(const char *token)
{
    unsigned char buf[16];
    return inet_pton(AF_INET, token, buf) == 1 || inet_pton(AF_INET6, token, buf) == 1;
}

int dnsd_block_import(const char *text)
{
    const char *line = text;
    int added = 0;

    ensure_lock();
    plat_mutex_lock(&g_lock);
    while (line && *line) {
        const char *end = strchr(line, '\n');
        size_t len = end ? (size_t)(end - line) : strlen(line);
        char buf[512], *tok, *ctx = NULL, *hash;

        if (len >= sizeof buf) len = sizeof buf - 1;
        memcpy(buf, line, len);
        buf[len] = '\0';
        hash = strchr(buf, '#');
        if (hash) *hash = '\0';

        tok = strtok_s(buf, " \t\r", &ctx);
        if (tok && looks_like_ip(tok)) tok = strtok_s(NULL, " \t\r", &ctx);
        if (tok && add_locked(tok)) added++;

        line = end ? end + 1 : NULL;
    }
    plat_mutex_unlock(&g_lock);
    return added;
}

void dnsd_block_each(int (*fn)(const char *domain, void *ctx), void *ctx)
{
    int i;
    ensure_lock();
    plat_mutex_lock(&g_lock);
    for (i = 0; i < g_domain_count; i++) {
        if (!fn(g_domains[i], ctx)) break;
    }
    plat_mutex_unlock(&g_lock);
}

int dnsd_block_load(const char *path)
{
    FILE *f = NULL;
    char line[512];
    int added = 0;

    if (fopen_s(&f, path, "r") != 0 || !f) return 0;
    ensure_lock();
    plat_mutex_lock(&g_lock);
    while (fgets(line, sizeof line, f)) {
        if (line[0] == '#') continue;
        if (add_locked(line)) added++;
    }
    plat_mutex_unlock(&g_lock);
    fclose(f);
    return added;
}

static int write_entry(const char *domain, void *ctx)
{
    fprintf((FILE *)ctx, "%s\n", domain);
    return 1;
}

int dnsd_block_save(const char *path)
{
    char tmp[MAX_PATH];
    FILE *f = NULL;

    _snprintf_s(tmp, sizeof tmp, _TRUNCATE, "%s.tmp", path);
    if (fopen_s(&f, tmp, "w") != 0 || !f) return 0;
    fprintf(f, "# WireCee DNS blocklist. One domain per line, subdomains included.\n");
    dnsd_block_each(write_entry, f);
    fclose(f);
    return plat_replace_file(tmp, path);
}

static int read_name(const unsigned char *pkt, int len, int off, char *out, int cap, int *next)
{
    int n = 0, jumps = 0, after = -1;

    while (off < len) {
        int label = pkt[off];
        if (label == 0) {
            if (after < 0) after = off + 1;
            if (n == 0 && cap > 0) out[n++] = '.';
            out[n > 0 ? (out[n - 1] == '.' && n > 1 ? n - 1 : n) : 0] = '\0';
            if (next) *next = after;
            return 1;
        }
        if ((label & 0xC0) == 0xC0) {
            if (off + 1 >= len || ++jumps > 16) return 0;
            if (after < 0) after = off + 2;
            off = ((label & 0x3F) << 8) | pkt[off + 1];
            continue;
        }
        if (label > 63 || off + 1 + label > len || n + label + 2 >= cap) return 0;
        memcpy(out + n, pkt + off + 1, (size_t)label);
        n += label;
        out[n++] = '.';
        off += label + 1;
    }
    return 0;
}

static void lower(char *s)
{
    for (; *s; s++) if (*s >= 'A' && *s <= 'Z') *s = (char)(*s - 'A' + 'a');
}

static int parse_question(const unsigned char *pkt, int len, char *name, int cap, int *qtype, int *qend)
{
    int next;
    if (len < 12 || ((pkt[4] << 8) | pkt[5]) < 1) return 0;
    if (!read_name(pkt, len, 12, name, cap, &next) || next + 4 > len) return 0;
    *qtype = (pkt[next] << 8) | pkt[next + 1];
    *qend = next + 4;
    lower(name);
    return 1;
}

static int build_reply(const unsigned char *query, int qend, int rcode, unsigned char *out)
{
    memcpy(out, query, (size_t)qend);
    out[2] = (unsigned char)(0x80 | (query[2] & 0x79));
    out[3] = (unsigned char)(0x80 | rcode);
    out[4] = 0; out[5] = 1;
    out[6] = out[7] = out[8] = out[9] = out[10] = out[11] = 0;
    return qend;
}

static void learn_answers(const unsigned char *pkt, int len, const char *qname, char *first, size_t cap)
{
    char skip[256];
    int off, i, qd, an;

    if (first && cap) first[0] = '\0';
    if (len < 12) return;
    qd = (pkt[4] << 8) | pkt[5];
    an = (pkt[6] << 8) | pkt[7];
    off = 12;
    for (i = 0; i < qd; i++) {
        if (!read_name(pkt, len, off, skip, sizeof skip, &off) || off + 4 > len) return;
        off += 4;
    }
    for (i = 0; i < an; i++) {
        int type, rdlen;
        char ip[46];
        if (!read_name(pkt, len, off, skip, sizeof skip, &off) || off + 10 > len) return;
        type = (pkt[off] << 8) | pkt[off + 1];
        rdlen = (pkt[off + 8] << 8) | pkt[off + 9];
        off += 10;
        if (off + rdlen > len) return;
        ip[0] = '\0';
        if (type == 1 && rdlen == 4) inet_ntop(AF_INET, pkt + off, ip, sizeof ip);
        else if (type == 28 && rdlen == 16) inet_ntop(AF_INET6, pkt + off, ip, sizeof ip);
        if (ip[0]) {
            hostmap_put(ip, qname);
            if (first && !first[0]) strcpy_s(first, cap, ip);
        }
        off += rdlen;
    }
}

static int server_addr(const char *ip, struct sockaddr_storage *ss, int *ss_len)
{
    memset(ss, 0, sizeof *ss);
    if (strchr(ip, ':')) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)ss;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(DNS_PORT);
        if (inet_pton(AF_INET6, ip, &a->sin6_addr) != 1) return 0;
        *ss_len = sizeof *a;
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)ss;
        a->sin_family = AF_INET;
        a->sin_port = htons(DNS_PORT);
        if (inet_pton(AF_INET, ip, &a->sin_addr) != 1) return 0;
        *ss_len = sizeof *a;
    }
    return 1;
}

static void send_upstream(Slot *s)
{
    struct sockaddr_storage ss;
    int ss_len = 0, count;
    char server[46];
    plat_socket sock;

    plat_mutex_lock(&g_lock);
    count = g_up_count;
    if (count) strcpy_s(server, sizeof server, g_up[s->tries % count]);
    plat_mutex_unlock(&g_lock);

    s->tries++;
    s->sent_ms = plat_now_ms();
    if (!count || !server_addr(server, &ss, &ss_len)) return;
    sock = ss.ss_family == AF_INET6 ? g_up6 : g_up4;
    if (sock == PLAT_BAD_SOCKET) return;
    sendto(sock, (const char *)s->pkt, s->pkt_len, 0, (struct sockaddr *)&ss, ss_len);
}

static void handle_client(plat_socket listen)
{
    unsigned char buf[PKT_MAX], reply[PKT_MAX];
    struct sockaddr_storage from;
    socklen_t from_len = sizeof from;
    char name[DNSD_NAME];
    int len, qtype, qend, i, blocked;
    Slot *slot = NULL;

    len = (int)recvfrom(listen, (char *)buf, sizeof buf, 0, (struct sockaddr *)&from, &from_len);
    if (len < 12 || (buf[2] & 0x80)) return;
    if (!parse_question(buf, len, name, sizeof name, &qtype, &qend)) return;

    plat_mutex_lock(&g_lock);
    g_queries++;
    plat_mutex_unlock(&g_lock);

    blocked = g_enforce && dnsd_is_blocked(name);
    if (blocked) {
        int n = build_reply(buf, qend, 3, reply);
        sendto(listen, (const char *)reply, n, 0, (struct sockaddr *)&from, from_len);
        plat_mutex_lock(&g_lock);
        g_blocked++;
        plat_mutex_unlock(&g_lock);
        if (g_log_allowed) dnslog_add(0, name, qtype, DNSLOG_BLOCKED, "");
        return;
    }

    for (i = 0; i < SLOTS; i++) {
        Slot *s = &g_slots[(g_cursor + i) & (SLOTS - 1)];
        if (!s->used) {
            slot = s;
            g_cursor = (g_cursor + i + 1) & (SLOTS - 1);
            break;
        }
    }
    if (!slot) {
        int n = build_reply(buf, qend, 2, reply);
        sendto(listen, (const char *)reply, n, 0, (struct sockaddr *)&from, from_len);
        return;
    }

    memset(slot, 0, sizeof *slot);
    slot->used = 1;
    slot->orig_id = (unsigned short)((buf[0] << 8) | buf[1]);
    slot->up_id = (unsigned short)((slot - g_slots) | ((rand() & 0x3F) << 10));
    memcpy(&slot->client, &from, (size_t)from_len);
    slot->client_len = (int)from_len;
    slot->via = listen;
    memcpy(slot->pkt, buf, (size_t)len);
    slot->pkt_len = len;
    slot->pkt[0] = (unsigned char)(slot->up_id >> 8);
    slot->pkt[1] = (unsigned char)(slot->up_id & 0xFF);
    slot->qtype = qtype;
    strcpy_s(slot->name, sizeof slot->name, name);
    slot->first_ms = plat_now_ms();
    send_upstream(slot);
}

static void handle_upstream(plat_socket sock)
{
    unsigned char buf[4096];
    struct sockaddr_storage from;
    socklen_t from_len = sizeof from;
    char answer[46];
    int len, id;
    Slot *slot;

    len = (int)recvfrom(sock, (char *)buf, sizeof buf, 0, (struct sockaddr *)&from, &from_len);
    if (len < 12) return;
    id = (buf[0] << 8) | buf[1];
    slot = &g_slots[id & (SLOTS - 1)];
    if (!slot->used || slot->up_id != id) return;

    buf[0] = (unsigned char)(slot->orig_id >> 8);
    buf[1] = (unsigned char)(slot->orig_id & 0xFF);
    learn_answers(buf, len, slot->name, answer, sizeof answer);
    sendto(slot->via, (const char *)buf, len, 0, (struct sockaddr *)&slot->client, slot->client_len);
    if (g_log_allowed) {
        dnslog_add(0, slot->name, slot->qtype, (buf[3] & 0x0F) == 0 ? DNSLOG_ALLOWED : DNSLOG_FAILED, answer);
    }
    slot->used = 0;
}

static void expire_slots(void)
{
    long long now = plat_now_ms();
    int i, max_tries;

    plat_mutex_lock(&g_lock);
    max_tries = g_up_count < 2 ? 2 : g_up_count;
    plat_mutex_unlock(&g_lock);

    for (i = 0; i < SLOTS; i++) {
        Slot *s = &g_slots[i];
        if (!s->used) continue;
        if (now - s->first_ms > GIVE_UP_MS || (now - s->sent_ms > RETRY_MS && s->tries >= max_tries)) {
            unsigned char reply[PKT_MAX];
            char name[DNSD_NAME];
            int qtype, qend;
            s->pkt[0] = (unsigned char)(s->orig_id >> 8);
            s->pkt[1] = (unsigned char)(s->orig_id & 0xFF);
            if (parse_question(s->pkt, s->pkt_len, name, sizeof name, &qtype, &qend)) {
                int n = build_reply(s->pkt, qend, 2, reply);
                sendto(s->via, (const char *)reply, n, 0, (struct sockaddr *)&s->client, s->client_len);
            }
            if (g_log_allowed) dnslog_add(0, s->name, s->qtype, DNSLOG_FAILED, "");
            s->used = 0;
        } else if (now - s->sent_ms > RETRY_MS) {
            send_upstream(s);
        }
    }
}

static void set_timeouts(plat_socket s, int ms)
{
#ifdef _WIN32
    DWORD t = (DWORD)ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&t, sizeof t);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&t, sizeof t);
#else
    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
#endif
}

static int recv_all(plat_socket s, unsigned char *buf, int len)
{
    int got = 0;
    while (got < len) {
        int n = (int)recv(s, (char *)buf + got, len - got, 0);
        if (n <= 0) return 0;
        got += n;
    }
    return 1;
}

static int send_framed(plat_socket s, const unsigned char *msg, int len)
{
    unsigned char prefix[2];
    prefix[0] = (unsigned char)(len >> 8);
    prefix[1] = (unsigned char)(len & 0xFF);
    return send(s, (const char *)prefix, 2, 0) == 2 && send(s, (const char *)msg, len, 0) == len;
}

static void tcp_session(void *arg)
{
    plat_socket client = *(plat_socket *)arg;
    plat_socket up = PLAT_BAD_SOCKET;
    unsigned char *query = NULL, *resp = NULL, prefix[2];
    char name[DNSD_NAME], server[46], answer[46];
    struct sockaddr_storage ss;
    int ss_len = 0, len, rlen, qtype, qend, count;

    free(arg);
    set_timeouts(client, 5000);
    query = (unsigned char *)malloc(TCP_MAX);
    resp = (unsigned char *)malloc(TCP_MAX);
    if (!query || !resp || !recv_all(client, prefix, 2)) goto done;
    len = (prefix[0] << 8) | prefix[1];
    if (len < 12 || len > TCP_MAX || !recv_all(client, query, len)) goto done;
    if (!parse_question(query, len, name, sizeof name, &qtype, &qend)) goto done;

    if (g_enforce && dnsd_is_blocked(name)) {
        int n = build_reply(query, qend, 3, resp);
        send_framed(client, resp, n);
        plat_mutex_lock(&g_lock);
        g_blocked++;
        plat_mutex_unlock(&g_lock);
        goto done;
    }

    plat_mutex_lock(&g_lock);
    count = g_up_count;
    if (count) strcpy_s(server, sizeof server, g_up[0]);
    plat_mutex_unlock(&g_lock);
    if (!count || !server_addr(server, &ss, &ss_len)) goto done;

    up = socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (up == PLAT_BAD_SOCKET) goto done;
    set_timeouts(up, 4000);
    if (connect(up, (struct sockaddr *)&ss, ss_len) != 0) goto done;
    if (!send_framed(up, query, len) || !recv_all(up, prefix, 2)) goto done;
    rlen = (prefix[0] << 8) | prefix[1];
    if (rlen < 12 || rlen > TCP_MAX || !recv_all(up, resp, rlen)) goto done;
    learn_answers(resp, rlen, name, answer, sizeof answer);
    send_framed(client, resp, rlen);

done:
    if (up != PLAT_BAD_SOCKET) plat_closesocket(up);
    plat_closesocket(client);
    free(query);
    free(resp);
}

static void accept_tcp(plat_socket listen)
{
    plat_socket *job;
    plat_thread t;
    plat_socket s = accept(listen, NULL, NULL);

    if (s == PLAT_BAD_SOCKET) return;
    job = (plat_socket *)malloc(sizeof *job);
    if (!job) {
        plat_closesocket(s);
        return;
    }
    *job = s;
    t = plat_thread_start(tcp_session, job);
    if (!t) {
        plat_closesocket(s);
        free(job);
        return;
    }
    plat_thread_join(t, 0);
}

static plat_socket open_socket(int family, int type, const char *addr, int port, int listen_backlog)
{
    plat_socket s = socket(family, type, type == SOCK_DGRAM ? IPPROTO_UDP : IPPROTO_TCP);
    struct sockaddr_storage ss;
    int len;

    if (s == PLAT_BAD_SOCKET) return s;
    memset(&ss, 0, sizeof ss);
    if (family == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        int v6only = 1;
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&v6only, sizeof v6only);
        a->sin6_family = AF_INET6;
        a->sin6_port = htons((unsigned short)port);
        inet_pton(AF_INET6, addr, &a->sin6_addr);
        len = sizeof *a;
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET;
        a->sin_port = htons((unsigned short)port);
        inet_pton(AF_INET, addr, &a->sin_addr);
        len = sizeof *a;
    }
#ifndef _WIN32
    if (type == SOCK_STREAM) {
        int one = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    }
#endif
    if (bind(s, (struct sockaddr *)&ss, len) != 0 ||
        (type == SOCK_STREAM && listen(s, listen_backlog) != 0)) {
        plat_closesocket(s);
        return PLAT_BAD_SOCKET;
    }
#ifdef _WIN32
    if (type == SOCK_DGRAM) {
        BOOL off = FALSE;
        DWORD ret = 0;
        WSAIoctl(s, SIO_UDP_CONNRESET, &off, sizeof off, NULL, 0, &ret, NULL, NULL);
    }
#endif
    return s;
}

static void close_all(void)
{
    plat_socket *all[] = {&g_udp4, &g_udp6, &g_tcp4, &g_tcp6, &g_up4, &g_up6};
    size_t i;
    for (i = 0; i < sizeof all / sizeof all[0]; i++) {
        if (*all[i] != PLAT_BAD_SOCKET) plat_closesocket(*all[i]);
        *all[i] = PLAT_BAD_SOCKET;
    }
}

static void resolver_loop(void *arg)
{
    (void)arg;
    while (plat_flag_get(&g_running)) {
        plat_socket socks[6];
        fd_set rd;
        struct timeval tv;
        int i, count = 0, n;
#ifndef _WIN32
        int maxfd = 0;
#endif
        socks[0] = g_udp4; socks[1] = g_udp6; socks[2] = g_up4;
        socks[3] = g_up6; socks[4] = g_tcp4; socks[5] = g_tcp6;

        FD_ZERO(&rd);
        for (i = 0; i < 6; i++) {
            if (socks[i] == PLAT_BAD_SOCKET) continue;
            FD_SET(socks[i], &rd);
            count++;
#ifndef _WIN32
            if (socks[i] > maxfd) maxfd = socks[i];
#endif
        }
        if (!count) break;
        tv.tv_sec = 0;
        tv.tv_usec = 250000;
#ifdef _WIN32
        n = select(0, &rd, NULL, NULL, &tv);
#else
        n = select(maxfd + 1, &rd, NULL, NULL, &tv);
#endif
        if (n > 0) {
            if (g_udp4 != PLAT_BAD_SOCKET && FD_ISSET(g_udp4, &rd)) handle_client(g_udp4);
            if (g_udp6 != PLAT_BAD_SOCKET && FD_ISSET(g_udp6, &rd)) handle_client(g_udp6);
            if (g_up4 != PLAT_BAD_SOCKET && FD_ISSET(g_up4, &rd)) handle_upstream(g_up4);
            if (g_up6 != PLAT_BAD_SOCKET && FD_ISSET(g_up6, &rd)) handle_upstream(g_up6);
            if (g_tcp4 != PLAT_BAD_SOCKET && FD_ISSET(g_tcp4, &rd)) accept_tcp(g_tcp4);
            if (g_tcp6 != PLAT_BAD_SOCKET && FD_ISSET(g_tcp6, &rd)) accept_tcp(g_tcp6);
        }
        expire_slots();
    }
}

int dnsd_start(char *reason, size_t cap)
{
    ensure_lock();
    if (g_active) return 1;
    plat_init();

    g_udp4 = open_socket(AF_INET, SOCK_DGRAM, "127.0.0.1", DNS_PORT, 0);
    if (g_udp4 == PLAT_BAD_SOCKET) {
        _snprintf_s(reason, cap, _TRUNCATE, "Port 53 on 127.0.0.1 is in use by another program");
        close_all();
        return 0;
    }
    g_tcp4 = open_socket(AF_INET, SOCK_STREAM, "127.0.0.1", DNS_PORT, 16);
    g_udp6 = open_socket(AF_INET6, SOCK_DGRAM, "::1", DNS_PORT, 0);
    g_tcp6 = open_socket(AF_INET6, SOCK_STREAM, "::1", DNS_PORT, 16);
    g_up4 = open_socket(AF_INET, SOCK_DGRAM, "0.0.0.0", 0, 0);
    g_up6 = open_socket(AF_INET6, SOCK_DGRAM, "::", 0, 0);

    memset(g_slots, 0, sizeof g_slots);
    plat_flag_set(&g_running, 1);
    g_thread = plat_thread_start(resolver_loop, NULL);
    if (!g_thread) {
        plat_flag_set(&g_running, 0);
        close_all();
        _snprintf_s(reason, cap, _TRUNCATE, "The resolver thread could not be started");
        return 0;
    }
    g_active = 1;
    return 1;
}

void dnsd_stop(void)
{
    if (!g_active) return;
    plat_flag_set(&g_running, 0);
    plat_thread_join(g_thread, 2000);
    g_thread = NULL;
    close_all();
    g_active = 0;
}

int dnsd_active(void) { return g_active; }

void dnsd_set_upstreams(char servers[][46], int count)
{
    int i;
    ensure_lock();
    plat_mutex_lock(&g_lock);
    g_up_count = 0;
    for (i = 0; i < count && g_up_count < 8; i++) {
        if (!servers[i][0] || !strncmp(servers[i], "127.", 4) || !strcmp(servers[i], "::1")) continue;
        if (!_strnicmp(servers[i], "fec0:", 5) || !_strnicmp(servers[i], "fe80:", 5)) continue;
        strcpy_s(g_up[g_up_count++], 46, servers[i]);
    }
    plat_mutex_unlock(&g_lock);
}

void dnsd_set_enforce(int on) { g_enforce = on; }
void dnsd_set_log_allowed(int on) { g_log_allowed = on; }

void dnsd_stats(unsigned long long *queries, unsigned long long *blocked)
{
    ensure_lock();
    plat_mutex_lock(&g_lock);
    if (queries) *queries = g_queries;
    if (blocked) *blocked = g_blocked;
    plat_mutex_unlock(&g_lock);
}
