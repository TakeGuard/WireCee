#include "fw.h"
#include "platform.h"

#include <dirent.h>
#include <sys/stat.h>

#define CG_ROOT "/sys/fs/cgroup"
#define CG_BLOCK "wirecee-blocked"
#define CG_ALLOW "wirecee-allowed"
#define SCRIPT_CAP (4 * 1024 * 1024)

static const char *const DOH_V4[] = {
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "8.8.8.8", "8.8.4.4", "9.9.9.9",
    "149.112.112.112", "94.140.14.14", "94.140.15.15", "208.67.222.222", "208.67.220.220",
    "185.228.168.9", "185.228.169.9", "194.242.2.2", NULL};
static const char *const DOH_V6[] = {
    "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888",
    "2001:4860:4860::8844", "2620:fe::fe", "2620:fe::9", NULL};

static plat_mutex g_lock;
static int g_lock_ready = 0;
static int g_active = 0;
static int g_cgroups = 0;

static char g_block_paths[256][MAX_PATH];
static int g_block_count = 0;
static char g_allow_paths[256][MAX_PATH];
static int g_allow_count = 0;

typedef struct {
    char tag[24];
    FwDirection dir;
    unsigned long long packets;
} Counter;

static Counter g_counters[512];
static int g_counter_count = 0;
static FwDrop g_drops[256];
static int g_drop_count = 0;
static int g_tick = 0;

static void ensure_lock(void)
{
    if (!g_lock_ready) {
        plat_mutex_init(&g_lock);
        g_lock_ready = 1;
    }
}

int fw_start(char *reason, size_t cap)
{
    struct stat st;

    ensure_lock();
    if (g_active) return 1;
    if (geteuid() != 0) {
        _snprintf_s(reason, cap, _TRUNCATE, "Blocking requires root. Start WireCee with sudo.");
        return 0;
    }
    if (plat_run("nft --version") != 0) {
        _snprintf_s(reason, cap, _TRUNCATE, "nftables is not installed. Install the nftables package.");
        return 0;
    }
    plat_run("nft delete table inet wirecee");

    g_cgroups = stat(CG_ROOT "/cgroup.controllers", &st) == 0;
    if (g_cgroups) {
        mkdir(CG_ROOT "/" CG_BLOCK, 0755);
        mkdir(CG_ROOT "/" CG_ALLOW, 0755);
        g_cgroups = stat(CG_ROOT "/" CG_BLOCK "/cgroup.procs", &st) == 0;
    }
    g_active = 1;
    return 1;
}

void fw_stop(void)
{
    if (!g_active) return;
    plat_run("nft delete table inet wirecee");
    g_active = 0;
}

int fw_active(void) { return g_active; }

static int safe_addr(const char *s)
{
    if (!*s) return 0;
    for (; *s; s++) {
        if (!((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f') || (*s >= 'A' && *s <= 'F') ||
              *s == '.' || *s == ':' || *s == '/')) return 0;
    }
    return 1;
}

static int is_any(const char *s)
{
    return !s[0] || !_stricmp(s, "any") || !strcmp(s, "*");
}

typedef struct {
    char *buf;
    size_t n;
    int rules;
} Script;

static void emit(Script *s, const char *fmt, ...)
{
    va_list args;
    int w;
    if (s->n + 512 >= SCRIPT_CAP) return;
    va_start(args, fmt);
    w = vsnprintf(s->buf + s->n, SCRIPT_CAP - s->n, fmt, args);
    va_end(args);
    if (w > 0) s->n += (size_t)w;
}

static int emit_addrs(Script *s, const FwRule *r, FwDirection dir, int v6)
{
    const char *p = r->remote;
    int count = 0;

    while (*p) {
        char one[64];
        size_t len = strcspn(p, ",");
        if (len && len < sizeof one) {
            memcpy(one, p, len);
            one[len] = '\0';
            if (safe_addr(one) && (strchr(one, ':') != NULL) == v6) {
                if (!count) emit(s, "    %s %s { ", v6 ? "ip6" : "ip", dir == FW_OUT ? "daddr" : "saddr");
                emit(s, "%s%s", count ? ", " : "", one);
                count++;
            }
        }
        p += len;
        if (*p == ',') p++;
    }
    if (count) emit(s, " } ");
    return count > 0;
}

static void emit_rule(Script *s, const FwRule *r, FwDirection dir)
{
    char match[256] = "";
    const char *verdict = !_stricmp(r->action, "allow") ? "accept" : "drop";
    int port = is_any(r->port) ? 0 : atoi(r->port);
    int family;

    if (!is_any(r->port) && (port < 1 || port > 65535)) return;

    if (!_stricmp(r->proto, "TCP") || !_stricmp(r->proto, "UDP")) {
        char p[64];
        const char *proto = !_stricmp(r->proto, "TCP") ? "tcp" : "udp";
        if (port) _snprintf_s(p, sizeof p, _TRUNCATE, "%s dport %d ", proto, port);
        else _snprintf_s(p, sizeof p, _TRUNCATE, "meta l4proto %s ", proto);
        strcat_s(match, sizeof match, p);
    } else if (port) {
        char p[64];
        _snprintf_s(p, sizeof p, _TRUNCATE, "meta l4proto { tcp, udp } th dport %d ", port);
        strcat_s(match, sizeof match, p);
    }
    if (is_any(r->remote)) {
        emit(s, "    %scounter %s comment \"%s\"\n", match, verdict, r->id);
        s->rules++;
        return;
    }
    for (family = 0; family < 2; family++) {
        if (!emit_addrs(s, r, dir, family)) continue;
        emit(s, "%scounter %s comment \"%s\"\n", match, verdict, r->id);
        s->rules++;
    }
}

static void emit_doh(Script *s)
{
    int i;
    emit(s, "    meta l4proto { tcp, udp } th dport 853 counter drop comment \"encrypted-dns\"\n");
    emit(s, "    ip daddr { ");
    for (i = 0; DOH_V4[i]; i++) emit(s, "%s%s", i ? ", " : "", DOH_V4[i]);
    emit(s, " } meta l4proto { tcp, udp } th dport 443 counter drop comment \"encrypted-dns\"\n");
    emit(s, "    ip6 daddr { ");
    for (i = 0; DOH_V6[i]; i++) emit(s, "%s%s", i ? ", " : "", DOH_V6[i]);
    emit(s, " } meta l4proto { tcp, udp } th dport 443 counter drop comment \"encrypted-dns\"\n");
    s->rules += 3;
}

int fw_apply(const FwPolicy *p, char *detail, size_t cap)
{
    Script s;
    char path[MAX_PATH], command[MAX_PATH + 32];
    FILE *f;
    int i, lockdown, out_block, in_block, rc;

    if (!g_active) {
        _snprintf_s(detail, cap, _TRUNCATE, "Enforcement is not running");
        return -1;
    }
    memset(&s, 0, sizeof s);
    s.buf = (char *)malloc(SCRIPT_CAP);
    if (!s.buf) return -1;

    lockdown = !_stricmp(p->posture, "lockdown");
    out_block = lockdown || _stricmp(p->default_out, "allow") != 0;
    in_block = lockdown || _stricmp(p->default_in, "allow") != 0;

    emit(&s, "table inet wirecee\ndelete table inet wirecee\n");
    if (_stricmp(p->posture, "off") != 0) {
        emit(&s, "table inet wirecee {\n  chain output {\n    type filter hook output priority 0; policy accept;\n");
        emit(&s, "    oif \"lo\" accept\n");
        if (p->dns_guard) {
            emit(&s, "    meta skuid 0 meta l4proto { tcp, udp } th dport 53 accept\n");
            emit(&s, "    meta l4proto { tcp, udp } th dport 53 counter drop comment \"dns-guard\"\n");
            s.rules += 2;
        }
        if (p->block_encrypted_dns) emit_doh(&s);
        if (g_cgroups) {
            emit(&s, "    socket cgroupv2 level 1 \"" CG_BLOCK "\" counter drop comment \"blocked-apps\"\n");
            s.rules++;
        }
        for (i = 0; i < p->rule_count; i++) {
            if (_stricmp(p->rules[i].direction, "in")) emit_rule(&s, &p->rules[i], FW_OUT);
        }
        if (out_block) {
            emit(&s, "    ct state established,related accept\n");
            emit(&s, "    meta l4proto { icmp, ipv6-icmp } accept\n");
            emit(&s, "    meta l4proto { tcp, udp } th dport 53 accept\n");
            emit(&s, "    udp dport { 67, 68, 546, 547 } accept\n");
            if (!lockdown && g_cgroups) emit(&s, "    socket cgroupv2 level 1 \"" CG_ALLOW "\" accept\n");
            emit(&s, "    counter drop comment \"default-out\"\n");
            s.rules += 6;
        }
        emit(&s, "  }\n  chain input {\n    type filter hook input priority 0; policy accept;\n");
        emit(&s, "    iif \"lo\" accept\n");
        if (g_cgroups) emit(&s, "    socket cgroupv2 level 1 \"" CG_BLOCK "\" counter drop comment \"blocked-apps\"\n");
        for (i = 0; i < p->rule_count; i++) {
            if (_stricmp(p->rules[i].direction, "out")) emit_rule(&s, &p->rules[i], FW_IN);
        }
        if (in_block) {
            emit(&s, "    ct state established,related accept\n");
            emit(&s, "    meta l4proto { icmp, ipv6-icmp } accept\n");
            emit(&s, "    udp dport { 68, 546 } accept\n");
            emit(&s, "    counter drop comment \"default-in\"\n");
            s.rules += 4;
        }
        emit(&s, "  }\n}\n");
    }

    plat_data_path(NULL, "wirecee.nft", path, sizeof path);
    f = fopen(path, "w");
    if (!f) {
        free(s.buf);
        _snprintf_s(detail, cap, _TRUNCATE, "The rule script could not be written");
        return -1;
    }
    fwrite(s.buf, 1, s.n, f);
    fclose(f);
    free(s.buf);

    _snprintf_s(command, sizeof command, _TRUNCATE, "nft -f %s", path);
    rc = plat_run(command);
    if (rc != 0) {
        _snprintf_s(detail, cap, _TRUNCATE, "nftables rejected the rule set (exit %d). Previous rules kept.", rc);
        return -1;
    }

    plat_mutex_lock(&g_lock);
    g_block_count = g_allow_count = 0;
    for (i = 0; i < p->app_count; i++) {
        if (p->apps[i].block && g_block_count < 256) strcpy_s(g_block_paths[g_block_count++], MAX_PATH, p->apps[i].path);
        else if (p->apps[i].allow && g_allow_count < 256) strcpy_s(g_allow_paths[g_allow_count++], MAX_PATH, p->apps[i].path);
    }
    g_counter_count = 0;
    plat_mutex_unlock(&g_lock);

    g_tick = 0;
    fw_tick();
    _snprintf_s(detail, cap, _TRUNCATE, "%d nftables rules installed%s", s.rules,
                g_cgroups ? "" : ". Application policies need cgroup v2 and are not enforced");
    return s.rules;
}

static void move_pid(unsigned long pid, const char *group)
{
    char path[128], line[32];
    FILE *f;
    _snprintf_s(path, sizeof path, _TRUNCATE, CG_ROOT "/%s/cgroup.procs", group);
    f = fopen(path, "w");
    if (!f) return;
    _snprintf_s(line, sizeof line, _TRUNCATE, "%lu\n", pid);
    fputs(line, f);
    fclose(f);
}

enum { GROUP_NONE = 0, GROUP_BLOCK = 1, GROUP_ALLOW = 2 };

static int group_of(unsigned long pid)
{
    char path[64], line[512];
    FILE *f;
    int group = GROUP_NONE;
    _snprintf_s(path, sizeof path, _TRUNCATE, "/proc/%lu/cgroup", pid);
    f = fopen(path, "r");
    if (!f) return GROUP_NONE;
    while (fgets(line, sizeof line, f)) {
        if (strstr(line, CG_BLOCK)) group = GROUP_BLOCK;
        else if (strstr(line, CG_ALLOW)) group = GROUP_ALLOW;
    }
    fclose(f);
    return group;
}

static int endpoint_text(const char *s)
{
    if (!*s) return 0;
    for (; *s; s++) {
        if (!((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
              *s == '.' || *s == ':' || *s == '[' || *s == ']' || *s == '%' || *s == '_' || *s == '-')) return 0;
    }
    return 1;
}

static void cut_sockets(const unsigned long *pids, int count)
{
    static unsigned long inodes[4096];
    int n = 0, i;
    FILE *ss;
    char line[512];

    for (i = 0; i < count; i++) {
        char dir[64], link[64], target[64];
        DIR *fd;
        struct dirent *e;
        _snprintf_s(dir, sizeof dir, _TRUNCATE, "/proc/%lu/fd", pids[i]);
        fd = opendir(dir);
        if (!fd) continue;
        while ((e = readdir(fd)) != NULL && n < 4096) {
            ssize_t len;
            _snprintf_s(link, sizeof link, _TRUNCATE, "%s/%s", dir, e->d_name);
            len = readlink(link, target, sizeof target - 1);
            if (len <= 0) continue;
            target[len] = '\0';
            if (!strncmp(target, "socket:[", 8)) inodes[n++] = strtoul(target + 8, NULL, 10);
        }
        closedir(fd);
    }
    if (!n) return;

    ss = popen("ss -Htuane 2>/dev/null", "r");
    if (!ss) return;
    while (fgets(line, sizeof line, ss)) {
        char netid[8], state[16], rq[16], sq[16], local[128], peer[128], command[400];
        char *ino = strstr(line, "ino:");
        unsigned long inode;
        int hit = 0;

        if (!ino || sscanf(line, "%7s %15s %15s %15s %127s %127s", netid, state, rq, sq, local, peer) != 6) continue;
        inode = strtoul(ino + 4, NULL, 10);
        for (i = 0; i < n && !hit; i++) hit = inodes[i] == inode;
        if (!hit || strchr(peer, '*') || !endpoint_text(local) || !endpoint_text(peer)) continue;
        _snprintf_s(command, sizeof command, _TRUNCATE, "ss -K -%c src %s dst %s",
                    netid[0] == 'u' ? 'u' : 't', local, peer);
        plat_run(command);
    }
    pclose(ss);
}

static void sync_processes(void)
{
    DIR *proc;
    struct dirent *e;
    unsigned long moved[512];
    int moved_count = 0;

    if (!g_cgroups) return;
    proc = opendir("/proc");
    if (!proc) return;
    plat_mutex_lock(&g_lock);
    while ((e = readdir(proc)) != NULL) {
        char link[64], exe[MAX_PATH], *deleted;
        unsigned long pid;
        ssize_t n;
        int i, blocked = 0, allowed = 0, current;

        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        pid = strtoul(e->d_name, NULL, 10);
        if (pid == (unsigned long)getpid()) continue;
        _snprintf_s(link, sizeof link, _TRUNCATE, "/proc/%lu/exe", pid);
        n = readlink(link, exe, sizeof exe - 1);
        if (n <= 0) continue;
        exe[n] = '\0';
        deleted = strstr(exe, " (deleted)");
        if (deleted) *deleted = '\0';

        for (i = 0; i < g_block_count; i++) if (!strcmp(g_block_paths[i], exe)) blocked = 1;
        for (i = 0; i < g_allow_count && !blocked; i++) if (!strcmp(g_allow_paths[i], exe)) allowed = 1;

        current = group_of(pid);
        if (blocked && current != GROUP_BLOCK) {
            move_pid(pid, CG_BLOCK);
            if (moved_count < 512) moved[moved_count++] = pid;
        }
        else if (allowed && current != GROUP_ALLOW) move_pid(pid, CG_ALLOW);
        else if (!blocked && !allowed && current != GROUP_NONE) {
            FILE *f = fopen(CG_ROOT "/cgroup.procs", "w");
            if (f) {
                fprintf(f, "%lu\n", pid);
                fclose(f);
            }
        }
    }
    plat_mutex_unlock(&g_lock);
    closedir(proc);
    cut_sockets(moved, moved_count);
}

static void read_counters(void)
{
    FILE *f = popen("nft list table inet wirecee 2>/dev/null", "r");
    char line[1024];
    FwDirection dir = FW_OUT;

    if (!f) return;
    plat_mutex_lock(&g_lock);
    while (fgets(line, sizeof line, f)) {
        char *counter, *comment, tag[24];
        unsigned long long packets;
        int i;

        if (strstr(line, "chain output")) dir = FW_OUT;
        else if (strstr(line, "chain input")) dir = FW_IN;
        counter = strstr(line, "counter packets ");
        comment = strstr(line, "comment \"");
        if (!counter || !comment || sscanf(counter, "counter packets %llu", &packets) != 1) continue;
        if (sscanf(comment, "comment \"%23[^\"]\"", tag) != 1) continue;

        for (i = 0; i < g_counter_count; i++) {
            if (!strcmp(g_counters[i].tag, tag) && g_counters[i].dir == dir) break;
        }
        if (i == g_counter_count) {
            if (g_counter_count == 512) continue;
            strcpy_s(g_counters[i].tag, sizeof g_counters[i].tag, tag);
            g_counters[i].dir = dir;
            g_counters[i].packets = packets;
            g_counter_count++;
            continue;
        }
        if (packets > g_counters[i].packets && g_drop_count < 256) {
            FwDrop *d = &g_drops[g_drop_count++];
            memset(d, 0, sizeof *d);
            d->direction = dir;
            d->count = (int)(packets - g_counters[i].packets);
            if (!strncmp(tag, "rule_", 5)) strcpy_s(d->rule_id, sizeof d->rule_id, tag);
            else if (!strcmp(tag, "blocked-apps")) strcpy_s(d->app_path, sizeof d->app_path, "Blocked applications");
            else if (!strcmp(tag, "dns-guard")) strcpy_s(d->app_path, sizeof d->app_path, "DNS bypass attempts");
            else if (!strcmp(tag, "encrypted-dns")) strcpy_s(d->app_path, sizeof d->app_path, "Encrypted DNS");
            else strcpy_s(d->app_path, sizeof d->app_path, "Default policy");
        }
        g_counters[i].packets = packets;
    }
    plat_mutex_unlock(&g_lock);
    pclose(f);
}

void fw_tick(void)
{
    if (!g_active) return;
    if (g_tick % 2 == 0) sync_processes();
    if (g_tick % 3 == 0) read_counters();
    g_tick++;
}

int fw_take_drops(FwDrop *out, int cap)
{
    int n;
    ensure_lock();
    plat_mutex_lock(&g_lock);
    n = g_drop_count < cap ? g_drop_count : cap;
    memcpy(out, g_drops, sizeof(FwDrop) * (size_t)n);
    g_drop_count = 0;
    plat_mutex_unlock(&g_lock);
    return n;
}
