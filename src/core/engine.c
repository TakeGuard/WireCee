#include "compat.h"

#include "engine.h"
#include "platform.h"
#include "netenum.h"
#include "fw.h"
#include "flows.h"
#include "dnsd.h"
#include "hostmap.h"
#include "c2list.h"

#include <time.h>

#ifndef _WIN32
#include <netdb.h>
#endif

typedef struct {
    char id[16];
    char name[64];
    char path[192];
    Policy policy;
    int connections;
    long long rx, tx;
    long long retired_rx, retired_tx;
    long long counted_rx, counted_tx;
    long long first_seen;
    int pinned;
} App;

typedef struct {
    char id[16];
    char process[64];
    char path[192];
    unsigned long pid;
    int local_port;
    char remote_ip[46];
    char remote_host[96];
    int remote_port;
    char proto[8];
    char state[16];
    long long rx, tx;
    long long since;
    NetConn net;
    int has_net;
} Conn;

typedef struct {
    char id[16];
    char name[96];
    char action[8];
    char direction[8];
    char remote[FW_REMOTE_CAP];
    char port[16];
    char proto[8];
    char note[192];
    int enabled;
    int hits;
    int builtin;
} Rule;

typedef struct {
    char id[16];
    long long ts;
    char level[8];
    char message[256];
} LogEntry;

typedef struct {
    int startWithWindows, notifyOnBlock, notifyOnNewApp, keepRunningInBackground;
    char defaultOutbound[8], defaultInbound[8];
    int logRetentionDays;
    int dnsFilter, blockEncryptedDns;
    char dnsUpstream[16];
    int notifyOnNewDevice, quietMode;
    int alertHostsFile, alertDnsChange, alertProxyChange, alertRemoteAccess, alertAppChange;
    int alertNotify;
    int dataLimitMb, dataResetDay;
} Settings;

#define ENG_MAX_DEVICES 256
#define ENG_MAX_ALERTS 200
#define NOTICE_CAP 16
#define USAGE_DAYS 100
#define USAGE_APP_ROWS 8192
#define USAGE_KEEP_DAYS 90
#define ENG_MAX_FPS 512

typedef struct {
    char mac[18];
    char ip[46];
    char name[64];
    char hostname[96];
    long long first_seen, last_seen;
    int online, gateway, resolve_tried;
} Device;

typedef struct {
    char id[16];
    long long ts;
    char kind[16];
    char title[96];
    char detail[256];
    int unread;
} Alert;

typedef struct {
    char title[64];
    char body[256];
} Notice;

typedef struct {
    int day;
    long long rx, tx;
} DayTotal;

typedef struct {
    int day;
    char app[64];
    long long rx, tx;
} DayApp;

typedef struct {
    char name[64];
    char path[MAX_PATH];
    long long size, mtime;
} Fingerprint;

static plat_rwlock g_lock;
static plat_mutex g_enforce_lock;
static plat_thread g_tick_thread = NULL;
static plat_thread g_monitor_thread = NULL;
static plat_flag g_running = 0;
static unsigned g_generation = 0;
static unsigned g_next_id = 1;

static App g_apps[ENG_MAX_APPS];
static int g_app_count = 0;
static Conn g_conns[ENG_MAX_CONNS];
static int g_conn_count = 0;
static Rule g_rules[ENG_MAX_RULES];
static int g_rule_count = 0;
static LogEntry g_logs[ENG_MAX_LOGS];
static int g_log_count = 0;
static Settings g_settings;
static char g_posture[12] = "on";

static long long g_blocked24h = 0, g_allowed24h = 0;

static char g_notice[256] = {0};
static int g_notice_pending = 0;
static Notice g_notices[NOTICE_CAP];
static int g_notice_count = 0;

#define SAMPLES 60
static long long g_rx[SAMPLES], g_tx[SAMPLES];

static Snapshot g_snaps[SNAP_COUNT];

static int g_enforcing = 0;
static char g_enforcement_reason[160] = "Starting";

static int g_dns_active = 0;
static char g_dns_reason[160] = "Off";
static char g_dns_servers[8][46];
static int g_dns_server_count = 0;
static int g_dns_settle = 0;

static Device g_devices[ENG_MAX_DEVICES];
static int g_device_count = 0;
static int g_devices_scanned = 0;

static Alert g_alerts[ENG_MAX_ALERTS];
static int g_alert_count = 0;

static DayTotal g_totals[USAGE_DAYS];
static int g_total_count = 0;
static DayApp *g_day_apps = NULL;
static int g_day_app_count = 0;
static int g_limit_period = 0, g_limit_level = 0;

static Fingerprint g_fps[ENG_MAX_FPS];
static int g_fp_count = 0;

static FILE *g_log_file = NULL;
static int g_log_day = -1;

const char *policy_name(Policy p)
{
    return p == POLICY_BLOCK ? "block" : (p == POLICY_ASK ? "ask" : "allow");
}

int policy_parse(const char *s, Policy *out)
{
    if (!s) return 0;
    if (!_stricmp(s, "allow")) { *out = POLICY_ALLOW; return 1; }
    if (!_stricmp(s, "ask"))   { *out = POLICY_ASK;   return 1; }
    if (!_stricmp(s, "block") || !_stricmp(s, "deny")) { *out = POLICY_BLOCK; return 1; }
    return 0;
}

static void gen_id(char *out, size_t len, const char *prefix)
{
    _snprintf_s(out, len, _TRUNCATE, "%s_%x", prefix, g_next_id++);
}

static size_t json_str(char *out, size_t cap, const char *in)
{
    size_t n = 0;
    for (; *in && n + 8 < cap; in++) {
        unsigned char c = (unsigned char)*in;
        switch (c) {
            case '"':  out[n++] = '\\'; out[n++] = '"';  break;
            case '\\': out[n++] = '\\'; out[n++] = '\\'; break;
            case '\n': out[n++] = '\\'; out[n++] = 'n';  break;
            case '\r': out[n++] = '\\'; out[n++] = 'r';  break;
            case '\t': out[n++] = '\\'; out[n++] = 't';  break;
            default:
                if (c < 0x20) n += sprintf_s(out + n, cap - n, "\\u%04x", c);
                else out[n++] = (char)c;
        }
    }
    out[n] = '\0';
    return n;
}

static void human_bytes(long long n, char *out, size_t cap)
{
    static const char *unit[] = {"B", "KB", "MB", "GB", "TB"};
    double v = (double)n;
    int i = 0;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; i++; }
    if (i > 0 && v < 10.0) _snprintf_s(out, cap, _TRUNCATE, "%.1f %s", v, unit[i]);
    else _snprintf_s(out, cap, _TRUNCATE, "%.0f %s", v, unit[i]);
}

static void human_age(long long since, char *out, size_t cap)
{
    long long secs = (plat_now_ms() - since) / 1000;
    if (secs < 60) _snprintf_s(out, cap, _TRUNCATE, "%llds", secs);
    else if (secs < 3600) _snprintf_s(out, cap, _TRUNCATE, "%lldm", secs / 60);
    else if (secs < 86400) _snprintf_s(out, cap, _TRUNCATE, "%lldh", secs / 3600);
    else _snprintf_s(out, cap, _TRUNCATE, "%lldd", secs / 86400);
}

static void clean_field(char *s)
{
    for (; *s; s++) {
        if (*s == '\t' || *s == '\r' || *s == '\n') *s = ' ';
    }
}

static int is_policy_word(const char *s)
{
    return !strcmp(s, "allow") || !strcmp(s, "ask") || !strcmp(s, "block");
}

static long days_from_civil(long y, unsigned m, unsigned d)
{
    long era;
    unsigned yoe, doy, doe;
    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = (unsigned)(y - era * 400);
    doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (long)doe - 719468;
}

static int civil_key(long z)
{
    long era, y;
    unsigned doe, yoe, doy, mp, d, m;
    z += 719468;
    era = (z >= 0 ? z : z - 146096) / 146097;
    doe = (unsigned)(z - era * 146097);
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y = (long)yoe + era * 400;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1;
    m = mp < 10 ? mp + 3 : mp - 9;
    return (int)((y + (m <= 2)) * 10000 + (long)m * 100 + d);
}

static long key_days(int key)
{
    return days_from_civil(key / 10000, (unsigned)(key / 100 % 100), (unsigned)(key % 100));
}

static int today_key(void)
{
    PlatTime t;
    plat_local_time(&t);
    return t.year * 10000 + t.month * 100 + t.day;
}

static void key_text(int key, char *out, size_t cap)
{
    _snprintf_s(out, cap, _TRUNCATE, "%04d-%02d-%02d", key / 10000, key / 100 % 100, key % 100);
}

static int period_start_key(int reset_day)
{
    PlatTime t;
    int y, m;
    plat_local_time(&t);
    if (reset_day < 1) reset_day = 1;
    if (reset_day > 28) reset_day = 28;
    y = t.year;
    m = t.month;
    if (t.day < reset_day) {
        m--;
        if (m < 1) { m = 12; y--; }
    }
    return y * 10000 + m * 100 + reset_day;
}

static void write_log_line(const LogEntry *e)
{
    PlatTime t;

    plat_local_time(&t);
    if (!g_log_file || t.day != g_log_day) {
        char name[32], path[MAX_PATH];
        if (g_log_file) fclose(g_log_file);
        g_log_file = NULL;
        _snprintf_s(name, sizeof name, _TRUNCATE, "%04d-%02d-%02d.log", t.year, t.month, t.day);
        if (plat_data_path("logs", name, path, sizeof path)) g_log_file = plat_fopen_shared(path, "a");
        g_log_day = t.day;
    }
    if (g_log_file) {
        fprintf(g_log_file, "%02d:%02d:%02d  %-5s  %s\n", t.hour, t.minute, t.second, e->level, e->message);
    }
}

static void add_log(const char *level, const char *fmt, ...)
{
    LogEntry *e;
    va_list args;

    if (g_log_count >= ENG_MAX_LOGS) {
        memmove(g_logs, g_logs + 1, sizeof(LogEntry) * (ENG_MAX_LOGS - 1));
        g_log_count = ENG_MAX_LOGS - 1;
    }
    e = &g_logs[g_log_count++];
    gen_id(e->id, sizeof e->id, "log");
    e->ts = plat_now_ms();
    strncpy_s(e->level, sizeof e->level, level, _TRUNCATE);
    va_start(args, fmt);
    _vsnprintf_s(e->message, sizeof e->message, _TRUNCATE, fmt, args);
    va_end(args);
    write_log_line(e);
}

static void push_notice(const char *title, const char *body)
{
    Notice *n;
    if (g_notice_count >= NOTICE_CAP) {
        memmove(g_notices, g_notices + 1, sizeof(Notice) * (NOTICE_CAP - 1));
        g_notice_count = NOTICE_CAP - 1;
    }
    n = &g_notices[g_notice_count++];
    strncpy_s(n->title, sizeof n->title, title, _TRUNCATE);
    strncpy_s(n->body, sizeof n->body, body, _TRUNCATE);
}

static void add_alert(const char *kind, const char *title, int notify, const char *fmt, ...)
{
    Alert *a;
    va_list args;

    if (g_alert_count >= ENG_MAX_ALERTS) {
        memmove(g_alerts, g_alerts + 1, sizeof(Alert) * (ENG_MAX_ALERTS - 1));
        g_alert_count = ENG_MAX_ALERTS - 1;
    }
    a = &g_alerts[g_alert_count++];
    memset(a, 0, sizeof *a);
    gen_id(a->id, sizeof a->id, "alert");
    a->ts = plat_now_ms();
    a->unread = 1;
    strncpy_s(a->kind, sizeof a->kind, kind, _TRUNCATE);
    strncpy_s(a->title, sizeof a->title, title, _TRUNCATE);
    va_start(args, fmt);
    _vsnprintf_s(a->detail, sizeof a->detail, _TRUNCATE, fmt, args);
    va_end(args);

    add_log("warn", "%s: %s", a->title, a->detail);
    if (notify && g_settings.alertNotify) push_notice(a->title, a->detail);
}

static void seed_rule(const char *name, const char *action, const char *dir,
                      const char *remote, const char *port, const char *proto,
                      const char *note)
{
    Rule *r = &g_rules[g_rule_count++];
    memset(r, 0, sizeof *r);
    gen_id(r->id, sizeof r->id, "rule");
    strncpy_s(r->name, sizeof r->name, name, _TRUNCATE);
    strncpy_s(r->action, sizeof r->action, action, _TRUNCATE);
    strncpy_s(r->direction, sizeof r->direction, dir, _TRUNCATE);
    strncpy_s(r->remote, sizeof r->remote, remote, _TRUNCATE);
    strncpy_s(r->port, sizeof r->port, port, _TRUNCATE);
    strncpy_s(r->proto, sizeof r->proto, proto, _TRUNCATE);
    strncpy_s(r->note, sizeof r->note, note, _TRUNCATE);
    r->enabled = 1;
    r->builtin = 1;
}

static void seed(void)
{
    seed_rule("Block inbound Telnet", "block", "in", "any", "23", "TCP",
              "Telnet sends credentials in clear text and has no place on a home network.");
    seed_rule("Block outbound SMB", "block", "out", "any", "445", "TCP",
              "Prevents file sharing credentials from reaching servers on the internet.");
    seed_rule("Block known C2 servers", "block", "out", C2_LIST, "any", "any",
              "Malware command and control servers reported in the TweetFeed #C2 feed over the past year.");

    memset(&g_settings, 0, sizeof g_settings);
    g_settings.notifyOnNewApp = 1;
    g_settings.keepRunningInBackground = 1;
    strcpy_s(g_settings.defaultOutbound, sizeof g_settings.defaultOutbound, "allow");
    strcpy_s(g_settings.defaultInbound, sizeof g_settings.defaultInbound, "allow");
    g_settings.logRetentionDays = 14;
    strcpy_s(g_settings.dnsUpstream, sizeof g_settings.dnsUpstream, "system");
    g_settings.notifyOnNewDevice = 1;
    g_settings.alertHostsFile = 1;
    g_settings.alertDnsChange = 1;
    g_settings.alertProxyChange = 1;
    g_settings.alertRemoteAccess = 1;
    g_settings.alertAppChange = 1;
    g_settings.alertNotify = 1;
    g_settings.dataResetDay = 1;

    memset(g_rx, 0, sizeof g_rx);
    memset(g_tx, 0, sizeof g_tx);

    add_log("info", "WireCee engine started on %s", plat_os());
    add_log("info", "Loaded %d built in rules", g_rule_count);
}

static DayTotal *usage_total(int day)
{
    int i;
    for (i = g_total_count - 1; i >= 0; i--) {
        if (g_totals[i].day == day) return &g_totals[i];
        if (g_totals[i].day < day) break;
    }
    if (g_total_count == USAGE_DAYS) {
        memmove(g_totals, g_totals + 1, sizeof(DayTotal) * (USAGE_DAYS - 1));
        g_total_count--;
    }
    g_totals[g_total_count].day = day;
    g_totals[g_total_count].rx = 0;
    g_totals[g_total_count].tx = 0;
    return &g_totals[g_total_count++];
}

static DayApp *usage_app(int day, const char *app)
{
    int i;
    if (!g_day_apps) return NULL;
    for (i = g_day_app_count - 1; i >= 0; i--) {
        if (g_day_apps[i].day != day) {
            if (g_day_apps[i].day < day) break;
            continue;
        }
        if (!_stricmp(g_day_apps[i].app, app)) return &g_day_apps[i];
    }
    if (g_day_app_count == USAGE_APP_ROWS) {
        int oldest = g_day_apps[0].day, drop = 0;
        while (drop < g_day_app_count && g_day_apps[drop].day == oldest) drop++;
        memmove(g_day_apps, g_day_apps + drop, sizeof(DayApp) * (size_t)(g_day_app_count - drop));
        g_day_app_count -= drop;
    }
    memset(&g_day_apps[g_day_app_count], 0, sizeof(DayApp));
    g_day_apps[g_day_app_count].day = day;
    strncpy_s(g_day_apps[g_day_app_count].app, sizeof g_day_apps[0].app, app, _TRUNCATE);
    return &g_day_apps[g_day_app_count++];
}

static void save_usage(void)
{
    char path[MAX_PATH], tmp[MAX_PATH];
    FILE *f = NULL;
    int i;

    if (!plat_data_path(NULL, "usage.tsv", path, sizeof path)) return;
    _snprintf_s(tmp, sizeof tmp, _TRUNCATE, "%s.tmp", path);
    if (fopen_s(&f, tmp, "w") != 0 || !f) return;
    for (i = 0; i < g_total_count; i++) {
        fprintf(f, "t\t%d\t%lld\t%lld\n", g_totals[i].day, g_totals[i].rx, g_totals[i].tx);
    }
    for (i = 0; i < g_day_app_count; i++) {
        const DayApp *r = &g_day_apps[i];
        if (!r->rx && !r->tx) continue;
        fprintf(f, "a\t%d\t%lld\t%lld\t%s\n", r->day, r->rx, r->tx, r->app);
    }
    fclose(f);
    plat_replace_file(tmp, path);
}

static void load_usage(void)
{
    char path[MAX_PATH], line[512];
    FILE *f = NULL;
    int cutoff = civil_key(key_days(today_key()) - USAGE_KEEP_DAYS);

    if (!g_day_apps) g_day_apps = (DayApp *)calloc(USAGE_APP_ROWS, sizeof(DayApp));
    if (!plat_data_path(NULL, "usage.tsv", path, sizeof path)) return;
    if (fopen_s(&f, path, "r") != 0 || !f) return;
    while (fgets(line, sizeof line, f)) {
        char *ctx = NULL, *kind, *day, *rx, *tx, *name;
        line[strcspn(line, "\r\n")] = '\0';
        kind = strtok_s(line, "\t", &ctx);
        day = strtok_s(NULL, "\t", &ctx);
        rx = strtok_s(NULL, "\t", &ctx);
        tx = strtok_s(NULL, "\t", &ctx);
        if (!kind || !day || !rx || !tx || atoi(day) < cutoff) continue;
        if (!strcmp(kind, "t")) {
            DayTotal *t = usage_total(atoi(day));
            t->rx = _atoi64(rx);
            t->tx = _atoi64(tx);
        } else if (!strcmp(kind, "a") && (name = strtok_s(NULL, "\t", &ctx)) != NULL) {
            DayApp *r = usage_app(atoi(day), name);
            if (r) {
                r->rx = _atoi64(rx);
                r->tx = _atoi64(tx);
            }
        }
    }
    fclose(f);
}

static long long period_bytes(int start)
{
    long long used = 0;
    int i;
    for (i = 0; i < g_total_count; i++) {
        if (g_totals[i].day >= start) used += g_totals[i].rx + g_totals[i].tx;
    }
    return used;
}

static void save_state(void);

static void check_data_limit(void)
{
    long long used, limit;
    int start, level;
    char used_s[24], limit_s[24], start_s[16];

    if (g_settings.dataLimitMb <= 0) return;
    start = period_start_key(g_settings.dataResetDay);
    if (start != g_limit_period) {
        g_limit_period = start;
        g_limit_level = 0;
    }
    used = period_bytes(start);
    limit = (long long)g_settings.dataLimitMb * 1024LL * 1024LL;
    level = used >= limit ? 2 : (used * 10 >= limit * 8 ? 1 : 0);
    if (level <= g_limit_level) return;

    g_limit_level = level;
    human_bytes(used, used_s, sizeof used_s);
    human_bytes(limit, limit_s, sizeof limit_s);
    key_text(start, start_s, sizeof start_s);
    add_alert("data", level == 2 ? "Data limit reached" : "Data limit at 80 percent", 1,
              "%s of %s used since %s", used_s, limit_s, start_s);
    save_state();
}

static NetConn g_scan[ENG_MAX_CONNS];
static Conn g_fresh[ENG_MAX_CONNS];
static Flow g_flows[ENG_MAX_CONNS];

static int g_bytes_denied = 0;
static int g_bytes_available = 0;

static unsigned long long g_if_in = 0, g_if_out = 0;
static long long g_if_ms = 0;

typedef struct {
    unsigned long pid;
    char name[64];
    char dir[192];
} PidInfo;

static App *find_app_by_name(const char *name)
{
    int i;
    for (i = 0; i < g_app_count; i++) {
        if (_stricmp(g_apps[i].name, name) == 0) return &g_apps[i];
    }
    return NULL;
}

static unsigned long text_hash(const char *key)
{
    unsigned long h = 2166136261UL;
    for (; *key; key++) {
        h ^= (unsigned char)*key;
        h *= 16777619UL;
    }
    return h;
}

static void describe_pid(unsigned long pid, PidInfo *cache, int *count, int cap, PidInfo *out)
{
    char full[MAX_PATH];
    PidInfo info;
    char *slash;
    int i;

    for (i = 0; i < *count; i++) {
        if (cache[i].pid == pid) {
            *out = cache[i];
            return;
        }
    }

    memset(&info, 0, sizeof info);
    info.pid = pid;

    if (pid == 0) {
#ifdef _WIN32
        strcpy_s(info.name, sizeof info.name, "System Idle Process");
        strcpy_s(info.dir, sizeof info.dir, "Closed connections without an owning process");
#else
        strcpy_s(info.name, sizeof info.name, "kernel");
        strcpy_s(info.dir, sizeof info.dir, "Sockets without an owning process");
#endif
#ifdef _WIN32
    } else if (pid == 4) {
        strcpy_s(info.name, sizeof info.name, "System");
        strcpy_s(info.dir, sizeof info.dir, "Windows kernel");
#endif
    } else if (netenum_process_image(pid, full, sizeof full)) {
        slash = strrchr(full, PATH_SEP_CHAR);
        if (slash) {
            *slash = '\0';
            strncpy_s(info.name, sizeof info.name, slash + 1, _TRUNCATE);
            strncpy_s(info.dir, sizeof info.dir, full, _TRUNCATE);
        } else {
            strncpy_s(info.name, sizeof info.name, full, _TRUNCATE);
        }
    } else if (netenum_process_name(pid, info.name, sizeof info.name)) {
        strcpy_s(info.dir, sizeof info.dir, "Path requires administrator rights");
    } else {
        _snprintf_s(info.name, sizeof info.name, _TRUNCATE, "pid %lu", pid);
        strcpy_s(info.dir, sizeof info.dir, "Process exited before it could be identified");
    }

    if (*count < cap) cache[(*count)++] = info;
    *out = info;
}

static App *app_for(const PidInfo *info, long long now, int announce)
{
    App *a = find_app_by_name(info->name);
    if (a) return a;
    if (g_app_count >= ENG_MAX_APPS) return NULL;

    a = &g_apps[g_app_count++];
    memset(a, 0, sizeof *a);
    gen_id(a->id, sizeof a->id, "app");
    strncpy_s(a->name, sizeof a->name, info->name, _TRUNCATE);
    strncpy_s(a->path, sizeof a->path, info->dir, _TRUNCATE);
    a->policy = POLICY_ALLOW;
    a->first_seen = now;

    if (announce) {
        char body[160];
        add_log("info", "New application on the network: %s", a->name);
        if (g_settings.notifyOnNewApp) {
            _snprintf_s(body, sizeof body, _TRUNCATE, "%s connected to the network for the first time", a->name);
            push_notice("New application", body);
        }
    }
    return a;
}

static void account_usage(long long drx, long long dtx, int initial)
{
    int day = today_key(), i;
    DayTotal *t;

    if (drx > 0 || dtx > 0) {
        t = usage_total(day);
        if (drx > 0) t->rx += drx;
        if (dtx > 0) t->tx += dtx;
    }
    for (i = 0; i < g_app_count; i++) {
        App *a = &g_apps[i];
        long long dr = a->rx - a->counted_rx, dt = a->tx - a->counted_tx;
        if (!initial && (dr > 0 || dt > 0)) {
            DayApp *r = usage_app(day, a->name);
            if (r) {
                if (dr > 0) r->rx += dr;
                if (dt > 0) r->tx += dt;
            }
        }
        a->counted_rx = a->rx;
        a->counted_tx = a->tx;
    }
}

static void refresh_from_system(int initial)
{
    static PidInfo pids[256];
    int pid_count = 0;
    int n, i, j, fresh = 0, flow_count;
    long long now = plat_now_ms(), drx = 0, dtx = 0;
    unsigned long long in_now = 0, out_now = 0;
    int remote_port = plat_remote_access_port();

    if (netenum_interface_octets(&in_now, &out_now)) {
        if (g_if_ms && now > g_if_ms) {
            double secs = (double)(now - g_if_ms) / 1000.0;
            drx = in_now >= g_if_in ? (long long)(in_now - g_if_in) : 0;
            dtx = out_now >= g_if_out ? (long long)(out_now - g_if_out) : 0;
            memmove(g_rx, g_rx + 1, sizeof(long long) * (SAMPLES - 1));
            memmove(g_tx, g_tx + 1, sizeof(long long) * (SAMPLES - 1));
            g_rx[SAMPLES - 1] = (long long)(drx / secs);
            g_tx[SAMPLES - 1] = (long long)(dtx / secs);
        }
        g_if_in = in_now;
        g_if_out = out_now;
        g_if_ms = now;
    }

    n = netenum_connections(g_scan, ENG_MAX_CONNS);
    if (n < 0) {
        add_log("warn", "The TCP connection table could not be read");
        return;
    }

    for (i = 0; i < g_app_count; i++) g_apps[i].connections = 0;

    for (i = 0; i < n; i++) {
        NetConn *s = &g_scan[i];
        Conn *c = &g_fresh[fresh];
        PidInfo info;
        App *app;
        char key[200];
        int found = 0;

        describe_pid(s->pid, pids, &pid_count, 256, &info);

        memset(c, 0, sizeof *c);
        _snprintf_s(key, sizeof key, _TRUNCATE, "%d|%s|%d|%s|%d|%lu", s->family, s->local_ip,
                    s->local_port, s->remote_ip, s->remote_port, s->pid);
        _snprintf_s(c->id, sizeof c->id, _TRUNCATE, "c%08lx", text_hash(key) & 0xffffffffUL);
        strncpy_s(c->process, sizeof c->process, info.name, _TRUNCATE);
        strncpy_s(c->path, sizeof c->path, info.dir, _TRUNCATE);
        c->pid = s->pid;
        c->local_port = s->local_port;
        strncpy_s(c->remote_ip, sizeof c->remote_ip, s->remote_ip, _TRUNCATE);
        hostmap_get(c->remote_ip, c->remote_host, sizeof c->remote_host);
        c->remote_port = s->remote_port;
        strcpy_s(c->proto, sizeof c->proto, s->family == AF_INET6 ? "TCP6" : "TCP");
        strncpy_s(c->state, sizeof c->state, netenum_state_name(s->state), _TRUNCATE);
        c->net = *s;
        c->has_net = 1;

        for (j = 0; j < g_conn_count; j++) {
            if (strcmp(g_conns[j].id, c->id) == 0) {
                c->since = g_conns[j].since;
                c->rx = g_conns[j].rx;
                c->tx = g_conns[j].tx;
                found = 1;
                break;
            }
        }
        if (!found) {
            c->since = now;
            if (!initial) {
                g_allowed24h++;
                if (c->local_port == remote_port && !strcmp(c->state, "ESTABLISHED") &&
                    g_settings.alertRemoteAccess) {
                    add_alert("remote", "Remote access session", 1, "%s connected to %s on port %d",
                              c->remote_ip, c->process, c->local_port);
                }
            }
        }

        if (!g_bytes_denied) {
            unsigned long long rx = 0, tx = 0;
            int r = netenum_conn_bytes(s, &rx, &tx);
            if (r < 0) {
                g_bytes_denied = 1;
                add_log("info", "Per application byte counts require administrator rights");
            } else if (r > 0) {
                c->rx = (long long)rx;
                c->tx = (long long)tx;
                g_bytes_available = 1;
            }
        }

        app = app_for(&info, now, !initial);
        if (app) app->connections++;
        fresh++;
    }

    flow_count = flows_copy(g_flows, ENG_MAX_CONNS);
    for (i = 0; i < flow_count && fresh < ENG_MAX_CONNS; i++) {
        const Flow *f = &g_flows[i];
        Conn *c = &g_fresh[fresh];
        PidInfo info;
        App *app;
        char key[96];
        int found = 0;

        describe_pid(f->pid, pids, &pid_count, 256, &info);

        memset(c, 0, sizeof *c);
        _snprintf_s(key, sizeof key, _TRUNCATE, "udp|%d|%s|%d", f->local_port, f->remote_ip, f->remote_port);
        _snprintf_s(c->id, sizeof c->id, _TRUNCATE, "u%08lx", text_hash(key) & 0xffffffffUL);
        strncpy_s(c->process, sizeof c->process, info.name, _TRUNCATE);
        strncpy_s(c->path, sizeof c->path, info.dir, _TRUNCATE);
        c->pid = f->pid;
        c->local_port = f->local_port;
        strncpy_s(c->remote_ip, sizeof c->remote_ip, f->remote_ip, _TRUNCATE);
        hostmap_get(c->remote_ip, c->remote_host, sizeof c->remote_host);
        c->remote_port = f->remote_port;
        strcpy_s(c->proto, sizeof c->proto, f->family == AF_INET6 ? "UDP6" : "UDP");
        strcpy_s(c->state, sizeof c->state, f->idle_ms < 5000 ? "ACTIVE" : "IDLE");
        c->rx = (long long)f->rx;
        c->tx = (long long)f->tx;

        for (j = 0; j < g_conn_count; j++) {
            if (strcmp(g_conns[j].id, c->id) == 0) {
                c->since = g_conns[j].since;
                found = 1;
                break;
            }
        }
        if (!found) {
            c->since = now - f->age_ms;
            if (!initial) g_allowed24h++;
        }
        g_bytes_available = 1;

        app = app_for(&info, now, !initial);
        if (app) app->connections++;
        fresh++;
    }

    for (j = 0; j < g_conn_count; j++) {
        int still = 0;
        for (i = 0; i < fresh; i++) {
            if (strcmp(g_fresh[i].id, g_conns[j].id) == 0) {
                still = 1;
                break;
            }
        }
        if (!still) {
            App *a = find_app_by_name(g_conns[j].process);
            if (a) {
                a->retired_rx += g_conns[j].rx;
                a->retired_tx += g_conns[j].tx;
            }
        }
    }

    for (i = 0; i < g_app_count; i++) {
        g_apps[i].rx = g_apps[i].retired_rx;
        g_apps[i].tx = g_apps[i].retired_tx;
    }
    for (i = 0; i < fresh; i++) {
        App *a = find_app_by_name(g_fresh[i].process);
        if (a) {
            a->rx += g_fresh[i].rx;
            a->tx += g_fresh[i].tx;
        }
    }

    memcpy(g_conns, g_fresh, sizeof(Conn) * (size_t)fresh);
    g_conn_count = fresh;

    account_usage(drx, dtx, initial);
}

static void rebuild_snapshots(void);

static void save_state(void)
{
    char path[MAX_PATH], tmp[MAX_PATH];
    FILE *f = NULL;
    const Settings *s = &g_settings;
    int i;

    if (!plat_data_path(NULL, "state.tsv", path, sizeof path)) return;
    _snprintf_s(tmp, sizeof tmp, _TRUNCATE, "%s.tmp", path);
    if (fopen_s(&f, tmp, "w") != 0 || !f) return;

    fprintf(f, "version\t2\n");
    fprintf(f, "posture\t%s\n", g_posture);
    fprintf(f, "setting\tnotifyOnBlock\t%d\n", s->notifyOnBlock);
    fprintf(f, "setting\tnotifyOnNewApp\t%d\n", s->notifyOnNewApp);
    fprintf(f, "setting\tkeepRunningInBackground\t%d\n", s->keepRunningInBackground);
    fprintf(f, "setting\tlogRetentionDays\t%d\n", s->logRetentionDays);
    fprintf(f, "setting\tdefaultOutbound\t%s\n", s->defaultOutbound);
    fprintf(f, "setting\tdefaultInbound\t%s\n", s->defaultInbound);
    fprintf(f, "setting\tdnsFilter\t%d\n", s->dnsFilter);
    fprintf(f, "setting\tblockEncryptedDns\t%d\n", s->blockEncryptedDns);
    fprintf(f, "setting\tdnsUpstream\t%s\n", s->dnsUpstream);
    fprintf(f, "setting\tnotifyOnNewDevice\t%d\n", s->notifyOnNewDevice);
    fprintf(f, "setting\tquietMode\t%d\n", s->quietMode);
    fprintf(f, "setting\talertHostsFile\t%d\n", s->alertHostsFile);
    fprintf(f, "setting\talertDnsChange\t%d\n", s->alertDnsChange);
    fprintf(f, "setting\talertProxyChange\t%d\n", s->alertProxyChange);
    fprintf(f, "setting\talertRemoteAccess\t%d\n", s->alertRemoteAccess);
    fprintf(f, "setting\talertAppChange\t%d\n", s->alertAppChange);
    fprintf(f, "setting\talertNotify\t%d\n", s->alertNotify);
    fprintf(f, "setting\tdataLimitMb\t%d\n", s->dataLimitMb);
    fprintf(f, "setting\tdataResetDay\t%d\n", s->dataResetDay);
    fprintf(f, "limit\t%d\t%d\n", g_limit_period, g_limit_level);

    for (i = 0; i < g_app_count; i++) {
        const App *a = &g_apps[i];
        if (a->policy == POLICY_ALLOW && !a->pinned) continue;
        fprintf(f, "app\t%s\t%s\t%s\n", policy_name(a->policy), a->name, a->path[0] ? a->path : "-");
    }

    for (i = 0; i < g_rule_count; i++) {
        Rule r = g_rules[i];
        clean_field(r.name);
        clean_field(r.note);
        clean_field(r.remote);
        clean_field(r.port);
        if (r.builtin) {
            fprintf(f, "builtin\t%s\t%d\n", r.name, r.enabled);
        } else {
            fprintf(f, "rule\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.enabled, r.action, r.direction,
                    r.remote[0] ? r.remote : "any", r.port[0] ? r.port : "any", r.proto,
                    r.name[0] ? r.name : "Untitled rule", r.note[0] ? r.note : "-");
        }
    }

    for (i = 0; i < g_device_count; i++) {
        Device d = g_devices[i];
        clean_field(d.name);
        fprintf(f, "device\t%s\t%lld\t%s\n", d.mac, d.first_seen, d.name[0] ? d.name : "-");
    }

    fclose(f);
    plat_replace_file(tmp, path);
}

static void set_flag(const char *k, const char *v)
{
    int on = atoi(v) != 0;
    Settings *s = &g_settings;
    if (!strcmp(k, "notifyOnBlock")) s->notifyOnBlock = on;
    else if (!strcmp(k, "notifyOnNewApp")) s->notifyOnNewApp = on;
    else if (!strcmp(k, "keepRunningInBackground")) s->keepRunningInBackground = on;
    else if (!strcmp(k, "dnsFilter")) s->dnsFilter = on;
    else if (!strcmp(k, "blockEncryptedDns")) s->blockEncryptedDns = on;
    else if (!strcmp(k, "notifyOnNewDevice")) s->notifyOnNewDevice = on;
    else if (!strcmp(k, "quietMode")) s->quietMode = on;
    else if (!strcmp(k, "alertHostsFile")) s->alertHostsFile = on;
    else if (!strcmp(k, "alertDnsChange")) s->alertDnsChange = on;
    else if (!strcmp(k, "alertProxyChange")) s->alertProxyChange = on;
    else if (!strcmp(k, "alertRemoteAccess")) s->alertRemoteAccess = on;
    else if (!strcmp(k, "alertAppChange")) s->alertAppChange = on;
    else if (!strcmp(k, "alertNotify")) s->alertNotify = on;
}

static int is_upstream_word(const char *v)
{
    return !strcmp(v, "system") || !strcmp(v, "cloudflare") || !strcmp(v, "quad9") || !strcmp(v, "google");
}

static void load_state(void)
{
    static char line[FW_REMOTE_CAP + 1024];
    char path[MAX_PATH];
    FILE *f = NULL;

    if (!plat_data_path(NULL, "state.tsv", path, sizeof path)) return;
    if (fopen_s(&f, path, "r") != 0 || !f) return;

    while (fgets(line, sizeof line, f)) {
        char *ctx = NULL;
        char *kind;

        line[strcspn(line, "\r\n")] = '\0';
        kind = strtok_s(line, "\t", &ctx);
        if (!kind) continue;

        if (!strcmp(kind, "posture")) {
            char *v = strtok_s(NULL, "\t", &ctx);
            if (v && (!strcmp(v, "on") || !strcmp(v, "off") || !strcmp(v, "lockdown"))) {
                strcpy_s(g_posture, sizeof g_posture, v);
            }
        } else if (!strcmp(kind, "setting")) {
            char *k = strtok_s(NULL, "\t", &ctx);
            char *v = strtok_s(NULL, "\t", &ctx);
            if (!k || !v) continue;
            if (!strcmp(k, "logRetentionDays")) g_settings.logRetentionDays = atoi(v) > 0 ? atoi(v) : 14;
            else if (!strcmp(k, "dataLimitMb")) g_settings.dataLimitMb = atoi(v) > 0 ? atoi(v) : 0;
            else if (!strcmp(k, "dataResetDay")) g_settings.dataResetDay = atoi(v) >= 1 && atoi(v) <= 28 ? atoi(v) : 1;
            else if (!strcmp(k, "defaultOutbound") && is_policy_word(v))
                strcpy_s(g_settings.defaultOutbound, sizeof g_settings.defaultOutbound, v);
            else if (!strcmp(k, "defaultInbound") && is_policy_word(v))
                strcpy_s(g_settings.defaultInbound, sizeof g_settings.defaultInbound, v);
            else if (!strcmp(k, "dnsUpstream") && is_upstream_word(v))
                strcpy_s(g_settings.dnsUpstream, sizeof g_settings.dnsUpstream, v);
            else set_flag(k, v);
        } else if (!strcmp(kind, "limit")) {
            char *period = strtok_s(NULL, "\t", &ctx);
            char *level = strtok_s(NULL, "\t", &ctx);
            if (period && level) {
                g_limit_period = atoi(period);
                g_limit_level = atoi(level);
            }
        } else if (!strcmp(kind, "app")) {
            char *pol = strtok_s(NULL, "\t", &ctx);
            char *name = strtok_s(NULL, "\t", &ctx);
            char *dir = strtok_s(NULL, "\t", &ctx);
            PidInfo info;
            Policy p;
            App *a;
            if (!pol || !name || !dir || !policy_parse(pol, &p)) continue;
            memset(&info, 0, sizeof info);
            strncpy_s(info.name, sizeof info.name, name, _TRUNCATE);
            if (strcmp(dir, "-")) strncpy_s(info.dir, sizeof info.dir, dir, _TRUNCATE);
            a = app_for(&info, plat_now_ms(), 0);
            if (a) {
                a->policy = p;
                a->pinned = 1;
            }
        } else if (!strcmp(kind, "builtin")) {
            char *name = strtok_s(NULL, "\t", &ctx);
            char *on = strtok_s(NULL, "\t", &ctx);
            int i;
            if (!name || !on) continue;
            for (i = 0; i < g_rule_count; i++) {
                if (g_rules[i].builtin && !strcmp(g_rules[i].name, name)) g_rules[i].enabled = atoi(on) != 0;
            }
        } else if (!strcmp(kind, "rule")) {
            char *fields[8];
            int i;
            Rule *r;
            for (i = 0; i < 8; i++) {
                fields[i] = strtok_s(NULL, "\t", &ctx);
                if (!fields[i]) break;
            }
            if (i < 8 || g_rule_count >= ENG_MAX_RULES) continue;
            r = &g_rules[g_rule_count++];
            memset(r, 0, sizeof *r);
            gen_id(r->id, sizeof r->id, "rule");
            r->enabled = atoi(fields[0]) != 0;
            strncpy_s(r->action, sizeof r->action, fields[1], _TRUNCATE);
            strncpy_s(r->direction, sizeof r->direction, fields[2], _TRUNCATE);
            strncpy_s(r->remote, sizeof r->remote, fields[3], _TRUNCATE);
            strncpy_s(r->port, sizeof r->port, fields[4], _TRUNCATE);
            strncpy_s(r->proto, sizeof r->proto, fields[5], _TRUNCATE);
            strncpy_s(r->name, sizeof r->name, fields[6], _TRUNCATE);
            if (strcmp(fields[7], "-")) strncpy_s(r->note, sizeof r->note, fields[7], _TRUNCATE);
        } else if (!strcmp(kind, "device")) {
            char *mac = strtok_s(NULL, "\t", &ctx);
            char *first = strtok_s(NULL, "\t", &ctx);
            char *name = strtok_s(NULL, "\t", &ctx);
            Device *d;
            if (!mac || !first || !name || g_device_count >= ENG_MAX_DEVICES) continue;
            d = &g_devices[g_device_count++];
            memset(d, 0, sizeof *d);
            strncpy_s(d->mac, sizeof d->mac, mac, _TRUNCATE);
            d->first_seen = _atoi64(first);
            d->last_seen = d->first_seen;
            if (strcmp(name, "-")) strncpy_s(d->name, sizeof d->name, name, _TRUNCATE);
        }
    }
    fclose(f);
    g_devices_scanned = g_device_count > 0;
}

static void load_fingerprints(void)
{
    char path[MAX_PATH], line[MAX_PATH + 128];
    FILE *f = NULL;

    if (!plat_data_path(NULL, "fingerprints.tsv", path, sizeof path)) return;
    if (fopen_s(&f, path, "r") != 0 || !f) return;
    while (fgets(line, sizeof line, f) && g_fp_count < ENG_MAX_FPS) {
        char *ctx = NULL, *name, *file, *size, *mtime;
        line[strcspn(line, "\r\n")] = '\0';
        name = strtok_s(line, "\t", &ctx);
        file = strtok_s(NULL, "\t", &ctx);
        size = strtok_s(NULL, "\t", &ctx);
        mtime = strtok_s(NULL, "\t", &ctx);
        if (!name || !file || !size || !mtime) continue;
        strncpy_s(g_fps[g_fp_count].name, sizeof g_fps[0].name, name, _TRUNCATE);
        strncpy_s(g_fps[g_fp_count].path, sizeof g_fps[0].path, file, _TRUNCATE);
        g_fps[g_fp_count].size = _atoi64(size);
        g_fps[g_fp_count].mtime = _atoi64(mtime);
        g_fp_count++;
    }
    fclose(f);
}

static void save_fingerprints(void)
{
    char path[MAX_PATH], tmp[MAX_PATH];
    FILE *f = NULL;
    int i;

    if (!plat_data_path(NULL, "fingerprints.tsv", path, sizeof path)) return;
    _snprintf_s(tmp, sizeof tmp, _TRUNCATE, "%s.tmp", path);
    if (fopen_s(&f, tmp, "w") != 0 || !f) return;
    for (i = 0; i < g_fp_count; i++) {
        fprintf(f, "%s\t%s\t%lld\t%lld\n", g_fps[i].name, g_fps[i].path, g_fps[i].size, g_fps[i].mtime);
    }
    fclose(f);
    plat_replace_file(tmp, path);
}

static void blocklist_path(char *out, size_t cap)
{
    plat_data_path(NULL, "dns-blocklist.txt", out, cap);
}

static FwApp g_fw_apps[ENG_MAX_APPS];
static FwRule g_fw_rules[ENG_MAX_RULES];
static NetConn g_cut[ENG_MAX_CONNS];

static int app_exe_path(const App *a, char *out, size_t cap)
{
    if (!a->path[0]) return 0;
    _snprintf_s(out, cap, _TRUNCATE, "%s" PATH_SEP "%s", a->path, a->name);
    return plat_file_stat(out, NULL, NULL);
}

static void apply_enforcement(void)
{
    FwPolicy p;
    char detail[160];
    int i, apps = 0, rules = 0, installed;

    if (!fw_active()) return;
    plat_mutex_lock(&g_enforce_lock);

    memset(&p, 0, sizeof p);
    plat_rw_read(&g_lock);
    strcpy_s(p.posture, sizeof p.posture, g_posture);
    strcpy_s(p.default_out, sizeof p.default_out, g_settings.defaultOutbound);
    strcpy_s(p.default_in, sizeof p.default_in, g_settings.defaultInbound);
    for (i = 0; i < g_app_count && apps < ENG_MAX_APPS; i++) {
        const App *a = &g_apps[i];
        FwApp *w = &g_fw_apps[apps];
        if (!app_exe_path(a, w->path, sizeof w->path)) continue;
        w->block = a->policy != POLICY_ALLOW;
        w->allow = a->policy == POLICY_ALLOW;
        apps++;
    }
    for (i = 0; i < g_rule_count; i++) {
        const Rule *src = &g_rules[i];
        FwRule *w = &g_fw_rules[rules];
        if (!src->enabled) continue;
        strcpy_s(w->id, sizeof w->id, src->id);
        strcpy_s(w->action, sizeof w->action, src->action);
        strcpy_s(w->direction, sizeof w->direction, src->direction);
        strcpy_s(w->remote, sizeof w->remote, src->remote);
        strcpy_s(w->port, sizeof w->port, src->port);
        strcpy_s(w->proto, sizeof w->proto, src->proto);
        rules++;
    }
    p.dns_guard = g_dns_active;
    p.block_encrypted_dns = g_settings.blockEncryptedDns;
    plat_rw_read_end(&g_lock);

    p.apps = g_fw_apps;
    p.app_count = apps;
    p.rules = g_fw_rules;
    p.rule_count = rules;
    installed = fw_apply(&p, detail, sizeof detail);

    plat_rw_write(&g_lock);
    add_log(installed < 0 ? "warn" : "info", "Enforcement: %s", detail);
    rebuild_snapshots();
    plat_rw_write_end(&g_lock);

    plat_mutex_unlock(&g_enforce_lock);
}

static void cut_connections_of(const char *name)
{
    int i, n = 0, cut = 0;

    if (!fw_active()) return;
    plat_mutex_lock(&g_enforce_lock);
    plat_rw_read(&g_lock);
    for (i = 0; i < g_conn_count && n < ENG_MAX_CONNS; i++) {
        if (g_conns[i].has_net && _stricmp(g_conns[i].process, name) == 0) g_cut[n++] = g_conns[i].net;
    }
    plat_rw_read_end(&g_lock);
    for (i = 0; i < n; i++) {
        if (netenum_close(&g_cut[i]) == 1) cut++;
    }
    plat_mutex_unlock(&g_enforce_lock);

    if (cut) {
        plat_rw_write(&g_lock);
        add_log("block", "Reset %d open connection%s of %s", cut, cut == 1 ? "" : "s", name);
        plat_rw_write_end(&g_lock);
    }
}

typedef struct {
    char name[96];
    int count;
    FwDirection direction;
    char remote_ip[46];
    int remote_port;
} DropTally;

static long long g_dns_guard_blocked = 0;
static long long g_dns_guard_logged = 0;

static void drain_drops(void)
{
    static FwDrop drops[256];
    DropTally tally[32];
    int n, i, j, tallies = 0, discovered = 0;
    long long now = plat_now_ms();

    n = fw_take_drops(drops, 256);
    if (n <= 0) return;

    plat_rw_write(&g_lock);
    for (i = 0; i < n; i++) {
        const FwDrop *d = &drops[i];
        const char *slash = strrchr(d->app_path, PATH_SEP_CHAR);
        int count = d->count > 0 ? d->count : 1;
        char name[96] = "";

        g_blocked24h += count;
        if (d->rule_id[0]) {
            for (j = 0; j < g_rule_count; j++) {
                if (!strcmp(g_rules[j].id, d->rule_id)) {
                    g_rules[j].hits += count;
                    if (!d->app_path[0]) strncpy_s(name, sizeof name, g_rules[j].name, _TRUNCATE);
                    break;
                }
            }
        }
        if (!name[0]) {
            strncpy_s(name, sizeof name, slash ? slash + 1 : (d->app_path[0] ? d->app_path : "System"), _TRUNCATE);
        }

        if (slash && !find_app_by_name(name)) {
            const char *def = d->direction == FW_OUT ? g_settings.defaultOutbound : g_settings.defaultInbound;
            PidInfo info;
            App *a;

            memset(&info, 0, sizeof info);
            strncpy_s(info.name, sizeof info.name, name, _TRUNCATE);
            _snprintf_s(info.dir, sizeof info.dir, _TRUNCATE, "%.*s", (int)(slash - d->app_path), d->app_path);
            a = app_for(&info, now, 0);
            if (a) {
                a->policy = !strcmp(def, "ask") ? POLICY_ASK : POLICY_BLOCK;
                add_log("block", "New application %s refused by the default %s policy", a->name, def);
                if (a->policy == POLICY_ASK && g_settings.notifyOnNewApp) {
                    char body[160];
                    _snprintf_s(body, sizeof body, _TRUNCATE, "%s wants to connect. Open WireCee to allow or block it.", a->name);
                    push_notice("Connection request", body);
                }
                discovered = 1;
            }
        }

        for (j = 0; j < tallies; j++) {
            if (!_stricmp(tally[j].name, name)) break;
        }
        if (j == tallies) {
            if (tallies == 32) continue;
            memset(&tally[j], 0, sizeof tally[j]);
            strncpy_s(tally[j].name, sizeof tally[j].name, name, _TRUNCATE);
            tallies++;
        }
        tally[j].count += count;
        tally[j].direction = d->direction;
        strncpy_s(tally[j].remote_ip, sizeof tally[j].remote_ip, d->remote_ip, _TRUNCATE);
        tally[j].remote_port = d->remote_port;
    }

    for (j = 0; j < tallies; j++) {
        const DropTally *t = &tally[j];
        const char *ip = t->remote_ip[0] ? t->remote_ip : "unknown";

        if (g_dns_active && t->remote_port == 53) {
            g_dns_guard_blocked += t->count;
            if (now - g_dns_guard_logged > 60000) {
                g_dns_guard_logged = now;
                add_log("block", "Prevented %lld direct DNS queries from bypassing the filter",
                        g_dns_guard_blocked);
                g_dns_guard_blocked = 0;
            }
            continue;
        }

        add_log("block", "Blocked %s: %d %s attempt%s, last %s:%d", t->name, t->count,
                t->direction == FW_OUT ? "outbound" : "inbound", t->count == 1 ? "" : "s", ip, t->remote_port);
        if (g_settings.notifyOnBlock) {
            _snprintf_s(g_notice, sizeof g_notice, _TRUNCATE, "%s was blocked %s %s:%d", t->name,
                        t->direction == FW_OUT ? "from reaching" : "from being reached by", ip, t->remote_port);
            g_notice_pending += t->count;
        }
    }

    if (discovered) save_state();
    rebuild_snapshots();
    plat_rw_write_end(&g_lock);
}

static int upstreams_for(const char *choice, char out[][46], int cap)
{
    static const char *const cloudflare[] = {"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111"};
    static const char *const quad9[] = {"9.9.9.9", "149.112.112.112", "2620:fe::fe"};
    static const char *const google[] = {"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888"};
    const char *const *list = NULL;
    int i, n = 0;

    if (!strcmp(choice, "quad9")) list = quad9;
    else if (!strcmp(choice, "google")) list = google;
    else if (!strcmp(choice, "cloudflare")) list = cloudflare;
    else {
        n = plat_dns_upstreams(out, cap);
        if (n > 0) return n;
        list = cloudflare;
    }
    for (i = 0; i < 3 && n < cap; i++) strcpy_s(out[n++], 46, list[i]);
    return n;
}

static void dns_apply(void)
{
    char reason[160] = "", choice[16];
    char servers[8][46];
    int want, enforce, count, changed = 0;

    plat_mutex_lock(&g_enforce_lock);

    plat_rw_read(&g_lock);
    want = g_settings.dnsFilter;
    enforce = strcmp(g_posture, "off") != 0;
    strcpy_s(choice, sizeof choice, g_settings.dnsUpstream);
    plat_rw_read_end(&g_lock);

    dnsd_set_enforce(enforce);

    if (want && !g_dns_active) {
        if (!plat_is_admin()) {
            strcpy_s(reason, sizeof reason, "Administrator rights are required");
        } else {
            count = upstreams_for(choice, servers, 8);
            dnsd_set_upstreams(servers, count);
            dnsd_set_log_allowed(!flows_dns_names());
            if (dnsd_start(reason, sizeof reason)) {
                g_dns_settle = 3;
                if (plat_dns_redirect_begin(reason, sizeof reason)) {
                    int i;
                    g_dns_active = 1;
                    g_dns_server_count = count;
                    for (i = 0; i < count; i++) strcpy_s(g_dns_servers[i], 46, servers[i]);
                    strcpy_s(reason, sizeof reason, "Active");
                } else {
                    dnsd_stop();
                }
            }
        }
        changed = 1;
    } else if (!want && g_dns_active) {
        g_dns_settle = 3;
        plat_dns_redirect_end();
        dnsd_stop();
        g_dns_active = 0;
        g_dns_server_count = 0;
        strcpy_s(reason, sizeof reason, "Off");
        changed = 1;
    } else if (g_dns_active) {
        int i;
        count = upstreams_for(choice, servers, 8);
        dnsd_set_upstreams(servers, count);
        g_dns_server_count = count;
        for (i = 0; i < count; i++) strcpy_s(g_dns_servers[i], 46, servers[i]);
        strcpy_s(reason, sizeof reason, "Active");
    } else {
        strcpy_s(reason, sizeof reason, want ? g_dns_reason : "Off");
    }

    plat_rw_write(&g_lock);
    if (changed) {
        if (g_dns_active) add_log("info", "DNS filtering active with %d blocked domains", dnsd_block_count());
        else if (want) add_log("warn", "DNS filtering unavailable. %s", reason);
        else add_log("info", "DNS filtering stopped and system DNS settings restored");
    }
    strcpy_s(g_dns_reason, sizeof g_dns_reason, reason);
    rebuild_snapshots();
    plat_rw_write_end(&g_lock);

    if (changed) apply_enforcement();
    plat_mutex_unlock(&g_enforce_lock);
}

static PlatNeighbor g_neighbors[ENG_MAX_DEVICES];

static void scan_devices(void)
{
    int n = plat_neighbors(g_neighbors, ENG_MAX_DEVICES), i, j, changed = 0;
    long long now = plat_now_ms();

    plat_rw_write(&g_lock);
    for (i = 0; i < g_device_count; i++) g_devices[i].online = 0;
    for (i = 0; i < n; i++) {
        const PlatNeighbor *nb = &g_neighbors[i];
        Device *d = NULL;
        for (j = 0; j < g_device_count; j++) {
            if (!strcmp(g_devices[j].mac, nb->mac)) {
                d = &g_devices[j];
                break;
            }
        }
        if (!d) {
            if (g_device_count >= ENG_MAX_DEVICES) continue;
            d = &g_devices[g_device_count++];
            memset(d, 0, sizeof *d);
            strcpy_s(d->mac, sizeof d->mac, nb->mac);
            d->first_seen = now;
            changed = 1;
            if (g_devices_scanned) {
                add_alert("device", "New device on the network", g_settings.notifyOnNewDevice,
                          "%s joined with address %s", nb->mac, nb->ip);
            }
        }
        if (strcmp(d->ip, nb->ip)) {
            strcpy_s(d->ip, sizeof d->ip, nb->ip);
            d->resolve_tried = 0;
        }
        d->gateway = nb->gateway;
        d->online = 1;
        d->last_seen = now;
    }
    if (!g_devices_scanned && n > 0) {
        g_devices_scanned = 1;
        add_log("info", "Found %d devices on the local network", n);
    }
    if (changed) save_state();
    plat_rw_write_end(&g_lock);
}

static plat_flag g_resolving = 0;

static void resolve_worker(void *arg)
{
    char ips[2][46], macs[2][18], host[NI_MAXHOST];
    int i, n = 0;
    (void)arg;

    plat_rw_write(&g_lock);
    for (i = 0; i < g_device_count && n < 2; i++) {
        Device *d = &g_devices[i];
        if (d->online && !d->resolve_tried && d->ip[0]) {
            d->resolve_tried = 1;
            strcpy_s(ips[n], 46, d->ip);
            strcpy_s(macs[n], 18, d->mac);
            n++;
        }
    }
    plat_rw_write_end(&g_lock);

    for (i = 0; i < n; i++) {
        struct sockaddr_storage ss;
        socklen_t len;
        memset(&ss, 0, sizeof ss);
        if (strchr(ips[i], ':')) {
            struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
            a->sin6_family = AF_INET6;
            if (inet_pton(AF_INET6, ips[i], &a->sin6_addr) != 1) continue;
            len = sizeof *a;
        } else {
            struct sockaddr_in *a = (struct sockaddr_in *)&ss;
            a->sin_family = AF_INET;
            if (inet_pton(AF_INET, ips[i], &a->sin_addr) != 1) continue;
            len = sizeof *a;
        }
        if (getnameinfo((struct sockaddr *)&ss, len, host, sizeof host, NULL, 0, NI_NAMEREQD) == 0) {
            int j, n = (int)strlen(host);
            while (n > 0 && host[n - 1] == '.') host[--n] = '\0';
            if (!host[0] || !strcmp(host, ips[i])) continue;
            plat_rw_write(&g_lock);
            for (j = 0; j < g_device_count; j++) {
                if (!strcmp(g_devices[j].mac, macs[i])) {
                    strncpy_s(g_devices[j].hostname, sizeof g_devices[j].hostname, host, _TRUNCATE);
                }
            }
            plat_rw_write_end(&g_lock);
        }
    }
    plat_flag_set(&g_resolving, 0);
}

static void resolve_device_names(void)
{
    plat_thread t;

    if (plat_flag_get(&g_resolving)) return;
    plat_flag_set(&g_resolving, 1);
    t = plat_thread_start(resolve_worker, NULL);
    if (!t) {
        plat_flag_set(&g_resolving, 0);
        return;
    }
    plat_thread_join(t, 0);
}

static char g_sig_hosts[64] = "";
static char g_sig_dns[512] = "";
static char g_sig_proxy[1100] = "";

static int changed_signature(char *baseline, size_t cap, const char *current)
{
    int changed = baseline[0] && strcmp(baseline, current) != 0;
    strncpy_s(baseline, cap, current, _TRUNCATE);
    return changed;
}

static void check_security(void)
{
    char path[MAX_PATH], sig[1100], servers[16][46];
    long long size = 0, mtime = 0;
    int i, n, hosts_changed, dns_changed = 0, proxy_changed;

    plat_hosts_file(path, sizeof path);
    if (plat_file_stat(path, &size, &mtime)) _snprintf_s(sig, sizeof sig, _TRUNCATE, "%lld:%lld", size, mtime);
    else strcpy_s(sig, sizeof sig, "missing");
    hosts_changed = changed_signature(g_sig_hosts, sizeof g_sig_hosts, sig);

    n = plat_dns_servers(servers, 16);
    sig[0] = '\0';
    for (i = 0; i < n; i++) {
        if (i) strcat_s(sig, sizeof sig, ", ");
        strcat_s(sig, sizeof sig, servers[i]);
    }
    if (!sig[0]) strcpy_s(sig, sizeof sig, "none");
    if (g_dns_settle > 0) {
        g_dns_settle--;
        strncpy_s(g_sig_dns, sizeof g_sig_dns, sig, _TRUNCATE);
    } else {
        dns_changed = changed_signature(g_sig_dns, sizeof g_sig_dns, sig);
    }

    plat_proxy_signature(sig, sizeof sig);
    if (!sig[0]) strcpy_s(sig, sizeof sig, "direct");
    proxy_changed = changed_signature(g_sig_proxy, sizeof g_sig_proxy, sig);

    if (!hosts_changed && !dns_changed && !proxy_changed) return;

    plat_rw_write(&g_lock);
    if (hosts_changed && g_settings.alertHostsFile) {
        add_alert("hosts", "Hosts file modified", 1, "%s was changed. Entries there override DNS for this computer.", path);
    }
    if (dns_changed && g_settings.alertDnsChange) {
        add_alert("dns", "DNS servers changed", 1, "This computer now resolves names through %s", g_sig_dns);
    }
    if (proxy_changed && g_settings.alertProxyChange) {
        add_alert("proxy", "Proxy settings changed", 1, "Web traffic now uses: %s", g_sig_proxy);
    }
    plat_rw_write_end(&g_lock);
}

static Fingerprint g_fp_candidates[ENG_MAX_APPS];

static void check_fingerprints(void)
{
    int i, j, n = 0, dirty = 0;

    plat_rw_read(&g_lock);
    for (i = 0; i < g_app_count && n < ENG_MAX_APPS; i++) {
        if (!app_exe_path(&g_apps[i], g_fp_candidates[n].path, sizeof g_fp_candidates[n].path)) continue;
        strcpy_s(g_fp_candidates[n].name, sizeof g_fp_candidates[n].name, g_apps[i].name);
        n++;
    }
    plat_rw_read_end(&g_lock);

    for (i = 0; i < n; i++) {
        Fingerprint *c = &g_fp_candidates[i];
        Fingerprint *known = NULL;
        if (!plat_file_stat(c->path, &c->size, &c->mtime)) continue;
        for (j = 0; j < g_fp_count; j++) {
            if (!_stricmp(g_fps[j].path, c->path)) {
                known = &g_fps[j];
                break;
            }
        }
        if (!known) {
            if (g_fp_count < ENG_MAX_FPS) {
                g_fps[g_fp_count++] = *c;
                dirty = 1;
            }
            continue;
        }
        if (known->size != c->size || known->mtime != c->mtime) {
            *known = *c;
            dirty = 1;
            plat_rw_write(&g_lock);
            if (g_settings.alertAppChange) {
                add_alert("app", "Application changed", 1,
                          "The executable of %s was modified. Updates do this too, so confirm it was expected.", c->name);
            }
            plat_rw_write_end(&g_lock);
        }
    }
    if (dirty) save_fingerprints();
}

static void buf_set(char **dst, size_t *dst_len, const char *src, size_t len)
{
    if (!*dst || *dst_len < len) {
        char *grown = (char *)realloc(*dst, len + 1024);
        if (!grown) return;
        *dst = grown;
    }
    memcpy(*dst, src, len);
    (*dst)[len] = '\0';
    *dst_len = len;
}

#define SCRATCH (8 * 1024 * 1024)
static char g_scratch_json[SCRATCH];
static char g_scratch_text[SCRATCH];

static void render_connections(Snapshot *s)
{
    size_t j = 0, t = 0;
    int i;
    char path_esc[400], proc_esc[128], host_esc[200], rxs[24], txs[24], age[24];

    j += sprintf_s(g_scratch_json + j, SCRATCH - j, "[");
    t += sprintf_s(g_scratch_text + t, SCRATCH - t, "%-20s %-7s %-40s %-6s %-5s %-12s %10s %10s  %s\n",
                   "PROCESS", "PID", "REMOTE", "PORT", "PROTO", "STATE", "IN", "OUT", "AGE");

    for (i = 0; i < g_conn_count; i++) {
        Conn *c = &g_conns[i];
        const char *host = c->remote_host[0] ? c->remote_host : c->remote_ip;

        json_str(path_esc, sizeof path_esc, c->path);
        json_str(proc_esc, sizeof proc_esc, c->process);
        json_str(host_esc, sizeof host_esc, c->remote_host);
        if (i) j += sprintf_s(g_scratch_json + j, SCRATCH - j, ",");
        j += sprintf_s(g_scratch_json + j, SCRATCH - j,
                       "{\"id\":\"%s\",\"process\":\"%s\",\"pid\":%lu,\"path\":\"%s\","
                       "\"localPort\":%d,\"remoteIp\":\"%s\",\"remoteHost\":\"%s\","
                       "\"remotePort\":%d,\"proto\":\"%s\",\"state\":\"%s\","
                       "\"rx\":%lld,\"tx\":%lld,\"since\":%lld}",
                       c->id, proc_esc, c->pid, path_esc, c->local_port, c->remote_ip, host_esc,
                       c->remote_port, c->proto, c->state, c->rx, c->tx, c->since);

        if (g_bytes_available) {
            human_bytes(c->rx, rxs, sizeof rxs);
            human_bytes(c->tx, txs, sizeof txs);
        } else {
            strcpy_s(rxs, sizeof rxs, "-");
            strcpy_s(txs, sizeof txs, "-");
        }
        human_age(c->since, age, sizeof age);
        t += sprintf_s(g_scratch_text + t, SCRATCH - t, "%-20.20s %-7lu %-40.40s %-6d %-5s %-12s %10s %10s  %s\n",
                       c->process, c->pid, host, c->remote_port, c->proto, c->state, rxs, txs, age);
    }
    j += sprintf_s(g_scratch_json + j, SCRATCH - j, "]");
    t += sprintf_s(g_scratch_text + t, SCRATCH - t, "\n%d live connection%s%s\n", g_conn_count,
                   g_conn_count == 1 ? "" : "s", g_bytes_available ? "" : ". Byte counts require administrator rights.");

    buf_set(&s->json, &s->json_len, g_scratch_json, j);
    buf_set(&s->text, &s->text_len, g_scratch_text, t);
}

static void render_apps(Snapshot *s, int blocked_only)
{
    size_t j = 0, t = 0;
    int i, shown = 0;
    char esc[400], name_esc[128], rxs[24], txs[24];

    j += sprintf_s(g_scratch_json + j, SCRATCH - j, "[");
    t += sprintf_s(g_scratch_text + t, SCRATCH - t, "%-26s %-8s %6s %10s %10s  %s\n",
                   "APPLICATION", "POLICY", "CONNS", "IN", "OUT", "PATH");

    for (i = 0; i < g_app_count; i++) {
        App *a = &g_apps[i];
        if (blocked_only && a->policy != POLICY_BLOCK) continue;

        if (shown) j += sprintf_s(g_scratch_json + j, SCRATCH - j, ",");
        json_str(esc, sizeof esc, a->path);
        json_str(name_esc, sizeof name_esc, a->name);
        j += sprintf_s(g_scratch_json + j, SCRATCH - j,
                       "{\"id\":\"%s\",\"name\":\"%s\",\"path\":\"%s\",\"policy\":\"%s\","
                       "\"connections\":%d,\"rx\":%lld,\"tx\":%lld,\"firstSeen\":%lld}",
                       a->id, name_esc, esc, policy_name(a->policy), a->connections, a->rx, a->tx, a->first_seen);

        if (g_bytes_available) {
            human_bytes(a->rx, rxs, sizeof rxs);
            human_bytes(a->tx, txs, sizeof txs);
        } else {
            strcpy_s(rxs, sizeof rxs, "-");
            strcpy_s(txs, sizeof txs, "-");
        }
        t += sprintf_s(g_scratch_text + t, SCRATCH - t, "%-26.26s %-8s %6d %10s %10s  %s\n",
                       a->name, policy_name(a->policy), a->connections, rxs, txs, a->path);
        shown++;
    }
    j += sprintf_s(g_scratch_json + j, SCRATCH - j, "]");

    if (!shown) {
        t += sprintf_s(g_scratch_text + t, SCRATCH - t, "%s\n",
                       blocked_only ? "No applications are blocked." : "No applications have used the network yet.");
    } else {
        t += sprintf_s(g_scratch_text + t, SCRATCH - t, "\n%d application%s%s\n",
                       shown, shown == 1 ? "" : "s", blocked_only ? " blocked" : "");
    }

    buf_set(&s->json, &s->json_len, g_scratch_json, j);
    buf_set(&s->text, &s->text_len, g_scratch_text, t);
}

static void render_rules(Snapshot *s)
{
    size_t j = 0, t = 0;
    int i;
    static char remote_esc[FW_REMOTE_CAP * 2];
    char note_esc[400], name_esc[200];

    j += sprintf_s(g_scratch_json + j, SCRATCH - j, "[");
    t += sprintf_s(g_scratch_text + t, SCRATCH - t, "%-3s %-30s %-6s %-9s %-24s %8s\n",
                   "ON", "RULE", "ACTION", "DIR", "MATCH", "HITS");

    for (i = 0; i < g_rule_count; i++) {
        Rule *r = &g_rules[i];
        char match[96];

        if (i) j += sprintf_s(g_scratch_json + j, SCRATCH - j, ",");
        json_str(note_esc, sizeof note_esc, r->note);
        json_str(name_esc, sizeof name_esc, r->name);
        json_str(remote_esc, sizeof remote_esc, r->remote);
        j += sprintf_s(g_scratch_json + j, SCRATCH - j,
                       "{\"id\":\"%s\",\"name\":\"%s\",\"action\":\"%s\",\"direction\":\"%s\","
                       "\"remote\":\"%s\",\"port\":\"%s\",\"proto\":\"%s\",\"note\":\"%s\","
                       "\"enabled\":%s,\"hits\":%d,\"builtin\":%s}",
                       r->id, name_esc, r->action, r->direction, remote_esc, r->port, r->proto, note_esc,
                       r->enabled ? "true" : "false", r->hits, r->builtin ? "true" : "false");

        _snprintf_s(match, sizeof match, _TRUNCATE, "%s:%s %s", r->remote, r->port, r->proto);
        t += sprintf_s(g_scratch_text + t, SCRATCH - t, "%-3s %-30.30s %-6s %-9s %-24.24s %8d\n",
                       r->enabled ? "on" : "off", r->name, r->action, r->direction, match, r->hits);
    }
    j += sprintf_s(g_scratch_json + j, SCRATCH - j, "]");
    t += sprintf_s(g_scratch_text + t, SCRATCH - t, "\n%d rule%s\n", g_rule_count, g_rule_count == 1 ? "" : "s");

    buf_set(&s->json, &s->json_len, g_scratch_json, j);
    buf_set(&s->text, &s->text_len, g_scratch_text, t);
}

static void render_metrics(Snapshot *s)
{
    size_t j = 0, t = 0;
    int i, active_rules = 0, blocked_apps = 0, unread = 0, online = 0;
    char rxs[24], txs[24], reason_esc[320], dns_esc[320];
    int today = today_key();
    long long today_rx = 0, today_tx = 0;

    for (i = 0; i < g_rule_count; i++) if (g_rules[i].enabled) active_rules++;
    for (i = 0; i < g_app_count; i++) if (g_apps[i].policy == POLICY_BLOCK) blocked_apps++;
    for (i = 0; i < g_alert_count; i++) if (g_alerts[i].unread) unread++;
    for (i = 0; i < g_device_count; i++) if (g_devices[i].online) online++;
    for (i = g_total_count - 1; i >= 0; i--) {
        if (g_totals[i].day == today) {
            today_rx = g_totals[i].rx;
            today_tx = g_totals[i].tx;
            break;
        }
    }
    json_str(reason_esc, sizeof reason_esc, g_enforcement_reason);
    json_str(dns_esc, sizeof dns_esc, g_dns_reason);

    j += sprintf_s(g_scratch_json + j, SCRATCH - j,
                   "{\"blocked24h\":%lld,\"allowed24h\":%lld,\"activeConnections\":%d,"
                   "\"activeRules\":%d,\"blockedApps\":%d,\"enforcement\":%s,\"enforcementReason\":\"%s\","
                   "\"bytesPerApp\":%s,\"alertsUnread\":%d,\"devicesOnline\":%d,\"todayRx\":%lld,\"todayTx\":%lld,"
                   "\"dns\":\"%s\",\"dnsReason\":\"%s\",\"rxBps\":%lld,\"txBps\":%lld,\"rxSeries\":[",
                   g_blocked24h, g_allowed24h, g_conn_count, active_rules, blocked_apps,
                   g_enforcing ? "true" : "false", reason_esc, g_bytes_available ? "true" : "false",
                   unread, online, today_rx, today_tx,
                   g_dns_active ? "active" : (g_settings.dnsFilter ? "unavailable" : "off"), dns_esc,
                   g_rx[SAMPLES - 1], g_tx[SAMPLES - 1]);
    for (i = 0; i < SAMPLES; i++) j += sprintf_s(g_scratch_json + j, SCRATCH - j, "%s%lld", i ? "," : "", g_rx[i]);
    j += sprintf_s(g_scratch_json + j, SCRATCH - j, "],\"txSeries\":[");
    for (i = 0; i < SAMPLES; i++) j += sprintf_s(g_scratch_json + j, SCRATCH - j, "%s%lld", i ? "," : "", g_tx[i]);
    j += sprintf_s(g_scratch_json + j, SCRATCH - j, "]}");

    human_bytes(g_rx[SAMPLES - 1], rxs, sizeof rxs);
    human_bytes(g_tx[SAMPLES - 1], txs, sizeof txs);
    t += sprintf_s(g_scratch_text + t, SCRATCH - t,
                   "posture            %s\n"
                   "enforcement        %s\n"
                   "dns filtering      %s\n"
                   "live connections   %d\n"
                   "blocked            %lld\n"
                   "allowed            %lld\n"
                   "active rules       %d\n"
                   "blocked apps       %d\n"
                   "devices online     %d\n"
                   "unread alerts      %d\n"
                   "throughput         %s/s down, %s/s up\n",
                   g_posture, g_enforcing ? "active" : g_enforcement_reason, g_dns_reason, g_conn_count,
                   g_blocked24h, g_allowed24h, active_rules, blocked_apps, online, unread, rxs, txs);

    buf_set(&s->json, &s->json_len, g_scratch_json, j);
    buf_set(&s->text, &s->text_len, g_scratch_text, t);
}

#define B(v) ((v) ? "true" : "false")

static void render_settings(Snapshot *s)
{
    const Settings *g = &g_settings;
    size_t j, t;

    j = sprintf_s(g_scratch_json, SCRATCH,
                  "{\"startWithWindows\":%s,\"notifyOnBlock\":%s,\"notifyOnNewApp\":%s,"
                  "\"keepRunningInBackground\":%s,\"defaultOutbound\":\"%s\",\"defaultInbound\":\"%s\","
                  "\"logRetentionDays\":%d,\"dnsFilter\":%s,\"blockEncryptedDns\":%s,\"dnsUpstream\":\"%s\","
                  "\"notifyOnNewDevice\":%s,\"quietMode\":%s,\"alertHostsFile\":%s,\"alertDnsChange\":%s,"
                  "\"alertProxyChange\":%s,\"alertRemoteAccess\":%s,\"alertAppChange\":%s,"
                  "\"alertNotify\":%s,\"dataLimitMb\":%d,\"dataResetDay\":%d}",
                  B(g->startWithWindows), B(g->notifyOnBlock), B(g->notifyOnNewApp),
                  B(g->keepRunningInBackground), g->defaultOutbound, g->defaultInbound,
                  g->logRetentionDays, B(g->dnsFilter), B(g->blockEncryptedDns), g->dnsUpstream,
                  B(g->notifyOnNewDevice), B(g->quietMode), B(g->alertHostsFile), B(g->alertDnsChange),
                  B(g->alertProxyChange), B(g->alertRemoteAccess), B(g->alertAppChange),
                  B(g->alertNotify), g->dataLimitMb, g->dataResetDay);

    t = sprintf_s(g_scratch_text, SCRATCH,
                  "keep running          %s\n"
                  "start automatically   %s\n"
                  "default outbound      %s\n"
                  "default inbound       %s\n"
                  "dns filtering         %s (upstream %s)\n"
                  "block encrypted dns   %s\n"
                  "notify on block       %s\n"
                  "notify on new app     %s\n"
                  "notify on new device  %s\n"
                  "alert notifications   %s\n"
                  "quiet mode            %s\n"
                  "data limit            %d MB, resets on day %d\n"
                  "log retention         %d days\n",
                  g->keepRunningInBackground ? "on" : "off", g->startWithWindows ? "on" : "off",
                  g->defaultOutbound, g->defaultInbound, g->dnsFilter ? "on" : "off", g->dnsUpstream,
                  g->blockEncryptedDns ? "on" : "off", g->notifyOnBlock ? "on" : "off",
                  g->notifyOnNewApp ? "on" : "off", g->notifyOnNewDevice ? "on" : "off",
                  g->alertNotify ? "on" : "off", g->quietMode ? "on" : "off",
                  g->dataLimitMb, g->dataResetDay, g->logRetentionDays);

    buf_set(&s->json, &s->json_len, g_scratch_json, j);
    buf_set(&s->text, &s->text_len, g_scratch_text, t);
}

static unsigned long long fnv1a(const char *data, size_t len)
{
    unsigned long long h = 14695981039346656037ULL;
    size_t i;
    for (i = 0; i < len; i++) {
        h ^= (unsigned char)data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static void rebuild_snapshots(void)
{
    int i;
    g_generation++;
    render_connections(&g_snaps[SNAP_CONNECTIONS]);
    render_apps(&g_snaps[SNAP_APPS], 0);
    render_apps(&g_snaps[SNAP_APPS_BLOCKED], 1);
    render_rules(&g_snaps[SNAP_RULES]);
    render_metrics(&g_snaps[SNAP_METRICS]);
    render_settings(&g_snaps[SNAP_SETTINGS]);
    for (i = 0; i < SNAP_COUNT; i++) {
        Snapshot *sn = &g_snaps[i];
        unsigned long long h = sn->json ? fnv1a(sn->json, sn->json_len) : 0;
        sn->generation = g_generation;
        _snprintf_s(sn->etag, sizeof sn->etag, _TRUNCATE, "\"%016llx\"", h);
    }
}

static void tick_thread(void *arg)
{
    int n = 0;
    (void)arg;
    while (plat_flag_get(&g_running)) {
        drain_drops();
        fw_tick();
        plat_rw_write(&g_lock);
        refresh_from_system(0);
        n++;
        if (n % 10 == 0) check_data_limit();
        if (n % 60 == 0) save_usage();
        rebuild_snapshots();
        if (g_log_file) fflush(g_log_file);
        plat_rw_write_end(&g_lock);
        plat_sleep_ms(1000);
    }
}

static void monitor_thread(void *arg)
{
    int n = 0, i;
    (void)arg;
    plat_sleep_ms(1500);
    while (plat_flag_get(&g_running)) {
        check_security();
        if (n % 2 == 0) {
            scan_devices();
            resolve_device_names();
        }
        if (n % 6 == 0) check_fingerprints();
        n++;
        for (i = 0; i < 10 && plat_flag_get(&g_running); i++) plat_sleep_ms(500);
    }
}

void engine_start(void)
{
    char reason[160], path[MAX_PATH];
    int task, recovered, loaded;

    plat_init();
    plat_rw_init(&g_lock);
    plat_mutex_init(&g_enforce_lock);
    hostmap_init();
    srand((unsigned)time(NULL) ^ (unsigned)plat_pid());

    plat_rw_write(&g_lock);
    seed();
    load_state();
    load_usage();
    plat_prune_files("logs", ".log", g_settings.logRetentionDays);
    refresh_from_system(1);
    rebuild_snapshots();
    plat_rw_write_end(&g_lock);

    load_fingerprints();
    recovered = plat_dns_redirect_recover();
    blocklist_path(path, sizeof path);
    loaded = dnsd_block_load(path);
    task = plat_startup_exists();

    plat_rw_write(&g_lock);
    g_settings.startWithWindows = task;
    if (recovered) add_log("warn", "Restored DNS settings left behind by an unexpected shutdown");
    if (loaded) add_log("info", "Loaded %d domains into the DNS blocklist", loaded);
    plat_rw_write_end(&g_lock);

    if (flows_start(reason, sizeof reason)) {
        engine_log("info", "UDP flow tracing active%s", flows_dns_names() ? " with DNS names per application" : "");
    } else {
        engine_log("warn", "UDP traffic is not visible. %s", reason);
    }

    if (fw_start(reason, sizeof reason)) {
        plat_rw_write(&g_lock);
        g_enforcing = 1;
        strcpy_s(g_enforcement_reason, sizeof g_enforcement_reason, "Active");
        add_log("info", "Enforcement active");
        plat_rw_write_end(&g_lock);
    } else {
        plat_rw_write(&g_lock);
        g_enforcing = 0;
        strcpy_s(g_enforcement_reason, sizeof g_enforcement_reason, reason);
        add_log("warn", "Monitoring only. %s", reason);
        rebuild_snapshots();
        plat_rw_write_end(&g_lock);
    }

    dns_apply();
    apply_enforcement();

    plat_flag_set(&g_running, 1);
    g_tick_thread = plat_thread_start(tick_thread, NULL);
    g_monitor_thread = plat_thread_start(monitor_thread, NULL);
}

void engine_stop(void)
{
    plat_flag_set(&g_running, 0);
    plat_thread_join(g_tick_thread, 2500);
    plat_thread_join(g_monitor_thread, 6000);
    g_tick_thread = NULL;
    g_monitor_thread = NULL;

    plat_rw_write(&g_lock);
    save_usage();
    save_state();
    plat_rw_write_end(&g_lock);

    if (g_dns_active) {
        plat_dns_redirect_end();
        dnsd_stop();
        g_dns_active = 0;
    }
    fw_stop();
    flows_stop();
    g_enforcing = 0;
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
}

const Snapshot *engine_acquire(SnapKind kind)
{
    plat_rw_read(&g_lock);
    return &g_snaps[kind];
}

void engine_release(void)
{
    plat_rw_read_end(&g_lock);
}

int engine_set_policy(const char *name, Policy policy)
{
    int i, found = 0;
    char app_name[64] = {0};

    if (!name || !*name) return 0;
    plat_rw_write(&g_lock);
    for (i = 0; i < g_app_count; i++) {
        if (_stricmp(g_apps[i].name, name) == 0 || _stricmp(g_apps[i].id, name) == 0) {
            g_apps[i].policy = policy;
            g_apps[i].pinned = 1;
            strncpy_s(app_name, sizeof app_name, g_apps[i].name, _TRUNCATE);
            add_log("info", "%s policy set to %s", g_apps[i].name, policy_name(policy));
            found = 1;
            break;
        }
    }
    if (found) {
        save_state();
        rebuild_snapshots();
    }
    plat_rw_write_end(&g_lock);

    if (found) {
        apply_enforcement();
        if (policy != POLICY_ALLOW) cut_connections_of(app_name);
    }
    return found;
}

static int json_field(const char *body, const char *key, char *out, size_t cap)
{
    char needle[64];
    const char *p, *end;
    size_t n = 0;

    if (!body) return 0;
    _snprintf_s(needle, sizeof needle, _TRUNCATE, "\"%s\"", key);
    p = strstr(body, needle);
    if (!p) return 0;
    p = strchr(p + strlen(needle), ':');
    if (!p) return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;

    if (*p == '"') {
        p++;
        end = p;
        while (*end && *end != '"') {
            if (*end == '\\' && end[1]) end++;
            end++;
        }
    } else {
        end = p;
        while (*end && *end != ',' && *end != '}' && *end != ' ') end++;
    }
    while (p < end && n + 1 < cap) {
        if (*p == '\\' && p + 1 < end) {
            p++;
            out[n++] = (*p == 'n') ? '\n' : (*p == 't') ? '\t' : *p;
            p++;
        } else {
            out[n++] = *p++;
        }
    }
    out[n] = '\0';
    return 1;
}

static void normalize_remote(const char *in, char *out, size_t cap)
{
    size_t n = 0;

    out[0] = '\0';
    while (*in) {
        const char *start;
        size_t len;
        if (*in == '#') {
            while (*in && *in != '\n') in++;
            continue;
        }
        if (strchr(",; \t\r\n", *in)) {
            in++;
            continue;
        }
        start = in;
        while (*in && !strchr(",; \t\r\n#", *in)) in++;
        len = (size_t)(in - start);
        if (len == 3 && !_strnicmp(start, "any", 3)) continue;
        if (n + len + 2 >= cap) break;
        if (n) out[n++] = ',';
        memcpy(out + n, start, len);
        n += len;
        out[n] = '\0';
    }
    if (!n) strcpy_s(out, cap, "any");
}

static void rule_fields(Rule *r, const char *body, int creating)
{
    static char list[FW_REMOTE_CAP * 2];
    char buf[256];
    if (json_field(body, "name", buf, sizeof buf)) strncpy_s(r->name, sizeof r->name, buf, _TRUNCATE);
    else if (creating) strcpy_s(r->name, sizeof r->name, "Untitled rule");
    if (json_field(body, "action", buf, sizeof buf)) strncpy_s(r->action, sizeof r->action, buf, _TRUNCATE);
    else if (creating) strcpy_s(r->action, sizeof r->action, "block");
    if (json_field(body, "direction", buf, sizeof buf)) strncpy_s(r->direction, sizeof r->direction, buf, _TRUNCATE);
    else if (creating) strcpy_s(r->direction, sizeof r->direction, "out");
    if (json_field(body, "remote", list, sizeof list)) normalize_remote(list, r->remote, sizeof r->remote);
    else if (creating) strcpy_s(r->remote, sizeof r->remote, "any");
    if (json_field(body, "port", buf, sizeof buf)) strncpy_s(r->port, sizeof r->port, buf[0] ? buf : "any", _TRUNCATE);
    else if (creating) strcpy_s(r->port, sizeof r->port, "any");
    if (json_field(body, "proto", buf, sizeof buf)) strncpy_s(r->proto, sizeof r->proto, buf, _TRUNCATE);
    else if (creating) strcpy_s(r->proto, sizeof r->proto, "any");
    if (json_field(body, "note", buf, sizeof buf)) strncpy_s(r->note, sizeof r->note, buf, _TRUNCATE);
    if (json_field(body, "enabled", buf, sizeof buf)) r->enabled = (strcmp(buf, "true") == 0);
}

int engine_rule_create(const char *body)
{
    Rule *r;

    plat_rw_write(&g_lock);
    if (g_rule_count >= ENG_MAX_RULES) {
        plat_rw_write_end(&g_lock);
        return 0;
    }
    r = &g_rules[g_rule_count];
    memset(r, 0, sizeof *r);
    gen_id(r->id, sizeof r->id, "rule");
    r->enabled = 1;
    rule_fields(r, body, 1);
    g_rule_count++;
    add_log("info", "Rule created: %s", r->name);
    save_state();
    rebuild_snapshots();
    plat_rw_write_end(&g_lock);

    apply_enforcement();
    return 1;
}

int engine_rule_patch(const char *id, const char *body)
{
    int i, found = 0;

    plat_rw_write(&g_lock);
    for (i = 0; i < g_rule_count; i++) {
        if (strcmp(g_rules[i].id, id) != 0) continue;
        rule_fields(&g_rules[i], body, 0);
        found = 1;
        break;
    }
    if (found) {
        save_state();
        rebuild_snapshots();
    }
    plat_rw_write_end(&g_lock);

    if (found) apply_enforcement();
    return found;
}

int engine_rule_delete(const char *id)
{
    int i, found = 0;

    plat_rw_write(&g_lock);
    for (i = 0; i < g_rule_count; i++) {
        if (strcmp(g_rules[i].id, id) != 0) continue;
        add_log("info", "Rule deleted: %s", g_rules[i].name);
        memmove(&g_rules[i], &g_rules[i + 1], sizeof(Rule) * (size_t)(g_rule_count - i - 1));
        g_rule_count--;
        found = 1;
        break;
    }
    if (found) {
        save_state();
        rebuild_snapshots();
    }
    plat_rw_write_end(&g_lock);

    if (found) apply_enforcement();
    return found;
}

int engine_kill_connection(const char *id)
{
    NetConn net;
    char label[200] = {0};
    int i, found = 0, has_net = 0, rc;

    memset(&net, 0, sizeof net);
    plat_rw_read(&g_lock);
    for (i = 0; i < g_conn_count; i++) {
        if (strcmp(g_conns[i].id, id) != 0) continue;
        net = g_conns[i].net;
        has_net = g_conns[i].has_net;
        _snprintf_s(label, sizeof label, _TRUNCATE, "%s to %s:%d",
                    g_conns[i].process, g_conns[i].remote_ip, g_conns[i].remote_port);
        found = 1;
        break;
    }
    plat_rw_read_end(&g_lock);

    if (!found) return 0;
    if (!has_net) return -1;
    rc = netenum_close(&net);
    if (rc != 1) return -1;

    plat_rw_write(&g_lock);
    add_log("warn", "Terminated %s", label);
    plat_rw_write_end(&g_lock);
    return 1;
}

static int bool_field(const char *body, const char *key, int *out)
{
    char buf[16];
    if (!json_field(body, key, buf, sizeof buf)) return 0;
    *out = !strcmp(buf, "true");
    return 1;
}

int engine_settings_patch(const char *body)
{
    char buf[64];
    int want_startup = -1, enforcement_changed = 0, dns_changed = 0, retention_changed = 0;
    int v;
    Settings *s = &g_settings;

    plat_rw_write(&g_lock);
    if (bool_field(body, "startWithWindows", &v)) want_startup = v;
    bool_field(body, "notifyOnBlock", &s->notifyOnBlock);
    bool_field(body, "notifyOnNewApp", &s->notifyOnNewApp);
    bool_field(body, "notifyOnNewDevice", &s->notifyOnNewDevice);
    bool_field(body, "alertHostsFile", &s->alertHostsFile);
    bool_field(body, "alertDnsChange", &s->alertDnsChange);
    bool_field(body, "alertProxyChange", &s->alertProxyChange);
    bool_field(body, "alertRemoteAccess", &s->alertRemoteAccess);
    bool_field(body, "alertAppChange", &s->alertAppChange);
    bool_field(body, "alertNotify", &s->alertNotify);
    if (bool_field(body, "quietMode", &v) && v != s->quietMode) {
        s->quietMode = v;
        add_log("info", "Quiet mode %s", v ? "on" : "off");
    }
    if (bool_field(body, "keepRunningInBackground", &v)) {
        s->keepRunningInBackground = v;
        add_log("info", "Background protection %s", v ? "enabled" : "disabled");
    }
    if (bool_field(body, "dnsFilter", &v) && v != s->dnsFilter) {
        s->dnsFilter = v;
        dns_changed = 1;
    }
    if (bool_field(body, "blockEncryptedDns", &v) && v != s->blockEncryptedDns) {
        s->blockEncryptedDns = v;
        add_log("info", "Encrypted DNS blocking %s", v ? "enabled" : "disabled");
        enforcement_changed = 1;
    }
    if (json_field(body, "dnsUpstream", buf, sizeof buf) && is_upstream_word(buf) && strcmp(buf, s->dnsUpstream)) {
        strcpy_s(s->dnsUpstream, sizeof s->dnsUpstream, buf);
        add_log("info", "DNS upstream set to %s", buf);
        dns_changed = 1;
    }
    if (json_field(body, "defaultOutbound", buf, sizeof buf) && is_policy_word(buf) && strcmp(buf, s->defaultOutbound)) {
        strcpy_s(s->defaultOutbound, sizeof s->defaultOutbound, buf);
        add_log("info", "Default outbound policy set to %s", buf);
        enforcement_changed = 1;
    }
    if (json_field(body, "defaultInbound", buf, sizeof buf) && is_policy_word(buf) && strcmp(buf, s->defaultInbound)) {
        strcpy_s(s->defaultInbound, sizeof s->defaultInbound, buf);
        add_log("info", "Default inbound policy set to %s", buf);
        enforcement_changed = 1;
    }
    if (json_field(body, "logRetentionDays", buf, sizeof buf) && atoi(buf) > 0) {
        s->logRetentionDays = atoi(buf) > 365 ? 365 : atoi(buf);
        retention_changed = 1;
    }
    if (json_field(body, "dataLimitMb", buf, sizeof buf) && atoi(buf) >= 0) {
        s->dataLimitMb = atoi(buf);
        g_limit_level = 0;
        g_limit_period = 0;
    }
    if (json_field(body, "dataResetDay", buf, sizeof buf) && atoi(buf) >= 1 && atoi(buf) <= 28) {
        s->dataResetDay = atoi(buf);
        g_limit_level = 0;
        g_limit_period = 0;
    }
    save_state();
    rebuild_snapshots();
    plat_rw_write_end(&g_lock);

    if (want_startup >= 0) {
        int ok = plat_startup_set(want_startup);
        int actual = plat_startup_exists();
        plat_rw_write(&g_lock);
        g_settings.startWithWindows = actual;
        if (!ok || actual != want_startup) {
            add_log("warn", "The startup entry could not be %s. Administrator rights are required.",
                    want_startup ? "created" : "removed");
        } else {
            add_log("info", "Automatic start %s", actual ? "enabled" : "disabled");
        }
        rebuild_snapshots();
        plat_rw_write_end(&g_lock);
    }

    if (dns_changed) dns_apply();
    if (enforcement_changed) apply_enforcement();
    if (retention_changed) plat_prune_files("logs", ".log", g_settings.logRetentionDays);
    return 1;
}

size_t engine_render_logs(long long since, char *out, size_t cap)
{
    size_t n = 0;
    int i, first = 1;
    char esc[600];

    plat_rw_read(&g_lock);
    n += sprintf_s(out + n, cap - n, "[");
    for (i = 0; i < g_log_count && n + 1024 < cap; i++) {
        if (g_logs[i].ts <= since) continue;
        json_str(esc, sizeof esc, g_logs[i].message);
        n += sprintf_s(out + n, cap - n, "%s{\"id\":\"%s\",\"ts\":%lld,\"level\":\"%s\",\"message\":\"%s\"}",
                       first ? "" : ",", g_logs[i].id, g_logs[i].ts, g_logs[i].level, esc);
        first = 0;
    }
    n += sprintf_s(out + n, cap - n, "]");
    plat_rw_read_end(&g_lock);
    return n;
}

typedef struct {
    char name[64];
    long long rx, tx;
} AppSum;

static int by_total_desc(const void *a, const void *b)
{
    const AppSum *x = (const AppSum *)a, *y = (const AppSum *)b;
    long long tx = x->rx + x->tx, ty = y->rx + y->tx;
    return tx < ty ? 1 : (tx > ty ? -1 : 0);
}

size_t engine_render_usage(int days, int text, char *out, size_t cap)
{
    static AppSum sums[512];
    int sum_count = 0, i, j, today, start_key, period;
    long start_days, d;
    long long range_rx = 0, range_tx = 0;
    size_t n = 0;
    char day_s[16], rxs[24], txs[24], esc[128];

    if (days < 1) days = 1;
    if (days > USAGE_KEEP_DAYS) days = USAGE_KEEP_DAYS;
    today = today_key();
    start_days = key_days(today) - days + 1;
    start_key = civil_key(start_days);

    plat_rw_read(&g_lock);
    period = period_start_key(g_settings.dataResetDay);

    for (i = 0; i < g_day_app_count; i++) {
        const DayApp *r = &g_day_apps[i];
        if (r->day < start_key) continue;
        for (j = 0; j < sum_count; j++) if (!_stricmp(sums[j].name, r->app)) break;
        if (j == sum_count) {
            if (sum_count == 512) continue;
            strcpy_s(sums[j].name, sizeof sums[j].name, r->app);
            sums[j].rx = sums[j].tx = 0;
            sum_count++;
        }
        sums[j].rx += r->rx;
        sums[j].tx += r->tx;
    }
    qsort(sums, (size_t)sum_count, sizeof(AppSum), by_total_desc);

    if (text) {
        n += sprintf_s(out + n, cap - n, "%-12s %12s %12s\n", "DATE", "DOWNLOAD", "UPLOAD");
    } else {
        n += sprintf_s(out + n, cap - n, "{\"range\":%d,\"days\":[", days);
    }
    for (d = start_days; d <= key_days(today); d++) {
        int key = civil_key(d);
        long long rx = 0, tx = 0;
        for (i = 0; i < g_total_count; i++) {
            if (g_totals[i].day == key) {
                rx = g_totals[i].rx;
                tx = g_totals[i].tx;
                break;
            }
        }
        range_rx += rx;
        range_tx += tx;
        key_text(key, day_s, sizeof day_s);
        if (text) {
            human_bytes(rx, rxs, sizeof rxs);
            human_bytes(tx, txs, sizeof txs);
            n += sprintf_s(out + n, cap - n, "%-12s %12s %12s\n", day_s, rxs, txs);
        } else {
            n += sprintf_s(out + n, cap - n, "%s{\"day\":\"%s\",\"rx\":%lld,\"tx\":%lld}",
                           d == start_days ? "" : ",", day_s, rx, tx);
        }
    }

    if (text) {
        n += sprintf_s(out + n, cap - n, "\n%-26s %12s %12s\n", "APPLICATION", "DOWNLOAD", "UPLOAD");
    } else {
        n += sprintf_s(out + n, cap - n, "],\"apps\":[");
    }
    for (i = 0; i < sum_count && i < 50 && n + 512 < cap; i++) {
        if (text) {
            human_bytes(sums[i].rx, rxs, sizeof rxs);
            human_bytes(sums[i].tx, txs, sizeof txs);
            n += sprintf_s(out + n, cap - n, "%-26.26s %12s %12s\n", sums[i].name, rxs, txs);
        } else {
            json_str(esc, sizeof esc, sums[i].name);
            n += sprintf_s(out + n, cap - n, "%s{\"name\":\"%s\",\"rx\":%lld,\"tx\":%lld}",
                           i ? "," : "", esc, sums[i].rx, sums[i].tx);
        }
    }

    key_text(period, day_s, sizeof day_s);
    if (text) {
        human_bytes(range_rx + range_tx, rxs, sizeof rxs);
        n += sprintf_s(out + n, cap - n, "\nTotal for the last %d day%s: %s\n", days, days == 1 ? "" : "s", rxs);
        if (g_settings.dataLimitMb > 0) {
            human_bytes(period_bytes(period), rxs, sizeof rxs);
            n += sprintf_s(out + n, cap - n, "Billing period since %s: %s of %d MB\n", day_s, rxs, g_settings.dataLimitMb);
        }
    } else {
        n += sprintf_s(out + n, cap - n,
                       "],\"rx\":%lld,\"tx\":%lld,\"period\":{\"start\":\"%s\",\"used\":%lld,\"limitMb\":%d,\"resetDay\":%d}}",
                       range_rx, range_tx, day_s, period_bytes(period), g_settings.dataLimitMb, g_settings.dataResetDay);
    }
    plat_rw_read_end(&g_lock);
    return n;
}

size_t engine_render_devices(int text, char *out, size_t cap)
{
    size_t n = 0;
    int i;
    char name_esc[128], host_esc[200];

    plat_rw_read(&g_lock);
    if (text) n += sprintf_s(out + n, cap - n, "%-18s %-40s %-8s %s\n", "MAC", "ADDRESS", "STATUS", "NAME");
    else n += sprintf_s(out + n, cap - n, "[");
    for (i = 0; i < g_device_count && n + 600 < cap; i++) {
        const Device *d = &g_devices[i];
        if (text) {
            n += sprintf_s(out + n, cap - n, "%-18s %-40.40s %-8s %s%s\n", d->mac, d->ip[0] ? d->ip : "-",
                           d->online ? "online" : "offline", d->name[0] ? d->name : d->hostname,
                           d->gateway ? " (router)" : "");
        } else {
            json_str(name_esc, sizeof name_esc, d->name);
            json_str(host_esc, sizeof host_esc, d->hostname);
            n += sprintf_s(out + n, cap - n,
                           "%s{\"mac\":\"%s\",\"ip\":\"%s\",\"name\":\"%s\",\"hostname\":\"%s\","
                           "\"firstSeen\":%lld,\"lastSeen\":%lld,\"online\":%s,\"gateway\":%s}",
                           i ? "," : "", d->mac, d->ip, name_esc, host_esc, d->first_seen, d->last_seen,
                           B(d->online), B(d->gateway));
        }
    }
    if (text) n += sprintf_s(out + n, cap - n, "\n%d device%s known\n", g_device_count, g_device_count == 1 ? "" : "s");
    else n += sprintf_s(out + n, cap - n, "]");
    plat_rw_read_end(&g_lock);
    return n;
}

int engine_device_rename(const char *mac, const char *name)
{
    int i, found = 0;
    plat_rw_write(&g_lock);
    for (i = 0; i < g_device_count; i++) {
        if (!_stricmp(g_devices[i].mac, mac)) {
            strncpy_s(g_devices[i].name, sizeof g_devices[i].name, name ? name : "", _TRUNCATE);
            clean_field(g_devices[i].name);
            found = 1;
            break;
        }
    }
    if (found) save_state();
    plat_rw_write_end(&g_lock);
    return found;
}

size_t engine_render_alerts(int text, char *out, size_t cap)
{
    size_t n = 0;
    int i, first = 1;
    char title_esc[200], detail_esc[600];

    plat_rw_read(&g_lock);
    if (!text) n += sprintf_s(out + n, cap - n, "[");
    for (i = g_alert_count - 1; i >= 0 && n + 1024 < cap; i--) {
        const Alert *a = &g_alerts[i];
        if (text) {
            char age[24];
            human_age(a->ts, age, sizeof age);
            n += sprintf_s(out + n, cap - n, "%-6s %s %s\n       %s\n", age, a->unread ? "*" : " ", a->title, a->detail);
        } else {
            json_str(title_esc, sizeof title_esc, a->title);
            json_str(detail_esc, sizeof detail_esc, a->detail);
            n += sprintf_s(out + n, cap - n,
                           "%s{\"id\":\"%s\",\"ts\":%lld,\"kind\":\"%s\",\"title\":\"%s\",\"detail\":\"%s\",\"unread\":%s}",
                           first ? "" : ",", a->id, a->ts, a->kind, title_esc, detail_esc, B(a->unread));
            first = 0;
        }
    }
    if (text && !g_alert_count) n += sprintf_s(out + n, cap - n, "No alerts.\n");
    if (!text) n += sprintf_s(out + n, cap - n, "]");
    plat_rw_read_end(&g_lock);
    return n;
}

void engine_alerts_read(void)
{
    int i;
    plat_rw_write(&g_lock);
    for (i = 0; i < g_alert_count; i++) g_alerts[i].unread = 0;
    rebuild_snapshots();
    plat_rw_write_end(&g_lock);
}

void engine_alerts_clear(void)
{
    plat_rw_write(&g_lock);
    g_alert_count = 0;
    rebuild_snapshots();
    plat_rw_write_end(&g_lock);
}

static const char *qtype_name(int t, char *buf, size_t cap)
{
    switch (t) {
        case 1: return "A";
        case 5: return "CNAME";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 64: return "SVCB";
        case 65: return "HTTPS";
    }
    _snprintf_s(buf, cap, _TRUNCATE, "TYPE%d", t);
    return buf;
}

typedef struct {
    char *out;
    size_t n, cap;
    int count, limit, text;
} ListCtx;

static int list_domain(const char *domain, void *arg)
{
    ListCtx *c = (ListCtx *)arg;
    if (c->count >= c->limit || c->n + 256 >= c->cap) return 0;
    if (c->text) c->n += sprintf_s(c->out + c->n, c->cap - c->n, "  %s\n", domain);
    else c->n += sprintf_s(c->out + c->n, c->cap - c->n, "%s\"%s\"", c->count ? "," : "", domain);
    c->count++;
    return 1;
}

size_t engine_render_dns(int text, char *out, size_t cap)
{
    static DnsLogEntry recent[DNSLOG_CAP];
    unsigned long pids[64];
    char names[64][64];
    int pid_count = 0, count, i, j, active, total;
    unsigned long long queries = 0, blocked = 0;
    char reason[160], upstream[16], servers[8][46], name_esc[300], type_buf[16], reason_esc[320];
    int server_count;
    size_t n = 0;
    ListCtx ctx;
    static const char *const status_text[] = {"allowed", "blocked", "failed"};

    plat_rw_read(&g_lock);
    active = g_dns_active;
    strcpy_s(reason, sizeof reason, g_dns_reason);
    strcpy_s(upstream, sizeof upstream, g_settings.dnsUpstream);
    server_count = g_dns_server_count;
    for (i = 0; i < server_count; i++) strcpy_s(servers[i], 46, g_dns_servers[i]);
    total = g_settings.dnsFilter;
    plat_rw_read_end(&g_lock);

    dnsd_stats(&queries, &blocked);
    count = dnslog_copy(recent, DNSLOG_CAP);
    json_str(reason_esc, sizeof reason_esc, reason);

    if (text) {
        n += sprintf_s(out + n, cap - n, "DNS filtering    %s\nUpstream         %s", reason, upstream);
        for (i = 0; i < server_count; i++) n += sprintf_s(out + n, cap - n, "%s%s", i ? ", " : " (", servers[i]);
        n += sprintf_s(out + n, cap - n, "%s\nQueries          %llu\nBlocked          %llu\nBlocklist        %d domains\n\n",
                       server_count ? ")" : "", queries, blocked, dnsd_block_count());
    } else {
        n += sprintf_s(out + n, cap - n,
                       "{\"enabled\":%s,\"active\":%s,\"reason\":\"%s\",\"upstream\":\"%s\",\"upstreams\":[",
                       B(total), B(active), reason_esc, upstream);
        for (i = 0; i < server_count; i++) n += sprintf_s(out + n, cap - n, "%s\"%s\"", i ? "," : "", servers[i]);
        n += sprintf_s(out + n, cap - n,
                       "],\"queries\":%llu,\"blocked\":%llu,\"perProcess\":%s,\"blocklistCount\":%d,\"blocklist\":[",
                       queries, blocked, B(flows_dns_names()), dnsd_block_count());
    }

    ctx.out = out;
    ctx.n = n;
    ctx.cap = cap / 2;
    ctx.count = 0;
    ctx.limit = 2000;
    ctx.text = text;
    if (text) ctx.n += sprintf_s(out + ctx.n, cap - ctx.n, "Blocked domains\n");
    dnsd_block_each(list_domain, &ctx);
    n = ctx.n;

    if (text) n += sprintf_s(out + n, cap - n, "\nRecent lookups\n");
    else n += sprintf_s(out + n, cap - n, "],\"recent\":[");

    for (i = 0; i < count && i < 200 && n + 1024 < cap; i++) {
        const DnsLogEntry *e = &recent[i];
        const char *process = "";
        if (e->pid) {
            for (j = 0; j < pid_count; j++) {
                if (pids[j] == e->pid) {
                    process = names[j];
                    break;
                }
            }
            if (j == pid_count && pid_count < 64) {
                char full[MAX_PATH];
                const char *base = "";
                names[pid_count][0] = '\0';
                if (netenum_process_image(e->pid, full, sizeof full)) {
                    base = strrchr(full, PATH_SEP_CHAR);
                    strncpy_s(names[pid_count], 64, base ? base + 1 : full, _TRUNCATE);
                } else {
                    netenum_process_name(e->pid, names[pid_count], 64);
                }
                pids[pid_count] = e->pid;
                process = names[pid_count++];
            }
        }
        json_str(name_esc, sizeof name_esc, e->name);
        if (text) {
            n += sprintf_s(out + n, cap - n, "  %-8s %-6s %-48.48s %s\n", status_text[e->status % 3],
                           qtype_name(e->qtype, type_buf, sizeof type_buf), e->name, process);
        } else {
            n += sprintf_s(out + n, cap - n,
                           "%s{\"id\":%lu,\"ts\":%lld,\"name\":\"%s\",\"type\":\"%s\",\"status\":\"%s\",\"answer\":\"%s\",\"process\":\"%s\"}",
                           i ? "," : "", e->id, e->ts, name_esc, qtype_name(e->qtype, type_buf, sizeof type_buf),
                           status_text[e->status % 3], e->answer, process);
        }
    }
    if (!text) n += sprintf_s(out + n, cap - n, "]}");
    return n;
}

int engine_dns_block(const char *domain, int add)
{
    char path[MAX_PATH];
    int changed = add ? dnsd_block_add(domain) : dnsd_block_remove(domain);
    if (!changed) return 0;
    blocklist_path(path, sizeof path);
    dnsd_block_save(path);
    plat_dns_flush();
    engine_log("info", "%s %s the DNS blocklist", domain, add ? "added to" : "removed from");
    return 1;
}

int engine_dns_import(const char *text)
{
    char path[MAX_PATH];
    int added = dnsd_block_import(text);
    if (added) {
        blocklist_path(path, sizeof path);
        dnsd_block_save(path);
        plat_dns_flush();
    }
    engine_log("info", "Imported %d new domains into the DNS blocklist", added);
    return added;
}

int engine_app_path(const char *name, char *out, size_t cap)
{
    int i, found = 0;

    if (!name || !*name) return 0;
    plat_rw_read(&g_lock);
    for (i = 0; i < g_app_count; i++) {
        if (_stricmp(g_apps[i].name, name) == 0 || _stricmp(g_apps[i].id, name) == 0) {
            _snprintf_s(out, cap, _TRUNCATE, "%s" PATH_SEP "%s", g_apps[i].path, g_apps[i].name);
            found = 1;
            break;
        }
    }
    plat_rw_read_end(&g_lock);
    return found;
}

int engine_take_block_notice(char *out, size_t cap, int *suppressed)
{
    int have = 0;

    plat_rw_write(&g_lock);
    if (g_notice_pending > 0) {
        if (g_settings.notifyOnBlock && !g_settings.quietMode) {
            _snprintf_s(out, cap, _TRUNCATE, "%s", g_notice);
            *suppressed = g_notice_pending - 1;
            have = 1;
        }
        g_notice_pending = 0;
    }
    plat_rw_write_end(&g_lock);
    return have;
}

int engine_take_notice(char *title, size_t tcap, char *body, size_t bcap)
{
    int have = 0;

    plat_rw_write(&g_lock);
    if (g_notice_count > 0) {
        if (g_settings.quietMode) {
            g_notice_count = 0;
        } else {
            strncpy_s(title, tcap, g_notices[0].title, _TRUNCATE);
            strncpy_s(body, bcap, g_notices[0].body, _TRUNCATE);
            memmove(g_notices, g_notices + 1, sizeof(Notice) * (size_t)(g_notice_count - 1));
            g_notice_count--;
            have = 1;
        }
    }
    plat_rw_write_end(&g_lock);
    return have;
}

void engine_log(const char *level, const char *fmt, ...)
{
    char message[256];
    va_list args;

    va_start(args, fmt);
    _vsnprintf_s(message, sizeof message, _TRUNCATE, fmt, args);
    va_end(args);

    plat_rw_write(&g_lock);
    add_log(level, "%s", message);
    plat_rw_write_end(&g_lock);
}

int engine_keep_running(void)
{
    int v;
    plat_rw_read(&g_lock);
    v = g_settings.keepRunningInBackground;
    plat_rw_read_end(&g_lock);
    return v;
}

const char *engine_posture(void) { return g_posture; }

int engine_set_posture(const char *posture)
{
    if (!posture) return 0;
    if (strcmp(posture, "on") && strcmp(posture, "off") && strcmp(posture, "lockdown")) return 0;
    plat_rw_write(&g_lock);
    strncpy_s(g_posture, sizeof g_posture, posture, _TRUNCATE);
    add_log("info", "Protection mode set to %s", g_posture);
    save_state();
    rebuild_snapshots();
    plat_rw_write_end(&g_lock);

    dnsd_set_enforce(strcmp(posture, "off") != 0);
    apply_enforcement();
    return 1;
}

int engine_enforcement(char *reason, size_t cap)
{
    int active;
    plat_rw_read(&g_lock);
    active = g_enforcing;
    _snprintf_s(reason, cap, _TRUNCATE, "%s", g_enforcement_reason);
    plat_rw_read_end(&g_lock);
    return active;
}

int engine_dns_state(char *reason, size_t cap)
{
    int active;
    plat_rw_read(&g_lock);
    active = g_dns_active;
    _snprintf_s(reason, cap, _TRUNCATE, "%s", g_dns_reason);
    plat_rw_read_end(&g_lock);
    return active;
}
