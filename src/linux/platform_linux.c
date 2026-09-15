#include "platform.h"

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

#define DATA_DIR "/var/lib/wirecee"
#define UNIT_PATH "/etc/systemd/system/wirecee.service"
#define RESOLV "/etc/resolv.conf"

struct plat_thread_s {
    pthread_t thread;
    void (*fn)(void *);
    void *arg;
    int done;
    pthread_mutex_t m;
    pthread_cond_t c;
};

static void *thread_entry(void *param)
{
    struct plat_thread_s *t = (struct plat_thread_s *)param;
    t->fn(t->arg);
    pthread_mutex_lock(&t->m);
    t->done = 1;
    pthread_cond_signal(&t->c);
    pthread_mutex_unlock(&t->m);
    return NULL;
}

plat_thread plat_thread_start(void (*fn)(void *), void *arg)
{
    struct plat_thread_s *t = (struct plat_thread_s *)calloc(1, sizeof *t);
    if (!t) return NULL;
    t->fn = fn;
    t->arg = arg;
    pthread_mutex_init(&t->m, NULL);
    pthread_cond_init(&t->c, NULL);
    if (pthread_create(&t->thread, NULL, thread_entry, t) != 0) {
        free(t);
        return NULL;
    }
    return t;
}

void plat_thread_join(plat_thread t, int timeout_ms)
{
    struct timespec deadline;
    int done;

    if (!t) return;
    if (timeout_ms <= 0) {
        pthread_detach(t->thread);
        return;
    }
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&t->m);
    while (!t->done) {
        if (pthread_cond_timedwait(&t->c, &t->m, &deadline) != 0) break;
    }
    done = t->done;
    pthread_mutex_unlock(&t->m);
    if (done) {
        pthread_join(t->thread, NULL);
        free(t);
    } else {
        pthread_detach(t->thread);
    }
}

void plat_sleep_ms(int ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

void plat_init(void)
{
    signal(SIGPIPE, SIG_IGN);
}

long long plat_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000L;
}

void plat_local_time(PlatTime *t)
{
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    t->year = tm.tm_year + 1900;
    t->month = tm.tm_mon + 1;
    t->day = tm.tm_mday;
    t->hour = tm.tm_hour;
    t->minute = tm.tm_min;
    t->second = tm.tm_sec;
}

unsigned long plat_pid(void) { return (unsigned long)getpid(); }
int plat_is_admin(void) { return geteuid() == 0; }
const char *plat_os(void) { return "linux"; }

int plat_self_exe(char *out, size_t cap)
{
    ssize_t n = readlink("/proc/self/exe", out, cap - 1);
    if (n <= 0) return 0;
    out[n] = '\0';
    return 1;
}

static void mkdir_p(const char *dir)
{
    char buf[MAX_PATH];
    char *p;
    strncpy_s(buf, sizeof buf, dir, _TRUNCATE);
    for (p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(buf, 0755);
            *p = '/';
        }
    }
    mkdir(buf, 0755);
}

int plat_data_path(const char *sub, const char *file, char *out, size_t cap)
{
    const char *env = getenv("WIRECEE_DATA_DIR");
    char dir[MAX_PATH];
    const char *base = env && *env ? env : DATA_DIR;

    if (sub && *sub) _snprintf_s(dir, sizeof dir, _TRUNCATE, "%s/%s", base, sub);
    else strcpy_s(dir, sizeof dir, base);
    mkdir_p(dir);
    _snprintf_s(out, cap, _TRUNCATE, "%s/%s", dir, file);
    return 1;
}

int plat_file_stat(const char *path, long long *size, long long *mtime)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) return 0;
    if (size) *size = (long long)st.st_size;
    if (mtime) *mtime = (long long)st.st_mtim.tv_sec * 1000LL + st.st_mtim.tv_nsec / 1000000L;
    return 1;
}

int plat_replace_file(const char *from, const char *to)
{
    return rename(from, to) == 0;
}

FILE *plat_fopen_shared(const char *path, const char *mode)
{
    return fopen(path, mode);
}

void plat_prune_files(const char *sub, const char *suffix, int days)
{
    char probe[MAX_PATH], dir[MAX_PATH], path[MAX_PATH];
    DIR *d;
    struct dirent *e;
    time_t cutoff;
    size_t slen = strlen(suffix);
    char *slash;

    if (days < 1) days = 1;
    plat_data_path(sub, "x", probe, sizeof probe);
    strcpy_s(dir, sizeof dir, probe);
    slash = strrchr(dir, '/');
    if (slash) *slash = '\0';
    cutoff = time(NULL) - (time_t)days * 86400;

    d = opendir(dir);
    if (!d) return;
    while ((e = readdir(d)) != NULL) {
        struct stat st;
        size_t len = strlen(e->d_name);
        if (len < slen || strcmp(e->d_name + len - slen, suffix) != 0) continue;
        _snprintf_s(path, sizeof path, _TRUNCATE, "%s/%s", dir, e->d_name);
        if (stat(path, &st) == 0 && st.st_mtime < cutoff) unlink(path);
    }
    closedir(d);
}

int plat_run(const char *command)
{
    char buf[2048];
    int rc;
    _snprintf_s(buf, sizeof buf, _TRUNCATE, "%s >/dev/null 2>&1", command);
    rc = system(buf);
    if (rc == -1) return -1;
    return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}

int plat_linux_write_unit(void)
{
    char exe[MAX_PATH];
    FILE *f;

    if (!plat_self_exe(exe, sizeof exe)) strcpy_s(exe, sizeof exe, "/usr/bin/wirecee");
    f = fopen(UNIT_PATH, "w");
    if (!f) return 0;
    fprintf(f,
            "[Unit]\n"
            "Description=WireCee firewall engine\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n\n"
            "[Service]\n"
            "ExecStart=%s --service\n"
            "Restart=on-failure\n"
            "RestartSec=3\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n", exe);
    fclose(f);
    plat_run("systemctl daemon-reload");
    return 1;
}

int plat_startup_exists(void)
{
    return plat_run("systemctl is-enabled --quiet wirecee.service") == 0;
}

int plat_startup_set(int enable)
{
    if (!enable) return plat_run("systemctl disable wirecee.service") == 0;
    if (!plat_file_stat(UNIT_PATH, NULL, NULL) && !plat_linux_write_unit()) return 0;
    return plat_run("systemctl enable wirecee.service") == 0;
}

int plat_hosts_file(char *out, size_t cap)
{
    const char *override = getenv("WIRECEE_HOSTS_FILE");
    strcpy_s(out, cap, override && *override ? override : "/etc/hosts");
    return 1;
}

int plat_proxy_signature(char *out, size_t cap)
{
    FILE *f = fopen("/etc/environment", "r");
    char line[512];

    out[0] = '\0';
    if (!f) return 1;
    while (fgets(line, sizeof line, f)) {
        if (!strcasestr(line, "proxy")) continue;
        line[strcspn(line, "\r\n")] = '\0';
        if (out[0]) strcat_s(out, cap, " ");
        strcat_s(out, cap, line);
    }
    fclose(f);
    return 1;
}

int plat_remote_access_port(void) { return 22; }

int plat_notifications_enabled(void)
{
    return plat_run("command -v notify-send") == 0;
}

static char g_upstreams[8][46];
static int g_upstream_count = 0;
static int g_redirected = 0;

static int is_loopback_text(const char *ip)
{
    return !strncmp(ip, "127.", 4) || !strcmp(ip, "::1");
}

static int read_nameservers(const char *path, char out[][46], int cap)
{
    FILE *f = fopen(path, "r");
    char line[256], ip[64];
    int n = 0;

    if (!f) return 0;
    while (fgets(line, sizeof line, f) && n < cap) {
        if (sscanf(line, " nameserver %63s", ip) == 1) strcpy_s(out[n++], 46, ip);
    }
    fclose(f);
    return n;
}

int plat_dns_servers(char out[][46], int cap)
{
    return read_nameservers(RESOLV, out, cap);
}

static int real_upstreams(char out[][46], int cap)
{
    char all[8][46];
    int i, n = read_nameservers(RESOLV, all, 8), count = 0, stub = 0;

    for (i = 0; i < n; i++) {
        if (!strcmp(all[i], "127.0.0.53")) stub = 1;
        else if (!is_loopback_text(all[i]) && count < cap) strcpy_s(out[count++], 46, all[i]);
    }
    if (!count && stub) {
        n = read_nameservers("/run/systemd/resolve/resolv.conf", all, 8);
        for (i = 0; i < n && count < cap; i++) {
            if (!is_loopback_text(all[i])) strcpy_s(out[count++], 46, all[i]);
        }
    }
    return count;
}

static int backup_paths(char *meta, char *copy, size_t cap)
{
    return plat_data_path(NULL, "dns-backup.tsv", meta, cap) && plat_data_path(NULL, "resolv.conf.backup", copy, cap);
}

static int copy_file(const char *from, const char *to)
{
    FILE *in = fopen(from, "r"), *out;
    char buf[4096];
    size_t n;
    if (!in) return 0;
    out = fopen(to, "w");
    if (!out) {
        fclose(in);
        return 0;
    }
    while ((n = fread(buf, 1, sizeof buf, in)) > 0) fwrite(buf, 1, n, out);
    fclose(in);
    fclose(out);
    return 1;
}

static int restore_resolv(void)
{
    char meta[MAX_PATH], copy[MAX_PATH], line[MAX_PATH + 16];
    FILE *f;
    int restored = 0;

    backup_paths(meta, copy, sizeof meta);
    f = fopen(meta, "r");
    if (!f) return 0;
    if (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (!strncmp(line, "link\t", 5)) {
            unlink(RESOLV);
            restored = symlink(line + 5, RESOLV) == 0;
        } else if (!strcmp(line, "file")) {
            restored = copy_file(copy, RESOLV);
        }
    }
    fclose(f);
    unlink(meta);
    unlink(copy);
    return restored;
}

void plat_dns_flush(void)
{
    plat_run("resolvectl flush-caches");
}

int plat_dns_redirect_begin(char *reason, size_t cap)
{
    char meta[MAX_PATH], copy[MAX_PATH], target[MAX_PATH];
    struct stat st;
    FILE *f;
    ssize_t len;
    int i;

    if (g_redirected) return 1;
    if (geteuid() != 0) {
        _snprintf_s(reason, cap, _TRUNCATE, "Changing DNS settings requires root");
        return 0;
    }
    g_upstream_count = real_upstreams(g_upstreams, 8);
    backup_paths(meta, copy, sizeof meta);

    f = fopen(meta, "w");
    if (!f) {
        _snprintf_s(reason, cap, _TRUNCATE, "The DNS backup could not be written");
        return 0;
    }
    if (lstat(RESOLV, &st) == 0 && S_ISLNK(st.st_mode) &&
        (len = readlink(RESOLV, target, sizeof target - 1)) > 0) {
        target[len] = '\0';
        fprintf(f, "link\t%s\n", target);
    } else {
        copy_file(RESOLV, copy);
        fprintf(f, "file\n");
    }
    fclose(f);

    unlink(RESOLV);
    f = fopen(RESOLV, "w");
    if (!f) {
        restore_resolv();
        _snprintf_s(reason, cap, _TRUNCATE, "/etc/resolv.conf could not be written");
        return 0;
    }
    fprintf(f, "# Managed by WireCee while DNS filtering is on\nnameserver 127.0.0.1\n");
    for (i = 0; i < g_upstream_count && i < 2; i++) fprintf(f, "nameserver %s\n", g_upstreams[i]);
    fprintf(f, "options timeout:1 attempts:2\n");
    fclose(f);

    g_redirected = 1;
    plat_dns_flush();
    return 1;
}

void plat_dns_redirect_end(void)
{
    if (!g_redirected) return;
    restore_resolv();
    g_redirected = 0;
    plat_dns_flush();
}

int plat_dns_redirect_recover(void)
{
    return geteuid() == 0 && restore_resolv();
}

int plat_dns_upstreams(char out[][46], int cap)
{
    int i, n = 0;
    if (g_redirected) {
        for (i = 0; i < g_upstream_count && n < cap; i++) strcpy_s(out[n++], 46, g_upstreams[i]);
        return n;
    }
    return real_upstreams(out, cap);
}

int plat_neighbors(PlatNeighbor *out, int cap)
{
    FILE *f;
    char line[256], gateway[46] = "";
    int n = 0;

    f = fopen("/proc/net/route", "r");
    if (f) {
        char iface[32];
        unsigned long dest, gw;
        while (fgets(line, sizeof line, f)) {
            if (sscanf(line, "%31s %lx %lx", iface, &dest, &gw) == 3 && dest == 0 && gw != 0) {
                struct in_addr a;
                a.s_addr = (in_addr_t)gw;
                inet_ntop(AF_INET, &a, gateway, sizeof gateway);
                break;
            }
        }
        fclose(f);
    }

    f = fopen("/proc/net/arp", "r");
    if (!f) return 0;
    if (!fgets(line, sizeof line, f)) {
        fclose(f);
        return 0;
    }
    while (fgets(line, sizeof line, f) && n < cap) {
        char ip[46], hw[32], flags[16], mask[16], dev[32], type[16];
        if (sscanf(line, "%45s %15s %15s %31s %15s %31s", ip, type, flags, hw, mask, dev) != 6) continue;
        if (strtoul(flags, NULL, 16) == 0 || !strcmp(hw, "00:00:00:00:00:00")) continue;
        memset(&out[n], 0, sizeof out[n]);
        strcpy_s(out[n].ip, sizeof out[n].ip, ip);
        strncpy_s(out[n].mac, sizeof out[n].mac, hw, _TRUNCATE);
        out[n].gateway = gateway[0] && !strcmp(gateway, ip);
        n++;
    }
    fclose(f);
    return n;
}
