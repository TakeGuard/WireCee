#include "compat.h"

#include "cli.h"
#include "platform.h"

#include <stdarg.h>
#include <time.h>

#ifndef _WIN32
#include <signal.h>
#endif

#define CLI_BUF (1024 * 1024)

int g_color = 0;
int g_quiet = 0;

const char *C(const char *ansi) { return g_color ? ansi : ""; }

void cw_log(FILE *stream, const char *color, const char *sigil, const char *fmt, ...)
{
    va_list args;
    if (g_quiet && stream == stdout) return;

    fprintf(stream, "%s[ %s%s%s ] %s", C("\033[1;97m"), color, sigil, C("\033[1;97m"), color);
    va_start(args, fmt);
    vfprintf(stream, fmt, args);
    va_end(args);
    fprintf(stream, "%s", C("\033[0m"));
    fflush(stream);
}

void cw_rule(void)
{
    if (g_quiet) return;
    printf("--------------------------------------------------------\n");
}

static int instance_file_path(char *out, size_t len)
{
    return plat_data_path(NULL, "instance.port", out, len);
}

void instance_write(int port)
{
    char path[MAX_PATH];
    FILE *f = NULL;
    if (!instance_file_path(path, sizeof path)) return;
    if (fopen_s(&f, path, "w") == 0 && f) {
        fprintf(f, "%d\n%lu\n", port, plat_pid());
        fclose(f);
    }
}

void instance_clear(void)
{
    char path[MAX_PATH];
    if (instance_file_path(path, sizeof path)) remove(path);
}

int instance_read(void)
{
    char path[MAX_PATH];
    FILE *f = NULL;
    int port = 0;
    unsigned long pid = 0;

    if (!instance_file_path(path, sizeof path)) return 0;
    if (fopen_s(&f, path, "r") != 0 || !f) return 0;
    if (fscanf(f, "%d %lu", &port, &pid) != 2) port = 0;
    fclose(f);
    if (!port) return 0;

#ifdef _WIN32
    {
        HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, (DWORD)pid);
        if (h) {
            int gone = WaitForSingleObject(h, 0) == WAIT_OBJECT_0;
            CloseHandle(h);
            if (gone) {
                instance_clear();
                return 0;
            }
        }
    }
#else
    if (pid && kill((pid_t)pid, 0) != 0 && errno == ESRCH) {
        instance_clear();
        return 0;
    }
#endif
    return port;
}

int http_call(int port, const char *method, const char *path, const char *accept,
              char *body_out, size_t body_len, int *status_out)
{
    plat_socket s;
    struct sockaddr_in addr;
    char request[1024];
    char *buffer;
    int total = 0, ok = 0;
    const char *body;

    if (body_out && body_len) body_out[0] = '\0';
    if (status_out) *status_out = 0;

    plat_init();
    buffer = (char *)malloc(CLI_BUF);
    if (!buffer) return 0;

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == PLAT_BAD_SOCKET) {
        free(buffer);
        return 0;
    }

    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(s, (struct sockaddr *)&addr, sizeof addr) != 0) goto done;

    _snprintf_s(request, sizeof request, _TRUNCATE,
                "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: %s\r\n"
                "Connection: close\r\nContent-Length: 0\r\n\r\n",
                method, path, accept ? accept : "application/json");
    if (send(s, request, (int)strlen(request), 0) <= 0) goto done;

    while (total < CLI_BUF - 1) {
        int received = (int)recv(s, buffer + total, CLI_BUF - 1 - total, 0);
        if (received <= 0) break;
        total += received;
    }
    buffer[total] = '\0';
    if (total == 0) goto done;

    ok = 1;
    if (status_out && total > 12) *status_out = atoi(buffer + 9);
    if (body_out && body_len) {
        body = strstr(buffer, "\r\n\r\n");
        _snprintf_s(body_out, body_len, _TRUNCATE, "%s", body ? body + 4 : "");
    }

done:
    plat_closesocket(s);
    free(buffer);
    return ok;
}

static int port_is_free(int port)
{
    plat_socket s;
    struct sockaddr_in addr;
    int free_port;

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == PLAT_BAD_SOCKET) return 0;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    free_port = bind(s, (struct sockaddr *)&addr, sizeof addr) == 0;
    plat_closesocket(s);
    return free_port;
}

int pick_port(int requested)
{
    int candidate, i;

    plat_init();
    if (requested) return port_is_free(requested) ? requested : 0;

    srand((unsigned)time(NULL) ^ (unsigned)plat_pid());
    candidate = PORT_MIN + rand() % (PORT_MAX - PORT_MIN);
    for (i = 0; i <= PORT_MAX - PORT_MIN; i++) {
        int try_port = PORT_MIN + (candidate - PORT_MIN + i) % (PORT_MAX - PORT_MIN);
        if (port_is_free(try_port)) return try_port;
    }
    return 0;
}

void cli_print_usage(void)
{
    const char *h = C("\033[1;97m"), *r = C("\033[0m");

    printf("%sWireCee%s %s  Personal firewall by TakeGuard\n\n", C("\033[1;96m"), r, WIRECEE_VERSION);
    printf("%sUSAGE%s\n  wirecee [command] [options]\n\n", h, r);
    printf("%sCOMMANDS%s\n"
           "  (none)                  Start the engine%s\n"
           "  connections             Live connections, one row each\n"
           "  apps [--blocked]        Applications seen on the network\n"
           "  block <program>         Block a program's network access\n"
           "  allow <program>         Allow it again\n"
           "  ask <program>           Refuse it until you decide\n"
           "  rules                   Firewall rules\n"
           "  usage [--days <n>]      Data usage per day and per application\n"
           "  devices                 Devices seen on the local network\n"
           "  alerts                  Security alerts\n"
           "  dns                     DNS filtering status, blocklist and recent lookups\n"
           "  dns block <domain>      Add a domain and its subdomains to the blocklist\n"
           "  dns unblock <domain>    Remove a domain from the blocklist\n"
           "  settings                Current settings\n"
           "  metrics                 Counters and throughput\n\n",
           h, r,
#ifdef _WIN32
           ", tray icon and window");
#else
           " and serve the interface");
#endif
    printf("%sSERVICE%s\n", h, r);
#ifdef _WIN32
    printf("  --install-service       Install the Windows service (administrator)\n"
           "  --uninstall-service     Remove it (administrator)\n"
           "  --start-service         Start it (administrator)\n"
           "  --stop-service          Stop it (administrator)\n"
           "  --service-status        Report whether it is installed and running\n\n");
#else
    printf("  --install-service       Install and enable the systemd unit (root)\n"
           "  --uninstall-service     Disable and remove it (root)\n"
           "  --start-service         Start it (root)\n"
           "  --stop-service          Stop it (root)\n"
           "  --service-status        Report whether it is installed and running\n\n");
#endif
    printf("%sOPTIONS%s\n"
           "  -h, --help              Show this help\n"
           "  -V, --version           Print the version\n"
           "      --status            Report on the running engine\n"
           "      --stop              Stop the running engine\n"
           "  -p, --port <n>          Listen on this port instead of one from %d to %d\n"
           "      --headless          Run without opening a window\n"
           "      --open              Open the interface in the default browser\n"
#ifdef _WIN32
           "      --no-elevate        Skip the administrator prompt. Monitoring works,\n"
           "                          blocking, DNS filtering and byte counts do not.\n"
#endif
           "      --json              Machine readable output\n"
           "  -q, --quiet             Suppress progress output\n"
           "  -v, --verbose           Extra detail\n"
           "      --no-color          Never emit ANSI color\n\n",
           h, r, PORT_MIN, PORT_MAX);
    printf("%sEXAMPLES%s\n"
           "  wirecee connections\n"
#ifdef _WIN32
           "  wirecee block chrome.exe\n"
#else
           "  sudo wirecee block firefox-esr\n"
#endif
           "  wirecee usage --days 30\n"
           "  wirecee dns block ads.example.com\n\n"
           "Commands use the same API as the window, so both always agree.\n", h, r);
}

int cli_parse_args(int argc, char **argv, Options *opt)
{
    int i;

    memset(opt, 0, sizeof *opt);
    opt->mode = RUN_APP;

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (i == 1 && a[0] != '-') {
            if (!_stricmp(a, "connections") || !_stricmp(a, "conns")) opt->mode = RUN_CONNECTIONS;
            else if (!_stricmp(a, "apps") || !_stricmp(a, "applications")) opt->mode = RUN_APPS;
            else if (!_stricmp(a, "rules")) opt->mode = RUN_RULES;
            else if (!_stricmp(a, "settings")) opt->mode = RUN_SETTINGS;
            else if (!_stricmp(a, "metrics")) opt->mode = RUN_METRICS;
            else if (!_stricmp(a, "usage")) opt->mode = RUN_USAGE;
            else if (!_stricmp(a, "devices")) opt->mode = RUN_DEVICES;
            else if (!_stricmp(a, "alerts")) opt->mode = RUN_ALERTS;
            else if (!_stricmp(a, "dns")) {
                opt->mode = RUN_DNS;
                if (i + 1 < argc && argv[i + 1][0] != '-') {
                    const char *sub = argv[++i];
                    if (!_stricmp(sub, "block")) opt->mode = RUN_DNS_BLOCK;
                    else if (!_stricmp(sub, "unblock")) opt->mode = RUN_DNS_UNBLOCK;
                    else {
                        WARN("Unknown dns command: %s", sub);
                        return 2;
                    }
                    if (i + 1 >= argc) {
                        WARN("dns %s needs a domain, for example: wirecee dns %s ads.example.com", sub, sub);
                        return 2;
                    }
                    strncpy_s(opt->target, sizeof opt->target, argv[++i], _TRUNCATE);
                }
            } else if (!_stricmp(a, "block") || !_stricmp(a, "allow") || !_stricmp(a, "ask")) {
                opt->mode = RUN_POLICY;
                policy_parse(a, &opt->policy);
                if (i + 1 >= argc) {
                    WARN("%s needs a program name, for example: wirecee %s firefox", a, a);
                    return 2;
                }
                strncpy_s(opt->target, sizeof opt->target, argv[++i], _TRUNCATE);
            } else {
                WARN("Unknown command: %s", a);
                fprintf(stderr, "Run 'wirecee --help' for the list of commands.\n");
                return 2;
            }
            continue;
        }

        if (!strcmp(a, "-h") || !strcmp(a, "--help")) opt->mode = RUN_HELP;
        else if (!strcmp(a, "-V") || !strcmp(a, "--version")) opt->mode = RUN_VERSION;
        else if (!strcmp(a, "--status")) opt->mode = RUN_STATUS;
        else if (!strcmp(a, "--stop")) opt->mode = RUN_STOP;
        else if (!strcmp(a, "--service")) opt->mode = RUN_SERVICE;
        else if (!strcmp(a, "--install-service")) opt->mode = RUN_SVC_INSTALL;
        else if (!strcmp(a, "--uninstall-service")) opt->mode = RUN_SVC_UNINSTALL;
        else if (!strcmp(a, "--start-service")) opt->mode = RUN_SVC_START;
        else if (!strcmp(a, "--stop-service")) opt->mode = RUN_SVC_STOP;
        else if (!strcmp(a, "--service-status")) opt->mode = RUN_SVC_STATUS;
        else if (!strcmp(a, "--blocked")) opt->blocked_only = 1;
        else if (!strcmp(a, "--headless") || !strcmp(a, "--no-ui")) opt->headless = 1;
        else if (!strcmp(a, "--open")) opt->open_browser = 1;
        else if (!strcmp(a, "--no-elevate")) opt->no_elevate = 1;
        else if (!strcmp(a, "--elevated")) opt->elevated_relaunch = 1;
        else if (!strcmp(a, "--json")) opt->json = 1;
        else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) g_quiet = 1;
        else if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) opt->verbose = 1;
        else if (!strcmp(a, "--no-color") || !strcmp(a, "--no-colour")) g_color = 0;
        else if (!strcmp(a, "--days")) {
            if (i + 1 >= argc) { WARN("--days needs a number"); return 2; }
            opt->days = atoi(argv[++i]);
            if (opt->days < 1 || opt->days > 90) { WARN("--days must be between 1 and 90"); return 2; }
        } else if (!strcmp(a, "-p") || !strcmp(a, "--port")) {
            if (i + 1 >= argc) { WARN("--port needs a number"); return 2; }
            opt->port = atoi(argv[++i]);
            if (opt->port < 1 || opt->port > 65535) { WARN("--port must be between 1 and 65535"); return 2; }
        } else {
            WARN("Unknown option: %s", a);
            fprintf(stderr, "Run 'wirecee --help' for the list of options.\n");
            return 2;
        }
    }
    return 0;
}

static int require_engine(void)
{
    int port = instance_read();
    if (!port) {
        WARN("WireCee is not running.");
#ifdef _WIN32
        fprintf(stderr, "    Start it with 'wirecee', or install the service with 'wirecee --install-service'.\n");
#else
        fprintf(stderr, "    Start it with 'sudo wirecee --headless', or install the service with 'sudo wirecee --install-service'.\n");
#endif
    }
    return port;
}

static int cmd_get(const char *path, int json)
{
    char *body;
    int port = require_engine(), status = 0, rc = 1;

    if (!port) return 1;
    body = (char *)malloc(CLI_BUF);
    if (!body) return 1;

    if (!http_call(port, "GET", path, json ? "application/json" : "text/plain", body, CLI_BUF, &status)) {
        WARN("The engine on port %d did not answer.", port);
    } else if (status != 200) {
        WARN("The engine returned HTTP %d for %s", status, path);
    } else {
        fputs(body, stdout);
        if (json) fputc('\n', stdout);
        rc = 0;
    }
    free(body);
    return rc;
}

static int cmd_policy(const Options *opt)
{
    char path[256], body[1024];
    int port = require_engine(), status = 0;

    if (!port) return 1;
    _snprintf_s(path, sizeof path, _TRUNCATE, "/api/apps/policy?name=%s&policy=%s",
                opt->target, policy_name(opt->policy));
    if (!http_call(port, "POST", path, "application/json", body, sizeof body, &status)) {
        WARN("The engine on port %d did not answer.", port);
        return 1;
    }
    if (status == 404) {
        WARN("No application named '%s'.", opt->target);
        fprintf(stderr, "    'wirecee apps' lists the applications WireCee has seen.\n");
        return 1;
    }
    if (status != 200) {
        WARN("The engine returned HTTP %d.", status);
        return 1;
    }
    if (opt->json) printf("%s\n", body);
    else OKAY("%s is now set to %s.", opt->target, policy_name(opt->policy));
    return 0;
}

static int cmd_dns_block(const Options *opt, int add)
{
    char path[256], body[512];
    int port = require_engine(), status = 0;

    if (!port) return 1;
    _snprintf_s(path, sizeof path, _TRUNCATE, "/api/dns/block?domain=%s", opt->target);
    if (!http_call(port, add ? "POST" : "DELETE", path, "application/json", body, sizeof body, &status)) {
        WARN("The engine on port %d did not answer.", port);
        return 1;
    }
    if (status != 200) {
        WARN(add ? "%s is already listed or is not a valid domain." : "%s is not on the blocklist.", opt->target);
        return 1;
    }
    OKAY(add ? "%s added to the DNS blocklist." : "%s removed from the DNS blocklist.", opt->target);
    return 0;
}

static int cmd_status(const Options *opt)
{
    int port = instance_read(), status = 0;
    char body[2048];

    if (!port) {
        if (opt->json) printf("{\"running\":false}\n");
        else WARN("WireCee is not running.");
        return 1;
    }
    if (!http_call(port, "GET", "/api/status", "application/json", body, sizeof body, &status) || status != 200) {
        instance_clear();
        if (opt->json) printf("{\"running\":false,\"stale\":true}\n");
        else WARN("Cleared a stale instance record for port %d.", port);
        return 1;
    }
    if (opt->json) printf("%s\n", body);
    else {
        OKAY("WireCee is running on 127.0.0.1:%d", port);
        printf("    %s\n", body);
    }
    return 0;
}

static int cmd_stop(void)
{
    int port = instance_read(), status = 0;

    if (!port) {
        WARN("WireCee is not running.");
        return 1;
    }
    if (!http_call(port, "POST", "/api/quit", "application/json", NULL, 0, &status)) {
        WARN("The engine on port %d did not answer.", port);
        return 1;
    }
    OKAY("Shutdown requested.");
    return 0;
}

int cli_run(const Options *opt)
{
    char path[64];

    switch (opt->mode) {
        case RUN_HELP: cli_print_usage(); return 0;
        case RUN_VERSION: printf("wirecee %s\n", WIRECEE_VERSION); return 0;
        case RUN_STATUS: return cmd_status(opt);
        case RUN_STOP: return cmd_stop();
        case RUN_CONNECTIONS: return cmd_get("/api/connections", opt->json);
        case RUN_APPS: return cmd_get(opt->blocked_only ? "/api/apps?policy=block" : "/api/apps", opt->json);
        case RUN_RULES: return cmd_get("/api/rules", opt->json);
        case RUN_SETTINGS: return cmd_get("/api/settings", opt->json);
        case RUN_METRICS: return cmd_get("/api/metrics", opt->json);
        case RUN_POLICY: return cmd_policy(opt);
        case RUN_USAGE:
            _snprintf_s(path, sizeof path, _TRUNCATE, "/api/usage?days=%d", opt->days ? opt->days : 7);
            return cmd_get(path, opt->json);
        case RUN_DEVICES: return cmd_get("/api/devices", opt->json);
        case RUN_ALERTS: return cmd_get("/api/alerts", opt->json);
        case RUN_DNS: return cmd_get("/api/dns", opt->json);
        case RUN_DNS_BLOCK: return cmd_dns_block(opt, 1);
        case RUN_DNS_UNBLOCK: return cmd_dns_block(opt, 0);
        default: return -1;
    }
}
