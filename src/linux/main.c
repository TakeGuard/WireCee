#include "compat.h"

#include "api.h"
#include "cli.h"
#include "engine.h"
#include "platform.h"

#include <signal.h>
#include <sys/stat.h>

int plat_linux_write_unit(void);

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void linux_quit(void)
{
    g_stop = 1;
}

static int is_dir(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int resolve_app_root(char *out, size_t cap)
{
    char exe[MAX_PATH], *slash;
    const char *env = getenv("WIRECEE_APP_DIR");
    const char *layouts[] = {"%s/app", "%s/../share/wirecee/app", "%s/../../../src/web", NULL};
    int i;

    if (env && is_dir(env)) {
        strncpy_s(out, cap, env, _TRUNCATE);
        return 1;
    }
    if (plat_self_exe(exe, sizeof exe) && (slash = strrchr(exe, '/')) != NULL) {
        *slash = '\0';
        for (i = 0; layouts[i]; i++) {
            _snprintf_s(out, cap, _TRUNCATE, layouts[i], exe);
            if (is_dir(out)) return 1;
        }
    }
    strcpy_s(out, cap, "/usr/share/wirecee/app");
    return is_dir(out);
}

static int require_root(const char *what)
{
    if (geteuid() == 0) return 1;
    WARN("%s requires root. Run it again with sudo.", what);
    return 0;
}

static int service_command(const Options *opt)
{
    switch (opt->mode) {
        case RUN_SVC_INSTALL:
            if (!require_root("Installing the service")) return 1;
            if (!plat_linux_write_unit()) {
                WARN("The systemd unit could not be written.");
                return 1;
            }
            if (plat_run("systemctl enable --now wirecee.service") != 0) {
                WARN("systemctl could not enable the service.");
                return 1;
            }
            OKAY("Installed and started wirecee.service. It starts automatically at boot.");
            return 0;
        case RUN_SVC_UNINSTALL:
            if (!require_root("Removing the service")) return 1;
            plat_run("systemctl disable --now wirecee.service");
            unlink("/etc/systemd/system/wirecee.service");
            plat_run("systemctl daemon-reload");
            OKAY("Removed wirecee.service.");
            return 0;
        case RUN_SVC_START:
            if (!require_root("Starting the service")) return 1;
            return plat_run("systemctl start wirecee.service") == 0 ? (OKAY("Service started."), 0) : 1;
        case RUN_SVC_STOP:
            if (!require_root("Stopping the service")) return 1;
            return plat_run("systemctl stop wirecee.service") == 0 ? (OKAY("Service stopped."), 0) : 1;
        case RUN_SVC_STATUS:
            if (plat_run("systemctl is-active --quiet wirecee.service") == 0) {
                OKAY("wirecee.service is running.");
                return 0;
            }
            INFO("wirecee.service is not running.");
            return 1;
        default:
            return -1;
    }
}

static void desktop_notify(const char *title, const char *body)
{
    char command[1024], safe_title[128], safe_body[400];
    const char *user = getenv("SUDO_USER");
    size_t i;

    strncpy_s(safe_title, sizeof safe_title, title, _TRUNCATE);
    strncpy_s(safe_body, sizeof safe_body, body, _TRUNCATE);
    for (i = 0; safe_title[i]; i++) if (safe_title[i] == '"' || safe_title[i] == '`') safe_title[i] = '\'';
    for (i = 0; safe_body[i]; i++) if (safe_body[i] == '"' || safe_body[i] == '`') safe_body[i] = '\'';

    if (geteuid() == 0 && user && *user) {
        _snprintf_s(command, sizeof command, _TRUNCATE,
                    "sudo -u %s DISPLAY=${DISPLAY:-:0} "
                    "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u %s)/bus "
                    "notify-send -a WireCee \"%s\" \"%s\"",
                    user, user, safe_title, safe_body);
    } else {
        _snprintf_s(command, sizeof command, _TRUNCATE,
                    "notify-send -a WireCee \"%s\" \"%s\"", safe_title, safe_body);
    }
    plat_run(command);
}

static void pump_notices(void)
{
    static long long last_block = 0;
    char title[64], body[400];
    int suppressed = 0;

    while (engine_take_notice(title, sizeof title, body, sizeof body)) {
        desktop_notify(title, body);
    }
    if (plat_now_ms() - last_block >= 15000 && engine_take_block_notice(body, sizeof body, &suppressed)) {
        char text[500];
        last_block = plat_now_ms();
        if (suppressed > 0) {
            _snprintf_s(text, sizeof text, _TRUNCATE, "%s, and %d more in the last 15 seconds", body, suppressed);
        } else {
            strcpy_s(text, sizeof text, body);
        }
        desktop_notify("WireCee blocked traffic", text);
    }
}

static void open_browser(const char *url)
{
    char command[512];
    const char *user = getenv("SUDO_USER");
    if (geteuid() == 0 && user && *user) {
        _snprintf_s(command, sizeof command, _TRUNCATE, "sudo -u %s xdg-open %s &", user, url);
    } else {
        _snprintf_s(command, sizeof command, _TRUNCATE, "xdg-open %s &", url);
    }
    plat_run(command);
}

int main(int argc, char **argv)
{
    Options opt;
    ApiHooks hooks;
    struct mg_context *ctx;
    char app_root[MAX_PATH], url[64], body[512];
    int rc, port, status = 0;

    g_color = isatty(1) && !getenv("NO_COLOR");
    plat_init();

    rc = cli_parse_args(argc, argv, &opt);
    if (rc) return rc;
    rc = cli_run(&opt);
    if (rc >= 0) return rc;
    rc = service_command(&opt);
    if (rc >= 0) return rc;

    port = instance_read();
    if (port && http_call(port, "GET", "/api/status", "application/json", body, sizeof body, &status) &&
        status == 200) {
        INFO("WireCee is already running at http://127.0.0.1:%d/", port);
        if (opt.open_browser) {
            _snprintf_s(url, sizeof url, _TRUNCATE, "http://127.0.0.1:%d/", port);
            open_browser(url);
        }
        return 0;
    }
    if (port) instance_clear();

    if (!plat_is_admin()) {
        WARN("Not running as root. Monitoring works, blocking and DNS filtering need sudo.");
    }
    if (!resolve_app_root(app_root, sizeof app_root)) {
        WARN("The interface files were not found. Set WIRECEE_APP_DIR to the app directory.");
        return 1;
    }

    port = pick_port(opt.mode == RUN_SERVICE && !opt.port ? 30700 : opt.port);
    if (!port) port = pick_port(0);
    if (!port) {
        WARN("No free port between %d and %d.", PORT_MIN, PORT_MAX);
        return 1;
    }

    engine_start();

    memset(&hooks, 0, sizeof hooks);
    hooks.quit = linux_quit;
    hooks.headless = 1;
    hooks.service = opt.mode == RUN_SERVICE;
    ctx = api_start(port, app_root, &hooks);
    if (!ctx) {
        WARN("The HTTP server could not start on port %d.", port);
        engine_stop();
        return 1;
    }
    instance_write(port);

    _snprintf_s(url, sizeof url, _TRUNCATE, "http://127.0.0.1:%d/", port);
    OKAY("WireCee is running at %s", url);
    if (opt.open_browser) open_browser(url);
    if (!opt.headless && opt.mode != RUN_SERVICE && !opt.open_browser) {
        INFO("Open %s in a browser, or start with --open. Press Ctrl+C to stop.", url);
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    while (!g_stop) {
        pump_notices();
        plat_sleep_ms(500);
    }

    INFO("Shutting down");
    api_stop(ctx);
    engine_stop();
    instance_clear();
    return 0;
}
