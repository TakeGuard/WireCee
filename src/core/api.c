#include "compat.h"

#include "api.h"
#include "engine.h"
#include "platform.h"
#include "version.h"

#define RENDER_BUF (1024 * 1024)
#define IMPORT_MAX (8 * 1024 * 1024)

static ApiHooks g_hooks;
static int g_port = 0;

int api_send_json(struct mg_connection *conn, int status, const char *body)
{
    mg_printf(conn,
              "HTTP/1.1 %d %s\r\n"
              "Content-Type: application/json\r\n"
              "Content-Length: %d\r\n"
              "Cache-Control: no-store\r\n"
              "\r\n%s",
              status, status == 200 ? "OK" : "Error", (int)strlen(body), body);
    return status;
}

static int wants_text(struct mg_connection *conn)
{
    const char *accept = mg_get_header(conn, "Accept");
    return accept && strstr(accept, "text/plain") != NULL;
}

static int send_body(struct mg_connection *conn, int text, const char *body, size_t len)
{
    mg_printf(conn,
              "HTTP/1.1 200 OK\r\n"
              "Content-Type: %s\r\n"
              "Content-Length: %d\r\n"
              "Cache-Control: no-store\r\n"
              "\r\n",
              text ? "text/plain; charset=utf-8" : "application/json", (int)len);
    if (len) mg_write(conn, body, len);
    return 200;
}

static int send_snapshot(struct mg_connection *conn, SnapKind kind)
{
    const Snapshot *snap;
    const char *inm, *body;
    int text = wants_text(conn);
    size_t len;
    char etag[40];

    snap = engine_acquire(kind);
    _snprintf_s(etag, sizeof etag, _TRUNCATE, "%s", snap->etag);
    inm = mg_get_header(conn, "If-None-Match");
    if (inm && strcmp(inm, etag) == 0) {
        engine_release();
        mg_printf(conn, "HTTP/1.1 304 Not Modified\r\nETag: %s\r\nCache-Control: no-cache\r\n\r\n", etag);
        return 304;
    }

    body = text ? snap->text : snap->json;
    len = text ? snap->text_len : snap->json_len;
    mg_printf(conn,
              "HTTP/1.1 200 OK\r\n"
              "Content-Type: %s\r\n"
              "Content-Length: %d\r\n"
              "ETag: %s\r\n"
              "Cache-Control: no-cache\r\n"
              "\r\n",
              text ? "text/plain; charset=utf-8" : "application/json", (int)len, etag);
    if (len) mg_write(conn, body, len);
    engine_release();
    return 200;
}

static int read_body(struct mg_connection *conn, char *out, size_t cap)
{
    size_t total = 0;
    while (total + 1 < cap) {
        int n = mg_read(conn, out + total, cap - 1 - total);
        if (n <= 0) break;
        total += (size_t)n;
    }
    out[total] = '\0';
    return (int)total;
}

static const char *sub_path(const struct mg_request_info *req, const char *root)
{
    const char *p;
    if (!req || !req->local_uri) return "";
    p = req->local_uri + strlen(root);
    while (*p == '/') p++;
    return p;
}

static int query_var(const struct mg_request_info *req, const char *name, char *out, size_t cap)
{
    out[0] = '\0';
    if (!req->query_string) return 0;
    return mg_get_var(req->query_string, strlen(req->query_string), name, out, cap) > 0;
}

static int is_method(const struct mg_request_info *req, const char *method)
{
    return strcmp(req->request_method, method) == 0;
}

typedef size_t (*RenderFn)(int text, char *out, size_t cap);

static int send_render(struct mg_connection *conn, RenderFn fn)
{
    int text = wants_text(conn);
    char *buf = (char *)malloc(RENDER_BUF);
    size_t n;
    if (!buf) return api_send_json(conn, 500, "{\"error\":\"Out of memory\"}");
    n = fn(text, buf, RENDER_BUF);
    send_body(conn, text, buf, n);
    free(buf);
    return 200;
}

static int h_connections(struct mg_connection *conn, void *cbdata)
{
    const struct mg_request_info *req = mg_get_request_info(conn);
    const char *id = sub_path(req, "/api/connections");
    (void)cbdata;

    if (!*id) return send_snapshot(conn, SNAP_CONNECTIONS);
    if (!is_method(req, "DELETE")) return api_send_json(conn, 405, "{\"error\":\"Method not allowed\"}");
    switch (engine_kill_connection(id)) {
        case 1: return api_send_json(conn, 200, "{\"ok\":true}");
        case 0: return api_send_json(conn, 404, "{\"error\":\"No such connection\"}");
        default:
            return api_send_json(conn, 403,
                                 "{\"error\":\"The connection could not be closed. This requires administrator "
                                 "rights and works for IPv4 TCP connections.\"}");
    }
}

static int h_apps(struct mg_connection *conn, void *cbdata)
{
    const struct mg_request_info *req = mg_get_request_info(conn);
    const char *sub = sub_path(req, "/api/apps");
    char name[128], policy_str[16], body[512];
    Policy policy;
    (void)cbdata;

    if (!strcmp(sub, "icon")) {
        query_var(req, "name", name, sizeof name);
        if (!g_hooks.icon || !name[0]) return api_send_json(conn, 404, "{\"error\":\"No icon\"}");
        return g_hooks.icon(conn, name);
    }

    if (!strcmp(sub, "policy")) {
        if (!is_method(req, "POST") && !is_method(req, "PATCH")) {
            return api_send_json(conn, 405, "{\"error\":\"Method not allowed\"}");
        }
        query_var(req, "name", name, sizeof name);
        query_var(req, "policy", policy_str, sizeof policy_str);
        if (!policy_parse(policy_str, &policy)) {
            return api_send_json(conn, 400, "{\"error\":\"Policy must be allow, ask or block\"}");
        }
        if (!engine_set_policy(name, policy)) {
            return api_send_json(conn, 404, "{\"error\":\"No such application\"}");
        }
        _snprintf_s(body, sizeof body, _TRUNCATE, "{\"ok\":true,\"policy\":\"%s\"}", policy_name(policy));
        return api_send_json(conn, 200, body);
    }

    if (*sub) return api_send_json(conn, 404, "{\"error\":\"Unknown action\"}");
    query_var(req, "policy", policy_str, sizeof policy_str);
    return send_snapshot(conn, _stricmp(policy_str, "block") == 0 ? SNAP_APPS_BLOCKED : SNAP_APPS);
}

static int h_rules(struct mg_connection *conn, void *cbdata)
{
    const struct mg_request_info *req = mg_get_request_info(conn);
    const char *id = sub_path(req, "/api/rules");
    enum { BODY_CAP = 128 * 1024 };
    char *body;
    int ok;
    (void)cbdata;

    if (!*id && !is_method(req, "POST")) return send_snapshot(conn, SNAP_RULES);
    body = malloc(BODY_CAP);
    if (!body) return api_send_json(conn, 503, "{\"error\":\"Out of memory\"}");

    if (*id && is_method(req, "DELETE")) {
        free(body);
        return engine_rule_delete(id) ? api_send_json(conn, 200, "{\"ok\":true}")
                                      : api_send_json(conn, 404, "{\"error\":\"No such rule\"}");
    }
    read_body(conn, body, BODY_CAP);
    ok = *id ? engine_rule_patch(id, body) : engine_rule_create(body);
    free(body);
    if (ok) return api_send_json(conn, 200, "{\"ok\":true}");
    return *id ? api_send_json(conn, 404, "{\"error\":\"No such rule\"}")
               : api_send_json(conn, 507, "{\"error\":\"The rule table is full\"}");
}

static int h_metrics(struct mg_connection *conn, void *cbdata)
{
    (void)cbdata;
    return send_snapshot(conn, SNAP_METRICS);
}

static int h_settings(struct mg_connection *conn, void *cbdata)
{
    const struct mg_request_info *req = mg_get_request_info(conn);
    char body[4096];
    (void)cbdata;

    if (is_method(req, "PATCH") || is_method(req, "POST")) {
        read_body(conn, body, sizeof body);
        engine_settings_patch(body);
    }
    return send_snapshot(conn, SNAP_SETTINGS);
}

static int h_logs(struct mg_connection *conn, void *cbdata)
{
    const struct mg_request_info *req = mg_get_request_info(conn);
    char since[32];
    char *buf;
    size_t n;
    (void)cbdata;

    query_var(req, "since", since, sizeof since);
    buf = (char *)malloc(RENDER_BUF);
    if (!buf) return api_send_json(conn, 500, "{\"error\":\"Out of memory\"}");
    n = engine_render_logs(_atoi64(since), buf, RENDER_BUF);
    send_body(conn, 0, buf, n);
    free(buf);
    return 200;
}

static int h_usage(struct mg_connection *conn, void *cbdata)
{
    const struct mg_request_info *req = mg_get_request_info(conn);
    char days[16];
    int text = wants_text(conn);
    char *buf;
    size_t n;
    (void)cbdata;

    query_var(req, "days", days, sizeof days);
    buf = (char *)malloc(RENDER_BUF);
    if (!buf) return api_send_json(conn, 500, "{\"error\":\"Out of memory\"}");
    n = engine_render_usage(days[0] ? atoi(days) : 7, text, buf, RENDER_BUF);
    send_body(conn, text, buf, n);
    free(buf);
    return 200;
}

static int h_devices(struct mg_connection *conn, void *cbdata)
{
    const struct mg_request_info *req = mg_get_request_info(conn);
    char mac[32], name[96];
    (void)cbdata;

    if (is_method(req, "PATCH") || is_method(req, "POST")) {
        query_var(req, "mac", mac, sizeof mac);
        query_var(req, "name", name, sizeof name);
        return engine_device_rename(mac, name) ? api_send_json(conn, 200, "{\"ok\":true}")
                                               : api_send_json(conn, 404, "{\"error\":\"No such device\"}");
    }
    return send_render(conn, engine_render_devices);
}

static int h_alerts(struct mg_connection *conn, void *cbdata)
{
    const struct mg_request_info *req = mg_get_request_info(conn);
    const char *sub = sub_path(req, "/api/alerts");
    (void)cbdata;

    if (!strcmp(sub, "read") && is_method(req, "POST")) {
        engine_alerts_read();
        return api_send_json(conn, 200, "{\"ok\":true}");
    }
    if (!*sub && is_method(req, "DELETE")) {
        engine_alerts_clear();
        return api_send_json(conn, 200, "{\"ok\":true}");
    }
    return send_render(conn, engine_render_alerts);
}

static int h_dns(struct mg_connection *conn, void *cbdata)
{
    const struct mg_request_info *req = mg_get_request_info(conn);
    const char *sub = sub_path(req, "/api/dns");
    char domain[160], reply[96];
    (void)cbdata;

    if (!strcmp(sub, "block")) {
        query_var(req, "domain", domain, sizeof domain);
        if (is_method(req, "DELETE")) {
            return engine_dns_block(domain, 0) ? api_send_json(conn, 200, "{\"ok\":true}")
                                               : api_send_json(conn, 404, "{\"error\":\"That domain is not on the blocklist\"}");
        }
        return engine_dns_block(domain, 1) ? api_send_json(conn, 200, "{\"ok\":true}")
                                           : api_send_json(conn, 400, "{\"error\":\"The domain is already listed or is not valid\"}");
    }
    if (!strcmp(sub, "import") && is_method(req, "POST")) {
        char *body = (char *)malloc(IMPORT_MAX);
        int added;
        if (!body) return api_send_json(conn, 500, "{\"error\":\"Out of memory\"}");
        read_body(conn, body, IMPORT_MAX);
        added = engine_dns_import(body);
        free(body);
        _snprintf_s(reply, sizeof reply, _TRUNCATE, "{\"ok\":true,\"added\":%d}", added);
        return api_send_json(conn, 200, reply);
    }
    return send_render(conn, engine_render_dns);
}

static void plain_json(char *out, size_t cap, const char *in)
{
    size_t n = 0;
    for (; *in && n + 2 < cap; in++) {
        if (*in == '"' || *in == '\\') continue;
        out[n++] = *in;
    }
    out[n] = '\0';
}

static int h_status(struct mg_connection *conn, void *cbdata)
{
    const struct mg_request_info *req = mg_get_request_info(conn);
    char body[1400], reason[160], dns_reason[160], r1[160], r2[160], posture[32] = {0};
    int enforcing, dns;
    (void)cbdata;

    if (is_method(req, "PUT") || is_method(req, "POST")) {
        query_var(req, "posture", posture, sizeof posture);
        if (!posture[0]) {
            char rb[256];
            read_body(conn, rb, sizeof rb);
            if (strstr(rb, "lockdown")) strcpy_s(posture, sizeof posture, "lockdown");
            else if (strstr(rb, "\"off\"")) strcpy_s(posture, sizeof posture, "off");
            else if (strstr(rb, "\"on\"")) strcpy_s(posture, sizeof posture, "on");
        }
        if (!engine_set_posture(posture)) {
            return api_send_json(conn, 400, "{\"error\":\"Posture must be on, off or lockdown\"}");
        }
    }

    enforcing = engine_enforcement(reason, sizeof reason);
    dns = engine_dns_state(dns_reason, sizeof dns_reason);
    plain_json(r1, sizeof r1, reason);
    plain_json(r2, sizeof r2, dns_reason);
    _snprintf_s(body, sizeof body, _TRUNCATE,
                "{\"engine\":\"online\",\"posture\":\"%s\",\"version\":\"%s\",\"platform\":\"%s\","
                "\"port\":%d,\"pid\":%lu,\"headless\":%s,\"service\":%s,"
                "\"keepRunningInBackground\":%s,\"elevated\":%s,\"notifications\":%s,"
                "\"enforcement\":\"%s\",\"enforcementReason\":\"%s\",\"dns\":\"%s\",\"dnsReason\":\"%s\"}",
                engine_posture(), WIRECEE_VERSION, plat_os(), g_port, plat_pid(),
                g_hooks.headless ? "true" : "false", g_hooks.service ? "true" : "false",
                engine_keep_running() ? "true" : "false", plat_is_admin() ? "true" : "false",
                plat_notifications_enabled() ? "true" : "false",
                enforcing ? "active" : "unavailable", r1, dns ? "active" : "off", r2);
    return api_send_json(conn, 200, body);
}

static int h_quit(struct mg_connection *conn, void *cbdata)
{
    (void)cbdata;
    if (g_hooks.quit) g_hooks.quit();
    return api_send_json(conn, 200, "{\"ok\":true,\"stopping\":true}");
}

static int h_window(struct mg_connection *conn, void *cbdata)
{
    const struct mg_request_info *req = mg_get_request_info(conn);
    (void)cbdata;
    if (!g_hooks.window) return api_send_json(conn, 404, "{\"error\":\"No window\"}");
    return g_hooks.window(conn, sub_path(req, "/api/window"), req->query_string ? req->query_string : "");
}

struct mg_context *api_start(int port, const char *app_root, const ApiHooks *hooks)
{
    struct mg_context *ctx;
    struct mg_callbacks callbacks;
    char listen_spec[32];

    const char *options[] = {
        "document_root", app_root,
        "listening_ports", listen_spec,
        "enable_directory_listing", "no",
        "num_threads", "8",
        "access_control_list", "-0.0.0.0/0,+127.0.0.1",
        "tcp_nodelay", "1",
        "enable_keep_alive", "yes",
        "keep_alive_timeout_ms", "10000",
        "static_file_cache_control", "no-cache",
        NULL
    };

    memset(&callbacks, 0, sizeof callbacks);
    if (hooks) g_hooks = *hooks;
    g_port = port;
    _snprintf_s(listen_spec, sizeof listen_spec, _TRUNCATE, "127.0.0.1:%d", port);

    ctx = mg_start(&callbacks, NULL, options);
    if (!ctx) return NULL;

    mg_set_request_handler(ctx, "/api/status", h_status, NULL);
    mg_set_request_handler(ctx, "/api/metrics", h_metrics, NULL);
    mg_set_request_handler(ctx, "/api/connections", h_connections, NULL);
    mg_set_request_handler(ctx, "/api/apps", h_apps, NULL);
    mg_set_request_handler(ctx, "/api/rules", h_rules, NULL);
    mg_set_request_handler(ctx, "/api/settings", h_settings, NULL);
    mg_set_request_handler(ctx, "/api/logs", h_logs, NULL);
    mg_set_request_handler(ctx, "/api/usage", h_usage, NULL);
    mg_set_request_handler(ctx, "/api/devices", h_devices, NULL);
    mg_set_request_handler(ctx, "/api/alerts", h_alerts, NULL);
    mg_set_request_handler(ctx, "/api/dns", h_dns, NULL);
    mg_set_request_handler(ctx, "/api/window", h_window, NULL);
    mg_set_request_handler(ctx, "/api/quit", h_quit, NULL);
    return ctx;
}

void api_stop(struct mg_context *ctx)
{
    if (ctx) mg_stop(ctx);
}
