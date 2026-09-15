#ifndef WIRECEE_ENGINE_H
#define WIRECEE_ENGINE_H

#include "compat.h"

#define ENG_MAX_APPS 256
#define ENG_MAX_CONNS 512
#define ENG_MAX_RULES 128
#define ENG_MAX_LOGS 512

typedef enum { POLICY_ALLOW = 0, POLICY_ASK = 1, POLICY_BLOCK = 2 } Policy;

const char *policy_name(Policy p);
int policy_parse(const char *s, Policy *out);

typedef struct {
    char *json;
    size_t json_len;
    char *text;
    size_t text_len;
    unsigned generation;
    char etag[32];
} Snapshot;

typedef enum {
    SNAP_CONNECTIONS = 0,
    SNAP_APPS,
    SNAP_APPS_BLOCKED,
    SNAP_RULES,
    SNAP_METRICS,
    SNAP_SETTINGS,
    SNAP_COUNT
} SnapKind;

void engine_start(void);
void engine_stop(void);

const Snapshot *engine_acquire(SnapKind kind);
void engine_release(void);

int engine_set_policy(const char *name, Policy policy);

int engine_rule_create(const char *json_body);
int engine_rule_patch(const char *id, const char *json_body);
int engine_rule_delete(const char *id);

int engine_kill_connection(const char *id);

int engine_settings_patch(const char *json_body);

size_t engine_render_logs(long long since, char *out, size_t cap);
size_t engine_render_usage(int days, int text, char *out, size_t cap);
size_t engine_render_devices(int text, char *out, size_t cap);
size_t engine_render_alerts(int text, char *out, size_t cap);
size_t engine_render_dns(int text, char *out, size_t cap);

int engine_device_rename(const char *mac, const char *name);
void engine_alerts_read(void);
void engine_alerts_clear(void);

int engine_dns_block(const char *domain, int add);
int engine_dns_import(const char *text);

const char *engine_posture(void);
int engine_set_posture(const char *posture);

int engine_keep_running(void);

int engine_enforcement(char *reason, size_t cap);
int engine_dns_state(char *reason, size_t cap);

void engine_log(const char *level, const char *fmt, ...);

int engine_take_block_notice(char *out, size_t cap, int *suppressed);

int engine_take_notice(char *title, size_t tcap, char *body, size_t bcap);

int engine_app_path(const char *name, char *out, size_t cap);

#endif
