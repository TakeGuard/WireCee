#ifndef WIRECEE_CLI_H
#define WIRECEE_CLI_H

#include "compat.h"
#include "engine.h"
#include "version.h"

#include <stdio.h>

extern int g_color;
extern int g_quiet;

const char *C(const char *ansi);
void cw_log(FILE *stream, const char *color, const char *sigil, const char *fmt, ...);
void cw_rule(void);

#define OKAY(MSG, ...) cw_log(stdout, C("\033[1;92m"), "+", MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) cw_log(stdout, C("\033[1;33m"), "*", MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) cw_log(stderr, C("\033[1;91m"), "-", MSG "\n", ##__VA_ARGS__)
#define LINE() cw_rule()

#define PORT_MIN 30000
#define PORT_MAX 31000

typedef enum {
    RUN_APP,
    RUN_HELP,
    RUN_VERSION,
    RUN_STATUS,
    RUN_STOP,

    RUN_CONNECTIONS,
    RUN_APPS,
    RUN_RULES,
    RUN_SETTINGS,
    RUN_METRICS,
    RUN_POLICY,
    RUN_USAGE,
    RUN_DEVICES,
    RUN_ALERTS,
    RUN_DNS,
    RUN_DNS_BLOCK,
    RUN_DNS_UNBLOCK,

    RUN_SERVICE,
    RUN_SVC_INSTALL,
    RUN_SVC_UNINSTALL,
    RUN_SVC_START,
    RUN_SVC_STOP,
    RUN_SVC_STATUS
} RunMode;

typedef struct {
    RunMode mode;
    int port;
    int headless;
    int open_browser;
    int json;
    int verbose;
    int blocked_only;
    int no_elevate;
    int elevated_relaunch;
    int days;
    Policy policy;
    char target[160];
} Options;

int cli_parse_args(int argc, char **argv, Options *opt);
void cli_print_usage(void);

int cli_run(const Options *opt);

void instance_write(int port);
void instance_clear(void);
int instance_read(void);

int http_call(int port, const char *method, const char *path, const char *accept,
              char *body_out, size_t body_len, int *status_out);
int pick_port(int requested);

#endif
