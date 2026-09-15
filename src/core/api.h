#ifndef WIRECEE_API_H
#define WIRECEE_API_H

#include "compat.h"
#include "civetweb.h"

typedef struct {
    int (*icon)(struct mg_connection *conn, const char *name);
    int (*window)(struct mg_connection *conn, const char *action, const char *query);
    void (*quit)(void);
    int headless;
    int service;
} ApiHooks;

struct mg_context *api_start(int port, const char *app_root, const ApiHooks *hooks);
void api_stop(struct mg_context *ctx);

int api_send_json(struct mg_connection *conn, int status, const char *body);

#endif
