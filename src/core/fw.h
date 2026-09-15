#ifndef WIRECEE_FW_H
#define WIRECEE_FW_H

#include "compat.h"

#define FW_REMOTE_CAP 32768

typedef enum { FW_OUT = 0, FW_IN = 1 } FwDirection;

typedef struct {
    char path[MAX_PATH];
    int block;
    int allow;
} FwApp;

typedef struct {
    char id[16];
    char action[8];
    char direction[8];
    char remote[FW_REMOTE_CAP];
    char port[16];
    char proto[8];
} FwRule;

typedef struct {
    char posture[12];
    char default_out[8];
    char default_in[8];
    const FwApp *apps;
    int app_count;
    const FwRule *rules;
    int rule_count;
    int dns_guard;
    int block_encrypted_dns;
} FwPolicy;

typedef struct {
    char app_path[MAX_PATH];
    char remote_ip[46];
    int remote_port;
    int protocol;
    FwDirection direction;
    char rule_id[16];
    int count;
} FwDrop;

int fw_start(char *reason, size_t cap);
void fw_stop(void);
int fw_active(void);

int fw_apply(const FwPolicy *policy, char *detail, size_t cap);

int fw_take_drops(FwDrop *out, int cap);

void fw_tick(void);

#endif
