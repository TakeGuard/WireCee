#ifndef WIRECEE_FLOWS_H
#define WIRECEE_FLOWS_H

#include "compat.h"

typedef struct {
    int family;
    unsigned long pid;
    int local_port;
    char remote_ip[46];
    int remote_port;
    unsigned long long rx, tx;
    long long age_ms;
    long long idle_ms;
} Flow;

int flows_start(char *reason, size_t cap);
void flows_stop(void);

int flows_copy(Flow *out, int cap);

int flows_dns_names(void);

#endif
