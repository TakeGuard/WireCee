#ifndef WIRECEE_HOSTMAP_H
#define WIRECEE_HOSTMAP_H

#include "compat.h"

#define HOSTMAP_NAME 128
#define DNSLOG_CAP 300

enum { DNSLOG_ALLOWED = 0, DNSLOG_BLOCKED = 1, DNSLOG_FAILED = 2 };

typedef struct {
    unsigned long id;
    long long ts;
    unsigned long pid;
    int qtype;
    int status;
    char name[HOSTMAP_NAME];
    char answer[46];
} DnsLogEntry;

void hostmap_init(void);

void hostmap_put(const char *ip, const char *name);
int hostmap_get(const char *ip, char *out, size_t cap);

void dnslog_add(unsigned long pid, const char *name, int qtype, int status, const char *answer);
int dnslog_copy(DnsLogEntry *out, int cap);

#endif
