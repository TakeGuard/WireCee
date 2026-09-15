#ifndef WIRECEE_DNSD_H
#define WIRECEE_DNSD_H

#include "compat.h"

#define DNSD_NAME 128

int dnsd_start(char *reason, size_t cap);
void dnsd_stop(void);
int dnsd_active(void);

void dnsd_set_upstreams(char servers[][46], int count);
void dnsd_set_enforce(int on);
void dnsd_set_log_allowed(int on);
void dnsd_stats(unsigned long long *queries, unsigned long long *blocked);

int dnsd_is_blocked(const char *name);
int dnsd_block_add(const char *domain);
int dnsd_block_remove(const char *domain);
int dnsd_block_count(void);
int dnsd_block_import(const char *text);
void dnsd_block_each(int (*fn)(const char *domain, void *ctx), void *ctx);
int dnsd_block_load(const char *path);
int dnsd_block_save(const char *path);

#endif
