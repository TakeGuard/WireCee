#ifndef WIRECEE_PLATFORM_H
#define WIRECEE_PLATFORM_H

#include "compat.h"

#ifndef _WIN32
#include <pthread.h>
#endif

#ifdef _WIN32
typedef SRWLOCK plat_rwlock;
#define plat_rw_init(l) InitializeSRWLock(l)
#define plat_rw_read(l) AcquireSRWLockShared(l)
#define plat_rw_read_end(l) ReleaseSRWLockShared(l)
#define plat_rw_write(l) AcquireSRWLockExclusive(l)
#define plat_rw_write_end(l) ReleaseSRWLockExclusive(l)

typedef CRITICAL_SECTION plat_mutex;
#define plat_mutex_init(m) InitializeCriticalSection(m)
#define plat_mutex_lock(m) EnterCriticalSection(m)
#define plat_mutex_unlock(m) LeaveCriticalSection(m)

typedef LONG plat_flag;
#define plat_flag_set(f, v) InterlockedExchange((f), (v))
#define plat_flag_get(f) InterlockedCompareExchange((f), 0, 0)
#else
typedef pthread_rwlock_t plat_rwlock;
#define plat_rw_init(l) pthread_rwlock_init((l), NULL)
#define plat_rw_read(l) pthread_rwlock_rdlock(l)
#define plat_rw_read_end(l) pthread_rwlock_unlock(l)
#define plat_rw_write(l) pthread_rwlock_wrlock(l)
#define plat_rw_write_end(l) pthread_rwlock_unlock(l)

typedef pthread_mutex_t plat_mutex;
#define plat_mutex_init(m) do { pthread_mutexattr_t a_; pthread_mutexattr_init(&a_); \
    pthread_mutexattr_settype(&a_, PTHREAD_MUTEX_RECURSIVE); pthread_mutex_init((m), &a_); } while (0)
#define plat_mutex_lock(m) pthread_mutex_lock(m)
#define plat_mutex_unlock(m) pthread_mutex_unlock(m)

typedef long plat_flag;
#define plat_flag_set(f, v) __sync_lock_test_and_set((f), (v))
#define plat_flag_get(f) __sync_val_compare_and_swap((f), 0, 0)
#endif

typedef struct plat_thread_s *plat_thread;

plat_thread plat_thread_start(void (*fn)(void *), void *arg);
void plat_thread_join(plat_thread t, int timeout_ms);
void plat_sleep_ms(int ms);

typedef struct {
    int year, month, day, hour, minute, second;
} PlatTime;

void plat_init(void);
long long plat_now_ms(void);
void plat_local_time(PlatTime *t);
unsigned long plat_pid(void);
int plat_is_admin(void);
int plat_self_exe(char *out, size_t cap);
const char *plat_os(void);

int plat_data_path(const char *sub, const char *file, char *out, size_t cap);

int plat_file_stat(const char *path, long long *size, long long *mtime);
int plat_replace_file(const char *from, const char *to);

FILE *plat_fopen_shared(const char *path, const char *mode);
void plat_prune_files(const char *sub, const char *suffix, int days);

int plat_run(const char *command);

int plat_startup_exists(void);
int plat_startup_set(int enable);

int plat_hosts_file(char *out, size_t cap);
int plat_proxy_signature(char *out, size_t cap);
int plat_remote_access_port(void);

int plat_notifications_enabled(void);

int plat_dns_servers(char out[][46], int cap);

int plat_dns_redirect_begin(char *reason, size_t cap);
void plat_dns_redirect_end(void);
int plat_dns_redirect_recover(void);
int plat_dns_upstreams(char out[][46], int cap);
void plat_dns_flush(void);

typedef struct {
    char ip[46];
    char mac[18];
    int gateway;
} PlatNeighbor;

int plat_neighbors(PlatNeighbor *out, int cap);

#endif
