#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <iphlpapi.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "flows.h"
#include "hostmap.h"
#include "dnsd.h"

#define SESSION_NAME L"WireCee Network Trace"

#define IDLE_EVICT_MS 30000

static const GUID UDPIP_GUID = {0xbf3a50c5, 0xa9c9, 0x4988, {0xa0, 0x05, 0x2d, 0xf0, 0xb7, 0xc8, 0x0f, 0x80}};

static const GUID SESSION_GUID = {0x3c1e8b52, 0x6f0d, 0x4e4b, {0x9d, 0x1a, 0x5a, 0x7c, 0x2e, 0x9f, 0x0b, 0x64}};

#pragma pack(push, 1)
typedef struct {
    ULONG pid;
    ULONG size;
    ULONG daddr;
    ULONG saddr;
    USHORT dport;
    USHORT sport;
} UdpV4;

typedef struct {
    ULONG pid;
    ULONG size;
    UCHAR daddr[16];
    UCHAR saddr[16];
    USHORT dport;
    USHORT sport;
} UdpV6;
#pragma pack(pop)

typedef struct {
    int used;
    int family;
    UCHAR remote[16];
    USHORT remote_port;
    USHORT local_port;
    DWORD pid;
    unsigned long long rx, tx;
    ULONGLONG first, last;
} Entry;

#define TABLE_SIZE 4096
static Entry g_table[TABLE_SIZE];
static Entry g_keep[TABLE_SIZE];
static int g_used = 0;
static CRITICAL_SECTION g_lock;
static int g_lock_ready = 0;

static TRACEHANDLE g_session = 0;
static TRACEHANDLE g_trace = INVALID_PROCESSTRACE_HANDLE;
static HANDLE g_thread = NULL;

typedef struct {
    EVENT_TRACE_PROPERTIES p;
    wchar_t name[128];
} TraceProps;

static void props_init(TraceProps *t)
{
    memset(t, 0, sizeof *t);
    t->p.Wnode.BufferSize = sizeof *t;
    t->p.Wnode.Guid = SESSION_GUID;
    t->p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    t->p.Wnode.ClientContext = 1;
    t->p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    t->p.EnableFlags = EVENT_TRACE_FLAG_NETWORK_TCPIP;
    t->p.FlushTimer = 1;
    t->p.BufferSize = 256;
    t->p.MinimumBuffers = 4;
    t->p.MaximumBuffers = 64;
    t->p.LoggerNameOffset = offsetof(TraceProps, name);
}

static unsigned hash_key(int family, const UCHAR *remote, USHORT rport, USHORT lport)
{
    unsigned h = 2166136261u;
    int i, len = family == AF_INET6 ? 16 : 4;
    for (i = 0; i < len; i++) h = (h ^ remote[i]) * 16777619u;
    h = (h ^ rport) * 16777619u;
    h = (h ^ lport) * 16777619u;
    return h;
}

static Entry *lookup(int family, const UCHAR *remote, USHORT rport, USHORT lport, int create)
{
    unsigned i = hash_key(family, remote, rport, lport) & (TABLE_SIZE - 1);
    int len = family == AF_INET6 ? 16 : 4;
    int probes;

    for (probes = 0; probes < TABLE_SIZE; probes++, i = (i + 1) & (TABLE_SIZE - 1)) {
        Entry *e = &g_table[i];
        if (!e->used) {
            if (!create || g_used >= TABLE_SIZE * 3 / 4) return NULL;
            memset(e, 0, sizeof *e);
            e->used = 1;
            e->family = family;
            memcpy(e->remote, remote, (size_t)len);
            e->remote_port = rport;
            e->local_port = lport;
            g_used++;
            return e;
        }
        if (e->family == family && e->remote_port == rport && e->local_port == lport &&
            memcmp(e->remote, remote, (size_t)len) == 0) {
            return e;
        }
    }
    return NULL;
}

static void WINAPI on_event(PEVENT_RECORD ev)
{
    UCHAR op = ev->EventHeader.EventDescriptor.Opcode;
    UCHAR remote[16];
    USHORT rport, lport;
    ULONG pid, size;
    int family, recv;
    Entry *e;

    if (!IsEqualGUID(&ev->EventHeader.ProviderId, &UDPIP_GUID)) return;

    switch (op) {
        case 10: family = AF_INET;  recv = 0; break;
        case 11: family = AF_INET;  recv = 1; break;
        case 26: family = AF_INET6; recv = 0; break;
        case 27: family = AF_INET6; recv = 1; break;
        default: return;
    }

    memset(remote, 0, sizeof remote);
    if (family == AF_INET) {
        const UdpV4 *d = (const UdpV4 *)ev->UserData;
        if (ev->UserDataLength < sizeof *d) return;
        if ((d->daddr & 0xff) == 127) return;
        memcpy(remote, &d->daddr, 4);
        rport = ntohs(d->dport);
        lport = ntohs(d->sport);
        pid = d->pid;
        size = d->size;
    } else {
        static const UCHAR loop6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        const UdpV6 *d = (const UdpV6 *)ev->UserData;
        if (ev->UserDataLength < sizeof *d) return;
        if (memcmp(d->daddr, loop6, 16) == 0) return;
        memcpy(remote, d->daddr, 16);
        rport = ntohs(d->dport);
        lport = ntohs(d->sport);
        pid = d->pid;
        size = d->size;
    }

    EnterCriticalSection(&g_lock);
    e = lookup(family, remote, rport, lport, 1);
    if (e) {
        ULONGLONG now = GetTickCount64();
        if (!e->first) e->first = now;
        e->last = now;
        if (pid != 0 && pid != 4) e->pid = pid;
        else if (!e->pid) e->pid = pid;
        if (recv) e->rx += size;
        else e->tx += size;
    }
    LeaveCriticalSection(&g_lock);
}

static DWORD WINAPI trace_thread(LPVOID param)
{
    (void)param;
    ProcessTrace(&g_trace, 1, NULL, NULL);
    return 0;
}

#define DNS_SESSION_NAME L"WireCee DNS Trace"

static const GUID DNSCLIENT_GUID = {0x1c95126e, 0x7eea, 0x49a9, {0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d}};
static const GUID DNS_SESSION_GUID = {0x6b0e2a71, 0x3d4c, 0x4f1e, {0x8a, 0x52, 0x1f, 0x9c, 0x3e, 0x7b, 0x2d, 0x10}};

static TRACEHANDLE g_dns_session = 0;
static TRACEHANDLE g_dns_trace = INVALID_PROCESSTRACE_HANDLE;
static HANDLE g_dns_thread = NULL;

static void dns_props_init(TraceProps *t)
{
    memset(t, 0, sizeof *t);
    t->p.Wnode.BufferSize = sizeof *t;
    t->p.Wnode.Guid = DNS_SESSION_GUID;
    t->p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    t->p.Wnode.ClientContext = 1;
    t->p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    t->p.FlushTimer = 1;
    t->p.BufferSize = 64;
    t->p.MinimumBuffers = 2;
    t->p.MaximumBuffers = 16;
    t->p.LoggerNameOffset = offsetof(TraceProps, name);
}

static void wide_to_utf8(const wchar_t *w, size_t len, char *out, int cap)
{
    int n = WideCharToMultiByte(CP_UTF8, 0, w, (int)len, out, cap - 1, NULL, NULL);
    out[n > 0 ? n : 0] = '\0';
}

static void WINAPI on_dns_event(PEVENT_RECORD ev)
{
    const BYTE *p, *end;
    size_t chars, name_len, results_len;
    UINT32 qtype, status;
    char name[256], results[2048], answer[46] = "", *tok, *ctx = NULL;
    int code, i;

    if (!IsEqualGUID(&ev->EventHeader.ProviderId, &DNSCLIENT_GUID)) return;
    if (ev->EventHeader.EventDescriptor.Id != 3008) return;
    if (ev->EventHeader.ProcessId == GetCurrentProcessId()) return;

    p = (const BYTE *)ev->UserData;
    end = p + ev->UserDataLength;
    chars = (size_t)(end - p) / 2;
    name_len = wcsnlen((const wchar_t *)p, chars);
    if (name_len == 0 || name_len >= chars) return;
    wide_to_utf8((const wchar_t *)p, name_len, name, sizeof name);
    p += (name_len + 1) * 2;
    if (end - p < 16) return;
    memcpy(&qtype, p, 4);
    memcpy(&status, p + 12, 4);
    p += 16;
    if (qtype == 12) return;

    for (i = 0; name[i]; i++) if (name[i] >= 'A' && name[i] <= 'Z') name[i] = (char)(name[i] - 'A' + 'a');

    results[0] = '\0';
    if (end > p) {
        chars = (size_t)(end - p) / 2;
        results_len = wcsnlen((const wchar_t *)p, chars);
        wide_to_utf8((const wchar_t *)p, results_len, results, sizeof results);
    }
    for (tok = strtok_s(results, ";", &ctx); tok; tok = strtok_s(NULL, ";", &ctx)) {
        unsigned char buf[16];
        while (*tok == ' ') tok++;
        if (!_strnicmp(tok, "type:", 5)) continue;
        if (!_strnicmp(tok, "::ffff:", 7) && strchr(tok + 7, '.')) tok += 7;
        if (inet_pton(AF_INET, tok, buf) != 1 && inet_pton(AF_INET6, tok, buf) != 1) continue;
        hostmap_put(tok, name);
        if (!answer[0]) strcpy_s(answer, sizeof answer, tok);
    }

    if (status == 0) code = DNSLOG_ALLOWED;
    else code = dnsd_active() && dnsd_is_blocked(name) ? DNSLOG_BLOCKED : DNSLOG_FAILED;
    dnslog_add(ev->EventHeader.ProcessId, name, (int)qtype, code, answer);
}

static DWORD WINAPI dns_thread(LPVOID param)
{
    (void)param;
    ProcessTrace(&g_dns_trace, 1, NULL, NULL);
    return 0;
}

static void dns_trace_stop(void)
{
    TraceProps t;
    if (g_dns_trace != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_dns_trace);
        g_dns_trace = INVALID_PROCESSTRACE_HANDLE;
    }
    if (g_dns_session) {
        dns_props_init(&t);
        ControlTraceW(g_dns_session, NULL, &t.p, EVENT_TRACE_CONTROL_STOP);
        g_dns_session = 0;
    }
    if (g_dns_thread) {
        WaitForSingleObject(g_dns_thread, 3000);
        CloseHandle(g_dns_thread);
        g_dns_thread = NULL;
    }
}

static int dns_trace_start(void)
{
    TraceProps t;
    EVENT_TRACE_LOGFILEW log;
    ULONG rc;

    dns_props_init(&t);
    rc = StartTraceW(&g_dns_session, DNS_SESSION_NAME, &t.p);
    if (rc == ERROR_ALREADY_EXISTS) {
        dns_props_init(&t);
        ControlTraceW(0, DNS_SESSION_NAME, &t.p, EVENT_TRACE_CONTROL_STOP);
        dns_props_init(&t);
        rc = StartTraceW(&g_dns_session, DNS_SESSION_NAME, &t.p);
    }
    if (rc != ERROR_SUCCESS) {
        g_dns_session = 0;
        return 0;
    }
    rc = EnableTraceEx2(g_dns_session, &DNSCLIENT_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);
    if (rc != ERROR_SUCCESS) {
        dns_trace_stop();
        return 0;
    }

    memset(&log, 0, sizeof log);
    log.LoggerName = DNS_SESSION_NAME;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = on_dns_event;
    g_dns_trace = OpenTraceW(&log);
    if (g_dns_trace == INVALID_PROCESSTRACE_HANDLE) {
        dns_trace_stop();
        return 0;
    }
    g_dns_thread = CreateThread(NULL, 0, dns_thread, NULL, 0, NULL);
    if (!g_dns_thread) {
        dns_trace_stop();
        return 0;
    }
    return 1;
}

int flows_dns_names(void)
{
    return g_dns_thread != NULL;
}

int flows_start(char *reason, size_t cap)
{
    TraceProps t;
    EVENT_TRACE_LOGFILEW log;
    ULONG rc;

    if (!g_lock_ready) {
        InitializeCriticalSection(&g_lock);
        g_lock_ready = 1;
    }
    if (g_thread) return 1;

    props_init(&t);
    rc = StartTraceW(&g_session, SESSION_NAME, &t.p);
    if (rc == ERROR_ALREADY_EXISTS) {
        props_init(&t);
        ControlTraceW(0, SESSION_NAME, &t.p, EVENT_TRACE_CONTROL_STOP);
        props_init(&t);
        rc = StartTraceW(&g_session, SESSION_NAME, &t.p);
    }
    if (rc != ERROR_SUCCESS) {
        g_session = 0;
        if (rc == ERROR_ACCESS_DENIED) {
            _snprintf_s(reason, cap, _TRUNCATE, "Reading UDP traffic requires administrator rights");
        } else {
            _snprintf_s(reason, cap, _TRUNCATE, "could not start the network trace (error %lu)", rc);
        }
        return 0;
    }

    memset(&log, 0, sizeof log);
    log.LoggerName = SESSION_NAME;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = on_event;
    g_trace = OpenTraceW(&log);
    if (g_trace == INVALID_PROCESSTRACE_HANDLE) {
        _snprintf_s(reason, cap, _TRUNCATE, "could not open the network trace (error %lu)", GetLastError());
        props_init(&t);
        ControlTraceW(g_session, NULL, &t.p, EVENT_TRACE_CONTROL_STOP);
        g_session = 0;
        return 0;
    }

    g_thread = CreateThread(NULL, 0, trace_thread, NULL, 0, NULL);
    if (!g_thread) {
        _snprintf_s(reason, cap, _TRUNCATE, "could not start the trace thread");
        flows_stop();
        return 0;
    }
    dns_trace_start();
    return 1;
}

void flows_stop(void)
{
    TraceProps t;

    dns_trace_stop();

    if (g_trace != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_trace);
        g_trace = INVALID_PROCESSTRACE_HANDLE;
    }
    if (g_session) {
        props_init(&t);
        ControlTraceW(g_session, NULL, &t.p, EVENT_TRACE_CONTROL_STOP);
        g_session = 0;
    }
    if (g_thread) {
        WaitForSingleObject(g_thread, 3000);
        CloseHandle(g_thread);
        g_thread = NULL;
    }
}

static DWORD udp_owner(int family, int port)
{
    DWORD size = 0, pid = 0, i;
    void *table;

    if (GetExtendedUdpTable(NULL, &size, FALSE, family, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER)
        return 0;
    table = malloc(size);
    if (!table) return 0;
    if (GetExtendedUdpTable(table, &size, FALSE, family, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        if (family == AF_INET) {
            MIB_UDPTABLE_OWNER_PID *t = (MIB_UDPTABLE_OWNER_PID *)table;
            for (i = 0; i < t->dwNumEntries; i++) {
                if (ntohs((u_short)t->table[i].dwLocalPort) == port) { pid = t->table[i].dwOwningPid; break; }
            }
        } else {
            MIB_UDP6TABLE_OWNER_PID *t = (MIB_UDP6TABLE_OWNER_PID *)table;
            for (i = 0; i < t->dwNumEntries; i++) {
                if (ntohs((u_short)t->table[i].dwLocalPort) == port) { pid = t->table[i].dwOwningPid; break; }
            }
        }
    }
    free(table);
    return pid;
}

int flows_copy(Flow *out, int cap)
{
    ULONGLONG now = GetTickCount64();
    int i, kept = 0, n = 0;

    if (!g_lock_ready) return 0;

    EnterCriticalSection(&g_lock);
    for (i = 0; i < TABLE_SIZE; i++) {
        if (g_table[i].used && now - g_table[i].last < IDLE_EVICT_MS) g_keep[kept++] = g_table[i];
    }
    memset(g_table, 0, sizeof g_table);
    g_used = 0;
    for (i = 0; i < kept; i++) {
        Entry *src = &g_keep[i];
        Entry *e = lookup(src->family, src->remote, src->remote_port, src->local_port, 1);
        if (e) *e = *src;
    }
    for (i = 0; i < kept && n < cap; i++) {
        const Entry *e = &g_keep[i];
        Flow *f = &out[n++];
        memset(f, 0, sizeof *f);
        f->family = e->family;
        f->pid = e->pid;
        f->local_port = e->local_port;
        f->remote_port = e->remote_port;
        inet_ntop(e->family, e->remote, f->remote_ip, sizeof f->remote_ip);
        f->rx = e->rx;
        f->tx = e->tx;
        f->age_ms = (long long)(now - e->first);
        f->idle_ms = (long long)(now - e->last);
    }
    LeaveCriticalSection(&g_lock);

    for (i = 0; i < n; i++) {
        if (out[i].pid == 0 || out[i].pid == 4) {
            DWORD owner = udp_owner(out[i].family, out[i].local_port);
            if (owner) out[i].pid = owner;
        }
    }
    return n;
}
