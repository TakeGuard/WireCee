#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <initguid.h>
#include <fwpmu.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "fw.h"

static const GUID WIRECEE_SUBLAYER = {
    0x6a1b3c2d, 0x8e4f, 0x4b7a, {0x9c, 0x31, 0x2d, 0x5e, 0x7f, 0x10, 0xa4, 0xb8}};

#define W_LOOPBACK  0xF000000000000000ULL
#define W_SELF      0xEE00000000000000ULL
#define W_GUARD     0xEC00000000000000ULL
#define W_APP_BLOCK 0xE800000000000000ULL
#define W_RULE      0xE000000000000000ULL
#define W_ESSENTIAL 0x3000000000000000ULL
#define W_APP_ALLOW 0x2000000000000000ULL
#define W_DEFAULT   0x1000000000000000ULL

static const char *const DOH_V4[] = {
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
    "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10",
    "9.9.9.11", "149.112.112.11", "94.140.14.14", "94.140.15.15", "208.67.222.222",
    "208.67.220.220", "185.228.168.9", "185.228.169.9", "194.242.2.2", "76.76.2.0",
    "76.76.10.0", NULL};
static const char *const DOH_V6[] = {
    "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888",
    "2001:4860:4860::8844", "2620:fe::fe", "2620:fe::9", "2a10:50c0::ad1:ff",
    "2a10:50c0::ad2:ff", "2620:119:35::35", "2620:119:53::53", NULL};

static HANDLE g_engine = NULL;
static HANDLE g_events = NULL;
static int g_restore_collection = 0;

static CRITICAL_SECTION g_apply_lock;
static CRITICAL_SECTION g_state_lock;
static int g_locks_ready = 0;

typedef struct {
    UINT64 id;
    int block;
    FwDirection dir;
    int rule;
} FilterRec;

#define MAX_FILTERS 16384
static FilterRec g_filters[MAX_FILTERS];
static int g_filter_count = 0;
static FilterRec g_pending[MAX_FILTERS];
static int g_pending_count = 0;

static int compare_filters(const void *a, const void *b)
{
    UINT64 x = ((const FilterRec *)a)->id, y = ((const FilterRec *)b)->id;
    return x < y ? -1 : x > y;
}

static int find_filter(UINT64 id)
{
    int lo = 0, hi = g_filter_count - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (g_filters[mid].id == id) return mid;
        if (g_filters[mid].id < id) lo = mid + 1;
        else hi = mid - 1;
    }
    return -1;
}

#define MAX_RULE_IDS 128
static int g_current_rule = -1;
static char g_rule_ids[MAX_RULE_IDS][16];
static char g_pending_rule_ids[MAX_RULE_IDS][16];

#define DROP_CAP 512
static FwDrop g_drops[DROP_CAP];
static int g_drop_head = 0;
static int g_drop_count = 0;

typedef struct {
    wchar_t device[MAX_PATH];
    size_t len;
    wchar_t drive[3];
} DriveMap;
static DriveMap g_drives[26];
static int g_drive_count = 0;

static const GUID *const OUT_LAYERS[2] = {&FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                                          &FWPM_LAYER_ALE_AUTH_CONNECT_V6};
static const GUID *const IN_LAYERS[2] = {&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                                         &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6};

static void build_drive_map(void)
{
    wchar_t letter[3] = L"A:";
    int i;

    g_drive_count = 0;
    for (i = 0; i < 26; i++) {
        DriveMap *d = &g_drives[g_drive_count];
        letter[0] = (wchar_t)(L'A' + i);
        if (QueryDosDeviceW(letter, d->device, MAX_PATH)) {
            d->len = wcslen(d->device);
            wcscpy_s(d->drive, 3, letter);
            g_drive_count++;
        }
    }
}

static void device_to_dos(const wchar_t *device, char *out, size_t cap)
{
    wchar_t full[MAX_PATH * 2];
    int i;

    for (i = 0; i < g_drive_count; i++) {
        const DriveMap *d = &g_drives[i];
        if (_wcsnicmp(device, d->device, d->len) == 0 && device[d->len] == L'\\') {
            _snwprintf_s(full, _countof(full), _TRUNCATE, L"%s%s", d->drive, device + d->len);
            WideCharToMultiByte(CP_ACP, 0, full, -1, out, (int)cap, NULL, NULL);
            return;
        }
    }
    WideCharToMultiByte(CP_ACP, 0, device, -1, out, (int)cap, NULL, NULL);
}

static void CALLBACK on_net_event(void *context, const FWPM_NET_EVENT1 *ev)
{
    const FWPM_NET_EVENT_HEADER1 *h;
    FwDrop drop;
    FwDirection dir = FW_OUT;
    int i, ours = 0;
    char rule_id[16] = {0};
    (void)context;

    if (!ev || ev->type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP || !ev->classifyDrop) return;

    EnterCriticalSection(&g_state_lock);
    i = find_filter(ev->classifyDrop->filterId);
    if (i >= 0 && g_filters[i].block) {
        ours = 1;
        dir = g_filters[i].dir;
        if (g_filters[i].rule >= 0) strcpy_s(rule_id, sizeof rule_id, g_rule_ids[g_filters[i].rule]);
    }
    LeaveCriticalSection(&g_state_lock);
    if (!ours) return;

    memset(&drop, 0, sizeof drop);
    h = &ev->header;
    drop.direction = dir;
    strcpy_s(drop.rule_id, sizeof drop.rule_id, rule_id);
    drop.count = 1;

    if ((h->flags & FWPM_NET_EVENT_FLAG_APP_ID_SET) && h->appId.data && h->appId.size >= 2) {
        wchar_t device[MAX_PATH];
        size_t chars = h->appId.size / sizeof(wchar_t);
        if (chars >= MAX_PATH) chars = MAX_PATH - 1;
        wmemcpy(device, (const wchar_t *)h->appId.data, chars);
        device[chars] = L'\0';
        device_to_dos(device, drop.app_path, sizeof drop.app_path);
    }

    if (h->flags & FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET) {
        if (h->ipVersion == FWP_IP_VERSION_V4) {
            IN_ADDR addr;
            addr.S_un.S_addr = htonl(h->remoteAddrV4);
            inet_ntop(AF_INET, &addr, drop.remote_ip, sizeof drop.remote_ip);
        } else if (h->ipVersion == FWP_IP_VERSION_V6) {
            inet_ntop(AF_INET6, h->remoteAddrV6.byteArray16, drop.remote_ip,
                      sizeof drop.remote_ip);
        }
    }
    if (h->flags & FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET) drop.remote_port = h->remotePort;
    if (h->flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET) drop.protocol = h->ipProtocol;

    EnterCriticalSection(&g_state_lock);
    g_drops[(g_drop_head + g_drop_count) % DROP_CAP] = drop;
    if (g_drop_count < DROP_CAP) {
        g_drop_count++;
    } else {
        g_drop_head = (g_drop_head + 1) % DROP_CAP;
    }
    LeaveCriticalSection(&g_state_lock);
}

int fw_take_drops(FwDrop *out, int cap)
{
    int n = 0;

    if (!g_locks_ready) return 0;
    EnterCriticalSection(&g_state_lock);
    while (g_drop_count > 0 && n < cap) {
        out[n++] = g_drops[g_drop_head];
        g_drop_head = (g_drop_head + 1) % DROP_CAP;
        g_drop_count--;
    }
    LeaveCriticalSection(&g_state_lock);
    return n;
}

static int is_access_denied(DWORD rc)
{
    return rc == ERROR_ACCESS_DENIED || rc == (DWORD)E_ACCESSDENIED;
}

int fw_start(char *reason, size_t cap)
{
    FWPM_SESSION0 session;
    FWPM_SUBLAYER0 sublayer;
    DWORD rc;

    if (!g_locks_ready) {
        InitializeCriticalSection(&g_apply_lock);
        InitializeCriticalSection(&g_state_lock);
        g_locks_ready = 1;
    }
    if (g_engine) return 1;

    memset(&session, 0, sizeof session);
    session.displayData.name = L"WireCee";
    session.displayData.description = L"WireCee firewall engine";
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    rc = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_engine);
    if (rc != ERROR_SUCCESS) {
        g_engine = NULL;
        if (is_access_denied(rc)) {
            _snprintf_s(reason, cap, _TRUNCATE, "Blocking needs administrator rights");
        } else {
            _snprintf_s(reason, cap, _TRUNCATE,
                        "Could not open the Windows Filtering Platform (0x%08lx)", rc);
        }
        return 0;
    }

    memset(&sublayer, 0, sizeof sublayer);
    sublayer.subLayerKey = WIRECEE_SUBLAYER;
    sublayer.displayData.name = L"WireCee rules";
    sublayer.weight = 0x7FFF;
    rc = FwpmSubLayerAdd0(g_engine, &sublayer, NULL);
    if (rc != ERROR_SUCCESS) {
        FwpmEngineClose0(g_engine);
        g_engine = NULL;
        if (is_access_denied(rc)) {
            _snprintf_s(reason, cap, _TRUNCATE, "Blocking needs administrator rights");
        } else {
            _snprintf_s(reason, cap, _TRUNCATE, "Could not add the WireCee sublayer (0x%08lx)", rc);
        }
        return 0;
    }

    build_drive_map();

    {
        FWP_VALUE0 *current = NULL;
        FWPM_NET_EVENT_ENUM_TEMPLATE0 tmpl;
        FWPM_NET_EVENT_SUBSCRIPTION0 sub;

        if (FwpmEngineGetOption0(g_engine, FWPM_ENGINE_COLLECT_NET_EVENTS, &current) ==
                ERROR_SUCCESS && current) {
            if (current->type == FWP_UINT32 && current->uint32 == 0) {
                FWP_VALUE0 on;
                memset(&on, 0, sizeof on);
                on.type = FWP_UINT32;
                on.uint32 = 1;
                if (FwpmEngineSetOption0(g_engine, FWPM_ENGINE_COLLECT_NET_EVENTS, &on) ==
                    ERROR_SUCCESS) {
                    g_restore_collection = 1;
                }
            }
            FwpmFreeMemory0((void **)&current);
        }

        memset(&tmpl, 0, sizeof tmpl);
        memset(&sub, 0, sizeof sub);
        sub.enumTemplate = &tmpl;
        if (FwpmNetEventSubscribe0(g_engine, &sub, on_net_event, NULL, &g_events) !=
            ERROR_SUCCESS) {
            g_events = NULL;
        }
    }

    return 1;
}

void fw_stop(void)
{
    if (!g_engine) return;

    if (g_events) {
        FwpmNetEventUnsubscribe0(g_engine, g_events);
        g_events = NULL;
    }
    if (g_restore_collection) {
        FWP_VALUE0 off;
        memset(&off, 0, sizeof off);
        off.type = FWP_UINT32;
        off.uint32 = 0;
        FwpmEngineSetOption0(g_engine, FWPM_ENGINE_COLLECT_NET_EVENTS, &off);
        g_restore_collection = 0;
    }

    FwpmEngineClose0(g_engine);
    g_engine = NULL;

    EnterCriticalSection(&g_state_lock);
    g_filter_count = 0;
    LeaveCriticalSection(&g_state_lock);
}

int fw_active(void)
{
    return g_engine != NULL;
}

typedef struct {
    FWPM_FILTER_CONDITION0 c[6];
    UINT32 n;
    FWP_V4_ADDR_AND_MASK v4;
    FWP_V6_ADDR_AND_MASK v6;
} Conds;

static void cond_loopback(Conds *k)
{
    FWPM_FILTER_CONDITION0 *c = &k->c[k->n++];
    c->fieldKey = FWPM_CONDITION_FLAGS;
    c->matchType = FWP_MATCH_FLAGS_ALL_SET;
    c->conditionValue.type = FWP_UINT32;
    c->conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
}

static void cond_app(Conds *k, FWP_BYTE_BLOB *app)
{
    FWPM_FILTER_CONDITION0 *c = &k->c[k->n++];
    c->fieldKey = FWPM_CONDITION_ALE_APP_ID;
    c->matchType = FWP_MATCH_EQUAL;
    c->conditionValue.type = FWP_BYTE_BLOB_TYPE;
    c->conditionValue.byteBlob = app;
}

static void cond_port(Conds *k, FwDirection dir, UINT16 port)
{
    FWPM_FILTER_CONDITION0 *c = &k->c[k->n++];
    c->fieldKey = dir == FW_OUT ? FWPM_CONDITION_IP_REMOTE_PORT : FWPM_CONDITION_IP_LOCAL_PORT;
    c->matchType = FWP_MATCH_EQUAL;
    c->conditionValue.type = FWP_UINT16;
    c->conditionValue.uint16 = port;
}

static void cond_proto(Conds *k, UINT8 proto)
{
    FWPM_FILTER_CONDITION0 *c = &k->c[k->n++];
    c->fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    c->matchType = FWP_MATCH_EQUAL;
    c->conditionValue.type = FWP_UINT8;
    c->conditionValue.uint8 = proto;
}

static void cond_v4(Conds *k, UINT32 addr, UINT32 mask)
{
    FWPM_FILTER_CONDITION0 *c = &k->c[k->n++];
    k->v4.addr = addr;
    k->v4.mask = mask;
    c->fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    c->matchType = FWP_MATCH_EQUAL;
    c->conditionValue.type = FWP_V4_ADDR_MASK;
    c->conditionValue.v4AddrMask = &k->v4;
}

static void cond_v6(Conds *k, const UINT8 *addr, UINT8 prefix)
{
    FWPM_FILTER_CONDITION0 *c = &k->c[k->n++];
    memcpy(k->v6.addr, addr, 16);
    k->v6.prefixLength = prefix;
    c->fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    c->matchType = FWP_MATCH_EQUAL;
    c->conditionValue.type = FWP_V6_ADDR_MASK;
    c->conditionValue.v6AddrMask = &k->v6;
}

static DWORD add_filter(const GUID *layer, FWP_ACTION_TYPE action, UINT64 weight,
                        Conds *k, FwDirection dir)
{
    FWPM_FILTER0 f;
    UINT64 id = 0;
    UINT64 w = weight;
    DWORD rc;

    if (g_pending_count >= MAX_FILTERS) return ERROR_NOT_ENOUGH_MEMORY;

    memset(&f, 0, sizeof f);
    f.layerKey = *layer;
    f.subLayerKey = WIRECEE_SUBLAYER;
    f.displayData.name = L"WireCee";
    f.action.type = action;
    f.weight.type = FWP_UINT64;
    f.weight.uint64 = &w;
    f.numFilterConditions = k ? k->n : 0;
    f.filterCondition = k && k->n ? k->c : NULL;

    rc = FwpmFilterAdd0(g_engine, &f, NULL, &id);
    if (rc == ERROR_SUCCESS) {
        g_pending[g_pending_count].id = id;
        g_pending[g_pending_count].block = action == FWP_ACTION_BLOCK;
        g_pending[g_pending_count].dir = dir;
        g_pending[g_pending_count].rule = g_current_rule;
        g_pending_count++;
    }
    return rc;
}

static DWORD add_both(FwDirection dir, FWP_ACTION_TYPE action, UINT64 weight, const Conds *k)
{
    const GUID *const *layers = dir == FW_OUT ? OUT_LAYERS : IN_LAYERS;
    DWORD rc;
    int i;

    for (i = 0; i < 2; i++) {
        Conds copy;
        if (k) {
            copy = *k;
            if (copy.n) {
                UINT32 j;
                for (j = 0; j < copy.n; j++) {
                    if (copy.c[j].conditionValue.type == FWP_V4_ADDR_MASK) {
                        copy.c[j].conditionValue.v4AddrMask = &copy.v4;
                    } else if (copy.c[j].conditionValue.type == FWP_V6_ADDR_MASK) {
                        copy.c[j].conditionValue.v6AddrMask = &copy.v6;
                    }
                }
            }
        }
        rc = add_filter(layers[i], action, weight, k ? &copy : NULL, dir);
        if (rc != ERROR_SUCCESS) return rc;
    }
    return ERROR_SUCCESS;
}

static int parse_v4(const char *text, UINT32 *addr, UINT32 *mask)
{
    char buf[64];
    char *slash;
    IN_ADDR in;
    int bits = 32;

    strncpy_s(buf, sizeof buf, text, _TRUNCATE);
    slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        bits = atoi(slash + 1);
        if (bits < 0 || bits > 32) return 0;
    }
    if (inet_pton(AF_INET, buf, &in) != 1) return 0;

    *mask = bits == 0 ? 0 : (0xFFFFFFFFUL << (32 - bits));
    *addr = ntohl(in.S_un.S_addr) & *mask;
    return 1;
}

static int parse_v6(const char *text, UINT8 *addr, UINT8 *prefix)
{
    char buf[64];
    char *slash;
    IN6_ADDR in;
    int bits = 128;

    strncpy_s(buf, sizeof buf, text, _TRUNCATE);
    slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        bits = atoi(slash + 1);
        if (bits < 0 || bits > 128) return 0;
    }
    if (inet_pton(AF_INET6, buf, &in) != 1) return 0;
    memcpy(addr, in.u.Byte, 16);
    *prefix = (UINT8)bits;
    return 1;
}

static int is_any(const char *s)
{
    return !s[0] || _stricmp(s, "any") == 0 || strcmp(s, "*") == 0;
}

static int add_rule_one(const FwRule *r, const char *remote, UINT64 weight, DWORD *rc)
{
    FWP_ACTION_TYPE action = _stricmp(r->action, "allow") == 0 ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
    int want_out = _stricmp(r->direction, "in") != 0;
    int want_in = _stricmp(r->direction, "out") != 0;
    int family = 0, port = 0, d;
    UINT8 proto = 0, addr6[16], prefix6 = 0;
    UINT32 addr = 0, mask = 0;

    if (!is_any(remote)) {
        if (parse_v4(remote, &addr, &mask)) family = 4;
        else if (parse_v6(remote, addr6, &prefix6)) family = 6;
        else return 0;
    }
    if (!is_any(r->port)) {
        port = atoi(r->port);
        if (port < 1 || port > 65535) return 0;
    }
    if (_stricmp(r->proto, "TCP") == 0) proto = IPPROTO_TCP;
    else if (_stricmp(r->proto, "UDP") == 0) proto = IPPROTO_UDP;

    for (d = 0; d < 2; d++) {
        FwDirection dir = d == 0 ? FW_OUT : FW_IN;
        Conds k;
        const GUID *const *layers;
        int i;

        if (dir == FW_OUT && !want_out) continue;
        if (dir == FW_IN && !want_in) continue;

        memset(&k, 0, sizeof k);
        if (proto) cond_proto(&k, proto);
        if (port) cond_port(&k, dir, (UINT16)port);

        layers = dir == FW_OUT ? OUT_LAYERS : IN_LAYERS;
        for (i = 0; i < 2; i++) {
            Conds per = k;
            if (family == 4) {
                if (i == 1) continue;
                cond_v4(&per, addr, mask);
            } else if (family == 6) {
                if (i == 0) continue;
                cond_v6(&per, addr6, prefix6);
            }
            *rc = add_filter(layers[i], action, weight, &per, dir);
            if (*rc != ERROR_SUCCESS) return 0;
        }
    }
    return 1;
}

static int add_rule(const FwRule *r, UINT64 weight, DWORD *rc)
{
    const char *p = r->remote;
    int installed = 0;

    if (is_any(p)) return add_rule_one(r, "any", weight, rc);
    while (*p) {
        char one[64];
        size_t len = strcspn(p, ",");
        if (len && len < sizeof one) {
            memcpy(one, p, len);
            one[len] = '\0';
            if (add_rule_one(r, one, weight, rc)) installed = 1;
            else if (*rc != ERROR_SUCCESS) return 0;
        }
        p += len;
        if (*p == ',') p++;
    }
    return installed;
}

static int to_wide(const char *in, wchar_t *out, int cap)
{
    return MultiByteToWideChar(CP_ACP, 0, in, -1, out, cap) > 0;
}

int fw_apply(const FwPolicy *p, char *detail, size_t cap)
{
    int lockdown, default_out_block, default_in_block;
    int i, skipped = 0, result = -1;
    DWORD rc = ERROR_SUCCESS;
    Conds k;

    if (!g_engine) {
        _snprintf_s(detail, cap, _TRUNCATE, "Enforcement is not running");
        return -1;
    }

    EnterCriticalSection(&g_apply_lock);

    rc = FwpmTransactionBegin0(g_engine, 0);
    if (rc != ERROR_SUCCESS) {
        _snprintf_s(detail, cap, _TRUNCATE, "Could not start a filter transaction (0x%08lx)", rc);
        LeaveCriticalSection(&g_apply_lock);
        return -1;
    }

    EnterCriticalSection(&g_state_lock);
    for (i = 0; i < g_filter_count; i++) FwpmFilterDeleteById0(g_engine, g_filters[i].id);
    LeaveCriticalSection(&g_state_lock);
    g_pending_count = 0;

    if (_stricmp(p->posture, "off") == 0) goto commit;

    lockdown = _stricmp(p->posture, "lockdown") == 0;
    default_out_block = lockdown || _stricmp(p->default_out, "allow") != 0;
    default_in_block = lockdown || _stricmp(p->default_in, "allow") != 0;

    memset(&k, 0, sizeof k);
    cond_loopback(&k);
    if ((rc = add_both(FW_OUT, FWP_ACTION_PERMIT, W_LOOPBACK, &k)) != ERROR_SUCCESS) goto fail;
    if ((rc = add_both(FW_IN, FWP_ACTION_PERMIT, W_LOOPBACK, &k)) != ERROR_SUCCESS) goto fail;

    if (p->dns_guard) {
        wchar_t self[MAX_PATH];
        FWP_BYTE_BLOB *blob = NULL;
        if (GetModuleFileNameW(NULL, self, MAX_PATH) &&
            FwpmGetAppIdFromFileName0(self, &blob) == ERROR_SUCCESS) {
            memset(&k, 0, sizeof k);
            cond_app(&k, blob);
            cond_port(&k, FW_OUT, 53);
            rc = add_both(FW_OUT, FWP_ACTION_PERMIT, W_SELF, &k);
            FwpmFreeMemory0((void **)&blob);
            if (rc != ERROR_SUCCESS) goto fail;
        }
        memset(&k, 0, sizeof k);
        cond_port(&k, FW_OUT, 53);
        if ((rc = add_both(FW_OUT, FWP_ACTION_BLOCK, W_GUARD, &k)) != ERROR_SUCCESS) goto fail;
    }

    if (p->block_encrypted_dns) {
        memset(&k, 0, sizeof k);
        cond_port(&k, FW_OUT, 853);
        if ((rc = add_both(FW_OUT, FWP_ACTION_BLOCK, W_GUARD, &k)) != ERROR_SUCCESS) goto fail;
        for (i = 0; DOH_V4[i]; i++) {
            UINT32 addr, mask;
            if (!parse_v4(DOH_V4[i], &addr, &mask)) continue;
            memset(&k, 0, sizeof k);
            cond_port(&k, FW_OUT, 443);
            cond_v4(&k, addr, mask);
            rc = add_filter(&FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_BLOCK, W_GUARD, &k, FW_OUT);
            if (rc != ERROR_SUCCESS) goto fail;
        }
        for (i = 0; DOH_V6[i]; i++) {
            UINT8 addr6[16], prefix6;
            memset(&k, 0, sizeof k);
            if (!parse_v6(DOH_V6[i], addr6, &prefix6)) continue;
            cond_port(&k, FW_OUT, 443);
            cond_v6(&k, addr6, prefix6);
            rc = add_filter(&FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWP_ACTION_BLOCK, W_GUARD, &k, FW_OUT);
            if (rc != ERROR_SUCCESS) goto fail;
        }
    }

    for (i = 0; i < p->app_count; i++) {
        const FwApp *a = &p->apps[i];
        wchar_t wpath[MAX_PATH];
        FWP_BYTE_BLOB *blob = NULL;

        if (!a->block) continue;
        if (!to_wide(a->path, wpath, MAX_PATH) ||
            FwpmGetAppIdFromFileName0(wpath, &blob) != ERROR_SUCCESS) {
            skipped++;
            continue;
        }
        memset(&k, 0, sizeof k);
        cond_app(&k, blob);
        rc = add_both(FW_OUT, FWP_ACTION_BLOCK, W_APP_BLOCK, &k);
        if (rc == ERROR_SUCCESS) rc = add_both(FW_IN, FWP_ACTION_BLOCK, W_APP_BLOCK, &k);
        FwpmFreeMemory0((void **)&blob);
        if (rc != ERROR_SUCCESS) goto fail;
    }

    for (i = 0; i < p->rule_count && i < MAX_RULE_IDS; i++) {
        strcpy_s(g_pending_rule_ids[i], sizeof g_pending_rule_ids[i], p->rules[i].id);
        g_current_rule = i;
        if (!add_rule(&p->rules[i], W_RULE - (UINT64)i, &rc)) {
            g_current_rule = -1;
            if (rc != ERROR_SUCCESS) goto fail;
            skipped++;
        }
        g_current_rule = -1;
    }

    if (default_out_block || default_in_block) {
        memset(&k, 0, sizeof k);
        cond_port(&k, FW_OUT, 53);
        if ((rc = add_both(FW_OUT, FWP_ACTION_PERMIT, W_ESSENTIAL, &k)) != ERROR_SUCCESS) goto fail;
        memset(&k, 0, sizeof k);
        cond_proto(&k, IPPROTO_UDP);
        cond_port(&k, FW_OUT, 67);
        if ((rc = add_both(FW_OUT, FWP_ACTION_PERMIT, W_ESSENTIAL, &k)) != ERROR_SUCCESS) goto fail;
        memset(&k, 0, sizeof k);
        cond_proto(&k, IPPROTO_UDP);
        cond_port(&k, FW_IN, 68);
        if ((rc = add_both(FW_IN, FWP_ACTION_PERMIT, W_ESSENTIAL, &k)) != ERROR_SUCCESS) goto fail;
    }

    if (!lockdown && (default_out_block || default_in_block)) {
        for (i = 0; i < p->app_count; i++) {
            const FwApp *a = &p->apps[i];
            wchar_t wpath[MAX_PATH];
            FWP_BYTE_BLOB *blob = NULL;

            if (!a->allow) continue;
            if (!to_wide(a->path, wpath, MAX_PATH) ||
                FwpmGetAppIdFromFileName0(wpath, &blob) != ERROR_SUCCESS) {
                continue;
            }
            memset(&k, 0, sizeof k);
            cond_app(&k, blob);
            rc = ERROR_SUCCESS;
            if (default_out_block) rc = add_both(FW_OUT, FWP_ACTION_PERMIT, W_APP_ALLOW, &k);
            if (rc == ERROR_SUCCESS && default_in_block)
                rc = add_both(FW_IN, FWP_ACTION_PERMIT, W_APP_ALLOW, &k);
            FwpmFreeMemory0((void **)&blob);
            if (rc != ERROR_SUCCESS) goto fail;
        }
    }

    if (default_out_block &&
        (rc = add_both(FW_OUT, FWP_ACTION_BLOCK, W_DEFAULT, NULL)) != ERROR_SUCCESS) goto fail;
    if (default_in_block &&
        (rc = add_both(FW_IN, FWP_ACTION_BLOCK, W_DEFAULT, NULL)) != ERROR_SUCCESS) goto fail;

commit:
    rc = FwpmTransactionCommit0(g_engine);
    if (rc != ERROR_SUCCESS) goto fail_uncommitted;

    EnterCriticalSection(&g_state_lock);
    memcpy(g_filters, g_pending, sizeof(FilterRec) * (size_t)g_pending_count);
    qsort(g_filters, (size_t)g_pending_count, sizeof(FilterRec), compare_filters);
    memcpy(g_rule_ids, g_pending_rule_ids, sizeof g_rule_ids);
    g_filter_count = g_pending_count;
    LeaveCriticalSection(&g_state_lock);

    if (skipped) {
        _snprintf_s(detail, cap, _TRUNCATE, "%d filters installed, %d entr%s could not be expressed",
                    g_pending_count, skipped, skipped == 1 ? "y" : "ies");
    } else {
        _snprintf_s(detail, cap, _TRUNCATE, "%d filters installed", g_pending_count);
    }
    result = g_pending_count;
    LeaveCriticalSection(&g_apply_lock);
    return result;

fail:
    FwpmTransactionAbort0(g_engine);
fail_uncommitted:
    _snprintf_s(detail, cap, _TRUNCATE, "Could not install filters (0x%08lx); previous policy kept", rc);
    g_pending_count = 0;
    LeaveCriticalSection(&g_apply_lock);
    return -1;
}

void fw_tick(void)
{
}
