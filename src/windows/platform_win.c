#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000008
#endif

#include "platform.h"

#include <iphlpapi.h>
#include <shlobj.h>
#include <objbase.h>
#include <share.h>

#include <time.h>

struct plat_thread_s {
    HANDLE handle;
    void (*fn)(void *);
    void *arg;
};

static DWORD WINAPI thread_entry(LPVOID param)
{
    struct plat_thread_s *t = (struct plat_thread_s *)param;
    t->fn(t->arg);
    return 0;
}

plat_thread plat_thread_start(void (*fn)(void *), void *arg)
{
    struct plat_thread_s *t = (struct plat_thread_s *)calloc(1, sizeof *t);
    if (!t) return NULL;
    t->fn = fn;
    t->arg = arg;
    t->handle = CreateThread(NULL, 0, thread_entry, t, 0, NULL);
    if (!t->handle) {
        free(t);
        return NULL;
    }
    return t;
}

void plat_thread_join(plat_thread t, int timeout_ms)
{
    if (!t) return;
    if (WaitForSingleObject(t->handle, (DWORD)timeout_ms) == WAIT_OBJECT_0) {
        CloseHandle(t->handle);
        free(t);
    } else {
        CloseHandle(t->handle);
    }
}

void plat_sleep_ms(int ms) { Sleep((DWORD)ms); }

void plat_init(void)
{
    static int done = 0;
    WSADATA wsa;
    if (done) return;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    done = 1;
}

long long plat_now_ms(void)
{
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return (long long)(u.QuadPart / 10000ULL) - 11644473600000LL;
}

void plat_local_time(PlatTime *t)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    t->year = st.wYear;
    t->month = st.wMonth;
    t->day = st.wDay;
    t->hour = st.wHour;
    t->minute = st.wMinute;
    t->second = st.wSecond;
}

unsigned long plat_pid(void) { return GetCurrentProcessId(); }

const char *plat_os(void) { return "windows"; }

int plat_is_admin(void)
{
    HANDLE token = NULL;
    TOKEN_ELEVATION elevation;
    DWORD size = sizeof elevation;
    int elevated = 0;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        if (GetTokenInformation(token, TokenElevation, &elevation, size, &size)) {
            elevated = elevation.TokenIsElevated != 0;
        }
        CloseHandle(token);
    }
    return elevated;
}

int plat_self_exe(char *out, size_t cap)
{
    return GetModuleFileNameA(NULL, out, (DWORD)cap) > 0;
}

int plat_data_path(const char *sub, const char *file, char *out, size_t cap)
{
    char base[MAX_PATH], dir[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("WIRECEE_DATA_DIR", base, sizeof base);

    if (n > 0 && n < sizeof base) {
        if (sub && *sub) _snprintf_s(dir, sizeof dir, _TRUNCATE, "%s\\%s", base, sub);
        else strcpy_s(dir, sizeof dir, base);
    } else {
        if (!SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, base))) return 0;
        if (sub && *sub) _snprintf_s(dir, sizeof dir, _TRUNCATE, "%s\\TakeGuard\\WireCee\\%s", base, sub);
        else _snprintf_s(dir, sizeof dir, _TRUNCATE, "%s\\TakeGuard\\WireCee", base);
    }
    SHCreateDirectoryExA(NULL, dir, NULL);
    _snprintf_s(out, cap, _TRUNCATE, "%s\\%s", dir, file);
    return 1;
}

int plat_file_stat(const char *path, long long *size, long long *mtime)
{
    WIN32_FILE_ATTRIBUTE_DATA data;
    ULARGE_INTEGER u;

    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &data)) return 0;
    if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return 0;
    if (size) *size = ((long long)data.nFileSizeHigh << 32) | data.nFileSizeLow;
    if (mtime) {
        u.LowPart = data.ftLastWriteTime.dwLowDateTime;
        u.HighPart = data.ftLastWriteTime.dwHighDateTime;
        *mtime = (long long)(u.QuadPart / 10000ULL) - 11644473600000LL;
    }
    return 1;
}

int plat_replace_file(const char *from, const char *to)
{
    return MoveFileExA(from, to, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
}

FILE *plat_fopen_shared(const char *path, const char *mode)
{
    return _fsopen(path, mode, _SH_DENYNO);
}

void plat_prune_files(const char *sub, const char *suffix, int days)
{
    char pattern[MAX_PATH], path[MAX_PATH], mask[32];
    WIN32_FIND_DATAA fd;
    FILETIME now;
    ULARGE_INTEGER cutoff;
    HANDLE h;

    if (days < 1) days = 1;
    _snprintf_s(mask, sizeof mask, _TRUNCATE, "*%s", suffix);
    if (!plat_data_path(sub, mask, pattern, sizeof pattern)) return;

    GetSystemTimeAsFileTime(&now);
    cutoff.LowPart = now.dwLowDateTime;
    cutoff.HighPart = now.dwHighDateTime;
    cutoff.QuadPart -= (ULONGLONG)days * 24ULL * 3600ULL * 10000000ULL;

    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        ULARGE_INTEGER written;
        written.LowPart = fd.ftLastWriteTime.dwLowDateTime;
        written.HighPart = fd.ftLastWriteTime.dwHighDateTime;
        if (written.QuadPart < cutoff.QuadPart && plat_data_path(sub, fd.cFileName, path, sizeof path)) {
            DeleteFileA(path);
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

int plat_run(const char *command)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char buf[2048];
    DWORD code = 1;

    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    strncpy_s(buf, sizeof buf, command, _TRUNCATE);
    if (!CreateProcessA(NULL, buf, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return -1;
    WaitForSingleObject(pi.hProcess, 15000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (int)code;
}

#define STARTUP_TASK "TakeGuard\\WireCee"

int plat_startup_exists(void)
{
    return plat_run("schtasks.exe /query /tn \"" STARTUP_TASK "\"") == 0;
}

int plat_startup_set(int enable)
{
    char exe[MAX_PATH], command[1024];

    if (!enable) return plat_run("schtasks.exe /delete /f /tn \"" STARTUP_TASK "\"") == 0;

    GetModuleFileNameA(NULL, exe, sizeof exe);
    _snprintf_s(command, sizeof command, _TRUNCATE,
                "schtasks.exe /create /f /tn \"" STARTUP_TASK "\" /sc onlogon /rl highest "
                "/tr \"\\\"%s\\\" --headless\"", exe);
    return plat_run(command) == 0;
}

int plat_hosts_file(char *out, size_t cap)
{
    char root[MAX_PATH];
    if (GetEnvironmentVariableA("WIRECEE_HOSTS_FILE", out, (DWORD)cap)) return 1;
    if (!GetEnvironmentVariableA("SystemRoot", root, sizeof root)) strcpy_s(root, sizeof root, "C:\\Windows");
    _snprintf_s(out, cap, _TRUNCATE, "%s\\System32\\drivers\\etc\\hosts", root);
    return 1;
}

int plat_proxy_signature(char *out, size_t cap)
{
    static const char *key = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    DWORD enable = 0, size = sizeof enable;
    char server[512] = "", pac[512] = "";
    DWORD ssize = sizeof server, psize = sizeof pac;

    RegGetValueA(HKEY_CURRENT_USER, key, "ProxyEnable", RRF_RT_REG_DWORD, NULL, &enable, &size);
    RegGetValueA(HKEY_CURRENT_USER, key, "ProxyServer", RRF_RT_REG_SZ, NULL, server, &ssize);
    RegGetValueA(HKEY_CURRENT_USER, key, "AutoConfigURL", RRF_RT_REG_SZ, NULL, pac, &psize);
    _snprintf_s(out, cap, _TRUNCATE, "%s%s%s%s",
                enable ? "Proxy " : "", enable ? server : "", pac[0] ? " PAC " : "", pac);
    return 1;
}

int plat_remote_access_port(void) { return 3389; }

int plat_notifications_enabled(void)
{
    DWORD enabled = 1, size = sizeof enabled;
    RegGetValueA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PushNotifications",
                 "ToastEnabled", RRF_RT_REG_DWORD, NULL, &enabled, &size);
    return enabled != 0;
}

#define MAX_ADAPTERS 16

typedef struct {
    GUID guid;
    char guid_text[64];
    wchar_t v4[512];
    wchar_t v6[512];
} DnsBackup;

static DnsBackup g_backup[MAX_ADAPTERS];
static int g_backup_count = 0;
static char g_upstreams[8][46];
static int g_upstream_count = 0;
static int g_redirected = 0;

static void addr_text(const SOCKADDR *sa, char *out, size_t cap)
{
    out[0] = '\0';
    if (sa->sa_family == AF_INET) {
        inet_ntop(AF_INET, &((const SOCKADDR_IN *)sa)->sin_addr, out, cap);
    } else if (sa->sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &((const SOCKADDR_IN6 *)sa)->sin6_addr, out, cap);
    }
}

static int is_loopback_text(const char *ip)
{
    return !strncmp(ip, "127.", 4) || !strcmp(ip, "::1");
}

static int usable_upstream(const char *ip)
{
    if (!ip[0] || is_loopback_text(ip)) return 0;
    if (!_strnicmp(ip, "fec0:", 5) || !_strnicmp(ip, "fe80:", 5)) return 0;
    return strcmp(ip, "0.0.0.0") != 0 && strcmp(ip, "::") != 0;
}

static IP_ADAPTER_ADDRESSES *read_adapters(void)
{
    ULONG size = 32 * 1024;
    IP_ADAPTER_ADDRESSES *list = NULL;
    int attempt;

    for (attempt = 0; attempt < 3; attempt++) {
        ULONG rc;
        list = (IP_ADAPTER_ADDRESSES *)malloc(size);
        if (!list) return NULL;
        rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                  GAA_FLAG_INCLUDE_GATEWAYS, NULL, list, &size);
        if (rc == NO_ERROR) return list;
        free(list);
        list = NULL;
        if (rc != ERROR_BUFFER_OVERFLOW) break;
    }
    return NULL;
}

static int adapter_eligible(const IP_ADAPTER_ADDRESSES *a)
{
    return a->OperStatus == IfOperStatusUp && a->IfType != IF_TYPE_SOFTWARE_LOOPBACK &&
           (a->FirstGatewayAddress || a->FirstDnsServerAddress);
}

static int collect_upstreams(char out[][46], int cap)
{
    IP_ADAPTER_ADDRESSES *list = read_adapters(), *a;
    int n = 0, pass;

    for (pass = 0; pass < 2 && list; pass++) {
        for (a = list; a && n < cap; a = a->Next) {
            IP_ADAPTER_DNS_SERVER_ADDRESS *d;
            if (!adapter_eligible(a) || !a->FirstGatewayAddress) continue;
            for (d = a->FirstDnsServerAddress; d && n < cap; d = d->Next) {
                char ip[46];
                int i, dup = 0;
                addr_text(d->Address.lpSockaddr, ip, sizeof ip);
                if (!usable_upstream(ip)) continue;
                if ((strchr(ip, ':') != NULL) != (pass == 1)) continue;
                for (i = 0; i < n; i++) if (!strcmp(out[i], ip)) dup = 1;
                if (!dup) strcpy_s(out[n++], 46, ip);
            }
        }
    }
    free(list);
    return n;
}

int plat_dns_servers(char out[][46], int cap)
{
    IP_ADAPTER_ADDRESSES *list = read_adapters(), *a;
    int n = 0;

    for (a = list; a && n < cap; a = a->Next) {
        IP_ADAPTER_DNS_SERVER_ADDRESS *d;
        if (!adapter_eligible(a)) continue;
        for (d = a->FirstDnsServerAddress; d && n < cap; d = d->Next) {
            char ip[46];
            int i, dup = 0;
            addr_text(d->Address.lpSockaddr, ip, sizeof ip);
            if (!ip[0]) continue;
            for (i = 0; i < n; i++) if (!strcmp(out[i], ip)) dup = 1;
            if (!dup) strcpy_s(out[n++], 46, ip);
        }
    }
    free(list);
    return n;
}

static void save_backup_file(void)
{
    char path[MAX_PATH];
    FILE *f = NULL;
    int i;

    if (!plat_data_path(NULL, "dns-backup.tsv", path, sizeof path)) return;
    if (fopen_s(&f, path, "w") != 0 || !f) return;
    for (i = 0; i < g_backup_count; i++) {
        char v4[512], v6[512];
        WideCharToMultiByte(CP_UTF8, 0, g_backup[i].v4, -1, v4, sizeof v4, NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, g_backup[i].v6, -1, v6, sizeof v6, NULL, NULL);
        fprintf(f, "adapter\t%s\t%s\t%s\n", g_backup[i].guid_text, v4[0] ? v4 : "-", v6[0] ? v6 : "-");
    }
    for (i = 0; i < g_upstream_count; i++) fprintf(f, "upstream\t%s\n", g_upstreams[i]);
    fclose(f);
}

static void delete_backup_file(void)
{
    char path[MAX_PATH];
    if (plat_data_path(NULL, "dns-backup.tsv", path, sizeof path)) DeleteFileA(path);
}

static int set_servers(const GUID *guid, int ipv6, const wchar_t *servers)
{
    DNS_INTERFACE_SETTINGS s;
    memset(&s, 0, sizeof s);
    s.Version = DNS_INTERFACE_SETTINGS_VERSION1;
    s.Flags = DNS_SETTING_NAMESERVER | (ipv6 ? DNS_SETTING_IPV6 : 0);
    s.NameServer = (PWSTR)servers;
    return SetInterfaceDnsSettings(*guid, &s) == NO_ERROR;
}

static void get_static_servers(const GUID *guid, int ipv6, wchar_t *out, size_t cap)
{
    DNS_INTERFACE_SETTINGS s;
    memset(&s, 0, sizeof s);
    s.Version = DNS_INTERFACE_SETTINGS_VERSION1;
    s.Flags = ipv6 ? DNS_SETTING_IPV6 : 0;
    out[0] = L'\0';
    if (GetInterfaceDnsSettings(*guid, &s) == NO_ERROR) {
        if (s.NameServer) wcsncpy_s(out, cap, s.NameServer, _TRUNCATE);
        FreeInterfaceDnsSettings(&s);
    }
}

static int guid_from_text(const char *text, GUID *out)
{
    wchar_t wide[64];
    MultiByteToWideChar(CP_ACP, 0, text, -1, wide, 64);
    return SUCCEEDED(CLSIDFromString(wide, out));
}

void plat_dns_flush(void)
{
    plat_run("ipconfig.exe /flushdns");
}

int plat_dns_redirect_begin(char *reason, size_t cap)
{
    IP_ADAPTER_ADDRESSES *list, *a;
    int changed = 0;

    if (g_redirected) return 1;
    list = read_adapters();
    if (!list) {
        _snprintf_s(reason, cap, _TRUNCATE, "Network adapters could not be read");
        return 0;
    }

    g_backup_count = 0;
    g_upstream_count = collect_upstreams(g_upstreams, 8);
    for (a = list; a && g_backup_count < MAX_ADAPTERS; a = a->Next) {
        IP_ADAPTER_DNS_SERVER_ADDRESS *d;
        DnsBackup *b;
        wchar_t fallback4[512] = L"127.0.0.1", fallback6[512] = L"::1";

        if (!adapter_eligible(a)) continue;
        b = &g_backup[g_backup_count];
        memset(b, 0, sizeof *b);
        strcpy_s(b->guid_text, sizeof b->guid_text, a->AdapterName);
        if (!guid_from_text(a->AdapterName, &b->guid)) continue;

        get_static_servers(&b->guid, 0, b->v4, 512);
        get_static_servers(&b->guid, 1, b->v6, 512);

        for (d = a->FirstDnsServerAddress; d; d = d->Next) {
            char ip[46];
            wchar_t wip[46];
            addr_text(d->Address.lpSockaddr, ip, sizeof ip);
            if (!usable_upstream(ip)) continue;
            MultiByteToWideChar(CP_ACP, 0, ip, -1, wip, 46);
            if (strchr(ip, ':')) {
                wcscat_s(fallback6, 512, L",");
                wcscat_s(fallback6, 512, wip);
            } else {
                wcscat_s(fallback4, 512, L",");
                wcscat_s(fallback4, 512, wip);
            }
        }
        g_backup_count++;

        save_backup_file();
        if (set_servers(&b->guid, 0, fallback4)) changed++;
        set_servers(&b->guid, 1, fallback6);
    }
    free(list);

    if (!changed) {
        plat_dns_redirect_end();
        _snprintf_s(reason, cap, _TRUNCATE, "Windows refused to change the DNS server settings");
        return 0;
    }
    save_backup_file();
    g_redirected = 1;
    plat_dns_flush();
    return 1;
}

void plat_dns_redirect_end(void)
{
    int i;
    for (i = 0; i < g_backup_count; i++) {
        set_servers(&g_backup[i].guid, 0, g_backup[i].v4);
        set_servers(&g_backup[i].guid, 1, g_backup[i].v6);
    }
    if (g_backup_count) plat_dns_flush();
    g_backup_count = 0;
    g_redirected = 0;
    delete_backup_file();
}

int plat_dns_redirect_recover(void)
{
    char path[MAX_PATH], line[2048];
    FILE *f = NULL;
    int restored = 0;

    if (!plat_data_path(NULL, "dns-backup.tsv", path, sizeof path)) return 0;
    if (fopen_s(&f, path, "r") != 0 || !f) return 0;

    while (fgets(line, sizeof line, f)) {
        char *ctx = NULL, *kind, *guid_text, *v4, *v6;
        GUID guid;
        wchar_t w4[512], w6[512];

        line[strcspn(line, "\r\n")] = '\0';
        kind = strtok_s(line, "\t", &ctx);
        if (!kind || strcmp(kind, "adapter")) continue;
        guid_text = strtok_s(NULL, "\t", &ctx);
        v4 = strtok_s(NULL, "\t", &ctx);
        v6 = strtok_s(NULL, "\t", &ctx);
        if (!guid_text || !v4 || !v6 || !guid_from_text(guid_text, &guid)) continue;
        MultiByteToWideChar(CP_UTF8, 0, strcmp(v4, "-") ? v4 : "", -1, w4, 512);
        MultiByteToWideChar(CP_UTF8, 0, strcmp(v6, "-") ? v6 : "", -1, w6, 512);
        set_servers(&guid, 0, w4);
        set_servers(&guid, 1, w6);
        restored = 1;
    }
    fclose(f);
    DeleteFileA(path);
    if (restored) plat_dns_flush();
    return restored;
}

int plat_dns_upstreams(char out[][46], int cap)
{
    int i, n = 0;
    if (g_redirected) {
        for (i = 0; i < g_upstream_count && n < cap; i++) strcpy_s(out[n++], 46, g_upstreams[i]);
        return n;
    }
    (void)i;
    return collect_upstreams(out, cap);
}

int plat_neighbors(PlatNeighbor *out, int cap)
{
    MIB_IPNET_TABLE2 *table = NULL;
    MIB_IPFORWARD_TABLE2 *routes = NULL;
    char gateways[8][46];
    int gateway_count = 0, n = 0;
    ULONG i;

    if (GetIpForwardTable2(AF_UNSPEC, &routes) == NO_ERROR && routes) {
        for (i = 0; i < routes->NumEntries && gateway_count < 8; i++) {
            MIB_IPFORWARD_ROW2 *r = &routes->Table[i];
            if (r->DestinationPrefix.PrefixLength != 0) continue;
            addr_text((const SOCKADDR *)&r->NextHop, gateways[gateway_count], 46);
            if (gateways[gateway_count][0] && strcmp(gateways[gateway_count], "0.0.0.0") &&
                strcmp(gateways[gateway_count], "::")) {
                gateway_count++;
            }
        }
        FreeMibTable(routes);
    }

    if (GetIpNetTable2(AF_UNSPEC, &table) != NO_ERROR || !table) return 0;
    for (i = 0; i < table->NumEntries && n < cap; i++) {
        MIB_IPNET_ROW2 *r = &table->Table[i];
        const UCHAR *m = r->PhysicalAddress;
        PlatNeighbor *d;
        int j, existing = -1;
        char ip[46];

        if (r->PhysicalAddressLength != 6) continue;
        if (r->State != NlnsReachable && r->State != NlnsStale && r->State != NlnsDelay &&
            r->State != NlnsProbe) continue;
        if ((m[0] | m[1] | m[2] | m[3] | m[4] | m[5]) == 0) continue;
        if (m[0] & 0x01) continue;

        addr_text((const SOCKADDR *)&r->Address, ip, sizeof ip);
        if (!ip[0]) continue;

        for (j = 0; j < n; j++) {
            char mac[18];
            _snprintf_s(mac, sizeof mac, _TRUNCATE, "%02x:%02x:%02x:%02x:%02x:%02x",
                        m[0], m[1], m[2], m[3], m[4], m[5]);
            if (!strcmp(out[j].mac, mac)) existing = j;
        }
        if (existing >= 0) {
            if (!strchr(ip, ':') && strchr(out[existing].ip, ':')) strcpy_s(out[existing].ip, 46, ip);
            for (j = 0; j < gateway_count; j++) if (!strcmp(gateways[j], ip)) out[existing].gateway = 1;
            continue;
        }
        d = &out[n++];
        memset(d, 0, sizeof *d);
        strcpy_s(d->ip, sizeof d->ip, ip);
        _snprintf_s(d->mac, sizeof d->mac, _TRUNCATE, "%02x:%02x:%02x:%02x:%02x:%02x",
                    m[0], m[1], m[2], m[3], m[4], m[5]);
        for (j = 0; j < gateway_count; j++) if (!strcmp(gateways[j], ip)) d->gateway = 1;
    }
    FreeMibTable(table);
    return n;
}
