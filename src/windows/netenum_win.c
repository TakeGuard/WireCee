#include "netenum.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *read_tcp_table(ULONG family)
{
    DWORD size = 0;
    void *table = NULL;
    int attempt;

    for (attempt = 0; attempt < 4; attempt++) {
        DWORD rc = GetExtendedTcpTable(table, &size, FALSE, family,
                                       TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc == NO_ERROR && table) return table;
        if (rc != ERROR_INSUFFICIENT_BUFFER) break;

        free(table);
        size += 16 * 1024;
        table = malloc(size);
        if (!table) return NULL;
    }
    free(table);
    return NULL;
}

static int skip_remote_v4(DWORD addr)
{
    DWORD host = ntohl(addr);
    return addr == 0 || (host >> 24) == 127;
}

static int skip_remote_v6(const UCHAR *addr)
{
    static const UCHAR zero[16] = {0};
    static const UCHAR loop[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    return memcmp(addr, zero, 16) == 0 || memcmp(addr, loop, 16) == 0;
}

int netenum_connections(NetConn *out, int cap)
{
    MIB_TCPTABLE_OWNER_PID *t4;
    MIB_TCP6TABLE_OWNER_PID *t6;
    DWORD i;
    int n = 0, any = 0;

    t4 = (MIB_TCPTABLE_OWNER_PID *)read_tcp_table(AF_INET);
    if (t4) {
        any = 1;
        for (i = 0; i < t4->dwNumEntries && n < cap; i++) {
            MIB_TCPROW_OWNER_PID *r = &t4->table[i];
            IN_ADDR local, remote;
            NetConn *c;

            if (r->dwState == MIB_TCP_STATE_LISTEN) continue;
            if (skip_remote_v4(r->dwRemoteAddr)) continue;

            c = &out[n++];
            memset(c, 0, sizeof *c);
            c->family = AF_INET;
            local.S_un.S_addr = r->dwLocalAddr;
            remote.S_un.S_addr = r->dwRemoteAddr;
            inet_ntop(AF_INET, &local, c->local_ip, sizeof c->local_ip);
            inet_ntop(AF_INET, &remote, c->remote_ip, sizeof c->remote_ip);
            c->local_port = ntohs((u_short)r->dwLocalPort);
            c->remote_port = ntohs((u_short)r->dwRemotePort);
            c->state = (int)r->dwState;
            c->pid = r->dwOwningPid;
            c->raw4 = *r;
            c->has_raw4 = 1;
        }
        free(t4);
    }

    t6 = (MIB_TCP6TABLE_OWNER_PID *)read_tcp_table(AF_INET6);
    if (t6) {
        any = 1;
        for (i = 0; i < t6->dwNumEntries && n < cap; i++) {
            MIB_TCP6ROW_OWNER_PID *r = &t6->table[i];
            NetConn *c;

            if (r->dwState == MIB_TCP_STATE_LISTEN) continue;
            if (skip_remote_v6(r->ucRemoteAddr)) continue;

            c = &out[n++];
            memset(c, 0, sizeof *c);
            c->family = AF_INET6;
            inet_ntop(AF_INET6, r->ucLocalAddr, c->local_ip, sizeof c->local_ip);
            inet_ntop(AF_INET6, r->ucRemoteAddr, c->remote_ip, sizeof c->remote_ip);
            c->local_port = ntohs((u_short)r->dwLocalPort);
            c->remote_port = ntohs((u_short)r->dwRemotePort);
            c->state = (int)r->dwState;
            c->pid = r->dwOwningPid;
            c->raw6 = *r;
            c->has_raw6 = 1;
        }
        free(t6);
    }

    return any ? n : -1;
}

int netenum_process_image(DWORD pid, char *path, size_t cap)
{
    HANDLE process;
    DWORD len = (DWORD)cap;
    BOOL ok;

    if (!pid || pid == 4) return 0;

    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return 0;
    ok = QueryFullProcessImageNameA(process, 0, path, &len);
    CloseHandle(process);
    return ok ? 1 : 0;
}

int netenum_interface_octets(unsigned long long *in, unsigned long long *out)
{
    MIB_IF_TABLE2 *table = NULL;
    ULONG i;

    *in = 0;
    *out = 0;
    if (GetIfTable2(&table) != NO_ERROR || !table) return 0;

    for (i = 0; i < table->NumEntries; i++) {
        MIB_IF_ROW2 *row = &table->Table[i];
        if (!row->InterfaceAndOperStatusFlags.HardwareInterface) continue;
        if (row->OperStatus != IfOperStatusUp) continue;
        *in += row->InOctets;
        *out += row->OutOctets;
    }

    FreeMibTable(table);
    return 1;
}

static void to_tcprow(const MIB_TCPROW_OWNER_PID *src, MIB_TCPROW *dst)
{
    memset(dst, 0, sizeof *dst);
    dst->dwState = src->dwState;
    dst->dwLocalAddr = src->dwLocalAddr;
    dst->dwLocalPort = src->dwLocalPort;
    dst->dwRemoteAddr = src->dwRemoteAddr;
    dst->dwRemotePort = src->dwRemotePort;
}

static int tcp4_bytes(const MIB_TCPROW_OWNER_PID *row,
                      unsigned long long *rx, unsigned long long *tx)
{
    MIB_TCPROW r;
    TCP_ESTATS_DATA_RW_v0 rw;
    TCP_ESTATS_DATA_ROD_v0 rod;
    ULONG rc;

    to_tcprow(row, &r);

    rw.EnableCollection = TRUE;
    rc = SetPerTcpConnectionEStats(&r, TcpConnectionEstatsData,
                                   (PUCHAR)&rw, 0, sizeof rw, 0);
    if (rc == ERROR_ACCESS_DENIED) return -1;
    if (rc != NO_ERROR) return 0;

    memset(&rod, 0, sizeof rod);
    rc = GetPerTcpConnectionEStats(&r, TcpConnectionEstatsData,
                                   NULL, 0, 0, NULL, 0, 0,
                                   (PUCHAR)&rod, 0, sizeof rod);
    if (rc != NO_ERROR) return 0;

    *rx = rod.DataBytesIn;
    *tx = rod.DataBytesOut;
    return 1;
}

static int tcp6_bytes(const MIB_TCP6ROW_OWNER_PID *row,
                       unsigned long long *rx, unsigned long long *tx)
{
    MIB_TCP6ROW r;
    TCP_ESTATS_DATA_RW_v0 rw;
    TCP_ESTATS_DATA_ROD_v0 rod;
    ULONG rc;

    memset(&r, 0, sizeof r);
    r.State = (MIB_TCP_STATE)row->dwState;
    memcpy(&r.LocalAddr, row->ucLocalAddr, 16);
    r.dwLocalScopeId = row->dwLocalScopeId;
    r.dwLocalPort = row->dwLocalPort;
    memcpy(&r.RemoteAddr, row->ucRemoteAddr, 16);
    r.dwRemoteScopeId = row->dwRemoteScopeId;
    r.dwRemotePort = row->dwRemotePort;

    rw.EnableCollection = TRUE;
    rc = SetPerTcp6ConnectionEStats(&r, TcpConnectionEstatsData,
                                    (PUCHAR)&rw, 0, sizeof rw, 0);
    if (rc == ERROR_ACCESS_DENIED) return -1;
    if (rc != NO_ERROR) return 0;

    memset(&rod, 0, sizeof rod);
    rc = GetPerTcp6ConnectionEStats(&r, TcpConnectionEstatsData,
                                    NULL, 0, 0, NULL, 0, 0,
                                    (PUCHAR)&rod, 0, sizeof rod);
    if (rc != NO_ERROR) return 0;

    *rx = rod.DataBytesIn;
    *tx = rod.DataBytesOut;
    return 1;
}

static DWORD close_tcp4(const MIB_TCPROW_OWNER_PID *row)
{
    MIB_TCPROW r;
    to_tcprow(row, &r);
    r.dwState = MIB_TCP_STATE_DELETE_TCB;
    return SetTcpEntry(&r);
}

int netenum_conn_bytes(const NetConn *c, unsigned long long *rx, unsigned long long *tx)
{
    if (c->has_raw4) return tcp4_bytes(&c->raw4, rx, tx);
    if (c->has_raw6) return tcp6_bytes(&c->raw6, rx, tx);
    return 0;
}

int netenum_close(const NetConn *c)
{
    if (!c->has_raw4) return 0;
    return close_tcp4(&c->raw4) == NO_ERROR ? 1 : -1;
}

const char *netenum_state_name(int state)
{
    switch (state) {
        case MIB_TCP_STATE_CLOSED:     return "CLOSED";
        case MIB_TCP_STATE_LISTEN:     return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:    return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default:                       return "UNKNOWN";
    }
}

#include <tlhelp32.h>

int netenum_process_name(DWORD pid, char *name, size_t cap)
{
    HANDLE snap;
    PROCESSENTRY32 entry;
    int found = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    entry.dwSize = sizeof entry;
    if (Process32First(snap, &entry)) {
        do {
            if (entry.th32ProcessID == pid) {
                strncpy_s(name, cap, entry.szExeFile, _TRUNCATE);
                found = 1;
                break;
            }
        } while (Process32Next(snap, &entry));
    }
    CloseHandle(snap);
    return found;
}
