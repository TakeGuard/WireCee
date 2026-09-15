#include "flows.h"
#include "platform.h"

unsigned long netenum_linux_udp_owner(int family, int port);

static int g_active = 0;

int flows_start(char *reason, size_t cap)
{
    FILE *f;

    if (geteuid() != 0) {
        _snprintf_s(reason, cap, _TRUNCATE, "Reading UDP traffic requires root");
        return 0;
    }
    plat_run("modprobe nf_conntrack");
    f = fopen("/proc/sys/net/netfilter/nf_conntrack_acct", "w");
    if (f) {
        fputs("1\n", f);
        fclose(f);
    }
    f = fopen("/proc/net/nf_conntrack", "r");
    if (!f) {
        _snprintf_s(reason, cap, _TRUNCATE, "Connection tracking is unavailable. Load the nf_conntrack module.");
        return 0;
    }
    fclose(f);
    g_active = 1;
    return 1;
}

void flows_stop(void)
{
    g_active = 0;
}

int flows_dns_names(void)
{
    return 0;
}

static const char *field(const char *line, const char *key, int nth, char *out, size_t cap)
{
    const char *p = line;
    size_t klen = strlen(key);
    int seen = 0;

    while ((p = strstr(p, key)) != NULL) {
        if ((p == line || p[-1] == ' ') && seen++ == nth) {
            size_t n = 0;
            p += klen;
            while (*p && *p != ' ' && n + 1 < cap) out[n++] = *p++;
            out[n] = '\0';
            return out;
        }
        p += klen;
    }
    out[0] = '\0';
    return NULL;
}

int flows_copy(Flow *out, int cap)
{
    FILE *f;
    char line[1024];
    int n = 0;

    if (!g_active) return 0;
    f = fopen("/proc/net/nf_conntrack", "r");
    if (!f) return 0;

    while (fgets(line, sizeof line, f) && n < cap) {
        char l3[8], l4[8], src[46], dst[46], sport[8], dport[8], bytes_o[24], bytes_r[24];
        int timeout, family, sp, dp;
        unsigned long owner;
        Flow *fl;

        if (sscanf(line, "%7s %*d %7s %*d %d", l3, l4, &timeout) != 3 || strcmp(l4, "udp")) continue;
        family = !strcmp(l3, "ipv6") ? AF_INET6 : AF_INET;
        if (!field(line, "src=", 0, src, sizeof src) || !field(line, "dst=", 0, dst, sizeof dst) ||
            !field(line, "sport=", 0, sport, sizeof sport) || !field(line, "dport=", 0, dport, sizeof dport)) continue;
        field(line, "bytes=", 0, bytes_o, sizeof bytes_o);
        field(line, "bytes=", 1, bytes_r, sizeof bytes_r);
        sp = atoi(sport);
        dp = atoi(dport);

        fl = &out[n];
        memset(fl, 0, sizeof *fl);
        fl->family = family;
        fl->idle_ms = timeout < 25 ? 10000 : 0;

        owner = netenum_linux_udp_owner(family, sp);
        if (owner) {
            if (!strncmp(dst, "127.", 4) || !strcmp(dst, "::1")) continue;
            fl->pid = owner;
            fl->local_port = sp;
            strcpy_s(fl->remote_ip, sizeof fl->remote_ip, dst);
            fl->remote_port = dp;
            fl->tx = strtoull(bytes_o, NULL, 10);
            fl->rx = strtoull(bytes_r, NULL, 10);
        } else if ((owner = netenum_linux_udp_owner(family, dp)) != 0) {
            if (!strncmp(src, "127.", 4) || !strcmp(src, "::1")) continue;
            fl->pid = owner;
            fl->local_port = dp;
            strcpy_s(fl->remote_ip, sizeof fl->remote_ip, src);
            fl->remote_port = sp;
            fl->rx = strtoull(bytes_o, NULL, 10);
            fl->tx = strtoull(bytes_r, NULL, 10);
        } else {
            continue;
        }
        n++;
    }
    fclose(f);
    return n;
}
