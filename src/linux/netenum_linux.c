#include "netenum.h"
#include "platform.h"

#include <stddef.h>
#include <dirent.h>
#include <sys/stat.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/tcp.h>

#define MAP_SIZE 32768

typedef struct {
    unsigned long inode;
    unsigned long pid;
    unsigned long long rx, tx;
    int has_bytes;
} InodeEntry;

static InodeEntry g_map[MAP_SIZE];
static long long g_map_ms = 0;

static InodeEntry *map_slot(unsigned long inode, int create)
{
    unsigned long i = (inode * 2654435761UL) & (MAP_SIZE - 1);
    int probes;
    for (probes = 0; probes < MAP_SIZE; probes++, i = (i + 1) & (MAP_SIZE - 1)) {
        if (g_map[i].inode == inode) return &g_map[i];
        if (!g_map[i].inode) {
            if (!create) return NULL;
            g_map[i].inode = inode;
            return &g_map[i];
        }
    }
    return NULL;
}

static void scan_owners(void)
{
    DIR *proc = opendir("/proc");
    struct dirent *p;

    if (!proc) return;
    while ((p = readdir(proc)) != NULL) {
        char path[64], link[64];
        DIR *fds;
        struct dirent *fd;
        unsigned long pid;

        if (p->d_name[0] < '0' || p->d_name[0] > '9') continue;
        pid = strtoul(p->d_name, NULL, 10);
        _snprintf_s(path, sizeof path, _TRUNCATE, "/proc/%lu/fd", pid);
        fds = opendir(path);
        if (!fds) continue;
        while ((fd = readdir(fds)) != NULL) {
            ssize_t n;
            unsigned long inode;
            InodeEntry *e;
            if (fd->d_name[0] == '.') continue;
            n = readlinkat(dirfd(fds), fd->d_name, link, sizeof link - 1);
            if (n <= 0) continue;
            link[n] = '\0';
            if (strncmp(link, "socket:[", 8) != 0) continue;
            inode = strtoul(link + 8, NULL, 10);
            e = map_slot(inode, 1);
            if (e && !e->pid) e->pid = pid;
        }
        closedir(fds);
    }
    closedir(proc);
}

static void diag_bytes(int family)
{
    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 req;
    } msg;
    char buf[32768];
    int fd, done = 0;

    fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_SOCK_DIAG);
    if (fd < 0) return;

    memset(&msg, 0, sizeof msg);
    msg.nlh.nlmsg_len = sizeof msg;
    msg.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    msg.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg.req.sdiag_family = (unsigned char)family;
    msg.req.sdiag_protocol = IPPROTO_TCP;
    msg.req.idiag_states = 0xFFF;
    msg.req.idiag_ext = 1 << (INET_DIAG_INFO - 1);

    if (send(fd, &msg, sizeof msg, 0) < 0) {
        close(fd);
        return;
    }
    while (!done) {
        ssize_t len = recv(fd, buf, sizeof buf, 0);
        struct nlmsghdr *h;
        if (len <= 0) break;
        for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned)len); h = NLMSG_NEXT(h, len)) {
            struct inet_diag_msg *d;
            struct rtattr *rta;
            int rlen;
            if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR) {
                done = 1;
                break;
            }
            d = (struct inet_diag_msg *)NLMSG_DATA(h);
            rta = (struct rtattr *)((char *)d + NLMSG_ALIGN(sizeof *d));
            rlen = (int)h->nlmsg_len - NLMSG_LENGTH(sizeof *d);
            for (; RTA_OK(rta, rlen); rta = RTA_NEXT(rta, rlen)) {
                if (rta->rta_type == INET_DIAG_INFO &&
                    RTA_PAYLOAD(rta) >= offsetof(struct tcp_info, tcpi_bytes_received) + sizeof(__u64)) {
                    const struct tcp_info *ti = (const struct tcp_info *)RTA_DATA(rta);
                    InodeEntry *e = map_slot(d->idiag_inode, 1);
                    if (e) {
                        e->rx = ti->tcpi_bytes_received;
                        e->tx = ti->tcpi_bytes_acked;
                        e->has_bytes = 1;
                    }
                }
            }
        }
    }
    close(fd);
}

static void refresh_maps(void)
{
    long long now = plat_now_ms();
    if (now - g_map_ms < 500) return;
    memset(g_map, 0, sizeof g_map);
    scan_owners();
    diag_bytes(AF_INET);
    diag_bytes(AF_INET6);
    g_map_ms = now;
}

static int parse_endpoint(const char *text, int family, char *ip, size_t cap, int *port)
{
    const char *colon = strchr(text, ':');
    if (!colon) return 0;
    *port = (int)strtoul(colon + 1, NULL, 16);
    if (family == AF_INET) {
        struct in_addr a;
        a.s_addr = (in_addr_t)strtoul(text, NULL, 16);
        inet_ntop(AF_INET, &a, ip, (socklen_t)cap);
        return 1;
    } else {
        struct in6_addr a;
        char word[9];
        int i;
        if (colon - text != 32) return 0;
        for (i = 0; i < 4; i++) {
            memcpy(word, text + i * 8, 8);
            word[8] = '\0';
            a.s6_addr32[i] = (uint32_t)strtoul(word, NULL, 16);
        }
        inet_ntop(AF_INET6, &a, ip, (socklen_t)cap);
        return 1;
    }
}

static int skip_remote(const char *ip)
{
    return !strcmp(ip, "0.0.0.0") || !strcmp(ip, "::") || !strncmp(ip, "127.", 4) || !strcmp(ip, "::1") ||
           !strncmp(ip, "::ffff:127.", 11);
}

static int read_table(const char *path, int family, NetConn *out, int n, int cap)
{
    FILE *f = fopen(path, "r");
    char line[512];

    if (!f) return n;
    if (!fgets(line, sizeof line, f)) {
        fclose(f);
        return n;
    }
    while (fgets(line, sizeof line, f) && n < cap) {
        char local[64], remote[64];
        unsigned int state;
        unsigned long inode;
        NetConn *c;
        InodeEntry *e;

        if (sscanf(line, "%*s %63s %63s %x %*s %*s %*s %*u %*u %lu", local, remote, &state, &inode) != 4) continue;
        if (state == 0x0A) continue;

        c = &out[n];
        memset(c, 0, sizeof *c);
        c->family = family;
        if (!parse_endpoint(local, family, c->local_ip, sizeof c->local_ip, &c->local_port)) continue;
        if (!parse_endpoint(remote, family, c->remote_ip, sizeof c->remote_ip, &c->remote_port)) continue;
        if (skip_remote(c->remote_ip)) continue;
        c->state = (int)state;
        c->inode = inode;
        e = map_slot(inode, 0);
        c->pid = e ? e->pid : 0;
        n++;
    }
    fclose(f);
    return n;
}

int netenum_connections(NetConn *out, int cap)
{
    int n;
    refresh_maps();
    n = read_table("/proc/net/tcp", AF_INET, out, 0, cap);
    n = read_table("/proc/net/tcp6", AF_INET6, out, n, cap);
    return n;
}

unsigned long netenum_linux_udp_owner(int family, int port)
{
    FILE *f;
    char line[512];
    unsigned long pid = 0;

    refresh_maps();
    f = fopen(family == AF_INET6 ? "/proc/net/udp6" : "/proc/net/udp", "r");
    if (!f) return 0;
    if (!fgets(line, sizeof line, f)) {
        fclose(f);
        return 0;
    }
    while (fgets(line, sizeof line, f)) {
        char local[64];
        unsigned long inode;
        const char *colon;
        if (sscanf(line, "%*s %63s %*s %*s %*s %*s %*s %*u %*u %lu", local, &inode) != 2) continue;
        colon = strchr(local, ':');
        if (!colon || (int)strtoul(colon + 1, NULL, 16) != port) continue;
        {
            InodeEntry *e = map_slot(inode, 0);
            if (e && e->pid) {
                pid = e->pid;
                break;
            }
        }
    }
    fclose(f);
    return pid;
}

int netenum_process_image(unsigned long pid, char *path, size_t cap)
{
    char link[64];
    ssize_t n;
    char *deleted;

    if (!pid) return 0;
    _snprintf_s(link, sizeof link, _TRUNCATE, "/proc/%lu/exe", pid);
    n = readlink(link, path, cap - 1);
    if (n <= 0) return 0;
    path[n] = '\0';
    deleted = strstr(path, " (deleted)");
    if (deleted) *deleted = '\0';
    return 1;
}

int netenum_process_name(unsigned long pid, char *name, size_t cap)
{
    char path[64];
    FILE *f;

    _snprintf_s(path, sizeof path, _TRUNCATE, "/proc/%lu/comm", pid);
    f = fopen(path, "r");
    if (!f) return 0;
    if (!fgets(name, (int)cap, f)) {
        fclose(f);
        return 0;
    }
    fclose(f);
    name[strcspn(name, "\r\n")] = '\0';
    return name[0] != '\0';
}

int netenum_interface_octets(unsigned long long *in, unsigned long long *out)
{
    FILE *f = fopen("/proc/net/dev", "r");
    char line[512];

    *in = 0;
    *out = 0;
    if (!f) return 0;
    while (fgets(line, sizeof line, f)) {
        char *colon = strchr(line, ':'), *name = line;
        unsigned long long rx, tx;
        if (!colon) continue;
        *colon = '\0';
        while (*name == ' ') name++;
        if (!strcmp(name, "lo") || !strncmp(name, "veth", 4) || !strncmp(name, "docker", 6) ||
            !strncmp(name, "br-", 3) || !strncmp(name, "virbr", 5)) continue;
        if (sscanf(colon + 1, "%llu %*u %*u %*u %*u %*u %*u %*u %llu", &rx, &tx) == 2) {
            *in += rx;
            *out += tx;
        }
    }
    fclose(f);
    return 1;
}

int netenum_conn_bytes(const NetConn *c, unsigned long long *rx, unsigned long long *tx)
{
    InodeEntry *e = map_slot(c->inode, 0);
    if (!e || !e->has_bytes) return 0;
    *rx = e->rx;
    *tx = e->tx;
    return 1;
}

int netenum_close(const NetConn *c)
{
    char command[256];
    if (geteuid() != 0) return -1;
    if (c->family == AF_INET6) {
        _snprintf_s(command, sizeof command, _TRUNCATE, "ss -K dst [%s] dport = :%d sport = :%d",
                    c->remote_ip, c->remote_port, c->local_port);
    } else {
        _snprintf_s(command, sizeof command, _TRUNCATE, "ss -K dst %s dport = :%d sport = :%d",
                    c->remote_ip, c->remote_port, c->local_port);
    }
    return plat_run(command) == 0 ? 1 : -1;
}

const char *netenum_state_name(int state)
{
    switch (state) {
        case 0x01: return "ESTABLISHED";
        case 0x02: return "SYN_SENT";
        case 0x03: return "SYN_RECV";
        case 0x04: return "FIN_WAIT1";
        case 0x05: return "FIN_WAIT2";
        case 0x06: return "TIME_WAIT";
        case 0x07: return "CLOSED";
        case 0x08: return "CLOSE_WAIT";
        case 0x09: return "LAST_ACK";
        case 0x0A: return "LISTEN";
        case 0x0B: return "CLOSING";
        default: return "UNKNOWN";
    }
}
