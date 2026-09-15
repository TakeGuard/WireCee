#ifndef WIRECEE_NETENUM_H
#define WIRECEE_NETENUM_H

#include "compat.h"

#ifdef _WIN32
#include <iphlpapi.h>
#endif

typedef struct {
    int family;
    char local_ip[46];
    int local_port;
    char remote_ip[46];
    int remote_port;
    int state;
    unsigned long pid;

#ifdef _WIN32
    MIB_TCPROW_OWNER_PID raw4;
    int has_raw4;
    MIB_TCP6ROW_OWNER_PID raw6;
    int has_raw6;
#else
    unsigned long inode;
#endif
} NetConn;

int netenum_connections(NetConn *out, int cap);

int netenum_process_image(unsigned long pid, char *path, size_t cap);

int netenum_process_name(unsigned long pid, char *name, size_t cap);

int netenum_interface_octets(unsigned long long *in, unsigned long long *out);

int netenum_conn_bytes(const NetConn *c, unsigned long long *rx, unsigned long long *tx);

int netenum_close(const NetConn *c);

const char *netenum_state_name(int state);

#endif
