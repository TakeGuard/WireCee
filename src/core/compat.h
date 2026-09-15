#ifndef WIRECEE_COMPAT_H
#define WIRECEE_COMPAT_H

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PATH_SEP "\\"
#define PATH_SEP_CHAR '\\'

typedef SOCKET plat_socket;
#define PLAT_BAD_SOCKET INVALID_SOCKET
#define plat_closesocket closesocket

#else

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef MAX_PATH
#define MAX_PATH 1024
#endif

#define PATH_SEP "/"
#define PATH_SEP_CHAR '/'

typedef int plat_socket;
#define PLAT_BAD_SOCKET (-1)
#define plat_closesocket close

#define _TRUNCATE ((size_t)-1)

#define _stricmp strcasecmp
#define _strnicmp strncasecmp
#define _atoi64 atoll
#define strtok_s strtok_r

#define _snprintf_s(buf, cap, trunc, ...) snprintf((buf), (cap), __VA_ARGS__)
#define _vsnprintf_s(buf, cap, trunc, fmt, ap) vsnprintf((buf), (cap), (fmt), (ap))
#define strcpy_s(dst, cap, src) ((void)snprintf((dst), (cap), "%s", (src)))
#define strncpy_s(dst, cap, src, n) ((void)snprintf((dst), (cap), "%s", (src)))
#define strcat_s(dst, cap, src) ((void)strncat((dst), (src), (cap) - strlen(dst) - 1))
#define fopen_s(fp, path, mode) ((*(fp) = fopen((path), (mode))) ? 0 : errno)

static inline int compat_sprintf(char *buf, size_t cap, const char *fmt, ...)
{
    va_list args;
    int n;
    if (!cap) return 0;
    va_start(args, fmt);
    n = vsnprintf(buf, cap, fmt, args);
    va_end(args);
    if (n < 0) return 0;
    if ((size_t)n >= cap) n = (int)(cap - 1);
    return n;
}
#define sprintf_s(buf, cap, ...) compat_sprintf((buf), (cap), __VA_ARGS__)

#endif

#endif
