#ifndef WIRECEE_HOST_H
#define WIRECEE_HOST_H

#include "compat.h"
#include "cli.h"

#include <stdio.h>

#define PRINT_ERROR(FUNCTION_NAME)                                            \
    do {                                                                      \
        fprintf(stderr, "[!] [" FUNCTION_NAME "] failed, error: 0x%lx\n",    \
                GetLastError());                                              \
    } while (0)

#define PROGRAM_TITLE "WireCee Firewall"

#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_APP_ICON 5000
#define ID_TRAY_EXIT 5001
#define ID_TRAY_OPEN 5002

extern HWND g_hWnd;
extern HWND g_child_hwnd;
extern NOTIFYICONDATAA g_nid;
extern PROCESS_INFORMATION g_pi;
extern const char *g_port;

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
HWND GetMainWindowHandle(DWORD pid);
int IsProcessRunning(HANDLE process);
int WireCeeLauncher(const char *port, PROCESS_INFORMATION *pi);
int CreateHiddenWindowForTrayMessages(const char *port, PROCESS_INFORMATION *pi);

typedef struct {
    DWORD pid;
    HWND hwnd;
} PIDEnumData;

#endif
