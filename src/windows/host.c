#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <objidl.h>

typedef enum { GdipOk = 0 } GpStatus;
typedef void GpImage;
typedef void GpBitmap;

typedef struct {
    UINT32 GdiplusVersion;
    void *DebugEventCallback;
    BOOL SuppressBackgroundThread;
    BOOL SuppressExternalCodecs;
} GdiplusStartupInputC;

GpStatus WINAPI GdiplusStartup(ULONG_PTR *token, const GdiplusStartupInputC *input, void *output);
void WINAPI GdiplusShutdown(ULONG_PTR token);
GpStatus WINAPI GdipCreateBitmapFromHICON(HICON hicon, GpBitmap **bitmap);
GpStatus WINAPI GdipSaveImageToStream(GpImage *image, IStream *stream,
                                      const CLSID *encoder, const void *params);
GpStatus WINAPI GdipDisposeImage(GpImage *image);

#include "civetweb.h"
#include "host.h"
#include "engine.h"
#include "api.h"
#include "cli.h"
#include "platform.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

HWND g_hWnd = NULL;
HWND g_child_hwnd = NULL;
NOTIFYICONDATAA g_nid = {0};
PROCESS_INFORMATION g_pi = {0};
const char *g_port = NULL;

static struct mg_context *g_ctx = NULL;
static char g_port_str[16] = {0};
static char g_app_root[MAX_PATH] = {0};
static int g_headless = 0;
static int g_service_mode = 0;

#define SERVICE_NAME "WireCeeEngine"
#define SERVICE_DISPLAY "WireCee Firewall Engine"
#define SERVICE_PORT 30700

#define NOTIFY_TIMER_ID 1
#define NOTIFY_INTERVAL_MS 2000
#define BLOCK_NOTICE_GAP_MS 15000

static SERVICE_STATUS_HANDLE g_svc_status_handle = NULL;
static SERVICE_STATUS g_svc_status = {0};
static HANDLE g_svc_stop_event = NULL;

static int is_elevated(void);

static int launched_from_terminal(void)
{
    DWORD pids[8];
    DWORD count = GetConsoleProcessList(pids, (DWORD)(sizeof pids / sizeof pids[0]));
    return count > 1;
}

static int enable_vt_output(void)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;

    if (out == INVALID_HANDLE_VALUE || !GetConsoleMode(out, &mode)) return 0;
    return SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
}

static void detach_gui_console(void)
{
    HWND console = GetConsoleWindow();
    if (console) ShowWindow(console, SW_HIDE);
    FreeConsole();
}

static ULONG_PTR g_gdiplus_token = 0;

static void gdiplus_start(void)
{
    GdiplusStartupInputC input;
    memset(&input, 0, sizeof input);
    input.GdiplusVersion = 1;
    GdiplusStartup(&g_gdiplus_token, &input, NULL);
}

static void gdiplus_stop(void)
{
    if (g_gdiplus_token) {
        GdiplusShutdown(g_gdiplus_token);
        g_gdiplus_token = 0;
    }
}

static unsigned char *icon_to_png(HICON icon, size_t *out_len)
{
    static const CLSID png = {0x557cf406, 0x1a04, 0x11d3, {0x9a, 0x73, 0x00, 0x00, 0xf8, 0x1e, 0xf3, 0x2e}};
    GpBitmap *bitmap = NULL;
    IStream *stream = NULL;
    unsigned char *result = NULL;
    LARGE_INTEGER zero = {0};
    STATSTG stat;
    ULONG read = 0;

    *out_len = 0;
    if (GdipCreateBitmapFromHICON(icon, &bitmap) != GdipOk || !bitmap) return NULL;
    if (CreateStreamOnHGlobal(NULL, TRUE, &stream) != S_OK) goto done;
    if (GdipSaveImageToStream((GpImage *)bitmap, stream, &png, NULL) != GdipOk) goto done;
    if (stream->lpVtbl->Stat(stream, &stat, STATFLAG_NONAME) != S_OK) goto done;

    *out_len = (size_t)stat.cbSize.QuadPart;
    if (!*out_len) goto done;
    result = (unsigned char *)malloc(*out_len);
    if (!result) {
        *out_len = 0;
        goto done;
    }
    stream->lpVtbl->Seek(stream, zero, STREAM_SEEK_SET, NULL);
    if (stream->lpVtbl->Read(stream, result, (ULONG)*out_len, &read) != S_OK || read != *out_len) {
        free(result);
        result = NULL;
        *out_len = 0;
    }

done:
    if (stream) stream->lpVtbl->Release(stream);
    if (bitmap) GdipDisposeImage((GpImage *)bitmap);
    return result;
}

typedef struct {
    char path[MAX_PATH];
    unsigned char *png;
    size_t len;
} IconEntry;

static IconEntry g_icons[ENG_MAX_APPS];
static int g_icon_count = 0;
static CRITICAL_SECTION g_icon_lock;
static int g_icon_lock_ready = 0;

static void icon_cache_init(void)
{
    InitializeCriticalSection(&g_icon_lock);
    g_icon_lock_ready = 1;
}

static void icon_cache_free(void)
{
    int i;
    if (!g_icon_lock_ready) return;
    for (i = 0; i < g_icon_count; i++) free(g_icons[i].png);
    g_icon_count = 0;
    DeleteCriticalSection(&g_icon_lock);
    g_icon_lock_ready = 0;
}

static const IconEntry *icon_for(const char *path)
{
    IconEntry *entry;
    SHFILEINFOA info;
    int com_ready, i;

    EnterCriticalSection(&g_icon_lock);
    for (i = 0; i < g_icon_count; i++) {
        if (_stricmp(g_icons[i].path, path) == 0) {
            LeaveCriticalSection(&g_icon_lock);
            return &g_icons[i];
        }
    }
    if (g_icon_count >= ENG_MAX_APPS) {
        LeaveCriticalSection(&g_icon_lock);
        return NULL;
    }

    entry = &g_icons[g_icon_count];
    memset(entry, 0, sizeof *entry);
    strncpy_s(entry->path, sizeof entry->path, path, _TRUNCATE);

    com_ready = SUCCEEDED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE));
    memset(&info, 0, sizeof info);
    if (SHGetFileInfoA(path, 0, &info, sizeof info, SHGFI_ICON | SHGFI_LARGEICON) && info.hIcon) {
        entry->png = icon_to_png(info.hIcon, &entry->len);
        DestroyIcon(info.hIcon);
    }
    if (com_ready) CoUninitialize();

    g_icon_count++;
    LeaveCriticalSection(&g_icon_lock);
    return entry;
}

static int host_icon(struct mg_connection *conn, const char *name)
{
    char path[MAX_PATH] = {0};
    const IconEntry *entry;

    if (!name[0] || !engine_app_path(name, path, sizeof path)) {
        return api_send_json(conn, 404, "{\"error\":\"No such application\"}");
    }
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        return api_send_json(conn, 404, "{\"error\":\"The executable is not on this computer\"}");
    }
    entry = icon_for(path);
    if (!entry || !entry->png || !entry->len) {
        return api_send_json(conn, 404, "{\"error\":\"No icon\"}");
    }
    mg_printf(conn,
              "HTTP/1.1 200 OK\r\n"
              "Content-Type: image/png\r\n"
              "Content-Length: %d\r\n"
              "Cache-Control: private, max-age=86400\r\n\r\n",
              (int)entry->len);
    mg_write(conn, entry->png, entry->len);
    return 200;
}

static HWND ui_window(void)
{
    if (g_child_hwnd && IsWindow(g_child_hwnd)) return g_child_hwnd;
    g_child_hwnd = NULL;
    if (g_pi.dwProcessId) g_child_hwnd = GetMainWindowHandle(g_pi.dwProcessId);
    if (!g_child_hwnd) g_child_hwnd = FindWindowA("WireCeeShellWindow", NULL);
    return g_child_hwnd;
}

static int host_window(struct mg_connection *conn, const char *action, const char *query)
{
    HWND hwnd = ui_window();

    if (!hwnd) return api_send_json(conn, 503, "{\"error\":\"No window\"}");

    if (strcmp(action, "minimize") == 0) {
        ShowWindow(hwnd, SW_MINIMIZE);
    } else if (strcmp(action, "maximize") == 0) {
        ShowWindow(hwnd, IsZoomed(hwnd) ? SW_RESTORE : SW_MAXIMIZE);
    } else if (strcmp(action, "restore") == 0) {
        ShowWindow(hwnd, SW_RESTORE);
    } else if (strcmp(action, "close") == 0) {
        PostMessageA(hwnd, WM_CLOSE, 0, 0);
    } else if (strcmp(action, "drag") == 0) {
        char dx_s[16] = {0}, dy_s[16] = {0};
        RECT rc;
        size_t qlen = strlen(query);
        mg_get_var(query, qlen, "dx", dx_s, sizeof dx_s);
        mg_get_var(query, qlen, "dy", dy_s, sizeof dy_s);
        if (GetWindowRect(hwnd, &rc)) {
            SetWindowPos(hwnd, NULL, rc.left + atoi(dx_s), rc.top + atoi(dy_s), 0, 0,
                         SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        }
    } else if (strcmp(action, "state") == 0) {
        return api_send_json(conn, 200,
                             IsZoomed(hwnd) ? "{\"state\":\"maximized\"}"
                                            : (IsIconic(hwnd) ? "{\"state\":\"minimized\"}" : "{\"state\":\"normal\"}"));
    } else {
        return api_send_json(conn, 404, "{\"error\":\"Unknown action\"}");
    }
    return api_send_json(conn, 200, "{\"ok\":true}");
}

static void host_quit(void)
{
    if (g_svc_stop_event) SetEvent(g_svc_stop_event);
    if (g_hWnd) PostMessageA(g_hWnd, WM_COMMAND, ID_TRAY_EXIT, 0);
}

static void module_dir(char *out, size_t len)
{
    char *slash;
    GetModuleFileNameA(NULL, out, (DWORD)len);
    slash = strrchr(out, '\\');
    if (slash) *slash = '\0';
}

static int resolve_app_root(char *out, size_t len)
{
    char base[MAX_PATH];
    DWORD attrs;

    module_dir(base, sizeof base);
    _snprintf_s(out, len, _TRUNCATE, "%s\\app", base);
    attrs = GetFileAttributesA(out);
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) return 1;

    _snprintf_s(out, len, _TRUNCATE, "%s\\..\\..\\app", base);
    attrs = GetFileAttributesA(out);
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) return 1;

    out[0] = '\0';
    return 0;
}

static int bring_up(int port, int verbose)
{
    ApiHooks hooks;

    if (!resolve_app_root(g_app_root, sizeof g_app_root)) {
        WARN("The app directory was not found next to the executable.");
        return 1;
    }
    if (verbose) INFO("Serving files from %s", g_app_root);

    _snprintf_s(g_port_str, sizeof g_port_str, _TRUNCATE, "%d", port);
    g_port = g_port_str;

    gdiplus_start();
    icon_cache_init();
    engine_start();

    memset(&hooks, 0, sizeof hooks);
    hooks.icon = host_icon;
    hooks.window = host_window;
    hooks.quit = host_quit;
    hooks.headless = g_headless;
    hooks.service = g_service_mode;
    g_ctx = api_start(port, g_app_root, &hooks);
    if (!g_ctx) {
        WARN("The HTTP server could not start.");
        engine_stop();
        return 1;
    }
    instance_write(port);
    return 0;
}

static void tear_down(void)
{
    api_stop(g_ctx);
    g_ctx = NULL;
    engine_stop();
    icon_cache_free();
    gdiplus_stop();
    instance_clear();
}

int IsProcessRunning(HANDLE process)
{
    if (!process) return 0;
    return WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
}

static BOOL CALLBACK enum_windows_proc(HWND hwnd, LPARAM param)
{
    PIDEnumData *data = (PIDEnumData *)param;
    DWORD pid = 0;

    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == data->pid && GetWindow(hwnd, GW_OWNER) == NULL && IsWindowVisible(hwnd)) {
        data->hwnd = hwnd;
        return FALSE;
    }
    return TRUE;
}

HWND GetMainWindowHandle(DWORD pid)
{
    PIDEnumData data = {pid, NULL};
    EnumWindows(enum_windows_proc, (LPARAM)&data);
    return data.hwnd;
}

int WireCeeLauncher(const char *port, PROCESS_INFORMATION *pi)
{
    STARTUPINFOA si = {0};
    char command[MAX_PATH + 32];
    char exe_dir[MAX_PATH];

    module_dir(exe_dir, sizeof exe_dir);
    si.cb = sizeof si;
    ZeroMemory(pi, sizeof *pi);
    _snprintf_s(command, sizeof command, _TRUNCATE, "\"%s\\WireCeeUI.exe\" %s", exe_dir, port);

    if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, exe_dir, &si, pi)) {
        PRINT_ERROR("CreateProcessA");
        return 1;
    }
    return 0;
}

int CreateHiddenWindowForTrayMessages(const char *port, PROCESS_INFORMATION *pi)
{
    WNDCLASSA wc = {0};
    HINSTANCE instance = GetModuleHandleA(NULL);
    char icon_path[MAX_PATH];
    HICON icon;
    (void)pi;

    wc.lpfnWndProc = WindowProc;
    wc.hInstance = instance;
    wc.lpszClassName = "WireCeeTrayWindow";
    if (!RegisterClassA(&wc)) {
        PRINT_ERROR("RegisterClassA");
        return 1;
    }

    g_hWnd = CreateWindowExA(0, "WireCeeTrayWindow", PROGRAM_TITLE, 0, 0, 0, 0, 0,
                             HWND_MESSAGE, NULL, instance, NULL);
    if (!g_hWnd) {
        PRINT_ERROR("CreateWindowExA");
        return 1;
    }

    _snprintf_s(icon_path, sizeof icon_path, _TRUNCATE, "%s\\resources\\logo.ico", g_app_root);
    icon = (HICON)LoadImageA(NULL, icon_path, IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE);

    g_nid.cbSize = sizeof g_nid;
    g_nid.hWnd = g_hWnd;
    g_nid.uID = ID_TRAY_APP_ICON;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = icon ? icon : LoadIcon(NULL, IDI_APPLICATION);
    _snprintf_s(g_nid.szTip, sizeof g_nid.szTip, _TRUNCATE, "%s (port %s)", PROGRAM_TITLE, port);

    if (!Shell_NotifyIconA(NIM_ADD, &g_nid)) {
        PRINT_ERROR("Shell_NotifyIconA");
        return 1;
    }
    SetTimer(g_hWnd, NOTIFY_TIMER_ID, NOTIFY_INTERVAL_MS, NULL);
    return 0;
}

static void svc_report(DWORD state, DWORD exit_code, DWORD wait_hint)
{
    static DWORD checkpoint = 1;

    g_svc_status.dwCurrentState = state;
    g_svc_status.dwWin32ExitCode = exit_code;
    g_svc_status.dwWaitHint = wait_hint;
    g_svc_status.dwControlsAccepted =
        (state == SERVICE_START_PENDING) ? 0 : SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_svc_status.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkpoint++;
    if (g_svc_status_handle) SetServiceStatus(g_svc_status_handle, &g_svc_status);
}

static DWORD WINAPI svc_ctrl_handler(DWORD ctrl, DWORD type, LPVOID data, LPVOID ctx)
{
    (void)type; (void)data; (void)ctx;
    switch (ctrl) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            svc_report(SERVICE_STOP_PENDING, NO_ERROR, 3000);
            if (g_svc_stop_event) SetEvent(g_svc_stop_event);
            return NO_ERROR;
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

static VOID WINAPI svc_main(DWORD argc, LPSTR *argv)
{
    int port;
    (void)argc; (void)argv;

    g_svc_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_svc_status_handle = RegisterServiceCtrlHandlerExA(SERVICE_NAME, svc_ctrl_handler, NULL);
    if (!g_svc_status_handle) return;

    svc_report(SERVICE_START_PENDING, NO_ERROR, 5000);
    g_service_mode = 1;
    g_headless = 1;
    g_svc_stop_event = CreateEventA(NULL, TRUE, FALSE, NULL);

    port = pick_port(SERVICE_PORT);
    if (!port) port = pick_port(0);
    if (!port || bring_up(port, 0) != 0) {
        svc_report(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        return;
    }

    svc_report(SERVICE_RUNNING, NO_ERROR, 0);
    WaitForSingleObject(g_svc_stop_event, INFINITE);

    tear_down();
    CloseHandle(g_svc_stop_event);
    g_svc_stop_event = NULL;
    svc_report(SERVICE_STOPPED, NO_ERROR, 0);
}

static int is_elevated(void)
{
    return plat_is_admin();
}

static int relaunch_elevated(int argc, char **argv)
{
    SHELLEXECUTEINFOA sei;
    char exe[MAX_PATH], params[2048] = {0};
    int i;

    GetModuleFileNameA(NULL, exe, sizeof exe);
    for (i = 1; i < argc; i++) {
        strcat_s(params, sizeof params, "\"");
        strcat_s(params, sizeof params, argv[i]);
        strcat_s(params, sizeof params, "\" ");
    }
    strcat_s(params, sizeof params, "--elevated");

    memset(&sei, 0, sizeof sei);
    sei.cbSize = sizeof sei;
    sei.fMask = SEE_MASK_NOASYNC;
    sei.lpVerb = "runas";
    sei.lpFile = exe;
    sei.lpParameters = params;
    sei.nShow = SW_HIDE;
    return ShellExecuteExA(&sei) ? 1 : 0;
}

static int cmd_install_service(void)
{
    SC_HANDLE scm, svc;
    char exe[MAX_PATH], cmd[MAX_PATH + 32];

    if (!is_elevated()) {
        WARN("Installing the service requires an administrator terminal.");
        return 1;
    }

    GetModuleFileNameA(NULL, exe, sizeof exe);
    _snprintf_s(cmd, sizeof cmd, _TRUNCATE, "\"%s\" --service", exe);

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { PRINT_ERROR("OpenSCManagerA"); return 1; }

    svc = CreateServiceA(scm, SERVICE_NAME, SERVICE_DISPLAY, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                         SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, cmd, NULL, NULL, NULL, NULL, NULL);
    if (!svc) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) WARN("The %s service is already installed.", SERVICE_NAME);
        else PRINT_ERROR("CreateServiceA");
        CloseServiceHandle(scm);
        return 1;
    }

    {
        SERVICE_DESCRIPTIONA desc;
        desc.lpDescription = (LPSTR)"Enforces WireCee firewall rules while the WireCee window is closed.";
        ChangeServiceConfig2A(svc, SERVICE_CONFIG_DESCRIPTION, &desc);
    }

    OKAY("Installed the %s service. It starts automatically at boot.", SERVICE_NAME);
    INFO("Start it now with: wirecee --start-service");
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

static int service_control(DWORD control, DWORD desired, const char *what)
{
    SC_HANDLE scm, svc;
    SERVICE_STATUS status = {0};
    int rc = 0;

    if (!is_elevated()) {
        WARN("%s the service requires an administrator terminal.", what);
        return 1;
    }
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { PRINT_ERROR("OpenSCManagerA"); return 1; }

    svc = OpenServiceA(scm, SERVICE_NAME, desired);
    if (!svc) {
        WARN("The %s service is not installed.", SERVICE_NAME);
        CloseServiceHandle(scm);
        return 1;
    }

    if (control == 0) {
        if (!StartServiceA(svc, 0, NULL)) {
            if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) INFO("The service is already running.");
            else { PRINT_ERROR("StartServiceA"); rc = 1; }
        } else {
            OKAY("Service started.");
        }
    } else if (control == SERVICE_CONTROL_STOP) {
        if (!ControlService(svc, SERVICE_CONTROL_STOP, &status)) {
            WARN("The service could not be stopped. It may not be running.");
            rc = 1;
        } else {
            OKAY("Service stopped.");
        }
    } else {
        ControlService(svc, SERVICE_CONTROL_STOP, &status);
        Sleep(500);
        if (!DeleteService(svc)) { PRINT_ERROR("DeleteService"); rc = 1; }
        else OKAY("Service removed.");
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return rc;
}

static int cmd_service_status(int json)
{
    SC_HANDLE scm, svc;
    SERVICE_STATUS_PROCESS ssp = {0};
    DWORD needed = 0;
    const char *state = "unknown";

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        if (json) printf("{\"installed\":false}\n");
        else WARN("The service manager could not be reached.");
        return 1;
    }

    svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (!svc) {
        CloseServiceHandle(scm);
        if (json) printf("{\"installed\":false}\n");
        else INFO("The %s service is not installed. Install it with --install-service.", SERVICE_NAME);
        return 1;
    }

    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof ssp, &needed)) {
        switch (ssp.dwCurrentState) {
            case SERVICE_RUNNING: state = "running"; break;
            case SERVICE_STOPPED: state = "stopped"; break;
            case SERVICE_START_PENDING: state = "starting"; break;
            case SERVICE_STOP_PENDING: state = "stopping"; break;
        }
    }
    if (json) printf("{\"installed\":true,\"state\":\"%s\",\"pid\":%lu}\n", state, ssp.dwProcessId);
    else OKAY("Service %s is %s (pid %lu).", SERVICE_NAME, state, ssp.dwProcessId);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return strcmp(state, "running") == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    Options opt;
    int from_terminal = launched_from_terminal();
    int port, rc;
    MSG msg;
    BOOL ret;

    g_color = from_terminal && !getenv("NO_COLOR") && enable_vt_output();
    plat_init();

    rc = cli_parse_args(argc, argv, &opt);
    if (rc) return rc;

    rc = cli_run(&opt);
    if (rc >= 0) return rc;

    switch (opt.mode) {
        case RUN_SVC_INSTALL:   return cmd_install_service();
        case RUN_SVC_UNINSTALL: return service_control(1, SERVICE_ALL_ACCESS, "Removing");
        case RUN_SVC_START:     return service_control(0, SERVICE_START, "Starting");
        case RUN_SVC_STOP:      return service_control(SERVICE_CONTROL_STOP, SERVICE_STOP, "Stopping");
        case RUN_SVC_STATUS:    return cmd_service_status(opt.json);

        case RUN_SERVICE: {
            SERVICE_TABLE_ENTRYA table[] = {
                {(LPSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONA)svc_main},
                {NULL, NULL}
            };
            if (!StartServiceCtrlDispatcherA(table)) {
                WARN("--service is used by the service manager. Use --start-service instead.");
                return 1;
            }
            return 0;
        }

        default: break;
    }

    if (!from_terminal) detach_gui_console();

    port = instance_read();
    if (port) {
        char body[1024];
        int status = 0;
        if (http_call(port, "GET", "/api/status", "application/json", body, sizeof body, &status) && status == 200) {
            INFO("An engine is already running on port %d.", port);
            if (!opt.headless) {
                _snprintf_s(g_port_str, sizeof g_port_str, _TRUNCATE, "%d", port);
                if (WireCeeLauncher(g_port_str, &g_pi) == 0) {
                    OKAY("Opened a window onto the running engine.");
                    return 0;
                }
            }
            WARN("Nothing to do. Use --status to inspect it or --stop to end it.");
            return 1;
        }
        instance_clear();
    }

    if (!opt.no_elevate && !opt.elevated_relaunch && !is_elevated()) {
        if (relaunch_elevated(argc, argv)) {
            INFO("Restarting with administrator rights.");
            return 0;
        }
        WARN("Administrator rights were not granted. Running in monitoring mode.");
    }

    g_headless = opt.headless;

    port = pick_port(opt.port);
    if (!port) {
        WARN(opt.port ? "Port %d is already in use." : "No free port between %d and %d.",
             opt.port ? opt.port : PORT_MIN, PORT_MAX);
        return 1;
    }

    INFO("Serving the interface on http://127.0.0.1:%d/", port);
    if (bring_up(port, opt.verbose) != 0) return 1;
    OKAY("Engine started.");

    if (CreateHiddenWindowForTrayMessages(g_port, &g_pi) != 0) {
        WARN("The tray icon could not be created.");
        tear_down();
        return 1;
    }

    if (opt.open_browser) {
        char url[64];
        _snprintf_s(url, sizeof url, _TRUNCATE, "http://127.0.0.1:%d/", port);
        ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);
        OKAY("Opened the interface in your browser.");
    } else if (!opt.headless) {
        INFO("Launching the WireCee window.");
        if (WireCeeLauncher(g_port, &g_pi) != 0) {
            WARN("WireCeeUI.exe could not be launched.");
            tear_down();
            return 1;
        }
        OKAY("Window launched.");
    } else {
        OKAY("Running headless. Open http://127.0.0.1:%d/ in any browser.", port);
    }

    if (from_terminal && !g_quiet) {
        LINE();
        INFO("Running in the tray. Press Ctrl+C or run 'wirecee --stop' to quit.");
    }

    while ((ret = GetMessage(&msg, NULL, 0, 0)) != 0) {
        if (ret == -1) break;
        TranslateMessage(&msg);
        DispatchMessage(&msg);

        if (g_pi.hProcess && WaitForSingleObject(g_pi.hProcess, 0) == WAIT_OBJECT_0) {
            CloseHandle(g_pi.hProcess);
            CloseHandle(g_pi.hThread);
            ZeroMemory(&g_pi, sizeof g_pi);
            g_child_hwnd = NULL;
            if (engine_keep_running()) {
                if (opt.verbose) INFO("Window closed. Protection continues from the tray.");
            } else {
                INFO("Window closed with background protection off. Shutting down.");
                PostMessageA(g_hWnd, WM_COMMAND, ID_TRAY_EXIT, 0);
            }
        }
    }

    INFO("Shutting down.");
    tear_down();
    if (g_pi.hProcess) CloseHandle(g_pi.hProcess);
    if (g_pi.hThread) CloseHandle(g_pi.hThread);
    return 0;
}

static ULONGLONG g_last_block_notice = 0;

static void show_balloon(const char *title, const char *text, DWORD icon)
{
    NOTIFYICONDATAA info = {0};

    info.cbSize = sizeof info;
    info.hWnd = g_hWnd;
    info.uID = ID_TRAY_APP_ICON;
    info.uFlags = NIF_INFO;
    info.dwInfoFlags = icon;
    strncpy_s(info.szInfoTitle, sizeof info.szInfoTitle, title, _TRUNCATE);
    strncpy_s(info.szInfo, sizeof info.szInfo, text, _TRUNCATE);

    if (!Shell_NotifyIconA(NIM_MODIFY, &info)) {
        engine_log("warn", "Notification failed with error %lu", GetLastError());
    } else if (plat_notifications_enabled()) {
        engine_log("info", "Notification shown: %s", text);
    } else {
        engine_log("warn", "Notification suppressed because Windows notifications are turned off for this account: %s",
                   text);
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg) {
        case WM_TRAYICON:
            if (lParam == WM_RBUTTONUP) {
                POINT pt;
                HMENU menu;

                GetCursorPos(&pt);
                SetForegroundWindow(hwnd);
                menu = CreatePopupMenu();
                if (menu) {
                    InsertMenuA(menu, -1, MF_BYPOSITION, ID_TRAY_OPEN, "Open WireCee");
                    InsertMenuA(menu, -1, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
                    InsertMenuA(menu, -1, MF_BYPOSITION, ID_TRAY_EXIT, "Exit");
                    TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
                    DestroyMenu(menu);
                }
            } else if (lParam == WM_LBUTTONDBLCLK) {
                PostMessageA(hwnd, WM_COMMAND, ID_TRAY_OPEN, 0);
            }
            break;

        case WM_TIMER:
            if (wParam == NOTIFY_TIMER_ID) {
                char message[256], body[300], title[64];
                int suppressed = 0;
                ULONGLONG now = GetTickCount64();
                static int ui_seen = 0;

                if (ui_window()) {
                    ui_seen = 1;
                } else if (ui_seen) {
                    ui_seen = 0;
                    if (!engine_keep_running()) {
                        engine_log("info", "Window closed with background protection off. Shutting down.");
                        PostMessageA(hwnd, WM_COMMAND, ID_TRAY_EXIT, 0);
                    }
                }

                if (engine_take_notice(title, sizeof title, body, sizeof body)) {
                    show_balloon(title, body, NIIF_INFO);
                }

                if (now - g_last_block_notice >= BLOCK_NOTICE_GAP_MS &&
                    engine_take_block_notice(message, sizeof message, &suppressed)) {
                    g_last_block_notice = now;
                    if (suppressed > 0) {
                        _snprintf_s(body, sizeof body, _TRUNCATE, "%s, and %d more in the last %d seconds",
                                    message, suppressed, BLOCK_NOTICE_GAP_MS / 1000);
                    } else {
                        strcpy_s(body, sizeof body, message);
                    }
                    show_balloon("WireCee blocked traffic", body, NIIF_WARNING);
                }
            }
            break;

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_TRAY_EXIT:
                    if (!g_pi.hProcess) {
                        HWND ui = ui_window();
                        if (ui) PostMessageA(ui, WM_CLOSE, 0, 0);
                    } else if (IsProcessRunning(g_pi.hProcess)) {
                        HWND ui = ui_window();
                        if (ui) PostMessageA(ui, WM_CLOSE, 0, 0);
                        if (WaitForSingleObject(g_pi.hProcess, 3000) != WAIT_OBJECT_0) {
                            TerminateProcess(g_pi.hProcess, 0);
                            WaitForSingleObject(g_pi.hProcess, INFINITE);
                        }
                    }
                    if (g_pi.hProcess) CloseHandle(g_pi.hProcess);
                    if (g_pi.hThread) CloseHandle(g_pi.hThread);
                    ZeroMemory(&g_pi, sizeof g_pi);
                    Shell_NotifyIconA(NIM_DELETE, &g_nid);
                    PostQuitMessage(0);
                    break;

                case ID_TRAY_OPEN: {
                    HWND ui = ui_window();
                    if (ui) {
                        if (IsIconic(ui)) ShowWindow(ui, SW_RESTORE);
                        ShowWindow(ui, SW_SHOW);
                        SetForegroundWindow(ui);
                    } else if (g_port) {
                        WireCeeLauncher(g_port, &g_pi);
                    }
                    break;
                }
            }
            break;

        case WM_DESTROY:
            Shell_NotifyIconA(NIM_DELETE, &g_nid);
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}
