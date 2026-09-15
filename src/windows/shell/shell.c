#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include <dwmapi.h>
#include <shlobj.h>

#include "capi/cef_app_capi.h"
#include "capi/cef_client_capi.h"
#include "capi/cef_life_span_handler_capi.h"
#include "cef_version_win.h"

#include "shell.h"

#define MIN_WIDTH 900
#define MIN_HEIGHT 620

#define SHELL_BG_COLORREF RGB(0x05, 0x08, 0x0F)
#define SHELL_BG_ARGB 0xFF05080FU

#define SHELL_CLASS "WireCeeShellWindow"

#define WM_WIRECEE_DRAG (WM_APP + 1)

cef_life_span_handler_t g_life_span_handler = {0};
static HWND g_shell_hwnd = NULL;
static HWND g_browser_hwnd = NULL;
static cef_browser_t *g_browser = NULL;
static HBRUSH g_bg_brush = NULL;
static int g_closing = 0;

void initialize_cef_life_span_handler(cef_life_span_handler_t *handler);
void initialize_cef_client(cef_client_t *client);

void CEF_CALLBACK on_after_created(struct _cef_life_span_handler_t *self,
                                   struct _cef_browser_t *browser)
{
    cef_browser_host_t *host;
    RECT client;
    (void)self;

    g_browser = browser;
    if (!browser) return;

    host = browser->get_host(browser);
    if (!host) return;

    g_browser_hwnd = host->get_window_handle(host);

    if (g_browser_hwnd && g_shell_hwnd && GetClientRect(g_shell_hwnd, &client)) {
        SetWindowPos(g_browser_hwnd, NULL, 0, 0, client.right, client.bottom,
                     SWP_NOZORDER | SWP_NOACTIVATE);
    }
}

int CEF_CALLBACK on_do_close(struct _cef_life_span_handler_t *self,
                             struct _cef_browser_t *browser)
{
    (void)self;
    (void)browser;
    return 0;
}

void CEF_CALLBACK on_before_close(struct _cef_life_span_handler_t *self,
                                  struct _cef_browser_t *browser)
{
    (void)self;
    (void)browser;
    g_browser = NULL;
    cef_quit_message_loop();
}

cef_life_span_handler_t *CEF_CALLBACK get_life_span_handler(struct _cef_client_t *self)
{
    (void)self;
    return &g_life_span_handler;
}

void initialize_cef_life_span_handler(cef_life_span_handler_t *handler)
{
    handler->base.size = sizeof(cef_life_span_handler_t);
    handler->on_after_created = on_after_created;
    handler->do_close = on_do_close;
    handler->on_before_close = on_before_close;
}

void initialize_cef_client(cef_client_t *client)
{
    client->base.size = sizeof(cef_client_t);
    client->get_life_span_handler = get_life_span_handler;
}

void CEF_CALLBACK on_before_command_line_processing(
    struct _cef_app_t *self, const cef_string_t *process_type,
    struct _cef_command_line_t *command_line)
{
    static const char *const names[] = {
        "disable-component-update", "no-proxy-server", "disable-background-networking",
        "no-pings", "dns-prefetch-disable", NULL};
    int i;
    (void)self;
    (void)process_type;

    if (!command_line) return;
    for (i = 0; names[i]; i++) {
        cef_string_t switch_name = {0};
        cef_string_utf8_to_utf16(names[i], strlen(names[i]), &switch_name);
        command_line->append_switch(command_line, &switch_name);
        cef_string_clear(&switch_name);
    }
}

static LRESULT CALLBACK shell_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
        case WM_GETMINMAXINFO: {
            MINMAXINFO *mmi = (MINMAXINFO *)lp;
            mmi->ptMinTrackSize.x = MIN_WIDTH;
            mmi->ptMinTrackSize.y = MIN_HEIGHT;
            return 0;
        }

        case WM_WINDOWPOSCHANGING: {
            WINDOWPOS *pos = (WINDOWPOS *)lp;
            if (!(pos->flags & SWP_NOSIZE)) {
                if (pos->cx < MIN_WIDTH) pos->cx = MIN_WIDTH;
                if (pos->cy < MIN_HEIGHT) pos->cy = MIN_HEIGHT;
            }
            break;
        }

        case WM_SIZE:
            if (g_browser_hwnd && wp != SIZE_MINIMIZED) {
                SetWindowPos(g_browser_hwnd, NULL, 0, 0, LOWORD(lp), HIWORD(lp),
                             SWP_NOZORDER | SWP_NOACTIVATE);
            }
            return 0;

        case WM_ERASEBKGND: {
            RECT rc;
            GetClientRect(hwnd, &rc);
            FillRect((HDC)wp, &rc, g_bg_brush);
            return 1;
        }

        case WM_SETFOCUS:
            if (g_browser_hwnd) SetFocus(g_browser_hwnd);
            return 0;

        case WM_CLOSE:
            if (g_browser && !g_closing) {
                cef_browser_host_t *host = g_browser->get_host(g_browser);
                if (host) {
                    g_closing = 1;
                    host->close_browser(host, 1);
                    return 0;
                }
            }
            break;

        case WM_WIRECEE_DRAG:
            SetForegroundWindow(hwnd);
            ReleaseCapture();
            SendMessageA(hwnd, WM_NCLBUTTONDOWN, HTCAPTION, lp);
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

static HWND create_shell_window(HINSTANCE instance)
{
    WNDCLASSA wc = {0};
    RECT work = {0, 0, 1280, 800};
    HWND hwnd;
    int w, h, width, height, x, y;

    g_bg_brush = CreateSolidBrush(SHELL_BG_COLORREF);

    wc.lpfnWndProc = shell_proc;
    wc.hInstance = instance;
    wc.lpszClassName = SHELL_CLASS;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIconA(instance, MAKEINTRESOURCEA(1));
    wc.hbrBackground = g_bg_brush;
    wc.style = CS_HREDRAW | CS_VREDRAW;
    if (!RegisterClassA(&wc)) return NULL;

    SystemParametersInfoA(SPI_GETWORKAREA, 0, &work, 0);
    w = work.right - work.left;
    h = work.bottom - work.top;

    width = (w - 80 < 1180) ? (w - 80) : 1180;
    height = (h - 80 < 780) ? (h - 80) : 780;
    if (width < MIN_WIDTH) width = MIN_WIDTH;
    if (height < MIN_HEIGHT) height = MIN_HEIGHT;

    x = work.left + (w - width) / 2;
    y = work.top + (h - height) / 2;

    hwnd = CreateWindowExA(
        WS_EX_APPWINDOW, SHELL_CLASS, PROGRAM_TITLE,
        WS_POPUP | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX |
            WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        x, y, width, height, NULL, NULL, instance, NULL);

    if (hwnd) {
        COLORREF border = SHELL_BG_COLORREF;
        BOOL dark = TRUE;
        DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, &border, sizeof border);
        DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof dark);
    }
    return hwnd;
}

int main(int argc, char **argv)
{
    cef_main_args_t main_args = {0};
    cef_app_t app = {0};
    cef_settings_t settings = {0};
    cef_client_t client = {0};
    cef_window_info_t window_info = {0};
    cef_browser_settings_t browser_settings = {0};
    cef_string_t cef_url = {0};
    RECT client_rect;
    char url[64];
    const char *port;
    int exit_code;

    main_args.instance = GetModuleHandle(NULL);

    app.base.size = sizeof(cef_app_t);
    app.on_before_command_line_processing = on_before_command_line_processing;

    exit_code = cef_execute_process(&main_args, &app, NULL);
    if (exit_code >= 0) {
        return exit_code;
    }

    port = (argc > 1) ? argv[1] : NULL;
    if (!port || !*port) {
        fprintf(stderr,
                "WireCeeUI: no port given.\n"
                "This is launched by WireCee.exe, not run directly.\n"
                "Usage: WireCeeUI.exe <port>\n");
        return 2;
    }
    _snprintf_s(url, sizeof url, _TRUNCATE, "http://127.0.0.1:%s/", port);

    settings.size = sizeof(cef_settings_t);
    settings.no_sandbox = 1;
    settings.log_severity = LOGSEVERITY_WARNING;
    settings.background_color = SHELL_BG_ARGB;

    {
        char base[MAX_PATH], cache[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, base))) {
            _snprintf_s(cache, sizeof cache, _TRUNCATE,
                        "%s\\TakeGuard\\WireCee\\cef", base);
            SHCreateDirectoryExA(NULL, cache, NULL);
            cef_string_utf8_to_utf16(cache, strlen(cache), &settings.root_cache_path);
            cef_string_utf8_to_utf16(cache, strlen(cache), &settings.cache_path);
        }
    }

    if (!cef_initialize(&main_args, &settings, &app, NULL)) {
        fprintf(stderr, "CEF initialization failed\n");
        return 1;
    }

    initialize_cef_client(&client);
    initialize_cef_life_span_handler(&g_life_span_handler);

    g_shell_hwnd = create_shell_window(main_args.instance);
    if (!g_shell_hwnd) {
        fprintf(stderr, "Could not create the shell window\n");
        cef_shutdown();
        return 1;
    }

    GetClientRect(g_shell_hwnd, &client_rect);
    window_info.parent_window = g_shell_hwnd;
    window_info.style = WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS;
    window_info.bounds.x = 0;
    window_info.bounds.y = 0;
    window_info.bounds.width = client_rect.right;
    window_info.bounds.height = client_rect.bottom;

    cef_string_utf8_to_utf16(url, strlen(url), &cef_url);

    browser_settings.size = sizeof(cef_browser_settings_t);
    browser_settings.background_color = SHELL_BG_ARGB;

    if (!cef_browser_host_create_browser(&window_info, &client, &cef_url,
                                         &browser_settings, NULL, NULL)) {
        fprintf(stderr, "Failed to create browser\n");
        cef_shutdown();
        return 1;
    }

    ShowWindow(g_shell_hwnd, SW_SHOW);
    UpdateWindow(g_shell_hwnd);

    cef_run_message_loop();
    cef_shutdown();

    if (g_bg_brush) DeleteObject(g_bg_brush);
    return 0;
}
