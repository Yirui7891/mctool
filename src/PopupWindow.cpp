#include "PopupWindow.h"
#include <shellapi.h>
#include <cstdio>
#include <commctrl.h>
#include <gdiplus.h>
#include <wincrypt.h>

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "comctl32.lib")

using namespace Gdiplus;

// ---------- 静态辅助函数 ----------
std::wstring PopupWindow::UTF8ToWide(const std::string& utf8) {
    if (utf8.empty()) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
    std::wstring wstr(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &wstr[0], len);
    return wstr;
}

std::string PopupWindow::WideToUTF8(const std::wstring& wide) {
    if (wide.empty()) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, NULL, 0, NULL, NULL);
    std::string utf8(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &utf8[0], len, NULL, NULL);
    return utf8;
}

// ---------- 服务器管理对话框窗口过程 ----------
static LRESULT CALLBACK ManageDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    static Config* s_pConfig = nullptr;
    static HWND s_hList = nullptr;

    switch (msg) {
        case WM_NCCREATE: {
            CREATESTRUCTW* pCreate = (CREATESTRUCTW*)lParam;
            SetWindowLongPtr(hDlg, GWLP_USERDATA, (LONG_PTR)pCreate->lpCreateParams);
            return DefWindowProcW(hDlg, msg, wParam, lParam);
        }
        case WM_INITDIALOG: {
            s_pConfig = (Config*)GetWindowLongPtr(hDlg, GWLP_USERDATA);
            HINSTANCE hInst = (HINSTANCE)GetWindowLongPtr(hDlg, GWLP_HINSTANCE);
            s_hList = CreateWindowW(WC_LISTVIEWW, NULL,
                WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_EDITLABELS,
                10, 10, 380, 180, hDlg, (HMENU)1001, hInst, NULL);
            ListView_SetExtendedListViewStyle(s_hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
            LVCOLUMNW lvc = {0};
            lvc.mask = LVCF_TEXT | LVCF_WIDTH;
            lvc.cx = 250;
            lvc.pszText = L"服务器地址";
            ListView_InsertColumn(s_hList, 0, &lvc);
            lvc.cx = 80;
            lvc.pszText = L"端口";
            ListView_InsertColumn(s_hList, 1, &lvc);
            for (size_t i = 0; i < s_pConfig->servers.size(); ++i) {
                LVITEMW lvi = {0};
                lvi.mask = LVIF_TEXT;
                lvi.iItem = (int)i;
                std::wstring hostW = PopupWindow::UTF8ToWide(s_pConfig->servers[i].host);
                lvi.pszText = (LPWSTR)hostW.c_str();
                ListView_InsertItem(s_hList, &lvi);
                wchar_t portStr[16];
                swprintf(portStr, 16, L"%d", s_pConfig->servers[i].port);
                // 使用 SendMessage 设置子项文本
                LVITEMW item = {0};
                item.iSubItem = 1;
                item.pszText = portStr;
                SendMessageW(s_hList, LVM_SETITEMTEXTW, (WPARAM)i, (LPARAM)&item);
            }
            // 按钮创建部分不变...
            CreateWindowW(L"BUTTON", L"添加", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, 200, 60, 25, hDlg, (HMENU)1002, hInst, NULL);
            CreateWindowW(L"BUTTON", L"编辑", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                80, 200, 60, 25, hDlg, (HMENU)1003, hInst, NULL);
            CreateWindowW(L"BUTTON", L"删除", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                150, 200, 60, 25, hDlg, (HMENU)1004, hInst, NULL);
            CreateWindowW(L"BUTTON", L"上移", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                220, 200, 60, 25, hDlg, (HMENU)1005, hInst, NULL);
            CreateWindowW(L"BUTTON", L"下移", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                290, 200, 60, 25, hDlg, (HMENU)1006, hInst, NULL);
            CreateWindowW(L"BUTTON", L"测试连接", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, 235, 100, 25, hDlg, (HMENU)1007, hInst, NULL);
            CreateWindowW(L"BUTTON", L"确定", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                310, 235, 70, 25, hDlg, (HMENU)IDOK, hInst, NULL);
            return TRUE;
        }
        case WM_COMMAND: {
            int id = LOWORD(wParam);
            HWND hList = s_hList;
            if (id == IDOK) {
                int count = ListView_GetItemCount(hList);
                s_pConfig->servers.clear();
                for (int i = 0; i < count; ++i) {
                    wchar_t host[256];
                    wchar_t portStr[16];
                    // 获取主项文本
                    LVITEMW item = {0};
                    item.iSubItem = 0;
                    item.pszText = host;
                    item.cchTextMax = 256;
                    SendMessageW(hList, LVM_GETITEMTEXTW, i, (LPARAM)&item);
                    // 获取子项文本
                    LVITEMW item2 = {0};
                    item2.iSubItem = 1;
                    item2.pszText = portStr;
                    item2.cchTextMax = 16;
                    SendMessageW(hList, LVM_GETITEMTEXTW, i, (LPARAM)&item2);
                    ServerInfo si;
                    si.host = PopupWindow::WideToUTF8(host);
                    si.port = _wtoi(portStr);
                    if (!si.host.empty() && si.port > 0 && si.port <= 65535) {
                        s_pConfig->servers.push_back(si);
                    }
                }
                wchar_t modulePath[MAX_PATH];
                GetModuleFileNameW(NULL, modulePath, MAX_PATH);
                std::wstring ws(modulePath);
                std::string exePath(ws.begin(), ws.end());
                size_t pos = exePath.find_last_of("\\");
                std::string configPath = exePath.substr(0, pos + 1) + "config.json";
                s_pConfig->Save(configPath);
                DestroyWindow(hDlg);
                return TRUE;
            }
            else if (id == 1002) { // 添加
                wchar_t host[256] = L"example.com";
                wchar_t portStr[16] = L"25565";
                int newIndex = ListView_GetItemCount(hList);
                LVITEMW lvi = {0};
                lvi.mask = LVIF_TEXT;
                lvi.iItem = newIndex;
                lvi.pszText = host;
                ListView_InsertItem(hList, &lvi);
                LVITEMW item = {0};
                item.iSubItem = 1;
                item.pszText = portStr;
                SendMessageW(hList, LVM_SETITEMTEXTW, (WPARAM)newIndex, (LPARAM)&item);
            }
            else if (id == 1003) { // 编辑
                int sel = ListView_GetSelectionMark(hList);
                if (sel >= 0) {
                    wchar_t host[256];
                    wchar_t portStr[16];
                    LVITEMW item = {0};
                    item.iSubItem = 0;
                    item.pszText = host;
                    item.cchTextMax = 256;
                    SendMessageW(hList, LVM_GETITEMTEXTW, sel, (LPARAM)&item);
                    LVITEMW item2 = {0};
                    item2.iSubItem = 1;
                    item2.pszText = portStr;
                    item2.cchTextMax = 16;
                    SendMessageW(hList, LVM_GETITEMTEXTW, sel, (LPARAM)&item2);
                    MessageBoxW(hDlg, L"编辑功能待完善", L"提示", MB_OK);
                }
            }
            else if (id == 1004) { // 删除
                int sel = ListView_GetSelectionMark(hList);
                if (sel >= 0) {
                    ListView_DeleteItem(hList, sel);
                }
            }
            else if (id == 1005) { // 上移
                int sel = ListView_GetSelectionMark(hList);
                if (sel > 0) {
                    wchar_t host1[256], host2[256];
                    wchar_t port1[16], port2[16];
                    LVITEMW item1 = {0};
                    item1.iSubItem = 0;
                    item1.pszText = host1;
                    item1.cchTextMax = 256;
                    SendMessageW(hList, LVM_GETITEMTEXTW, sel, (LPARAM)&item1);
                    LVITEMW item1p = {0};
                    item1p.iSubItem = 1;
                    item1p.pszText = port1;
                    item1p.cchTextMax = 16;
                    SendMessageW(hList, LVM_GETITEMTEXTW, sel, (LPARAM)&item1p);
                    LVITEMW item2 = {0};
                    item2.iSubItem = 0;
                    item2.pszText = host2;
                    item2.cchTextMax = 256;
                    SendMessageW(hList, LVM_GETITEMTEXTW, sel-1, (LPARAM)&item2);
                    LVITEMW item2p = {0};
                    item2p.iSubItem = 1;
                    item2p.pszText = port2;
                    item2p.cchTextMax = 16;
                    SendMessageW(hList, LVM_GETITEMTEXTW, sel-1, (LPARAM)&item2p);
                    // 设置新值
                    LVITEMW set1 = {0};
                    set1.iSubItem = 0;
                    set1.pszText = host2;
                    SendMessageW(hList, LVM_SETITEMTEXTW, sel, (LPARAM)&set1);
                    LVITEMW set1p = {0};
                    set1p.iSubItem = 1;
                    set1p.pszText = port2;
                    SendMessageW(hList, LVM_SETITEMTEXTW, sel, (LPARAM)&set1p);
                    LVITEMW set2 = {0};
                    set2.iSubItem = 0;
                    set2.pszText = host1;
                    SendMessageW(hList, LVM_SETITEMTEXTW, sel-1, (LPARAM)&set2);
                    LVITEMW set2p = {0};
                    set2p.iSubItem = 1;
                    set2p.pszText = port1;
                    SendMessageW(hList, LVM_SETITEMTEXTW, sel-1, (LPARAM)&set2p);
                    ListView_SetSelectionMark(hList, sel-1);
                }
            }
            else if (id == 1006) { // 下移
                int sel = ListView_GetSelectionMark(hList);
                int count = ListView_GetItemCount(hList);
                if (sel >= 0 && sel < count-1) {
                    wchar_t host1[256], host2[256];
                    wchar_t port1[16], port2[16];
                    LVITEMW item1 = {0};
                    item1.iSubItem = 0;
                    item1.pszText = host1;
                    item1.cchTextMax = 256;
                    SendMessageW(hList, LVM_GETITEMTEXTW, sel, (LPARAM)&item1);
                    LVITEMW item1p = {0};
                    item1p.iSubItem = 1;
                    item1p.pszText = port1;
                    item1p.cchTextMax = 16;
                    SendMessageW(hList, LVM_GETITEMTEXTW, sel, (LPARAM)&item1p);
                    LVITEMW item2 = {0};
                    item2.iSubItem = 0;
                    item2.pszText = host2;
                    item2.cchTextMax = 256;
                    SendMessageW(hList, LVM_GETITEMTEXTW, sel+1, (LPARAM)&item2);
                    LVITEMW item2p = {0};
                    item2p.iSubItem = 1;
                    item2p.pszText = port2;
                    item2p.cchTextMax = 16;
                    SendMessageW(hList, LVM_GETITEMTEXTW, sel+1, (LPARAM)&item2p);
                    LVITEMW set1 = {0};
                    set1.iSubItem = 0;
                    set1.pszText = host2;
                    SendMessageW(hList, LVM_SETITEMTEXTW, sel, (LPARAM)&set1);
                    LVITEMW set1p = {0};
                    set1p.iSubItem = 1;
                    set1p.pszText = port2;
                    SendMessageW(hList, LVM_SETITEMTEXTW, sel, (LPARAM)&set1p);
                    LVITEMW set2 = {0};
                    set2.iSubItem = 0;
                    set2.pszText = host1;
                    SendMessageW(hList, LVM_SETITEMTEXTW, sel+1, (LPARAM)&set2);
                    LVITEMW set2p = {0};
                    set2p.iSubItem = 1;
                    set2p.pszText = port1;
                    SendMessageW(hList, LVM_SETITEMTEXTW, sel+1, (LPARAM)&set2p);
                    ListView_SetSelectionMark(hList, sel+1);
                }
            }
            else if (id == 1007) { // 测试连接
                int sel = ListView_GetSelectionMark(hList);
                if (sel >= 0) {
                    wchar_t host[256];
                    wchar_t portStr[16];
                    LVITEMW item = {0};
                    item.iSubItem = 0;
                    item.pszText = host;
                    item.cchTextMax = 256;
                    SendMessageW(hList, LVM_GETITEMTEXTW, sel, (LPARAM)&item);
                    LVITEMW item2 = {0};
                    item2.iSubItem = 1;
                    item2.pszText = portStr;
                    item2.cchTextMax = 16;
                    SendMessageW(hList, LVM_GETITEMTEXTW, sel, (LPARAM)&item2);
                    std::string hostA = PopupWindow::WideToUTF8(host);
                    int port = _wtoi(portStr);
                    ServerStatus status;
                    if (PingServer(hostA, port, status)) {
                        wchar_t msg[512];
                        swprintf(msg, 512, L"在线 - 延迟: %d ms\n玩家: %d/%d\n版本: %s",
                            status.latency, status.players, status.maxPlayers,
                            PopupWindow::UTF8ToWide(status.version).c_str());
                        MessageBoxW(hDlg, msg, L"测试结果", MB_OK);
                    } else {
                        MessageBoxW(hDlg, L"连接失败", L"测试结果", MB_OK);
                    }
                }
            }
            break;
        }
        case WM_CLOSE:
            DestroyWindow(hDlg);
            return TRUE;
    }
    return DefWindowProcW(hDlg, msg, wParam, lParam);
}
// ---------- PopupWindow 实现 ----------
PopupWindow::PopupWindow() 
    : m_hWnd(NULL), m_hServerAddressStatic(NULL), m_hServerStatusStatic(NULL),
      m_hBkBrush(NULL), m_hHoverButton(NULL), m_hNormalFont(NULL), m_hBoldFont(NULL),
      m_hExitButton(NULL), m_hSwitchButton(NULL), m_hManageButton(NULL),
      m_lastX(0), m_autoHideScheduled(false),
      m_hFaviconStatic(NULL), m_pFaviconBitmap(NULL), m_gdiplusToken(0) {
    for (int i = 0; i < 4; ++i) m_hShortcutButtons[i] = NULL;
}

PopupWindow::~PopupWindow() {
    if (m_pFaviconBitmap) delete m_pFaviconBitmap;
    if (m_hWnd) DestroyWindow(m_hWnd);
    if (m_hBkBrush) DeleteObject(m_hBkBrush);
    if (m_hNormalFont) DeleteObject(m_hNormalFont);
    if (m_hBoldFont) DeleteObject(m_hBoldFont);
    if (m_gdiplusToken) GdiplusShutdown(m_gdiplusToken);
}

LRESULT CALLBACK PopupWindow::ButtonSubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    PopupWindow* pThis = reinterpret_cast<PopupWindow*>(dwRefData);
    if (!pThis) return DefSubclassProc(hWnd, msg, wParam, lParam);

    switch (msg) {
        case WM_MOUSEMOVE: {
            PostMessage(pThis->m_hWnd, WM_UPDATE_HOVER, (WPARAM)hWnd, 0);
            TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hWnd, 0 };
            TrackMouseEvent(&tme);
            break;
        }
        case WM_MOUSELEAVE: {
            PostMessage(pThis->m_hWnd, WM_UPDATE_HOVER, 0, 0);
            break;
        }
    }
    return DefSubclassProc(hWnd, msg, wParam, lParam);
}

bool PopupWindow::Create(HWND hParent, HINSTANCE hInst, const Config& cfg) {
    m_config = cfg;

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = NULL;
    wc.lpszClassName = L"PopupClass";
    RegisterClassExW(&wc);

    m_hWnd = CreateWindowExW(
        WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
        L"PopupClass", NULL,
        WS_POPUP,
        0, 0, cfg.popupWidth, cfg.popupHeight,
        hParent, NULL, hInst, this);
    if (!m_hWnd) return false;

    // 初始化 GDI+
    GdiplusStartupInput gdiplusStartupInput;
    GdiplusStartup(&m_gdiplusToken, &gdiplusStartupInput, NULL);

    m_hBkBrush = CreateSolidBrush(RGB(32, 32, 32));

    LOGFONTW lf = {0};
    lf.lfHeight = -14;
    lf.lfWeight = FW_NORMAL;
    lf.lfCharSet = DEFAULT_CHARSET;
    wcscpy_s(lf.lfFaceName, L"Segoe UI");
    m_hNormalFont = CreateFontIndirectW(&lf);

    lf.lfWeight = FW_BOLD;
    m_hBoldFont = CreateFontIndirectW(&lf);

    // 服务器地址标签（标题）
    CreateWindowW(L"STATIC", L"当前服务器", WS_CHILD | WS_VISIBLE,
        10, 10, 380, 20, m_hWnd, NULL, hInst, NULL);
    m_hServerAddressStatic = CreateWindowW(L"STATIC", L"未知", WS_CHILD | WS_VISIBLE,
        10, 30, 380, 20, m_hWnd, (HMENU)IDC_SERVER_STATUS, hInst, NULL);
    SendMessageW(m_hServerAddressStatic, WM_SETFONT, (WPARAM)m_hNormalFont, TRUE);

    CreateWindowW(L"STATIC", L"服务器状态", WS_CHILD | WS_VISIBLE,
        10, 60, 380, 20, m_hWnd, NULL, hInst, NULL);
    
    // 服务器状态文字区域
    m_hServerStatusStatic = CreateWindowW(L"STATIC", L"未知", WS_CHILD | WS_VISIBLE,
        10, 80, 310, 90, m_hWnd, (HMENU)(IDC_SERVER_STATUS + 1), hInst, NULL);
    SendMessageW(m_hServerStatusStatic, WM_SETFONT, (WPARAM)m_hNormalFont, TRUE);

    // favicon 控件
    m_hFaviconStatic = CreateWindowW(L"STATIC", NULL, WS_CHILD | WS_VISIBLE | SS_BITMAP,
        320, 80, 32, 32, m_hWnd, NULL, hInst, NULL);
    SendMessageW(m_hFaviconStatic, STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)NULL);

    // 快捷按钮
    int btnWidth = (cfg.popupWidth - 50) / 4;
    for (int i = 0; i < 4 && i < (int)cfg.shortcuts.size(); ++i) {
        m_hShortcutButtons[i] = CreateWindowW(
            L"BUTTON",
            UTF8ToWide(cfg.shortcuts[i].name).c_str(),
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            10 + i * (btnWidth + 10), 190, btnWidth, 30,
            m_hWnd, (HMENU)(IDC_SHORTCUT1 + i), hInst, NULL);
        SendMessageW(m_hShortcutButtons[i], WM_SETFONT, (WPARAM)m_hNormalFont, TRUE);
        SetWindowSubclass(m_hShortcutButtons[i], ButtonSubclassProc, 0, (DWORD_PTR)this);
    }

    // 启动游戏按钮
    HWND hLaunch = CreateWindowW(L"BUTTON", L"启动游戏", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        150, 230, 100, 30, m_hWnd, (HMENU)IDC_LAUNCH_BUTTON, hInst, NULL);
    SendMessageW(hLaunch, WM_SETFONT, (WPARAM)m_hNormalFont, TRUE);
    SetWindowSubclass(hLaunch, ButtonSubclassProc, 0, (DWORD_PTR)this);

    // 切换服务器按钮
    m_hSwitchButton = CreateWindowW(L"BUTTON", L"切换服务器", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        260, 230, 100, 30, m_hWnd, (HMENU)IDC_SWITCH_BUTTON, hInst, NULL);
    SendMessageW(m_hSwitchButton, WM_SETFONT, (WPARAM)m_hNormalFont, TRUE);
    SetWindowSubclass(m_hSwitchButton, ButtonSubclassProc, 0, (DWORD_PTR)this);

    // 管理服务器按钮
    m_hManageButton = CreateWindowW(L"BUTTON", L"管理服务器", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        150, 270, 100, 30, m_hWnd, (HMENU)IDC_MANAGE_BUTTON, hInst, NULL);
    SendMessageW(m_hManageButton, WM_SETFONT, (WPARAM)m_hNormalFont, TRUE);
    SetWindowSubclass(m_hManageButton, ButtonSubclassProc, 0, (DWORD_PTR)this);

    // 退出按钮
    m_hExitButton = CreateWindowW(L"BUTTON", L"×", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        cfg.popupWidth - 30, 0, 30, 30,
        m_hWnd, (HMENU)IDC_EXIT_BUTTON, hInst, NULL);
    SendMessageW(m_hExitButton, WM_SETFONT, (WPARAM)m_hNormalFont, TRUE);
    SetWindowSubclass(m_hExitButton, ButtonSubclassProc, 0, (DWORD_PTR)this);

    TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, m_hWnd, 0 };
    TrackMouseEvent(&tme);

    return true;
}

void PopupWindow::Show() {
    if (IsWindowVisible(m_hWnd)) return;
    int x = (m_lastX != 0) ? m_lastX : (GetSystemMetrics(SM_CXSCREEN) - m_config.popupWidth) / 2;
    SetWindowPos(m_hWnd, HWND_TOPMOST, x, 0, m_config.popupWidth, m_config.popupHeight, SWP_NOZORDER);
    AnimateWindow(m_hWnd, 200, AW_SLIDE | AW_VER_POSITIVE | AW_ACTIVATE);
    m_hHoverButton = NULL;
    CancelAutoHide();
    TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, m_hWnd, 0 };
    TrackMouseEvent(&tme);
}

void PopupWindow::Hide() {
    if (!IsWindowVisible(m_hWnd)) return;
    UpdateLastX();
    AnimateWindow(m_hWnd, 200, AW_SLIDE | AW_VER_NEGATIVE | AW_HIDE);
    CancelAutoHide();
}

void PopupWindow::UpdateLastX() {
    RECT rc;
    GetWindowRect(m_hWnd, &rc);
    m_lastX = rc.left;
}

void PopupWindow::AdhereToTop() {
    if (!IsWindowVisible(m_hWnd)) return;
    RECT rc;
    GetWindowRect(m_hWnd, &rc);
    int x = rc.left;
    SetWindowPos(m_hWnd, HWND_TOPMOST, x, 0, m_config.popupWidth, m_config.popupHeight, SWP_NOZORDER);
    UpdateLastX();
    ScheduleAutoHide();
}

void PopupWindow::ScheduleAutoHide() {
    if (m_autoHideScheduled) return;
    SetTimer(m_hWnd, 100, 2000, NULL);
    m_autoHideScheduled = true;
}

void PopupWindow::CancelAutoHide() {
    if (m_autoHideScheduled) {
        KillTimer(m_hWnd, 100);
        m_autoHideScheduled = false;
    }
}

void PopupWindow::OnAutoHideTimer() {
    KillTimer(m_hWnd, 100);
    m_autoHideScheduled = false;
    if (IsWindowVisible(m_hWnd)) {
        POINT pt;
        GetCursorPos(&pt);
        RECT rc;
        GetWindowRect(m_hWnd, &rc);
        if (!PtInRect(&rc, pt)) {
            Hide();
        }
    }
}

void PopupWindow::SetCurrentServerInfo() {
    if (!m_hServerAddressStatic || !m_hServerStatusStatic) return;
    if (!m_config.servers.empty()) {
        int idx = m_config.currentServer;
        std::string addr = m_config.servers[idx].host + ":" + std::to_string(m_config.servers[idx].port);
        SetWindowTextW(m_hServerAddressStatic, UTF8ToWide(addr).c_str());
        SetWindowTextW(m_hServerStatusStatic, L"检测中...");
    } else {
        SetWindowTextW(m_hServerAddressStatic, L"无服务器配置");
        SetWindowTextW(m_hServerStatusStatic, L"");
    }
    InvalidateRect(m_hServerAddressStatic, NULL, TRUE);
    InvalidateRect(m_hServerStatusStatic, NULL, TRUE);
    UpdateWindow(m_hServerAddressStatic);
    UpdateWindow(m_hServerStatusStatic);
}

void PopupWindow::UpdateServerStatus(const ServerStatus& status) {
    if (m_hServerStatusStatic) {
        std::wstring text;
        if (status.online) {
            wchar_t buf[2048];
            swprintf(buf, 2048, L"在线 - %s\n%d/%d 玩家\n版本: %s\n延迟: %d ms",
                UTF8ToWide(status.motd).c_str(),
                status.players, status.maxPlayers,
                UTF8ToWide(status.version).c_str(),
                status.latency);
            text = buf;
            if (!status.mods.empty()) {
                text += L"\n模组: ";
                for (size_t i = 0; i < status.mods.size() && i < 3; ++i) {
                    if (i > 0) text += L", ";
                    text += UTF8ToWide(status.mods[i].modid);
                }
                if (status.mods.size() > 3) text += L" ...";
            }
        } else {
            text = L"离线";
        }
        SetWindowTextW(m_hServerStatusStatic, text.c_str());
        InvalidateRect(m_hServerStatusStatic, NULL, TRUE);
        UpdateWindow(m_hServerStatusStatic);
    }

    if (m_hFaviconStatic) {
        if (m_pFaviconBitmap) {
            delete m_pFaviconBitmap;
            m_pFaviconBitmap = NULL;
        }
        if (!status.favicon_base64.empty()) {
            m_pFaviconBitmap = Base64ToBitmap(status.favicon_base64);
            if (m_pFaviconBitmap) {
                HBITMAP hBitmap = NULL;
                m_pFaviconBitmap->GetHBITMAP(Color(0,0,0), &hBitmap);
                if (hBitmap) {
                    SendMessageW(m_hFaviconStatic, STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)hBitmap);
                }
            }
        } else {
            SendMessageW(m_hFaviconStatic, STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)NULL);
        }
    }
}

void PopupWindow::SyncCurrentServerIndex(int idx) {
    if (idx >= 0 && idx < (int)m_config.servers.size()) {
        m_config.currentServer = idx;
        SetCurrentServerInfo();
    }
}

void PopupWindow::OnManageServers() {
    // 注册对话框窗口类
    HINSTANCE hInst = (HINSTANCE)GetWindowLongPtr(m_hWnd, GWLP_HINSTANCE);
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = ManageDlgProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"ManageDlgClass";
    RegisterClassExW(&wc);
    HWND hDlg = CreateWindowExW(0, L"ManageDlgClass", L"服务器管理",
        WS_OVERLAPPEDWINDOW | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, 420, 300, m_hWnd, NULL, hInst, (LPVOID)&m_config);
    if (hDlg) {
        ShowWindow(hDlg, SW_SHOW);
        // 模态循环
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0)) {
            if (!IsDialogMessage(hDlg, &msg)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
            if (!IsWindow(hDlg)) break;
        }
    }
    // 刷新当前显示
    SetCurrentServerInfo();
    // 通知主窗口重新 ping
    SendMessage(GetParent(m_hWnd), WM_COMMAND, IDC_SWITCH_BUTTON, 0);
}

bool PopupWindow::IsButton(HWND hWnd) {
    for (int i = 0; i < 4; ++i) {
        if (hWnd == m_hShortcutButtons[i]) return true;
    }
    HWND hLaunch = GetDlgItem(m_hWnd, IDC_LAUNCH_BUTTON);
    return (hWnd == hLaunch || hWnd == m_hExitButton || hWnd == m_hSwitchButton || hWnd == m_hManageButton);
}

void PopupWindow::SetHoverButton(HWND hBtn) {
    if (m_hHoverButton == hBtn) return;
    HWND oldHover = m_hHoverButton;
    m_hHoverButton = hBtn;
    if (oldHover) InvalidateRect(oldHover, NULL, TRUE);
    if (m_hHoverButton) InvalidateRect(m_hHoverButton, NULL, TRUE);
}

Gdiplus::Bitmap* PopupWindow::CreateBitmapFromData(const BYTE* data, size_t len) {
    HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, len);
    if (!hGlobal) return NULL;
    void* pMem = GlobalLock(hGlobal);
    if (!pMem) {
        GlobalFree(hGlobal);
        return NULL;
    }
    memcpy(pMem, data, len);
    GlobalUnlock(hGlobal);
    IStream* pStream = NULL;
    if (CreateStreamOnHGlobal(hGlobal, TRUE, &pStream) != S_OK) {
        GlobalFree(hGlobal);
        return NULL;
    }
    Gdiplus::Bitmap* pBitmap = Gdiplus::Bitmap::FromStream(pStream);
    pStream->Release();
    return pBitmap;
}

Gdiplus::Bitmap* PopupWindow::Base64ToBitmap(const std::string& base64Data) {
    size_t commaPos = base64Data.find(',');
    std::string data = (commaPos != std::string::npos) ? base64Data.substr(commaPos + 1) : base64Data;
    DWORD decodedLen = 0;
    if (!CryptStringToBinaryA(data.c_str(), data.size(), CRYPT_STRING_BASE64, NULL, &decodedLen, NULL, NULL)) {
        return NULL;
    }
    std::vector<BYTE> decoded(decodedLen);
    if (!CryptStringToBinaryA(data.c_str(), data.size(), CRYPT_STRING_BASE64, decoded.data(), &decodedLen, NULL, NULL)) {
        return NULL;
    }
    return CreateBitmapFromData(decoded.data(), decodedLen);
}

LRESULT CALLBACK PopupWindow::WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    PopupWindow* pThis = nullptr;
    if (msg == WM_NCCREATE) {
        pThis = (PopupWindow*)((CREATESTRUCT*)lParam)->lpCreateParams;
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pThis);
    } else {
        pThis = (PopupWindow*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    }

    if (!pThis) return DefWindowProcW(hWnd, msg, wParam, lParam);

    switch (msg) {
        case WM_UPDATE_HOVER: {
            HWND hBtn = (HWND)wParam;
            pThis->SetHoverButton(hBtn);
            return 0;
        }
        case WM_NCHITTEST: {
            POINT pt = { LOWORD(lParam), HIWORD(lParam) };
            ScreenToClient(hWnd, &pt);
            if (pt.y < 30) {
                return HTCAPTION;
            }
            break;
        }
        case WM_MOVING: {
            RECT* pRect = (RECT*)lParam;
            int height = pRect->bottom - pRect->top;
            pRect->top = 0;
            pRect->bottom = height;
            return TRUE;
        }
        case WM_EXITSIZEMOVE: {
            pThis->UpdateLastX();
            break;
        }
        case WM_MOUSELEAVE: {
            pThis->SetHoverButton(NULL);
            pThis->AdhereToTop();
            break;
        }
        case WM_TIMER:
            if (wParam == 100) {
                pThis->OnAutoHideTimer();
            }
            break;
        case WM_ERASEBKGND: {
            HDC hdc = (HDC)wParam;
            RECT rc;
            GetClientRect(hWnd, &rc);
            FillRect(hdc, &rc, pThis->m_hBkBrush);
            return TRUE;
        }
        case WM_CTLCOLORSTATIC: {
            HDC hdcStatic = (HDC)wParam;
            SetTextColor(hdcStatic, RGB(240, 240, 240));
            SetBkColor(hdcStatic, RGB(32, 32, 32));
            return (LRESULT)pThis->m_hBkBrush;
        }
        case WM_DRAWITEM: {
            LPDRAWITEMSTRUCT lpDIS = (LPDRAWITEMSTRUCT)lParam;
            if (lpDIS->CtlType == ODT_BUTTON) {
                wchar_t text[256];
                GetWindowTextW(lpDIS->hwndItem, text, 256);
                HDC hdc = lpDIS->hDC;
                SetBkMode(hdc, TRANSPARENT);

                bool bHover = (lpDIS->hwndItem == pThis->m_hHoverButton);
                bool bPressed = (lpDIS->itemState & ODS_SELECTED);

                COLORREF bgColor;
                if (lpDIS->hwndItem == pThis->m_hExitButton) {
                    if (bPressed)
                        bgColor = RGB(40, 20, 20);
                    else if (bHover)
                        bgColor = RGB(60, 30, 30);
                    else
                        bgColor = RGB(80, 40, 40);
                } else {
                    if (bPressed)
                        bgColor = RGB(30, 30, 30);
                    else if (bHover)
                        bgColor = RGB(40, 40, 40);
                    else
                        bgColor = RGB(60, 60, 60);
                }

                HBRUSH bgBrush = CreateSolidBrush(bgColor);
                FillRect(hdc, &lpDIS->rcItem, bgBrush);
                DeleteObject(bgBrush);

                COLORREF borderColor = bHover ? RGB(200, 200, 200) : RGB(80, 80, 80);
                HPEN pen = CreatePen(PS_SOLID, 1, borderColor);
                SelectObject(hdc, pen);
                SelectObject(hdc, GetStockObject(NULL_BRUSH));
                Rectangle(hdc, lpDIS->rcItem.left, lpDIS->rcItem.top,
                          lpDIS->rcItem.right, lpDIS->rcItem.bottom);
                DeleteObject(pen);

                COLORREF textColor = bHover ? RGB(255, 220, 100) : RGB(220, 220, 220);
                SetTextColor(hdc, textColor);
                HFONT hOldFont = (HFONT)SelectObject(hdc, bHover ? pThis->m_hBoldFont : pThis->m_hNormalFont);
                DrawTextW(hdc, text, -1, &lpDIS->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                SelectObject(hdc, hOldFont);
                return TRUE;
            }
            break;
        }
        case WM_COMMAND: {
            int id = LOWORD(wParam);
            if (id >= IDC_SHORTCUT1 && id <= IDC_SHORTCUT4) {
                int index = id - IDC_SHORTCUT1;
                if (index < (int)pThis->m_config.shortcuts.size()) {
                    const std::string& url = pThis->m_config.shortcuts[index].url;
                    ShellExecuteA(NULL, "open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);
                }
                break;
            } else if (id == IDC_LAUNCH_BUTTON) {
                SendMessage(GetParent(hWnd), WM_COMMAND, IDC_LAUNCH_BUTTON, 0);
            } else if (id == IDC_EXIT_BUTTON) {
                PostQuitMessage(0);
            } else if (id == IDC_SWITCH_BUTTON) {
                SendMessage(GetParent(hWnd), WM_COMMAND, IDC_SWITCH_BUTTON, 0);
            } else if (id == IDC_MANAGE_BUTTON) {
                pThis->OnManageServers();
            }
            break;
        }
        case WM_DESTROY:
            break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}