#include "PopupWindow.h"
#include <string>
#include <vector>

void PopupWindow::Show() {
    // 原有的显示代码...
    SetWindowPos(...);

    // 临时测试：手动构造一个假状态
    ServerStatus testStatus;
    testStatus.online = true;
    testStatus.motd = "Test Server";
    testStatus.players = 10;
    testStatus.maxPlayers = 20;
    testStatus.version = "1.19.2";
    testStatus.latency = 45;
    UpdateServerStatus(testStatus);
}

// 辅助函数：UTF-8 转宽字符串
static std::wstring UTF8ToWide(const std::string& utf8) {
    if (utf8.empty()) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
    std::wstring wstr(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &wstr[0], len);
    return wstr;
}

PopupWindow::PopupWindow() : m_hWnd(NULL), m_hServerStatic(NULL), m_hNewsEdit(NULL) {}
PopupWindow::~PopupWindow() { if (m_hWnd) DestroyWindow(m_hWnd); }

bool PopupWindow::Create(HWND hParent, HINSTANCE hInst, const Config& cfg) {
    m_config = cfg;

    WNDCLASSEXW wc = { sizeof(WNDCLASSEXW) };
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"PopupClass";
    RegisterClassExW(&wc);

    m_hWnd = CreateWindowExW(
        WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
        L"PopupClass", NULL,
        WS_POPUP | WS_BORDER,
        0, 0, cfg.popupWidth, cfg.popupHeight,
        hParent, NULL, hInst, this);

    if (!m_hWnd) return false;

    // 创建子控件，使用宽字符
    CreateWindowW(L"STATIC", L"游戏新闻", WS_CHILD | WS_VISIBLE,
        10, 10, 380, 20, m_hWnd, NULL, hInst, NULL);
    m_hNewsEdit = CreateWindowW(L"EDIT", NULL, WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
        10, 30, 380, 100, m_hWnd, (HMENU)IDC_NEWS_CONTENT, hInst, NULL);

    CreateWindowW(L"STATIC", L"服务器状态", WS_CHILD | WS_VISIBLE,
        10, 140, 380, 20, m_hWnd, NULL, hInst, NULL);
    m_hServerStatic = CreateWindowW(L"STATIC", L"未知", WS_CHILD | WS_VISIBLE,
        10, 160, 380, 60, m_hWnd, (HMENU)IDC_SERVER_STATUS, hInst, NULL);

    CreateWindowW(L"BUTTON", L"启动游戏", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        150, 230, 100, 30, m_hWnd, (HMENU)IDC_LAUNCH_BUTTON, hInst, NULL);

    return true;
}

void PopupWindow::Show() {
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    SetWindowPos(m_hWnd, HWND_TOPMOST,
        (screenWidth - m_config.popupWidth) / 2, 0,
        m_config.popupWidth, m_config.popupHeight,
        SWP_SHOWWINDOW);
}

void PopupWindow::Hide() {
    ShowWindow(m_hWnd, SW_HIDE);
}

void PopupWindow::UpdateServerStatus(const ServerStatus& status) {
    if (!m_hServerStatic) return;
    std::wstring text;
    if (status.online) {
        wchar_t buf[1024];
        swprintf(buf, 1024, L"在线 - %s\n%d/%d 玩家\n版本: %s\n延迟: %d ms",
        UTF8ToWide(status.motd).c_str(),
        status.players, status.maxPlayers,
        UTF8ToWide(status.version).c_str(),
        status.latency);
        text = buf;
    } else {
        text = L"离线";
    }
    SetWindowTextW(m_hServerStatic, text.c_str());
}

void PopupWindow::UpdateNews(const std::string& news) {
    if (!m_hNewsEdit) return;
    SetWindowTextW(m_hNewsEdit, UTF8ToWide(news).c_str());
}

LRESULT CALLBACK PopupWindow::WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    PopupWindow* pThis = nullptr;
    if (msg == WM_NCCREATE) {
        pThis = (PopupWindow*)((CREATESTRUCT*)lParam)->lpCreateParams;
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pThis);
    } else {
        pThis = (PopupWindow*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    }

    if (pThis) {
        switch (msg) {
            case WM_COMMAND:
                if (LOWORD(wParam) == IDC_LAUNCH_BUTTON) {
                    // 发送启动命令给父窗口
                    SendMessage(GetParent(hWnd), WM_COMMAND, IDC_LAUNCH_BUTTON, 0);
                }
                break;
        }
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}