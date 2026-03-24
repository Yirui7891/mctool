#pragma once
#include <windows.h>
#include <gdiplus.h>
#include <string>
#include "Config.h"
#include "ServerPinger.h"

#define IDC_SERVER_STATUS 1001
#define IDC_LAUNCH_BUTTON 1003
#define IDC_SHORTCUT1     1004
#define IDC_SHORTCUT2     1005
#define IDC_SHORTCUT3     1006
#define IDC_SHORTCUT4     1007
#define IDC_EXIT_BUTTON   1008
#define IDC_SWITCH_BUTTON 1009
#define IDC_MANAGE_BUTTON 1010   // 管理服务器按钮

// 自定义消息：通知父窗口按钮悬停变化
#define WM_UPDATE_HOVER   (WM_USER + 200)

class PopupWindow {
public:
    PopupWindow();
    ~PopupWindow();

    bool Create(HWND hParent, HINSTANCE hInst, const Config& cfg);
    void Show();
    void Hide();
    void UpdateServerStatus(const ServerStatus& status);
    void SetCurrentServerInfo();
    void SyncCurrentServerIndex(int idx);
    HWND GetHWND() const { return m_hWnd; }
    int GetLastX() const { return m_lastX; }
    void SetLastX(int x) { m_lastX = x; }

    // 辅助函数：UTF-8 <-> UTF-16 转换
    static std::wstring UTF8ToWide(const std::string& utf8);
    static std::string WideToUTF8(const std::wstring& wide);

    // 打开服务器管理对话框
    void OnManageServers();

private:
    HWND m_hWnd;
    HWND m_hServerAddressStatic;
    HWND m_hServerStatusStatic;
    HWND m_hShortcutButtons[4];
    Config m_config;
    HBRUSH m_hBkBrush;
    HWND m_hHoverButton;
    HFONT m_hNormalFont;
    HFONT m_hBoldFont;
    HWND m_hExitButton;
    HWND m_hSwitchButton;
    HWND m_hManageButton;          // 管理服务器按钮
    int m_lastX;
    bool m_autoHideScheduled;

    // favicon 相关
    HWND m_hFaviconStatic;
    Gdiplus::Bitmap* m_pFaviconBitmap;
    ULONG_PTR m_gdiplusToken;

    // GDI+ 辅助函数
    Gdiplus::Bitmap* CreateBitmapFromData(const BYTE* data, size_t len);
    Gdiplus::Bitmap* Base64ToBitmap(const std::string& base64Data);

    // 内部函数
    static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK ButtonSubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData);

    void SetHoverButton(HWND hBtn);
    bool IsButton(HWND hWnd);
    void ScheduleAutoHide();
    void CancelAutoHide();
    void OnAutoHideTimer();
    void AdhereToTop();
    void UpdateLastX();
};