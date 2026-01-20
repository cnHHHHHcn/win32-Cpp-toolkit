#include <Windows.h>

#pragma once
class WinSysHook {
public:
    enum HookType {
        HOOK_NULL = 0,
        HOOK_KEYBOARD = WH_KEYBOARD,
        HOOK_KEYBOARD_LL = WH_KEYBOARD_LL,
        HOOK_MOUSE = WH_MOUSE,
        HOOK_MOUSE_LL = WH_MOUSE_LL,
        HOOK_CALLWNDPROC = WH_CALLWNDPROC,
        HOOK_GETMESSAGE = WH_GETMESSAGE,
        HOOK_CBT = WH_CBT,
        HOOK_SYSMSGFILTER = WH_SYSMSGFILTER,
        HOOK_DEBUG = WH_DEBUG,
        HOOK_SHELL = WH_SHELL,
        HOOK_FOREGROUNDIDLE = WH_FOREGROUNDIDLE,
    };
    LPCTSTR DLLName = NULL;
    HHOOK HookHandle = NULL;
    WinSysHook();
    virtual ~WinSysHook();
    bool IntsallHook(WinSysHook::HookType hookID, DWORD ThreadId);   // 安装钩子
    bool UnInstallHook();   // 卸载钩子
    void DispatchMSG();   // 发送 Windows Message ,与 InstallHook 连用
private:
    HookType ID = HOOK_NULL;
    static WinSysHook *pHook;
    // 获取所对应钩子类型的函数地址
    HOOKPROC GetHookProc(WinSysHook::HookType hookID);

protected:
    // 静态回调函数
    static LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK KeyboardLLProc(int nCode, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK MouseProc(int nCode, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK MouseLLProc(int nCode, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK CallWndProc(int nCode, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK GetMsgProc(int nCode, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK SysMsgFilterProc(int nCode, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK DebugProc(int nCode, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK ShellProc(int nCode, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK ForegroundIdle(int nCode, WPARAM wParam, LPARAM lParam);

    // 钩子处理虚函数 - 子类需要重写这些函数
    virtual LRESULT OnKeyboard(int nCode, WPARAM wParam, LPARAM lParam);
    virtual LRESULT OnKeyboardLL(int nCode, WPARAM wParam, LPARAM lParam);
    virtual LRESULT OnMouse(int nCode, WPARAM wParam, LPARAM lParam);
    virtual LRESULT OnMouseLL(int nCode, WPARAM wParam, LPARAM lParam);
    virtual LRESULT OnCallWndProc(int nCode, WPARAM wParam, LPARAM lParam);
    virtual LRESULT OnGetMessage(int nCode, WPARAM wParam, LPARAM lParam);
    virtual LRESULT OnCBT(int nCode, WPARAM wParam, LPARAM lParam);
    virtual LRESULT OnSysMsgFilter(int nCode, WPARAM wParam, LPARAM lParam);
    virtual LRESULT OnDebug(int nCode, WPARAM wParam, LPARAM lParam);
    virtual LRESULT OnShell(int nCode, WPARAM wParam, LPARAM lParam);
    virtual LRESULT OnForegroundIdle(int nCode, WPARAM wParam, LPARAM lParam);
};