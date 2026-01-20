
#include "WinSysDevice.h"
#include <fstream>

// 鼠标输出
void WinSysDevice::MouseSend(WinSysDevice::MouseInfo Data) {
    INPUT MouseData[1] = {INPUT_MOUSE};     // 输入类型为 鼠标
    ZeroMemory(&MouseData, sizeof(MouseData));   // 结构体 INPUT 初始化
    // 设置鼠标滚轮
    if (Data.WheelMove != Mouse::MouseNULL) { 
        MouseData[0].mi.dwFlags = MOUSEEVENTF_WHEEL; 
        MouseData[0].mi.mouseData = Data.WheelMove;
    }
    // 设置鼠标位置
    if (Data.AbsolutePos.x != 0 && Data.AbsolutePos.y != 0) {
        // 相对位置
        MouseData[0].mi.dwFlags = MouseData[0].mi.dwFlags | MOUSEEVENTF_MOVE;
        MouseData[0].mi.dx = Data.AbsolutePos.x;
        MouseData[0].mi.dy = Data.AbsolutePos.y;
    }else {
        // 绝对位置
        SetCursorPos(Data.ScreenPos.x,Data.ScreenPos.y);
    }
    // 输出
    SendInput(ARRAYSIZE(MouseData), MouseData, sizeof(INPUT));
}

// 获取鼠标相对位置
POINT WinSysDevice::GetAbsolutePos() {
    POINT CurrentPos, RTNPos;
    GetCursorPos(&CurrentPos);
    RTNPos.x = -(LastPos.x - CurrentPos.x);
    RTNPos.y = -(LastPos.y - CurrentPos.y);
    LastPos = CurrentPos;
    return RTNPos;
}

// 获取鼠标绝对位置
POINT WinSysDevice::GetScreenPos() {
    POINT RTNPos;
    GetCursorPos(&RTNPos);
    return RTNPos;
}

// 获取屏幕桌面大小尺寸
WinSysDevice::WinSize WinSysDevice::GetDesktopSize() {
    RECT Area; WinSysDevice::WinSize RTN;
    GetWindowRect(GetDesktopWindow(), &Area);
    RTN.Width = Area.right - Area.left;
    RTN.Height = Area.bottom - Area.top;
    return RTN;
}

// 键盘输出(除去汉字)
void WinSysDevice::KeyboardSend(std::wstring WordData, bool WithShift) {
    std::vector<INPUT> KeyboardData; 
    UINT Index = 0, Count = (WithShift ? 2 : 0) + WordData.size() * 2;
    KeyboardData.resize(Count);
    ZeroMemory(&KeyboardData[0], sizeof(INPUT) * Count);
    if (WithShift) {
        KeyboardData[Index].type = INPUT_KEYBOARD;
        KeyboardData[Index].ki.wVk = VK_SHIFT;
        Index++;
    }
    for (int i = 0; i < WordData.size(); i++) {
        KeyboardData[Index + i * 2] .type = INPUT_KEYBOARD;
        KeyboardData[Index + i * 2 + 1].type = INPUT_KEYBOARD;
        if ('a' <= WordData[i] && WordData[i] <= 'z') WordData[i] = WordData[i] - 32;
        KeyboardData[Index + i * 2 + 1].ki.wVk = WordData[i];
        KeyboardData[Index + i * 2 + 1].ki.dwFlags = KEYEVENTF_KEYUP;
    }
    if (WithShift) {
        KeyboardData[Count - 1].type = INPUT_KEYBOARD;
        KeyboardData[Count - 1].ki.wVk = VK_SHIFT;
        KeyboardData[Count - 1].ki.dwFlags = KEYEVENTF_KEYUP;
    }
    SendInput(KeyboardData.size(), KeyboardData.data(), sizeof(INPUT));
}


// 发送Ctrl快捷键
void WinSysDevice::CtrlHotKey(WinSysDevice::ControlHotKey Flag) {
    INPUT KeyInfo[4];
    memset(&KeyInfo, 0, sizeof(KeyInfo));
    for (int i = 0; i < 4; i++) {
        KeyInfo[i].type = INPUT_KEYBOARD;
    }
    KeyInfo[0].ki.wVk = Keyboard::Crtl;
    KeyInfo[1].ki.wVk = Flag;
    KeyInfo[2].ki.wVk = Flag;
    KeyInfo[3].ki.wVk = Keyboard::Crtl;
    KeyInfo[2].ki.dwFlags = KEYEVENTF_KEYUP;
    KeyInfo[3].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(4, KeyInfo, sizeof(INPUT));
}

// 输入法获取与切换
WinSysDevice::LayoutMap WinSysDevice::InputMethod(WinSysDevice::LayoutOpera Flag, HKL HandleKeyboardLayout) {
    LayoutMap RTN;
    RTN[0] = {L"", L"", 0};
    InputInfo Temp;
    switch (Flag) {
    case LayoutOpera::List_All:
        this->DisplayAvailableLayouts(RTN);
        break;
    case LayoutOpera::List_Current:
        this->DisplayCurrentLayoutInfo(Temp);
        RTN[0] = Temp;
        break;
    case LayoutOpera::Set_Next:
        this->SwitchToNextKeyboardLayout();
        break;
    case LayoutOpera::Set_Appoint:
        this->SetKeyboardLayout(HandleKeyboardLayout);
    }
    return RTN;
}

// 剪贴板设置数据(ANSI版本)
bool WinSysDevice::ClipboardSetA(std::string ClipData) {
    if (!OpenClipboard(NULL)) return false;
    EmptyClipboard();
    HGLOBAL hGlobalText = GlobalAlloc(GHND, ClipData.size() + 1);
    char* pClipData = (char*)GlobalLock(hGlobalText);
    strcpy_s(pClipData, ClipData.size() + 1, ClipData.c_str());
    GlobalUnlock(hGlobalText);
    SetClipboardData(CF_TEXT, hGlobalText);
    CloseClipboard();
    return true;
}
// 剪贴板获取数据(ANSI版本)
std::string WinSysDevice::ClipboardGetA() {
    if (!OpenClipboard(NULL)) return "";
    HANDLE hGlobalText = GetClipboardData(CF_TEXT);
    if (!hGlobalText) return "";
    char* pClipData = (char*)GlobalLock(hGlobalText);
    GlobalUnlock(hGlobalText);
    CloseClipboard();
    return std::string(pClipData);
}

// 剪贴板输出(ANSI版本)
void WinSysDevice::ClipboardSendA(std::string ClipData, int DelaySecond) {
    ClipboardSetA(ClipData);
    Sleep(DelaySecond * 1000);
    CtrlHotKey(ControlHotKey::Paste);
}

// 剪贴板设置数据(UNICODE版本)
bool WinSysDevice::ClipboardSetW(std::wstring ClipData) {
    if (!OpenClipboard(NULL)) return false;
    EmptyClipboard();
    HGLOBAL hGlobalText = GlobalAlloc(GHND, (ClipData.size() + 1) * sizeof(wchar_t));
    wchar_t* pClipData = (wchar_t*)GlobalLock(hGlobalText);
    wcscpy_s(pClipData, (ClipData.size() + 1) * sizeof(wchar_t) , ClipData.c_str());
    GlobalUnlock(hGlobalText);
    SetClipboardData(CF_UNICODETEXT, hGlobalText);
    CloseClipboard();
    return true;
}

// 剪贴板获取数据(UNICODE版本)
std::wstring WinSysDevice::ClipboardGetW() {
    if (!OpenClipboard(NULL)) return TEXT("");
    HANDLE hGlobalText = GetClipboardData(CF_UNICODETEXT);
    if (!hGlobalText) return TEXT("");
    wchar_t* pClipData = (wchar_t*)GlobalLock(hGlobalText);
    GlobalUnlock(hGlobalText);
    CloseClipboard();
    return std::wstring(pClipData);
}

// 剪贴板输出(UNICODE版本)
void WinSysDevice::ClipboardSendW(std::wstring ClipData, int DelaySecond) {
    ClipboardSetW(ClipData);
    Sleep(DelaySecond * 1000);
    CtrlHotKey(ControlHotKey::Paste);
}

// 清除剪贴板内容
bool WinSysDevice::ClipboardClear() {
    if (!OpenClipboard(NULL)) return false;
    EmptyClipboard();
    CloseClipboard();
    return true;
}

void WinSysDevice::CaptureDesktop(const char* FileName) {
    // 获取屏幕DC
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    RECT Area; GetWindowRect((HWND)0x00010132, &Area);
    int screenWidth = Area.right;
    int screenHeight = Area.bottom;
    // 创建兼容位图
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);
    SelectObject(hdcMem, hBitmap);
    // 复制屏幕到内存DC
    BitBlt(hdcMem, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY);
    // 保存到文件
    SaveBitmapToFile(hBitmap, FileName);
    // 清理
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
}

void WinSysDevice::CaptureWindow(HWND Handle, const char* FileName) {
    // 获取 窗口DC
    HDC hdcWindow = GetWindowDC(Handle);
    HDC hdcMem = CreateCompatibleDC(hdcWindow);
    // 获取 窗口大小
    RECT Area; GetWindowRect(Handle, &Area);
    int WindowWidth = Area.right - Area.left;
    int WindowHeight = Area.bottom - Area.top;
    // 创建兼容位图
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcWindow, WindowWidth, WindowHeight);
    SelectObject(hdcMem, hBitmap);
    // 复制屏幕到内存DC
    BitBlt(hdcMem, 0, 0, WindowWidth, WindowHeight, hdcWindow, 0, 0, SRCCOPY);
    // 保存到文件
    SaveBitmapToFile(hBitmap, FileName);
    // 清理
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcWindow);
}

void WinSysDevice::CaptureScreenArea(int x, int y, int Width, int Height, const char* FileName) {
    // 获取屏幕DC
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    // 创建兼容位图
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, Width, Height);
    SelectObject(hdcMem, hBitmap);
    // 复制屏幕到内存DC
    BitBlt(hdcMem, 0, 0, Width, Height, hdcScreen, x, y, SRCCOPY);
    // 保存到文件
    SaveBitmapToFile(hBitmap, FileName);
    // 清理
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
}


// 获取当前键盘布局句柄
HKL WinSysDevice::GetCurrentKeyboardLayout() {
    // 获取前台窗口的线程ID
    HWND foregroundWindow = GetForegroundWindow();
    DWORD threadID = GetWindowThreadProcessId(foregroundWindow, NULL);
    // 获取该线程的键盘布局
    return GetKeyboardLayout(threadID);
}

// 获取系统所有可用的键盘布局
std::map<int, HKL> WinSysDevice::GetAvailableKeyboardLayouts() {
    std::map<int, HKL> layouts;

    // 获取系统安装的键盘布局数量
    UINT layoutCount = GetKeyboardLayoutList(0, NULL);

    if (layoutCount > 0) {
        // 获取所有键盘布局
        HKL* layoutList = new HKL[layoutCount];
        GetKeyboardLayoutList(layoutCount, layoutList);

        for (UINT i = 0; i < layoutCount; i++) {
            layouts[i] = layoutList[i];
        }

        delete[] layoutList;
    }

    return layouts;
}

// 获取键盘布局的名称
std::wstring WinSysDevice::GetKeyboardLayoutNames(HKL layout) {
    wchar_t name[KL_NAMELENGTH];
    if (GetKeyboardLayoutNameW(name)) {
        return std::wstring(name);
    }
    return L"Unknown";
}

// 获取键盘布局的语言名称
std::wstring WinSysDevice::GetKeyboardLayoutLanguageName(HKL layout) {
    // 获取语言ID
    LANGID langId = LOWORD(layout);

    // 获取语言名称
    wchar_t languageName[LOCALE_NAME_MAX_LENGTH];
    if (LCIDToLocaleName(MAKELCID(langId, SORT_DEFAULT),
        languageName,
        LOCALE_NAME_MAX_LENGTH,
        0) > 0) {
        return std::wstring(languageName);
    }

    return L"Unknown";
}

// 切换键盘布局
bool WinSysDevice::SwitchToNextKeyboardLayout() {
    // 模拟按下Alt+Shift切换键盘布局
    INPUT inputs[4] = {};

    // 按下 Windows键
    inputs[0].type = INPUT_KEYBOARD;
    inputs[0].ki.wVk = VK_LWIN;

    // 按下 Space 键
    inputs[1].type = INPUT_KEYBOARD;
    inputs[1].ki.wVk = VK_SPACE;

    // 释放 Space 键
    inputs[2].type = INPUT_KEYBOARD;
    inputs[2].ki.wVk = VK_SPACE;
    inputs[2].ki.dwFlags = KEYEVENTF_KEYUP;

    // 释放 Windows 键
    inputs[3].type = INPUT_KEYBOARD;
    inputs[3].ki.wVk = VK_LWIN;
    inputs[3].ki.dwFlags = KEYEVENTF_KEYUP;

    // 发送输入
    UINT sent = SendInput(4, inputs, sizeof(INPUT));
    return sent == 4;
}

// 设置特定键盘布局
bool WinSysDevice::SetKeyboardLayout(HKL HandleKeyboardLayout) {
    int Count = GetKeyboardLayoutList(0, NULL), i;
    for (i = 0; i < Count; i++) {
        this->SwitchToNextKeyboardLayout();
        if (HandleKeyboardLayout == GetCurrentKeyboardLayout()) break;
    }
    return Count != i;
}

// 显示当前键盘布局信息
void WinSysDevice::DisplayCurrentLayoutInfo(InputInfo &LayoutInfo) {
    HKL currentLayout = GetCurrentKeyboardLayout();
    LayoutInfo.LayoutName = GetKeyboardLayoutNames(currentLayout);
    LayoutInfo.LanguageName = GetKeyboardLayoutLanguageName(currentLayout);
    LayoutInfo.LayoutHandle = currentLayout;
}

// 显示所有可用的键盘布局
void WinSysDevice::DisplayAvailableLayouts(std::map<int, InputInfo> &LayoutInfo) {
    std::map<int, HKL> layouts = GetAvailableKeyboardLayouts();
    for (size_t i = 0; i < layouts.size(); i++) {
        LayoutInfo[i].LayoutName = GetKeyboardLayoutNames(layouts[i]);
        LayoutInfo[i].LanguageName = GetKeyboardLayoutLanguageName(layouts[i]);
        LayoutInfo[i].LayoutHandle = layouts[i];
    }
}


bool WinSysDevice::SaveBitmapToFile(HBITMAP hBitmap, const char* FileName) {
    BITMAP bmp;
    GetObject(hBitmap, sizeof(BITMAP), &bmp);

    BITMAPFILEHEADER bmfHeader;
    BITMAPINFOHEADER bi;

    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = bmp.bmWidth;
    bi.biHeight = bmp.bmHeight;
    bi.biPlanes = 1;
    bi.biBitCount = 32; // 通常使用32位，确保有alpha通道
    bi.biCompression = BI_RGB;
    bi.biSizeImage = 0;
    bi.biXPelsPerMeter = 0;
    bi.biYPelsPerMeter = 0;
    bi.biClrUsed = 0;
    bi.biClrImportant = 0;

    DWORD dwBmpSize = ((bmp.bmWidth * bi.biBitCount + 31) / 32) * 4 * bmp.bmHeight;

    // 创建位图数据
    BYTE* lpBitmap = new BYTE[dwBmpSize];
    HDC hdc = GetDC(NULL);

    // 获取位图数据
    GetDIBits(hdc, hBitmap, 0, bmp.bmHeight, lpBitmap, (BITMAPINFO*)&bi, DIB_RGB_COLORS);

    // 创建文件
    std::ofstream file(FileName, std::ios::binary);
    if (!file.is_open()) {
        delete[] lpBitmap;
        ReleaseDC(NULL, hdc);
        return false;
    }

    // 设置文件头
    bmfHeader.bfType = 0x4D42; // "BM"
    bmfHeader.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + dwBmpSize;
    bmfHeader.bfReserved1 = 0;
    bmfHeader.bfReserved2 = 0;
    bmfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

    // 写入文件头
    file.write((char*)&bmfHeader, sizeof(BITMAPFILEHEADER));
    file.write((char*)&bi, sizeof(BITMAPINFOHEADER));
    file.write((char*)lpBitmap, dwBmpSize);

    file.close();
    delete[] lpBitmap;
    ReleaseDC(NULL, hdc);
    return true;
}