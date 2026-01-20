/*  Register  作者:HHH 
* 文件：Register.h、Register.cpp 
* 功能：注册表操作(类模块REG)、注册表功能(类模块REGFunc)  
* REG类模块 包含ANSI版本和UNICODE版本
* Tstring数据类型、TEXTEx方法、to_Tstring方法 会根据使用字符集版本
* 将字符串自动转化为string(ANSI)、wstring(UNICODE)类型
* 其余的不再赘述(调用方法不会用到)，如上述同理。

* 注:
* 建议使用ANSI版本。
* 在UNICODE版本中，调用ModifyKeyValue方法，如下。
* REG::ModifyKeyValue(注册表路径, 注册值名(键名), 注册值(键值))
* 注册值的数据类型为字符类型(即:含有 char、wchar_t，或 string、wstring)
* 注册表中的注册值容易乱码，其余没有问题。
* 作者已经无能为力。
*/
#include <windows.h>
#include <type_traits>
#include <string>
#include <locale>
#include <codecvt>
#include <vector>
#include <map>

#define ANSI_Base(quote) quote
#define UNICODE_Base(quote) TEXT(quote)

/*
// UNICODE 版本
#define FormatMessage FormatMessageW
#define RegOpenKeyEx  RegOpenKeyExW
#define RegCreateKeyEx RegCreateKeyExW
#define RegDeleteKeyEx RegDeleteKeyExW
#define RegEnumKeyEx RegEnumKeyExW
#define RegSetValueEx RegSetValueExW
#define RegDeleteValue RegDeleteValueW
#define RegQueryValueEx RegQueryValueExW
#define RegEnumValue RegEnumValueW
#define RegSaveKeyEx RegSaveKeyExW
#define RegLoadKey RegLoadKeyW
#define RegUnLoadKey RegUnLoadKeyW
#define RegCopyTree   RegCopyTreeW
#define RegDeleteTree RegDeleteTreeW
#define to_Tstring std::to_wstring
#define TEXTEx(quote) UNICODE_Base(quote)
#define T_cLen std::wcslen
#define PathHeadSize 4
typedef std::wstring Tstring;
typedef LPCWSTR T_LPCSTR;
typedef LPWSTR T_LPSTR;
typedef wchar_t T_CHAR;
typedef const wchar_t* T_CCHAR;
*/

// ANSI 版本
#define FormatMessage FormatMessageA
#define RegOpenKeyEx  RegOpenKeyExA
#define RegCreateKeyEx RegCreateKeyExA
#define RegDeleteKeyEx RegDeleteKeyExA
#define RegEnumKeyEx RegEnumKeyExA
#define RegSetValueEx RegSetValueExA
#define RegDeleteValue RegDeleteValueA
#define RegQueryValueEx RegQueryValueExA
#define RegEnumValue RegEnumValueA
#define RegSaveKeyEx RegSaveKeyExA
#define RegLoadKey RegLoadKeyA
#define RegUnLoadKey RegUnLoadKeyA
#define RegCopyTree   RegCopyTreeA
#define RegDeleteTree RegDeleteTreeA
#define to_Tstring std::to_string
#define TEXTEx(quote) ANSI_Base(quote)
#define T_cLen std::strlen
#define PathHeadSize 7
typedef std::string Tstring;
typedef LPCSTR T_LPCSTR;
typedef LPSTR T_LPSTR;
typedef char T_CHAR;
typedef const char* T_CCHAR;


#define  NAME_BUFFER_SIZE  255
#define DATA_BUFFER_SIZE 16383
#pragma once

using namespace std;
class REG{
private:
    enum CustomError { Parameters = 0, TypeRead = 1, TypeWrite = 2,TypeError = 3};
    enum SubKeyState { New = REG_CREATED_NEW_KEY, Old = REG_OPENED_EXISTING_KEY };
    // 子键信息类型
    struct SubKeyInfo {
        HKEY Handle;
        SubKeyState State;
    };
    // 子键路径信息类型
    struct REGPathInfo {
        Tstring RootKeyName;
        HKEY RootKeyHandle = (HKEY)0;
        Tstring SubKeyPath;
    };
    SubKeyInfo m_SubKey = SubKeyInfo();
    REGPathInfo m_REGInfo = REGPathInfo();

    HKEY GetRootKeyHandle(Tstring& Path);
	bool GetSubKeyHandle(HKEY RootKey, Tstring Path, SubKeyInfo &Result);
    bool CloseSubKey(HKEY SubKeyHandle);
    Tstring GetLastErrorString(LSTATUS errorCode);
    Tstring GetCustomErrorString(CustomError errorCode);
    //bool EnableBackupPrivilege();
public:
    struct KeyValueInfo {
        Tstring Name;        // 值名
        DWORD Type;          // 值类型
        vector<BYTE> Data;   // 数据
    };
    enum REGbit { bit32 = KEY_WOW64_32KEY, bit64 = KEY_WOW64_64KEY };  // 根据 操作系统位数 决定使用
    Tstring ErrorInfo, RegisterPath;   // 调用方法错误信息、当前注册表路径
    // 宽字符和窄字符转换
    string WStringToString(const wstring &wstr, bool toUtf8 = true);     
    wstring StringToWString(const string &str, bool toUtf8 = true);
    template<typename T>
    T ExchangeREGData(vector<BYTE> ByteTemp, DWORD REGType);   // 注册表 转化为 C++ 数据类型
    Tstring GetKeyPathInfo();  // 当前注册表路径信息
	bool AddSubKey(Tstring KeyPath, Tstring KeyName);   // 添加子项
	bool DeleteSubKey(Tstring KeyPath, Tstring KeyName, REGbit bitFlag);   // 删除子项
    bool RenameSubKey(Tstring KeyPath, wstring OldKeyName, wstring NewKeyName);   // 重命名子项
	bool EnumSubKey(Tstring KeyPath, map<int, Tstring> &ReturnSubKey);   // 枚举子项
    template<typename T>
    bool ModifyKeyValue(Tstring KeyPath, Tstring ValueName, T ValueData);   // 添加、修改值数据
    bool DeleteKeyValue(Tstring KeyPath, Tstring ValueName);   // 删除值数据
    template <typename T>
    bool QueryKeyValue(Tstring KeyPath, Tstring ValueName, T& ValueData);   // 查询值数据
    bool EnumKeyValue(Tstring KeyPath, map<int, KeyValueInfo> &ReturnKeyValue);   // 枚举值数据
    bool CopyTree(Tstring ScrKeyPath, Tstring DesKeyPath);   // 复制注册表树
    bool DeleteTree(Tstring KeyPath);   // 删除注册表树
    //bool SaveREGInfo(Tstring KeyPath, Tstring OutFile);
    //bool OperaREGfile(Tstring KeyPath, Tstring KeyName, Tstring InFile);
};

class REGFunc{
// 请使用ANSI版本，UNICODE版本会出现乱码
public:
    enum ProductOpera{ Install = 1, UnInstall = 2};
    // 文件弹出菜单结构体
    struct FileMenuInfo {
        Tstring MenuName = TEXTEx("open");  // 菜单名称
        Tstring DisplayName = TEXTEx("");   // 菜单名称
        Tstring Icon;               // 图标
        Tstring Command;            // 命令
    };
    // 文件后缀名结构体
    struct FileSuffixInfo {
        Tstring FileType;      // 文件类型
        Tstring DefaultIcon;   // 默认图标
        FileMenuInfo MenuInfo; // 文件弹出菜单
    };
    // 产品注册结构体
    struct ProductInfo {
        string DisplayName;    // 名称
        string DisplayIcon;    // 图标
        string DisplayVersion; // 版本
        string Publisher;      // 发布者
        string HelpLink;       // 帮助链接
        string URLInfoAbout;   // 关于链接
        string URLUpdateInfo;  // 更新链接
        string UnInstallString;// 卸载程序路径
        DWORD EstimatedSize;   // 产品大小
        // 以下成员不会出现在注册表中
        ProductOpera State = REGFunc::UnInstall;    // 状态(作者自定义)
    };
   
    bool WinStartRun(Tstring ProgramPath, bool is_Current);   // 开机自启动
    void SetFileAssociation(Tstring FileSuffix, REGFunc::FileSuffixInfo FSInfo);   // 设置文件扩展名关联
    void SetGeneralPopupMenu(REGFunc::FileMenuInfo FMInfo);   // 设置通用右键弹出式菜单
    bool Product(Tstring ProgramPath, REGFunc::ProductInfo PInfo);   // 产品注册安装与卸载

private:
    REG Opera;
    Tstring GetFileName(Tstring Path);
    void SetFilePopupMenu(Tstring MenuShellPath, REGFunc::FileMenuInfo FMInfo);
};
