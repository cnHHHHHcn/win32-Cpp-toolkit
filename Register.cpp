#include "Register.h"

HKEY REG::GetRootKeyHandle(Tstring &Path) {
	Path = (Path.substr(0, PathHeadSize) == TEXTEx("计算机\\")) ? Path.substr(PathHeadSize) : Path;
	m_REGInfo.RootKeyName = Path.substr(0, Path.find(TEXTEx("\\")));
	Path = Path.substr(Path.find(TEXTEx("\\"))+1);
	m_REGInfo.SubKeyPath = Path;
	if(m_REGInfo.RootKeyName == TEXTEx("HKEY_CLASSES_ROOT")) return HKEY_CLASSES_ROOT;
	if(m_REGInfo.RootKeyName == TEXTEx("HKEY_CURRENT_CONFIG")) return HKEY_CURRENT_CONFIG;
	if(m_REGInfo.RootKeyName == TEXTEx("HKEY_CURRENT_USER")) return HKEY_CURRENT_USER;
	if(m_REGInfo.RootKeyName == TEXTEx("HKEY_CURRENT_USER_LOCAL_SETTINGS")) return HKEY_CURRENT_USER_LOCAL_SETTINGS;
	if(m_REGInfo.RootKeyName == TEXTEx("HKEY_DYN_DATA")) return HKEY_DYN_DATA;
	if(m_REGInfo.RootKeyName == TEXTEx("HKEY_LOCAL_MACHINE")) return HKEY_LOCAL_MACHINE;
	if(m_REGInfo.RootKeyName == TEXTEx("HKEY_PERFORMANCE_DATA")) return HKEY_PERFORMANCE_DATA;
	if(m_REGInfo.RootKeyName == TEXTEx("HKEY_PERFORMANCE_NLSTEXTEx")) return HKEY_PERFORMANCE_NLSTEXT;
	if(m_REGInfo.RootKeyName == TEXTEx("HKEY_PERFORMANCE_TEXTEx")) return HKEY_PERFORMANCE_TEXT;
	if(m_REGInfo.RootKeyName == TEXTEx("HKEY_USERS")) return HKEY_USERS;
}

bool REG::GetSubKeyHandle(HKEY RootKey, Tstring Path, SubKeyInfo &Result) {
	SECURITY_ATTRIBUTES securityAttributes;
	securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	securityAttributes.lpSecurityDescriptor = NULL;
	securityAttributes.bInheritHandle = FALSE;
	LSTATUS RTN = ERROR_SUCCESS;
	RTN = RegCreateKeyEx(RootKey, (T_LPCSTR)Path.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, &securityAttributes, &Result.Handle, (LPDWORD)&Result.State);
	if (RTN != ERROR_SUCCESS) ErrorInfo = this->GetLastErrorString(RTN);
	return RTN == ERROR_SUCCESS;
}

bool REG::CloseSubKey(HKEY SubKeyHandle) {
	LSTATUS Result = RegCloseKey(SubKeyHandle);
	return Result == ERROR_SUCCESS;
}

Tstring REG::GetLastErrorString(LSTATUS errorCode) {
	if (errorCode == 0) return Tstring();
	T_LPSTR buffer = nullptr;
	size_t size = FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(T_LPSTR)&buffer, 0, NULL);
	Tstring message(buffer, size);
	LocalFree(buffer);
	// Trim trailing whitespace
	message.erase(message.find_last_not_of(TEXTEx(" \n\r\t")) + 1);
	return message;
} 

Tstring REG::GetCustomErrorString(CustomError errorCode){
	map<int, Tstring> Error;
	Error[0] = TEXTEx("请检查参数是否填写完整，缺少参数");
	Error[1] = TEXTEx("不支持对此类型键值读取");
	Error[2] = TEXTEx("不支持对此类型键值写入");
	Error[3] = TEXTEx("类型不匹配错误");
	return Error[errorCode];
}
/*
// 启用必要的权限
bool REG::EnableBackupPrivilege() {
	HANDLE hToken;
	// 使用足够大的缓冲区（3个权限）
	struct TOKEN_PRIVILEGES {
		DWORD PrivilegeCount;
		LUID_AND_ATTRIBUTES Privileges[3];
	} tkp;
	// 获取当前进程的令牌
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		ErrorInfo = "OpenProcessToken failed: " + this->GetLastErrorString(GetLastError());
		return false;
	}
	// 获取 LUID 用于备份权限
	tkp.PrivilegeCount = 3;
	LookupPrivilegeValue(NULL, SE_BACKUP_NAME, &tkp.Privileges[0].Luid);
	LookupPrivilegeValue(NULL, SE_RESTORE_NAME, &tkp.Privileges[1].Luid);
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[2].Luid);
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tkp.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
	tkp.Privileges[2].Attributes = SE_PRIVILEGE_ENABLED;
	// 调整权限
	if (!AdjustTokenPrivileges(hToken, FALSE, (PTOKEN_PRIVILEGES)&tkp, 0, NULL, NULL)) {
		ErrorInfo = "OpenProcessToken failed: " + this->GetLastErrorString(GetLastError());
		CloseHandle(hToken);
		return false;
	}
	CloseHandle(hToken);
	return true;
}
*/

string REG::WStringToString(const wstring& wstr, bool toUtf8) {
	if (wstr.empty()) return "";

	// 计算所需缓冲区大小
	int size_needed = WideCharToMultiByte(
		toUtf8 ? CP_UTF8 : CP_ACP,  // 目标编码：UTF-8 或 ANSI
		0,
		wstr.c_str(), (int)wstr.size(),
		nullptr, 0,
		nullptr, nullptr
	);

	// 分配缓冲区并转换
	string str(size_needed, '\0');
	WideCharToMultiByte(
		toUtf8 ? CP_UTF8 : CP_ACP, 0,
		wstr.c_str(), (int)wstr.size(),
		&str[0], size_needed,
		nullptr, nullptr
	);

	return str;
}

/* 使用示例
* std::wstring wideStr = L"AAA";
* std::string narrowStr = WStringToString(wideStr);   默认转为 UTF-8
* std::string ansiStr = WStringToString(wideStr, false);   转为 ANSI
*/
wstring REG::StringToWString(const string& str, bool isUtf8) {
	if (str.empty()) return L"";

	int size_needed = MultiByteToWideChar(
		isUtf8 ? CP_UTF8 : CP_ACP,  // 源编码：UTF-8 或 ANSI
		0,
		str.c_str(), (int)str.size(),
		nullptr, 0
	);

	wstring wstr(size_needed, L'\0');
	MultiByteToWideChar(
		isUtf8 ? CP_UTF8 : CP_ACP, 0,
		str.c_str(), (int)str.size(),
		&wstr[0], size_needed
	);

	return wstr;
}

template<typename T>
T REG::ExchangeREGData(vector<BYTE> ByteTemp, DWORD REGType){
ULONGLONG Temp = 0;
	switch (REGType) {
	case REG_SZ:
	case REG_EXPAND_SZ:
	case REG_MULTI_SZ:
		if constexpr (std::is_same_v<T, Tstring>) {
			return Tstring(reinterpret_cast<T_CCHAR>(ByteTemp.data()));
		}else {
			ErrorInfo = this->GetCustomErrorString(this->TypeError);
			return T();
		}		
		break;
	case REG_BINARY:
		if constexpr (std::is_same_v<T, std::vector<BYTE>>) {
			return std::vector<BYTE>(ByteTemp.begin(), ByteTemp.end());
		}else {
			ErrorInfo = this->GetCustomErrorString(this->TypeError);
			return T();
		}
	case REG_DWORD:
		for (int i = 0; i < ByteTemp.size(); i++) {
			Temp = (Temp * 256) + ByteTemp[4 - i];
		}
		return (T&)Temp;
		break;
	case REG_QWORD:
		for (int i = 0; i < ByteTemp.size(); i++) {
			Temp = (Temp * 256) + ByteTemp[8 - i];
		}
		return (T&)Temp;
		break;
	case REG_NONE:
		ErrorInfo = this->GetCustomErrorString(this->TypeRead);
		return T();
		break;
	}
}
template bool REG::ExchangeREGData<bool>(vector<BYTE> ByteTemp, DWORD REGType);
template short REG::ExchangeREGData<short>(vector<BYTE> ByteTemp, DWORD REGType);
template unsigned short REG::ExchangeREGData<unsigned short>(vector<BYTE> ByteTemp, DWORD REGType);
template int REG::ExchangeREGData<int>(vector<BYTE> ByteTemp, DWORD REGType);
template unsigned int REG::ExchangeREGData<unsigned int>(vector<BYTE> ByteTemp, DWORD REGType);
template long REG::ExchangeREGData<long>(vector<BYTE> ByteTemp, DWORD REGType);
template unsigned long REG::ExchangeREGData<unsigned long>(vector<BYTE> ByteTemp, DWORD REGType);
template long long REG::ExchangeREGData<long long>(vector<BYTE> ByteTemp, DWORD REGType);
template unsigned long long REG::ExchangeREGData<unsigned long long>(vector<BYTE> ByteTemp, DWORD REGType);
template float REG::ExchangeREGData<float>(vector<BYTE> ByteTemp, DWORD REGType);
template double REG::ExchangeREGData<double>(vector<BYTE> ByteTemp, DWORD REGType);
template long double REG::ExchangeREGData<long double>(vector<BYTE> ByteTemp, DWORD REGType);
template Tstring REG::ExchangeREGData<Tstring>(vector<BYTE> ByteTemp, DWORD REGType);

Tstring REG::GetKeyPathInfo() {
	Tstring stateStr((m_SubKey.State == SubKeyState::New) ? TEXTEx("Created new subkey") : TEXTEx("Opened existing subkey"));

	return TEXTEx("Root key name:") + m_REGInfo.RootKeyName + TEXTEx("\n") +
		TEXTEx("Root key handle: ") + to_Tstring((long)m_REGInfo.RootKeyHandle) + TEXTEx("\n") +
		TEXTEx("Subkey path: ") + m_REGInfo.SubKeyPath + TEXTEx("\n") +
		TEXTEx("Subkey handle: ") + to_Tstring((long)m_SubKey.Handle) + TEXTEx("\n") +
		TEXTEx("Subkey state: ") + stateStr;
}

bool REG::AddSubKey(Tstring KeyPath, Tstring KeyName) {
	if (KeyPath.empty()) { ErrorInfo = this->GetCustomErrorString(this->Parameters); return false; }
	m_REGInfo.RootKeyHandle = this->GetRootKeyHandle(KeyPath);
	if (!KeyPath.empty()) KeyPath = (KeyPath.substr(KeyPath.size() - 1, 1) == TEXTEx("\\") ? KeyPath : KeyPath + TEXTEx("\\"));
	KeyPath.append(KeyName);
	bool Flag = this->GetSubKeyHandle(m_REGInfo.RootKeyHandle, KeyPath, m_SubKey);
	if (Flag) { this->CloseSubKey(m_SubKey.Handle); RegisterPath = m_REGInfo.RootKeyName + TEXTEx("\\") + KeyPath; }
	return Flag;
}

bool REG::RenameSubKey(Tstring KeyPath, wstring OldKeyName, wstring NewKeyName) {
	if (KeyPath.empty()) { ErrorInfo = this->GetCustomErrorString(this->Parameters); return false; }
	m_REGInfo.RootKeyHandle = this->GetRootKeyHandle(KeyPath);
	bool Flag = this->GetSubKeyHandle(m_REGInfo.RootKeyHandle, KeyPath, m_SubKey);
	LSTATUS RTN = ERROR_SUCCESS;
	if (Flag) {
		RTN = RegRenameKey(m_SubKey.Handle,(LPCWSTR)OldKeyName.c_str(), (LPCWSTR)NewKeyName.c_str());
		if (RTN != ERROR_SUCCESS) { ErrorInfo = this->GetLastErrorString(RTN); Flag = false;}
		this->CloseSubKey(m_SubKey.Handle);
	}
	return Flag;
}

bool REG::DeleteSubKey(Tstring KeyPath, Tstring KeyName, REGbit bitFlag) {
	if (KeyPath.empty()) { ErrorInfo = this->GetCustomErrorString(this->Parameters); return false; }
	m_REGInfo.RootKeyHandle = this->GetRootKeyHandle(KeyPath);
	LSTATUS RTN = ERROR_SUCCESS;
	bool Flag = this->GetSubKeyHandle(m_REGInfo.RootKeyHandle, KeyPath, m_SubKey);
	if (Flag) {
		RTN = RegDeleteKeyEx(m_SubKey.Handle, (T_LPCSTR)((!KeyPath.empty()) ? KeyName : TEXTEx("")).c_str(), bitFlag, 0);
		if (RTN != ERROR_SUCCESS) {ErrorInfo = this->GetLastErrorString(RTN); Flag = false;}
		this->CloseSubKey(m_SubKey.Handle);
	}
	return Flag;
}

bool REG::EnumSubKey(Tstring KeyPath, map<int, Tstring> &ReturnSubKey) {
	T_CHAR SubKeyName[NAME_BUFFER_SIZE] = {0};
	DWORD SubKeySize = NAME_BUFFER_SIZE, Index = 0;
	FILETIME lastWriteTime;
	if (KeyPath.empty()) { ErrorInfo = this->GetCustomErrorString(this->Parameters); return false; }
	m_REGInfo.RootKeyHandle = this->GetRootKeyHandle(KeyPath);
	LSTATUS RTN = ERROR_SUCCESS;
	if (this->GetSubKeyHandle(m_REGInfo.RootKeyHandle, KeyPath, m_SubKey)) {
		//清除 旧map模板容器的所有元素
		ReturnSubKey.clear();
		while (RTN != ERROR_NO_MORE_ITEMS) {
			ErrorInfo = this->GetLastErrorString(RTN);
			RTN = RegEnumKeyEx(m_SubKey.Handle, Index, SubKeyName, &SubKeySize, NULL, NULL, NULL, &lastWriteTime);
			ReturnSubKey[Index] = Tstring(SubKeyName).substr(0, SubKeySize);
			Index++; SubKeySize = NAME_BUFFER_SIZE;
		}
		this->CloseSubKey(m_SubKey.Handle);
		return (ReturnSubKey.size() != 0);
	} 
}

template<typename T>
bool REG::ModifyKeyValue(Tstring KeyPath, Tstring ValueName, T ValueData) {
	DWORD ValueType = REG_NONE,ValueSize = 0;
	if (KeyPath.empty()) { ErrorInfo = this->GetCustomErrorString(this->Parameters); return false; }
	m_REGInfo.RootKeyHandle = this->GetRootKeyHandle(KeyPath);
	LSTATUS RTN = ERROR_SUCCESS; vector<BYTE> REGData;
	bool Flag = this->GetSubKeyHandle(m_REGInfo.RootKeyHandle, KeyPath, m_SubKey);
	if (Flag) {
		if constexpr (std::is_same_v<T, T_CCHAR> || std::is_same_v<T, T_CHAR*>) {
			REGData.assign(ValueData, ValueData + T_cLen(ValueData) + 1); // Include null terminator
			ValueSize = static_cast<DWORD>(REGData.size());
			ValueType = (ValueSize > 32) ? REG_BINARY : REG_SZ;
		}else if constexpr (std::is_same_v<T, string> || std::is_same_v<T, wstring>) {
			REGData.assign(ValueData.begin(), ValueData.end()); 
			REGData.push_back('\0'); // Add null terminator
			ValueSize = static_cast<DWORD>(REGData.size() + 1);
			ValueType = (ValueData.find('%') != std::string::npos) ? REG_EXPAND_SZ : REG_SZ;
		}else if constexpr (std::is_same_v<T, bool> || std::is_same_v<T, float> ||
			std::is_same_v<T, short> || std::is_same_v<T, unsigned short> ||
			std::is_same_v<T, int> || std::is_same_v<T, unsigned int> ||
			std::is_same_v<T, long> || std::is_same_v<T, unsigned long>) {
			ValueType = REG_DWORD;
			DWORD temp = static_cast<DWORD>((ULONG32&)ValueData);
			REGData.resize(sizeof(DWORD));
			memcpy(REGData.data(), &temp, sizeof(DWORD));
			ValueSize = sizeof(DWORD);
		}else if constexpr (std::is_same_v<T, unsigned long long> || std::is_same_v<T, long long> ||
						   std::is_same_v<T, double> || std::is_same_v<T,long double>) {
			ValueType = REG_QWORD;
			ULONGLONG temp = static_cast<ULONGLONG>((ULONG64&)ValueData);
			REGData.resize(sizeof(ULONGLONG));
			memcpy(REGData.data(), &temp, sizeof(ULONGLONG));
			ValueSize = sizeof(ULONGLONG);
		}else {
			ErrorInfo = this->GetCustomErrorString(this->TypeWrite);
			this->CloseSubKey(m_SubKey.Handle);
			return false;
		}
		if (m_SubKey.State == REG::New || m_SubKey.State == REG::Old) {
			RTN = ::RegSetValueEx(m_SubKey.Handle, ValueName.c_str(), 0, ValueType, (CONST BYTE*)REGData.data(), ValueSize);
			if (RTN != ERROR_SUCCESS) { ErrorInfo = this->GetLastErrorString(RTN); Flag = false; }
			this->CloseSubKey(m_SubKey.Handle);
		}
	}
	return Flag;
}
template bool REG::ModifyKeyValue<T_CCHAR>(Tstring KeyPath, Tstring ValueName, T_CCHAR ValueData);
template bool REG::ModifyKeyValue<bool>(Tstring KeyPath, Tstring ValueName, bool ValueData);
template bool REG::ModifyKeyValue<short>(Tstring KeyPath, Tstring ValueName, short ValueData);
template bool REG::ModifyKeyValue<unsigned short>(Tstring KeyPath, Tstring ValueName, unsigned short ValueData);
template bool REG::ModifyKeyValue<int>(Tstring KeyPath, Tstring ValueName, int ValueData);
template bool REG::ModifyKeyValue<unsigned int>(Tstring KeyPath, Tstring ValueName, unsigned int ValueData);
template bool REG::ModifyKeyValue<long>(Tstring KeyPath, Tstring ValueName, long ValueData);
template bool REG::ModifyKeyValue<unsigned long>(Tstring KeyPath, Tstring ValueName, unsigned long ValueData);;
template bool REG::ModifyKeyValue<long long>(Tstring KeyPath, Tstring ValueName, long long ValueData);;
template bool REG::ModifyKeyValue<unsigned long long>(Tstring KeyPath, Tstring ValueName, unsigned long long ValueData);
template bool REG::ModifyKeyValue<float>(Tstring KeyPath, Tstring ValueName, float ValueData);
template bool REG::ModifyKeyValue<double>(Tstring KeyPath, Tstring ValueName, double ValueData);
template bool REG::ModifyKeyValue<long double>(Tstring KeyPath, Tstring ValueName, long double ValueData);
template bool REG::ModifyKeyValue<Tstring>(Tstring KeyPath, Tstring ValueName, Tstring ValueData);

bool REG::DeleteKeyValue(Tstring KeyPath, Tstring ValueName) {
	if (KeyPath.empty()) { ErrorInfo = this->GetCustomErrorString(this->Parameters); return false; }
	m_REGInfo.RootKeyHandle = this->GetRootKeyHandle(KeyPath);
	LSTATUS RTN = ERROR_SUCCESS; vector<BYTE> REGData;
	bool Flag = this->GetSubKeyHandle(m_REGInfo.RootKeyHandle, KeyPath, m_SubKey);
	if (Flag) {
		RTN = ::RegDeleteValue(m_SubKey.Handle, (T_LPCSTR)ValueName.c_str());
		if (RTN != ERROR_SUCCESS) ErrorInfo = this->GetLastErrorString(RTN); Flag = false;
		this->CloseSubKey(m_SubKey.Handle);
	}
	return Flag;
}

template<typename T>
bool REG::QueryKeyValue(Tstring KeyPath, Tstring ValueName, T& ValueData) {
	DWORD ValueDataType = REG_NONE, ValueDataSize = DATA_BUFFER_SIZE;
	if (KeyPath.empty()) { ErrorInfo = this->GetCustomErrorString(this->Parameters); return false; }
	m_REGInfo.RootKeyHandle = this->GetRootKeyHandle(KeyPath);
	LSTATUS RTN = ERROR_SUCCESS; vector<BYTE> REGData;
	bool Flag = this->GetSubKeyHandle(m_REGInfo.RootKeyHandle, KeyPath, m_SubKey);
	if (Flag) {
		RTN = RegQueryValueEx(m_SubKey.Handle, (T_LPCSTR)ValueName.c_str(), 0, &ValueDataType, NULL, &ValueDataSize);
		vector <BYTE> ValueTempData(ValueDataSize + 1);
		RTN = RegQueryValueEx(m_SubKey.Handle, (T_LPCSTR)ValueName.c_str(), 0, NULL, (LPBYTE)ValueTempData.data(), &ValueDataSize);
		if (RTN == ERROR_SUCCESS) {
			ValueData = this->ExchangeREGData<T>(ValueTempData, ValueDataType);
			Flag = (ValueDataType != REG_NONE);
		}
		this->CloseSubKey(m_SubKey.Handle);
	}
	return Flag;
}
template bool REG::QueryKeyValue<vector<BYTE>>(Tstring KeyPath, Tstring ValueName, vector<BYTE> &ValueData);
template bool REG::QueryKeyValue<bool>(Tstring KeyPath, Tstring ValueName, bool &ValueData);
template bool REG::QueryKeyValue<short>(Tstring KeyPath, Tstring ValueName, short &ValueData);
template bool REG::QueryKeyValue<unsigned short>(Tstring KeyPath, Tstring ValueName, unsigned short &ValueData);
template bool REG::QueryKeyValue<int>(Tstring KeyPath, Tstring ValueName, int &ValueData);
template bool REG::QueryKeyValue<unsigned int>(Tstring KeyPath, Tstring ValueName, unsigned int &ValueData);
template bool REG::QueryKeyValue<long>(Tstring KeyPath, Tstring ValueName, long &ValueData);
template bool REG::QueryKeyValue<unsigned long>(Tstring KeyPath, Tstring ValueName, unsigned long &ValueData);
template bool REG::QueryKeyValue<long long>(Tstring KeyPath, Tstring ValueName, long long &ValueData);
template bool REG::QueryKeyValue<unsigned long long>(Tstring KeyPath, Tstring ValueName, unsigned long long &ValueData);
template bool REG::QueryKeyValue<float>(Tstring KeyPath, Tstring ValueName, float &ValueData);
template bool REG::QueryKeyValue<double>(Tstring KeyPath, Tstring ValueName, double &ValueData);
template bool REG::QueryKeyValue<long double>(Tstring KeyPath, Tstring ValueName, long double &ValueData);
template bool REG::QueryKeyValue<Tstring>(Tstring KeyPath, Tstring ValueName, Tstring &ValueData);

bool REG::EnumKeyValue(Tstring KeyPath, map<int, KeyValueInfo> &ReturnKeyValue) {
	if (KeyPath.empty()) { ErrorInfo = this->GetCustomErrorString(this->Parameters); return false; }
	m_REGInfo.RootKeyHandle = this->GetRootKeyHandle(KeyPath);
	LSTATUS RTN = ERROR_SUCCESS;
	bool Flag = this->GetSubKeyHandle(m_REGInfo.RootKeyHandle, KeyPath, m_SubKey);
	if (Flag) {
		ReturnKeyValue.clear();
		DWORD Index = 0, ValueType = REG_NONE, 
			  ValueNameSize = NAME_BUFFER_SIZE, 
			  ValueDataSize = DATA_BUFFER_SIZE;
		T_CHAR ValueNameBuffer[NAME_BUFFER_SIZE] = {0};
		vector<BYTE> ValueDataBuffer(DATA_BUFFER_SIZE);
		KeyValueInfo Temp;
		while (RTN != ERROR_NO_MORE_ITEMS) {
			ErrorInfo = this->GetLastErrorString(RTN);
			RTN = RegEnumValue(m_SubKey.Handle, Index, (T_LPSTR)ValueNameBuffer, &ValueNameSize, 0, &ValueType, (LPBYTE)ValueDataBuffer.data(), &ValueDataSize);
			if (ValueType == REG_NONE) {Flag = false; continue; }
			ValueDataBuffer.erase(ValueDataBuffer.begin() + ((ValueDataSize != DATA_BUFFER_SIZE)? ValueDataSize + 1: 0), ValueDataBuffer.end());
			if (ValueDataBuffer.empty()) continue;
			Temp.Name = Tstring(ValueNameBuffer).substr(0, ValueNameSize);
			Temp.Data = ValueDataBuffer;Temp.Type = ValueType;
			ValueDataBuffer.assign(DATA_BUFFER_SIZE, 0);
			ValueDataSize = DATA_BUFFER_SIZE;ValueNameSize = NAME_BUFFER_SIZE;
			ReturnKeyValue[Index] = Temp; Index++; Flag = true;
		}
		this->CloseSubKey(m_SubKey.Handle);
	}
	return Flag;
}
bool REG::CopyTree(Tstring ScrKeyPath, Tstring DesKeyPath) {
	if (ScrKeyPath.empty()) { ErrorInfo = this->GetCustomErrorString(this->Parameters); return false; }
	if (DesKeyPath.empty()) { ErrorInfo = this->GetCustomErrorString(this->Parameters); return false; }
	HKEY SrcRootKeyHandle = this->GetRootKeyHandle(ScrKeyPath);
	HKEY DesRootKeyHandle = this->GetRootKeyHandle(DesKeyPath);
	SubKeyInfo SrcSubKey, DesSubKey;
	bool SrcFlag = this->GetSubKeyHandle(SrcRootKeyHandle, ScrKeyPath, SrcSubKey);
	bool DesFlag = this->GetSubKeyHandle(DesRootKeyHandle, DesKeyPath, DesSubKey);
	LSTATUS RTN = ERROR_SUCCESS;
	if (SrcFlag && DesFlag) {
		RTN = RegCopyTree(SrcSubKey.Handle, nullptr, DesSubKey.Handle);
		if (RTN != ERROR_SUCCESS) { ErrorInfo = this->GetLastErrorString(RTN); SrcFlag = false; }
	}
	this->CloseSubKey(SrcSubKey.Handle); this->CloseSubKey(DesSubKey.Handle);
	return SrcFlag && DesFlag;
}

bool REG::DeleteTree(Tstring KeyPath) {
	if (KeyPath.empty()) { ErrorInfo = this->GetCustomErrorString(this->Parameters); return false; }
	m_REGInfo.RootKeyHandle = this->GetRootKeyHandle(KeyPath);
	LSTATUS RTN = ERROR_SUCCESS;
	bool Flag = this->GetSubKeyHandle(m_REGInfo.RootKeyHandle, KeyPath, m_SubKey);
	if (Flag) {
		RTN = RegDeleteTree(m_SubKey.Handle, nullptr);
		if (RTN != ERROR_SUCCESS) { ErrorInfo = this->GetLastErrorString(RTN); Flag = false; }
	}
	this->CloseSubKey(m_SubKey.Handle);
	return Flag;
}

/*
bool REG::SaveREGInfo(Tstring KeyPath, Tstring OutFile) {
	if (KeyPath.empty()) { ErrorInfo = this->GetCustomErrorString(this->Parameters); return false; }
	m_REGInfo.RootKeyHandle = this->GetRootKeyHandle(KeyPath);
	LSTATUS RTN = ERROR_SUCCESS;
	bool Flag = this->GetSubKeyHandle(m_REGInfo.RootKeyHandle, KeyPath, m_SubKey);
	if (Flag && this->EnableBackupPrivilege()) {
		RTN = RegSaveKeyEx(m_SubKey.Handle,(T_LPCSTR)OutFile.c_str(), NULL, REG_STANDARD_FORMAT);
		if (RTN != ERROR_SUCCESS) { ErrorInfo = this->GetLastErrorString(RTN); Flag = false; }
	}
	this->CloseSubKey(m_SubKey.Handle);
	return Flag;
}

bool REG::OperaREGfile(string KeyPath, Tstring KeyName, Tstring InFile) {
	if (KeyPath.empty()) { ErrorInfo = this->GetCustomErrorString(this->Parameters); return false; }
	m_REGInfo.RootKeyHandle = this->GetRootKeyHandle(KeyPath);
	LSTATUS RTN = ERROR_SUCCESS;
	bool Flag = this->GetSubKeyHandle(m_REGInfo.RootKeyHandle, KeyPath, m_SubKey);
	if (Flag && this->EnableBackupPrivilege()) {
		if (!InFile.empty()) {
			RTN = RegLoadKey(m_SubKey.Handle, (T_LPCSTR)KeyName.c_str(), (T_LPCSTR)InFile.c_str());
		}else{
			RTN = RegUnLoadKey(m_SubKey.Handle, (T_LPCSTR)KeyName.c_str());
		}
		if (RTN != ERROR_SUCCESS) { ErrorInfo = this->GetLastErrorString(RTN); Flag = false; }
	}
	this->CloseSubKey(m_SubKey.Handle);
	return Flag;
}
*/

Tstring REGFunc::GetFileName(Tstring Path) {
	Tstring Name = Path.substr(Path.find_last_of(TEXTEx("\\")) + 1);
	return (Name.find(TEXTEx(".")) != Tstring::npos) ? Name.substr(0, Name.find(TEXTEx("."))) : TEXTEx("None");
}

bool REGFunc::WinStartRun(Tstring ProgramPath, bool is_Current) {
	Tstring SubPath = TEXTEx("\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
	Tstring WinStartRunPath = ((is_Current) ? TEXTEx("HKEY_CURRENT_USER") : TEXTEx("HKEY_LOCAL_MACHINE")) + SubPath;
	Tstring Name = this->GetFileName(ProgramPath);
	if ( Name == TEXTEx("None")) return false;
	return Opera.ModifyKeyValue(WinStartRunPath, Name, ProgramPath);
}

void REGFunc::SetFilePopupMenu(Tstring MenuShellPath, REGFunc::FileMenuInfo MenuInfo) {
	Opera.AddSubKey(MenuShellPath, MenuInfo.MenuName);   // 添加扩展名菜单命令路径
	Opera.ModifyKeyValue(Opera.RegisterPath, TEXTEx(""), MenuInfo.DisplayName);   // 设置扩展名菜单名称
	Opera.ModifyKeyValue(Opera.RegisterPath, TEXTEx("Icon"), MenuInfo.Icon);   // 设置扩展名菜单图标
	Opera.AddSubKey(Opera.RegisterPath + TEXTEx("\\command"), TEXTEx(""));   // 添加扩展名菜单命令子项
	Opera.ModifyKeyValue(Opera.RegisterPath, TEXTEx(""), MenuInfo.Command);   // 设置扩展名菜单命令
}

void REGFunc::SetFileAssociation(Tstring FileSuffix, REGFunc::FileSuffixInfo FSInfo) {
	Tstring ShellName, SuffixShellPath, MenuShellPath;
	if (FileSuffix.substr(0, 1) != TEXTEx(".")) {
		ShellName.append(FileSuffix + TEXTEx("file"));
		FileSuffix.insert(0, TEXTEx("."));
	}else {
		ShellName.append(FileSuffix.substr(1) + TEXTEx("file"));
	}
	// 设置扩展名及文件关联
	Opera.AddSubKey(TEXTEx("HKEY_CLASSES_ROOT\\"), FileSuffix);
	Opera.ModifyKeyValue(Opera.RegisterPath, TEXTEx(""), ShellName);
	// 设置扩展名信息与命令
	Opera.AddSubKey(TEXTEx("HKEY_CLASSES_ROOT\\"), ShellName);   // 添加扩展名信息路径

	Opera.ModifyKeyValue(Opera.RegisterPath, TEXTEx(""), FSInfo.FileType);   //设置扩展名类型
	Opera.AddSubKey(Opera.RegisterPath, TEXTEx("DefaultIcon"));   // 添加默认图标子项
	Opera.ModifyKeyValue(Opera.RegisterPath, TEXTEx(""), FSInfo.DefaultIcon);   // 设置扩展名默认图标
	// 设置扩展名菜单命令路径
	this->SetFilePopupMenu(TEXTEx("HKEY_CLASSES_ROOT\\") + ShellName + TEXTEx("\\shell\\"), FSInfo.MenuInfo);   

}
void REGFunc::SetGeneralPopupMenu(REGFunc::FileMenuInfo FMInfo) {
	this->SetFilePopupMenu(TEXTEx("HKEY_CLASSES_ROOT\\*\\shell"), FMInfo);
}
bool REGFunc::Product(Tstring ProgramPath, REGFunc::ProductInfo PInfo) {
	Tstring InstallPath = TEXTEx("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
	Tstring FileName = this->GetFileName(ProgramPath); bool RTN = false;
	switch (PInfo.State) {
	case REGFunc::Install:
		RTN = Opera.AddSubKey(InstallPath, FileName); InstallPath = Opera.RegisterPath;
		if (RTN) {
			Opera.ModifyKeyValue(InstallPath, TEXTEx("DisplayName"), PInfo.DisplayName);
			Opera.ModifyKeyValue(InstallPath, TEXTEx("DisplayIcon"), PInfo.DisplayIcon);
			Opera.ModifyKeyValue(InstallPath, TEXTEx("DisplayVersion"), PInfo.DisplayVersion);
			Opera.ModifyKeyValue(InstallPath, TEXTEx("Publisher"), PInfo.Publisher);
			Opera.ModifyKeyValue(InstallPath, TEXTEx("URLInfoAbout"), PInfo.URLInfoAbout);
			Opera.ModifyKeyValue(InstallPath, TEXTEx("URLUpdateInfo"), PInfo.URLUpdateInfo);
			Opera.ModifyKeyValue(InstallPath, TEXTEx("HelpLink"), PInfo.HelpLink);
			Opera.ModifyKeyValue(InstallPath, TEXTEx("UnInstallString"), PInfo.UnInstallString);
			Opera.ModifyKeyValue(InstallPath, TEXTEx("EstimatedSize"), PInfo.EstimatedSize);
		}
		return RTN;
		break;
	case REGFunc::UnInstall:
		return Opera.DeleteSubKey(InstallPath, FileName, REG::bit64);
		break;
	}
}