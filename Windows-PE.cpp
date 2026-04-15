#pragma once

// 如果使用方会使用智能指针的话，请把下一行的注释去掉，核心使用规范与重要注意事项中的 Part1 可以忽略
// #include <memory>

#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
//#include <ImageHlp.h>

//#pragma comment(lib, "ImageHlp.lib")

#define ALIGN_UP(Size, align) (((Size) + (align) - 1) & ~((align) - 1))

uintptr_t GetModuleBaseAddress(DWORD pid, const wchar_t* Module) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}
	MODULEENTRY32 moduleEntry = { 0 };
	moduleEntry.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hSnapshot, &moduleEntry)) {
		CloseHandle(hSnapshot);
		return 0;
	}
	do {
		if (_wcsicmp(moduleEntry.szModule, Module) == 0 || _wcsicmp(moduleEntry.szExePath, Module) == 0) {
			CloseHandle(hSnapshot);
			return (uintptr_t)moduleEntry.modBaseAddr;
		}
	} while (Module32Next(hSnapshot, &moduleEntry));

	CloseHandle(hSnapshot);
	return 0;
}

/*
* 1. RVA 与 FOA 互转 (RVA <-> File Offset)  yes
* 2. 获取导入表 (Import Table)				yes
* 3. 获取导出表 (Export Table)				yes
* 4. 获取资源表 (Resource Table)			yes
* 5. 手动映射 (Manual Map)					pass
* 6. 重定位表处理 (Relocation Table)		yes
* 7. 校验和计算 (Checksum)					yes
* 8. 获取节区详细信息						pass easy
* 9. 壳检测 (Packers Detection)				
*/

/*  核心使用规范与重要注意事项
* 
* Part 1
* 调用 Read，GetSectionName, GetExportTable，GetResourceTable 这些方法之后一定要记得调用 free(pointer);
* 调用 BuildMemoryImage 方法之后一定要调用 VirtualFree(pointer, 0, MEM_RELEASE);
* 否则会发生内存泄露
* 
* Part 2
* 为了防止架构不匹配导致的崩溃，MemoryToFileDump、GetExportTable、FixImportTable 和 Relocation 在执行核心逻辑前都会强制验证目标文件的平台位数。
*/
namespace PE {
	// 错误状态枚举，表示各种可能的错误情况
	enum STATUS {
		// 基础错误
		PE_STATUS_SUCCESS,							// 成功
		PE_STATUS_INVALID_PARAMETER,				// 无效参数
		PE_STATUS_INVALID_FORMAT,					// 无效的 PE 格式

		// 文件操作相关错误
		PE_STATUS_FILE_OPEN_FAILURE,				// 文件打开失败
		PE_STATUS_FILE_READ_FAILURE,				// 文件读取失败
		PE_STATUS_FILE_WRITE_FAILURE,				// 文件写入失败
		PE_STATUS_FILE_NOT_FOUND,					// 文件未找到
		PE_STATUS_FILE_ACCESS_DENIED,				// 文件访问被拒绝
		PE_STATUS_FILE_INVALID_SIZE,				// 文件大小无效
		
		// PE 结构相关错误
		PE_STATUS_ARCH_MISMATCH,					// 架构不匹配
		PE_STATUS_BUILD_IMAGE_FAILURE,				// 构建内存映像失败
		PE_STATUS_FIX_IMPORT_FAILURE,				// 修复导入表失败
		PE_STATUS_GET_EXPORT_FAILURE,				// 获取导出表失败
		PE_STATUS_SET_SECTION_PROPERTY_FAILURE,		// 设置节属性失败
		PE_STATUS_GET_RESOURCE_FAILURE,				// 获取资源表失败
		PE_STATUS_GET_FOA_FAILURE,					// 获取 FOA 失败
		PE_STATUS_GET_RVA_FAILURE,					// 获取 RVA 失败
		PE_STATUS_IMPORT_INT_MISSING,				// 导入表缺失 INT 信息

		// 内存操作相关错误
		PE_STATUS_PROCESS_OPEN_FAILURE,				// 打开进程失败
		PE_STATUS_REMOTE_MEMORY_ALLOCATION_FAILURE,	// 远程内存分配失败
		PE_STATUS_REMOTE_MEMORY_WRITE_FAILURE,		// 远程内存写入失败
		PE_STATUS_REMOTE_MEMORY_READ_FAILURE,		// 远程内存读取失败
		PE_STATUS_LOCAL_MEMORY_ALLOCATION_FAILURE,	// 本地内存分配失败
		PE_STATUS_LOCAL_MEMORY_WRITE_FAILURE,		// 本地内存写入失败
		PE_STATUS_LOCAL_MEMORY_READ_FAILURE,		// 本地内存读取失败
		PE_STATUS_LOAD_MODULE_FAILURE,				// 加载模块失败
		PE_STATUS_GET_MODULE_BASE_FAILURE,			// 获取模块基址失败
		PE_STATUS_GET_MODULE_INFO_FAILURE,          // 获取模块信息失败
		PE_STATUS_MODULE_NOT_FOUND,					// 模块未找到
		PE_STATUS_MODULE_RANGE_NOT_IN				// 模块范围不在预期范围内
	};

	// 节区转储枚举，表示要转储的 PE 结构部分
	enum DumpStruct {
		DOS,
		DOS_stub,
		NT,
		SectionTable,
		SectionInfo
	};

	// 资源类型枚举，包含常见的 Windows 资源类型
	enum ResourceType : WORD {
		Cursor = 1,
		Bitmap = 2,
		Icon = 3,
		Menu = 4,
		Dialog = 5,
		String = 6,
		FontDir = 7,
		Font = 8,
		Accelrator = 9,
		RC_Data = 10,
		MessageTable = 11,
		GroupCursor = Cursor + DIFFERENCE,
		GroupIcon = Icon + DIFFERENCE,
		Version = 16,
		Dlginclude = 17,
		NoneResources = 0xFFFF
	};

	struct FuncInfo {
		WORD Ordinal;				// 函数序号
		DWORD RVA_Address;			// 函数的 RVA 地址
		char* Name;					// 函数名称 (如果有的话，某些导出可能没有名称只有序号)
	};

	struct ExportInfo {
		char PEName[48];			// PE 文件名
		DWORD FuncCount;			// 导出函数数量
		DWORD ExportFuncSize;		// 导出函数表大小 (字节)
		FuncInfo* Fn;				// 动态数组，存储所有导出函数的信息
	};

	struct ResourceItem {
		wchar_t TypeName[32];      // 类型名 (或 ID)
		wchar_t Name[64];          // 资源名 (或 ID)
		wchar_t Language[16];      // 语言 ID
		DWORD DataRVA;             // 资源数据的 RVA
		DWORD Size;                // 资源大小
	};

	struct ResourceInfo {
		ResourceItem* Items;       // 动态数组，存储所有找到的资源项
		DWORD Count;               // 资源总数
	};
	
	STATUS Read(const wchar_t* FileName, void*& out_pFileBuffer, DWORD& out_FileSize);
	STATUS IsValid(void* pBuffer, IMAGE_NT_HEADERS*& out_pNtHeader);
	STATUS GetMachineType(void* pFileBuffer, WORD& out_MachineType);
	STATUS GetSubSystem(void* pFileBuffer, WORD& out_SubSystemInfo);
	STATUS GetEntryPoint(void* pFileBuffer, DWORD& out_OEP_Address);
	STATUS GetPeFormat(void* pFileBuffer, WORD& out_HDR);
	STATUS GetSectionName(void* pFileBuffer, void*& out_SectionName, size_t& SectionNameSize);
	STATUS GetPEChecksum(void* pFileBuffer, DWORD FileSize, DWORD& file_Checksum, DWORD& out_Checksum, bool& out_IsPass);
	STATUS FileSectionDump(void* pFileBuffer, DumpStruct Signature, char* SectionName, const wchar_t* DumpFile);
	STATUS MemoryDump(const wchar_t* ExecuteFile, const wchar_t* DumpFile);
	STATUS MemoryToFileDump(void* pMemoryImage, const wchar_t* DumpFile);
	DWORD RvaToFoa(void* pBuffer, DWORD RVA);
	DWORD FoaToRva(void* pBuffer, DWORD FileSize, DWORD FOA);
	STATUS BuildMemoryImage(void* pFileBuffer, void*& pMemoryImage);
	STATUS GetExportTable(void* pFileBuffer, ExportInfo*& out_pExpInfo);
	STATUS FixImportTable(DWORD pid, void* pMemoryImage/*, void* pRemoteImageBase*/);
	STATUS Relocation(void* pMemoryImage, void* pRemoteImageBase);
	STATUS SetSectionProperty(void* pFileBuffer, void* pMemoryImage);
	STATUS SetSectionProperty(HANDLE hProcess, void* pFileBuffer, void* pMemoryImage);
	STATUS GetResourceTable(void* pFileBuffer, ResourceInfo& ResInfo, ResourceType TypeID = NoneResources);
	STATUS CalculateEntropy(const void* buffer, size_t size, double& out_Entropy);
}

/**
 * @brief 读取整个 PE 文件内容到堆内存缓冲区
 *
 * 该函数负责打开指定路径的文件，获取其大小，并分配堆内存 (Heap Memory)
 * 将文件数据完整读入。这是解析 PE 结构的第一步。
 *
 * @warning 内存管理警告:
 * 该函数使用 calloc 分配内存，调用者有责任在使用完毕后 (如解析结束或注入完成后)
 * 调用 free(out_pFileBuffer) 释放内存，否则会导致堆内存泄露。
 *
 * @param FileName          [in]  要读取的 PE 文件路径 (宽字符字符串)
 * @param out_pFileBuffer   [out] 输出参数，指向包含文件原始字节流的内存缓冲区指针
 * @param out_FileSize      [out] 输出参数，返回实际读取到的文件大小 (字节)
 * @return PE::STATUS       返回读取操作的状态码
 * @retval PE_STATUS_SUCCESS            				读取成功
 * @retval PE_STATUS_INVALID_PARAMETER  				参数无效 (FileName 为空)
 * @retval PE_STATUS_INVALID_FORMAT     				源文件不是有效的 PE 格式
 * @retval PE_STATUS_FILE_NOT_FOUND     				文件不存在或无法访问
 * @retval PE_STATUS_FILE_OPEN_FAILURE  				打开文件失败 (权限不足或文件被占用)
 * @retval PE_STATUS_FILE_INVALID_SIZE   				源文件无法获取文件长度
 * @retval PE_STATUS_LOCAL_MEMORY_ALLOCATION_FAILURE    本地内存申请失败
 * @retval PE_STATUS_LOCAL_MEMORY_WRITE_FAILURE         数据写入失败 (系统资源不足)
 */
PE::STATUS  PE::Read(const wchar_t* FileName, void*& out_pFileBuffer, DWORD& out_FileSize) {
	if (FileName == nullptr) return PE_STATUS_INVALID_PARAMETER;
	BOOL apiRTN = FALSE;
	STATUS RTN = PE_STATUS_SUCCESS;
	out_pFileBuffer = nullptr;
	DWORD ReadTotalBytes = NULL;
	if (GetFileAttributesW(FileName) == INVALID_FILE_ATTRIBUTES) return PE_STATUS_FILE_NOT_FOUND;
	HANDLE hFile = CreateFileW(FileName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != 0 && hFile != INVALID_HANDLE_VALUE) {
		LARGE_INTEGER FS;
		apiRTN = GetFileSizeEx(hFile, &FS);
		out_FileSize = static_cast<DWORD>(FS.QuadPart);
		if (apiRTN && out_FileSize != NULL) {
			out_pFileBuffer = calloc(1, out_FileSize);
			if (out_pFileBuffer != nullptr) {
				apiRTN = ReadFile(hFile, out_pFileBuffer, out_FileSize, &ReadTotalBytes, NULL);
				if (apiRTN && out_FileSize == ReadTotalBytes) {
					CloseHandle(hFile);
					return PE_STATUS_SUCCESS;
				}else RTN = PE_STATUS_LOCAL_MEMORY_WRITE_FAILURE;
				free(out_pFileBuffer);
				out_pFileBuffer = nullptr;
			}else RTN = PE_STATUS_LOCAL_MEMORY_ALLOCATION_FAILURE;
		}else RTN = PE_STATUS_FILE_INVALID_SIZE;
		CloseHandle(hFile);
		return RTN;
	}
	return PE_STATUS_FILE_OPEN_FAILURE;
}

/**
 * @brief 验证内存缓冲区是否为有效的 PE (Portable Executable) 文件结构
 *
 * 该函数执行双重校验：
 * 1. 检查 DOS Header 签名 (IMAGE_DOS_SIGNATURE) 是否存在。
 * 2. 根据 e_lfanew 偏移定位并检查 NT Header 签名 (IMAGE_NT_SIGNATURE)。
 *
 * @warning 边界检查:
 * 函数内部包含对 e_lfanew 的范围检查，防止恶意构造的 PE 文件导致指针溢出
 * 或访问非法内存区域 (防止 0x7FFFFFFF 溢出攻击)。
 *
 * @param pBuffer         [in]  指向待校验的文件内存缓冲区 (通常由 Read 函数加载)
 * @param out_pNtHeader   [out] 输出参数。若校验成功，该指针指向缓冲区内的 IMAGE_NT_HEADERS 结构。
 *                            调用者可直接使用此指针访问 PE 的文件头和可选头信息。
 * @return PE::STATUS     校验结果状态码
 * @retval PE_STATUS_SUCCESS          	校验通过，这是一个有效的 PE 文件
 * @retval PE_STATUS_INVALID_PARAMETER 	输入缓冲区指针为空
 * @retval PE_STATUS_INVALID_FORMAT    	缓冲区数据不符合 PE 文件格式 (坏文件或非 PE 文件)
 */
PE::STATUS PE::IsValid(void* pBuffer, IMAGE_NT_HEADERS*& out_pNtHeader) {
	if (pBuffer == nullptr) return PE_STATUS_INVALID_PARAMETER;
	out_pNtHeader = nullptr;
	IMAGE_DOS_HEADER* pDosHeader = static_cast<IMAGE_DOS_HEADER*>(pBuffer);
	if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
		if (pDosHeader->e_lfanew <= 0 || pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > 0x7FFFFFFF) return PE_STATUS_INVALID_FORMAT;
		out_pNtHeader =  reinterpret_cast<IMAGE_NT_HEADERS*>(static_cast<char*>(pBuffer) + pDosHeader->e_lfanew);
		if (static_cast<IMAGE_NT_HEADERS*>(out_pNtHeader)->Signature == IMAGE_NT_SIGNATURE) {
			return PE_STATUS_SUCCESS; 
		}
	}
	return PE_STATUS_INVALID_FORMAT;
}

/**
 * @brief 获取 PE 文件的机器类型 (Machine Type)
 *
 * 该函数用于识别 PE 文件的目标运行架构。
 * 它通过解析 NT Header 中的 FileHeader.Machine 字段来判断文件是 32位 (x86)、
 * 64位 (x64) 还是其他架构 (如 ARM)。
 *
 * @note 架构常量参考:
 * - IMAGE_FILE_MACHINE_I386  (0x014c): 32位 x86 架构
 * - IMAGE_FILE_MACHINE_AMD64 (0x8664): 64位 x64 架构
 * - IMAGE_FILE_MACHINE_ARM   (0x01c0): ARM 架构
 *
 * @param pFileBuffer     [in]  指向 PE 文件内存缓冲区的指针 (需先通过 IsValid 校验)
 * @param out_MachineType [out] 输出参数，返回机器类型常量 (WORD 类型)
 * @return PE::STATUS     获取结果状态码
 * @retval PE_STATUS_SUCCESS          	获取成功
 * @retval PE_STATUS_INVALID_PARAMETER 	输入缓冲区指针为空
 * @retval PE_STATUS_INVALID_FORMAT    	文件格式无效，无法定位到 Machine 字段
 */
PE::STATUS PE::GetMachineType(void* pFileBuffer, WORD& out_MachineType) {
	if (pFileBuffer == nullptr) return PE_STATUS_INVALID_PARAMETER;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader) == PE_STATUS_SUCCESS) {
		out_MachineType = pNtHeader->FileHeader.Machine;
		return PE_STATUS_SUCCESS;
	}
	return PE_STATUS_INVALID_FORMAT;
}

/**
 * @brief 获取 PE 文件的子系统类型 (Subsystem)
 *
 * 该函数用于识别 PE 文件运行所需的系统环境。
 * 它读取 Optional Header 中的 Subsystem 字段，决定了程序启动时是显示图形界面、
 * 控制台窗口，还是作为内核驱动运行。
 *
 * @note 常见子系统常量参考:
 * - IMAGE_SUBSYSTEM_WINDOWS_GUI        (2): 图形界面程序 (无控制台窗口)
 * - IMAGE_SUBSYSTEM_WINDOWS_CUI        (3): 控制台程序 (黑框窗口)
 * - IMAGE_SUBSYSTEM_NATIVE             (1): 原生系统程序 (如 smss.exe)
 * - IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION (16): 启动应用程序
 *
 * @param pFileBuffer       [in]  指向 PE 文件内存缓冲区的指针
 * @param out_SubSystemInfo [out] 输出参数，返回子系统类型常量 (WORD 类型)
 * @return PE::STATUS       获取结果状态码
 * @retval PE_STATUS_SUCCESS          	获取成功
 * @retval PE_STATUS_INVALID_PARAMETER 	输入缓冲区指针为空
 * @retval PE_STATUS_INVALID_FORMAT    	文件格式无效，无法定位到 Subsystem 字段
 */
PE::STATUS PE::GetSubSystem(void* pFileBuffer, WORD& out_SubSystemInfo) {
	if (pFileBuffer == nullptr) return PE_STATUS_INVALID_PARAMETER;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader) == PE_STATUS_SUCCESS) {
		out_SubSystemInfo = pNtHeader->OptionalHeader.Subsystem;
		return PE_STATUS_SUCCESS;
	}
	return PE_STATUS_INVALID_FORMAT;
}

/**
 * @brief 获取 PE 文件的入口点地址 (OEP - Original Entry Point)
 *
 * 该函数提取 Optional Header 中的 AddressOfEntryPoint 字段。
 * 这是操作系统加载器在将 PE 文件映射到内存后，开始执行代码的起始位置。
 *
 * @note 重要说明:
 * 1. 返回值类型: 返回的是 **RVA (Relative Virtual Address)**，即相对于镜像基址的偏移量。
 *    在手动映射中，实际执行地址 = 映射基址 + RVA。
 * 2. 壳/加密影响: 如果 PE 文件被加壳 (如 UPX) 或加密，此字段通常指向壳的加载代码，
 *    而非程序的原始逻辑入口 (True OEP)。
 *
 * @param pFileBuffer     [in]  指向 PE 文件内存缓冲区的指针
 * @param out_OEP_Address [out] 输出参数，返回入口点的 RVA (DWORD 类型)
 * @return PE::STATUS     获取结果状态码
 * @retval PE_STATUS_SUCCESS          	获取成功
 * @retval PE_STATUS_INVALID_PARAMETER 	输入缓冲区指针为空
 * @retval PE_STATUS_INVALID_FORMAT    	文件格式无效，无法定位到入口点字段
 */
PE::STATUS PE::GetEntryPoint(void* pFileBuffer, DWORD& out_OEP_Address) {
	if (pFileBuffer == nullptr) return PE_STATUS_INVALID_PARAMETER;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader) == PE_STATUS_SUCCESS) {
		out_OEP_Address = pNtHeader->OptionalHeader.AddressOfEntryPoint;
		return PE_STATUS_SUCCESS;
	}
	return PE_STATUS_INVALID_FORMAT;
}

/**
 * @brief 获取 PE 文件的格式类型 (PE32 或 PE32+)
 *
 * 该函数通过读取 Optional Header 中的 Magic 字段，来判断 PE 文件是标准的 32 位格式
 * 还是扩展的 64 位格式 (PE32+)。
 *
 * @note 格式常量参考:
 * - IMAGE_NT_OPTIONAL_HDR32_MAGIC (0x10b): 标准 PE32 格式 (适用于 x86)
 * - IMAGE_NT_OPTIONAL_HDR64_MAGIC (0x20b): PE32+ 格式 (适用于 x64, IA64)
 *
 * @warning 架构关联:
 * 此格式决定了 Optional Header 中基址字段的大小。
 * PE32+ 格式通常意味着文件包含 64 位地址，需要使用 8 字节指针处理。
 *
 * @param pFileBuffer [in]  指向 PE 文件内存缓冲区的指针
 * @param out_HDR     [out] 输出参数，返回 Magic 值 (WORD 类型)
 * @return PE::STATUS   获取结果状态码
 * @retval PE_STATUS_SUCCESS          	获取成功
 * @retval PE_STATUS_INVALID_PARAMETER 	输入缓冲区指针为空
 * @retval PE_STATUS_INVALID_FORMAT    	文件格式无效，无法定位到 Magic 字段
 */
PE::STATUS PE::GetPeFormat(void* pFileBuffer, WORD& out_HDR) {
	if (pFileBuffer == nullptr) return PE_STATUS_INVALID_PARAMETER;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader) == PE_STATUS_SUCCESS) {
		out_HDR = pNtHeader->OptionalHeader.Magic;
		return PE_STATUS_SUCCESS;
	}
	return PE_STATUS_INVALID_FORMAT;
}

/**
 * @brief 获取 PE 文件中所有节区的名称列表 (Section Names)
 *
 * 该函数遍历 PE 文件的节表 (Section Table)，提取每个节的名称（如 .text, .data, .rsrc 等）。
 *
 * @note 内存管理警告:
 * 该函数使用 calloc 分配内存，调用者有责任在使用完毕后调用 free(out_SectionName) 释放内存。
 *
 * @note 数据结构说明:
 * 返回的内存块是一个连续的字符数组。
 * 每个节名固定占用 8 字节 (IMAGE_SIZEOF_SHORT_NAME)，即使实际名称不足 8 字符也会用 NULL 填充。
 * 访问第 N 个节名的公式: (char*)out_SectionName + (N * 8)
 *
 * @param pFileBuffer     [in]  指向 PE 文件内存缓冲区的指针
 * @param out_SectionName [out] 输出参数，指向包含所有节名的连续内存块
 * @param SectionNameSize [out] 输出参数，返回分配的总字节数 (NumberOfSections * 8)
 * @return PE::STATUS     获取结果状态码
 * @retval PE_STATUS_SUCCESS          	获取成功
 * @retval PE_STATUS_INVALID_PARAMETER 	输入缓冲区指针为空
 * @retval PE_STATUS_INVALID_FORMAT    	文件格式无效，无法定位节表
 */
PE::STATUS PE::GetSectionName(void* pFileBuffer, void*& out_SectionName, size_t& SectionNameSize) {
	if (pFileBuffer == nullptr) return PE_STATUS_INVALID_PARAMETER;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	out_SectionName = nullptr;
	if (IsValid(pFileBuffer, pNtHeader) == PE_STATUS_SUCCESS) {
		out_SectionName = calloc(pNtHeader->FileHeader.NumberOfSections, sizeof(char[8]));
		SectionNameSize = pNtHeader->FileHeader.NumberOfSections * sizeof(char[8]);
		IMAGE_SECTION_HEADER* pSectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(
			static_cast<char*>(pFileBuffer) + 
			static_cast<IMAGE_DOS_HEADER*>(pFileBuffer)->e_lfanew +
			offsetof(IMAGE_NT_HEADERS, OptionalHeader) +
			pNtHeader->FileHeader.SizeOfOptionalHeader
		);
		int SectionIndex = 0;
		for (; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
			void* WritePos = static_cast<char*>(out_SectionName) + SectionIndex * sizeof(char[8]);
			memcpy(WritePos, pSectionHeader->Name, sizeof(char[8]));
			pSectionHeader++;
		}
		if (SectionIndex == pNtHeader->FileHeader.NumberOfSections) return PE_STATUS_SUCCESS;
	}
	return PE_STATUS_INVALID_FORMAT;
}

/**
 * @brief 计算并验证 PE 文件的校验和 (Checksum)
 *
 * 该函数通过标准的 Windows PE 校验算法（16位字累加折叠算法）重新计算文件的校验和，
 * 并与文件头中存储的校验和进行比对。
 *
 * @note 算法原理:
 * 1. 临时将文件头中的 CheckSum 字段置为 0 (因为计算时不包含校验和本身的值)。
 * 2. 将整个文件视为 WORD (16位) 数组进行累加。
 * 3. 处理进位：将超过 16 位的高位折叠加回低位 (Carry Wraparound)。
 * 4. 最后加上文件的原始大小。
 *
 * @warning 内核驱动强制校验:
 * 普通应用程序 (EXE/DLL) 通常忽略此校验，但内核模式驱动 (SYS) 在加载时
 * 会强制检查此值。如果校验失败，驱动将无法加载。
 *
 * @param pFileBuffer   [in]  指向 PE 文件内存缓冲区的指针
 * @param FileSize      [in]  文件的总字节大小
 * @param file_Checksum [out] 输出文件中原本存储的校验和值 (来自 OptionalHeader)
 * @param out_Checksum  [out] 输出根据当前文件内容重新计算得到的校验和值
 * @param out_IsPass    [out] 输出校验结果 (true 表示文件完整未被篡改，false 表示不匹配)
 * @return PE::STATUS   验证结果状态码
 * @retval PE_STATUS_SUCCESS          	文件是有效的 PE，且完成了校验计算
 * @retval PE_STATUS_INVALID_PARAMETER 	输入缓冲区指针为空
 * @retval PE_STATUS_INVALID_FORMAT    	文件格式无效，无法定位校验和字段
 */
PE::STATUS PE::GetPEChecksum(void* pFileBuffer, DWORD FileSize, DWORD& file_Checksum, DWORD& out_Checksum, bool& out_IsPass) {
	if (pFileBuffer == nullptr) return PE_STATUS_INVALID_PARAMETER;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	STATUS RTN = IsValid(pFileBuffer, pNtHeader);
	if (RTN == PE_STATUS_SUCCESS) {
		file_Checksum = pNtHeader->OptionalHeader.CheckSum;
		pNtHeader->OptionalHeader.CheckSum = 0;
		DWORD tmp_FileSize = FileSize + (FileSize % 2);
		DWORD WordBlockTotal = tmp_FileSize / sizeof(WORD);
		out_Checksum = 0;
		for (DWORD WordBlockIndex = 0; WordBlockIndex < WordBlockTotal; WordBlockIndex++) {
			out_Checksum += *(WORD*)((char*)pFileBuffer + WordBlockIndex * sizeof(WORD));
			if (out_Checksum > 0xFFFF) {
				// 再次折叠以防万一
				out_Checksum = (out_Checksum & 0xFFFF) + (out_Checksum >> 16);
				out_Checksum = (out_Checksum & 0xFFFF) + (out_Checksum >> 16);
			}
		}
		out_Checksum += FileSize;
		out_IsPass = (file_Checksum == out_Checksum);
		pNtHeader->OptionalHeader.CheckSum = file_Checksum;
	}
	return RTN;
}

/**
 * @brief 将 PE 文件的特定结构部分转储 (Dump) 到磁盘文件
 *
 * 该函数允许用户将 PE 文件拆解，单独提取 DOS 头、NT 头、节表或特定节区的原始数据。
 * 常用于逆向分析、文件修复或 PE 结构学习。
 *
 * @param pFileBuffer [in]  PE 文件内存缓冲区
 * @param Signature   [in]  指定要转储的部分 (枚举值: DOS, DOS_stub, NT, SectionTable, SectionInfo) 
 *                        - DOS: 仅转储 IMAGE_DOS_HEADER (通常 64 字节)
 *                        - DOS_stub: 转储 DOS 头与 NT 头之间的填充代码 (Stub)
 *                        - NT: 转储 NT 头 (FileHeader + OptionalHeader)
 *                        - SectionTable: 转储整个节表数组 (所有 IMAGE_SECTION_HEADER)
 *                        - SectionInfo: 转储指定节名的**原始文件数据** (Raw Data)
 * @param SectionName [in]  当 Signature 为 SectionInfo 时，指定具体的节名称 (如 ".text", ".rsrc")。
 *                          其他模式下可传 nullptr。
 * @param DumpFile    [in]  输出文件的目标路径 (宽字符字符串)
 * @return PE::STATUS 操作结果状态码
 * @retval PE_STATUS_SUCCESS              		转储成功
 * @retval PE_STATUS_INVALID_PARAMETER    		参数无效 (如指定 SectionInfo 但未提供节名)
 * @retval PE_STATUS_INVALID_FORMAT       		源文件不是有效的 PE 格式
 * @retval PE_STATUS_FILE_OPEN_FAILURE    		无法创建或写入目标文件
 * @retval PE_STATUS_LOCAL_MEMORY_WRITE_FAILURE 写入过程中发生错误 (字节数不匹配)

 */
PE::STATUS PE::FileSectionDump(void* pFileBuffer, DumpStruct Signature, char* SectionName, const wchar_t* DumpFile) {
	if (pFileBuffer == nullptr) return PE_STATUS_INVALID_PARAMETER;
	if (DumpFile == nullptr) return PE_STATUS_INVALID_PARAMETER;

	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader) == PE_STATUS_SUCCESS) {
		// 创建输出文件
		HANDLE hFile = CreateFileW(DumpFile, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == 0 || hFile == INVALID_HANDLE_VALUE) return PE_STATUS_FILE_OPEN_FAILURE;

		bool RTN = false;
		void* WritePos = nullptr; // 数据源指针
		DWORD DumpSize = 0;       // 数据大小
		DWORD WriteBytes = 0;     // 实际写入字节数

		// 预计算关键偏移量
		DWORD DOS_Offset = static_cast<IMAGE_DOS_HEADER*>(pFileBuffer)->e_lfanew;
		DWORD OPTION_Offset = pNtHeader->FileHeader.SizeOfOptionalHeader;

		switch (Signature) {
		case DOS:
			// 转储 DOS 头 (通常是前 64 字节)
			WritePos = pFileBuffer;
			DumpSize = sizeof(IMAGE_DOS_HEADER);
			break;

		case DOS_stub:
			// 转储 DOS Stub (DOS 头之后，NT 头之前的部分，通常是一段 "This program cannot be run in DOS mode" 代码)
			WritePos = static_cast<char*>(pFileBuffer) + sizeof(IMAGE_DOS_HEADER);
			DumpSize = DOS_Offset - sizeof(IMAGE_DOS_HEADER);
			break;

		case NT:
			// 转储 NT 头 (包括 FileHeader 和 OptionalHeader)
			WritePos = static_cast<char*>(pFileBuffer) + DOS_Offset;
			DumpSize = offsetof(IMAGE_NT_HEADERS, OptionalHeader) + OPTION_Offset;
			break;

		case SectionTable:
			// 转储节表 (Section Table)，即所有 IMAGE_SECTION_HEADER 结构体
			WritePos = static_cast<char*>(pFileBuffer) + DOS_Offset + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + OPTION_Offset;
			DumpSize = pNtHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
			break;

		case SectionInfo:
			// 转储特定节区的**原始数据** (Raw Data)
			if (SectionName == nullptr) {
				CloseHandle(hFile);
				return PE_STATUS_INVALID_PARAMETER;
			}
			{
				// 定位到节表起始位置
				IMAGE_SECTION_HEADER* pSectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(
					static_cast<char*>(pFileBuffer) + DOS_Offset +
					offsetof(IMAGE_NT_HEADERS, OptionalHeader) + OPTION_Offset
					);

				// 遍历查找匹配的节名
				for (int SectionIndex = 0; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
					// 比较节名 (注意：节名不一定以 \0 结尾，但 strcmp 遇到 \0 会停，这里假设名字是标准的)
					// 更安全的做法是使用 memcmp 比较 8 字节
					if (strcmp((char*)pSectionHeader->Name, SectionName) == 0) { // 修正：strcmp 成功返回 0，原代码写的是 == NULL 也是对的
						// 定位到该节在文件中的原始数据偏移 (PointerToRawData)
						WritePos = static_cast<char*>(pFileBuffer) + pSectionHeader->PointerToRawData;
						// 大小为该节在文件中的占用大小 (SizeOfRawData)
						DumpSize = pSectionHeader->SizeOfRawData;
						break;
					}
					pSectionHeader++;
				}
			}
			break;

		default:
			CloseHandle(hFile);
			return PE_STATUS_INVALID_PARAMETER;
		}

		// 执行写入
		if (DumpSize > 0 && WritePos != nullptr) {
			RTN = WriteFile(hFile, WritePos, DumpSize, &WriteBytes, NULL);
		}

		CloseHandle(hFile);

		// 检查是否写入成功且字节数匹配
		if (RTN && DumpSize == WriteBytes) 
		    return PE_STATUS_SUCCESS;
		else
		    return PE_STATUS_LOCAL_MEMORY_WRITE_FAILURE;
	}
	return PE_STATUS_INVALID_FORMAT;
}

/**
 * @brief 启动指定可执行文件并将其进程内存镜像转储 (Dump) 到磁盘
 *
 * 该函数通过创建一个新进程，读取其加载到内存中的完整镜像 (Image)，
 * 并将其保存到本地磁盘。这通常用于获取程序加载后的实际内存布局。
 *
 * @warning 竞态条件 (Race Condition):
 * 由于进程创建后未挂起 (未使用 CREATE_SUSPENDED)，目标进程可能在 EnumProcessModules
 * 调用之前就已经开始执行甚至退出。这可能导致获取基址失败或读取到不完整的内存。
 *
 * @warning 暴力终止:
 * 获取内存后，函数使用 TerminateProcess 强制结束目标进程。这非常暴力，
 * 可能导致目标程序创建的文件被占用、资源未释放或产生僵尸进程。
 *
 * @warning 权限要求:
 * 调用此函数可能需要管理员权限，特别是当目标程序以高完整性级别运行时，
 * 否则 OpenProcess (EnumProcessModules 内部调用) 可能会因权限不足而失败。
 *
 * @param ExecuteFile [in] 要运行并转储的可执行文件路径 (宽字符字符串)
 * @param DumpFile    [in] 内存镜像保存的目标文件路径 (宽字符字符串)
 * @return PE::STATUS 操作结果状态码
 * @retval PE_STATUS_SUCCESS                 	转储成功
 * @retval PE_STATUS_FILE_OPEN_FAILURE        	无法创建目标进程或无法创建输出文件
 * @retval PE_STATUS_PROCESS_OPEN_FAILURE     	无法打开进程句柄 (权限不足)
 * @retval PE_STATUS_GET_MODULE_BASE_FAILURE  	无法获取模块基址
 * @retval PE_STATUS_GET_MODULE_INFO_FAILURE 	无法获取模块信息 (GetModuleInformation 失败)
 * @retval PE_STATUS_REMOTE_MEMORY_READ_FAILURE 读取远程进程内存失败 (可能被反作弊保护)
 * @retval PE_STATUS_FILE_WRITE_FAILURE       	写入磁盘文件失败 (字节数不匹配)
 */
PE::STATUS PE::MemoryDump(const wchar_t* ExecuteFile, const wchar_t* DumpFile) {
	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(STARTUPINFOW);

	MODULEINFO ModInfo = { 0 };
	SIZE_T ReadBytes = 0;
	void* pMemoryImage = nullptr;
	STATUS RTN = PE_STATUS_SUCCESS;

	// 构建命令行缓冲区
	wchar_t szCommandLine[MAX_PATH * 2] = { 0 };
	wcsncpy_s(szCommandLine, ExecuteFile, _TRUNCATE); // 建议使用 _TRUNCATE 防止溢出

	// 1. 创建进程 (挂起或直接运行，此处未挂起，存在竞态条件风险，但在简单场景下可用)
	// CREATE_NO_WINDOW: 不创建窗口
	if (CreateProcessW(NULL, (LPWSTR)szCommandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {

		HMODULE BaseAddress = nullptr;
		DWORD Need = 0;

		// 2. 枚举进程模块，获取主模块基址
		// 注意：EnumProcessModules 需要目标进程有查询权限
		if (EnumProcessModules(pi.hProcess, &BaseAddress, sizeof(BaseAddress), &Need)) {
			if (BaseAddress) {
				// 3. 获取模块详细信息 (基址、映像大小等)
				if (GetModuleInformation(pi.hProcess, BaseAddress, &ModInfo, sizeof(MODULEINFO))) {

					// 4. 在本地分配足够大的内存
					pMemoryImage = VirtualAlloc(NULL, ModInfo.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

					if (pMemoryImage) {
						// 5. 读取远程进程内存到本地缓冲区
						// 读取整个映像大小 (SizeOfImage) 或 读取字节数不足 (可能进程被保护或内存未提交)
						if (!ReadProcessMemory(pi.hProcess, ModInfo.lpBaseOfDll, pMemoryImage, ModInfo.SizeOfImage, &ReadBytes) || ReadBytes != ModInfo.SizeOfImage) {
							// 如果读取失败
							VirtualFree(pMemoryImage, 0, MEM_RELEASE);
							pMemoryImage = nullptr;
							RTN = PE_STATUS_REMOTE_MEMORY_READ_FAILURE;
						}
					}else RTN = PE_STATUS_LOCAL_MEMORY_ALLOCATION_FAILURE;
				}else RTN = PE_STATUS_GET_MODULE_INFO_FAILURE;
			}else RTN = PE_STATUS_GET_MODULE_BASE_FAILURE;
		}else RTN = PE_STATUS_MODULE_NOT_FOUND;

		// 6. 清理：终止进程并关闭句柄
		// 注意：这里直接 TerminateProcess 是非常暴力的，可能导致文件占用或资源泄露，但在 Dump 工具中常见
		ResumeThread(pi.hThread);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}else RTN = PE_STATUS_PROCESS_OPEN_FAILURE;

	// 如果前面任何步骤失败，直接返回错误码
	if (RTN != PE_STATUS_SUCCESS) return RTN;

	// 7. 将内存镜像写入文件
	DWORD WriteBytes = 0;
	HANDLE hFile = 0;
	hFile = CreateFileW(DumpFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile != INVALID_HANDLE_VALUE) {
		BOOL WriteFlag = WriteFile(hFile, pMemoryImage, ModInfo.SizeOfImage, &WriteBytes, NULL);
		CloseHandle(hFile);
		if (!WriteFlag) WriteBytes = 0; // 写入失败，重置写入字节数为 0
	}

	// 释放本地分配的内存
	VirtualFree(pMemoryImage, 0, MEM_RELEASE);
	// 检查句柄是否有效
    if(hFile == 0 || hFile == INVALID_HANDLE_VALUE) return PE_STATUS_PROCESS_OPEN_FAILURE;
	// 检查 WriteBytes 是否等于 SizeOfImage
	RTN = (WriteBytes == ModInfo.SizeOfImage) ? PE_STATUS_SUCCESS : PE_STATUS_FILE_WRITE_FAILURE;
	return RTN;
}

/**
 * @brief 将 RVA (相对虚拟地址) 转换为 FOA (文件偏移地址)
 *
 * 该函数用于在 PE 文件结构中查找数据。
 * 由于 PE 文件在磁盘上（文件对齐）和在内存中（内存对齐）的布局不同，
 * 必须通过此函数将内存地址 (RVA) 还原为文件中的物理偏移 (FOA)。
 *
 * @note 转换逻辑详解:
 * 1. 文件头区域 (Header Region): 当 RVA < SizeOfHeaders 时，文件对齐与内存对齐通常一致，
 *    此时 FOA 等于 RVA。
 * 2. 节区数据区域 (Section Region): 当 RVA 位于某个节内时，
 *    FOA = PointerToRawData (节在文件中的起始偏移) + (RVA - VirtualAddress (节在内存中的起始地址))。
 *
 * @param pBuffer [in]  PE 文件内存缓冲区
 * @param RVA     [in]  需要转换的相对虚拟地址 (相对于镜像基址的偏移)
 * @return DWORD  成功返回文件偏移地址 (FOA)，失败返回 -1 (0xFFFFFFFF)
 */
DWORD PE::RvaToFoa(void* pBuffer, DWORD RVA) {
	if (pBuffer == nullptr) return -1;

	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	// 1. 验证 PE 有效性并获取 NT 头指针
	if (IsValid(pBuffer, pNtHeader) == PE_STATUS_SUCCESS) {
		// 2. 边界检查：如果 RVA 超过映像大小，无效
		if (RVA > pNtHeader->OptionalHeader.SizeOfImage) return -1;

		// 3. 特殊情况：文件头区域
		// 在 SizeOfHeaders 范围内的数据，文件偏移与虚拟地址是一致的
		if (RVA < pNtHeader->OptionalHeader.SizeOfHeaders) return RVA;

		// 4. 定位节表 (Section Table) 起始位置
		// 计算公式: NT头基址 + Signature(4字节) + FileHeader(20字节) + OptionalHeaderSize
		// 注意：这里通过指针运算手动计算偏移，也可以直接使用 offsetof
		IMAGE_SECTION_HEADER* pSectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(
			(char*)pNtHeader + sizeof(pNtHeader->Signature) +
			sizeof(IMAGE_FILE_HEADER) + pNtHeader->FileHeader.SizeOfOptionalHeader
			);

		// 5. 遍历所有节
		for (DWORD SectionIndex = 0; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
			// 获取当前节的虚拟地址范围 [VAStart, VAEnd]
			DWORD VAStart = pSectionHeader->VirtualAddress;
			// 注意：这里使用 VirtualSize (内存中的实际大小) 来判断范围
			DWORD VAEnd = pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize;

			// 判断 RVA 是否落在当前节内
			if (RVA >= VAStart && RVA < VAEnd) { // 建议改为 < VAEnd 以避免边界重叠问题，原代码 <= 也可
				// 计算 RVA 相对于节起始地址的偏移量
				DWORD RVA_Offset = RVA - VAStart;

				// 返回：节的文件起始偏移 + 节内偏移
				return pSectionHeader->PointerToRawData + RVA_Offset;
			}
			pSectionHeader++; // 移动到下一个节表项
		}
	}
	// 未找到对应的节或验证失败
	return -1;
}

/**
 * @brief 将 FOA (文件偏移地址) 转换为 RVA (相对虚拟地址)
 *
 * 该函数是 RvaToFoa 的逆向操作，常用于解析 PE 文件结构时，
 * 根据文件中的物理偏移（如目录项指向的偏移）定位到内存中的虚拟地址。
 *
 * @note 转换逻辑详解:
 * 1. 文件头区域 (Header Region): 当 FOA < SizeOfHeaders 时，FOA 等于 RVA。
 * 2. 节区数据区域 (Section Region): 当 FOA 位于某个节的文件范围内时，
 *    RVA = VirtualAddress (节在内存中的起始地址) + (FOA - PointerToRawData (节在文件中的起始偏移))。
 * 3. 空数据节处理: 如果某节在文件中不占空间 (SizeOfRawData 为 0，如 .bss 节)，
 *    该节不会匹配任何 FOA，函数将自动跳过，这是符合预期的。
 *
 * @param pBuffer  [in] PE 文件内存缓冲区
 * @param FileSize [in] 文件总大小 (用于边界检查，防止越界)
 * @param FOA      [in] 需要转换的文件偏移地址 (File Offset Address)
 * @return DWORD   成功返回相对虚拟地址 (RVA)，失败返回 -1 (0xFFFFFFFF)
 */
DWORD PE::FoaToRva(void* pBuffer, DWORD FileSize, DWORD FOA) {
	if (pBuffer == nullptr) return -1;

	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pBuffer, pNtHeader) == PE_STATUS_SUCCESS) {
		// 1. 边界检查：如果 FOA 超过文件实际大小，无效
		if (FOA > FileSize) return -1;

		// 2. 特殊情况：文件头区域
		if (FOA < pNtHeader->OptionalHeader.SizeOfHeaders) return FOA;

		// 3. 定位节表起始位置 (逻辑同 RvaToFoa)
		IMAGE_SECTION_HEADER* pSectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(
			(char*)pNtHeader + sizeof(pNtHeader->Signature) +
			sizeof(IMAGE_FILE_HEADER) + pNtHeader->FileHeader.SizeOfOptionalHeader
			);

		// 4. 遍历所有节
		for (DWORD SectionIndex = 0; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
			// 获取当前节的文件偏移范围 [FAStart, FAEnd]
			DWORD FAStart = pSectionHeader->PointerToRawData;
			// 注意：这里使用 SizeOfRawData (文件中的占用大小) 来判断范围
			DWORD FAEnd = pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData;

			// 判断 FOA 是否落在当前节的文件范围内
			// 注意：如果 SizeOfRawData 为 0 (如 .bss 节在文件中不占空间)，此循环会跳过，这是正确的
			if (FOA >= FAStart && FOA < FAEnd) {
				// 计算 FOA 相对于节文件起始位置的偏移量
				DWORD FOA_Offset = FOA - pSectionHeader->PointerToRawData;

				// 返回：节的虚拟起始地址 + 节内偏移
				return pSectionHeader->VirtualAddress + FOA_Offset;
			}
			pSectionHeader++;
		}
	}
	return -1;
}

/**
 * @brief 构建内存中的 PE 镜像 (Build Memory Image)
 *
 * 该函数模拟 Windows 加载器的行为，将磁盘上按“文件对齐”存储的 PE 文件，
 * 重组为按“内存对齐”布局的内存镜像。
 *
 * @note 核心步骤:
 * 1. 分配内存: 根据 OptionalHeader.SizeOfImage 分配足够大的内存块。
 * 2. 复制头部: 将 DOS头、NT头、节表等头部信息整体复制到内存基址。
 * 3. 映射节区: 遍历节表，将每个节的原始数据 (RawData) 复制到其对应的虚拟地址 (VirtualAddress) 处。
 *
 * @warning 数据截断处理:
 * 在复制节区数据时，代码使用了 min(VirtualSize, SizeOfRawData)。
 * 这是为了防止当文件中的 SizeOfRawData 大于内存 VirtualSize 时发生缓冲区溢出。
 * 注意：这会导致 .bss 等未初始化节区的数据无法被填充（因为它们 VirtualSize 大但 RawSize 为 0），
 * 但在手动映射的上下文中，通常只需关注有实际数据的节。
 *
 * @param pFileBuffer  [in]  指向磁盘上原始 PE 文件数据的指针
 * @param pMemoryImage [out] 指向新分配的、已重组的内存镜像基址 (调用者需负责 VirtualFree)
 * @return PE::STATUS  操作结果状态码
 * @retval PE_STATUS_SUCCESS                 			构建成功
 * @retval PE_STATUS_INVALID_PARAMETER       			输入缓冲区指针为空
 * @retval PE_STATUS_INVALID_FORMAT          			文件格式无效
 * @retval PE_STATUS_LOCAL_MEMORY_ALLOCATION_FAILURE 	内存分配失败
 */
PE::STATUS PE::BuildMemoryImage(void* pFileBuffer, void*& pMemoryImage) {
	if (pFileBuffer == nullptr) return PE_STATUS_INVALID_PARAMETER;

	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	// 验证文件头有效性并获取 NT 头指针
	if (IsValid(pFileBuffer, pNtHeader) == PE_STATUS_SUCCESS) {
		void* Base = nullptr;
		// 1. 分配内存：大小为 OptionalHeader 中定义的 SizeOfImage (内存对齐后的总大小)
		// 权限设为 PAGE_READWRITE 以便后续写入数据和修复重定位/导入表
		Base = VirtualAlloc(NULL, pNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
		if (Base == nullptr) return PE_STATUS_LOCAL_MEMORY_ALLOCATION_FAILURE;

		// 2. 复制 PE 头 (DOS 头 + NT 头 + 节表)
		// 复制大小为 SizeOfHeaders，这通常包含了所有头部信息和节表
		memcpy(Base, pFileBuffer, pNtHeader->OptionalHeader.SizeOfHeaders);

		void* WritePos = nullptr; // 目标内存中的写入位置
		void* resPos = nullptr;   // 源文件缓冲区中的读取位置
		size_t WriteSize = 0;     // 实际要复制的数据大小

		// 3. 获取节表 (Section Header) 的起始位置
		// 计算公式：NT头指针 + Signature(4字节) + FileHeader + OptionalHeader大小
		IMAGE_SECTION_HEADER* pSectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(
			(char*)pNtHeader + sizeof(pNtHeader->Signature) +
			sizeof(IMAGE_FILE_HEADER) + pNtHeader->FileHeader.SizeOfOptionalHeader
		);

		// 4. 遍历所有节区，将数据从文件偏移位置复制到内存虚拟地址位置
		for (int SectionIndex = 0; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
			// 目标地址 = 基址 + 节的虚拟地址 (VirtualAddress)
			WritePos = static_cast<void*>(static_cast<char*>(Base) + pSectionHeader->VirtualAddress);

			// 源地址 = 文件缓冲基址 + 节的文件偏移 (PointerToRawData)
			resPos = static_cast<void*>(static_cast<char*>(pFileBuffer) + pSectionHeader->PointerToRawData);

			// 复制大小：取 "内存中所需大小 (VirtualSize)" 和 "文件中实际大小 (SizeOfRawData)" 的较小值
			// 防止越界读取文件或写入超出预期内存
			WriteSize = min(pSectionHeader->Misc.VirtualSize, pSectionHeader->SizeOfRawData);

			memcpy(WritePos, resPos, WriteSize);

			// 移动到下一个节表项
			pSectionHeader++;
		}

		pMemoryImage = Base;
		return PE_STATUS_SUCCESS;
	}
	return PE_STATUS_INVALID_FORMAT;
}

/**
 * @brief 解析 PE 文件的导出表 (Export Table)
 *
 * 该函数遍历 PE 文件的导出目录，提取所有导出函数的名称、RVA 和序号。
 * 它能够处理标准的有名导出函数以及纯序号导出函数。
 *
 * @note 内存管理规则 (重要):
 * 调用者在使用完 out_pExpInfo 后，必须手动释放内存：
 * 1. free(out_pExpInfo->Fn);  // 释放函数信息数组
 * 2. free(out_pExpInfo);      // 释放主结构体
 * 注意：函数名称字符串 (Name) 是直接指向 pFileBuffer 内部的指针，不需要也不应该单独 free。
 *
 * @note 解析算法逻辑:
 * 导出表包含三个数组：地址表 (AddressOfFunctions)、名称表 (AddressOfNames)、序号表 (AddressOfNameOrdinals)。
 * 由于名称表只包含有名函数且按字母排序，而地址表包含所有函数且按序号排序，
 * 因此算法采用 "遍历地址表 -> 在序号表中查找索引 -> 通过索引定位名称表" 的方式。
 *
 * @param pFileBuffer  [in]  PE 文件内存缓冲区
 * @param out_pExpInfo [out] 输出参数，指向解析后的导出信息结构
 * @return PE::STATUS  操作结果状态码
 * @retval PE_STATUS_SUCCESS							解析成功
 * @retval PE_STATUS_INVALID_PARAMETER					输入缓冲区为空
 * @retval PE_STATUS_INVALID_FORMAT                   	文件格式无效
 * @retval PE_STATUS_ARCH_MISMATCH						文件架构与编译环境不匹配 (32/64位)
 * @retval PE_STATUS_GET_EXPORT_FAILURE					文件无导出表或解析过程中断
 * @retval PE_STATUS_LOCAL_MEMORY_ALLOCATION_FAILURE 	内存分配失败
 * @retval PE_STATUS_GET_FOA_FAILURE					RVA 转 FOA 失败
 */
PE::STATUS PE::GetExportTable(void* pFileBuffer, ExportInfo*& out_pExpInfo) {
	if (pFileBuffer == nullptr) return PE_STATUS_INVALID_PARAMETER;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;

	// 1. 验证 PE 有效性
	if (IsValid(pFileBuffer, pNtHeader) == PE_STATUS_SUCCESS) {
		// 额外验证 Optional Header 的 Magic 字段，确保是 PE32 或 PE32+ 格式
		#if defined(_WIN64)
			if (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return PE_STATUS_ARCH_MISMATCH;
		#else
			if (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return PE_STATUS_ARCH_MISMATCH;
		#endif

		// 2. 获取导出表的数据目录项 (Data Directory Entry for Export)
		IMAGE_DATA_DIRECTORY DataDir = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		// 3. 分配主结构体内存
		out_pExpInfo = static_cast<ExportInfo*>(calloc(1, sizeof(ExportInfo)));
		if (out_pExpInfo == nullptr) return PE_STATUS_LOCAL_MEMORY_ALLOCATION_FAILURE;

		// 4. 检查是否存在导出表
		if (DataDir.VirtualAddress == 0 || DataDir.Size == 0) {
			free(out_pExpInfo);
			out_pExpInfo = nullptr;
			return PE_STATUS_GET_EXPORT_FAILURE;
		}

		// 5. 将导出目录的 RVA 转换为文件偏移 (FOA)
		DWORD FileOffset = 0;
		FileOffset = RvaToFoa(pFileBuffer, DataDir.VirtualAddress);
		if (FileOffset == DWORD(-1)) {
			free(out_pExpInfo);
			out_pExpInfo = nullptr;
			return PE_STATUS_LOCAL_MEMORY_ALLOCATION_FAILURE;
		}

		// 6. 定位到 IMAGE_EXPORT_DIRECTORY 结构
		IMAGE_EXPORT_DIRECTORY* pExportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
			static_cast<char*>(pFileBuffer) + FileOffset
		);

		// 7. 获取并保存 PE 文件名 (DLL Name)
		FileOffset = RvaToFoa(pFileBuffer, pExportDir->Name);
		if (FileOffset == DWORD(-1)) {
			free(out_pExpInfo);
			out_pExpInfo = nullptr;
			return PE_STATUS_GET_FOA_FAILURE;
		}
		char* FileName = static_cast<char*>(pFileBuffer) + FileOffset;

		// 假设 ExportInfo.PEName 是一个固定大小的字符数组 (如 char PEName[256])
		strcpy_s(out_pExpInfo->PEName, FileName);
		out_pExpInfo->ExportFuncSize = 0;

		// 8. 初始化函数信息数组
		// 先分配一个元素的空间，后续根据需要 realloc 扩容
		FuncInfo* pFunctionsInfo = static_cast<FuncInfo*>(calloc(1, sizeof(FuncInfo)));
		if (pFunctionsInfo == nullptr) {
			free(out_pExpInfo);
			out_pExpInfo = nullptr;
			return PE_STATUS_LOCAL_MEMORY_ALLOCATION_FAILURE;
		}
		int RealFunctions = 0;	// 实际解析到的有名函数数量
		DWORD FuncIndex = 0;

		// --- 准备三个关键数组的指针 ---

		// A. 函数地址表 (AddressOfFunctions): 存储函数的 RVA
		FileOffset = RvaToFoa(pFileBuffer, pExportDir->AddressOfFunctions);
		if (FileOffset == DWORD(-1)) {
			free(out_pExpInfo->Fn);
			free(out_pExpInfo);
			out_pExpInfo = nullptr;
			return PE_STATUS_GET_FOA_FAILURE;
		}
		DWORD* pFuncAddr = reinterpret_cast<DWORD*>(
			static_cast<char*>(pFileBuffer) + FileOffset
		);
		// B. 名称序号映射表 (AddressOfNameOrdinals): 存储函数名对应的序号索引
		FileOffset = RvaToFoa(pFileBuffer, pExportDir->AddressOfNameOrdinals);
		if (FileOffset == DWORD(-1)) {
			free(out_pExpInfo->Fn);
			free(out_pExpInfo);
			out_pExpInfo = nullptr;
			return PE_STATUS_GET_FOA_FAILURE;
		}
		WORD* pFuncOrdinals = reinterpret_cast<WORD*>(
			static_cast<char*>(pFileBuffer) + FileOffset
		);
		// C. 函数名称表 (AddressOfNames): 存储函数名字符串的 RVA
		FileOffset = RvaToFoa(pFileBuffer, pExportDir->AddressOfNames);
		if (FileOffset == DWORD(-1)) {
			free(out_pExpInfo->Fn);
			free(out_pExpInfo);
			out_pExpInfo = nullptr;
			return PE_STATUS_GET_FOA_FAILURE;
		}
		DWORD* FuncNameOffset = reinterpret_cast<DWORD*>(
			static_cast<char*>(pFileBuffer) + FileOffset
		);

		// 9. 遍历导出函数表 (AddressOfFunctions)
		// ---------------------------------------------------------------------------
		// 核心逻辑说明：
		// 1. 外层循环遍历 "地址表" (范围: 0 ~ NumberOfFunctions-1)。
		//    因为地址表包含了所有导出的函数（包括有名字的和纯序号导出的）。
		//    地址表的下标 (i) 与真实序号的关系为：Ordinal = Base + i。
		//
		// 2. 内层循环遍历 "名字表" (范围: 0 ~ NumberOfNames-1)。
		//    因为名字表只包含有名字的函数，且顺序通常是按字母排序，与地址表顺序不一致。
		//    我们需要通过 "名字序号映射表" (AddressOfNameOrdinals) 来查找：
		//    是否有某个名字映射到了当前的地址表下标 (i)？
		//
		// 3. 为什么不能直接用同一个下标遍历两个表？
		//    - 长度不同：NumberOfFunctions 通常 >= NumberOfNames (存在纯序号导出函数)。
		//    - 顺序不同：名字表按字母排序，地址表按序号排序。
		//    - 直接映射会导致越界访问或名字与地址错配。
		// ---------------------------------------------------------------------------
		for (FuncIndex = 0; FuncIndex < pExportDir->NumberOfFunctions; FuncIndex++) {
			// 如果 函数地址RVA 值为 NULL，证明没有函数
			if (pFuncAddr[FuncIndex] == NULL) continue;
			// 给 FuncInfo结构体 动态扩容空间
			if (RealFunctions > 0) {
				void* tmp_Pointer = realloc(pFunctionsInfo, sizeof(FuncInfo) * (RealFunctions + 1));
				if (tmp_Pointer == nullptr) {
					free(out_pExpInfo);
					out_pExpInfo = nullptr;
					return PE_STATUS_LOCAL_MEMORY_ALLOCATION_FAILURE;
				}
				pFunctionsInfo = static_cast<FuncInfo*>(tmp_Pointer);
			}
			// 获取当前要填充的结构体指针
			FuncInfo* pCurrentFunctionsInfo = reinterpret_cast<FuncInfo*>(
				(char*)pFunctionsInfo + sizeof(FuncInfo) * RealFunctions
			);

			// 填入 函数地址RVA 和 序号
			pCurrentFunctionsInfo->RVA_Address = pFuncAddr[FuncIndex];
			pCurrentFunctionsInfo->Ordinal = pExportDir->Base + FuncIndex;

			pCurrentFunctionsInfo->Name = nullptr;
			for (DWORD FuncNameIndex = 0; FuncNameIndex < pExportDir->NumberOfNames; FuncNameIndex++) {
				if (pFuncOrdinals[FuncNameIndex] == FuncIndex) {
					// 当前指向为 函数名RVA 块(4 bytes), 需要再进行一次 RvaToFoa
					FileOffset = RvaToFoa(pFileBuffer, FuncNameOffset[FuncNameIndex]);
					if (FileOffset == DWORD(-1)) {
						free(out_pExpInfo->Fn);
						free(out_pExpInfo);
						out_pExpInfo = nullptr;
						return PE_STATUS_GET_FOA_FAILURE;
					}
					// 直接指向缓冲区内的函数名称字符串，无需复制 (节省内存，但依赖 pFileBuffer 生命周期)
					pCurrentFunctionsInfo->Name = static_cast<char*>(static_cast<char*>(pFileBuffer) + FileOffset);
					break;	// 找到后立刻停止查找
				}
			}
			RealFunctions++;
		}
		// 10. 保存结果
		out_pExpInfo->Fn = pFunctionsInfo;
		out_pExpInfo->FuncCount = RealFunctions;
		out_pExpInfo->ExportFuncSize = sizeof(FuncInfo) * RealFunctions;
		STATUS RTN = (pExportDir->NumberOfFunctions == FuncIndex) ? PE_STATUS_SUCCESS : PE_STATUS_GET_EXPORT_FAILURE;
		return RTN;
	}
	return PE_STATUS_INVALID_FORMAT;
}

/**
 * @brief 修复导入表 (针对远程进程)
 *
 * 该函数用于手动映射场景。它解析本地镜像的导入表，加载对应的 DLL，
 * 获取函数在**本地进程**中的地址偏移 (RVA)，然后结合**远程进程**中 DLL 的基址，
 * 计算出函数在远程进程中的绝对地址，并填入本地镜像的 IAT 中。
 *
 * @note 核心逻辑:
 * 1. 本地加载: 使用 LoadLibrary 加载依赖 DLL，确保能获取到函数地址。
 * 2. 获取远程基址: 使用 GetModuleBaseAddress 获取该 DLL 在目标进程 (pid) 中的基址。
 * 3. 计算偏移: 计算函数地址相对于本地 DLL 基址的偏移量 (RVA)。
 * 4. 合成地址: 最终 IAT 条目值 = 远程 DLL 基址 + 函数偏移 (RVA)。
 *
 * @warning 版本一致性假设:
 * 此算法假设目标进程中加载的 DLL 版本与本地系统版本一致。
 * 如果版本不同，函数的 RVA 可能会发生变化，导致调用错误的代码地址。
 *
 * @param pid             [in] 目标远程进程的 ID
 * @param pMemoryImage    [in] 本地已构建好的 PE 内存镜像 (包含待修复的 IAT)
 * @return PE::STATUS     操作结果状态码
 * @retval PE_STATUS_SUCCESS                 修复成功
 * @retval PE_STATUS_INVALID_PARAMETER       进程 ID 或 指针 无效
 * @retval PE_STATUS_INVALID_FORMAT          镜像无效不匹配
 * @retval PE_STATUS_ARCH_MISMATCH		     文件架构与编译环境不匹配 (32/64位)
 * @retval PE_STATUS_LOAD_MODULE_FAILURE     无法在本地加载依赖 DLL
 * @retval PE_STATUS_GET_MODULE_BASE_FAILURE 无法获取远程进程中 DLL 的基址
 * @retval PE_STATUS_MODULE_NOT_FOUND        无法获取本地模块信息 (用于校验)
 * @retval PE_STATUS_MODULE_RANGE_NOT_IN     获取到的函数地址不在模块范围内 (异常)
 */
PE::STATUS PE::FixImportTable(DWORD pid, void* pMemoryImage /*, void* pRemoteImageBase*/) {
	if (pid == 0) return PE_STATUS_INVALID_PARAMETER;
	if (pMemoryImage == nullptr) return PE_STATUS_INVALID_PARAMETER;
	//if (pRemoteImageBase == nullptr) return PE_STATUS_INVALID_PARAMETER;

	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pMemoryImage, pNtHeader) == PE_STATUS_SUCCESS) {
		// 额外验证 Optional Header 的 Magic 字段，确保是 PE32 或 PE32+ 格式
		#if defined(_WIN64)
			if (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return PE_STATUS_ARCH_MISMATCH;
		#else
			if (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return PE_STATUS_ARCH_MISMATCH;
		#endif
		// 获取导入表目录项
		IMAGE_DATA_DIRECTORY DataDir = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (DataDir.VirtualAddress == 0 || DataDir.Size == 0) return PE_STATUS_SUCCESS; // 无导入表，视为成功

		// 定位到导入描述符数组
		IMAGE_IMPORT_DESCRIPTOR* pImportDest = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
			static_cast<char*>(pMemoryImage) + DataDir.VirtualAddress
		);

		// 遍历每个导入的 DLL (以 Name 为 0 结尾)
		while (pImportDest->Name) {
			// 获取依赖的 DLL 名称 (如 "kernel32.dll")
			char* pDllName = static_cast<char*>(static_cast<char*>(pMemoryImage) + pImportDest->Name);

			// OriginalFirstThunk: 指向导入名称表 (INT)，包含原始函数名/序号
			IMAGE_THUNK_DATA* pOriginalThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
				static_cast<char*>(pMemoryImage) + pImportDest->OriginalFirstThunk
			);

			// FirstThunk: 指向导入地址表 (IAT)，我们需要在这里填入最终的函数地址
			IMAGE_THUNK_DATA* pThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
				static_cast<char*>(pMemoryImage) + pImportDest->FirstThunk
			);

			LPVOID FnAddr = nullptr; // 用于存储本地进程中获取到的函数地址

			// 1. 在本地进程加载该 DLL，以便获取函数地址
			HMODULE local_hModule = LoadLibraryA(pDllName);
			if (local_hModule == nullptr) return PE_STATUS_LOAD_MODULE_FAILURE;

			// 转换 DLL 名为宽字符，用于查询远程进程中的模块基址
			WCHAR wDllName[MAX_PATH] = { 0 };
			MultiByteToWideChar(CP_ACP, 0, pDllName, -1, wDllName, MAX_PATH);

			// 2. 获取该 DLL 在**远程进程**中的基址
			// 假设远程进程已经加载了该 DLL，且版本与本地一致（否则偏移可能无效）
			HMODULE remote_hModule = (HMODULE)GetModuleBaseAddress(pid, wDllName);
			if (remote_hModule == nullptr) {
				FreeLibrary(local_hModule);
				return PE_STATUS_GET_MODULE_BASE_FAILURE;
			}

			// 遍历该 DLL 导入的所有函数
			while (pOriginalThunk->u1.AddressOfData != 0) {
				// 判断是按序号导入还是按名称导入
				if (pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
					// 按序号导入
					WORD Ordinal = IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal);
					FnAddr = GetProcAddress(local_hModule, (LPCSTR)Ordinal);
				}
				else {
					// 按名称导入
					// 获取函数名称结构体
					IMAGE_IMPORT_BY_NAME* pImportFuncName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
						static_cast<char*>(pMemoryImage) + pOriginalThunk->u1.AddressOfData
					);
					FnAddr = GetProcAddress(local_hModule, pImportFuncName->Name);
				}

				// [安全性/正确性检查]
				// 确保获取到的函数地址确实位于刚才 LoadLibrary 加载的模块范围内
				MODULEINFO ModuleInfo = { 0 };
				if (!GetModuleInformation(GetCurrentProcess(), local_hModule, &ModuleInfo, sizeof(MODULEINFO))) {
					FreeLibrary(local_hModule);
					return PE_STATUS_MODULE_NOT_FOUND;
				}

				ULONG_PTR ModuleStart = (ULONG_PTR)local_hModule;
				ULONG_PTR ModuleEnd = (ULONG_PTR)local_hModule + ModuleInfo.SizeOfImage;
				ULONG_PTR ModuleFnAddr = (ULONG_PTR)FnAddr;

				// 如果函数地址不在模块范围内，说明出错
				if (ModuleFnAddr <= ModuleStart || ModuleFnAddr >= ModuleEnd) {
					FreeLibrary(local_hModule);
					return PE_STATUS_MODULE_RANGE_NOT_IN;
				}

				// 3. 计算函数相对于模块基址的偏移 (RVA)
				ULONG_PTR FnAddrOffset = (ULONG_PTR)FnAddr - (ULONG_PTR)local_hModule;

				// 4. 计算该函数在远程进程中的绝对地址
				// 公式：远程模块基址 + 函数偏移
				// 并将结果写入到本地镜像的 IAT (pThunk) 中
				// 当这个本地镜像被写入远程进程后，远程进程执行时就会跳转到正确的远程函数地址
				pThunk->u1.Function = (ULONG_PTR)remote_hModule + FnAddrOffset;

				pOriginalThunk++;
				pThunk++;
			}

			// 释放本地加载的 DLL，因为我们只需要它的地址信息，不需要它在本地长期驻留
			FreeLibrary(local_hModule);
			pImportDest++;
		}
		return PE_STATUS_SUCCESS;
	}
	return PE_STATUS_INVALID_FORMAT;
}

/**
 * @brief 修复 PE 映像的重定位表 (Base Relocation)
 * 
 * 在手动映射 (Manual Map) 注入技术中，如果目标进程无法在 PE 文件首选的 
 * ImageBase（镜像基址）分配内存，加载器必须修正所有“硬编码”的绝对地址。
 * 该函数模拟 Windows 加载器的重定位过程，将映像从“首选基址”修正为“实际加载基址”。
 * 
 * @note 重定位原理:
 * 1. 计算偏移量 (Delta): pRemoteImage - pMemoryImage
 * 2. 遍历重定位块 (Block)，找到所有需要修正的偏移位置。
 * 3. 内存中的值 = 原始值 + Delta
 * 
 * @warning 版本一致性假设:
 * 此算法假设目标进程中加载的 DLL 版本与本地系统版本一致。
 * 如果版本不同，函数的 RVA 可能会发生变化，导致调用错误的代码地址。
 * 
 * @param pMemoryImage [in/out] 指向本地已构建的 PE 内存镜像的基址。
 *                              函数会直接修改该内存区域中的重定位项。
 * @param pRemoteImage [in]     目标远程进程中，该 PE 映像实际被分配到的基址
 *                              (即：VirtualAlloc 在远程进程返回的地址)。
 * @return PE::STATUS 
 * @retval PE_STATUS_SUCCESS 			重定位成功或无需重定位
 * @retval PE_STATUS_INVALID_PARAMETER 	输入指针为空
 * @retval PE_STATUS_INVALID_FORMAT 	文件格式无效 (非 PE 格式)
 * @retval PE_STATUS_ARCH_MISMATCH  	文件架构与编译环境不匹配 (32/64位)
 */
PE::STATUS PE::Relocation(void* pMemoryImage, void* pRemoteImage) {
	if (pMemoryImage == nullptr) return PE_STATUS_INVALID_PARAMETER;
	if (pRemoteImage == nullptr) return PE_STATUS_INVALID_PARAMETER;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;

	// 1. 验证 PE 有效性
	if (IsValid(pMemoryImage, pNtHeader) == PE_STATUS_SUCCESS) {
		// 额外验证 Optional Header 的 Magic 字段，确保是 PE32 或 PE32+ 格式
		#if defined(_WIN64)
			if (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return PE_STATUS_ARCH_MISMATCH;
		#else
			if (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return PE_STATUS_ARCH_MISMATCH;
		#endif

		// 2. 获取重定位表 (Base Relocation Table) 的数据目录
		IMAGE_DATA_DIRECTORY DataDir = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		
		// 如果没有重定位表或大小为0，说明不需要重定位 (或者是一个无法重定位的驱动/EXE)，直接返回成功
		if (DataDir.VirtualAddress == 0 || DataDir.Size == 0) return PE_STATUS_SUCCESS;

		// 3. 定位重定位表起始位置
		IMAGE_BASE_RELOCATION* pBaseReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
			static_cast<char*>(pMemoryImage) + DataDir.VirtualAddress
		);

		// 4. 计算基址差值 (Delta)  Delta = 实际加载地址 - 首选基址 (ImageBase)
		ULONG_PTR Delta = (ULONG_PTR)pRemoteImage - (ULONG_PTR)pMemoryImage;

		// 如果差值为 0，说明加载地址与预期一致，无需重定位
		if (Delta == 0) return PE_STATUS_SUCCESS;

		// 5. 遍历重定位块 (Block)
		// 重定位表由多个 IMAGE_BASE_RELOCATION 块组成，以 VirtualAddress 为 0 结束
		while (pBaseReloc->VirtualAddress) {
			// 计算当前块中的重定位项数量
			// SizeOfBlock 包含头结构大小，减去头大小后除以 WORD (2字节) 即为项数
			WORD RelocCount = static_cast<WORD>((pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD));
			// 指向当前块的具体重定位项数组 (紧接在头结构之后)
			WORD* pRelocBlock = reinterpret_cast<WORD*>((char*)pBaseReloc + sizeof(IMAGE_BASE_RELOCATION));

			// 6. 遍历块内的每一项
			for (DWORD RelocIndex = 0; RelocIndex < RelocCount; RelocIndex++) {
				// 每一项是一个 WORD (16位):
				// 高 4 位: 类型 (Type)
				// 低 12 位: 偏移量 (Offset)，相对于当前块的 VirtualAddress
				WORD RelocType = pRelocBlock[RelocIndex] >> 12;
				WORD RelocOffset = pRelocBlock[RelocIndex] & 0x0FFF;
				if (RelocType == IMAGE_REL_BASED_HIGHLOW || RelocType == IMAGE_REL_BASED_DIR64) {
					// 计算需要修改的地址在内存中的实际位置
					ULONG_PTR* pRelocAddr = reinterpret_cast<ULONG_PTR*>(
						static_cast<char*>(pMemoryImage) + pBaseReloc->VirtualAddress + RelocOffset
					);
					// 执行修正：原始地址 + Delta = 新地址
					*pRelocAddr += Delta;
				}
			}
			// 移动到下一个重定位块
			pBaseReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
				(char*)pBaseReloc + pBaseReloc->SizeOfBlock
			);
		}
		return PE_STATUS_SUCCESS;
	}
	return PE_STATUS_INVALID_FORMAT;
}

/**
 * @brief 设置本地进程内存中各节区的保护属性 (VirtualProtect)
 *
 * 该函数遍历 PE 文件的节表，根据每个节的特征标志 (Characteristics)，
 * 调用 VirtualProtect 设置内存页的读写执行权限。
 * 这是手动映射中必不可少的一步，用于确保代码段可执行、数据段可写。
 *
 * @note 权限映射逻辑:
 * - 可执行 + 可读写 -> PAGE_EXECUTE_READWRITE (极少见，通常不安全)
 * - 仅可执行		 -> PAGE_EXECUTE_READ
 * - 仅可写			 -> PAGE_READWRITE
 * - 只读/默认		 -> PAGE_READONLY (如 .rdata)
 *
 * @warning 内存对齐注意事项:
 * VirtualProtect 作用于内存页。如果节的 VirtualSize 不是页大小的整数倍，
 * 系统会自动向上取整。确保 pMemoryImage 分配的内存足够大，以免越界。
 *
 * @param pFileBuffer  [in] PE 文件缓冲区 (用于读取节表信息)
 * @param pMemoryImage [in] 已加载到内存的 PE 图像 (用于修改属性)
 * @return PE::STATUS  操作结果状态码
 * @retval PE_STATUS_SUCCESS          				设置成功
 * @retval PE_STATUS_INVALID_PARAMETER 				输入缓冲区指针为空
 * @retval PE_STATUS_INVALID_FORMAT   				文件格式无效
 * @retval PE_STATUS_SET_SECTION_PROPERTY_FAILURE 	部分设置节属性失败
 */
PE::STATUS PE::SetSectionProperty(void* pFileBuffer, void* pMemoryImage) {
	if (pFileBuffer == nullptr) return PE_STATUS_INVALID_PARAMETER;
	if (pMemoryImage == nullptr) return PE_STATUS_INVALID_PARAMETER;

	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader) == PE_STATUS_SUCCESS) {
		// 获取第一个节表项的指针 (使用 SDK 宏更安全)
		IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
		STATUS RTN = PE_STATUS_SUCCESS;
		for (int SectionIndex = 0; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
			// 1. 根据节特征标志确定初始保护属性
			// 默认为只读
			DWORD memProperty = PAGE_READONLY;

			// 检查是否可执行 (IMAGE_SCN_MEM_EXECUTE)
			if (pSectionHeader[SectionIndex].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
				// 如果既可执行又可写 (IMAGE_SCN_MEM_WRITE) -> PAGE_EXECUTE_READWRITE (极少见，通常不安全)
				// 如果只可执行 -> PAGE_EXECUTE_READ
				memProperty = (pSectionHeader[SectionIndex].Characteristics & IMAGE_SCN_MEM_WRITE)
					? PAGE_EXECUTE_READWRITE
					: PAGE_EXECUTE_READ;
			}
			// 检查是否可写 (但未标记可执行)
			else if (pSectionHeader[SectionIndex].Characteristics & IMAGE_SCN_MEM_WRITE) {
				memProperty = PAGE_READWRITE;
			}
			// 其他情况保持 PAGE_READONLY (例如纯数据节 .rdata)

			// 2. 计算该节在内存中的起始地址
			void* pSectionAddr = (char*)pMemoryImage + pSectionHeader[SectionIndex].VirtualAddress;

			DWORD oldmemPropery = 0;
			// 3. 调用 Windows API 修改内存保护属性
			// 范围：节的虚拟大小 (VirtualSize)，确保覆盖节在内存中的实际占用
			if (!VirtualProtect(pSectionAddr, pSectionHeader[SectionIndex].Misc.VirtualSize, memProperty, &oldmemPropery))
				RTN = PE_STATUS_SET_SECTION_PROPERTY_FAILURE;

			pSectionHeader++; // 移动到下一个节表项
		}
		return RTN;
	}
	return PE_STATUS_INVALID_PARAMETER;
}

/**
 * @brief 设置远程进程内存中各节区的保护属性 (VirtualProtectEx)
 *
 * 该函数是本地 SetSectionProperty 的远程版本。
 * 它通过句柄操作目标进程的内存空间，常用于 DLL 注入场景中，
 * 在将代码写入远程进程后，修复其内存页属性（如将 .text 设为可执行）。
 *
 * @note 权限要求:
 * 调用 VirtualProtectEx 需要进程句柄具有 PROCESS_VM_OPERATION 权限。
 * 如果目标进程受保护 (如系统进程或反作弊游戏)，操作可能会因权限不足而失败。
 *
 * @note 逻辑复用:
 * 节区属性的判断逻辑（Characteristics -> PAGE_XXX）与本地版本完全一致。
 *
 * @param hProcess     [in] 目标远程进程的句柄
 * @param pFileBuffer  [in] PE 文件缓冲区 (用于读取节表信息)
 * @param pMemoryImage [in] 远程进程中已加载的 PE 图像基址
 * @return PE::STATUS  操作结果状态码
 * @retval PE_STATUS_SUCCESS          				设置成功
 * @retval PE_STATUS_INVALID_PARAMETER 				句柄或指针无效
 * @retval PE_STATUS_INVALID_FORMAT   				文件格式无效
 * @retval PE_STATUS_SET_SECTION_PROPERTY_FAILURE 	部分设置节属性失败
 */
PE::STATUS PE::SetSectionProperty(HANDLE hProcess, void* pFileBuffer, void* pMemoryImage) {
	if (pFileBuffer == nullptr) return PE_STATUS_INVALID_PARAMETER;
	if (pMemoryImage == nullptr) return PE_STATUS_INVALID_PARAMETER;
	if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) return PE_STATUS_INVALID_PARAMETER;

	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader) == PE_STATUS_SUCCESS) {
		IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
		
		STATUS RTN = PE_STATUS_SUCCESS;
		for (int SectionIndex = 0; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
			DWORD memProperty = PAGE_READONLY;

			// 逻辑同上：根据 Characteristics 决定属性
			if (pSectionHeader[SectionIndex].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
				memProperty = (pSectionHeader[SectionIndex].Characteristics & IMAGE_SCN_MEM_WRITE)
					? PAGE_EXECUTE_READWRITE
					: PAGE_EXECUTE_READ;
			}
			else if (pSectionHeader[SectionIndex].Characteristics & IMAGE_SCN_MEM_WRITE) {
				memProperty = PAGE_READWRITE;
			}

			// 计算远程进程中的节地址
			void* pSectionAddr = (char*)pMemoryImage + pSectionHeader[SectionIndex].VirtualAddress;

			DWORD oldmemPropery = 0;
			// 使用 VirtualProtectEx 操作远程进程内存
			if (!VirtualProtectEx(hProcess, pSectionAddr, pSectionHeader[SectionIndex].Misc.VirtualSize, memProperty, &oldmemPropery)) 
				RTN = PE_STATUS_SET_SECTION_PROPERTY_FAILURE;
			pSectionHeader++;
		}
		return RTN;
	}
	return PE_STATUS_INVALID_FORMAT;
}

/**
 * @brief 深度解析 PE 文件的资源表 (完整三层结构解析)
 *
 * 该函数遍历 PE 资源目录的三层结构（类型 -> 名称 -> 语言），提取所有叶子节点（资源数据）的信息。
 * 支持按类型过滤 (TypeID)，也支持提取所有资源。
 *
 * @note 内存管理: 调用者需在使用完毕后释放 ResInfo.Items 的内存 (free(ResInfo.Items))。
 *
 * @param pFileBuffer [in] 指向 PE 文件内存缓冲区的指针
 * @param ResInfo [out] 输出参数，包含解析出的资源项数组和数量
 * @param TypeID [in] 指定要提取的资源类型 (可选，默认为 0xFFFF 提取所有)
 * @return PE::STATUS
 * @retval PE_STATUS_SUCCESS 							解析成功
 * @retval PE_STATUS_INVALID_PARAMETER 					指针无效
 * @retval PE_STATUS_INVALID_FORMAT   					文件格式无效
 * @retval PE_STATUS_GET_FOA_FAILURE    				RVA 转 FOA 失败
 * @retval PE_STATUS_LOCAL_MEMORY_ALLOCATION_FAILURE    本地内存分配失败
 * @retval PE_STATUS_GET_RESOURCE_FAILURE 				无资源表或解析失败
 */
PE::STATUS PE::GetResourceTable(void* pFileBuffer, ResourceInfo& ResInfo, ResourceType TypeID) {
	if (pFileBuffer == nullptr) return PE_STATUS_INVALID_PARAMETER;

	// 1. 初始化输出参数
	ResInfo.Items = nullptr;
	ResInfo.Count = 0;

	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader) != PE_STATUS_SUCCESS) {
		return PE_STATUS_INVALID_FORMAT;
	}

	// 2. 获取资源表数据目录
	IMAGE_DATA_DIRECTORY DataDir = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	if (DataDir.VirtualAddress == 0 || DataDir.Size == 0) {
		return PE_STATUS_GET_RESOURCE_FAILURE;
	}

	// 3. 定位到资源目录头部 (第一层：类型层)
	DWORD ResourceOffset = RvaToFoa(pFileBuffer, DataDir.VirtualAddress);
	if (ResourceOffset == DWORD(-1)) return PE_STATUS_GET_FOA_FAILURE;

	IMAGE_RESOURCE_DIRECTORY* pTypeDir = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY*>(
		static_cast<char*>(pFileBuffer) + ResourceOffset
	);

	// 4. 遍历第一层 (资源类型)
	IMAGE_RESOURCE_DIRECTORY_ENTRY* pTypeEntry = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY_ENTRY*>(pTypeDir + 1);

	for (WORD i = 0; i < pTypeDir->NumberOfNamedEntries + pTypeDir->NumberOfIdEntries; i++) {
		// 检查类型是否匹配 (如果指定了 TypeID)
		bool isNamedType = pTypeEntry->NameIsString;
		WORD wType = 0;

		if (isNamedType) {
			// 处理命名类型 (很少见，通常是 ID)
			continue;
		}
		else {
			wType = (WORD)pTypeEntry->Id;
		}

		// 如果指定了 TypeID 且当前类型不匹配，跳过
		if (TypeID != 0xFFFF && wType != TypeID) {
			pTypeEntry++;
			continue;
		}

		// 5. 进入第二层 (名称层)
		if (pTypeEntry->DataIsDirectory) {
			DWORD NameDirOffset = DataDir.VirtualAddress + pTypeEntry->OffsetToDirectory;
			IMAGE_RESOURCE_DIRECTORY* pNameDir = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY*>(
				static_cast<char*>(pFileBuffer) + RvaToFoa(pFileBuffer, NameDirOffset)
			);
			IMAGE_RESOURCE_DIRECTORY_ENTRY* pNameEntry = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY_ENTRY*>(pNameDir + 1);

			// 6. 遍历第二层 (资源名称/ID)
			for (DWORD j = 0; j < pNameDir->NumberOfNamedEntries + pNameDir->NumberOfIdEntries; j++) {

				// 7. 进入第三层 (语言层)
				if (pNameEntry->DataIsDirectory) {
					DWORD LangDirOffset = DataDir.VirtualAddress + pNameEntry->OffsetToDirectory;
					IMAGE_RESOURCE_DIRECTORY* pLangDir = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY*>(
						static_cast<char*>(pFileBuffer) + RvaToFoa(pFileBuffer, LangDirOffset)
					);
					IMAGE_RESOURCE_DIRECTORY_ENTRY* pLangEntry = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY_ENTRY*>(pLangDir + 1);

					// 8. 遍历第三层 (资源语言)
					for (WORD k = 0; k < pLangDir->NumberOfNamedEntries + pLangDir->NumberOfIdEntries; k++) {

						// 9. 找到叶子节点 (资源数据)
						if (!pLangEntry->DataIsDirectory) {
							DWORD DataEntryOffset = DataDir.VirtualAddress + pLangEntry->OffsetToData;
							IMAGE_RESOURCE_DATA_ENTRY* pDataEntry = reinterpret_cast<IMAGE_RESOURCE_DATA_ENTRY*>(
								static_cast<char*>(pFileBuffer) + RvaToFoa(pFileBuffer, DataEntryOffset)
							);

							// 10. 动态扩容存储数组 (类似 GetExportTable 的逻辑)
							if (ResInfo.Items == nullptr) {
								ResInfo.Items = static_cast<ResourceItem*>(calloc(1, sizeof(ResourceItem)));
							}
							else {
								void* tmp = realloc(ResInfo.Items, (ResInfo.Count + 1) * sizeof(ResourceItem));
								if (!tmp) return PE_STATUS_LOCAL_MEMORY_ALLOCATION_FAILURE;
								ResInfo.Items = static_cast<ResourceItem*>(tmp);
							}

							// 11. 填充资源信息
							ResourceItem* pItem = &ResInfo.Items[ResInfo.Count];

							// 填充类型 (转换为字符串方便查看)
							if (wType >= 1 && wType <= 16) {
								// 这里可以写一个映射表，或者直接存 ID
								swprintf(pItem->TypeName, 32, L"TYPE_%d", wType);
							}
							else {
								swprintf(pItem->TypeName, 32, L"ID_%d", wType);
							}

							// 填充名称 (判断是字符串还是 ID)
							if (pNameEntry->NameIsString) {
								DWORD NameRVA = pNameEntry->NameOffset;
								// 这里需要解析字符串结构，为了简化，示例中直接标记
								wcscpy_s(pItem->Name, 64, L"NamedResource");
							}
							else {
								swprintf(pItem->Name, 64, L"ID_%d", pNameEntry->Id);
							}

							// 填充语言 ID
							swprintf(pItem->Language, 16, L"LANG_%04x", pLangEntry->Id);

							// 填充数据信息
							pItem->DataRVA = pDataEntry->OffsetToData;
							pItem->Size = pDataEntry->Size;

							ResInfo.Count++;
						}
						pLangEntry++;
					}
				}
				pNameEntry++;
			}
		}
		pTypeEntry++;
	}

	if (ResInfo.Count == 0) {
		return PE_STATUS_GET_RESOURCE_FAILURE;
	}

	return PE_STATUS_SUCCESS;
}

/**
 * @brief 计算数据缓冲区的香农熵 (Shannon Entropy)
 *
 * 该函数通过统计字节频率来计算数据的混乱程度。
 * 熵值范围通常为 0.0 - 8.0。
 * - 熵值 < 6.0: 通常为明文或未压缩代码
 * - 熵值 > 7.0: 通常为压缩、加密或加壳数据
 *
 * 香农熵的计算公式：H = -Σ(p_i * log2(p_i))，其中 p_i 是第 i 个符号出现的概率
 *
 * @param buffer [in] 指向待分析数据缓冲区的指针 (例如 PE 文件内存映射)
 * @param size [in] 数据缓冲区的大小 (字节数)
 * @param out_Entropy [out] 引用传递，用于返回计算出的熵值
 * @return PE::STATUS
 * @retval PE_STATUS_SUCCESS 			计算成功
 * @retval PE_STATUS_INVALID_PARAMETER 	输入指针为空
 * @retval PE_STATUS_FILE_INVALID_SIZE 	数据大小为 0
 */
PE::STATUS PE::CalculateEntropy(const void* buffer, size_t size, double& out_Entropy) {
	if (buffer == nullptr) {
		out_Entropy = 0.0;
		return PE_STATUS_INVALID_PARAMETER;
	}
	if (size == 0) {
		out_Entropy = 0.0;
		return PE_STATUS_FILE_INVALID_SIZE;
	}

	// 统计每个字节值的频率
	unsigned long long frequency[256] = { 0 };
	for (size_t fpPos = 0; fpPos < size; fpPos++) {
		unsigned char byte = static_cast<const unsigned char*>(buffer)[fpPos];
		frequency[byte]++;
	}

	// 计算熵值
	double entropy = 0.0;
	for (unsigned int i = 0; i < 256; i++) {
		if (frequency[i] > 0) {
			double p = static_cast<double>(frequency[i]) / size;
			entropy -= p * log2(p);
		}
	}
	out_Entropy = entropy;
	return PE_STATUS_SUCCESS;
}

/**
 * @brief 将内存中的 PE 镜像还原并保存为可执行文件 (Dump)
 *
 * 该函数负责将加载到内存中的 PE 文件结构
 * 如通过 ReadProcessMemory 或者 调用 MemoryDump, Read函数 获取的数据 
 * 还原为标准的磁盘文件格式。
 * 主要步骤包括：
 * 1. 写入 PE 头部及节表。
 * 2. 按节对齐将内存中的代码/数据段写入文件。
 * 3. 【关键】修复导入地址表 (IAT)，将运行时的绝对地址还原为函数名 RVA，以便文件能被系统再次正确加载。
 *
 * @note 内存管理: 传入的 pMemoryImage 指针由调用者维护，函数内部不释放。
 * @note 局限性: 若 PE 文件的 INT (OriginalFirstThunk) 缺失，函数将返回 PE_STATUS_INT_MISSING，
 *       此时导入表修复不完整，需配合专业工具（如 Scylla）进一步处理。
 *
 * @param pMemoryImage [in] 指向内存中 PE 文件镜像的指针 (Base Address)
 * @param DumpFile [in] 目标文件的路径 (宽字符)
 * @return PE::STATUS
 * @retval PE_STATUS_SUCCESS 				文件生成且导入表修复成功
 * @retval PE_STATUS_INVALID_PARAMETER 		输入指针为空
 * @retval PE_STATUS_INVALID_FORMAT 		数据不是有效的 PE 格式
 * @retval PE_STATUS_FILE_OPEN_FAILURE 		无法创建或打开目标文件
 * @retval PE_STATUS_FILE_WRITE_FAILURE 	写入文件数据时发生错误
 * @retval PE_STATUS_IMPORT_INT_MISSING 	导入表缺失 INT 信息，修复不完整
 * 
 * 本意是想通过内存的 PE文件格式数据 还原成一个文件，失败
 * 大部分数据是正确的，但是 IMAGE_DATA_DIRECTORY 中所对应的地址中的内容已经被系统修改了，导致无法正确还原文件
 */
PE::STATUS PE::MemoryToFileDump(void* pMemoryImage, const wchar_t* DumpFile)
{
	if (pMemoryImage == nullptr) return PE_STATUS_INVALID_PARAMETER;
	if (DumpFile == nullptr) return PE_STATUS_INVALID_PARAMETER;
	
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pMemoryImage, pNtHeader) == PE_STATUS_SUCCESS) {
		// 额外验证 Optional Header 的 Magic 字段，确保是 PE32 或 PE32+ 格式
		#if defined(_WIN64)
			if (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return PE_STATUS_ARCH_MISMATCH;
			pNtHeader->OptionalHeader.ImageBase = 0x0000140000000000;
		#else
			if (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return PE_STATUS_ARCH_MISMATCH;
			pNtHeader->OptionalHeader.ImageBase = 0x400000;
		#endif
		DWORD WriteBytes = 0, NextWritePos = 0;
		DWORD FileAlignment = pNtHeader->OptionalHeader.FileAlignment;
		DWORD WriteSize = pNtHeader->OptionalHeader.SizeOfHeaders;

		// 1.创建 Dump 文件 
		HANDLE hFile = CreateFileW(DumpFile, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)	return PE_STATUS_FILE_OPEN_FAILURE;
		// 2.写入 PE 头部
		bool apiRTN = WriteFile(hFile, pMemoryImage, WriteSize, &WriteBytes, NULL);
		if (!apiRTN || WriteBytes != WriteSize) {
			CloseHandle(hFile);
			return PE_STATUS_FILE_WRITE_FAILURE;
		}
		// 3.将内存中的头部数据写入文件 
		IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
		for (int SectionIndex = 0; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
			SetFilePointer(hFile, pSectionHeader->PointerToRawData, NULL, FILE_BEGIN);
			void* MemWritePos = static_cast<void*>(
				static_cast<char*>(pMemoryImage) + pSectionHeader->VirtualAddress
			);
			WriteSize = pSectionHeader->SizeOfRawData;
			apiRTN = WriteFile(hFile, MemWritePos, WriteSize, &WriteBytes, NULL);
			if (!apiRTN || WriteBytes != WriteSize) {
				CloseHandle(hFile);
				return PE_STATUS_FILE_WRITE_FAILURE;
			}
			pSectionHeader++;
		}
		STATUS RTN = PE_STATUS_SUCCESS;
		// 4.修复 导入表 IAT 
		IMAGE_DATA_DIRECTORY DataDir = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (DataDir.VirtualAddress != 0 && DataDir.Size != 0) {
			IMAGE_IMPORT_DESCRIPTOR* pImportDest = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
				static_cast<char*>(pMemoryImage) + DataDir.VirtualAddress
			);
			
			// 遍历导入目录表（每个项代表一个依赖的 DLL）
			while (pImportDest->Name != 0) { 
				DWORD originalThunkRVA = pImportDest->OriginalFirstThunk;	// INT (导入名称表) 的 RVA
				DWORD firstThunkRVA = pImportDest->FirstThunk;				// IAT (导入地址表) 的 RVA
				
				// 情况 1: INT (OriginalFirstThunk) 存在
				if (originalThunkRVA != 0) {
					// 定位到内存中的 INT 表（存的是函数名/序号的 RVA，通常未被修改）
					IMAGE_THUNK_DATA* pOriginalThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
						static_cast<char*>(pMemoryImage) + originalThunkRVA
					);
					// 定位到内存中的 IAT 表（存的是系统加载后填写的绝对地址，如 0x77001234）
					IMAGE_THUNK_DATA* pThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
						static_cast<char*>(pMemoryImage) + firstThunkRVA
					);

					// 遍历直到遇到全 0 的项
					while (pOriginalThunk->u1.AddressOfData != 0) {
						// 【核心修复逻辑】：
						// 1. 在内存中：pThunk (IAT) 存的是绝对地址，pOriginalThunk (INT) 存的是函数名 RVA。
						// 2. 在文件中：IAT 必须存函数名 RVA，以便 Windows 加载器下次重新解析。
						// 3. 操作：直接用 INT 的值覆盖 IAT 的值，相当于“时光倒流”，让 IAT 变回初始状态。
						pThunk->u1.AddressOfData = pOriginalThunk->u1.AddressOfData;

						pOriginalThunk++;
						pThunk++;
					}
				}
				// 情况 2: INT 为 0，只能依赖 IAT (但这在内存 Dump 中通常意味着数据已损坏/扁平化)
				else {
					// 如果 OriginalFirstThunk 为 0，说明没有备份的函数名表。
					// 此时 IAT 里只有绝对地址，无法反推函数名（无法从 0x77001234 推出 "MessageBoxA"）。
					// 这种情况通常需要复杂的 IAT 扫描算法（如 Scylla 工具所做的那样）。
					// 为了保持代码简洁与稳定，这里选择跳过，但这会导致该 DLL 的导入信息丢失。
					RTN = PE_STATUS_IMPORT_INT_MISSING;
					break; // 暂时跳出，避免死循环或错误写入
				}
				pImportDest++;
			}
		}
		return RTN;
	}
	return PE_STATUS_INVALID_FORMAT;
}

/*
 * 智能指针 针对 malloc、realloc、calloc 的安全写法
 * std::unique_ptr<void, decltype(&free)> upFile(pFile, &free);
 * 智能指针 针对 VirtualFree 的安全写法
 * std::unique_ptr<void, decltype(&VirtualFree)> ptr(buffer, VirtualFree);
 */

int main(){
	/*		// 计算熵值
	DWORD FileSize = 0;
	void* pFile = nullptr;
	PE::STATUS a = PE::Read(L"C:\\Users\\OMEN\\Desktop\\test_des.exe", pFile, FileSize);
	double entropy = 0.0;
	a = PE::CalculateEntropy(pFile, FileSize, entropy);
	std::cout << "Entropy: " << entropy << std::endl;
	free(pFile);
	*/

	/*		// 获取资源表
	DWORD FileSize = 0;
	void* pFile = nullptr;
	PE::STATUS a = PE::Read(L"C:\\Users\\OMEN\\Desktop\\test_src.exe", pFile, FileSize);
	PE::ResourceInfos ResInfo = { 0 };
	a = ParseResourceTable(pFile, ResInfo, PE::Icon);
	for(int i = 0; i < ResInfo.Count; i++) {
		std::wcout << L"Type: " << ResInfo.Items[i].TypeName << L"\tName: " << ResInfo.Items[i].Name << L"\tLanguage: " << ResInfo.Items[i].Language << L"\tDataRVA: " << std::hex << ResInfo.Items[i].DataRVA << L"\tSize: " << ResInfo.Items[i].Size << std::endl;
	}
	a = PE::PE_STATUS_SUCCESS;
	free(pFile);
	*/


	/*		// 获取导出表
	DWORD FileSize = 0; WORD Bit = 0;
	void* pFile = nullptr;
	PE::STATUS a = PE::Read(L"C:\\Users\\OMEN\\Desktop\\KernelBase.dll", pFile, FileSize);
	PE::ExportInfo* pExp = nullptr;
	a = PE::GetExportTable(pFile, pExp);
	a = PE::PE_STATUS_SUCCESS;
	for (int i = 0; i < pExp->ExportFuncSize / sizeof(PE::FuncInfo); i++) {
		PE::FuncInfo* pCurrent = (PE::FuncInfo*)((char*)pExp->Fn + sizeof(PE::FuncInfo) * i);
		std::cout  << pCurrent->Ordinal << "\t\t" <<  pCurrent->RVA_Address << "\t\t" <<  pCurrent->Name << "\r\n";
	}
	free(pExp->Fn);
	free(pExp);
	free(pFile);
	*/
	
	/*		// PE 文件结构  内存 转化为 文件 
	PE::STATUS a = PE::PE_STATUS_SUCCESS;
	a = PE::MemoryDump(L"C:\\Users\\OMEN\\Desktop\\MFCTextCompare.exe", L"C:\\Users\\OMEN\\Desktop\\MFCTextCompare.exe_Mem.txt");
	void* pFile = nullptr;
	DWORD FileSize = 0;
	a = PE::Read(L"C:\\Users\\OMEN\\Desktop\\MFCTextCompare.exe_Mem.txt", pFile, FileSize);
	a = PE::MemoryToFileDump(pFile, L"C:\\Users\\OMEN\\Desktop\\MFCTextCompare.exe_file.exe"); 
	free(pFile);
	*/

	/*		 // 计算校验和
	DWORD FileSum = 0, CheckSum = 0;
	//MapFileAndCheckSumW(L"C:\\Users\\OMEN\\Desktop\\test_src.exe", &FileSum, &CheckSum);
	DWORD FileSize = 0; bool RTN = false;
	void* pFile = nullptr;
	PE::STATUS a = PE::Read(L"C:\\Users\\OMEN\\Desktop\\test_src.exe", pFile, FileSize);
	PE::GetPEChecksum(pFile, FileSize, FileSum, CheckSum, RTN);
	free(pFile);
	*/

	/*		// Dump各个节区数据
	DWORD FileSize = 0;
	void* pFile = nullptr;
	PE::STATUS a = PE::Read(L"C:\\Users\\OMEN\\Desktop\\MFCLibpvzCheat64.dll", pFile, FileSize);
	void* pSectionName = nullptr;
	size_t SectionNameSize = 0;
	PE::DumpStructData(pFile, PE::DOS, nullptr, L"D:\\MFCLibpvzCheat64-DOS.txt");
	PE::DumpStructData(pFile, PE::DOS_stub, nullptr, L"D:\\MFCLibpvzCheat64-DOS_stub.txt");
	PE::DumpStructData(pFile, PE::NT, nullptr, L"D:\\MFCLibpvzCheat64-NT.txt");
	PE::DumpStructData(pFile, PE::SectionTable, nullptr, L"D:\\MFCLibpvzCheat64-SectionTable.txt");
	if (PE::GetSectionName(pFile, pSectionName, SectionNameSize) == PE::PE_STATUS_SUCCESS) {
		for (int Index = 0; Index < SectionNameSize / sizeof(char[8]); Index++) {
			std::cout << (char*)pSectionName + Index * sizeof(char[8]) << "\n";
			std::wstring out_File = L"D:\\MFCLibpvzCheat64-Section";
			out_File.append(1, 49 + Index);
			out_File.append(L".txt");
			PE::DumpStructData(pFile, PE::SectionInfo, (char*)pSectionName + Index * sizeof(char[8]), out_File.c_str());
		}
	}
	free(pSectionName);
	free(pFile);
	*/
	return 0;
}

