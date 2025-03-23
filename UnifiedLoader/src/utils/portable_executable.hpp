#pragma once
#include <Windows.h>
#include <vector>
#include <string>

namespace portable_executable {

	struct RelocInfo {
		ULONG64 address;
		USHORT* item;
		ULONG count;
	};

	struct ImportFunctionInfo {
		std::string name;
		ULONG64* address;
	};

	struct ImportInfo {
		std::string module_name;
		std::vector<ImportFunctionInfo> function_datas;
	};

	typedef std::vector<RelocInfo> vec_relocs;
	typedef std::vector<ImportInfo> vec_imports;

	PIMAGE_NT_HEADERS64 GetNtHeaders(void* image_base);
	vec_relocs GetRelocs(void* image_base);
	vec_imports GetImports(void* image_base);
}
