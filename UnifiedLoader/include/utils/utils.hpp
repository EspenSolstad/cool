#pragma once
#include <Windows.h>
#include <string>
#include "nt.hpp"

// Global logging functions accessible to any file
void Log(const std::wstring& message);
void Log(const std::string& message);

namespace utils {
    // Path and file operations
    std::wstring GetFullTempPath();
    bool CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size);
    
    // Kernel module operations
    uint64_t GetKernelModuleAddress(const std::string& module_name);
    
    // PE file parsing utilities
    bool GetSectionBaseAndSize(BYTE* data, const char* section_name, uintptr_t* out_base, ULONG* out_size);
    void* FindSection(const char* section_name, uintptr_t module_base, PULONG section_size);
    
    // Pattern scanning utilities
    void* FindPattern(uintptr_t module_base, const BYTE* pattern, const char* mask);
    uintptr_t FindPattern(uintptr_t base, ULONG size, BYTE* pattern, const char* mask);
}
