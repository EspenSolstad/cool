#include "utils/utils.hpp"
#include <Windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <filesystem>
#include <TlHelp32.h>

void Log(const std::wstring& message) {
    std::wcout << message;
}

void Log(const std::string& message) {
    std::cout << message;
}

std::wstring utils::GetFullTempPath() {
    wchar_t temp_directory[MAX_PATH + 1] = { 0 };
    const uint32_t get_temp_path_ret = GetTempPathW(sizeof(temp_directory) / 2, temp_directory);
    if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH + 1) {
        return L"";
    }
    return std::wstring(temp_directory);
}

bool utils::CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size) {
    std::ofstream file_ofstream(desired_file_path.c_str(), std::ios_base::out | std::ios_base::binary);

    if (!file_ofstream.write(address, size)) {
        file_ofstream.close();
        return false;
    }

    file_ofstream.close();
    return true;
}

uint64_t utils::GetKernelModuleAddress(const std::string& module_name) {
    void* buffer = nullptr;
    DWORD buffer_size = 0;

    NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);

    while (status == nt::STATUS_INFO_LENGTH_MISMATCH) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);
    }

    if (!NT_SUCCESS(status)) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return 0;
    }

    const auto modules = static_cast<nt::PRTL_PROCESS_MODULES>(buffer);

    for (auto i = 0u; i < modules->NumberOfModules; ++i) {
        const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[i].FullPathName) + modules->Modules[i].OffsetToFileName);

        if (!_stricmp(current_module_name.c_str(), module_name.c_str())) {
            const uint64_t result = reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);
            VirtualFree(buffer, 0, MEM_RELEASE);
            return result;
        }
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    return 0;
}

bool utils::GetSectionBaseAndSize(BYTE* data, const char* section_name, uintptr_t* out_base, ULONG* out_size) {
    const PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(data);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    const PIMAGE_NT_HEADERS nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(data + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    const PIMAGE_SECTION_HEADER first_section = IMAGE_FIRST_SECTION(nt_headers);

    // Find section
    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        const auto section = &first_section[i];
        if (!_strnicmp(reinterpret_cast<const char*>(section->Name), section_name, 8)) {
            *out_base = section->VirtualAddress;
            *out_size = section->Misc.VirtualSize;
            return true;
        }
    }

    return false;
}

void* utils::FindSection(const char* section_name, uintptr_t module_base, PULONG section_size) {
    const PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module_base);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return nullptr;
    }

    const PIMAGE_NT_HEADERS nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(module_base + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        return nullptr;
    }

    const PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_headers);

    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        if (!_strnicmp(reinterpret_cast<const char*>(section_header[i].Name), section_name, 8)) {
            *section_size = section_header[i].Misc.VirtualSize;
            return reinterpret_cast<void*>(module_base + section_header[i].VirtualAddress);
        }
    }

    return nullptr;
}

void* utils::FindPattern(uintptr_t module_base, const BYTE* pattern, const char* mask) {
    const auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(module_base);
    const auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(module_base + dos_header->e_lfanew);

    const auto size_of_image = nt_headers->OptionalHeader.SizeOfImage;
    auto pattern_length = strlen(mask);

    for (size_t i = 0; i < size_of_image - pattern_length; i++) {
        bool found = true;
        for (size_t j = 0; j < pattern_length; j++) {
            found &= mask[j] == '?' || pattern[j] == *reinterpret_cast<BYTE*>(module_base + i + j);
            if (!found) break;
        }
        if (found) {
            return reinterpret_cast<void*>(module_base + i);
        }
    }

    return nullptr;
}

uintptr_t utils::FindPattern(uintptr_t base, ULONG size, BYTE* pattern, const char* mask) {
    const size_t pattern_length = strlen(mask);

    for (size_t i = 0; i < size - pattern_length; i++) {
        bool found = true;

        for (size_t j = 0; j < pattern_length; j++) {
            if (mask[j] != '?' && pattern[j] != *reinterpret_cast<BYTE*>(base + i + j)) {
                found = false;
                break;
            }
        }

        if (found) {
            return base + i;
        }
    }

    return 0;
}
