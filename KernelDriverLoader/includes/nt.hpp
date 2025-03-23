#pragma once
#include <Windows.h>
#include <string>

namespace nt {
    // Define core types to avoid redefinition errors
    typedef LONG NTSTATUS;
    
    // Status code constants
    constexpr NTSTATUS STATUS_SUCCESS = 0;
    constexpr NTSTATUS STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
    
    // Define UNICODE_STRING structure
    typedef struct _UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR Buffer;
    } UNICODE_STRING, *PUNICODE_STRING;
    
    // Pool types for memory allocation
    enum POOL_TYPE {
        NonPagedPool = 0,
        PagedPool = 1,
        NonPagedPoolExecute = 0
    };
    
    // System information classes
    enum SYSTEM_INFORMATION_CLASS {
        SystemBasicInformation = 0,
        SystemModuleInformation = 11
    };
    
    // System module entry with helper methods to avoid access errors
    typedef struct _SYSTEM_MODULE_ENTRY {
        PVOID Reserved[2];
        PVOID Base;
        ULONG Size;
        ULONG Flags;
        USHORT Index;
        USHORT Unknown;
        USHORT LoadCount;
        USHORT ModuleNameOffset;
        CHAR ImageName[256];
        
        // Helper methods
        PVOID ImageBase() const { return Base; }
        ULONG_PTR GetImageSize() const { return Size; }
        
        // Get the module name without path
        const char* GetName() const {
            return ImageName + ModuleNameOffset;
        }
        
        // Get the full path name
        const char* FullPathName() const {
            return ImageName;
        }
        
        // Get the offset to the file name
        USHORT OffsetToFileName() const {
            return ModuleNameOffset;
        }
    } SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;
    
    // Definition for the system module information structure
    typedef struct _RTL_PROCESS_MODULES {
        ULONG NumberOfModules;
        SYSTEM_MODULE_ENTRY Modules[1];
    } RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;
    
    // Function declarations
    extern "C" {
        NTSTATUS NTAPI NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
        );
        
        NTSTATUS NTAPI RtlAdjustPrivilege(
            ULONG Privilege,
            BOOLEAN Enable,
            BOOLEAN CurrentThread,
            PBOOLEAN Enabled
        );
        
        NTSTATUS NTAPI NtLoadDriver(PUNICODE_STRING DriverServiceName);
        NTSTATUS NTAPI NtUnloadDriver(PUNICODE_STRING DriverServiceName);
        
        NTSTATUS NTAPI NtAllocateVirtualMemory(
            HANDLE ProcessHandle,
            PVOID* BaseAddress,
            ULONG_PTR ZeroBits,
            PSIZE_T RegionSize,
            ULONG AllocationType,
            ULONG Protect
        );
        
        NTSTATUS NTAPI NtFreeVirtualMemory(
            HANDLE ProcessHandle,
            PVOID* BaseAddress,
            PSIZE_T RegionSize,
            ULONG FreeType
        );
    }
    
    // Helper functions
    inline bool NT_SUCCESS(NTSTATUS status) {
        return status >= 0;
    }
    
    // Helper to convert std::wstring to UNICODE_STRING
    inline void RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
        if (SourceString) {
            size_t length = wcslen(SourceString) * sizeof(WCHAR);
            DestinationString->Length = static_cast<USHORT>(length);
            DestinationString->MaximumLength = static_cast<USHORT>(length + sizeof(WCHAR));
        }
        else {
            DestinationString->Length = DestinationString->MaximumLength = 0;
        }
        DestinationString->Buffer = const_cast<PWSTR>(SourceString);
    }
}
