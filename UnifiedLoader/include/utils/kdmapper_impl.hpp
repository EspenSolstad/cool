#pragma once
#include <Windows.h>
#include <string>
#include "portable_executable.hpp"

namespace kdmapper {

    // Define the AllocationMode enum that's missing
    enum class AllocationMode {
        AllocatePool,
        AllocateIndependentPages
    };

    // Define callback type for MapDriver
    typedef bool (*mapCallback)(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, size_t allocationSize);

    // Function declarations
    ULONG64 MapDriver(HANDLE device_handle, BYTE* data, ULONG64 param1, ULONG64 param2, 
                     bool free, bool destroyHeader, AllocationMode mode, 
                     bool PassAllocationAddressAsFirstParam, mapCallback callback, NTSTATUS* exitCode);

    // Helper functions (based on the binary kdmapper.hpp content)
    ULONG64 AllocateIndependentPages(HANDLE device_handle, ULONG32 size);
    void RelocateImageByDelta(portable_executable::vec_relocs relocs, const ULONG64 delta);
    bool FixSecurityCookie(void* local_image, ULONG64 kernel_image_base);
    bool ResolveImports(HANDLE device_handle, portable_executable::vec_imports imports);

} // namespace kdmapper
