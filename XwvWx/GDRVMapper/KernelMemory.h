#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include "GDRVTypes.h"

class KernelMemory {
public:
    KernelMemory() = delete;
    
    // Function type for memory operations
    using MemoryReadFn = std::function<bool(uint64_t, void*, size_t)>;
    using MemoryWriteFn = std::function<bool(uint64_t, const void*, size_t)>;
    using ShellcodeExecFn = std::function<bool(const void*, size_t, uint64_t*)>;

    // Find writable data section in loaded drivers
    static uint64_t FindWritableDataSection(
        uint64_t ntoskrnlBase,
        const MemoryReadFn& readMemory,
        const MemoryWriteFn& writeMemory,
        const std::string& skipModulePath = ""
    );

    // Direct kernel memory allocation using ExAllocatePool2
    static uint64_t DirectKernelAlloc(
        uint64_t exAllocatePoolAddr,
        size_t size,
        POOL_TYPE poolType,
        const MemoryReadFn& readMemory,
        const MemoryWriteFn& writeMemory,
        const ShellcodeExecFn& executeShellcode
    );

    // Get ntoskrnl.exe base address and required function addresses
    static bool GetKernelInfo(
        uint64_t& ntoskrnlBase,
        uint64_t& exAllocatePoolAddr,
        uint64_t& exFreePoolAddr
    );

private:
    // Constants
    static constexpr uint64_t PAGE_SIZE = 0x1000;
    static constexpr uint64_t ALLOCATION_GRANULARITY = 0x10000;
};
