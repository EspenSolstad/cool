#pragma once
#include <cstdint>
#include <string>
#include <functional>
#include "GDRVTypes.h"

class PageTableUtils {
public:
    PageTableUtils() = delete;
    
    // Function type for memory operations
    using MemoryReadFn = std::function<bool(uint64_t, void*, size_t)>;
    using MemoryWriteFn = std::function<bool(uint64_t, const void*, size_t)>;

    // Make memory executable by patching its PTE
    static bool MakeMemoryExecutable(
        uint64_t virtualAddr,
        const MemoryReadFn& readMemory,
        const MemoryWriteFn& writeMemory,
        std::function<bool(const void*, size_t, uint64_t*)> executeShellcode
    );

private:
    // Page table manipulation helpers
    static bool GetCR3Value(
        const MemoryReadFn& readMemory,
        const MemoryWriteFn& writeMemory,
        std::function<bool(const void*, size_t, uint64_t*)> executeShellcode,
        uint64_t& cr3Value
    );

    static bool ModifyPageTableEntry(
        uint64_t cr3,
        uint64_t virtualAddr,
        const MemoryReadFn& readMemory,
        const MemoryWriteFn& writeMemory,
        std::function<void(uint64_t&)> modifier
    );

    // Constants
    static constexpr uint64_t PAGE_SIZE = 0x1000;
    static constexpr uint64_t PTE_NX_BIT = 1ULL << 63;
};
