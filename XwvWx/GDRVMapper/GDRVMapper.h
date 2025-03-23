#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <chrono>
#include <thread>

class GDRVMapper {
public:
    GDRVMapper();
    ~GDRVMapper();

    // Initialize the mapper
    bool Initialize();
    bool ExecuteBootstrapShellcode(uint64_t functionAddr, uint64_t* result);
    uint64_t FindKThreadStackMemory();
    
    // Map a driver into kernel memory
    bool MapMemoryDriver(const std::string& driverPath, uint64_t& baseAddress);

private:
    // Device handle
    HANDLE hDevice;
    
    // Kernel addresses
    uint64_t ntoskrnlBase;
    uint64_t exAllocatePoolAddress;
    uint64_t exFreePoolAddress;
    
    // Memory management
    uint64_t lastAllocationEnd;
    uint64_t kernelBase;
    uint64_t kernelSize;
    uint64_t cachedWritableAddr;
    
    // Memory operations
    bool ReadPhysicalMemory(uint64_t physAddress, void* buffer, size_t size);
    bool WritePhysicalMemory(uint64_t physAddress, const void* buffer, size_t size, bool strictValidation = true);
    bool WriteShellcodeIncrementally(uint64_t baseAddress, const void* shellcode, size_t size);
    
    // Driver mapping helpers
    bool MapDriverWithExecPatch(const std::string& driverPath, uint64_t& baseAddress);
    bool ExecuteKernelShellcode(const void* shellcode, size_t size, uint64_t* result = nullptr);
    
    // Memory search helpers
    uint64_t FindGDRVWritableMemory();
    uint64_t TryWritableRegion(uint64_t startAddr);

    // Memory constants
    static constexpr uint64_t PAGE_SIZE = 0x1000;
    static constexpr uint64_t ALLOCATION_GRANULARITY = 0x10000;
    static constexpr uint64_t MAX_SEARCH_RANGE = 0x1000000;  // 16MB search range
    static constexpr uint64_t WRITE_CHUNK_SIZE = 8;  // Write shellcode in 8-byte chunks
    static constexpr uint64_t WRITE_DELAY_US = 100;  // 100 microseconds between writes
};
