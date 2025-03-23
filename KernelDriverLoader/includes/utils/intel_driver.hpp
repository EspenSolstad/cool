#pragma once
#include <Windows.h>
#include <string>
#include <memory>
#include <filesystem>
#include "../nt.hpp"
#include "resource_utils.hpp"
#include "logging.hpp"
#include "secure_memory.hpp"
#include "../resources/resource.h"

// Class for communicating with the Intel driver
class IntelDriver {
public:
    // Constructor
    IntelDriver();
    
    // Destructor - ensures driver is unloaded
    ~IntelDriver();
    
    // Deleted copy and move operations
    IntelDriver(const IntelDriver&) = delete;
    IntelDriver& operator=(const IntelDriver&) = delete;
    IntelDriver(IntelDriver&&) = delete;
    IntelDriver& operator=(IntelDriver&&) = delete;
    
    // Load the driver
    bool Load();
    
    // Unload the driver
    bool Unload();
    
    // Check if the driver is loaded
    bool IsLoaded() const;
    
    // Get the device handle
    HANDLE GetDeviceHandle() const;
    
    // Read from kernel memory
    bool ReadMemory(uint64_t address, void* buffer, uint64_t size);
    
    // Write to kernel memory
    bool WriteMemory(uint64_t address, const void* buffer, uint64_t size);
    
    // Allocate memory in the kernel
    uint64_t AllocatePool(uint32_t size, nt::POOL_TYPE poolType = nt::NonPagedPool);
    
    // Free memory in the kernel
    bool FreePool(uint64_t address);
    
    // Get kernel module information
    uint64_t GetKernelModuleAddress(const std::string& moduleName);
    
    // Get kernel module export address
    uint64_t GetKernelProcAddress(uint64_t moduleBase, const std::string& exportName);
    
    // Create driver service - uses registry 
    bool CreateDriverService(const std::wstring& serviceName, const std::wstring& displayName, const std::wstring& driverPath);
    
    // Delete driver service
    bool DeleteDriverService(const std::wstring& serviceName);
    
    // Start driver service
    bool StartDriverService(const std::wstring& serviceName);
    
    // Stop driver service
    bool StopDriverService(const std::wstring& serviceName);
    
    // Get the version of Windows
    static uint32_t GetWindowsVersion();

    // Device IO control (made public for kernel_bridge.cpp)
    bool DeviceIoControl(DWORD ioControlCode, void* inBuffer, DWORD inBufferSize, void* outBuffer, DWORD outBufferSize, DWORD* bytesReturned = nullptr);

private:
    // Device handle
    HANDLE m_deviceHandle;
    
    // Driver file path
    std::wstring m_driverPath;
    
    // Service name
    std::wstring m_serviceName;
    
    // Extract driver from resources
    bool ExtractDriver();
    
    // Clean up after driver usage
    void Cleanup();
};

// Single globally accessible pointer to the Intel driver instance
extern std::unique_ptr<IntelDriver> g_intelDriver;
