#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <filesystem>
#include "../nt.hpp"
#include "intel_driver.hpp"
#include "portable_executable.hpp"
#include "logging.hpp"
#include "secure_memory.hpp"
#include "../resources/resource.h"

// Kernel Driver Mapper class
class KDMapper {
public:
    // Constructor - initialize with Intel driver instance
    KDMapper(IntelDriver* intelDriver);
    
    // Destructor
    ~KDMapper();
    
    // Map a driver from memory
    bool MapDriver(void* driverBuffer, size_t driverSize, ULONG64* pOutModuleBase = nullptr);
    
    // Map a driver from file
    bool MapDriver(const std::wstring& driverPath, ULONG64* pOutModuleBase = nullptr);
    
    // Map a driver from a resource
    bool MapDriverFromResource(int resourceId, ULONG64* pOutModuleBase = nullptr);
    
    // Unload a mapped driver
    bool UnmapDriver(ULONG64 moduleBase);
    
    // Get the last error message
    std::string GetLastErrorMessage() const;
    
    // Get the NT status code of the last operation
    nt::NTSTATUS GetLastStatus() const;

private:
    // Intel driver instance (not owned by this class)
    IntelDriver* m_intelDriver;
    
    // Last error message
    std::string m_lastErrorMessage;
    
    // Last NT status code
    nt::NTSTATUS m_lastStatus;
    
    // Find a suitable location in kernel memory for the driver
    uint64_t FindKernelSpace(uint64_t size);
    
    // Load the driver sections into kernel memory
    bool MapDriverSections(PortableExecutable& portableExecutable, uint64_t imageBase, uint64_t targetBase);
    
    // Fix imports for the driver
    bool ResolveImports(PortableExecutable& portableExecutable, uint64_t imageBase);
    
    // Apply relocations for the driver
    bool ApplyRelocations(PortableExecutable& portableExecutable, uint64_t imageBase, uint64_t deltaImageBase);
    
    // Call the driver entry point
    bool CallEntryPoint(uint64_t driverBase, uint64_t driverSize);
    
    // Set the last error details
    void SetLastError(const std::string& errorMessage, nt::NTSTATUS status = 0);
};

// Global instance for easier access
extern std::unique_ptr<KDMapper, std::default_delete<KDMapper>> g_kdMapper;
