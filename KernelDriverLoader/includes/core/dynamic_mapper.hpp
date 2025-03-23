#pragma once
#include <Windows.h>
#include <memory>
#include <vector>
#include "../utils/logging.hpp"
#include "../utils/secure_memory.hpp"

// Forward declarations
class PortableExecutable;
class DynamicMapper;

// Global instance for easier access
extern std::unique_ptr<DynamicMapper> g_dynamicMapper;

// Include after forward declarations
#include "../utils/kdmapper.hpp"
#include "../utils/portable_executable.hpp"

// Dynamic mapper provides memory protection and anti-detection for mapped drivers
class DynamicMapper {
public:
    // Constructor
    DynamicMapper();
    
    // Destructor
    ~DynamicMapper();
    
    // Map a driver into memory
    bool MapDriver(const void* driverData, size_t size, uint64_t* pOutModuleBase = nullptr);
    
    // Unmap a previously mapped driver
    bool UnmapDriver();
    
    // Map a driver from a resource
    bool MapDriverFromResource(int resourceId, uint64_t* pOutModuleBase = nullptr);
    
    // Memory section management
    void* CreateSecureSection(size_t size);
    bool FreeSecureSection(void* section);
    
    // Verification
    bool VerifyMapping();
    bool CheckIntegrity();
    
    // Get information about the mapping
    bool IsDriverMapped() const;
    uint64_t GetMappedDriverBase() const;
    size_t GetMappedDriverSize() const;
    
    // Get the last error message
    std::string GetLastErrorMessage() const;

private:
    // Internal context structure
    struct MappingContext;
    std::unique_ptr<MappingContext> m_context;
    
    // Last error message
    std::string m_lastErrorMessage;
    
    // Mapped driver information
    uint64_t m_mappedDriverBase;
    size_t m_mappedDriverSize;
    bool m_isDriverMapped;
    
    // Setup functions
    bool SetupMapping();
    bool ConfigureProtection();
    void RemoveTraces();
    
    // Memory protection functions
    bool ProtectMappedMemory(void* address, size_t size);
    bool HideMappedRegion(void* address, size_t size);
    
    // Integrity check functions
    bool ValidateHeaders(const void* data, size_t size);
    bool VerifyCodeSection(void* base, size_t size);
    bool CheckMemoryAccess(void* address, size_t size);
    
    // Anti-detection functions
    void ObfuscateHeaders(void* base);
    void RandomizePadding(void* section, size_t size);
    void ApplyMemoryProtection(void* address, size_t size);
    
    // Set the last error message
    void SetLastError(const std::string& errorMessage);
};
