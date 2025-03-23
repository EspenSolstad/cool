#pragma once
#include <Windows.h>
#include <memory>
#include <vector>

class DynamicMapper {
public:
    DynamicMapper();
    ~DynamicMapper();

    bool MapDriver(const void* driver_data, size_t size);
    bool UnmapDriver();
    
    // Memory section management
    void* CreateSecureSection(size_t size);
    bool FreeSecureSection(void* section);
    
    // Verification
    bool VerifyMapping();
    bool CheckIntegrity();

private:
    struct MappingContext;
    std::unique_ptr<MappingContext> context;

    bool SetupMapping();
    bool ConfigureProtection();
    void RemoveTraces();

    // Memory protection
    bool ProtectMappedMemory(void* address, size_t size);
    bool HideMappedRegion(void* address, size_t size);
    
    // Integrity checks
    bool ValidateHeaders(const void* data, size_t size);
    bool VerifyCodeSection(void* base, size_t size);
    bool CheckMemoryAccess(void* address, size_t size);

    // Anti-detection
    void ObfuscateHeaders(void* base);
    void RandomizePadding(void* section, size_t size);
    void ApplyMemoryProtection(void* address, size_t size);
};
