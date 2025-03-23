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
};
