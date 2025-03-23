#pragma once
#include <string>
#include <memory>

// Forward declarations
class IntelDriver;
class KDMapper;
class DynamicMapper;

// Driver Manager handles all components and their lifetime
class DriverManager {
public:
    // Constructor
    DriverManager();
    
    // Destructor
    ~DriverManager();
    
    // Initialize all components
    bool Initialize();
    
    // Cleanup all resources
    void Cleanup();
    
    // Get raw pointers to components (not owned by caller)
    IntelDriver* GetIntelDriver() const;
    KDMapper* GetKDMapper() const;
    DynamicMapper* GetDynamicMapper() const;
    
    // Driver mapping operations
    bool MapIntelDriver(uint64_t* pOutModuleBase = nullptr);
    bool MapRwDrvDriver(uint64_t* pOutModuleBase = nullptr);
    bool MapMemDriver(uint64_t* pOutModuleBase = nullptr);
    bool MapCheatDriver(uint64_t* pOutModuleBase = nullptr);
    bool MapCustomDriver(const std::string& driverPath, uint64_t* pOutModuleBase = nullptr);
    bool UnmapDriver();
    
private:
    // Private implementation
    class Impl;
    std::unique_ptr<Impl> m_pImpl;
};

// Create a global accessor function for the driver manager
DriverManager& GetDriverManager();
