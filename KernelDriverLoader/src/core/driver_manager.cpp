#include "../../includes/core/driver_manager.hpp"
#include "../../includes/utils/logging.hpp"
#include "../../includes/utils/intel_driver.hpp"
#include "../../includes/utils/kdmapper.hpp"
#include "../../includes/core/dynamic_mapper.hpp"
#include <filesystem>
#include <fstream>
#include <vector>
#include "../../resources/resource.h"

// Implementation class for DriverManager
class DriverManager::Impl {
public:
    // Constructor
    Impl() : m_initialized(false) {}
    
    // Initialize components
    bool Initialize() {
        // Initialize the Intel driver
        m_intelDriver = std::make_unique<IntelDriver>();
        if (m_intelDriver == nullptr) {
            Logger::LogError("Failed to create Intel driver instance");
            return false;
        }

        // Load the Intel driver
        if (m_intelDriver->Load() == false) {
            Logger::LogError("Failed to load Intel driver");
            return false;
        }

        Logger::LogInfo("Intel driver loaded successfully");

        // Initialize the KDMapper
        m_kdMapper = std::make_unique<KDMapper>(m_intelDriver.get());
        if (m_kdMapper == nullptr) {
            Logger::LogError("Failed to create KDMapper instance");
            return false;
        }

        Logger::LogInfo("KDMapper initialized successfully");

    // Initialize the Dynamic Mapper
    m_dynamicMapper = std::make_unique<DynamicMapper>();
    if (m_dynamicMapper == nullptr) {
        Logger::LogError("Failed to create Dynamic Mapper instance");
        return false;
    }
    
    // Set the KDMapper instance in the Dynamic Mapper
    m_dynamicMapper->SetKDMapper(m_kdMapper.get());

    Logger::LogInfo("Dynamic Mapper initialized successfully");
        
        m_initialized = true;
        return true;
    }
    
    // Cleanup resources
    void Cleanup() {
        if (!m_initialized) {
            return;
        }
        
        Logger::LogInfo("Cleaning up resources...");
        
        // Unmap any loaded drivers
        if (m_dynamicMapper != nullptr && m_dynamicMapper->IsDriverMapped()) {
            if (m_dynamicMapper->UnmapDriver()) {
                Logger::LogInfo("Dynamic driver unmapped successfully");
            }
            else {
                Logger::LogWarning("Failed to unmap dynamic driver");
            }
        }
        
        // Release Dynamic Mapper
        m_dynamicMapper.reset();
        
        // Release KDMapper
        m_kdMapper.reset();
        
        // Unload the Intel driver
        if (m_intelDriver != nullptr) {
            if (m_intelDriver->Unload()) {
                Logger::LogInfo("Intel driver unloaded successfully");
            }
            else {
                Logger::LogWarning("Failed to unload Intel driver");
            }
            
            m_intelDriver.reset();
        }
        
        m_initialized = false;
        Logger::LogInfo("Cleanup completed");
    }
    
    // Component getters
    IntelDriver* GetIntelDriver() const { return m_intelDriver.get(); }
    KDMapper* GetKDMapper() const { return m_kdMapper.get(); }
    DynamicMapper* GetDynamicMapper() const { return m_dynamicMapper.get(); }
    
    // Driver operations
    bool MapIntelDriver(uint64_t* pOutModuleBase) {
        Logger::LogInfo("Mapping Intel driver...");
        
        uint64_t driverBase = 0;
        if (m_kdMapper->MapDriverFromResource(DRIVER_INTEL_RESOURCE, &driverBase)) {
            Logger::LogInfo("Intel driver mapped successfully at 0x{:X}", driverBase);
            if (pOutModuleBase) {
                *pOutModuleBase = driverBase;
            }
            return true;
        }
        else {
            Logger::LogError("Failed to map Intel driver: {}", m_kdMapper->GetLastErrorMessage());
            return false;
        }
    }
    
    bool MapRwDrvDriver(uint64_t* pOutModuleBase) {
        Logger::LogInfo("Mapping RwDrv driver...");
        
        uint64_t driverBase = 0;
        if (m_kdMapper->MapDriverFromResource(DRIVER_RWDRV_RESOURCE, &driverBase)) {
            Logger::LogInfo("RwDrv driver mapped successfully at 0x{:X}", driverBase);
            if (pOutModuleBase) {
                *pOutModuleBase = driverBase;
            }
            return true;
        }
        else {
            Logger::LogError("Failed to map RwDrv driver: {}", m_kdMapper->GetLastErrorMessage());
            return false;
        }
    }
    
    bool MapMemDriver(uint64_t* pOutModuleBase) {
        Logger::LogInfo("Mapping MemDriver...");
        
        uint64_t driverBase = 0;
        if (m_kdMapper->MapDriverFromResource(DRIVER_MAPPER_RESOURCE, &driverBase)) {
            Logger::LogInfo("MemDriver mapped successfully at 0x{:X}", driverBase);
            if (pOutModuleBase) {
                *pOutModuleBase = driverBase;
            }
            return true;
        }
        else {
            Logger::LogError("Failed to map MemDriver: {}", m_kdMapper->GetLastErrorMessage());
            return false;
        }
    }
    
    bool MapCheatDriver(uint64_t* pOutModuleBase) {
        Logger::LogInfo("Mapping Cheat driver...");
        
        uint64_t driverBase = 0;
        if (m_kdMapper->MapDriverFromResource(DRIVER_CHEAT_RESOURCE, &driverBase)) {
            Logger::LogInfo("Cheat driver mapped successfully at 0x{:X}", driverBase);
            if (pOutModuleBase) {
                *pOutModuleBase = driverBase;
            }
            return true;
        }
        else {
            Logger::LogError("Failed to map Cheat driver: {}", m_kdMapper->GetLastErrorMessage());
            return false;
        }
    }
    
    bool MapCustomDriver(const std::string& driverPath, uint64_t* pOutModuleBase) {
        if (std::filesystem::exists(driverPath) == false) {
            Logger::LogError("Driver file not found: {}", driverPath);
            return false;
        }
        
        Logger::LogInfo("Mapping custom driver: {}", driverPath);
        
        // Read the driver file
        std::ifstream file(driverPath, std::ios::binary);
        if (file.is_open() == false) {
            Logger::LogError("Failed to open driver file: {}", driverPath);
            return false;
        }
        
        // Get file size
        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        
        // Read the file data
        std::vector<uint8_t> driverData(fileSize);
        file.read(reinterpret_cast<char*>(driverData.data()), fileSize);
        file.close();
        
        // Map the driver
        uint64_t driverBase = 0;
        if (m_kdMapper->MapDriver(driverData.data(), driverData.size(), &driverBase)) {
            Logger::LogInfo("Custom driver mapped successfully at 0x{:X}", driverBase);
            if (pOutModuleBase) {
                *pOutModuleBase = driverBase;
            }
            return true;
        }
        else {
            Logger::LogError("Failed to map custom driver: {}", m_kdMapper->GetLastErrorMessage());
            return false;
        }
    }
    
    bool UnmapDriver() {
        if (m_dynamicMapper->IsDriverMapped() == false) {
            Logger::LogWarning("No driver is currently mapped");
            return false;
        }
        
        uint64_t driverBase = m_dynamicMapper->GetMappedDriverBase();
        Logger::LogInfo("Unmapping driver at 0x{:X}...", driverBase);
        
        if (m_dynamicMapper->UnmapDriver()) {
            Logger::LogInfo("Driver unmapped successfully");
            return true;
        }
        else {
            Logger::LogError("Failed to unmap driver: {}", m_dynamicMapper->GetLastErrorMessage());
            return false;
        }
    }
    
private:
    // The unique_ptr instances are kept here in the implementation file
    std::unique_ptr<IntelDriver> m_intelDriver;
    std::unique_ptr<KDMapper> m_kdMapper;
    std::unique_ptr<DynamicMapper> m_dynamicMapper;
    bool m_initialized;
};

// DriverManager implementation 

DriverManager::DriverManager() : m_pImpl(std::make_unique<Impl>()) {
}

DriverManager::~DriverManager() {
    if (m_pImpl) {
        m_pImpl->Cleanup();
    }
}

bool DriverManager::Initialize() {
    return m_pImpl->Initialize();
}

void DriverManager::Cleanup() {
    m_pImpl->Cleanup();
}

IntelDriver* DriverManager::GetIntelDriver() const {
    return m_pImpl->GetIntelDriver();
}

KDMapper* DriverManager::GetKDMapper() const {
    return m_pImpl->GetKDMapper();
}

DynamicMapper* DriverManager::GetDynamicMapper() const {
    return m_pImpl->GetDynamicMapper();
}

bool DriverManager::MapIntelDriver(uint64_t* pOutModuleBase) {
    return m_pImpl->MapIntelDriver(pOutModuleBase);
}

bool DriverManager::MapRwDrvDriver(uint64_t* pOutModuleBase) {
    return m_pImpl->MapRwDrvDriver(pOutModuleBase);
}

bool DriverManager::MapMemDriver(uint64_t* pOutModuleBase) {
    return m_pImpl->MapMemDriver(pOutModuleBase);
}

bool DriverManager::MapCheatDriver(uint64_t* pOutModuleBase) {
    return m_pImpl->MapCheatDriver(pOutModuleBase);
}

bool DriverManager::MapCustomDriver(const std::string& driverPath, uint64_t* pOutModuleBase) {
    return m_pImpl->MapCustomDriver(driverPath, pOutModuleBase);
}

bool DriverManager::UnmapDriver() {
    return m_pImpl->UnmapDriver();
}

// Global instance and accessor
static std::unique_ptr<DriverManager> g_driverManager;

DriverManager& GetDriverManager() {
    if (!g_driverManager) {
        g_driverManager = std::make_unique<DriverManager>();
    }
    return *g_driverManager;
}
