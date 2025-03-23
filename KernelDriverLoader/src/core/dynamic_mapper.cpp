#include "../../includes/core/dynamic_mapper.hpp"
#include <random>
#include <chrono>

// Global instance for easier access - defined in main.cpp
extern std::unique_ptr<DynamicMapper> g_dynamicMapper;

// Internal implementation structure
struct DynamicMapper::MappingContext {
    // Mapping information
    void* sourceBuffer;
    size_t sourceSize;
    
    // Driver details
    std::string driverName;
    std::string driverVersion;
    bool isProtected;
    
    // Memory protection
    bool isMemoryHidden;
    bool isHeadersObfuscated;
    
    MappingContext()
        : sourceBuffer(nullptr),
          sourceSize(0),
          driverName(""),
          driverVersion(""),
          isProtected(false),
          isMemoryHidden(false),
          isHeadersObfuscated(false) {
    }
};

// Constructor
DynamicMapper::DynamicMapper()
    : m_context(std::make_unique<MappingContext>()),
      m_lastErrorMessage(""),
      m_mappedDriverBase(0),
      m_mappedDriverSize(0),
      m_isDriverMapped(false) {
}

// Destructor
DynamicMapper::~DynamicMapper() {
    // Unmap any mapped driver
    if (m_isDriverMapped) {
        UnmapDriver();
    }
}

// Map a driver into memory
bool DynamicMapper::MapDriver(const void* driverData, size_t size, uint64_t* pOutModuleBase) {
    if (!driverData || size == 0) {
        SetLastError("Invalid driver buffer or size");
        return false;
    }
    
    Logger::LogInfo("Mapping driver ({} bytes)...", size);
    
    // Unmap any previously mapped driver
    if (m_isDriverMapped) {
        if (!UnmapDriver()) {
            SetLastError("Failed to unmap previously mapped driver");
            return false;
        }
    }
    
    // Use KDMapper to do the actual mapping
    if (g_kdMapper == nullptr) {
        SetLastError("KDMapper not initialized");
        return false;
    }
    
    // Map the driver
    uint64_t driverBase = 0;
    if (!g_kdMapper->MapDriver(const_cast<void*>(driverData), size, &driverBase)) {
        SetLastError("KDMapper failed to map driver: " + g_kdMapper->GetLastErrorMessage());
        return false;
    }
    
    // Store the mapping information
    m_mappedDriverBase = driverBase;
    m_mappedDriverSize = size;
    m_isDriverMapped = true;
    
    // Store the source data for later verification
    m_context->sourceBuffer = memory::AllocateSecure(size);
    if (m_context->sourceBuffer) {
        memcpy(m_context->sourceBuffer, driverData, size);
        m_context->sourceSize = size;
    }
    
    // Apply protections
    if (!ConfigureProtection()) {
        Logger::LogWarning("Failed to apply some protections to the mapped driver");
    }
    
    // Return the base address if requested
    if (pOutModuleBase) {
        *pOutModuleBase = driverBase;
    }
    
    Logger::LogInfo("Driver mapped successfully at 0x{:X}", driverBase);
    return true;
}

// Unmap a previously mapped driver
bool DynamicMapper::UnmapDriver() {
    if (!m_isDriverMapped) {
        return true;
    }
    
    Logger::LogInfo("Unmapping driver at 0x{:X}...", m_mappedDriverBase);
    
    // Remove any traces before unmapping
    RemoveTraces();
    
    // Use KDMapper to do the actual unmapping
    if (g_kdMapper == nullptr) {
        SetLastError("KDMapper not initialized");
        return false;
    }
    
    // Unmap the driver
    if (!g_kdMapper->UnmapDriver(m_mappedDriverBase)) {
        SetLastError("KDMapper failed to unmap driver: " + g_kdMapper->GetLastErrorMessage());
        return false;
    }
    
    // Free the source buffer
    if (m_context->sourceBuffer) {
        memory::FreeSecure(m_context->sourceBuffer, m_context->sourceSize);
        m_context->sourceBuffer = nullptr;
        m_context->sourceSize = 0;
    }
    
    // Reset mapping information
    m_mappedDriverBase = 0;
    m_mappedDriverSize = 0;
    m_isDriverMapped = false;
    
    Logger::LogInfo("Driver unmapped successfully");
    return true;
}

// Map a driver from a resource
bool DynamicMapper::MapDriverFromResource(int resourceId, uint64_t* pOutModuleBase) {
    try {
        // Load the resource
        auto driverData = resource_utils::LoadResourceData(GetModuleHandle(NULL), resourceId);
        if (driverData.empty()) {
            SetLastError("Failed to load driver resource");
            return false;
        }
        
        // Map the driver from memory
        return MapDriver(driverData.data(), driverData.size(), pOutModuleBase);
    }
    catch (const std::exception& ex) {
        SetLastError("Failed to load driver resource: " + std::string(ex.what()));
        return false;
    }
}

// Create a secure memory section
void* DynamicMapper::CreateSecureSection(size_t size) {
    if (size == 0) {
        SetLastError("Invalid section size");
        return nullptr;
    }
    
    // Allocate secure memory
    return memory::AllocateSecure(size);
}

// Free a secure memory section
bool DynamicMapper::FreeSecureSection(void* section) {
    if (!section) {
        return false;
    }
    
    // We don't know the size, but the secure memory system should handle this
    memory::FreeSecure(section, 0);
    return true;
}

// Verify that the mapping is still valid
bool DynamicMapper::VerifyMapping() {
    if (!m_isDriverMapped || !m_context->sourceBuffer || m_context->sourceSize == 0) {
        return false;
    }
    
    // In a real implementation, this would check that the mapped driver
    // hasn't been tampered with by comparing it to the source
    return true;
}

// Check the integrity of the mapped driver
bool DynamicMapper::CheckIntegrity() {
    if (!m_isDriverMapped) {
        return false;
    }
    
    // In a real implementation, this would perform integrity checks
    // on the mapped driver to ensure it hasn't been modified
    return true;
}

// Get information about the mapping
bool DynamicMapper::IsDriverMapped() const {
    return m_isDriverMapped;
}

uint64_t DynamicMapper::GetMappedDriverBase() const {
    return m_mappedDriverBase;
}

size_t DynamicMapper::GetMappedDriverSize() const {
    return m_mappedDriverSize;
}

// Get the last error message
std::string DynamicMapper::GetLastErrorMessage() const {
    return m_lastErrorMessage;
}

// Setup the mapping
bool DynamicMapper::SetupMapping() {
    if (!m_isDriverMapped) {
        return false;
    }
    
    // In a real implementation, this would perform additional setup
    // tasks after the driver has been mapped
    return true;
}

// Configure protection for the mapped driver
bool DynamicMapper::ConfigureProtection() {
    if (!m_isDriverMapped) {
        return false;
    }
    
    bool result = true;
    
    // Apply memory protection
    if (!ProtectMappedMemory(reinterpret_cast<void*>(m_mappedDriverBase), m_mappedDriverSize)) {
        Logger::LogWarning("Failed to protect mapped memory");
        result = false;
    }
    
    // Hide the mapped region
    if (!HideMappedRegion(reinterpret_cast<void*>(m_mappedDriverBase), m_mappedDriverSize)) {
        Logger::LogWarning("Failed to hide mapped region");
        result = false;
    }
    
    // Obfuscate the PE headers
    ObfuscateHeaders(reinterpret_cast<void*>(m_mappedDriverBase));
    
    return result;
}

// Remove any traces of the mapping
void DynamicMapper::RemoveTraces() {
    if (!m_isDriverMapped) {
        return;
    }
    
    // In a real implementation, this would clean up any traces
    // left by the mapping process
}

// Protect the mapped memory
bool DynamicMapper::ProtectMappedMemory(void* address, size_t size) {
    if (!address || size == 0) {
        return false;
    }
    
    // In a real implementation, this would apply memory protection
    // to the mapped driver to prevent it from being easily detected
    return true;
}

// Hide the mapped region from memory scanners
bool DynamicMapper::HideMappedRegion(void* address, size_t size) {
    if (!address || size == 0) {
        return false;
    }
    
    // In a real implementation, this would hide the mapped region
    // from memory scanners
    return true;
}

// Validate the PE headers
bool DynamicMapper::ValidateHeaders(const void* data, size_t size) {
    if (!data || size == 0) {
        return false;
    }
    
    // Create a PE wrapper to validate the headers
    PortableExecutable pe(const_cast<void*>(data), size);
    return pe.IsValid();
}

// Verify the code section hasn't been tampered with
bool DynamicMapper::VerifyCodeSection(void* base, size_t size) {
    if (!base || size == 0) {
        return false;
    }
    
    // In a real implementation, this would verify that the code
    // section hasn't been tampered with
    return true;
}

// Check that the memory is accessible
bool DynamicMapper::CheckMemoryAccess(void* address, size_t size) {
    if (!address || size == 0) {
        return false;
    }
    
    // In a real implementation, this would check that the memory
    // is accessible
    return true;
}

// Obfuscate the PE headers
void DynamicMapper::ObfuscateHeaders(void* base) {
    if (!base) {
        return;
    }
    
    // In a real implementation, this would obfuscate the PE headers
    // to make it harder to detect the driver
}

// Randomize padding in the PE file
void DynamicMapper::RandomizePadding(void* section, size_t size) {
    if (!section || size == 0) {
        return;
    }
    
    // Create a random number generator
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 255);
    
    // Randomize the padding
    uint8_t* data = static_cast<uint8_t*>(section);
    for (size_t i = 0; i < size; i++) {
        data[i] = static_cast<uint8_t>(distrib(gen));
    }
}

// Apply memory protection to a specific region
void DynamicMapper::ApplyMemoryProtection(void* address, size_t size) {
    if (!address || size == 0) {
        return;
    }
    
    // In a real implementation, this would apply memory protection
    // to the specified region
}

// Set the last error message
void DynamicMapper::SetLastError(const std::string& errorMessage) {
    m_lastErrorMessage = errorMessage;
    
    if (!errorMessage.empty()) {
        Logger::LogError(errorMessage);
    }
}
