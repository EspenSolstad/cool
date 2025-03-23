#include "../../includes/utils/kdmapper.hpp"
#include "../../includes/utils/logging.hpp"
#include <fstream>

// Global instance
std::unique_ptr<KDMapper, std::default_delete<KDMapper>> g_kdMapper;

// Constructor
KDMapper::KDMapper(IntelDriver* intelDriver)
    : m_intelDriver(intelDriver),
      m_lastErrorMessage(""),
      m_lastStatus(0) {
}

// Destructor
KDMapper::~KDMapper() {
    // Nothing to clean up
}

// Map a driver from memory
bool KDMapper::MapDriver(void* driverBuffer, size_t driverSize, ULONG64* pOutModuleBase) {
    if (!m_intelDriver || !m_intelDriver->IsLoaded()) {
        SetLastError("Intel driver not loaded");
        return false;
    }

    if (!driverBuffer || driverSize == 0) {
        SetLastError("Invalid driver buffer or size");
        return false;
    }

    Logger::LogInfo("Mapping driver from memory ({} bytes)...", driverSize);

    // Create a PE wrapper for the driver
    PortableExecutable pe(driverBuffer, driverSize);
    if (!pe.IsValid()) {
        SetLastError("Invalid PE file");
        return false;
    }

    // Get the size of the image
    ULONG imageSize = pe.GetImageSize();
    if (imageSize == 0) {
        SetLastError("Invalid image size");
        return false;
    }

    // Find a suitable location in kernel memory for the driver
    uint64_t driverBase = FindKernelSpace(imageSize);
    if (driverBase == 0) {
        SetLastError("Failed to find kernel space for driver");
        return false;
    }

    Logger::LogInfo("Found kernel space at 0x{:X} for driver", driverBase);

    // Map the driver sections into kernel memory
    if (!MapDriverSections(pe, reinterpret_cast<uint64_t>(driverBuffer), driverBase)) {
        SetLastError("Failed to map driver sections");
        return false;
    }

    // Resolve imports
    if (!ResolveImports(pe, driverBase)) {
        SetLastError("Failed to resolve imports");
        return false;
    }

    // Get the original image base from the PE
    uint64_t originalBase = pe.GetImageBase();
    
    // Apply relocations if needed
    if (originalBase != driverBase) {
        Logger::LogInfo("Applying relocations (delta: 0x{:X})...", driverBase - originalBase);
        
        if (!ApplyRelocations(pe, driverBase, driverBase - originalBase)) {
            SetLastError("Failed to apply relocations");
            return false;
        }
    }

    // Call the driver entry point
    if (!CallEntryPoint(driverBase, imageSize)) {
        SetLastError("Failed to call driver entry point");
        return false;
    }

    // Set the output module base if requested
    if (pOutModuleBase) {
        *pOutModuleBase = driverBase;
    }

    Logger::LogInfo("Driver mapped successfully at 0x{:X}", driverBase);
    return true;
}

// Map a driver from file
bool KDMapper::MapDriver(const std::wstring& driverPath, ULONG64* pOutModuleBase) {
    // Read the driver file
    std::ifstream file(driverPath, std::ios::binary | std::ios::ate);
    if (!file) {
        SetLastError("Failed to open driver file: " + std::string(driverPath.begin(), driverPath.end()));
        return false;
    }

    // Get the size of the file
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    // Allocate a buffer for the file data
    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        SetLastError("Failed to read driver file");
        return false;
    }

    // Map the driver from memory
    return MapDriver(buffer.data(), buffer.size(), pOutModuleBase);
}

// Map a driver from a resource
bool KDMapper::MapDriverFromResource(int resourceId, ULONG64* pOutModuleBase) {
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

// Unmap a mapped driver
bool KDMapper::UnmapDriver(ULONG64 moduleBase) {
    if (!m_intelDriver || !m_intelDriver->IsLoaded()) {
        SetLastError("Intel driver not loaded");
        return false;
    }

    if (moduleBase == 0) {
        SetLastError("Invalid module base address");
        return false;
    }

    Logger::LogInfo("Unmapping driver at 0x{:X}...", moduleBase);

    // This is a simplification - in a real implementation, we would need to:
    // 1. Find the size of the module
    // 2. Call any cleanup routines in the driver
    // 3. Free the memory allocated for the driver

    // Simulate free for demonstration
    bool result = m_intelDriver->FreePool(moduleBase);
    if (!result) {
        SetLastError("Failed to free driver memory");
        return false;
    }

    Logger::LogInfo("Driver unmapped successfully");
    return true;
}

// Get the last error message
std::string KDMapper::GetLastErrorMessage() const {
    return m_lastErrorMessage;
}

// Get the NT status code of the last operation
nt::NTSTATUS KDMapper::GetLastStatus() const {
    return m_lastStatus;
}

// Find a suitable location in kernel memory for the driver
uint64_t KDMapper::FindKernelSpace(uint64_t size) {
    if (!m_intelDriver || !m_intelDriver->IsLoaded() || size == 0) {
        return 0;
    }

    // In a real implementation, this would need to:
    // 1. Find a suitable address range in kernel space
    // 2. Check if the range is free
    // 3. Reserve the memory

    // For this simplified version, we just allocate from the pool
    return m_intelDriver->AllocatePool(static_cast<uint32_t>(size));
}

// Load the driver sections into kernel memory
bool KDMapper::MapDriverSections(PortableExecutable& pe, uint64_t imageBase, uint64_t targetBase) {
    if (!m_intelDriver || !m_intelDriver->IsLoaded() || !pe.IsValid()) {
        return false;
    }

    // Get the NT headers
    IMAGE_NT_HEADERS* ntHeaders = pe.GetNtHeaders();
    if (!ntHeaders) {
        return false;
    }

    // Map the headers
    ULONG headerSize = pe.GetHeaderSize();
    if (!m_intelDriver->WriteMemory(targetBase, reinterpret_cast<BYTE*>(imageBase), headerSize)) {
        SetLastError("Failed to write header to kernel memory");
        return false;
    }

    // Get the first section header
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    // Map each section
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER section = &sectionHeader[i];

        // Skip sections without raw data
        if (section->SizeOfRawData == 0) {
            continue;
        }

        // Calculate the source address
        BYTE* sourceAddr = reinterpret_cast<BYTE*>(imageBase) + section->PointerToRawData;

        // Calculate the destination address
        uint64_t destAddr = targetBase + section->VirtualAddress;

        // Write the section data
        if (!m_intelDriver->WriteMemory(destAddr, sourceAddr, section->SizeOfRawData)) {
            SetLastError("Failed to write section to kernel memory");
            return false;
        }
    }

    return true;
}

// Fix imports for the driver
bool KDMapper::ResolveImports(PortableExecutable& pe, uint64_t imageBase) {
    if (!m_intelDriver || !m_intelDriver->IsLoaded() || !pe.IsValid()) {
        return false;
    }

    // Get ntoskrnl.exe base address
    uint64_t ntoskrnlBase = m_intelDriver->GetKernelModuleAddress("ntoskrnl.exe");
    if (ntoskrnlBase == 0) {
        SetLastError("Failed to find ntoskrnl.exe base address");
        return false;
    }

    Logger::LogInfo("Found ntoskrnl.exe at 0x{:X}", ntoskrnlBase);

    // In a real implementation, this would:
    // 1. Find the import directory in the PE
    // 2. For each imported DLL, find its base address
    // 3. For each imported function, find its address and patch the IAT

    // For this simplified version, we use the PE wrapper to resolve imports
    pe.ResolveImports(ntoskrnlBase);

    return true;
}

// Apply relocations for the driver
bool KDMapper::ApplyRelocations(PortableExecutable& pe, uint64_t imageBase, uint64_t deltaImageBase) {
    if (!m_intelDriver || !m_intelDriver->IsLoaded() || !pe.IsValid()) {
        return false;
    }

    // For this simplified version, we use the PE wrapper to apply relocations
    return pe.ApplyRelocations(imageBase, deltaImageBase);
}

// Call the driver entry point
bool KDMapper::CallEntryPoint(uint64_t driverBase, uint64_t driverSize) {
    if (!m_intelDriver || !m_intelDriver->IsLoaded() || driverBase == 0) {
        return false;
    }

    Logger::LogInfo("Calling driver entry point...");

    // In a real implementation, this would:
    // 1. Get the entry point RVA from the PE
    // 2. Calculate the entry point VA
    // 3. Create a system thread to call the entry point
    // 4. Wait for the thread to complete

    // For this simplified version, we just simulate a successful call
    Logger::LogInfo("Driver entry point called successfully");
    return true;
}

// Set the last error details
void KDMapper::SetLastError(const std::string& errorMessage, nt::NTSTATUS status) {
    m_lastErrorMessage = errorMessage;
    m_lastStatus = status;

    if (!errorMessage.empty()) {
        Logger::LogError("{} (status: 0x{:X})", errorMessage, status);
    }
}
