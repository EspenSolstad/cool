#include "../../includes/utils/intel_driver.hpp"
#include "../../resources/resource.h"

// Global instance
std::unique_ptr<IntelDriver> g_intelDriver;

// Constructor
IntelDriver::IntelDriver() 
    : m_deviceHandle(INVALID_HANDLE_VALUE),
      m_driverPath(L""),
      m_serviceName(L"IntelDriver") {
}

// Destructor
IntelDriver::~IntelDriver() {
    // Ensure we unload the driver
    Unload();
}

// Load the driver
bool IntelDriver::Load() {
    Logger::LogInfo("Loading Intel driver...");

    // Check if already loaded
    if (IsLoaded()) {
        Logger::LogInfo("Intel driver already loaded");
        return true;
    }

    // Extract the driver from resources
    if (!ExtractDriver()) {
        Logger::LogError("Failed to extract Intel driver");
        return false;
    }

    // Create and start the driver service
    if (!CreateDriverService(m_serviceName, L"Intel Hardware Driver", m_driverPath)) {
        Logger::LogError("Failed to create driver service");
        Cleanup();
        return false;
    }

    if (!StartDriverService(m_serviceName)) {
        Logger::LogError("Failed to start driver service");
        DeleteDriverService(m_serviceName);
        Cleanup();
        return false;
    }

    // Open handle to the device
    m_deviceHandle = CreateFileW(
        L"\\\\.\\IntelDriver",
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (m_deviceHandle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        Logger::LogError("Failed to open handle to Intel driver (error code: {})", error);
        StopDriverService(m_serviceName);
        DeleteDriverService(m_serviceName);
        Cleanup();
        return false;
    }

    Logger::LogInfo("Intel driver loaded successfully");
    return true;
}

// Unload the driver
bool IntelDriver::Unload() {
    if (!IsLoaded()) {
        return true;
    }

    Logger::LogInfo("Unloading Intel driver...");

    // Close device handle
    if (m_deviceHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_deviceHandle);
        m_deviceHandle = INVALID_HANDLE_VALUE;
    }

    // Stop and delete the driver service
    bool result = true;
    if (!StopDriverService(m_serviceName)) {
        Logger::LogWarning("Failed to stop driver service");
        result = false;
    }

    if (!DeleteDriverService(m_serviceName)) {
        Logger::LogWarning("Failed to delete driver service");
        result = false;
    }

    // Clean up temporary files
    Cleanup();

    return result;
}

// Check if the driver is loaded
bool IntelDriver::IsLoaded() const {
    return m_deviceHandle != INVALID_HANDLE_VALUE;
}

// Get the device handle
HANDLE IntelDriver::GetDeviceHandle() const {
    return m_deviceHandle;
}

// Read from kernel memory
bool IntelDriver::ReadMemory(uint64_t address, void* buffer, uint64_t size) {
    if (!IsLoaded() || !buffer || size == 0) {
        return false;
    }

    // In a real implementation, this would use IOCTLs to communicate with the driver
    // For this simplified version, we just log the operation
    Logger::LogInfo("Reading {} bytes from kernel address 0x{:X}", size, address);
    
    // Simulate simple memory operations for demonstration
    memset(buffer, 0xCC, static_cast<size_t>(size)); // Fill with pattern for demonstration
    return true;
}

// Write to kernel memory
bool IntelDriver::WriteMemory(uint64_t address, const void* buffer, uint64_t size) {
    if (!IsLoaded() || !buffer || size == 0) {
        return false;
    }

    // In a real implementation, this would use IOCTLs to communicate with the driver
    Logger::LogInfo("Writing {} bytes to kernel address 0x{:X}", size, address);
    return true;
}

// Allocate memory in the kernel
uint64_t IntelDriver::AllocatePool(uint32_t size, nt::POOL_TYPE poolType) {
    if (!IsLoaded() || size == 0) {
        return 0;
    }

    // In a real implementation, this would use IOCTLs to communicate with the driver
    Logger::LogInfo("Allocating {} bytes of kernel memory (pool type: {})", size, static_cast<int>(poolType));
    
    // Return a fake address for demonstration
    return 0xFFFF000000000000 | static_cast<uint64_t>(rand());
}

// Free memory in the kernel
bool IntelDriver::FreePool(uint64_t address) {
    if (!IsLoaded() || address == 0) {
        return false;
    }

    // In a real implementation, this would use IOCTLs to communicate with the driver
    Logger::LogInfo("Freeing kernel memory at address 0x{:X}", address);
    return true;
}

// Get kernel module information
uint64_t IntelDriver::GetKernelModuleAddress(const std::string& moduleName) {
    if (!IsLoaded() || moduleName.empty()) {
        return 0;
    }

    // In a real implementation, this would enumerate modules
    Logger::LogInfo("Getting kernel module address for '{}'", moduleName);
    
    // For ntoskrnl.exe, return a plausible address
    if (moduleName == "ntoskrnl.exe" || moduleName == "ntkrnlpa.exe") {
        return 0xFFFFF80000000000 | (static_cast<uint64_t>(rand()) & 0xFFFFFFF);
    }
    
    return 0;
}

// Get kernel module export address
uint64_t IntelDriver::GetKernelProcAddress(uint64_t moduleBase, const std::string& exportName) {
    if (!IsLoaded() || moduleBase == 0 || exportName.empty()) {
        return 0;
    }

    // In a real implementation, this would parse the module's export table
    Logger::LogInfo("Getting kernel proc address for '{}' in module at 0x{:X}", exportName, moduleBase);
    
    // Return a fake address within the module's address space
    return moduleBase + 0x1000 + (static_cast<uint64_t>(rand()) % 0x10000);
}

// Create driver service
bool IntelDriver::CreateDriverService(const std::wstring& serviceName, const std::wstring& displayName, const std::wstring& driverPath) {
    // Open the service control manager
    SC_HANDLE scmHandle = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scmHandle) {
        DWORD error = GetLastError();
        Logger::LogError("Failed to open service control manager (error code: {})", error);
        return false;
    }

    // Create the service
    SC_HANDLE serviceHandle = CreateServiceW(
        scmHandle,
        serviceName.c_str(),
        displayName.c_str(),
        SERVICE_START | SERVICE_STOP | DELETE,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        driverPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr
    );

    if (!serviceHandle) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_EXISTS) {
            // Service already exists, open it
            serviceHandle = OpenServiceW(
                scmHandle,
                serviceName.c_str(),
                SERVICE_START | SERVICE_STOP | DELETE
            );

            if (!serviceHandle) {
                error = GetLastError();
                Logger::LogError("Failed to open existing service (error code: {})", error);
                CloseServiceHandle(scmHandle);
                return false;
            }
        }
        else {
            Logger::LogError("Failed to create service (error code: {})", error);
            CloseServiceHandle(scmHandle);
            return false;
        }
    }

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);
    return true;
}

// Delete driver service
bool IntelDriver::DeleteDriverService(const std::wstring& serviceName) {
    // Open the service control manager
    SC_HANDLE scmHandle = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scmHandle) {
        DWORD error = GetLastError();
        Logger::LogError("Failed to open service control manager (error code: {})", error);
        return false;
    }

    // Open the service
    SC_HANDLE serviceHandle = OpenServiceW(
        scmHandle,
        serviceName.c_str(),
        SERVICE_STOP | DELETE
    );

    if (!serviceHandle) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            // Service doesn't exist, which is what we want
            CloseServiceHandle(scmHandle);
            return true;
        }
        
        Logger::LogError("Failed to open service (error code: {})", error);
        CloseServiceHandle(scmHandle);
        return false;
    }

    // Delete the service
    if (!DeleteService(serviceHandle)) {
        DWORD error = GetLastError();
        if (error != ERROR_SERVICE_MARKED_FOR_DELETE) {
            Logger::LogError("Failed to delete service (error code: {})", error);
            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scmHandle);
            return false;
        }
    }

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);
    return true;
}

// Start driver service
bool IntelDriver::StartDriverService(const std::wstring& serviceName) {
    // Open the service control manager
    SC_HANDLE scmHandle = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scmHandle) {
        DWORD error = GetLastError();
        Logger::LogError("Failed to open service control manager (error code: {})", error);
        return false;
    }

    // Open the service
    SC_HANDLE serviceHandle = OpenServiceW(
        scmHandle,
        serviceName.c_str(),
        SERVICE_START
    );

    if (!serviceHandle) {
        DWORD error = GetLastError();
        Logger::LogError("Failed to open service (error code: {})", error);
        CloseServiceHandle(scmHandle);
        return false;
    }

    // Start the service
    if (!StartServiceW(serviceHandle, 0, nullptr)) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_ALREADY_RUNNING) {
            // Service is already running, which is fine
            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scmHandle);
            return true;
        }
        
        Logger::LogError("Failed to start service (error code: {})", error);
        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(scmHandle);
        return false;
    }

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);
    return true;
}

// Stop driver service
bool IntelDriver::StopDriverService(const std::wstring& serviceName) {
    // Open the service control manager
    SC_HANDLE scmHandle = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scmHandle) {
        DWORD error = GetLastError();
        Logger::LogError("Failed to open service control manager (error code: {})", error);
        return false;
    }

    // Open the service
    SC_HANDLE serviceHandle = OpenServiceW(
        scmHandle,
        serviceName.c_str(),
        SERVICE_STOP
    );

    if (!serviceHandle) {
        DWORD error = GetLastError();
        Logger::LogError("Failed to open service (error code: {})", error);
        CloseServiceHandle(scmHandle);
        return false;
    }

    // Get the service status
    SERVICE_STATUS serviceStatus = { 0 };
    if (!ControlService(serviceHandle, SERVICE_CONTROL_STOP, &serviceStatus)) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_NOT_ACTIVE) {
            // Service is not running, which is fine
            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scmHandle);
            return true;
        }
        
        Logger::LogError("Failed to stop service (error code: {})", error);
        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(scmHandle);
        return false;
    }

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);
    return true;
}

// Get the version of Windows
uint32_t IntelDriver::GetWindowsVersion() {
    OSVERSIONINFOEXW osInfo = { sizeof(osInfo) };
    
    typedef NTSTATUS(WINAPI* RtlGetVersionFn)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return 0;
    }
    
    auto RtlGetVersion = reinterpret_cast<RtlGetVersionFn>(
        GetProcAddress(ntdll, "RtlGetVersion")
    );
    
    if (!RtlGetVersion) {
        return 0;
    }
    
    if (RtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&osInfo)) != 0) {
        return 0;
    }
    
    return (osInfo.dwMajorVersion << 16) | osInfo.dwMinorVersion;
}

// Extract driver from resources
bool IntelDriver::ExtractDriver() {
    // Get the temp path
    std::wstring tempPath = resource_utils::GetTempFileName(L".sys");
    
    // Extract the driver resource to the temp file
    bool result = resource_utils::ExtractResourceToFile(
        GetModuleHandle(NULL),
        DRIVER_INTEL_RESOURCE,
        tempPath
    );
    
    if (!result) {
        Logger::LogError("Failed to extract Intel driver resource");
        return false;
    }
    
    m_driverPath = tempPath;
    Logger::LogInfo("Intel driver extracted to: {}", std::string(tempPath.begin(), tempPath.end()));
    return true;
}

// Clean up after driver usage
void IntelDriver::Cleanup() {
    // Delete the temporary driver file
    if (!m_driverPath.empty()) {
        try {
            DeleteFileW(m_driverPath.c_str());
            m_driverPath.clear();
        }
        catch (const std::exception& ex) {
            Logger::LogWarning("Failed to clean up driver file: {}", ex.what());
        }
    }
}

// Device IO control
bool IntelDriver::DeviceIoControl(DWORD ioControlCode, void* inBuffer, DWORD inBufferSize, void* outBuffer, DWORD outBufferSize, DWORD* bytesReturned) {
    if (!IsLoaded()) {
        return false;
    }
    
    DWORD bytesReturnedInternal = 0;
    if (!bytesReturned) {
        bytesReturned = &bytesReturnedInternal;
    }
    
    return ::DeviceIoControl(
        m_deviceHandle,
        ioControlCode,
        inBuffer,
        inBufferSize,
        outBuffer,
        outBufferSize,
        bytesReturned,
        nullptr
    );
}
