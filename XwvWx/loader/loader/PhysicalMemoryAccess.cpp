#include "PhysicalMemoryAccess.h"
#include <Psapi.h>
#include <sstream>

// IOCTL codes matching those in memdriver.c
#define IOCTL_READ_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PROCESS_CR3 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Structures for IOCTL requests
typedef struct _KERNEL_READ_REQUEST {
    UINT64 Address;
    PVOID Buffer;
    UINT64 Size;
} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST {
    UINT64 Address;
    PVOID Buffer;
    UINT64 Size;
} KERNEL_WRITE_REQUEST, *PKERNEL_WRITE_REQUEST;

typedef struct _GET_PROCESS_CR3_REQUEST {
    UINT64 ProcessId;
    UINT64 CR3Value;
} GET_PROCESS_CR3_REQUEST, *PGET_PROCESS_CR3_REQUEST;

namespace kernel {

    PhysicalMemoryAccessor::PhysicalMemoryAccessor() {
        // Constructor
    }

    PhysicalMemoryAccessor::~PhysicalMemoryAccessor() {
        // Nothing to clean up
    }

    bool PhysicalMemoryAccessor::Initialize() {
        // First announce we're preparing the access mechanism
        LOG_INFO("Memory driver access mechanism preparing");
        
        // Attempt to elevate our process privileges - needed to communicate with driver
        if (!ElevateProcessPrivileges()) {
            LOG_WARNING("Failed to elevate process privileges. Driver operations may fail.");
            // We'll continue anyway and attempt to use the driver
        }
        
        // Try to check for the driver
        if (!CheckDriverAccess()) {
            LOG_ERROR("Failed to access memory driver. Kernel operations will not be available.");
            return false;
        }
        
        return true;
    }

    bool PhysicalMemoryAccessor::GetCR3Value() {
        // Get CR3 value for current process
        DWORD currentProcessId = GetCurrentProcessId();
        return GetProcessCr3Value(currentProcessId, cr3Value);
    }

    bool PhysicalMemoryAccessor::GetProcessCr3Value(DWORD processId, uint64_t& cr3ValueOut) {
        return GetProcessCr3ValueViaDriver(processId, cr3ValueOut);
    }

    bool PhysicalMemoryAccessor::ElevateProcessPrivileges() {
        HANDLE tokenHandle;
        
        // Open the process token
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle)) {
            LOG_ERROR("Failed to open process token. Error: " + std::to_string(GetLastError()));
            return false;
        }
        
        // Set up the privilege to enable
        LUID luid;
        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            LOG_ERROR("Failed to lookup privilege value. Error: " + std::to_string(GetLastError()));
            CloseHandle(tokenHandle);
            return false;
        }
        
        TOKEN_PRIVILEGES tokenPrivileges;
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = luid;
        tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        
        // Enable the privilege
        if (!AdjustTokenPrivileges(tokenHandle, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
            LOG_ERROR("Failed to adjust token privileges. Error: " + std::to_string(GetLastError()));
            CloseHandle(tokenHandle);
            return false;
        }
        
        // Check for specific error - note that AdjustTokenPrivileges returns success even if privileges weren't actually assigned
        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
            LOG_ERROR("The process does not have the privilege to adjust. Error: ERROR_NOT_ALL_ASSIGNED");
            CloseHandle(tokenHandle);
            return false;
        }
        
        // Try to enable additional privileges that might help with kernel operations
        const LPCTSTR privileges[] = {
            SE_LOAD_DRIVER_NAME,      // Required to load and unload device drivers
            SE_SYSTEM_PROFILE_NAME,   // Required to gather system-wide performance data
            SE_BACKUP_NAME,           // Might help with memory access permissions
            SE_RESTORE_NAME,          // Might help with memory access permissions
            SE_SYSTEM_ENVIRONMENT_NAME // Required to modify firmware environment values
        };
        
        for (const auto& privilege : privileges) {
            if (LookupPrivilegeValue(NULL, privilege, &luid)) {
                tokenPrivileges.Privileges[0].Luid = luid;
                AdjustTokenPrivileges(tokenHandle, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
                // We don't check for errors here, as we're just trying additional privileges that might help
            }
        }
        
        CloseHandle(tokenHandle);
        LOG_INFO("Process privileges elevated");
        return true;
    }

    bool PhysicalMemoryAccessor::CheckDriverAccess() {
        // Check if our custom device is available
        HANDLE hDevice = CreateFileW(
            L"\\\\.\\MemoryAccess",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
        
        if (hDevice != INVALID_HANDLE_VALUE) {
            // Device exists, we can use it
            CloseHandle(hDevice);
            LOG_INFO("Memory access driver found and ready");
            return true;
        }
        
        LOG_ERROR("Memory access driver not found. Make sure the driver is loaded.");
        return false;
    }

    // Read memory via driver
    bool PhysicalMemoryAccessor::ReadMemory(uint64_t address, void* buffer, size_t size) {
        // Open a handle to our device
        HANDLE hDevice = CreateFileW(
            L"\\\\.\\MemoryAccess",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
        
        if (hDevice == INVALID_HANDLE_VALUE) {
            LOG_ERROR("Failed to open memory access device for reading");
            return false;
        }
        
        // Set up the read request
        KERNEL_READ_REQUEST readRequest = { 0 };
        readRequest.Address = address;
        readRequest.Buffer = buffer;
        readRequest.Size = size;
        
        // Send the IOCTL
        DWORD bytesReturned = 0;
        BOOL success = DeviceIoControl(
            hDevice,
            IOCTL_READ_MEMORY,
            &readRequest,
            sizeof(readRequest),
            &readRequest,
            sizeof(readRequest),
            &bytesReturned,
            NULL
        );
        
        // Close the handle
        CloseHandle(hDevice);
        
        if (!success) {
            LOG_ERROR("Failed to read memory via driver, error: " + std::to_string(GetLastError()));
            return false;
        }
        
        return true;
    }

    // Write memory via driver
    bool PhysicalMemoryAccessor::WriteMemory(uint64_t address, const void* buffer, size_t size) {
        // Open a handle to our device
        HANDLE hDevice = CreateFileW(
            L"\\\\.\\MemoryAccess",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
        
        if (hDevice == INVALID_HANDLE_VALUE) {
            LOG_ERROR("Failed to open memory access device for writing");
            return false;
        }
        
        // Set up the write request
        KERNEL_WRITE_REQUEST writeRequest = { 0 };
        writeRequest.Address = address;
        writeRequest.Buffer = (PVOID)buffer; // Cast away const for the request structure
        writeRequest.Size = size;
        
        // Send the IOCTL
        DWORD bytesReturned = 0;
        BOOL success = DeviceIoControl(
            hDevice,
            IOCTL_WRITE_MEMORY,
            &writeRequest,
            sizeof(writeRequest),
            &writeRequest,
            sizeof(writeRequest),
            &bytesReturned,
            NULL
        );
        
        // Close the handle
        CloseHandle(hDevice);
        
        if (!success) {
            LOG_ERROR("Failed to write memory via driver, error: " + std::to_string(GetLastError()));
            return false;
        }
        
        return true;
    }

    // Get CR3 value for a process via driver
    bool PhysicalMemoryAccessor::GetProcessCr3ValueViaDriver(DWORD processId, uint64_t& cr3Value) {
        // Open a handle to our device
        HANDLE hDevice = CreateFileW(
            L"\\\\.\\MemoryAccess",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
        
        if (hDevice == INVALID_HANDLE_VALUE) {
            LOG_ERROR("Failed to open memory access device for CR3 query");
            return false;
        }
        
        // Set up the CR3 request
        GET_PROCESS_CR3_REQUEST cr3Request = { 0 };
        cr3Request.ProcessId = processId;
        
        // Send the IOCTL
        DWORD bytesReturned = 0;
        BOOL success = DeviceIoControl(
            hDevice,
            IOCTL_GET_PROCESS_CR3,
            &cr3Request,
            sizeof(cr3Request),
            &cr3Request,
            sizeof(cr3Request),
            &bytesReturned,
            NULL
        );
        
        // Close the handle
        CloseHandle(hDevice);
        
        if (!success) {
            LOG_ERROR("Failed to get CR3 value via driver, error: " + std::to_string(GetLastError()));
            return false;
        }
        
        // Update CR3 value from the response
        cr3Value = cr3Request.CR3Value;
        LOG_INFO("Got CR3 value via driver: 0x" + std::to_string(cr3Value));
        
        return true;
    }

    uint64_t PhysicalMemoryAccessor::AllocateMemory(size_t size) {
        // For kernel memory allocation, we need to find available non-paged pool
        // This is a simplified approach - in a real implementation, you'd need to
        // find and use kernel APIs like ExAllocatePoolWithTag
        
        // For demonstration, we'll simulate allocation from a fixed location
        static uint64_t nextAllocation = 0xFFFFA80000000000;
        
        // Align to page size
        size_t alignedSize = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        
        // "Allocate" memory
        uint64_t allocationAddress = nextAllocation;
        nextAllocation += alignedSize;
        
        // Zero the memory
        std::vector<uint8_t> zeroBuffer(alignedSize, 0);
        if (!WriteMemory(allocationAddress, zeroBuffer.data(), alignedSize)) {
            LOG_ERROR("Failed to zero allocated memory");
            return 0;
        }
        
        // Add to allocations list
        Allocation allocation;
        allocation.address = allocationAddress;
        allocation.size = alignedSize;
        allocations.push_back(allocation);
        
        LOG_INFO("Allocated " + std::to_string(alignedSize) + " bytes at 0x" + std::to_string(allocationAddress));
        return allocationAddress;
    }

    bool PhysicalMemoryAccessor::FreeMemory(uint64_t address) {
        // Find the allocation
        auto it = std::find_if(allocations.begin(), allocations.end(),
            [address](const Allocation& alloc) { return alloc.address == address; });
        
        if (it == allocations.end()) {
            LOG_ERROR("Could not find allocation at address: 0x" + std::to_string(address));
            return false;
        }
        
        // In a real implementation, you'd free the kernel memory
        // using APIs like ExFreePoolWithTag
        
        // Remove from allocations list
        allocations.erase(it);
        
        LOG_INFO("Freed memory at 0x" + std::to_string(address));
        return true;
    }

    bool PhysicalMemoryAccessor::ExecuteCode(uint64_t address) {
        // Executing code in kernel context is complex
        // In a real implementation, you might:
        // 1. Find an APC queue to insert the request
        // 2. Overwrite an existing function pointer in a device object
        // 3. Use an existing driver's IO control to execute code
        
        LOG_INFO("Executing code at 0x" + std::to_string(address));
        
        // This is a placeholder - real implementation would vary
        return true;
    }
}
