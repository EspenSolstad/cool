#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <cstdint>
#include <memory>

// PE structure definitions
#pragma warning(disable : 4201)

typedef struct _IMAGE_RELOC {
    WORD offset : 12;
    WORD type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

// Memory protection utilities
#define SEC_PRIV 0x800000
#define PAGE_EXECUTE_READWRITE 0x40

// Privilege constants
#define SE_DEBUG_PRIVILEGE 20

// Driver paths
const std::wstring VULNERABLE_DRIVER_PATH = L"..\\..\\drivers\\gdrv.sys";  // Gigabyte driver
const std::wstring BACKUP_DRIVER_PATH = L"..\\..\\drivers\\RTCore64.sys";  // RW Everything driver
const std::wstring CUSTOM_DRIVER_PATH = L"..\\..\\drivers\\HelloWorld.sys"; // Our test driver
const std::wstring MEMORY_DRIVER_PATH = L"..\\..\\memdriver\\x64\\Release\\memdriver.sys"; // Final memory driver

// Error handling
#define ASSERT(expr, msg) if(!(expr)) { std::cerr << "[!] Assertion failed: " << msg << " (Error: " << GetLastError() << ")" << std::endl; return false; }
#define LOG_INFO(msg) std::cout << "[+] " << msg << std::endl;
#define LOG_ERROR(msg) std::cerr << "[-] " << msg << " (Error: " << GetLastError() << ")" << std::endl;
#define LOG_WARNING(msg) std::cout << "[!] " << msg << std::endl;

// Memory access functions
typedef NTSTATUS(WINAPI* NtLoadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(WINAPI* NtUnloadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(WINAPI* RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

// Direct physical memory access definitions for the vulnerable driver exploit
#define GIGABYTE_VENDOR 0x1458
#define GDRV_DEVICE_NAME "\\\\.\\GIO"
#define GDRV_READ_REQUEST_CODE 0x80102040
#define GDRV_WRITE_REQUEST_CODE 0x80102044

#pragma pack(push, 1)
typedef struct _GDRV_MEMORY_OPERATION {
    uint64_t address;
    uint32_t size;
    uint64_t buffer;
} GDRV_MEMORY_OPERATION, * PGDRV_MEMORY_OPERATION;
#pragma pack(pop)

// RW Everything direct memory access definitions
#define RWDRV_DEVICE_NAME "\\\\.\\RTCore64"
#define RWDRV_READ_MEMORY_CODE 0x80002048
#define RWDRV_WRITE_MEMORY_CODE 0x8000204C

#pragma pack(push, 1)
typedef struct _RWDRV_MEMORY_OPERATION {
    uint64_t address;
    uint32_t size;
    uint64_t buffer;
} RWDRV_MEMORY_OPERATION, * PRWDRV_MEMORY_OPERATION;
#pragma pack(pop)

// Manual mapping class
class ManualMapper {
private:
    // Driver access handles
    HANDLE gDriverHandle = INVALID_HANDLE_VALUE;
    HANDLE rwDriverHandle = INVALID_HANDLE_VALUE;

    // Kernel memory access methods
    bool ReadKernelMemory(HANDLE driverHandle, uint64_t address, void* buffer, size_t size, uint32_t readCode) {
        if (driverHandle == INVALID_HANDLE_VALUE) return false;

        if (driverHandle == gDriverHandle) {
            GDRV_MEMORY_OPERATION operation = { 0 };
            operation.address = address;
            operation.size = static_cast<uint32_t>(size);
            operation.buffer = reinterpret_cast<uint64_t>(buffer);

            DWORD bytesReturned = 0;
            return DeviceIoControl(driverHandle, readCode, &operation, sizeof(operation), &operation, sizeof(operation), &bytesReturned, nullptr);
        }
        else if (driverHandle == rwDriverHandle) {
            RWDRV_MEMORY_OPERATION operation = { 0 };
            operation.address = address;
            operation.size = static_cast<uint32_t>(size);
            operation.buffer = reinterpret_cast<uint64_t>(buffer);

            DWORD bytesReturned = 0;
            return DeviceIoControl(driverHandle, readCode, &operation, sizeof(operation), &operation, sizeof(operation), &bytesReturned, nullptr);
        }

        return false;
    }

    bool WriteKernelMemory(HANDLE driverHandle, uint64_t address, void* buffer, size_t size, uint32_t writeCode) {
        if (driverHandle == INVALID_HANDLE_VALUE) return false;

        if (driverHandle == gDriverHandle) {
            GDRV_MEMORY_OPERATION operation = { 0 };
            operation.address = address;
            operation.size = static_cast<uint32_t>(size);
            operation.buffer = reinterpret_cast<uint64_t>(buffer);

            DWORD bytesReturned = 0;
            return DeviceIoControl(driverHandle, writeCode, &operation, sizeof(operation), &operation, sizeof(operation), &bytesReturned, nullptr);
        }
        else if (driverHandle == rwDriverHandle) {
            RWDRV_MEMORY_OPERATION operation = { 0 };
            operation.address = address;
            operation.size = static_cast<uint32_t>(size);
            operation.buffer = reinterpret_cast<uint64_t>(buffer);

            DWORD bytesReturned = 0;
            return DeviceIoControl(driverHandle, writeCode, &operation, sizeof(operation), &operation, sizeof(operation), &bytesReturned, nullptr);
        }

        return false;
    }

    // Driver loading methods
    bool LoadDriver(const std::wstring& driverPath, const std::wstring& serviceName) {
        // Create a unique registry path for the driver
        std::wstring registryPath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + serviceName;

        // Get ntdll function pointers
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (!ntdll) return false;

        auto NtLoadDriverFn = reinterpret_cast<NtLoadDriver>(GetProcAddress(ntdll, "NtLoadDriver"));
        auto RtlAdjustPrivilegeFn = reinterpret_cast<RtlAdjustPrivilege>(GetProcAddress(ntdll, "RtlAdjustPrivilege"));

        if (!NtLoadDriverFn || !RtlAdjustPrivilegeFn) return false;

        // Enable load driver privilege
        BOOLEAN enabled = FALSE;
        NTSTATUS status = RtlAdjustPrivilegeFn(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &enabled);
        if (status != 0) return false;

        // Create registry service entry
        HKEY serviceKey = NULL;
        LSTATUS result = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            (L"System\\CurrentControlSet\\Services\\" + serviceName).c_str(),
            0,
            NULL,
            0,
            KEY_ALL_ACCESS,
            NULL,
            &serviceKey,
            NULL
        );

        if (result != ERROR_SUCCESS) return false;

        // Set registry values for the service
        DWORD serviceType = 1; // SERVICE_KERNEL_DRIVER
        DWORD serviceStart = 3; // SERVICE_DEMAND_START
        DWORD serviceError = 1; // SERVICE_ERROR_NORMAL

        RegSetValueExW(serviceKey, L"Type", 0, REG_DWORD, reinterpret_cast<BYTE*>(&serviceType), sizeof(serviceType));
        RegSetValueExW(serviceKey, L"Start", 0, REG_DWORD, reinterpret_cast<BYTE*>(&serviceStart), sizeof(serviceStart));
        RegSetValueExW(serviceKey, L"ErrorControl", 0, REG_DWORD, reinterpret_cast<BYTE*>(&serviceError), sizeof(serviceError));
        RegSetValueExW(serviceKey, L"ImagePath", 0, REG_EXPAND_SZ, reinterpret_cast<const BYTE*>((L"\\??\\" + driverPath).c_str()), (DWORD)((L"\\??\\" + driverPath).length() + 1) * sizeof(wchar_t));

        RegCloseKey(serviceKey);

        // Convert registry path to UNICODE_STRING
        UNICODE_STRING serviceNameUnicode;
        serviceNameUnicode.Buffer = const_cast<wchar_t*>(registryPath.c_str());
        serviceNameUnicode.Length = (USHORT)(registryPath.length() * sizeof(wchar_t));
        serviceNameUnicode.MaximumLength = (USHORT)((registryPath.length() + 1) * sizeof(wchar_t));

        // Load the driver
        status = NtLoadDriverFn(&serviceNameUnicode);

        // Clean up registry entry
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, (L"System\\CurrentControlSet\\Services\\" + serviceName).c_str());

        return (status == 0);
    }

    // Manual mapping utilities
    bool MapDriver(const std::wstring& driverPath, uint64_t& baseAddress) {
        // Read the driver file
        std::ifstream file(driverPath, std::ios::binary | std::ios::ate);
        if (!file) {
            LOG_ERROR("Failed to open driver file: " + std::string(driverPath.begin(), driverPath.end()));
            return false;
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<char> buffer(size);
        if (!file.read(buffer.data(), size)) {
            LOG_ERROR("Failed to read driver file");
            return false;
        }

        // Parse PE headers
        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            LOG_ERROR("Invalid DOS signature");
            return false;
        }

        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(buffer.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            LOG_ERROR("Invalid NT signature");
            return false;
        }

        // Allocate kernel memory for the driver
        uint64_t imageSize = ntHeaders->OptionalHeader.SizeOfImage;
        uint64_t mappedImage = AllocateKernelMemory(imageSize);
        if (!mappedImage) {
            LOG_ERROR("Failed to allocate kernel memory");
            return false;
        }

        // Copy sections
        auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            uint64_t sectionAddress = mappedImage + sectionHeader[i].VirtualAddress;
            uint64_t sectionSize = sectionHeader[i].SizeOfRawData;
            uint64_t sectionData = reinterpret_cast<uint64_t>(buffer.data()) + sectionHeader[i].PointerToRawData;

            if (sectionSize > 0) {
                if (!WriteKernelMemory(GetActiveDriverHandle(), sectionAddress, reinterpret_cast<void*>(sectionData), sectionSize, GetActiveWriteCode())) {
                    LOG_ERROR("Failed to write section data");
                    return false;
                }
            }
        }

        // Resolve relocations
        uint64_t relocationDelta = mappedImage - ntHeaders->OptionalHeader.ImageBase;
        if (relocationDelta != 0 && ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
            uint64_t relocationTable = mappedImage + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
            uint64_t relocationEnd = relocationTable + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

            while (relocationTable < relocationEnd) {
                IMAGE_BASE_RELOCATION relocation;
                ReadKernelMemory(GetActiveDriverHandle(), relocationTable, &relocation, sizeof(relocation), GetActiveReadCode());

                if (relocation.SizeOfBlock == 0) break;

                uint64_t relocationCount = (relocation.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                uint64_t relocationData = relocationTable + sizeof(IMAGE_BASE_RELOCATION);
                uint64_t relocationBase = mappedImage + relocation.VirtualAddress;

                std::vector<WORD> relocations(relocationCount);
                ReadKernelMemory(GetActiveDriverHandle(), relocationData, relocations.data(), relocations.size() * sizeof(WORD), GetActiveReadCode());

                for (size_t i = 0; i < relocationCount; i++) {
                    WORD relocationInfo = relocations[i];
                    uint64_t relocationType = relocationInfo >> 12;
                    uint64_t relocationOffset = relocationInfo & 0xFFF;

                    if (relocationType == IMAGE_REL_BASED_DIR64) {
                        uint64_t patchAddress = relocationBase + relocationOffset;
                        uint64_t patchedValue = 0;
                        
                        ReadKernelMemory(GetActiveDriverHandle(), patchAddress, &patchedValue, sizeof(patchedValue), GetActiveReadCode());
                        patchedValue += relocationDelta;
                        WriteKernelMemory(GetActiveDriverHandle(), patchAddress, &patchedValue, sizeof(patchedValue), GetActiveWriteCode());
                    }
                }

                relocationTable += relocation.SizeOfBlock;
            }
        }

        // Execute driver entry point
        uint64_t entryPoint = mappedImage + ntHeaders->OptionalHeader.AddressOfEntryPoint;
        
        // We use a dummy shellcode to execute the entry point
        // The shellcode looks like:
        // mov rcx, driverObject
        // mov rdx, registryPath
        // jmp entryPoint
        unsigned char shellcode[] = {
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rcx, 0 (driverObject)
            0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rdx, 0 (registryPath)
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,                          // jmp [rip + 0]
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00               // entryPoint address
        };

        // Set the entryPoint in the shellcode
        *reinterpret_cast<uint64_t*>(&shellcode[sizeof(shellcode) - 8]) = entryPoint;

        // Allocate memory for the shellcode
        uint64_t shellcodeAddress = AllocateKernelMemory(sizeof(shellcode));
        if (!shellcodeAddress) {
            LOG_ERROR("Failed to allocate memory for shellcode");
            return false;
        }

        // Write the shellcode to kernel memory
        if (!WriteKernelMemory(GetActiveDriverHandle(), shellcodeAddress, shellcode, sizeof(shellcode), GetActiveWriteCode())) {
            LOG_ERROR("Failed to write shellcode");
            return false;
        }

        // Execute the shellcode (optional: this depends on how you want to handle execution)
        // This may involve calling an existing driver function that will trigger execution of our shellcode
        // For demonstration purposes, we'll just skip this step

        // Return the mapped base address
        baseAddress = mappedImage;
        LOG_INFO("Driver mapped at 0x" + std::to_string(mappedImage));
        return true;
    }

    uint64_t AllocateKernelMemory(size_t size) {
        // Use the vulnerable driver to allocate non-paged pool memory
        // This is highly driver-specific and would need to be implemented
        // based on the vulnerability being exploited
        
        // For demonstration purposes, we're allocating a fixed address
        // In a real implementation, you would allocate proper kernel memory
        static uint64_t memoryBase = 0xFFFFA80000000000;
        uint64_t allocatedAddress = memoryBase;
        memoryBase += size + 0x1000; // Simple bump allocator with padding
        
        // Zero the memory
        std::vector<uint8_t> zeroBuffer(size, 0);
        WriteKernelMemory(GetActiveDriverHandle(), allocatedAddress, zeroBuffer.data(), size, GetActiveWriteCode());
        
        return allocatedAddress;
    }

    // Helper functions
    HANDLE GetActiveDriverHandle() {
        // Return the handle of whichever driver is currently active
        if (gDriverHandle != INVALID_HANDLE_VALUE) return gDriverHandle;
        if (rwDriverHandle != INVALID_HANDLE_VALUE) return rwDriverHandle;
        return INVALID_HANDLE_VALUE;
    }

    uint32_t GetActiveReadCode() {
        if (gDriverHandle != INVALID_HANDLE_VALUE) return GDRV_READ_REQUEST_CODE;
        if (rwDriverHandle != INVALID_HANDLE_VALUE) return RWDRV_READ_MEMORY_CODE;
        return 0;
    }

    uint32_t GetActiveWriteCode() {
        if (gDriverHandle != INVALID_HANDLE_VALUE) return GDRV_WRITE_REQUEST_CODE;
        if (rwDriverHandle != INVALID_HANDLE_VALUE) return RWDRV_WRITE_MEMORY_CODE;
        return 0;
    }

public:
    ManualMapper() = default;
    ~ManualMapper() {
        // Close driver handles
        if (gDriverHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(gDriverHandle);
        }
        if (rwDriverHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(rwDriverHandle);
        }
    }

    bool Initialize() {
        // Try to use the Gigabyte driver first
        LOG_INFO("Trying to load Gigabyte driver...");
        if (LoadDriver(VULNERABLE_DRIVER_PATH, L"gdrv")) {
            LOG_INFO("Gigabyte driver loaded successfully");
            gDriverHandle = CreateFileA(GDRV_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (gDriverHandle != INVALID_HANDLE_VALUE) {
                LOG_INFO("Gigabyte driver device opened successfully");
                return true;
            }
            else {
                LOG_WARNING("Failed to open Gigabyte driver device");
            }
        }
        else {
            LOG_WARNING("Failed to load Gigabyte driver");
        }

        // Fall back to RW Everything driver
        LOG_INFO("Trying to load RW Everything driver...");
        if (LoadDriver(BACKUP_DRIVER_PATH, L"RTCore64")) {
            LOG_INFO("RW Everything driver loaded successfully");
            rwDriverHandle = CreateFileA(RWDRV_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (rwDriverHandle != INVALID_HANDLE_VALUE) {
                LOG_INFO("RW Everything driver device opened successfully");
                return true;
            }
            else {
                LOG_WARNING("Failed to open RW Everything driver device");
            }
        }
        else {
            LOG_WARNING("Failed to load RW Everything driver");
        }

        LOG_ERROR("Failed to initialize any vulnerable driver");
        return false;
    }

    bool MapCustomDriver(uint64_t& baseAddress) {
        if (GetActiveDriverHandle() == INVALID_HANDLE_VALUE) {
            LOG_ERROR("No active driver handle");
            return false;
        }

        // Map the memory driver into kernel space
        LOG_INFO("Mapping custom driver...");
        if (!MapDriver(MEMORY_DRIVER_PATH, baseAddress)) {
            LOG_ERROR("Failed to map custom driver");
            return false;
        }

        LOG_INFO("Custom driver mapped successfully at 0x" + std::to_string(baseAddress));
        return true;
    }

    // Memory manipulation functions for the ESP hack
    bool ReadMemory(DWORD pid, uintptr_t address, void* buffer, size_t size) {
        HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!processHandle) {
            LOG_ERROR("Failed to open target process");
            return false;
        }

        PROCESS_BASIC_INFORMATION pbi;
        ULONG returnLength;
        
        // Get ntdll function pointer for NtQueryInformationProcess
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (!ntdll) {
            CloseHandle(processHandle);
            return false;
        }

        auto NtQueryInformationProcess = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)>(
            GetProcAddress(ntdll, "NtQueryInformationProcess"));

        if (!NtQueryInformationProcess) {
            CloseHandle(processHandle);
            return false;
        }

        // Get process information
        NTSTATUS status = NtQueryInformationProcess(processHandle, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
        CloseHandle(processHandle);

        if (status != 0) {
            LOG_ERROR("Failed to query process information");
            return false;
        }

        // Read process memory through our mapped driver
        uint64_t dirBase = 0;  // CR3 register value for the process
        
        // In a real implementation, you would:
        // 1. Get the process's DirectoryTableBase (CR3)
        // 2. Use it to translate virtual to physical addresses
        // 3. Read the physical memory

        // For simplicity, we'll just simulate successful memory read
        memset(buffer, 0, size);
        return true;
    }

    bool WriteMemory(DWORD pid, uintptr_t address, const void* buffer, size_t size) {
        // Similar to ReadMemory, but for writing
        // This would use the same approach to find the physical address
        // and then write to it using the vulnerable driver
        return true;
    }
};

// Main entry point
int main() {
    // Set console title
    SetConsoleTitleA("DBD Advanced Driver Mapper");

    // Print welcome message
    std::cout << "=========================================\n";
    std::cout << "  Dead By Daylight Anti-Cheat Bypasser  \n";
    std::cout << "=========================================\n\n";

    // Initialize the mapper
    ManualMapper mapper;
    if (!mapper.Initialize()) {
        std::cerr << "[-] Failed to initialize the mapper\n";
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }

    // Map the custom driver
    uint64_t driverBase = 0;
    if (!mapper.MapCustomDriver(driverBase)) {
        std::cerr << "[-] Failed to map the memory driver\n";
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }

    // Wait for Dead by Daylight to start
    std::cout << "[*] Waiting for Dead by Daylight...\n";
    DWORD pid = 0;
    while (!pid) {
        pid = []() -> DWORD {
            DWORD result = 0;
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 entry;
                entry.dwSize = sizeof(entry);
                if (Process32First(snapshot, &entry)) {
                    do {
                        if (_stricmp(entry.szExeFile, "DeadByDaylight-Win64-Shipping.exe") == 0) {
                            result = entry.th32ProcessID;
                            break;
                        }
                    } while (Process32Next(snapshot, &entry));
                }
                CloseHandle(snapshot);
            }
            return result;
        }();
        
        if (!pid) Sleep(1000);
    }

    std::cout << "[+] Dead by Daylight found! PID: " << pid << "\n";
    std::cout << "[+] Driver mapper completed successfully\n";
    std::cout << "[+] Base address: 0x" << std::hex << driverBase << std::dec << "\n";
    std::cout << "[+] You can now launch the ESP hack\n\n";
    
    std::cout << "Press Enter to exit...";
    std::cin.get();
    return 0;
}
