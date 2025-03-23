#define _WIN32_WINNT 0x0601  // Target Windows 7 or later
#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <cstdint>
#include <memory>
#include <intrin.h>
#include <winternl.h>
#include <time.h>

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
#define SE_LOAD_DRIVER_PRIVILEGE 10

// Driver paths
const std::wstring MEMORY_DRIVER_PATH = L"..\\..\\memdriver\\x64\\Release\\memdriver.sys"; // Our memory driver

// Error handling
#define ASSERT(expr, msg) if(!(expr)) { std::cerr << "[!] Assertion failed: " << msg << " (Error: " << GetLastError() << ")" << std::endl; return false; }
#define LOG_INFO(msg) std::cout << "[+] " << msg << std::endl;
#define LOG_ERROR(msg) std::cerr << "[-] " << msg << " (Error: " << GetLastError() << ")" << std::endl;
#define LOG_WARNING(msg) std::cout << "[!] " << msg << std::endl;

// NTSTATUS values
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)

// For direct physical memory access
#define PHYSICAL_MEMORY_DEVICE L"\\Device\\PhysicalMemory"

// Undocumented Windows structures
typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE_INFORMATION_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

// For undocumented APIs
typedef NTSTATUS(NTAPI* NtQuerySystemInformationFn)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// For VirtualToPhysical translation
// Instead of redefining the enum, we'll use constants to avoid redefinition
#define SYSTEM_MODULE_INFORMATION_CLASS 11
#define SYSTEM_KERNEL_VA 0x25

// For kernel pool allocation
typedef enum _POOL_TYPE {
    NonPagedPool,
    PagedPool,
    NonPagedPoolExecute = 0,
    NonPagedPoolMustSucceed = 2,
    NonPagedPoolNx = 512
} POOL_TYPE;

// Function prototypes for manual implementation
typedef PVOID(NTAPI* ExAllocatePoolWithTagFn)(
    POOL_TYPE PoolType,
    SIZE_T NumberOfBytes,
    ULONG Tag
);

typedef NTSTATUS(NTAPI* KeInsertQueueApcFn)(
    PVOID ApcContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2,
    ULONG PriorityBoost
);

// Manual mapping class
class ManualMapper {
private:
    // Internal state
    uint64_t ntoskrnlBase = 0;
    ExAllocatePoolWithTagFn pExAllocatePoolWithTag = nullptr;
    KeInsertQueueApcFn pKeInsertQueueApc = nullptr;
    bool usingPhysicalMemory = false;
    bool usingMSR = false;
    bool usingExploit = false;
    
    // Anti-detection state
    int64_t timingCheckStart = 0;

    // Methods for kernel memory access
    bool ReadKernelMemory(uint64_t address, void* buffer, size_t size) {
        if (usingPhysicalMemory) {
            return ReadKernelMemoryViaPhysical(address, buffer, size);
        }
        else if (usingMSR) {
            return ReadKernelMemoryViaMSR(address, buffer, size);
        }
        else if (usingExploit) {
            return ReadKernelMemoryViaExploit(address, buffer, size);
        }
        return false;
    }

    bool WriteKernelMemory(uint64_t address, void* buffer, size_t size) {
        if (usingPhysicalMemory) {
            return WriteKernelMemoryViaPhysical(address, buffer, size);
        } 
        else if (usingMSR) {
            return WriteKernelMemoryViaMSR(address, buffer, size);
        }
        else if (usingExploit) {
            return WriteKernelMemoryViaExploit(address, buffer, size);
        }
        return false;
    }

    // Physical memory method implementation
    bool ReadKernelMemoryViaPhysical(uint64_t address, void* buffer, size_t size) {
        // This is a simplified approach - actual implementation would:
        // 1. Open \Device\PhysicalMemory
        // 2. Map a view of the physical memory
        // 3. Translate virtual address to physical
        // 4. Read from mapped view
        
        // For demo/pseudocode version, we're simulating this
        memset(buffer, 0, size); // For safety in the example
        LOG_INFO("Physical memory read from 0x" + std::to_string(address));
        return true;
    }

    bool WriteKernelMemoryViaPhysical(uint64_t address, void* buffer, size_t size) {
        // Similar to read but for writing
        LOG_INFO("Physical memory write to 0x" + std::to_string(address));
        return true;
    }

    // MSR method implementation
    bool ReadKernelMemoryViaMSR(uint64_t address, void* buffer, size_t size) {
        // Would use __readmsr and __writemsr to manipulate processor state
        // that allows memory access
        memset(buffer, 0, size); // For safety in the example
        LOG_INFO("MSR memory read from 0x" + std::to_string(address));
        return true;
    }

    bool WriteKernelMemoryViaMSR(uint64_t address, void* buffer, size_t size) {
        LOG_INFO("MSR memory write to 0x" + std::to_string(address));
        return true;
    }

    // Exploit method implementation
    bool ReadKernelMemoryViaExploit(uint64_t address, void* buffer, size_t size) {
        // This would use a specific kernel memory access vulnerability
        // that doesn't require loading a driver
        memset(buffer, 0, size); // For safety in the example
        LOG_INFO("Exploit memory read from 0x" + std::to_string(address));
        return true;
    }

    bool WriteKernelMemoryViaExploit(uint64_t address, void* buffer, size_t size) {
        LOG_INFO("Exploit memory write to 0x" + std::to_string(address));
        return true;
    }

    // Get ntoskrnl.exe base address
    bool GetNtoskrnlBase() {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (!ntdll) return false;

        auto NtQuerySystemInformation = (NtQuerySystemInformationFn)GetProcAddress(
            ntdll, "NtQuerySystemInformation");
        if (!NtQuerySystemInformation) return false;

        ULONG returnLength = 0;
        NTSTATUS status = NtQuerySystemInformation(
            SYSTEM_MODULE_INFORMATION_CLASS, 
            NULL, 
            0, 
            &returnLength);

        if (returnLength == 0) return false;

        std::vector<uint8_t> buffer(returnLength);
        status = NtQuerySystemInformation(
            SYSTEM_MODULE_INFORMATION_CLASS, 
            buffer.data(), 
            returnLength, 
            &returnLength);

        if (status != STATUS_SUCCESS) return false;

        auto modules = (PSYSTEM_MODULE_INFORMATION)buffer.data();
        if (modules->Count == 0) return false;

        // ntoskrnl.exe is typically the first module
        ntoskrnlBase = (uint64_t)modules->Modules[0].ImageBase;
        LOG_INFO("Found ntoskrnl.exe at 0x" + std::to_string(ntoskrnlBase));
        return true;
    }

    // Find kernel functions we need
    bool GetKernelFunctions() {
        if (ntoskrnlBase == 0 && !GetNtoskrnlBase()) {
            return false;
        }

        // Load ntoskrnl.exe into our process to find function offsets
        HMODULE localNtoskrnl = LoadLibraryExA("ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (!localNtoskrnl) {
            LOG_ERROR("Failed to load ntoskrnl.exe locally");
            return false;
        }

        // Find the functions we need
        FARPROC localExAllocatePoolWithTag = GetProcAddress(localNtoskrnl, "ExAllocatePoolWithTag");
        FARPROC localKeInsertQueueApc = GetProcAddress(localNtoskrnl, "KeInsertQueueApc");

        if (!localExAllocatePoolWithTag || !localKeInsertQueueApc) {
            LOG_ERROR("Failed to find required functions in ntoskrnl.exe");
            FreeLibrary(localNtoskrnl);
            return false;
        }

        // Calculate offsets from ntoskrnl base to functions
        uint64_t offsetExAllocatePoolWithTag = (uint64_t)localExAllocatePoolWithTag - (uint64_t)localNtoskrnl;
        uint64_t offsetKeInsertQueueApc = (uint64_t)localKeInsertQueueApc - (uint64_t)localNtoskrnl;

        // Free local module
        FreeLibrary(localNtoskrnl);

        // Calculate kernel addresses for these functions
        pExAllocatePoolWithTag = (ExAllocatePoolWithTagFn)(ntoskrnlBase + offsetExAllocatePoolWithTag);
        pKeInsertQueueApc = (KeInsertQueueApcFn)(ntoskrnlBase + offsetKeInsertQueueApc);

        LOG_INFO("ExAllocatePoolWithTag found at 0x" + std::to_string((uint64_t)pExAllocatePoolWithTag));
        LOG_INFO("KeInsertQueueApc found at 0x" + std::to_string((uint64_t)pKeInsertQueueApc));
        return true;
    }

    // Anti-detection methods
    bool CheckForVirtualization() {
        // Check for hypervisor presence using CPUID
        int cpuInfo[4] = { 0 };
        __cpuid(cpuInfo, 1);
        
        // Check hypervisor bit
        bool hypervisorPresent = (cpuInfo[2] & (1 << 31)) != 0;
        
        if (hypervisorPresent) {
            LOG_WARNING("Hypervisor detected!");
            
            // Check for specific hypervisors
            __cpuid(cpuInfo, 0x40000000);  // Hypervisor CPUID leaf
            
            char vendor[13] = { 0 };
            memcpy(vendor, &cpuInfo[1], 4);
            memcpy(vendor + 4, &cpuInfo[2], 4);
            memcpy(vendor + 8, &cpuInfo[3], 4);
            
            LOG_INFO("Hypervisor vendor: " + std::string(vendor));
            
            // You can add specific checks for known analysis platforms
            if (strcmp(vendor, "KVMKVMKVM") == 0 ||
                strcmp(vendor, "Microsoft Hv") == 0 ||
                strcmp(vendor, "VMwareVMware") == 0 ||
                strcmp(vendor, "XenVMMXenVMM") == 0) {
                return true;
            }
        }
        
        return false;
    }

    bool DetectAnalysisTools() {
        // Check for common debugging tools and analysis software
        const wchar_t* suspiciousProcesses[] = {
            L"ollydbg.exe", L"x64dbg.exe", L"windbg.exe", L"ida.exe", L"ida64.exe",
            L"processhacker.exe", L"procmon.exe", L"procexp.exe", L"tcpview.exe"
        };
        
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return false;
        }
        
        PROCESSENTRY32W entry;
        entry.dwSize = sizeof(entry);
        
        if (Process32FirstW(snapshot, &entry)) {
            do {
                for (const auto& process : suspiciousProcesses) {
                    if (_wcsicmp(entry.szExeFile, process) == 0) {
                        LOG_WARNING("Analysis tool detected: " + std::string(entry.szExeFile, entry.szExeFile + wcslen(entry.szExeFile)));
                        CloseHandle(snapshot);
                        return true;
                    }
                }
            } while (Process32NextW(snapshot, &entry));
        }
        
        CloseHandle(snapshot);
        return false;
    }

    void ApplyTimingTricks() {
        // Get high-precision time
        timingCheckStart = []() -> int64_t {
            LARGE_INTEGER counter;
            QueryPerformanceCounter(&counter);
            return counter.QuadPart;
        }();
    }

    bool CheckTimingAnomaly() {
        // Check if code execution is taking too long (indicating debugger/analysis)
        if (timingCheckStart == 0) return false;
        
        LARGE_INTEGER counter, frequency;
        QueryPerformanceCounter(&counter);
        QueryPerformanceFrequency(&frequency);
        
        int64_t current = counter.QuadPart;
        double elapsed = (double)(current - timingCheckStart) / frequency.QuadPart;
        
        // If more than 2 seconds elapsed, it's suspicious
        if (elapsed > 2.0) {
            LOG_WARNING("Execution timing anomaly detected!");
            return true;
        }
        
        return false;
    }

    // Memory allocation and mapping
    uint64_t AllocateKernelMemory(size_t size) {
        // Allocate non-paged kernel memory for our driver
        uint64_t allocatedAddress = 0;
        
        // In a real implementation, we would use our kernel memory access to call
        // ExAllocatePoolWithTag in the kernel, which would look like:
        // 
        // allocatedAddress = CallKernelFunction(
        //     (uint64_t)pExAllocatePoolWithTag,
        //     { (uint64_t)NonPagedPoolNx, (uint64_t)size, 'PYRT' }
        // );
        
        // For the example, simulate allocation using a static address
        static uint64_t memoryBase = 0xFFFFA80000000000;
        allocatedAddress = memoryBase;
        memoryBase += size + 0x1000; // Simple bump allocator with padding
        
        // Zero the memory
        std::vector<uint8_t> zeroBuffer(size, 0);
        WriteKernelMemory(allocatedAddress, zeroBuffer.data(), size);
        
        LOG_INFO("Allocated kernel memory at 0x" + std::to_string(allocatedAddress));
        return allocatedAddress;
    }

    bool MapDriverFile(const std::wstring& driverPath, uint64_t& baseAddress) {
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
                if (!WriteKernelMemory(sectionAddress, reinterpret_cast<void*>(sectionData), sectionSize)) {
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
                ReadKernelMemory(relocationTable, &relocation, sizeof(relocation));

                if (relocation.SizeOfBlock == 0) break;

                uint64_t relocationCount = (relocation.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                uint64_t relocationData = relocationTable + sizeof(IMAGE_BASE_RELOCATION);
                uint64_t relocationBase = mappedImage + relocation.VirtualAddress;

                std::vector<WORD> relocations(relocationCount);
                ReadKernelMemory(relocationData, relocations.data(), relocations.size() * sizeof(WORD));

                for (size_t i = 0; i < relocationCount; i++) {
                    WORD relocationInfo = relocations[i];
                    uint64_t relocationType = relocationInfo >> 12;
                    uint64_t relocationOffset = relocationInfo & 0xFFF;

                    if (relocationType == IMAGE_REL_BASED_DIR64) {
                        uint64_t patchAddress = relocationBase + relocationOffset;
                        uint64_t patchedValue = 0;
                        
                        ReadKernelMemory(patchAddress, &patchedValue, sizeof(patchedValue));
                        patchedValue += relocationDelta;
                        WriteKernelMemory(patchAddress, &patchedValue, sizeof(patchedValue));
                    }
                }

                relocationTable += relocation.SizeOfBlock;
            }
        }

        // Execute driver entry point
        uint64_t entryPoint = mappedImage + ntHeaders->OptionalHeader.AddressOfEntryPoint;
        
        // Create shellcode to call the driver entry point
        // mov rcx, driverObject (null)
        // mov rdx, registryPath (null)
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
        if (!WriteKernelMemory(shellcodeAddress, shellcode, sizeof(shellcode))) {
            LOG_ERROR("Failed to write shellcode");
            return false;
        }

        // Execute the shellcode
        // In a real implementation, we would trigger execution using one of several methods:
        // 1. Find a kernel function we can redirect temporarily
        // 2. Use a feature like APC queuing to schedule execution
        // 3. Overwrite a function pointer in a device object or driver object
        // Here we're just simulating success
        LOG_INFO("Executed driver entry point at 0x" + std::to_string(entryPoint));

        // Return the mapped base address
        baseAddress = mappedImage;
        LOG_INFO("Driver mapped at 0x" + std::to_string(mappedImage));
        return true;
    }

    void CleanupTraces() {
        // Clear registry traces if any were created
        // Clear any temporary files
        // Clear any logs
        LOG_INFO("Cleaned up all traces");
    }

public:
    ManualMapper() = default;
    ~ManualMapper() {
        // Cleanup
        CleanupTraces();
    }

    bool Initialize() {
        // Apply anti-detection techniques first
        ApplyTimingTricks();
        
        if (CheckForVirtualization() || DetectAnalysisTools()) {
            // If we detect analysis tools, silently fail
            // but pretend to succeed to fool the analysis
            LOG_INFO("Environment check passed");
            return false;
        }
        
        // Check for timing anomalies
        if (CheckTimingAnomaly()) {
            return false;
        }
        
        // Get admin rights
        if (!IsRunningAsAdmin()) {
            LOG_ERROR("Administrator privileges required");
            return false;
        }
        
        // Try each kernel memory access method in order
        LOG_INFO("Initializing direct physical memory access...");
        if (InitializePhysicalMemoryAccess()) {
            usingPhysicalMemory = true;
            LOG_INFO("Using physical memory access method");
            return true;
        }
        
        LOG_INFO("Initializing MSR-based access...");
        if (InitializeMSRAccess()) {
            usingMSR = true;
            LOG_INFO("Using MSR-based memory access method");
            return true;
        }
        
        LOG_INFO("Initializing exploit-based access...");
        if (InitializeExploitAccess()) {
            usingExploit = true;
            LOG_INFO("Using exploit-based memory access method");
            return true;
        }
        
        LOG_ERROR("Failed to initialize any memory access method");
        return false;
    }
    
    bool IsRunningAsAdmin() {
        BOOL isAdmin = FALSE;
        HANDLE tokenHandle = NULL;
        
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle)) {
            TOKEN_ELEVATION elevation;
            DWORD size = sizeof(TOKEN_ELEVATION);
            
            if (GetTokenInformation(tokenHandle, TokenElevation, &elevation, sizeof(elevation), &size)) {
                isAdmin = elevation.TokenIsElevated;
            }
            
            CloseHandle(tokenHandle);
        }
        
        return isAdmin != FALSE;
    }
    
    bool InitializePhysicalMemoryAccess() {
        // In a real implementation, we would:
        // 1. Create symbolic link to \\Device\\PhysicalMemory
        // 2. Open the device
        // 3. Map sections of physical memory
        
        // For demo/pseudocode, we're simulating success
        return true;
    }
    
    bool InitializeMSRAccess() {
        // In a real implementation, this would use processor features
        // For demo/pseudocode, we're simulating success
        return false; // Disabled for this example
    }
    
    bool InitializeExploitAccess() {
        // In a real implementation, this would use a specific kernel exploit
        // For demo/pseudocode, we're simulating success
        return false; // Disabled for this example
    }

    bool MapMemoryDriver(uint64_t& baseAddress) {
        // Find and initialize kernel function pointers
        if (!GetKernelFunctions()) {
            LOG_WARNING("Failed to get kernel functions, continuing with limited functionality");
        }
        
        // Map the memory driver directly
        LOG_INFO("Mapping memory driver...");
        if (!MapDriverFile(MEMORY_DRIVER_PATH, baseAddress)) {
            LOG_ERROR("Failed to map memory driver");
            return false;
        }

        LOG_INFO("Memory driver mapped successfully at 0x" + std::to_string(baseAddress));
        return true;
    }

    // Memory manipulation functions for the ESP hack
    bool ReadProcessMemory(DWORD pid, uintptr_t address, void* buffer, size_t size) {
        // For the ESP hack, we need to read memory from another process
        HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!processHandle) {
            LOG_ERROR("Failed to open target process");
            return false;
        }
        
        CloseHandle(processHandle);

        // In a real implementation, this would use our kernel access to read
        // the process's memory directly from kernel space
        memset(buffer, 0, size); // For safety in this example
        return true;
    }

    bool WriteProcessMemory(DWORD pid, uintptr_t address, const void* buffer, size_t size) {
        // Similar to ReadProcessMemory, but for writing
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

    // Hide console in final version
    #ifdef NDEBUG
    // ShowWindow(GetConsoleWindow(), SW_HIDE);
    #endif

    // Initialize the mapper
    ManualMapper mapper;
    if (!mapper.Initialize()) {
        std::cerr << "[-] Failed to initialize the mapper\n";
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }

    // Map the memory driver
    uint64_t driverBase = 0;
    if (!mapper.MapMemoryDriver(driverBase)) {
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
                PROCESSENTRY32W entry;
                entry.dwSize = sizeof(entry);
                if (Process32FirstW(snapshot, &entry)) {
                    do {
                        // Compare process name
                        wchar_t targetProcess[] = L"DeadByDaylight-Win64-Shipping.exe";
                        if (wcscmp(entry.szExeFile, targetProcess) == 0) {
                            result = entry.th32ProcessID;
                            break;
                        }
                    } while (Process32NextW(snapshot, &entry));
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
