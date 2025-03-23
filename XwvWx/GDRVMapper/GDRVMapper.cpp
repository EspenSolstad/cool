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
        
        // Find usable memory for shellcode
        uint64_t shellcodeAddr = FindUsableKernelMemory(size);
        if (!shellcodeAddr) {
            std::cerr << "[-] Failed to find memory for shellcode" << std::endl;
            return false;
        }

        // Write shellcode with retry
        std::cout << "[*] Writing shellcode to 0x" << std::hex << shellcodeAddr << std::dec << std::endl;
        if (!WritePhysicalMemory(shellcodeAddr, shellcode, size)) {
            std::cerr << "[-] Failed to write shellcode after all attempts" << std::endl;
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

        // Find space for result
        uint64_t resultAddr = FindUsableKernelMemory(8);  // Space for uint64_t
        if (!resultAddr) {
            std::cerr << "[-] Failed to find memory for result" << std::endl;
            return false;
        }
        *(uint64_t*)(jumpShellcode + 14) = resultAddr;

        // Find space for jump shellcode
        uint64_t jumpAddr = FindUsableKernelMemory(sizeof(jumpShellcode));
        if (!jumpAddr) {
            std::cerr << "[-] Failed to find memory for jump shellcode" << std::endl;
            return false;
        }

        std::cout << "[*] Writing jump shellcode to 0x" << std::hex << jumpAddr << std::dec << std::endl;
        if (!WritePhysicalMemory(jumpAddr, jumpShellcode, sizeof(jumpShellcode))) {
            std::cerr << "[-] Failed to write jump shellcode" << std::endl;
            return false;
        }

        // Execute shellcode
        uint8_t execShellcode[] = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, jumpAddr
            0xFF, 0xE0                                                    // jmp rax
        };
        *(uint64_t*)(execShellcode + 2) = jumpAddr;

        uint64_t execAddr = FindUsableKernelMemory(sizeof(execShellcode));
        if (!execAddr) {
            std::cerr << "[-] Failed to find memory for exec shellcode" << std::endl;
            return false;
        }

        std::cout << "[*] Writing exec shellcode to 0x" << std::hex << execAddr << std::dec << std::endl;
        if (!WritePhysicalMemory(execAddr, execShellcode, sizeof(execShellcode))) {
            std::cerr << "[-] Failed to write exec shellcode" << std::endl;
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
    
    // Constants for memory search
    static constexpr uint64_t SEARCH_RANGE_INCREMENT = 64 * 1024 * 1024; // 64MB increments
    static constexpr uint64_t MAX_SEARCH_RANGE = 16ULL * 1024 * 1024 * 1024; // 16GB max
    static constexpr int MAX_RETRY_ATTEMPTS = 5;
    static constexpr uint64_t RETRY_OFFSETS[] = {0x1000, 0x2000, 0x4000, 0x8000, 0x10000};

    // Find usable kernel memory region with enhanced search algorithm
    uint64_t FindUsableKernelMemory(size_t size) {
        if (kernelBase == 0) {
            // Initialize kernel base and size if not done yet
            HMODULE ntoskrnl = LoadLibraryA("ntoskrnl.exe");
            if (!ntoskrnl) return 0;

            // Get psapi.dll handle
            HMODULE psapi = LoadLibraryA("psapi.dll");
            if (!psapi) {
                FreeLibrary(ntoskrnl);
                return 0;
            }

            // Get GetModuleInformation function
            auto getModInfo = (GetModuleInformationFn)GetProcAddress(psapi, "GetModuleInformation");
            if (!getModInfo) {
                FreeLibrary(psapi);
                FreeLibrary(ntoskrnl);
                return 0;
            }

            MODULEINFO modInfo;
            if (!getModInfo(GetCurrentProcess(), ntoskrnl, &modInfo, sizeof(modInfo))) {
                FreeLibrary(psapi);
                FreeLibrary(ntoskrnl);
                return 0;
            }

            FreeLibrary(psapi);

            kernelBase = ntoskrnlBase;
            kernelSize = modInfo.SizeOfImage;
            FreeLibrary(ntoskrnl);
        }

        // Align size to allocation granularity
        size = (size + ALLOCATION_GRANULARITY - 1) & ~(ALLOCATION_GRANULARITY - 1);

        // Try multiple search ranges
        for (uint64_t searchRange = SEARCH_RANGE_INCREMENT; searchRange <= MAX_SEARCH_RANGE; searchRange += SEARCH_RANGE_INCREMENT) {
            uint64_t startAddr = lastAllocationEnd ? lastAllocationEnd : kernelBase;
            uint64_t endAddr = kernelBase + searchRange;

            // Align start address
            startAddr = (startAddr + ALLOCATION_GRANULARITY - 1) & ~(ALLOCATION_GRANULARITY - 1);

            std::cout << "[*] Searching memory range 0x" << std::hex << startAddr << " - 0x" << endAddr << std::dec << std::endl;

            for (uint64_t addr = startAddr; addr < endAddr; addr += ALLOCATION_GRANULARITY) {
                // Try each retry offset
                for (int i = 0; i < MAX_RETRY_ATTEMPTS; i++) {
                    uint64_t testAddr = addr + RETRY_OFFSETS[i];
                    
                    // Test if memory region is usable
                    std::vector<uint8_t> testBuffer(16, 0);
                    if (WritePhysicalMemory(testAddr, testBuffer.data(), testBuffer.size())) {
                        // Verify we can read back what we wrote
                        std::vector<uint8_t> readBuffer(16);
                        if (ReadPhysicalMemory(testAddr, readBuffer.data(), readBuffer.size()) &&
                            memcmp(testBuffer.data(), readBuffer.data(), testBuffer.size()) == 0) {
                            
                            // Found usable memory region
                            lastAllocationEnd = testAddr + size;
                            std::cout << "[+] Found usable memory at 0x" << std::hex << testAddr << std::dec 
                                    << " (attempt " << i + 1 << ")" << std::endl;
                            return testAddr;
                        }
                    }
                }

                // Implement dynamic skipping based on failure patterns
                if ((addr - startAddr) >= (4 * 1024 * 1024)) { // After 4MB of searching
                    uint64_t skip = ((addr - startAddr) / 4); // Skip by 1/4 of searched distance
                    addr += skip;
                    std::cout << "[*] Skipping ahead by 0x" << std::hex << skip << std::dec << " bytes" << std::endl;
                }
            }
        }

        std::cerr << "[-] Failed to find usable memory after exhaustive search" << std::endl;
        return 0;
    }

    // Allocate kernel memory using dynamic allocation strategy
    uint64_t AllocateKernelMemory(size_t size) {
        // Try to find usable memory region
        uint64_t addr = FindUsableKernelMemory(size);
        if (!addr) {
            std::cerr << "[-] Failed to find usable kernel memory region" << std::endl;
            return 0;
        }

        std::cout << "[*] Found usable memory region at 0x" << std::hex << addr << std::dec << std::endl;
        
        // Try to allocate using ExAllocatePool2 first
        uint8_t shellcode[] = {
            0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00,             // mov rcx, NonPagedPoolNx (4)
            0x48, 0xBA, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,             // mov rdx, size
            0x49, 0xB8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,             // mov r8, tag
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,             // mov rax, ExAllocatePool2
            0xFF, 0xD0,                         // call rax
            0x48, 0xA3, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,             // mov [resultAddr], rax
            0x48, 0x83, 0xC4, 0x28,             // add rsp, 0x28
            0xC3                                // ret
        };

        // Find space for result
        uint64_t resultAddr = FindUsableKernelMemory(8);  // Space for uint64_t
        if (!resultAddr) {
            std::cerr << "[-] Failed to find memory for result" << std::endl;
            return 0;
        }
        
        // Set up parameters for ExAllocatePool2
            // Use random pool tag from our set
            ULONG poolTag = POOL_TAGS[rand() % POOL_TAGS_COUNT];
            *(uint64_t*)(shellcode + 6) = 4;  // NonPagedPoolNx
            *(uint64_t*)(shellcode + 16) = size;
            *(uint64_t*)(shellcode + 26) = poolTag;  // Random pool tag
        *(uint64_t*)(shellcode + 36) = exAllocatePoolAddress;
        *(uint64_t*)(shellcode + 48) = resultAddr;
        
        // Find space for shellcode
        uint64_t shellcodeAddr = FindUsableKernelMemory(sizeof(shellcode));
        if (!shellcodeAddr) {
            std::cerr << "[-] Failed to find memory for shellcode" << std::endl;
            return 0;
        }
        
        std::cout << "[*] Writing allocation shellcode to 0x" << std::hex << shellcodeAddr << std::dec << std::endl;
        if (!WritePhysicalMemory(shellcodeAddr, shellcode, sizeof(shellcode))) {
            std::cerr << "[-] Failed to write allocation shellcode" << std::endl;
            return 0;
        }
        
        // Execute shellcode and get result
        uint64_t allocatedAddress = 0;
        if (!ExecuteKernelShellcode(shellcode, sizeof(shellcode), &allocatedAddress)) {
            std::cerr << "[-] Failed to execute allocation shellcode" << std::endl;
            return 0;
        }

        if (!allocatedAddress) {
            std::cerr << "[-] ExAllocatePool2 returned NULL" << std::endl;
            return 0;
        }
        
        // Zero the allocated memory
        std::vector<uint8_t> zeroBuffer(size, 0);
        std::cout << "[*] Zeroing allocated memory at 0x" << std::hex << allocatedAddress << std::dec << std::endl;
        if (!WritePhysicalMemory(allocatedAddress, zeroBuffer.data(), size)) {
            std::cerr << "[-] Failed to zero allocated memory" << std::endl;
            return 0;
        }
        
        std::cout << "[+] Successfully allocated and zeroed " << size << " bytes at 0x" << std::hex << allocatedAddress << std::dec << std::endl;
        return allocatedAddress;
    }
    
    // Map a driver into kernel memory
    bool MapDriver(const std::string& driverPath, uint64_t& baseAddress) {
        std::ifstream file(driverPath, std::ios::binary | std::ios::ate);
        if (!file) {
            std::cerr << "[-] Failed to open driver file: " << driverPath << std::endl;
            return false;
        }
        
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        std::vector<char> buffer(size);
        if (!file.read(buffer.data(), size)) {
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
        
        // Allocate kernel memory for the driver
        uint64_t imageSize = ntHeaders->OptionalHeader.SizeOfImage;
        uint64_t mappedImage = AllocateKernelMemory(imageSize);
        if (!mappedImage) {
            std::cerr << "[-] Failed to allocate kernel memory" << std::endl;
            return false;
        }
        
        // Copy sections
        auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            uint64_t sectionAddress = mappedImage + sectionHeader[i].VirtualAddress;
            uint64_t sectionSize = sectionHeader[i].SizeOfRawData;
            uint64_t sectionData = reinterpret_cast<uint64_t>(buffer.data()) + sectionHeader[i].PointerToRawData;
            
            if (sectionSize > 0) {
                std::cout << "[*] Writing section " << i << " to 0x" << std::hex << sectionAddress << std::dec << std::endl;
                if (!WritePhysicalMemory(sectionAddress, reinterpret_cast<void*>(sectionData), sectionSize)) {
                    std::cerr << "[-] Failed to write section data" << std::endl;
                    return false;
                }
            }
        }
        
        // Process relocations
        uint64_t relocationDelta = mappedImage - ntHeaders->OptionalHeader.ImageBase;
        if (relocationDelta != 0 && ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
            std::cout << "[+] Processing relocations for delta 0x" << std::hex << relocationDelta << std::dec << std::endl;
            
            auto relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            uint64_t relocationTable = mappedImage + relocDir.VirtualAddress;
            
            IMAGE_BASE_RELOCATION relocBlock;
            uint64_t relocOffset = 0;
            
            while (relocOffset < relocDir.Size) {
                // Read relocation block
                if (!ReadPhysicalMemory(relocationTable + relocOffset, &relocBlock, sizeof(relocBlock))) {
                    std::cerr << "[-] Failed to read relocation block" << std::endl;
                    return false;
                }
                
                uint64_t numEntries = (relocBlock.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                std::vector<WORD> entries(numEntries);
                
                // Read relocation entries
                if (!ReadPhysicalMemory(
                    relocationTable + relocOffset + sizeof(IMAGE_BASE_RELOCATION),
                    entries.data(),
                    numEntries * sizeof(WORD))) {
                    std::cerr << "[-] Failed to read relocation entries" << std::endl;
                    return false;
                }
                
                // Process each entry
                for (WORD entry : entries) {
                    if ((entry >> 12) == IMAGE_REL_BASED_DIR64) {
                        uint64_t offset = relocBlock.VirtualAddress + (entry & 0xFFF);
                        uint64_t address = 0;
                        
                        // Read address to relocate
                        if (!ReadPhysicalMemory(mappedImage + offset, &address, sizeof(address))) {
                            std::cerr << "[-] Failed to read relocation address" << std::endl;
                            return false;
                        }
                        
                        // Apply relocation
                        address += relocationDelta;
                        
                        // Write relocated address
                        if (!WritePhysicalMemory(mappedImage + offset, &address, sizeof(address))) {
                            std::cerr << "[-] Failed to write relocated address" << std::endl;
                            return false;
                        }
                    }
                }
                
                relocOffset += relocBlock.SizeOfBlock;
            }
        }
        
        // Execute driver entry point
        uint64_t entryPoint = mappedImage + ntHeaders->OptionalHeader.AddressOfEntryPoint;
        
        std::cout << "[+] Driver mapped at 0x" << std::hex << mappedImage << std::dec << std::endl;
        std::cout << "[+] Entry point at 0x" << std::hex << entryPoint << std::dec << std::endl;
        
        // Create driver object
        DRIVER_OBJECT driverObject = { 0 };
        uint64_t driverObjectAddr = AllocateKernelMemory(sizeof(DRIVER_OBJECT));
        if (!driverObjectAddr || !WritePhysicalMemory(driverObjectAddr, &driverObject, sizeof(DRIVER_OBJECT))) {
            std::cerr << "[-] Failed to create driver object" << std::endl;
            return false;
        }
        
        // Create registry path
        UNICODE_STRING registryPath = { 0 };
        uint64_t registryPathAddr = AllocateKernelMemory(sizeof(UNICODE_STRING));
        if (!registryPathAddr || !WritePhysicalMemory(registryPathAddr, &registryPath, sizeof(UNICODE_STRING))) {
            std::cerr << "[-] Failed to create registry path" << std::endl;
            return false;
        }
        
        // Create shellcode for driver entry
        uint8_t entryShellcode[] = {
            0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,             // mov rcx, driverObjectAddr
            0x48, 0xBA, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,             // mov rdx, registryPathAddr
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,             // mov rax, entryPoint
            0xFF, 0xD0,                         // call rax
            0x48, 0x83, 0xC4, 0x28,             // add rsp, 0x28
            0xC3                                // ret
        };

        // Set up parameters
        *(uint64_t*)(entryShellcode + 6) = driverObjectAddr;
        *(uint64_t*)(entryShellcode + 16) = registryPathAddr;
        *(uint64_t*)(entryShellcode + 26) = entryPoint;

        // Find space for result
        uint64_t resultAddr = FindUsableKernelMemory(8);  // Space for uint64_t
        if (!resultAddr) {
            std::cerr << "[-] Failed to find memory for result" << std::endl;
            return 0;
        }

        // Add result storage to shellcode
        uint8_t resultShellcode[] = {
            0x48, 0xA3, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00              // mov [resultAddr], rax
        };
        *(uint64_t*)(resultShellcode + 2) = resultAddr;

        // Combine shellcodes
        std::vector<uint8_t> fullShellcode;
        fullShellcode.insert(fullShellcode.end(), entryShellcode, entryShellcode + sizeof(entryShellcode));
        fullShellcode.insert(fullShellcode.end(), resultShellcode, resultShellcode + sizeof(resultShellcode));

        // Execute entry point and get result
        uint64_t entryResult = 0;
        if (!ExecuteKernelShellcode(fullShellcode.data(), fullShellcode.size(), &entryResult)) {
            std::cerr << "[-] Failed to execute driver entry point" << std::endl;
            return false;
        }

        if (entryResult != 0) {
            std::cerr << "[-] Driver entry point returned error 0x" << std::hex << entryResult << std::dec << std::endl;
            return false;
        }

        std::cout << "[+] Driver entry point executed successfully" << std::endl;
        
        baseAddress = mappedImage;
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
        
        if (!MapDriver(driverPath, baseAddress)) {
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
