#include <Windows.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <TlHelp32.h>
#include <fstream>
#include <vector>

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
typedef PVOID (*ExAllocatePoolFn)(POOL_TYPE PoolType, SIZE_T NumberOfBytes);
typedef VOID (*ExFreePoolFn)(PVOID P);

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
    
    // Write physical memory using GDRV vulnerability
    bool WritePhysicalMemory(uint64_t physAddress, const void* buffer, size_t size) {
        if (hDevice == INVALID_HANDLE_VALUE) return false;
        
        GDRV_MEMORY_WRITE writeRequest = { 0 };
        writeRequest.Address = physAddress;
        writeRequest.Length = size;
        writeRequest.Buffer = (UINT64)buffer;
        
        DWORD bytesReturned = 0;
        return DeviceIoControl(
            hDevice,
            GDRV_IOCTL_WRITE_MEMORY,
            &writeRequest,
            sizeof(writeRequest),
            NULL,
            0,
            &bytesReturned,
            NULL
        );
    }

    // Find kernel function address
    uint64_t FindKernelFunction(const char* functionName) {
        HMODULE ntoskrnl = LoadLibraryA("ntoskrnl.exe");
        if (!ntoskrnl) return 0;

        uint64_t functionRva = (uint64_t)GetProcAddress(ntoskrnl, functionName) - (uint64_t)ntoskrnl;
        FreeLibrary(ntoskrnl);

        return ntoskrnlBase + functionRva;
    }
    
    // Execute shellcode in kernel
    bool ExecuteKernelShellcode(const void* shellcode, size_t size) {
        // Allocate memory for shellcode
        uint64_t shellcodeAddr = AllocateKernelMemory(size);
        if (!shellcodeAddr) return false;

        // Write shellcode
        if (!WritePhysicalMemory(shellcodeAddr, shellcode, size)) {
            std::cerr << "[-] Failed to write shellcode" << std::endl;
            return false;
        }

        // Create shellcode to jump to our shellcode
        uint8_t jumpShellcode[] = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, shellcodeAddr
            0xFF, 0xE0                                                    // jmp rax
        };
        *(uint64_t*)(jumpShellcode + 2) = shellcodeAddr;

        // Write and execute jump shellcode
        uint64_t jumpAddr = AllocateKernelMemory(sizeof(jumpShellcode));
        if (!jumpAddr || !WritePhysicalMemory(jumpAddr, jumpShellcode, sizeof(jumpShellcode))) {
            std::cerr << "[-] Failed to write jump shellcode" << std::endl;
            return false;
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

        // Find required kernel functions
        exAllocatePoolAddress = FindKernelFunction("ExAllocatePool");
        if (!exAllocatePoolAddress) {
            std::cerr << "[-] Failed to find ExAllocatePool" << std::endl;
            return 0;
        }
        std::cout << "[+] Found ExAllocatePool at 0x" << std::hex << exAllocatePoolAddress << std::dec << std::endl;

        exFreePoolAddress = FindKernelFunction("ExFreePool");
        if (!exFreePoolAddress) {
            std::cerr << "[-] Failed to find ExFreePool" << std::endl;
            return 0;
        }
        std::cout << "[+] Found ExFreePool at 0x" << std::hex << exFreePoolAddress << std::dec << std::endl;

        return ntoskrnlBase;
    }
    
    // Allocate kernel memory using ExAllocatePool
    uint64_t AllocateKernelMemory(size_t size) {
        // Create shellcode to call ExAllocatePool
        KernelShellcode shellcode = {
            0x51,                   // push rcx
            0x52,                   // push rdx
            0x41, 0x50,            // push r8
            0x41, 0x51,            // push r9
            0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28
            0x48, 0xB9              // mov rcx, NonPagedPool (0)
        };
        *(uint64_t*)((uint8_t*)&shellcode + 12) = 0; // NonPagedPool
        
        // Set size parameter
        shellcode.movRdx[0] = 0x48;  // mov rdx, size
        shellcode.movRdx[1] = 0xBA;
        *(uint64_t*)(&shellcode.movRdx[2]) = size;
        
        // Call ExAllocatePool
        shellcode.callRax[0] = 0xFF;
        shellcode.callRax[1] = 0xD0;
        
        // Restore stack
        shellcode.addRsp28h = 0x48;
        shellcode.popR9 = 0x41;
        shellcode.popR8 = 0x41;
        shellcode.popRdx = 0x5A;
        shellcode.popRcx = 0x59;
        shellcode.ret = 0xC3;

        // Execute shellcode
        uint64_t shellcodeAddr = AllocateKernelMemory(sizeof(KernelShellcode));
        if (!shellcodeAddr || !WritePhysicalMemory(shellcodeAddr, &shellcode, sizeof(KernelShellcode))) {
            std::cerr << "[-] Failed to write allocation shellcode" << std::endl;
            return 0;
        }

        // Get allocated address
        uint64_t allocatedAddress = 0;
        if (!ReadPhysicalMemory(shellcodeAddr + offsetof(KernelShellcode, ret) + 1, &allocatedAddress, sizeof(allocatedAddress))) {
            std::cerr << "[-] Failed to read allocated address" << std::endl;
            return 0;
        }

        // Zero the memory
        std::vector<uint8_t> zeroBuffer(size, 0);
        if (!WritePhysicalMemory(allocatedAddress, zeroBuffer.data(), size)) {
            std::cerr << "[-] Failed to zero allocated memory" << std::endl;
            return 0;
        }

        std::cout << "[+] Allocated " << size << " bytes at 0x" << std::hex << allocatedAddress << std::dec << std::endl;
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
        KernelShellcode entryShellcode = {
            0x51,                   // push rcx
            0x52,                   // push rdx
            0x41, 0x50,            // push r8
            0x41, 0x51,            // push r9
            0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28
            0x48, 0xB9              // mov rcx, driverObjectAddr
        };
        *(uint64_t*)((uint8_t*)&entryShellcode + 12) = driverObjectAddr;
        
        // Set registry path parameter
        entryShellcode.movRdx[0] = 0x48;  // mov rdx, registryPathAddr
        entryShellcode.movRdx[1] = 0xBA;
        *(uint64_t*)(&entryShellcode.movRdx[2]) = registryPathAddr;
        
        // Call entry point
        entryShellcode.callRax[0] = 0xFF;
        entryShellcode.callRax[1] = 0xD0;
        
        // Restore stack
        entryShellcode.addRsp28h = 0x48;
        entryShellcode.popR9 = 0x41;
        entryShellcode.popR8 = 0x41;
        entryShellcode.popRdx = 0x5A;
        entryShellcode.popRcx = 0x59;
        entryShellcode.ret = 0xC3;

        // Execute entry point
        if (!ExecuteKernelShellcode(&entryShellcode, sizeof(entryShellcode))) {
            std::cerr << "[-] Failed to execute driver entry point" << std::endl;
            return false;
        }
        
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
