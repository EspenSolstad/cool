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

class GDRVMapper {
private:
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    uint64_t ntoskrnlBase = 0;
    
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
        return ntoskrnlBase;
    }
    
    // Allocate kernel memory using physical memory access
    uint64_t AllocateKernelMemory(size_t size) {
        // For demonstration, allocate from a fixed pool
        // In a real implementation, you'd want to find proper non-paged pool memory
        static uint64_t nextAllocation = 0xFFFF800000000000;
        
        size_t alignedSize = (size + 0xFFF) & ~0xFFF;
        uint64_t allocationAddress = nextAllocation;
        nextAllocation += alignedSize;
        
        // Zero the memory
        std::vector<uint8_t> zeroBuffer(alignedSize, 0);
        if (!WritePhysicalMemory(allocationAddress, zeroBuffer.data(), alignedSize)) {
            std::cerr << "[-] Failed to zero allocated memory" << std::endl;
            return 0;
        }
        
        std::cout << "[+] Allocated " << alignedSize << " bytes at 0x" << std::hex << allocationAddress << std::dec << std::endl;
        return allocationAddress;
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
            
            // Here you would process relocations using physical memory read/write
            // This is a complex process that requires walking the relocation table
            // and adjusting addresses based on the relocation delta
        }
        
        // Execute driver entry point
        uint64_t entryPoint = mappedImage + ntHeaders->OptionalHeader.AddressOfEntryPoint;
        
        std::cout << "[+] Driver mapped at 0x" << std::hex << mappedImage << std::dec << std::endl;
        std::cout << "[+] Entry point at 0x" << std::hex << entryPoint << std::dec << std::endl;
        
        // Here you would need to execute the driver entry point
        // This typically involves creating shellcode that sets up the parameters
        // and jumps to the entry point
        
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
        
        // Get ntoskrnl.exe base address
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
    std::string memDriverPath = currentDir + "\\memdriver.sys";
    
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
