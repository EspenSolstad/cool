#include <Windows.h>
#include <iostream>
#include <vector>
#include <fstream>
#include "intel_driver.hpp"
#include "kdmapper.hpp"
#include "portable_executable.hpp"
#include "memdriver.hpp"
#include "rwdrv.hpp"
#include "cheat.hpp"

// Save binary to disk
void DropToDisk(const BYTE* data, size_t size, const std::string& name) {
    std::ofstream f(name, std::ios::binary);
    f.write(reinterpret_cast<const char*>(data), size);
    f.close();
    std::cout << "[+] Dropped: " << name << "\n";
}

// Shellcode: mov rax, <entry>; xor rcx, rcx; xor rdx, rdx; call rax; ret
void BuildShellcode(BYTE* shell, ULONGLONG entry) {
    shell[0] = 0x48; shell[1] = 0xB8;
    memcpy(shell + 2, &entry, 8);
    shell[10] = 0x48; shell[11] = 0x31; shell[12] = 0xC9;
    shell[13] = 0x48; shell[14] = 0x31; shell[15] = 0xD2;
    shell[16] = 0xFF; shell[17] = 0xD0;
    shell[18] = 0xC3;
}

int main() {
    std::cout << "[*] UniversalLoader: Fully Integrated Mode\n";

    // Step 1: Load vulnerable driver
    HANDLE dev = intel_driver::Load();
    if (dev == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Failed to load intel driver\n";
        return -1;
    }

    // Step 2: Map memdriver.sys with kdmapper
    std::vector<uint8_t> driver(memdriver, memdriver + memdriver_len);
    if (!kdmapper::MapDriver(dev, driver.data(), 0, 0, false, true,
        kdmapper::AllocationMode::AllocatePool, false, nullptr, nullptr)) {
        std::cerr << "[-] Failed to map memdriver.sys\n";
        intel_driver::Unload(dev);
        return -1;
    }

    std::cout << "[+] memdriver.sys mapped successfully\n";

    // Step 3: Map rwdrv.sys manually
    std::vector<BYTE> rw(rwdrv, rwdrv + rwdrv_len);
    auto rw_nt = portable_executable::GetNtHeaders(rw.data());
    if (!rw_nt) {
        std::cerr << "[-] Invalid PE header in rwdrv.sys\n";
        intel_driver::Unload(dev);
        return -1;
    }

    ULONGLONG rw_base = intel_driver::AllocatePool(dev, nt::NonPagedPool, rw_nt->OptionalHeader.SizeOfImage);
    if (!rw_base) {
        std::cerr << "[-] Failed to allocate memory for rwdrv\n";
        intel_driver::Unload(dev);
        return -1;
    }

    std::cout << "[*] Mapping rwdrv.sys to 0x" << std::hex << rw_base << "\n";

    if (!intel_driver::WriteMemory(dev, rw_base, rw.data(), rw_nt->OptionalHeader.SizeOfHeaders)) {
        std::cerr << "[-] Failed to write headers\n";
        return -1;
    }

    auto sec = IMAGE_FIRST_SECTION(rw_nt);
    for (int i = 0; i < rw_nt->FileHeader.NumberOfSections; ++i, ++sec) {
        intel_driver::WriteMemory(dev,
            rw_base + sec->VirtualAddress,
            rw.data() + sec->PointerToRawData,
            sec->SizeOfRawData);
    }

    std::cout << "[+] rwdrv.sys mapped\n";

    // Step 4: Write shellcode to memory
    BYTE shell[32] = {};
    ULONGLONG entry = 0xFFFFF80000000000 + 0x500000 + portable_executable::GetNtHeaders((void*)memdriver)->OptionalHeader.AddressOfEntryPoint;
    BuildShellcode(shell, entry);
    ULONGLONG shellAddr = rw_base + 0x4000;
    intel_driver::WriteMemory(dev, shellAddr, shell, sizeof(shell));

    std::cout << "[*] Shellcode written to 0x" << std::hex << shellAddr << "\n";

    // Step 5: Trigger rwdrv.sys
    DropToDisk(rwdrv, rwdrv_len, "rwdrv.sys");
    HANDLE rw = CreateFileA("\\\\.\\rwdrv", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (rw == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Could not open rwdrv device\n";
        intel_driver::Unload(dev);
        return -1;
    }

    DWORD ret = 0;
    ULONGLONG ioctl_shell = shellAddr;
    BOOL result = DeviceIoControl(rw, 0x22240C, &ioctl_shell, sizeof(ioctl_shell), nullptr, 0, &ret, nullptr);
    if (!result) {
        std::cerr << "[-] Shellcode trigger failed\n";
        intel_driver::Unload(dev);
        return -1;
    }

    std::cout << "[+] Shellcode executed\n";

    intel_driver::Unload(dev);
    Sleep(1000);

    // Step 6: Launch cheat
    DropToDisk(cheat, cheat_len, "ExternalCheat.exe");
    system("ExternalCheat.exe");
    std::cout << "[✓] Cheat launched\n";

    return 0;
}