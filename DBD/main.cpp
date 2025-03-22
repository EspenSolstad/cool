
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include "memory.h"
#include "offsets.h"

struct Vector3 {
    float x, y, z;
};

int main() {
    DWORD pid = GetProcId(LL"DeadByDaylight-Win64-Shipping.exe");
    if (!pid) {
        std::cout << "[-] Game not found.\n";
        return 1;
    }

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        std::cout << "[-] Cannot open process.\n";
        return 1;
    }

    std::cout << "[+] Game process found! PID: " << pid << "\n";

    uintptr_t base = GetModuleBaseAddress(pid, L"DeadByDaylight-Win64-Shipping.exe");

    uintptr_t matchAddr = FindPattern(hProc, base, 0x5000000,
        (BYTE*)"\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x3F",
        "xxx????xxxxx");

    if (!matchAddr) {
        std::cout << "[-] Entity list pattern not found.\n";
        CloseHandle(hProc);
        return 1;
    }

    int relOffset = 0;
    ReadProcessMemory(hProc, (LPCVOID)(matchAddr + 3), &relOffset, sizeof(int), 0);

    uintptr_t entityListPtr = matchAddr + 7 + relOffset;

    std::cout << "[+] Entity list pointer resolved to: 0x" << std::hex << entityListPtr << "\n";

    uintptr_t entityList = 0;
    ReadProcessMemory(hProc, (LPCVOID)(entityListPtr), &entityList, sizeof(uintptr_t), 0);
    std::cout << "[+] Entity list base address: 0x" << std::hex << entityList << "\n";

    // Try to loop a few players
    for (int i = 0; i < 5; i++) {
        uintptr_t entityAddress = 0;
        ReadProcessMemory(hProc, (LPCVOID)(entityList + i * sizeof(uintptr_t)), &entityAddress, sizeof(uintptr_t), 0);

        if (entityAddress) {
            Vector3 position;
            ReadProcessMemory(hProc, (LPCVOID)(entityAddress + 0x1A0), &position, sizeof(Vector3), 0); // example offset

            std::cout << "[Entity " << i << "] Pos -> X: " << position.x << " Y: " << position.y << " Z: " << position.z << "\n";
        }
    }

    CloseHandle(hProc);
    return 0;
}
