
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <thread>
#include <iomanip>
#include "memory.h"
#include "offsets.h"
#include "item.h"

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

    ItemTracker itemTracker;
    bool running = true;

    // Create monitoring thread
    std::thread monitorThread([&]() {
        while (running) {
            for (int i = 0; i < 5; i++) {
                uintptr_t entityAddress = 0;
                ReadProcessMemory(hProc, (LPCVOID)(entityList + i * sizeof(uintptr_t)), &entityAddress, sizeof(uintptr_t), 0);

                if (entityAddress) {
                    Vector3 position;
                    ReadProcessMemory(hProc, (LPCVOID)(entityAddress + 0x1A0), &position, sizeof(Vector3), 0);

                    // Read item data
                    uintptr_t itemAddr = entityAddress + Offsets::ItemBase;
                    ItemProperties props;
                    if (ReadProcessMemory(hProc, (LPCVOID)(itemAddr + Offsets::ItemProperties), &props, sizeof(ItemProperties), 0)) {
                        if (props.type != ItemType::NONE) {
                            // Process item addons
                            ProcessAddons(hProc, itemAddr, props);
                            
                            // Update item state
                            itemTracker.UpdateItemState(entityAddress, props);
                            itemTracker.MonitorCharges(hProc, itemAddr);

                            // Display item info
                            std::cout << "\033[2J\033[H"; // Clear screen
                            std::cout << "Entity " << std::dec << i << " Position: X:" << position.x 
                                    << " Y:" << position.y << " Z:" << position.z << "\n";
                            
                            auto it = ITEM_DATABASE.find(props.type);
                            if (it != ITEM_DATABASE.end()) {
                                std::cout << "Item: " << it->second.name << "\n";
                                std::cout << "Rarity: " << static_cast<int>(props.rarity) << "\n";
                                std::cout << "Charges: " << props.remainingCharges << "/" << props.baseCharges << "\n";
                                std::cout << "Addons: " << props.addons[0].id << ", " << props.addons[1].id << "\n";
                            }
                        }
                    }
                }
            }
            Sleep(100); // Update every 100ms
        }
    });

    std::cout << "Press Enter to exit...\n";
    std::cin.get();
    
    running = false;
    monitorThread.join();
    CloseHandle(hProc);
    return 0;
}
