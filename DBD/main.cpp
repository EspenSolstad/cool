#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <thread>
#include <iomanip>
#include <vector>
#include "memory.h"
#include "offsets.h"
#include "item.h"

struct Vector3 {
    float x, y, z;
};

int main() {
    DWORD pid = GetProcId(L"DeadByDaylight-Win64-Shipping.exe");
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

    std::cout << "[*] Waiting for match to start...\n";
    
    uintptr_t entityListAddr = 0;
    uintptr_t matchStateAddr = 0;
    uintptr_t itemListAddr = 0;
    const int MAX_ATTEMPTS = 30; // 30 seconds timeout
    int attempts = 0;
    
    while (attempts < MAX_ATTEMPTS) {
        // Create pattern scan list
        std::vector<std::pair<uintptr_t*, std::pair<const BYTE*, const char*>>> patterns = {
            {&entityListAddr, {Patterns::ENTITY_LIST, Patterns::ENTITY_MASK}},
            {&matchStateAddr, {Patterns::MATCH_STATE, Patterns::MATCH_STATE_MASK}},
            {&itemListAddr, {Patterns::ITEM_LIST, Patterns::ITEM_MASK}}
        };
        
        // Try to find all patterns
        bool found = true;
        for (auto& [resultPtr, patternPair] : patterns) {
            *resultPtr = FindPattern(hProc, base, 0x5000000, patternPair.first, patternPair.second);
            if (!*resultPtr) {
                found = false;
                break;
            }
        }
        
        if (found) {
            std::cout << "\n[+] Match detected! All patterns found.\n";
            break;
        }
        
        Sleep(1000); // Wait 1 second between attempts
        attempts++;
        std::cout << "[*] Searching for match... " << attempts << "/" << MAX_ATTEMPTS << "\r";
    }
    
    if (!entityListAddr || !matchStateAddr || !itemListAddr) {
        std::cout << "\n[-] Could not find all required patterns. Are you in a match?\n";
        std::cout << "[*] Tip: Start the program after entering a match\n";
        CloseHandle(hProc);
        return 1;
    }

    int relOffset = 0;
    ReadProcessMemory(hProc, (LPCVOID)(entityListAddr + 3), &relOffset, sizeof(int), 0);

    uintptr_t entityListPtr = entityListAddr + 7 + relOffset;

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
