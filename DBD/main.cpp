#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <thread>
#include <iomanip>
#include <vector>
#include "memory.h"
#include "offsets.h"
#include "item.h"
#include "overlay.h"
#include "types.h"

bool VerifyComponent(HANDLE hProc, uintptr_t baseAddr, uintptr_t offset) {
    uintptr_t component = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)(baseAddr + offset), &component, sizeof(uintptr_t), nullptr)) {
        return false;
    }
    return component != 0;
}

class EntityManager {
public:
    std::vector<ESPEntity> entities;
    
    void UpdateEntity(HANDLE hProc, uintptr_t address) {
        if (!address) return;
        
        // Get player state
        uintptr_t playerState = 0;
        ReadProcessMemory(hProc, (LPCVOID)(address + Offsets::PlayerData), 
            &playerState, sizeof(uintptr_t), nullptr);
            
        if (!playerState) return;
        
        // Check role
        uint8_t role = 0;
        ReadProcessMemory(hProc, (LPCVOID)(playerState + Offsets::GameRole),
            &role, sizeof(uint8_t), nullptr);
            
        bool isKiller = (role == 1); // 1 = Killer, 0 = Survivor
        
        // Get root component for position
        uintptr_t rootComponent = 0;
        ReadProcessMemory(hProc, (LPCVOID)(address + 0x1A8), &rootComponent, sizeof(uintptr_t), nullptr);
        
        Vector3 position = {0, 0, 0};
        if (rootComponent) {
            ReadProcessMemory(hProc, (LPCVOID)(rootComponent + 0x1A0), &position, sizeof(Vector3), nullptr);
        }
            
        // Get state
        uint8_t camperState = 0;
        if (!isKiller) {
            ReadProcessMemory(hProc, (LPCVOID)(address + Offsets::CamperState),
                &camperState, sizeof(uint8_t), nullptr);
        }
        
        // Check if being carried
        uintptr_t carryingPlayer = 0;
        ReadProcessMemory(hProc, (LPCVOID)(address + Offsets::CarryingPlayer),
            &carryingPlayer, sizeof(uintptr_t), nullptr);
            
        // Get item info if survivor
        std::string itemName = "None";
        if (!isKiller) {
            uintptr_t inventory = 0;
            ReadProcessMemory(hProc, (LPCVOID)(address + Offsets::CharacterInventory),
                &inventory, sizeof(uintptr_t), nullptr);
                
            if (inventory) {
                // Get current item count
                int32_t itemCount = 0;
                ReadProcessMemory(hProc, (LPCVOID)(inventory + Offsets::ItemCount), &itemCount, sizeof(int32_t), nullptr);
                
                if (itemCount > 0) {
                    uint8_t itemType = 0;
                    ReadProcessMemory(hProc, (LPCVOID)(inventory + Offsets::ItemType), &itemType, sizeof(uint8_t), nullptr);
                    
                    bool isInUse = false;
                    ReadProcessMemory(hProc, (LPCVOID)(inventory + Offsets::IsInUse), &isInUse, sizeof(bool), nullptr);
                    
                    if (isInUse) {
                        switch(itemType) {
                            case 0: itemName = "Medkit"; break;
                            case 1: itemName = "Flashlight"; break;
                            case 2: itemName = "Toolbox"; break;
                            case 3: itemName = "Map"; break;
                            case 4: itemName = "Key"; break;
                        }
                    }
                }
            }
        }
            
        ESPEntity entity;
        entity.position = position;
        entity.isKiller = isKiller;
        entity.health = (camperState == 0) ? 100 : (camperState == 1) ? 50 : 0; // 0=Healthy, 1=Injured, 2=Dying
        entity.name = isKiller ? "KILLER" : ("Survivor - " + itemName).c_str();
        entity.color = isKiller ? Colors::Killer : 
                      (carryingPlayer ? Colors::Health : Colors::Survivor);
        
        entities.push_back(entity);
    }
    
    void Clear() {
        entities.clear();
    }
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
    std::cout << "[*] Scanning for players...\n";

    std::cout << "[*] Scanning memory for UWorld...\n";
    
    // Find UWorld
    uintptr_t uworldPattern = FindPattern(hProc, base, 0x10000000, 
        (BYTE*)Patterns::UWORLD, Patterns::UWORLD_MASK);
    
    if (!uworldPattern) {
        std::cout << "[-] UWorld pattern not found.\n";
        CloseHandle(hProc);
        return 1;
    }

    // Get UWorld pointer
    int uworldOffset = 0;
    ReadProcessMemory(hProc, (LPCVOID)(uworldPattern + 3), &uworldOffset, sizeof(int), nullptr);
    uintptr_t uworld = uworldPattern + 7 + uworldOffset;
    
    std::cout << "[+] Found UWorld at: 0x" << std::hex << uworld << std::dec << "\n";
    
    // Find GameState
    uintptr_t gameStatePtr = 0;
    ReadProcessMemory(hProc, (LPCVOID)uworld, &gameStatePtr, sizeof(uintptr_t), nullptr);
    
    if (!gameStatePtr) {
        std::cout << "[-] GameState not found.\n";
        CloseHandle(hProc);
        return 1;
    }
    
    std::cout << "[+] Found GameState at: 0x" << std::hex << gameStatePtr << std::dec << "\n";
    
    // Find PlayerArray
    uintptr_t playerArrayPattern = FindPattern(hProc, base, 0x10000000,
        (BYTE*)Patterns::PLAYER_ARRAY, Patterns::PLAYER_ARRAY_MASK);
        
    if (!playerArrayPattern) {
        std::cout << "[-] PlayerArray pattern not found.\n";
        CloseHandle(hProc);
        return 1;
    }
    
    int playerArrayOffset = 0;
    ReadProcessMemory(hProc, (LPCVOID)(playerArrayPattern + 3), &playerArrayOffset, sizeof(int), nullptr);
    uintptr_t playerArray = playerArrayPattern + 7 + playerArrayOffset;
    
    std::cout << "[+] Found PlayerArray at: 0x" << std::hex << playerArray << std::dec << "\n";

    // Initialize DirectX overlay
    Overlay overlay;
    if (!overlay.Init()) {
        std::cout << "[-] Failed to initialize overlay.\n";
        CloseHandle(hProc);
        return 1;
    }

    EntityManager entityManager;
    bool running = true;

    // Create monitoring thread
    std::thread monitorThread([&]() {
        while (running) {
            entityManager.Clear();
            
            // Read player array
            uintptr_t arrayPtr = 0;
            ReadProcessMemory(hProc, (LPCVOID)playerArray, &arrayPtr, sizeof(uintptr_t), nullptr);
            
            if (arrayPtr) {
                // Get array size
                int32_t count = 0;
                ReadProcessMemory(hProc, (LPCVOID)(arrayPtr + 0x8), &count, sizeof(int32_t), nullptr);
                count = min(count, 8); // Limit to 8 players max
                
                // Read data pointer
                uintptr_t dataPtr = 0;
                ReadProcessMemory(hProc, (LPCVOID)(arrayPtr), &dataPtr, sizeof(uintptr_t), nullptr);
                
                if (dataPtr) {
                    for (int i = 0; i < count; i++) {
                        uintptr_t player = 0;
                        ReadProcessMemory(hProc, (LPCVOID)(dataPtr + i * sizeof(uintptr_t)), 
                            &player, sizeof(uintptr_t), nullptr);
                            
                        if (player) {
                            entityManager.UpdateEntity(hProc, player);
                        }
                    }
                }
            }
            
            Sleep(10); // Update every 10ms
        }
    });

    // Create render thread
    std::thread renderThread([&]() {
        while (running) {
            overlay.BeginScene();
            
            // Render all entities
            for (const auto& entity : entityManager.entities) {
                // Draw box around entity
                overlay.DrawBox(entity.position, 50.0f, 100.0f, entity.color);
                
                // Draw health bar
                if (!entity.isKiller) {
                    Vector3 healthPos = entity.position;
                    healthPos.y += 60.0f; // Above the box
                    overlay.DrawBox(healthPos, 50.0f * (entity.health / 100.0f), 5.0f, Colors::Health);
                }
                
                // Draw name and item
                Vector3 textPos = entity.position;
                textPos.y -= 60.0f; // Below the box
                overlay.DrawText(textPos, entity.name, entity.color);
            }
            
            overlay.EndScene();
            Sleep(16); // ~60 FPS
        }
    });

    std::cout << "[+] ESP activated! Press Enter to exit...\n";
    std::cin.get();
    
    running = false;
    monitorThread.join();
    renderThread.join();
    CloseHandle(hProc);
    return 0;
}
