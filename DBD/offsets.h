
#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>
#include "types.h"

namespace Offsets {
    // From ADBDPlayer
    static constexpr uintptr_t CharacterInventory = 0xaf8;  // _characterInventoryComponent
    static constexpr uintptr_t PlayerData = 0xb98;         // _playerData
    static constexpr uintptr_t CarryingPlayer = 0xbf8;     // _carryingPlayer
    static constexpr uintptr_t InteractingPlayer = 0xc08;  // _interactingPlayer
    static constexpr uintptr_t CamperState = 0xb70;        // CurrentCamperState
    
    // From ACollectable
    static constexpr uintptr_t ItemCount = 0x520;          // _itemCount
    static constexpr uintptr_t ItemType = 0x548;           // _itemType
    static constexpr uintptr_t ItemAddons = 0x500;         // _itemAddons array
    static constexpr uintptr_t ItemState = 0x4f8;          // _state
    static constexpr uintptr_t IsInUse = 0x54e;            // _isInUse
    
    // From ADBDPlayerState
    static constexpr uintptr_t GameRole = 0x3fa;           // GameRole
    static constexpr uintptr_t PlayerGameState = 0x4d0;    // OnPlayerGameStateChanged
    static constexpr uintptr_t PlayerCustomization = 0x600; // _playerCustomization
    
    // From UItemAddon
    static constexpr uintptr_t TokenCount = 0x2d4;         // _tokenCount
    static constexpr uintptr_t MaxTokenCount = 0x2b4;      // _maxTokenCount
    static constexpr uintptr_t BaseItem = 0x2dc;           // _baseItem
}

// Patterns for memory scanning
namespace Patterns {
    // Try to find UWorld first
    const BYTE UWORLD[] = "\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\x88\x00\x00\x00\x00\x48\x85\xC9\x74\x06\x48\x8B\x49\x70";
    const char* UWORLD_MASK = "xxx????xxx????xxxxxxxxxx";
    
    // Then GameState
    const BYTE GAMESTATE[] = "\x48\x89\x5C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x20\x48\x8B\xD9\x41\x8B\xF0";
    const char* GAMESTATE_MASK = "xxxx?xxxx?xxxxxxxxxxx";
    
    // Finally PlayerArray
    const BYTE PLAYER_ARRAY[] = "\x48\x8B\x0D\x00\x00\x00\x00\x48\x8B\x01\x48\x8B\x40\x58";
    const char* PLAYER_ARRAY_MASK = "xxx????xxxxxxx";
}


// Pattern scanning for various game elements
uintptr_t FindPattern(HANDLE hProc, uintptr_t start, size_t size, const BYTE* pattern, const char* mask) {
    BYTE* buffer = new BYTE[size];
    SIZE_T bytesRead;

    if (!ReadProcessMemory(hProc, (LPCVOID)start, buffer, size, &bytesRead)) {
        delete[] buffer;
        return 0;
    }

    for (size_t i = 0; i < size; i++) {
        bool found = true;
        for (size_t j = 0; mask[j] != 0; j++) {
            if (mask[j] != '?' && pattern[j] != buffer[i + j]) {
                found = false;
                break;
            }
        }
        if (found) {
            delete[] buffer;
            return start + i;
        }
    }

    delete[] buffer;
    return 0;
}

// Helper function to scan multiple patterns
bool FindPatterns(HANDLE hProc, uintptr_t base, size_t scanSize, 
                 std::vector<std::pair<uintptr_t*, std::pair<const BYTE*, const char*>>>& patterns) {
    for (const auto& pattern : patterns) {
        *pattern.first = FindPattern(hProc, base, scanSize, (BYTE*)pattern.second.first, pattern.second.second);
        if (!*pattern.first) return false;
    }
    return true;
}
