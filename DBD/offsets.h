
#pragma once
#include <Windows.h>
#include <iostream>

// Component offsets
namespace Offsets {
    // Base component offsets
    constexpr auto RootComponent = 0x1A8;
    constexpr auto Mesh = 0x328;
    constexpr auto CharacterMovement = 0x330;
    
    // Player state offsets
    constexpr auto PlayerState = 0x320;
    constexpr auto Health = 0x334;
    constexpr auto Team = 0x338;
    constexpr auto IsKiller = 0x338;
    constexpr auto KillerPower = 0x340;
    constexpr auto KillerStunState = 0x348;
    
    // Item offsets
    constexpr auto ItemBase = 0x2A8;
    constexpr auto ItemProperties = 0x40;
    constexpr auto ItemCharges = 0x58;
    constexpr auto ItemAddon1 = 0x88;
    constexpr auto ItemAddon2 = 0x90;
    constexpr auto ItemRarity = 0x64;
    constexpr auto ItemState = 0x70;
}

// Patterns for memory scanning
namespace Patterns {
    // Player patterns
    const BYTE PLAYER_BASE[] = "\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\x48\x8B\x88";
    const char* PLAYER_MASK = "xxx????xxxx?xxx";
    
    // Killer patterns
    const BYTE KILLER_BASE[] = "\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\x48\x8B\x40";
    const char* KILLER_MASK = "xxx????xxxx?xxx";
}

// ESP Colors
namespace Colors {
    constexpr D3DCOLOR Survivor = D3DCOLOR_ARGB(255, 0, 255, 0);    // Green
    constexpr D3DCOLOR Killer = D3DCOLOR_ARGB(255, 255, 0, 0);      // Red
    constexpr D3DCOLOR Item = D3DCOLOR_ARGB(255, 255, 255, 0);      // Yellow
    constexpr D3DCOLOR Health = D3DCOLOR_ARGB(255, 0, 255, 255);    // Cyan
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
