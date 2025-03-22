
#pragma once
#include <Windows.h>
#include <iostream>

// Common patterns used for game state detection
namespace Patterns {
    // Entity list pattern
    const BYTE ENTITY_LIST[] = "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x3F";
    const char* ENTITY_MASK = "xxx????xxxxx";
    
    // Match state pattern
    const BYTE MATCH_STATE[] = "\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x05";
    const char* MATCH_STATE_MASK = "xxxxxxx????xxxxx";
    
    // Item list pattern
    const BYTE ITEM_LIST[] = "\x48\x8B\x0D\x00\x00\x00\x00\x48\x8B\x01\x48\x8B\x40\x58";
    const char* ITEM_MASK = "xxx????xxxxxxx";
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
    for (auto& [resultPtr, patternPair] : patterns) {
        *resultPtr = FindPattern(hProc, base, scanSize, patternPair.first, patternPair.second);
        if (!*resultPtr) return false;
    }
    return true;
}
