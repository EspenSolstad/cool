
#pragma once
#include <Windows.h>
#include <iostream>

// Pattern scanning for various game elements
uintptr_t FindPattern(HANDLE hProc, uintptr_t start, size_t size, BYTE* pattern, const char* mask) {
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

// Additional patterns for item detection
namespace Patterns {
    const BYTE ITEM_LIST[] = "\x48\x8B\x0D\x00\x00\x00\x00\x48\x8B\x01\x48\x8B\x40\x58";
    const char* ITEM_MASK = "xxx????xxxxxxx";
    
    const BYTE ITEM_STATE[] = "\x48\x89\x5C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x20\x48\x8B\xF1";
    const char* ITEM_STATE_MASK = "xxxx?xxxx?xxxxxxxx";
}
