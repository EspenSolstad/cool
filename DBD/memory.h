
#pragma once
#include <Windows.h>
#include <TlHelp32.h>

DWORD GetProcId(const wchar_t* procName) {
    PROCESSENTRY32W pe;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnap, &pe)) {
        while (Process32NextW(hSnap, &pe)) {
            if (!_wcsicmp(pe.szExeFile, procName)) {
                CloseHandle(hSnap);
                return pe.th32ProcessID;
            }
        }
    }

    CloseHandle(hSnap);
    return 0;
}

uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName) {
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32FirstW(hSnap, &modEntry)) {
            do {
                if (!_wcsicmp(modEntry.szModule, modName)) {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32NextW(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return modBaseAddr;
}
