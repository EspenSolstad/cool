#pragma once
#include <Windows.h>

namespace intel_driver {
	HANDLE Load();
	bool Unload(HANDLE handle);
	ULONGLONG AllocatePool(HANDLE handle, DWORD poolType, size_t size);
	bool WriteMemory(HANDLE handle, ULONGLONG address, void* buffer, size_t size);
	ULONGLONG GetKernelModuleExport(HANDLE handle, ULONGLONG kernelModuleBase, const std::string& functionName);
	bool CallKernelFunction(HANDLE handle, PVOID output, ULONGLONG funcAddress, ULONGLONG param1, ULONGLONG param2);
	ULONGLONG MmAllocateIndependentPagesEx(HANDLE handle, ULONG32 size);
	bool MmFreeIndependentPages(HANDLE handle, ULONGLONG base, ULONG32 size);
	bool MmSetPageProtection(HANDLE handle, ULONGLONG address, ULONG32 size, ULONG32 newProtection);
	bool FreePool(HANDLE handle, ULONGLONG address);
	extern ULONGLONG ntoskrnlAddr;
}
