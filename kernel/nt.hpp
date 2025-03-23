#pragma once
#include <Windows.h>

namespace nt {
	enum POOL_TYPE {
		NonPagedPool = 0
	};

	typedef struct _SYSTEM_MODULE_ENTRY {
		PVOID Reserved[2];
		PVOID Base;
		ULONG Size;
		ULONG Flags;
		USHORT Index;
		USHORT Unknown;
		USHORT LoadCount;
		USHORT ModuleNameOffset;
		CHAR ImageName[256];
	} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

	typedef struct _RTL_PROCESS_MODULES {
		ULONG NumberOfModules;
		SYSTEM_MODULE_ENTRY Modules[1];
	} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

	enum SYSTEM_INFORMATION_CLASS {
		SystemModuleInformation = 11
	};

	extern "C" {
		NTSTATUS NTAPI NtQuerySystemInformation(
			SYSTEM_INFORMATION_CLASS SystemInformationClass,
			PVOID SystemInformation,
			ULONG SystemInformationLength,
			PULONG ReturnLength
		);

		NTSTATUS NTAPI RtlAdjustPrivilege(
			ULONG Privilege,
			BOOLEAN Enable,
			BOOLEAN CurrentThread,
			PBOOLEAN Enabled
		);

		NTSTATUS NTAPI NtLoadDriver(PUNICODE_STRING DriverServiceName);
		NTSTATUS NTAPI NtUnloadDriver(PUNICODE_STRING DriverServiceName);
	}

	inline bool NT_SUCCESS(NTSTATUS status) {
		return status >= 0;
	}
}
