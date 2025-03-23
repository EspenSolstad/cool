#include <ntifs.h>
#include <ntddk.h>

// Device name and symbolic link
#define DEVICE_NAME L"\\Device\\MemoryAccess"
#define SYMBOLIC_LINK L"\\DosDevices\\MemoryAccess"

// IOCTL codes for our device
#define IOCTL_READ_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PROCESS_CR3 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Structures for our IOCTL requests
typedef struct _KERNEL_READ_REQUEST {
    UINT64 Address;
    PVOID Buffer;
    UINT64 Size;
} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST {
    UINT64 Address;
    PVOID Buffer;
    UINT64 Size;
} KERNEL_WRITE_REQUEST, *PKERNEL_WRITE_REQUEST;

typedef struct _GET_PROCESS_CR3_REQUEST {
    UINT64 ProcessId;
    UINT64 CR3Value;
} GET_PROCESS_CR3_REQUEST, *PGET_PROCESS_CR3_REQUEST;

// Forward declarations
DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DeviceControl;
NTSTATUS CreateDeviceAndSymbolicLink(PDRIVER_OBJECT DriverObject);

// Global device object
PDEVICE_OBJECT g_DeviceObject = NULL;

// Function to map physical memory
PVOID MmMapPhysicalMemoryRange(
    IN PHYSICAL_ADDRESS PhysicalAddress,
    IN SIZE_T NumberOfBytes
)
{
    PHYSICAL_ADDRESS viewBase;
    viewBase.QuadPart = PhysicalAddress.QuadPart;

    return MmMapIoSpace(viewBase, NumberOfBytes, MmNonCached);
}

// Function to unmap physical memory
VOID MmUnmapPhysicalMemoryRange(
    IN PVOID VirtualAddress,
    IN SIZE_T NumberOfBytes
)
{
    UNREFERENCED_PARAMETER(NumberOfBytes);
    MmUnmapIoSpace(VirtualAddress, NumberOfBytes);
}

// Function to get CR3 value for a process
NTSTATUS GetProcessCr3Value(HANDLE ProcessId, PUINT64 Cr3Value)
{
    PEPROCESS Process;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &Process);
    
    if (NT_SUCCESS(status)) {
        // Note: This is a non-documented field offset and may change between Windows versions
        // In a production driver, you'd want to dynamically determine this offset
        *Cr3Value = *(PUINT64)((UINT64)Process + 0x28); // DirectoryTableBase offset for Windows 10
        ObDereferenceObject(Process);
        return STATUS_SUCCESS;
    }
    
    return status;
}

// Function to handle device I/O control
NTSTATUS DeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    
    PIO_STACK_LOCATION stackLocation = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0;
    
    // Get the I/O control code
    ULONG ioControlCode = stackLocation->Parameters.DeviceIoControl.IoControlCode;
    
    switch (ioControlCode) {
        case IOCTL_READ_MEMORY: {
            if (stackLocation->Parameters.DeviceIoControl.InputBufferLength < sizeof(KERNEL_READ_REQUEST)) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            
            PKERNEL_READ_REQUEST readRequest = (PKERNEL_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;
            PVOID kernelBuffer = ExAllocatePool(NonPagedPool, readRequest->Size);
            
            if (kernelBuffer) {
                // Map physical memory and read
                PHYSICAL_ADDRESS physicalAddress;
                physicalAddress.QuadPart = readRequest->Address;
                
                PVOID mappedMemory = MmMapPhysicalMemoryRange(physicalAddress, readRequest->Size);
                
                if (mappedMemory) {
                    // Copy from mapped physical memory to our kernel buffer
                    RtlCopyMemory(kernelBuffer, mappedMemory, readRequest->Size);
                    
                    // Unmap the physical memory
                    MmUnmapPhysicalMemoryRange(mappedMemory, readRequest->Size);
                    
                    // Copy from kernel buffer to user buffer
                    __try {
                        RtlCopyMemory(readRequest->Buffer, kernelBuffer, readRequest->Size);
                        bytesReturned = sizeof(KERNEL_READ_REQUEST);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        status = STATUS_ACCESS_VIOLATION;
                    }
                } else {
                    status = STATUS_UNSUCCESSFUL;
                }
                
                ExFreePool(kernelBuffer);
            } else {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
            break;
        }
        
        case IOCTL_WRITE_MEMORY: {
            if (stackLocation->Parameters.DeviceIoControl.InputBufferLength < sizeof(KERNEL_WRITE_REQUEST)) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            
            PKERNEL_WRITE_REQUEST writeRequest = (PKERNEL_WRITE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
            PVOID kernelBuffer = ExAllocatePool(NonPagedPool, writeRequest->Size);
            
            if (kernelBuffer) {
                // Copy from user buffer to our kernel buffer
                __try {
                    RtlCopyMemory(kernelBuffer, writeRequest->Buffer, writeRequest->Size);
                    
                    // Map physical memory and write
                    PHYSICAL_ADDRESS physicalAddress;
                    physicalAddress.QuadPart = writeRequest->Address;
                    
                    PVOID mappedMemory = MmMapPhysicalMemoryRange(physicalAddress, writeRequest->Size);
                    
                    if (mappedMemory) {
                        // Copy from kernel buffer to mapped physical memory
                        RtlCopyMemory(mappedMemory, kernelBuffer, writeRequest->Size);
                        
                        // Unmap the physical memory
                        MmUnmapPhysicalMemoryRange(mappedMemory, writeRequest->Size);
                        
                        bytesReturned = sizeof(KERNEL_WRITE_REQUEST);
                    } else {
                        status = STATUS_UNSUCCESSFUL;
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    status = STATUS_ACCESS_VIOLATION;
                }
                
                ExFreePool(kernelBuffer);
            } else {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
            break;
        }
        
        case IOCTL_GET_PROCESS_CR3: {
            if (stackLocation->Parameters.DeviceIoControl.InputBufferLength < sizeof(GET_PROCESS_CR3_REQUEST)) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            
            PGET_PROCESS_CR3_REQUEST cr3Request = (PGET_PROCESS_CR3_REQUEST)Irp->AssociatedIrp.SystemBuffer;
            
            status = GetProcessCr3Value((HANDLE)cr3Request->ProcessId, &cr3Request->CR3Value);
            
            if (NT_SUCCESS(status)) {
                bytesReturned = sizeof(GET_PROCESS_CR3_REQUEST);
            }
            break;
        }
        
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
    
    // Complete the IRP
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return status;
}

// Driver unload routine
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symbolicLinkName;
    RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_LINK);
    
    // Delete the symbolic link
    IoDeleteSymbolicLink(&symbolicLinkName);
    
    // Delete the device object
    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
    
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[+] memdriver.sys unloaded\n");
}

// Create device and symbolic link
NTSTATUS CreateDeviceAndSymbolicLink(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLinkName;
    
    // Initialize the device name and symbolic link name
    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_LINK);
    
    // Create the device object
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );
    
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[-] Failed to create device object (0x%08X)\n", status);
        return status;
    }
    
    // Create the symbolic link
    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[-] Failed to create symbolic link (0x%08X)\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }
    
    return STATUS_SUCCESS;
}

// Driver entry point
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    
    NTSTATUS status;
    
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[+] memdriver.sys manually mapped and alive!\n");
    
    // Set up the unload routine
    DriverObject->DriverUnload = DriverUnload;
    
    // Set up the dispatch routines
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = NULL;
    }
    
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    
    // Create the device object and symbolic link
    status = CreateDeviceAndSymbolicLink(DriverObject);
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[+] memdriver.sys initialized successfully\n");
    
    return STATUS_SUCCESS;
}
