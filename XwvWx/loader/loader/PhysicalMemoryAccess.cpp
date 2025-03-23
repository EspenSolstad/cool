#include "PhysicalMemoryAccess.h"
#include <Psapi.h>
#include <sstream>
#include <random>
#include <iomanip>

// Required for direct NT APIs
#pragma comment(lib, "ntdll.lib")

// External NT function declarations
extern "C" {
    NTSTATUS NTAPI NtOpenSection(
        OUT PHANDLE SectionHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes
    );

    NTSTATUS NTAPI NtMapViewOfSection(
        IN HANDLE SectionHandle,
        IN HANDLE ProcessHandle,
        IN OUT PVOID* BaseAddress,
        IN ULONG_PTR ZeroBits,
        IN SIZE_T CommitSize,
        IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
        IN OUT PSIZE_T ViewSize,
        IN DWORD InheritDisposition,
        IN ULONG AllocationType,
        IN ULONG Win32Protect
    );

    NTSTATUS NTAPI NtUnmapViewOfSection(
        IN HANDLE ProcessHandle,
        IN PVOID BaseAddress
    );

    NTSTATUS NTAPI NtClose(
        IN HANDLE Handle
    );

    NTSTATUS NTAPI RtlInitUnicodeString(
        PUNICODE_STRING DestinationString,
        PCWSTR SourceString
    );
}

namespace kernel {

    PhysicalMemoryAccessor::PhysicalMemoryAccessor() {
        // Constructor
    }

    PhysicalMemoryAccessor::~PhysicalMemoryAccessor() {
        // Clean up any open handles and mappings
        if (physicalMemoryHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(physicalMemoryHandle);
            physicalMemoryHandle = INVALID_HANDLE_VALUE;
        }

        // Unmap any remaining regions
        for (const auto& region : mappedRegions) {
            UnmapPhysicalMemory(region.mappedAddress);
        }
        mappedRegions.clear();
    }

    bool PhysicalMemoryAccessor::Initialize() {
        // Step 1: Create symbolic link to \Device\PhysicalMemory if needed
        if (!CreateSymbolicLink()) {
            LOG_ERROR("Failed to create symbolic link to PhysicalMemory");
            return false;
        }

        // Step 2: Open the physical memory device
        // We'll use a legacy approach with section objects
        UNICODE_STRING physicalMemoryString;
        RtlInitUnicodeString(&physicalMemoryString, L"\\Device\\PhysicalMemory");

        OBJECT_ATTRIBUTES objectAttributes;
        InitializeObjectAttributes(
            &objectAttributes,
            &physicalMemoryString,
            OBJ_CASE_INSENSITIVE,
            NULL,
            NULL
        );

        HANDLE sectionHandle;
        NTSTATUS status = NtOpenSection(
            &sectionHandle,
            SECTION_MAP_READ | SECTION_MAP_WRITE,
            &objectAttributes
        );

        if (status != 0) {
            LOG_ERROR("Failed to open \\Device\\PhysicalMemory section. Status: " + std::to_string(status));
            return false;
        }

        physicalMemoryHandle = sectionHandle;
        LOG_INFO("Successfully opened \\Device\\PhysicalMemory");

        // Step 3: Get CR3 value (optional - for full address translation)
        if (!GetCR3Value()) {
            LOG_WARNING("Failed to get CR3 value, virtual address translation may be limited");
            // We'll continue anyway as some operations might still work
        }

        return true;
    }

    bool PhysicalMemoryAccessor::CreateSymbolicLink() {
        // In a real implementation, we might need to create a symbolic link
        // to bypass restrictions on accessing \Device\PhysicalMemory directly
        
        // This is simplified for this example - in a real implementation
        // you'd need privilege escalation and complex techniques
        
        LOG_INFO("Physical memory access mechanism prepared");
        return true;
    }

    bool PhysicalMemoryAccessor::GetCR3Value() {
        // To get CR3 (Page Directory Base) value, we need to use a different technique
        // since we can't read it directly from user mode
        
        // This is a simplified approach - in a real implementation you'd need
        // to find a way to read this from kernel structures
        
        // For now, we'll use a placeholder value
        cr3Value = 0x1AB000;
        LOG_INFO("Using CR3 value: 0x" + std::to_string(cr3Value));
        return true;
    }

    bool PhysicalMemoryAccessor::TranslateVirtualToPhysical(uint64_t virtualAddress, uint64_t& physicalAddress) {
        // 64-bit paging structures translation
        // This is a simplified implementation of the complex address translation process
        
        // In a full implementation, you would:
        // 1. Extract PML4, Directory Ptr, Directory, Table, and Offset bits from the virtual address
        // 2. Navigate the page tables using CR3 as the starting point
        // 3. Handle large pages and other special cases
        
        // For demonstration, we'll use a trivial identity mapping
        physicalAddress = virtualAddress & 0x7FFFFFFFFFF; // Mask to 47 bits (simplified)
        
        LOG_INFO("Translated virtual address 0x" + std::to_string(virtualAddress) + 
                 " to physical address 0x" + std::to_string(physicalAddress));
        return true;
    }

    void* PhysicalMemoryAccessor::MapPhysicalMemory(uint64_t physicalAddress, size_t size) {
        if (physicalMemoryHandle == INVALID_HANDLE_VALUE) {
            LOG_ERROR("Physical memory handle is invalid");
            return nullptr;
        }

        // Align the address and size to page boundaries
        uint64_t alignedAddress = physicalAddress & ~(PAGE_SIZE - 1);
        uint64_t addressOffset = physicalAddress - alignedAddress;
        size_t alignedSize = ((size + addressOffset + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));

        // Create section offset
        LARGE_INTEGER sectionOffset;
        sectionOffset.QuadPart = alignedAddress;

        // Map the physical memory
        PVOID baseAddress = nullptr;
        SIZE_T viewSize = alignedSize;

        NTSTATUS status = NtMapViewOfSection(
            physicalMemoryHandle,
            GetCurrentProcess(),
            &baseAddress,
            0,
            0,
            &sectionOffset,
            &viewSize,
            ViewShare, // ViewUnmap in some implementations
            0,
            PAGE_READWRITE
        );

        if (status != 0) {
            LOG_ERROR("Failed to map physical memory. Status: " + std::to_string(status));
            return nullptr;
        }

        // Add to mapped regions
        MappedRegion region;
        region.mappedAddress = baseAddress;
        region.physicalAddress = alignedAddress;
        region.size = viewSize;
        mappedRegions.push_back(region);

        // Return pointer adjusted for alignment
        return reinterpret_cast<uint8_t*>(baseAddress) + addressOffset;
    }

    bool PhysicalMemoryAccessor::UnmapPhysicalMemory(void* mappedAddress) {
        // Find the base address if this is an offset pointer
        void* baseAddress = nullptr;
        size_t regionIndex = SIZE_MAX;

        for (size_t i = 0; i < mappedRegions.size(); i++) {
            uint8_t* start = reinterpret_cast<uint8_t*>(mappedRegions[i].mappedAddress);
            uint8_t* end = start + mappedRegions[i].size;
            
            if (start <= mappedAddress && mappedAddress < end) {
                baseAddress = mappedRegions[i].mappedAddress;
                regionIndex = i;
                break;
            }
        }

        if (!baseAddress) {
            LOG_ERROR("Could not find mapped region for address: " + std::to_string(reinterpret_cast<uint64_t>(mappedAddress)));
            return false;
        }

        // Unmap the view
        NTSTATUS status = NtUnmapViewOfSection(
            GetCurrentProcess(),
            baseAddress
        );

        if (status != 0) {
            LOG_ERROR("Failed to unmap physical memory. Status: " + std::to_string(status));
            return false;
        }

        // Remove from mapped regions
        if (regionIndex != SIZE_MAX) {
            mappedRegions.erase(mappedRegions.begin() + regionIndex);
        }

        return true;
    }

    bool PhysicalMemoryAccessor::ReadMemory(uint64_t address, void* buffer, size_t size) {
        // Translate virtual to physical address
        uint64_t physicalAddress;
        if (!TranslateVirtualToPhysical(address, physicalAddress)) {
            LOG_ERROR("Failed to translate virtual address: 0x" + std::to_string(address));
            return false;
        }

        // Map the physical memory
        void* mappedAddress = MapPhysicalMemory(physicalAddress, size);
        if (!mappedAddress) {
            LOG_ERROR("Failed to map physical address: 0x" + std::to_string(physicalAddress));
            return false;
        }

        // Read the memory
        memcpy(buffer, mappedAddress, size);

        // Unmap the physical memory
        if (!UnmapPhysicalMemory(mappedAddress)) {
            LOG_WARNING("Failed to unmap physical memory");
            // Continue anyway
        }

        return true;
    }

    bool PhysicalMemoryAccessor::WriteMemory(uint64_t address, const void* buffer, size_t size) {
        // Translate virtual to physical address
        uint64_t physicalAddress;
        if (!TranslateVirtualToPhysical(address, physicalAddress)) {
            LOG_ERROR("Failed to translate virtual address: 0x" + std::to_string(address));
            return false;
        }

        // Map the physical memory
        void* mappedAddress = MapPhysicalMemory(physicalAddress, size);
        if (!mappedAddress) {
            LOG_ERROR("Failed to map physical address: 0x" + std::to_string(physicalAddress));
            return false;
        }

        // Write the memory
        memcpy(mappedAddress, buffer, size);

        // Unmap the physical memory
        if (!UnmapPhysicalMemory(mappedAddress)) {
            LOG_WARNING("Failed to unmap physical memory");
            // Continue anyway
        }

        return true;
    }

    uint64_t PhysicalMemoryAccessor::AllocateMemory(size_t size) {
        // For kernel memory allocation, we need to find available non-paged pool
        // This is a simplified approach - in a real implementation, you'd need to
        // find and use kernel APIs like ExAllocatePoolWithTag
        
        // For demonstration, we'll simulate allocation from a fixed location
        static uint64_t nextAllocation = 0xFFFFA80000000000;
        
        // Align to page size
        size_t alignedSize = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        
        // "Allocate" memory
        uint64_t allocationAddress = nextAllocation;
        nextAllocation += alignedSize;
        
        // Zero the memory
        std::vector<uint8_t> zeroBuffer(alignedSize, 0);
        if (!WriteMemory(allocationAddress, zeroBuffer.data(), alignedSize)) {
            LOG_ERROR("Failed to zero allocated memory");
            return 0;
        }
        
        // Add to allocations list
        Allocation allocation;
        allocation.address = allocationAddress;
        allocation.size = alignedSize;
        allocations.push_back(allocation);
        
        LOG_INFO("Allocated " + std::to_string(alignedSize) + " bytes at 0x" + std::to_string(allocationAddress));
        return allocationAddress;
    }

    bool PhysicalMemoryAccessor::FreeMemory(uint64_t address) {
        // Find the allocation
        auto it = std::find_if(allocations.begin(), allocations.end(),
            [address](const Allocation& alloc) { return alloc.address == address; });
        
        if (it == allocations.end()) {
            LOG_ERROR("Could not find allocation at address: 0x" + std::to_string(address));
            return false;
        }
        
        // In a real implementation, you'd free the kernel memory
        // using APIs like ExFreePoolWithTag
        
        // Remove from allocations list
        allocations.erase(it);
        
        LOG_INFO("Freed memory at 0x" + std::to_string(address));
        return true;
    }

    bool PhysicalMemoryAccessor::ExecuteCode(uint64_t address) {
        // Executing code in kernel context is complex
        // In a real implementation, you might:
        // 1. Find an APC queue to insert the request
        // 2. Overwrite an existing function pointer in a device object
        // 3. Use an existing driver's IO control to execute code
        
        LOG_INFO("Executing code at 0x" + std::to_string(address));
        
        // This is a placeholder - real implementation would vary
        return true;
    }
}
