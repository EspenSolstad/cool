#pragma once
#include "KernelMemoryAccess.h"
#include <vector>
#include <map>

namespace kernel {
    // Physical memory access implementation
    class PhysicalMemoryAccessor : public MemoryAccessor {
    private:
        HANDLE physicalMemoryHandle = INVALID_HANDLE_VALUE;
        uint64_t cr3Value = 0; // Control Register 3 (Page Directory Base)
        
        // Cached page table mappings
        struct MappedRegion {
            void* mappedAddress;
            uint64_t physicalAddress;
            size_t size;
        };
        std::vector<MappedRegion> mappedRegions;
        
        // Memory allocations
        struct Allocation {
            uint64_t address;
            size_t size;
        };
        std::vector<Allocation> allocations;
        
        // Memory page size
        const size_t PAGE_SIZE = 0x1000;
        
        // Paging structures
        static const uint64_t PTE_PRESENT = 0x1;
        static const uint64_t PTE_WRITE = 0x2;
        static const uint64_t PTE_USER = 0x4;
        static const uint64_t PTE_LARGE_PAGE = 0x80;
        static const uint64_t PTE_NX = 0x8000000000000000;
        
        // Internal functions
        bool CreateSymbolicLink();
        bool TranslateVirtualToPhysical(uint64_t virtualAddress, uint64_t& physicalAddress);
        void* MapPhysicalMemory(uint64_t physicalAddress, size_t size);
        bool UnmapPhysicalMemory(void* mappedAddress);
        bool GetCR3Value();
        bool ElevateProcessPrivileges();
        bool LoadDriverForMemoryAccess();
        
    public:
        PhysicalMemoryAccessor();
        ~PhysicalMemoryAccessor() override;
        
        // MemoryAccessor interface implementation
        bool Initialize() override;
        bool ReadMemory(uint64_t address, void* buffer, size_t size) override;
        bool WriteMemory(uint64_t address, const void* buffer, size_t size) override;
        uint64_t AllocateMemory(size_t size) override;
        bool FreeMemory(uint64_t address) override;
        bool ExecuteCode(uint64_t address) override;
        std::string GetName() const override { return "Physical Memory Access"; }
    };
}
