#pragma once
#include "KernelMemoryAccess.h"
#include <vector>

namespace kernel {
    // Driver-based memory access implementation
    class PhysicalMemoryAccessor : public MemoryAccessor {
    private:
        uint64_t cr3Value = 0; // Control Register 3 (Page Directory Base)
        
        // Memory allocations tracking
        struct Allocation {
            uint64_t address;
            size_t size;
        };
        std::vector<Allocation> allocations;
        
        // Memory page size
        const size_t PAGE_SIZE = 0x1000;
        
        // Internal functions
        bool GetCR3Value();
        bool ElevateProcessPrivileges();
        bool CheckDriverAccess();
        
        // Driver communication methods
        bool GetProcessCr3ValueViaDriver(DWORD processId, uint64_t& cr3Value);
        
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
        std::string GetName() const override { return "Driver Memory Access"; }
        
        // Additional helper methods
        bool GetProcessCr3Value(DWORD processId, uint64_t& cr3ValueOut);
    };
}
