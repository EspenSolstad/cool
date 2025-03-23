#pragma once
#include <Windows.h>
#include <memory>
#include <vector>
#include <string>

// Enum for allocation modes
enum class AllocationMode {
    AllocatePool,     // Regular pool allocation
    AllocateSecure    // Secure memory that is cleaned up automatically
};

// Class for secure memory handling that automatically zeroes memory when destroyed
class SecureMemory {
public:
    // Constructor for a new buffer of specified size
    SecureMemory(size_t size) 
        : m_size(size), m_buffer(nullptr) {
        if (size > 0) {
            m_buffer = static_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
            if (!m_buffer) {
                throw std::runtime_error("Failed to allocate secure memory");
            }
        }
    }

    // Constructor from existing buffer - takes ownership
    SecureMemory(void* buffer, size_t size) 
        : m_size(size), m_buffer(static_cast<uint8_t*>(buffer)) {
    }

    // Move constructor
    SecureMemory(SecureMemory&& other) noexcept
        : m_buffer(other.m_buffer), m_size(other.m_size) {
        other.m_buffer = nullptr;
        other.m_size = 0;
    }

    // No copy constructor
    SecureMemory(const SecureMemory&) = delete;
    SecureMemory& operator=(const SecureMemory&) = delete;

    // Move assignment
    SecureMemory& operator=(SecureMemory&& other) noexcept {
        if (this != &other) {
            Free();
            m_buffer = other.m_buffer;
            m_size = other.m_size;
            other.m_buffer = nullptr;
            other.m_size = 0;
        }
        return *this;
    }

    // Destructor - securely wipes memory
    ~SecureMemory() {
        Free();
    }

    // Get buffer pointer
    uint8_t* Get() const {
        return m_buffer;
    }

    // Get buffer size
    size_t Size() const {
        return m_size;
    }

    // Cast operator
    operator uint8_t*() const {
        return m_buffer;
    }

    // Free the memory securely
    void Free() {
        if (m_buffer) {
            // First overwrite with zeros
            SecureZeroMemory(m_buffer, m_size);
            // Then free the memory
            VirtualFree(m_buffer, 0, MEM_RELEASE);
            m_buffer = nullptr;
        }
        m_size = 0;
    }

private:
    uint8_t* m_buffer;
    size_t m_size;
};

// Global helper functions for memory allocation
namespace memory {
    // Allocate memory (simple or secure)
    inline void* Allocate(size_t size, AllocationMode mode = AllocationMode::AllocatePool) {
        if (size == 0) return nullptr;

        void* memory = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!memory) return nullptr;

        if (mode == AllocationMode::AllocateSecure) {
            // For secure allocations, we zero the memory
            SecureZeroMemory(memory, size);
        }

        return memory;
    }

    // Free memory (simple or secure)
    inline void Free(void* memory, size_t size, AllocationMode mode = AllocationMode::AllocatePool) {
        if (!memory) return;

        if (mode == AllocationMode::AllocateSecure) {
            // For secure deallocations, we zero the memory first
            SecureZeroMemory(memory, size);
        }

        VirtualFree(memory, 0, MEM_RELEASE);
    }

    // Convenience functions that match the original function names
    inline void* AllocatePool(size_t size) {
        return Allocate(size, AllocationMode::AllocatePool);
    }

    inline void* AllocateSecure(size_t size) {
        return Allocate(size, AllocationMode::AllocateSecure);
    }

    inline void FreePool(void* memory) {
        if (memory) VirtualFree(memory, 0, MEM_RELEASE);
    }

    inline void FreeSecure(void* memory, size_t size) {
        Free(memory, size, AllocationMode::AllocateSecure);
    }
}
