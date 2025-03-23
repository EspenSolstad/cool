#include "utils/secure_memory.hpp"
#include "utils/logging.hpp"
#include <random>
#include <algorithm>

void* SecureMemory::AllocateSecure(size_t size) {
    if (size == 0) {
        LOG_ERROR(L"Cannot allocate zero bytes");
        return nullptr;
    }

    // Add random padding to avoid memory patterns
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(1024, 8192); // 1-8KB of padding
    size_t padding_size = dist(gen);
    size_t total_size = size + padding_size;

    // Allocate with PAGE_READWRITE initially
    void* memory = VirtualAlloc(nullptr, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!memory) {
        LOG_ERROR(L"Failed to allocate secure memory");
        return nullptr;
    }

    // Randomize the entire memory block first
    RandomizeMemory(memory, total_size);

    // Choose a random offset within the padding for the actual data
    std::uniform_int_distribution<size_t> offset_dist(0, padding_size);
    size_t offset = offset_dist(gen);
    
    // Return a pointer to the usable memory (after the random offset)
    return static_cast<uint8_t*>(memory) + offset;
}

bool SecureMemory::FreeSecure(void* memory, size_t size) {
    if (!memory || size == 0) {
        return false;
    }

    // Find the base address of the allocation
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(memory, &mbi, sizeof(mbi))) {
        LOG_ERROR(L"Failed to query memory information");
        return false;
    }

    // Securely wipe the entire memory region
    volatile uint8_t* p = static_cast<uint8_t*>(mbi.AllocationBase);
    for (size_t i = 0; i < mbi.RegionSize; i++) {
        p[i] = 0;
    }

    // Free the memory
    return VirtualFree(mbi.AllocationBase, 0, MEM_RELEASE);
}

void SecureMemory::RandomizeMemory(void* memory, size_t size) {
    if (!memory || !size) return;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    uint8_t* p = static_cast<uint8_t*>(memory);
    for (size_t i = 0; i < size; i++) {
        p[i] = dist(gen);
    }
}

bool SecureMemory::ProtectMemory(void* memory, size_t size, DWORD protection) {
    if (!memory || !size) return false;

    DWORD old_protect;
    return VirtualProtect(memory, size, protection, &old_protect);
}
