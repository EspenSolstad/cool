#pragma once
#include <Windows.h>
#include <cstdint>

class SecureMemory {
public:
    /**
     * Allocates secure memory with randomized padding and protection
     *
     * @param size Size of memory to allocate
     * @return Pointer to allocated memory or nullptr on failure
     */
    static void* AllocateSecure(size_t size);

    /**
     * Securely frees memory, wiping it before releasing
     *
     * @param memory Pointer to memory allocated with AllocateSecure
     * @param size Size of the allocated memory
     * @return true on success, false on failure
     */
    static bool FreeSecure(void* memory, size_t size);

private:
    static void RandomizeMemory(void* memory, size_t size);
    static bool ProtectMemory(void* memory, size_t size, DWORD protection);
};
