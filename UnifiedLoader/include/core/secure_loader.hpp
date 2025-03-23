#pragma once
#include <Windows.h>
#include <vector>
#include <memory>

// Forward declarations
namespace kdmapper {
    enum class AllocationMode {
        AllocatePool,
        AllocateIndependentPages
    };
}

// Encryption key structure
struct EncryptionKey {
    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;
    
    EncryptionKey() {
        key.resize(32); // 256-bit key
        iv.resize(16);  // 128-bit IV
        GenerateRandomBytes(key.data(), key.size());
        GenerateRandomBytes(iv.data(), iv.size());
    }

private:
    void GenerateRandomBytes(uint8_t* buffer, size_t size) {
        for (size_t i = 0; i < size; i++) {
            buffer[i] = static_cast<uint8_t>(rand() % 256);
        }
    }
};

// Secure memory management
class SecureMemory {
public:
    static void* AllocateSecure(size_t size);
    static void FreeSecure(void* ptr, size_t size);
    static void WipeMemory(void* ptr, size_t size);
    static bool ProtectRegion(void* ptr, size_t size, DWORD protection);
};

// Driver encryption and loading
class SecureDriverLoader {
public:
    SecureDriverLoader();
    ~SecureDriverLoader();

    bool Initialize();
    bool LoadDriver(const void* driver_data, size_t size);
    bool UnloadDriver();
    
    // Anti-detection methods
    void ObfuscateMemoryRegions();
    void HideThreads();
    void PreventMemoryDumps();

private:
    struct Implementation;
    std::unique_ptr<Implementation> impl;

    std::vector<uint8_t> EncryptDriver(const void* data, size_t size);
    bool DecryptDriver(const std::vector<uint8_t>& encrypted, std::vector<uint8_t>& decrypted);
    bool VerifyDriverIntegrity(const void* driver_data, size_t size);
    void CleanupTraces();

    // Memory protection
    bool SetupMemoryProtection();
    bool HideMemoryRegions();
    
    // Thread management
    bool SecureThreadCreation();
    void ObfuscateThreadContext();

    // Anti-debugging
    void InstallAntiDebugHooks();
    bool CheckForDebugger();
    void PreventAttachment();
};
