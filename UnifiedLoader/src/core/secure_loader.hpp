#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <memory>
#include <cstdint>

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

// Kernel communication bridge
class KernelBridge {
public:
    static KernelBridge& GetInstance();
    
    bool EstablishSecureChannel();
    bool SendCommand(const void* cmd, size_t size);
    bool ReceiveResponse(void* response, size_t size);
    void CloseChannel();

private:
    KernelBridge() = default;
    ~KernelBridge() = default;
    KernelBridge(const KernelBridge&) = delete;
    KernelBridge& operator=(const KernelBridge&) = delete;

    bool EncryptPayload(const void* input, size_t input_size, std::vector<uint8_t>& output);
    bool DecryptPayload(const void* input, size_t input_size, std::vector<uint8_t>& output);
    
    EncryptionKey channel_key;
    HANDLE channel_handle;
    bool is_initialized;
};

// Driver verification and mapping
class DynamicMapper {
public:
    DynamicMapper();
    ~DynamicMapper();

    bool MapDriver(const void* driver_data, size_t size);
    bool UnmapDriver();
    
    // Memory section management
    void* CreateSecureSection(size_t size);
    bool FreeSecureSection(void* section);
    
    // Verification
    bool VerifyMapping();
    bool CheckIntegrity();

private:
    struct MappingContext;
    std::unique_ptr<MappingContext> context;

    bool SetupMapping();
    bool ConfigureProtection();
    void RemoveTraces();
};
