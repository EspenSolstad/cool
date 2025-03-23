#pragma once
#include <Windows.h>
#include <vector>
#include <memory>
#include <random>
#include "../utils/logging.hpp"
#include "../utils/secure_memory.hpp"
#include "../utils/kdmapper.hpp"

// Encryption key structure
class EncryptionKey {
public:
    EncryptionKey() {
        key.resize(32); // 256-bit key
        iv.resize(16);  // 128-bit IV
        GenerateRandomBytes();
    }
    
    // Get the key data
    const uint8_t* GetKey() const { return key.data(); }
    size_t GetKeySize() const { return key.size(); }
    
    // Get the IV data
    const uint8_t* GetIV() const { return iv.data(); }
    size_t GetIVSize() const { return iv.size(); }

private:
    // Generate cryptographically secure random bytes
    void GenerateRandomBytes() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(0, 255);
        
        for (auto& byte : key) {
            byte = static_cast<uint8_t>(distrib(gen));
        }
        
        for (auto& byte : iv) {
            byte = static_cast<uint8_t>(distrib(gen));
        }
    }

    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;
};

// Driver encryption and loading
class SecureDriverLoader {
public:
    // Constructor
    SecureDriverLoader();
    
    // Destructor
    ~SecureDriverLoader();
    
    // Initialize the loader
    bool Initialize();
    
    // Load a driver from memory
    bool LoadDriver(const void* driverData, size_t size);
    
    // Load a driver from a resource
    bool LoadDriverFromResource(int resourceId);
    
    // Unload a loaded driver
    bool UnloadDriver();
    
    // Anti-detection methods
    void ObfuscateMemoryRegions();
    void HideThreads();
    void PreventMemoryDumps();
    
    // Check if the loader is initialized
    bool IsInitialized() const;
    
    // Check if a driver is loaded
    bool IsDriverLoaded() const;
    
    // Get the address of the loaded driver
    uint64_t GetDriverAddress() const;

private:
    // Implementation struct to hide private details
    struct Implementation;
    std::unique_ptr<Implementation> m_impl;
    
    // Private methods
    std::vector<uint8_t> EncryptDriver(const void* data, size_t size);
    bool DecryptDriver(const std::vector<uint8_t>& encrypted, std::vector<uint8_t>& decrypted);
    bool VerifyDriverIntegrity(const void* driverData, size_t size);
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
