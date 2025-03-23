#pragma once
#include <Windows.h>
#include <vector>
#include <memory>
#include <random>
#include "../utils/intel_driver.hpp"
#include "../utils/logging.hpp"
#include "../utils/secure_memory.hpp"
#include "../nt.hpp"

// Class for establishing a secure bridge to the kernel
class KernelBridge {
public:
    // Singleton pattern
    static KernelBridge& GetInstance();
    
    // Connection management
    bool EstablishSecureChannel();
    bool SendCommand(const void* cmd, size_t size);
    bool ReceiveResponse(void* response, size_t size);
    void CloseChannel();
    
    // Memory operations
    bool ReadKernelMemory(uint64_t address, void* buffer, size_t size);
    bool WriteKernelMemory(uint64_t address, const void* buffer, size_t size);
    uint64_t AllocateKernelMemory(size_t size, nt::POOL_TYPE poolType = nt::NonPagedPool);
    bool FreeKernelMemory(uint64_t address);
    
    // Driver operations
    bool LoadDriver(const void* driverData, size_t size);
    bool UnloadDriver(uint64_t baseAddress);
    bool GetDriverInfo(uint64_t baseAddress, void* info, size_t infoSize);
    
    // Check if the channel is established
    bool IsChannelEstablished() const;
    
    // Get the last error message
    std::string GetLastErrorMessage() const;

private:
    // Private constructor for singleton pattern
    KernelBridge();
    
    // Private destructor
    ~KernelBridge();
    
    // Deleted copy and move operations
    KernelBridge(const KernelBridge&) = delete;
    KernelBridge& operator=(const KernelBridge&) = delete;
    KernelBridge(KernelBridge&&) = delete;
    KernelBridge& operator=(KernelBridge&&) = delete;
    
    // Encryption and decryption
    bool EncryptPayload(const void* input, size_t inputSize, std::vector<uint8_t>& output);
    bool DecryptPayload(const void* input, size_t inputSize, std::vector<uint8_t>& output);
    
    // Security features
    bool VerifyDriverSignature(const void* driverData, size_t size);
    bool ObfuscateMemoryAccess(uint64_t address, size_t size);
    bool HideDriverFromPatchGuard(uint64_t baseAddress);
    
    // Communication security
    bool EstablishEncryptedChannel();
    bool ValidateChannelIntegrity();
    void SecureChannelCleanup();
    
    // Set the last error message
    void SetLastError(const std::string& errorMessage);
    
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
    
    // Private members
    EncryptionKey m_channelKey;
    HANDLE m_channelHandle;
    bool m_isInitialized;
    std::string m_lastErrorMessage;
    
    // Pointer to the Intel driver
    IntelDriver* m_intelDriver;
};
