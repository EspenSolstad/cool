#pragma once
#include <Windows.h>
#include <vector>
#include "utils/intel_driver.hpp"

class KernelBridge {
public:
    static KernelBridge& GetInstance();
    
    bool EstablishSecureChannel();
    bool SendCommand(const void* cmd, size_t size);
    bool ReceiveResponse(void* response, size_t size);
    void CloseChannel();

    // Memory operations
    bool ReadKernelMemory(ULONGLONG address, void* buffer, size_t size);
    bool WriteKernelMemory(ULONGLONG address, const void* buffer, size_t size);
    ULONGLONG AllocateKernelMemory(size_t size);
    bool FreeKernelMemory(ULONGLONG address);

    // Driver operations
    bool LoadDriver(const void* driver_data, size_t size);
    bool UnloadDriver(ULONGLONG base_address);
    bool GetDriverInfo(ULONGLONG base_address, void* info, size_t info_size);

private:
    KernelBridge() = default;
    ~KernelBridge() = default;
    KernelBridge(const KernelBridge&) = delete;
    KernelBridge& operator=(const KernelBridge&) = delete;

    bool EncryptPayload(const void* input, size_t input_size, std::vector<uint8_t>& output);
    bool DecryptPayload(const void* input, size_t input_size, std::vector<uint8_t>& output);
    
    // Security features
    bool VerifyDriverSignature(const void* driver_data, size_t size);
    bool ObfuscateMemoryAccess(ULONGLONG address, size_t size);
    bool HideDriverFromPatchGuard(ULONGLONG base_address);
    
    // Communication security
    bool EstablishEncryptedChannel();
    bool ValidateChannelIntegrity();
    void SecureChannelCleanup();

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

    EncryptionKey channel_key;
    HANDLE channel_handle = INVALID_HANDLE_VALUE;
    bool is_initialized = false;
};
