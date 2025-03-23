#pragma once
#include <Windows.h>
#include <vector>
#include "../utils/intel_driver.hpp"

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
        void GenerateRandomBytes(uint8_t* buffer, size_t size);
    };

    EncryptionKey channel_key;
    HANDLE channel_handle = INVALID_HANDLE_VALUE;
    bool is_initialized = false;
};
