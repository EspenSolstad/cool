#include "secure_loader.hpp"
#include "intel_driver.hpp"
#include <random>

KernelBridge& KernelBridge::GetInstance() {
    static KernelBridge instance;
    return instance;
}

bool KernelBridge::EstablishSecureChannel() {
    if (is_initialized) {
        return true;
    }

    // Generate new encryption keys for this session
    channel_key = EncryptionKey();

    // Create secure channel handle
    channel_handle = intel_driver::Load();
    if (channel_handle == INVALID_HANDLE_VALUE) {
        return false;
    }

    is_initialized = true;
    return true;
}

bool KernelBridge::SendCommand(const void* cmd, size_t size) {
    if (!is_initialized || !cmd || !size) {
        return false;
    }

    std::vector<uint8_t> encrypted;
    if (!EncryptPayload(cmd, size, encrypted)) {
        return false;
    }

    // Send encrypted command to kernel
    return intel_driver::WriteMemory(channel_handle, 
        intel_driver::GetKernelModuleExport(channel_handle, intel_driver::ntoskrnlAddr, "NtQuerySystemInformation"),
        encrypted.data(), encrypted.size());
}

bool KernelBridge::ReceiveResponse(void* response, size_t size) {
    if (!is_initialized || !response || !size) {
        return false;
    }

    std::vector<uint8_t> encrypted(size);
    
    // Read encrypted response from kernel
    if (!intel_driver::WriteMemory(channel_handle,
        intel_driver::GetKernelModuleExport(channel_handle, intel_driver::ntoskrnlAddr, "NtQuerySystemInformation"),
        encrypted.data(), encrypted.size())) {
        return false;
    }

    std::vector<uint8_t> decrypted;
    if (!DecryptPayload(encrypted.data(), encrypted.size(), decrypted)) {
        return false;
    }

    if (decrypted.size() != size) {
        return false;
    }

    memcpy(response, decrypted.data(), size);
    return true;
}

void KernelBridge::CloseChannel() {
    if (!is_initialized) {
        return;
    }

    if (channel_handle != INVALID_HANDLE_VALUE) {
        intel_driver::Unload(channel_handle);
        channel_handle = INVALID_HANDLE_VALUE;
    }

    // Clear encryption keys
    SecureMemory::WipeMemory(channel_key.key.data(), channel_key.key.size());
    SecureMemory::WipeMemory(channel_key.iv.data(), channel_key.iv.size());

    is_initialized = false;
}

bool KernelBridge::EncryptPayload(const void* input, size_t input_size, std::vector<uint8_t>& output) {
    if (!input || !input_size) {
        return false;
    }

    output.resize(input_size);

    // XOR encryption with dynamic key generation
    for (size_t i = 0; i < input_size; i++) {
        uint8_t key_byte = channel_key.key[i % channel_key.key.size()];
        uint8_t iv_byte = channel_key.iv[i % channel_key.iv.size()];
        output[i] = static_cast<const uint8_t*>(input)[i] ^ key_byte ^ iv_byte;
    }

    return true;
}

bool KernelBridge::DecryptPayload(const void* input, size_t input_size, std::vector<uint8_t>& output) {
    if (!input || !input_size) {
        return false;
    }

    output.resize(input_size);

    // Reverse XOR encryption
    for (size_t i = 0; i < input_size; i++) {
        uint8_t key_byte = channel_key.key[i % channel_key.key.size()];
        uint8_t iv_byte = channel_key.iv[i % channel_key.iv.size()];
        output[i] = static_cast<const uint8_t*>(input)[i] ^ key_byte ^ iv_byte;
    }

    return true;
}
