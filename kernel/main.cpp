#include "secure_loader.hpp"
#include "intel_driver.hpp"
#include "kdmapper.hpp"
#include "memdriver.hpp"
#include "rwdrv.hpp"
#include "cheat.hpp"
#include <iostream>
#include <memory>
#include <thread>
#include <chrono>

class UnifiedLoader {
public:
    static bool Initialize() {
        std::cout << "[*] Initializing secure loader...\n";
        
        auto& bridge = KernelBridge::GetInstance();
        if (!bridge.EstablishSecureChannel()) {
            std::cerr << "[-] Failed to establish secure channel\n";
            return false;
        }

        loader = std::make_unique<SecureDriverLoader>();
        if (!loader->Initialize()) {
            std::cerr << "[-] Failed to initialize secure loader\n";
            return false;
        }

        mapper = std::make_unique<DynamicMapper>();
        return true;
    }

    static bool LoadDrivers() {
        std::cout << "[*] Loading system drivers...\n";

        // Load memdriver
        std::vector<uint8_t> mem_driver(memdriver, memdriver + memdriver_len);
        if (!loader->LoadDriver(mem_driver.data(), mem_driver.size())) {
            std::cerr << "[-] Failed to load memdriver\n";
            return false;
        }

        std::cout << "[+] memdriver loaded successfully\n";

        // Load rwdrv
        std::vector<uint8_t> rw_driver(rwdrv, rwdrv + rwdrv_len);
        if (!mapper->MapDriver(rw_driver.data(), rw_driver.size())) {
            std::cerr << "[-] Failed to map rwdrv\n";
            return false;
        }

        std::cout << "[+] rwdrv mapped successfully\n";

        return true;
    }

    static bool LoadCheat() {
        std::cout << "[*] Loading cheat module...\n";

        // Load cheat in memory
        std::vector<uint8_t> cheat_data(cheat, cheat + cheat_len);
        
        // Create secure memory region for cheat
        void* cheat_section = SecureMemory::AllocateSecure(cheat_data.size());
        if (!cheat_section) {
            std::cerr << "[-] Failed to allocate secure memory for cheat\n";
            return false;
        }

        // Copy cheat to secure memory
        memcpy(cheat_section, cheat_data.data(), cheat_data.size());

        // Execute cheat from memory
        using CheatEntry = void(*)();
        auto entry = reinterpret_cast<CheatEntry>(cheat_section);
        
        try {
            entry();
        }
        catch (...) {
            SecureMemory::FreeSecure(cheat_section, cheat_data.size());
            std::cerr << "[-] Failed to execute cheat\n";
            return false;
        }

        std::cout << "[+] Cheat loaded successfully\n";
        return true;
    }

    static void Cleanup() {
        std::cout << "[*] Performing secure cleanup...\n";

        if (mapper) {
            mapper->UnmapDriver();
        }

        if (loader) {
            loader->UnloadDriver();
        }

        auto& bridge = KernelBridge::GetInstance();
        bridge.CloseChannel();

        std::cout << "[+] Cleanup complete\n";
    }

private:
    static std::unique_ptr<SecureDriverLoader> loader;
    static std::unique_ptr<DynamicMapper> mapper;
};

std::unique_ptr<SecureDriverLoader> UnifiedLoader::loader;
std::unique_ptr<DynamicMapper> UnifiedLoader::mapper;

int main() {
    std::cout << "[*] Starting unified loader...\n";

    if (!UnifiedLoader::Initialize()) {
        std::cerr << "[-] Initialization failed\n";
        return -1;
    }

    if (!UnifiedLoader::LoadDrivers()) {
        UnifiedLoader::Cleanup();
        return -1;
    }

    // Small delay to ensure drivers are ready
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    if (!UnifiedLoader::LoadCheat()) {
        UnifiedLoader::Cleanup();
        return -1;
    }

    std::cout << "[✓] All components loaded successfully\n";
    
    // Keep the process running
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}
