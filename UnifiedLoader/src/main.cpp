#include "core/secure_loader.hpp"
#include "core/dynamic_mapper.hpp"
#include "core/kernel_bridge.hpp"
#include "drivers/memdriver.hpp"
#include "drivers/rwdrv.hpp"
#include "drivers/cheat.hpp"
#include <Windows.h>
#include <iostream>
#include <memory>
#include <thread>
#include <chrono>

class UnifiedLoader {
public:
    static bool Initialize() {
        // Hide console window
        ShowWindow(GetConsoleWindow(), SW_HIDE);
        
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
        if (!loader->LoadDriver(memdriver, memdriver_len)) {
            std::cerr << "[-] Failed to load memdriver\n";
            return false;
        }

        std::cout << "[+] memdriver loaded successfully\n";

        // Load rwdrv
        if (!mapper->MapDriver(rwdrv, rwdrv_len)) {
            std::cerr << "[-] Failed to map rwdrv\n";
            return false;
        }

        std::cout << "[+] rwdrv mapped successfully\n";

        return true;
    }

    static bool LoadCheat() {
        std::cout << "[*] Loading cheat module...\n";

        // Create secure memory region for cheat
        void* cheat_section = SecureMemory::AllocateSecure(cheat_len);
        if (!cheat_section) {
            std::cerr << "[-] Failed to allocate secure memory for cheat\n";
            return false;
        }

        // Copy cheat to secure memory
        memcpy(cheat_section, cheat, cheat_len);

        // Execute cheat from memory
        using CheatEntry = void(*)();
        auto entry = reinterpret_cast<CheatEntry>(cheat_section);
        
        try {
            entry();
        }
        catch (...) {
            SecureMemory::FreeSecure(cheat_section, cheat_len);
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

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Create console for output
    AllocConsole();
    FILE* fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);

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
