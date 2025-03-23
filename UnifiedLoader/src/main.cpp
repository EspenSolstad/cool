#include "core/secure_loader.hpp"
#include "core/dynamic_mapper.hpp"
#include "core/kernel_bridge.hpp"
#include "drivers/memdriver.hpp"
#include "drivers/rwdrv.hpp"
#include "drivers/cheat.hpp"
#include "utils/logging.hpp"
#include "utils/secure_memory.hpp"
#include <Windows.h>
#include <memory>
#include <thread>
#include <chrono>

class UnifiedLoader {
public:
    static bool Initialize() {
        // Hide console window
        ShowWindow(GetConsoleWindow(), SW_HIDE);
        
        LOG_INFO("Initializing secure loader...");
        
        auto& bridge = KernelBridge::GetInstance();
        if (!bridge.EstablishSecureChannel()) {
            LOG_ERROR("Failed to establish secure channel");
            return false;
        }

        loader = std::make_unique<SecureDriverLoader>();
        if (!loader->Initialize()) {
            LOG_ERROR("Failed to initialize secure loader");
            return false;
        }

        mapper = std::make_unique<DynamicMapper>();
        return true;
    }

    static bool LoadDrivers() {
        LOG_INFO("Loading system drivers...");

        // Load memdriver
        if (!loader->LoadDriver(memdriver, memdriver_len)) {
            LOG_ERROR("Failed to load memdriver");
            return false;
        }

        LOG_SUCCESS("memdriver loaded successfully");

        // Load rwdrv
        if (!mapper->MapDriver(rwdrv, rwdrv_len)) {
            LOG_ERROR("Failed to map rwdrv");
            return false;
        }

        LOG_SUCCESS("rwdrv mapped successfully");

        return true;
    }

    static bool LoadCheat() {
        LOG_INFO("Loading cheat module...");

        // Create secure memory region for cheat
        void* cheat_section = SecureMemory::AllocateSecure(cheat_len);
        if (!cheat_section) {
            LOG_ERROR("Failed to allocate secure memory for cheat");
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
            LOG_ERROR("Failed to execute cheat");
            return false;
        }

        LOG_SUCCESS("Cheat loaded successfully");
        return true;
    }

    static void Cleanup() {
        LOG_INFO("Performing secure cleanup...");

        if (mapper) {
            mapper->UnmapDriver();
        }

        if (loader) {
            loader->UnloadDriver();
        }

        auto& bridge = KernelBridge::GetInstance();
        bridge.CloseChannel();

        LOG_SUCCESS("Cleanup complete");
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

    LOG_INFO("Starting unified loader...");

    if (!UnifiedLoader::Initialize()) {
        LOG_ERROR("Initialization failed");
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

    LOG_SUCCESS("All components loaded successfully");
    
    // Keep the process running
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}
