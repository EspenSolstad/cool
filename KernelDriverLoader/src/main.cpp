#include <Windows.h>
#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <filesystem>
#include <fstream>
#include <conio.h>
#include <shlobj.h>
#include <limits>
#include <algorithm>
#include "../includes/utils/logging.hpp"
#include "../includes/utils/resource_utils.hpp"
#include "../includes/utils/intel_driver.hpp"
#include "../includes/utils/kdmapper.hpp"
#include "../includes/core/secure_loader.hpp"
#include "../includes/core/dynamic_mapper.hpp"
#include "../includes/core/kernel_bridge.hpp"
#include "../resources/resource.h"

// Global instances
std::unique_ptr<IntelDriver, std::default_delete<IntelDriver>> g_intelDriver;
std::unique_ptr<KDMapper, std::default_delete<KDMapper>> g_kdMapper;
std::unique_ptr<DynamicMapper, std::default_delete<DynamicMapper>> g_dynamicMapper;

// Print application banner
void PrintBanner() {
    system("cls");
    std::cout << "===================================================" << std::endl;
    std::cout << "          Kernel Driver Loader v1.0.0              " << std::endl;
    std::cout << "===================================================" << std::endl;
    std::cout << std::endl;
}

// Initialize the application
bool Initialize() {
    // Initialize the Intel driver
    g_intelDriver = std::make_unique<IntelDriver>();
    if (!g_intelDriver) {
        Logger::LogError("Failed to create Intel driver instance");
        return false;
    }

    // Load the Intel driver
    if (!g_intelDriver->Load()) {
        Logger::LogError("Failed to load Intel driver");
        return false;
    }

    Logger::LogInfo("Intel driver loaded successfully");

    // Initialize the KDMapper
    g_kdMapper = std::make_unique<KDMapper>(g_intelDriver.get());
    if (!g_kdMapper) {
        Logger::LogError("Failed to create KDMapper instance");
        return false;
    }

    Logger::LogInfo("KDMapper initialized successfully");

    // Initialize the Dynamic Mapper
    g_dynamicMapper = std::make_unique<DynamicMapper>();
    if (!g_dynamicMapper) {
        Logger::LogError("Failed to create Dynamic Mapper instance");
        return false;
    }

    Logger::LogInfo("Dynamic Mapper initialized successfully");

    return true;
}

// Cleanup resources
void Cleanup() {
    // Clean up in reverse order of initialization
    
    Logger::LogInfo("Cleaning up resources...");
    
    // Unmap any loaded drivers
    if (g_dynamicMapper && g_dynamicMapper.get()->IsDriverMapped()) {
        if (g_dynamicMapper.get()->UnmapDriver()) {
            Logger::LogInfo("Dynamic driver unmapped successfully");
        }
        else {
            Logger::LogWarning("Failed to unmap dynamic driver");
        }
    }
    
    // Release Dynamic Mapper
    g_dynamicMapper.reset();
    
    // Release KDMapper
    g_kdMapper.reset();
    
    // Unload the Intel driver
    if (g_intelDriver) {
        if (g_intelDriver->Unload()) {
            Logger::LogInfo("Intel driver unloaded successfully");
        }
        else {
            Logger::LogWarning("Failed to unload Intel driver");
        }
        
        g_intelDriver.reset();
    }
    
    Logger::LogInfo("Cleanup completed");
}

// Display menu
void DisplayMenu() {
    std::cout << "Menu Options:" << std::endl;
    std::cout << "1. Map Intel driver" << std::endl;
    std::cout << "2. Map RwDrv driver" << std::endl;
    std::cout << "3. Map MemDriver" << std::endl;
    std::cout << "4. Map Cheat driver" << std::endl;
    std::cout << "5. Map custom driver" << std::endl;
    std::cout << "6. Unmap driver" << std::endl;
    std::cout << "7. Exit" << std::endl;
    std::cout << "Enter your choice: ";
}

// Handle Intel driver mapping
bool MapIntelDriver() {
    Logger::LogInfo("Mapping Intel driver...");
    
    uint64_t driverBase = 0;
    if (g_kdMapper.get()->MapDriverFromResource(DRIVER_INTEL_RESOURCE, &driverBase)) {
        Logger::LogInfo("Intel driver mapped successfully at 0x{:X}", driverBase);
        return true;
    }
    else {
        Logger::LogError("Failed to map Intel driver: {}", g_kdMapper.get()->GetLastErrorMessage());
        return false;
    }
}

// Handle RwDrv driver mapping
bool MapRwDrvDriver() {
    Logger::LogInfo("Mapping RwDrv driver...");
    
    uint64_t driverBase = 0;
    if (g_kdMapper.get()->MapDriverFromResource(DRIVER_RWDRV_RESOURCE, &driverBase)) {
        Logger::LogInfo("RwDrv driver mapped successfully at 0x{:X}", driverBase);
        return true;
    }
    else {
        Logger::LogError("Failed to map RwDrv driver: {}", g_kdMapper.get()->GetLastErrorMessage());
        return false;
    }
}

// Handle MemDriver mapping
bool MapMemDriver() {
    Logger::LogInfo("Mapping MemDriver...");
    
    uint64_t driverBase = 0;
    if (g_kdMapper.get()->MapDriverFromResource(DRIVER_MAPPER_RESOURCE, &driverBase)) {
        Logger::LogInfo("MemDriver mapped successfully at 0x{:X}", driverBase);
        return true;
    }
    else {
        Logger::LogError("Failed to map MemDriver: {}", g_kdMapper.get()->GetLastErrorMessage());
        return false;
    }
}

// Handle Cheat driver mapping
bool MapCheatDriver() {
    Logger::LogInfo("Mapping Cheat driver...");
    
    uint64_t driverBase = 0;
    if (g_kdMapper.get()->MapDriverFromResource(DRIVER_CHEAT_RESOURCE, &driverBase)) {
        Logger::LogInfo("Cheat driver mapped successfully at 0x{:X}", driverBase);
        return true;
    }
    else {
        Logger::LogError("Failed to map Cheat driver: {}", g_kdMapper.get()->GetLastErrorMessage());
        return false;
    }
}

// Handle custom driver mapping
bool MapCustomDriver() {
    std::string driverPath;
    std::cout << "Enter driver path: ";
    std::cin >> driverPath;
    
    if (!std::filesystem::exists(driverPath)) {
        Logger::LogError("Driver file not found: {}", driverPath);
        return false;
    }
    
    Logger::LogInfo("Mapping custom driver: {}", driverPath);
    
    // Read the driver file
    std::ifstream file(driverPath, std::ios::binary);
    if (!file) {
        Logger::LogError("Failed to open driver file: {}", driverPath);
        return false;
    }
    
    // Get file size
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // Read the file data
    std::vector<uint8_t> driverData(fileSize);
    file.read(reinterpret_cast<char*>(driverData.data()), fileSize);
    file.close();
    
    // Map the driver
    uint64_t driverBase = 0;
    if (g_kdMapper.get()->MapDriver(driverData.data(), driverData.size(), &driverBase)) {
        Logger::LogInfo("Custom driver mapped successfully at 0x{:X}", driverBase);
        return true;
    }
    else {
        Logger::LogError("Failed to map custom driver: {}", g_kdMapper.get()->GetLastErrorMessage());
        return false;
    }
}

// Handle driver unmapping
bool UnmapDriver() {
    if (!g_dynamicMapper.get()->IsDriverMapped()) {
        Logger::LogWarning("No driver is currently mapped");
        return false;
    }
    
    uint64_t driverBase = g_dynamicMapper.get()->GetMappedDriverBase();
    Logger::LogInfo("Unmapping driver at 0x{:X}...", driverBase);
    
    if (g_dynamicMapper.get()->UnmapDriver()) {
        Logger::LogInfo("Driver unmapped successfully");
        return true;
    }
    else {
        Logger::LogError("Failed to unmap driver: {}", g_dynamicMapper.get()->GetLastErrorMessage());
        return false;
    }
}

// Main application function
int main() {
    // Set up console window
    SetConsoleTitle(L"Kernel Driver Loader");
    
    // Set the log level
    Logger::SetLogLevel(LogLevel::Info);
    
    // Display the banner
    PrintBanner();
    
    // Require administrator privileges
    if (!IsUserAnAdmin()) {
        Logger::LogCritical("This application requires administrator privileges");
        std::cout << "Press any key to exit..." << std::endl;
        (void)_getch();
        return 1;
    }
    
    // Initialize the application
    if (!Initialize()) {
        Logger::LogCritical("Failed to initialize application");
        std::cout << "Press any key to exit..." << std::endl;
        (void)_getch();
        Cleanup();
        return 1;
    }
    
    // Main application loop
    bool running = true;
    while (running) {
        DisplayMenu();
        
        int choice;
        std::cin >> choice;
        
        switch (choice) {
        case 1:
            MapIntelDriver();
            break;
        case 2:
            MapRwDrvDriver();
            break;
        case 3:
            MapMemDriver();
            break;
        case 4:
            MapCheatDriver();
            break;
        case 5:
            MapCustomDriver();
            break;
        case 6:
            UnmapDriver();
            break;
        case 7:
            running = false;
            break;
        default:
            Logger::LogWarning("Invalid choice");
            break;
        }
        
        std::cout << std::endl;
        std::cout << "Press Enter to continue...";
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cin.get();
        system("cls");
        PrintBanner();
    }
    
    // Clean up resources
    Cleanup();
    
    return 0;
}
