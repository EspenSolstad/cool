#include <Windows.h>
#include <iostream>
#include <string>
#include <conio.h>
#include <shlobj.h>
#include <limits>
#include "../includes/utils/logging.hpp"
#include "../includes/core/driver_manager.hpp"
#include "../resources/resource.h"

// Print application banner
void PrintBanner() {
    system("cls");
    std::cout << "===================================================" << std::endl;
    std::cout << "          Kernel Driver Loader v1.0.0              " << std::endl;
    std::cout << "===================================================" << std::endl;
    std::cout << std::endl;
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

// Main application function
int main() {
    // Set up console window
    SetConsoleTitle(L"Kernel Driver Loader");
    
    // Set the log level
    Logger::SetLogLevel(LogLevel::Info);
    
    // Display the banner
    PrintBanner();
    
    // Require administrator privileges
    if (IsUserAnAdmin() == false) {
        Logger::LogCritical("This application requires administrator privileges");
        std::cout << "Press any key to exit..." << std::endl;
        (void)_getch();
        return 1;
    }
    
    // Get the driver manager and initialize it
    DriverManager& driverManager = GetDriverManager();
    if (driverManager.Initialize() == false) {
        Logger::LogCritical("Failed to initialize application");
        std::cout << "Press any key to exit..." << std::endl;
        (void)_getch();
        driverManager.Cleanup();
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
            driverManager.MapIntelDriver();
            break;
        case 2:
            driverManager.MapRwDrvDriver();
            break;
        case 3:
            driverManager.MapMemDriver();
            break;
        case 4:
            driverManager.MapCheatDriver();
            break;
        case 5:
            {
                std::string driverPath;
                std::cout << "Enter driver path: ";
                std::cin >> driverPath;
                driverManager.MapCustomDriver(driverPath);
            }
            break;
        case 6:
            driverManager.UnmapDriver();
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
    driverManager.Cleanup();
    
    return 0;
}
