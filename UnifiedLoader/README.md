# UnifiedLoader

A secure system utility for loading drivers and modules.

## Project Structure

- `src/` - Source code files
- `include/` - Header files
- `resources/` - Resource files (icons, manifests, etc.)
- `tools/` - Utility tools for the build process

## Building with Visual Studio 2022

This project now uses Visual Studio 2022 instead of CMake for a more streamlined development experience.

### Prerequisites

- Visual Studio 2022 with C++ development workload
- Windows 10/11 SDK

### Build Instructions

#### Method 1: Using the Build Script

1. Run `vs_build.bat` to automatically build the project
2. The executable will be located at `bin\Release\UnifiedLoader.exe`

#### Method 2: Opening in Visual Studio

1. Open `UnifiedLoader.sln` in Visual Studio 2022
2. Select the desired configuration (Debug or Release)
3. Build → Build Solution (or press F7)

## Project Components

### Main Projects

- **UnifiedLoader** - Main application for secure driver loading
- **bin2header** - Utility for converting binary files to C++ headers

### Core Components

- **KernelBridge** - Communication layer with kernel-mode drivers
- **DynamicMapper** - Dynamic driver mapping system
- **SecureLoader** - Secure loading mechanism for drivers

## Development Notes

- The project compiles for x64 platforms only
- Using C++17 standard
- All warnings are treated as errors
- Security features enabled: Control Flow Guard, Buffer Security Check

## Binary Resources

The project automatically converts the following binary files to headers during the build process:

- `src/drivers/memdriver.sys` → `include/drivers/memdriver.hpp`
- `src/drivers/RwDrv.sys` → `include/drivers/rwdrv.hpp`
- `src/drivers/ExternalCheat.exe` → `include/drivers/cheat.hpp`

This conversion happens as a pre-build event for the main project.
