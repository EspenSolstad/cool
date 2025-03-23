# Kernel Driver Loader

A Windows kernel driver loader with support for secure memory operations, dynamic mapping, and anti-detection features.

## Overview

KernelDriverLoader is a comprehensive tool designed for loading, managing, and securing Windows kernel mode drivers. It provides a clean, modular architecture with various security features.

## Features

- **Intel Driver Integration**: Uses Intel driver for low-level kernel operations
- **Dynamic Mapping**: Advanced memory protection for mapped drivers
- **Secure Loading**: Encrypted driver loading with integrity verification
- **Anti-Detection**: Methods to hide from security monitoring systems
- **User-Friendly Interface**: Simple console interface for common operations

## Building the Project

### Prerequisites
- Windows 10/11
- Visual Studio 2022 with C++ desktop development workload
- Administrator privileges (to run the application)

### Build Options

#### Using Visual Studio
1. Open `KernelDriverLoader.sln` in Visual Studio 2022
2. Select configuration (Debug/Release) and platform (x64)
3. Build the solution (F7 or Build → Build Solution)

#### Using Batch File
1. Run `build.bat` from the command prompt
2. This will build both Debug and Release configurations

## Running the Application

The application **requires administrator privileges** to function correctly as it interacts with kernel mode components.

### From Visual Studio
- Right-click the project → Debug → Start New Instance

### From Explorer
1. Navigate to `bin\Debug\` or `bin\Release\` folder
2. Right-click `KernelDriverLoader.exe` and select "Run as administrator"

## Usage

The application provides a menu-driven interface with the following options:
1. Map Intel driver
2. Map RwDrv driver 
3. Map MemDriver
4. Map Cheat driver
5. Map custom driver
6. Unmap driver
7. Exit

## Architecture

The project is organized into several components:

- **Core Components**
  - SecureLoader: Handles encrypted driver loading
  - DynamicMapper: Manages memory protection features
  - KernelBridge: Provides communication with the kernel

- **Utility Components**
  - IntelDriver: Base driver for kernel operations
  - KDMapper: Maps drivers into kernel space
  - PortableExecutable: Handles PE file operations
  - SecureMemory: Manages secure memory allocations

## Security Note

This tool is designed for legitimate system development and testing purposes. It should be used responsibly and in compliance with applicable laws and regulations.
