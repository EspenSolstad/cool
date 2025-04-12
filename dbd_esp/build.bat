@echo off
echo =========================================
echo   Dead by Daylight ESP - Build & Run
echo =========================================
echo.

REM Check for admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] This script requires administrator privileges
    echo [!] Please right-click and select "Run as administrator"
    pause
    exit /b 1
)

REM Set working directory to script location
cd /d "%~dp0"

REM Activate virtual environment
call venv\Scripts\activate.bat || (
    echo [-] Virtual environment not found
    echo [!] Please run install.bat first
    pause
    exit /b 1
)

echo [*] Building ESP executable...
echo.

REM Clean previous build
if exist "dist" rmdir /s /q "dist"
if exist "build" rmdir /s /q "build"

REM Build with PyInstaller
pyinstaller --noconfirm --onefile --noconsole ^
    --hidden-import win32api ^
    --hidden-import win32con ^
    --hidden-import win32process ^
    --hidden-import win32security ^
    --hidden-import win32event ^
    --hidden-import win32service ^
    --hidden-import win32serviceutil ^
    --hidden-import win32ts ^
    --hidden-import pygame ^
    --hidden-import numpy ^
    --hidden-import psutil ^
    --hidden-import pymem ^
    --hidden-import src ^
    --hidden-import src.memory ^
    --hidden-import src.entity ^
    --hidden-import src.overlay ^
    --hidden-import src.process_utils ^
    --hidden-import src.offsets ^
    --add-data "src;src" ^
    --name "DBD-ESP" ^
    run.py

if %ERRORLEVEL% neq 0 (
    echo.
    echo [-] Build failed!
    pause
    exit /b 1
)

echo.
echo [+] Build successful!
echo [*] Executable created at: dist\run.exe
echo.

REM Ask if user wants to run the ESP
set /p run_now="Do you want to run the ESP now? (Y/N) "
if /i "%run_now%"=="Y" (
    echo.
    echo [*] Starting ESP...
    echo [!] Remember to have Dead by Daylight running!
    echo.
    start "" "dist\run.exe"
)

echo.
echo [*] You can find the ESP executable in the dist folder
echo [*] Always run as administrator!
echo.

pause
