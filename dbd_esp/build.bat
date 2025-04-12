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
echo [*] Cleaning previous build...
if exist "dist\DBD-ESP.exe" (
    del /f /q "dist\DBD-ESP.exe" >nul 2>&1
    if exist "dist\DBD-ESP.exe" (
        echo [-] Failed to remove previous executable
        echo [!] Please close any running instances of DBD-ESP
        pause
        exit /b 1
    )
)
if exist "dist\DBD-ESP-Debug.exe" (
    del /f /q "dist\DBD-ESP-Debug.exe" >nul 2>&1
    if exist "dist\DBD-ESP-Debug.exe" (
        echo [-] Failed to remove previous debug executable
        echo [!] Please close any running instances of DBD-ESP-Debug
        pause
        exit /b 1
    )
)

REM Remove build directories
if exist "dist" rmdir /s /q "dist" >nul 2>&1
if exist "build" rmdir /s /q "build" >nul 2>&1
if exist "*.spec" del /f /q *.spec >nul 2>&1

REM Create clean directories
mkdir dist >nul 2>&1
mkdir build >nul 2>&1

REM Create temporary work directory
set "TEMP_DIR=%TEMP%\dbd_esp_build"
if exist "%TEMP_DIR%" rmdir /s /q "%TEMP_DIR%" >nul 2>&1
mkdir "%TEMP_DIR%" >nul 2>&1

REM Build console version for debugging
echo [*] Building console version...
pyinstaller --noconfirm --onefile --workpath "%TEMP_DIR%\build" --distpath "dist" ^
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
    --name "DBD-ESP-Debug" ^
    run.py

REM Build non-console version
echo [*] Building release version...
pyinstaller --noconfirm --onefile --noconsole --workpath "%TEMP_DIR%\build" --distpath "dist" ^
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
echo [*] Executables created:
echo     - dist\DBD-ESP.exe (Release version)
echo     - dist\DBD-ESP-Debug.exe (Debug version)
echo.
echo [!] If the release version doesn't work:
echo     1. Run DBD-ESP-Debug.exe to see error messages
echo     2. Check error.log for detailed error information
echo.

REM Ask if user wants to run the ESP
set /p run_now="Do you want to run the ESP now? (Y/N) "
if /i "%run_now%"=="Y" (
    echo.
    echo [*] Choose version to run:
    echo     1. Release version (DBD-ESP.exe)
    echo     2. Debug version (DBD-ESP-Debug.exe)
    set /p version="Enter choice (1/2): "
    
    if "%version%"=="1" (
        echo.
        echo [*] Starting release version...
        echo [!] Remember to have Dead by Daylight running!
        echo.
        start "" "dist\DBD-ESP.exe"
    ) else if "%version%"=="2" (
        echo.
        echo [*] Starting debug version...
        echo [!] Remember to have Dead by Daylight running!
        echo.
        start "" "dist\DBD-ESP-Debug.exe"
    ) else (
        echo.
        echo [-] Invalid choice
    )
)

echo.
echo [*] You can find both executables in the dist folder
echo [!] Always run as administrator!
echo [!] Use debug version if you encounter problems
echo.

REM Clean up temporary files
echo [*] Cleaning up...
if exist "%TEMP_DIR%" rmdir /s /q "%TEMP_DIR%" >nul 2>&1
if exist "*.spec" del /f /q *.spec >nul 2>&1
if exist "%TEMP_DIR%\*.spec" del /f /q "%TEMP_DIR%\*.spec" >nul 2>&1

echo [+] Cleanup complete
echo.
pause
