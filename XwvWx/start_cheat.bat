@echo off
REM Change to the directory containing this batch file
cd /d "%~dp0"

echo =========================================
echo   Dead By Daylight Cheat Launch Script
echo =========================================
echo.

REM Check for Administrator privileges
NET SESSION >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] This script requires Administrator privileges.
    echo [!] Please right-click and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

echo [+] Running with Administrator privileges
echo [+] Current directory: %CD%
echo.

REM Define paths
set "CURRENT_DIR=%CD%"
set "GDRV_DRIVER=%CURRENT_DIR%\drivers\gdrv.sys"
set "MEMORY_DRIVER=%CURRENT_DIR%\yoo.sys"
set "MAPPER_EXE=%CURRENT_DIR%\GDRVMapper.exe"
set "ESP_EXE=%CURRENT_DIR%\DBD-ESP.exe"

REM Check if all required files exist
echo [*] Checking required files...

if not exist "%GDRV_DRIVER%" (
    echo [-] GDRV driver not found: %GDRV_DRIVER%
    echo [!] This driver is required for the exploit to work
    pause
    exit /b 1
)

if not exist "%MEMORY_DRIVER%" (
    echo [-] Memory driver not found: %MEMORY_DRIVER%
    echo [!] Please build the driver project first
    pause
    exit /b 1
)

if not exist "%MAPPER_EXE%" (
    echo [-] GDRVMapper not found: %MAPPER_EXE%
    echo [!] Please build GDRVMapper project first
    pause
    exit /b 1
)

if not exist "%ESP_EXE%" (
    echo [-] DBD-ESP not found: %ESP_EXE%
    echo [!] Please build DBD-ESP project first
    pause
    exit /b 1
)

echo [+] All required files found
echo.

REM Step 1: Load GDRV driver
echo [*] Step 1: Loading GDRV driver...

REM Check and cleanup existing service
echo [*] Checking for existing GDRV service...
sc query GDRVDrv >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [*] Found existing service, removing...
    sc stop GDRVDrv >nul 2>&1
    sc delete GDRVDrv >nul 2>&1
    timeout /t 2 >nul
)

echo [*] Creating service...

sc create GDRVDrv type= kernel binPath= "%GDRV_DRIVER%" >nul
if %ERRORLEVEL% NEQ 0 (
    echo [-] Failed to create service
    echo [!] Error details:
    sc create GDRVDrv type= kernel binPath= "%GDRV_DRIVER%"
    pause
    exit /b 1
)

echo [+] Service created successfully
echo [*] Starting service...
sc start GDRVDrv

REM Check if service started
sc query GDRVDrv | find "RUNNING" >nul
if %ERRORLEVEL% NEQ 0 (
    echo [-] Failed to start service
    echo [!] Error details:
    sc query GDRVDrv
    echo [*] Cleaning up...
    sc delete GDRVDrv >nul
    pause
    exit /b 1
)

echo [+] GDRV driver loaded successfully!
echo.

REM Step 2: Run GDRVMapper
echo [*] Step 2: Running GDRVMapper...
"%MAPPER_EXE%"
if %ERRORLEVEL% NEQ 0 (
    echo [-] GDRVMapper failed
    echo [*] Cleaning up...
    sc stop GDRVDrv >nul
    sc delete GDRVDrv >nul
    pause
    exit /b 1
)

REM Step 3: Launch ESP
echo.
echo [*] Step 3: Starting ESP overlay...
echo [*] Make sure Dead By Daylight is running...
start "" "%ESP_EXE%"

REM Clean up GDRV
echo.
echo [*] Cleaning up GDRV service...
sc stop GDRVDrv >nul
sc delete GDRVDrv >nul

echo.
echo [+] All components launched successfully!
echo [+] ESP overlay is now active and will display automatically in-game.
echo [+] Press Enter in the ESP console window to exit.
echo.
echo [!] Remember: Use at your own risk. Cheating can result in a game ban.
echo.

pause
