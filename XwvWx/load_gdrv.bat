@echo off
echo =========================================
echo   Dead By Daylight Memory Driver Loader
echo   Using GDRV Exploit
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
echo [+] Beginning driver loading sequence...
echo.

REM Define paths
set "CURRENT_DIR=%~dp0"
set "GDRV_DRIVER=%CURRENT_DIR%drivers\gdrv.sys"
set "MEMORY_DRIVER=%CURRENT_DIR%yoo.sys"

REM Check if required drivers exist
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

REM Attempt to load GDRV
echo [*] Loading GDRV driver...
echo [*] Creating service...
sc create GDRVDrv type= kernel binPath= "%GDRV_DRIVER%" >nul

REM Check service creation
sc query GDRVDrv >nul 2>&1
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

REM Run the mapper
echo [*] Running GDRV mapper to load yoo.sys...
if exist "GDRVMapper.exe" (
    GDRVMapper.exe
) else (
    echo [-] GDRVMapper.exe not found
    echo [!] Please build GDRVMapper project first
)

REM Clean up
echo.
echo [*] Cleaning up...
sc stop GDRVDrv >nul
sc delete GDRVDrv >nul

echo.
echo [*] Process complete
pause
