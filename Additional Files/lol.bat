@echo off
:: Ensure this script is run as Administrator
:: (otherwise, exit and request elevated permissions)
openfiles >nul 2>&1
if %errorlevel% NEQ 0 (
    echo This script requires Administrator privileges. Please run as Admin.
    pause
    exit /b
)

:: Load RTCore64 Driver
echo [+] Loading RTCore64.sys...
sc stop RTCore64 >nul 2>&1
sc delete RTCore64 >nul 2>&1
sc create RTCore64 binPath= "%~dp0RTCore64.sys" type= kernel start= demand
sc start RTCore64

:: Add a delay to ensure RTCore64.sys is fully loaded
timeout /t 5 /nobreak

:: Check for success before proceeding
sc qc RTCore64
if %errorlevel% NEQ 0 (
    echo [-] Failed to start RTCore64 service. Exiting...
    pause
    exit /b
)

:: Create fake rwdrv service for rwdrv access
echo [+] Creating fake rwdrv service for handle access...
sc stop rwdrv >nul 2>&1
sc delete rwdrv >nul 2>&1
sc create rwdrv binPath= "%~dp0null.sys" type= kernel start= demand
sc start rwdrv

:: Wait for rwdrv service to be accessible
timeout /t 2 /nobreak

:: Trigger the ManualSysMapper
echo [+] Launching ManualSysMapper...
"%~dp0ManualSysMapper.exe"

:: Wait and then launch the cheat
timeout /t 2 /nobreak
echo [+] Launching ExternalCheat.exe...
"%~dp0ExternalCheat.exe"

pause
