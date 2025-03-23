@echo off
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

echo [*] Starting cheat components...
echo.

REM Check if all required files exist
if not exist "GDRVMapper.exe" (
    echo [-] GDRVMapper.exe not found
    echo [!] Please build GDRVMapper project first
    pause
    exit /b 1
)

if not exist "yoo.sys" (
    echo [-] yoo.sys not found
    echo [!] Please build the driver project first
    pause
    exit /b 1
)

if not exist "DBD-ESP.exe" (
    echo [-] DBD-ESP.exe not found
    echo [!] Please build DBD-ESP project first
    pause
    exit /b 1
)

REM Step 1: Run the GDRV mapper to load yoo.sys
echo [*] Step 1: Loading and mapping drivers...
echo [*] Running GDRV mapper...
GDRVMapper.exe

REM Step 2: Launch the ESP
echo.
echo [*] Step 2: Starting ESP overlay...
echo [*] Make sure Dead By Daylight is running...
start "" "DBD-ESP.exe"

echo.
echo [+] All components launched!
echo [+] ESP overlay is now active and will display automatically in-game.
echo [+] Press Enter in the ESP console window to exit.
echo.
echo [!] Remember: Use at your own risk. Cheating can result in a game ban.
echo.

pause
