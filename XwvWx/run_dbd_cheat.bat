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

REM Step 1: Run the loader to map drivers
echo [*] Step 1: Loading and mapping drivers...
echo [*] Running loader...
cd "%~dp0\loader\loader\x64\Release"
start /wait loader.exe

REM Step 2: Launch the ESP
echo.
echo [*] Step 2: Starting ESP overlay...
echo [*] Make sure Dead By Daylight is running...
cd "%~dp0"
start "" "%~dp0\DBD\x64\Release\DBD-ESP.exe"

echo.
echo [+] All components launched!
echo [+] Press Insert key to toggle the ESP menu in-game.
echo.
echo [!] Remember: Use at your own risk. Cheating can result in a game ban.
echo.

pause
