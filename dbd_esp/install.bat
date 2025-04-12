@echo off
echo =========================================
echo   Dead by Daylight ESP - Installation
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

REM Check if Python is installed
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [-] Python not found
    echo [!] Please install Python 3.8 or higher
    pause
    exit /b 1
)

echo [*] Installing required Python packages...
echo.

REM Check if venv already exists
if exist "venv" (
    echo [*] Removing existing virtual environment...
    rmdir /s /q "venv"
)

REM Create virtual environment
echo [*] Creating virtual environment...
python -m venv venv
if %errorLevel% neq 0 (
    echo [-] Failed to create virtual environment
    pause
    exit /b 1
)

REM Activate virtual environment
echo [*] Activating virtual environment...
call venv\Scripts\activate.bat
if %errorLevel% neq 0 (
    echo [-] Failed to activate virtual environment
    pause
    exit /b 1
)

REM Upgrade pip
echo [*] Upgrading pip...
python -m pip install --upgrade pip
if %errorLevel% neq 0 (
    echo [-] Failed to upgrade pip
    pause
    exit /b 1
)

REM Install requirements
echo [*] Installing required packages...
pip install -r requirements.txt
if %errorLevel% neq 0 (
    echo [-] Failed to install requirements
    pause
    exit /b 1
)

echo.
echo [+] Installation complete!
echo [*] You can now run build.bat to compile the ESP
echo.

pause
