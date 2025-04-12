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

echo [*] Installing required Python packages...
echo.

REM Create virtual environment
python -m venv venv
call venv\Scripts\activate.bat

REM Upgrade pip
python -m pip install --upgrade pip

REM Install requirements
pip install -r requirements.txt

echo.
echo [+] Installation complete!
echo [*] You can now run build.bat to compile the ESP
echo.

pause
