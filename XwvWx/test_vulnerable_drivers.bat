@echo off
echo =========================================
echo   Vulnerable Driver Load Test Utility
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
echo [+] Beginning driver tests...
echo.

REM Define paths
set "CURRENT_DIR=%~dp0"
set "HELLO_DRIVER=%CURRENT_DIR%drivers\HelloWorld.sys"
set "GDRV_DRIVER=%CURRENT_DIR%drivers\gdrv.sys"
set "RTCORE_DRIVER=%CURRENT_DIR%drivers\RTCore64.sys"

REM Function to attempt driver loading
echo [*] Attempting to load drivers...
echo.

REM ======= ATTEMPT 1: HelloWorld.sys =======
echo [*] Testing HelloWorld.sys...
if not exist "%HELLO_DRIVER%" (
    echo [-] Driver not found: %HELLO_DRIVER%
) else (
    echo [+] Driver found: %HELLO_DRIVER%
    
    REM Attempt to create service
    echo [*] Creating service...
    sc create HelloDrv type= kernel binPath= "%HELLO_DRIVER%" >nul
    
    REM Check service creation
    sc query HelloDrv >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo [-] Failed to create service
        echo [!] Error details:
        sc create HelloDrv type= kernel binPath= "%HELLO_DRIVER%"
    ) else (
        echo [+] Service created successfully
        
        REM Attempt to start service
        echo [*] Starting service...
        sc start HelloDrv
        
        REM Check if service started
        sc query HelloDrv | find "RUNNING" >nul
        if %ERRORLEVEL% NEQ 0 (
            echo [-] Failed to start service
            echo [!] Error details:
            sc query HelloDrv
            echo [*] Cleaning up...
            sc delete HelloDrv >nul
        ) else (
            echo [+] HelloWorld.sys loaded successfully!
            echo [*] Cleaning up...
            sc stop HelloDrv >nul
            sc delete HelloDrv >nul
        )
    )
)

echo.
timeout /t 2 >nul

REM ======= ATTEMPT 2: gdrv.sys =======
echo [*] Testing gdrv.sys...
if not exist "%GDRV_DRIVER%" (
    echo [-] Driver not found: %GDRV_DRIVER%
) else (
    echo [+] Driver found: %GDRV_DRIVER%
    
    REM Attempt to create service
    echo [*] Creating service...
    sc create GDRVDrv type= kernel binPath= "%GDRV_DRIVER%" >nul
    
    REM Check service creation
    sc query GDRVDrv >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo [-] Failed to create service
        echo [!] Error details:
        sc create GDRVDrv type= kernel binPath= "%GDRV_DRIVER%"
    ) else (
        echo [+] Service created successfully
        
        REM Attempt to start service
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
        ) else (
            echo [+] gdrv.sys loaded successfully!
            echo [*] Cleaning up...
            sc stop GDRVDrv >nul
            sc delete GDRVDrv >nul
        )
    )
)

echo.
timeout /t 2 >nul

REM ======= ATTEMPT 3: RTCore64.sys =======
echo [*] Testing RTCore64.sys...
if not exist "%RTCORE_DRIVER%" (
    echo [-] Driver not found: %RTCORE_DRIVER%
) else (
    echo [+] Driver found: %RTCORE_DRIVER%
    
    REM Attempt to create service
    echo [*] Creating service...
    sc create RTCoreDrv type= kernel binPath= "%RTCORE_DRIVER%" >nul
    
    REM Check service creation
    sc query RTCoreDrv >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo [-] Failed to create service
        echo [!] Error details:
        sc create RTCoreDrv type= kernel binPath= "%RTCORE_DRIVER%"
    ) else (
        echo [+] Service created successfully
        
        REM Attempt to start service
        echo [*] Starting service...
        sc start RTCoreDrv
        
        REM Check if service started
        sc query RTCoreDrv | find "RUNNING" >nul
        if %ERRORLEVEL% NEQ 0 (
            echo [-] Failed to start service
            echo [!] Error details:
            sc query RTCoreDrv
            echo [*] Cleaning up...
            sc delete RTCoreDrv >nul
        ) else (
            echo [+] RTCore64.sys loaded successfully!
            echo [*] Cleaning up...
            sc stop RTCoreDrv >nul
            sc delete RTCoreDrv >nul
        )
    )
)

echo.
echo [*] Testing complete
echo [*] Check the output above to see which drivers (if any) loaded successfully
echo.
pause
