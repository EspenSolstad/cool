@echo off
echo =========================================
echo   Dead By Daylight Anti-Cheat Bypasser
echo   Driver Testing Utility
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
set "MEM_DRIVER=%CURRENT_DIR%memdriver\x64\Release\memdriver\memdriver.sys"
set "LOADER_EXE=%CURRENT_DIR%loader\loader\x64\Release\loader.exe"

REM Check if memdriver.sys exists
if not exist "%MEM_DRIVER%" (
    echo [-] Memory driver not found: %MEM_DRIVER%
    echo [!] Please make sure the driver is built (Release configuration)
    pause
    exit /b 1
)

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
    sc create HelloDrv type= kernel binPath= "%HELLO_DRIVER%" >nul 2>&1
    
    REM Check service creation
    sc query HelloDrv >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo [-] Failed to create service (likely blocked by Windows)
    ) else {
        echo [+] Service created successfully
        
        REM Attempt to start service
        echo [*] Starting service...
        sc start HelloDrv >nul 2>&1
        
        REM Check if service started
        sc query HelloDrv | find "RUNNING" >nul 2>&1
        if %ERRORLEVEL% NEQ 0 (
            echo [-] Failed to start service
            echo [*] Cleaning up...
            sc delete HelloDrv >nul 2>&1
        ) else (
            echo [+] HelloWorld.sys loaded successfully!
            set "LOADED_DRIVER=HelloDrv"
            goto DRIVER_LOADED
        )
    }
)

echo.

REM ======= ATTEMPT 2: gdrv.sys =======
echo [*] Testing gdrv.sys...
if not exist "%GDRV_DRIVER%" (
    echo [-] Driver not found: %GDRV_DRIVER%
) else (
    echo [+] Driver found: %GDRV_DRIVER%
    
    REM Attempt to create service
    echo [*] Creating service...
    sc create GDRVDrv type= kernel binPath= "%GDRV_DRIVER%" >nul 2>&1
    
    REM Check service creation
    sc query GDRVDrv >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo [-] Failed to create service (likely blocked by Windows)
    ) else {
        echo [+] Service created successfully
        
        REM Attempt to start service
        echo [*] Starting service...
        sc start GDRVDrv >nul 2>&1
        
        REM Check if service started
        sc query GDRVDrv | find "RUNNING" >nul 2>&1
        if %ERRORLEVEL% NEQ 0 (
            echo [-] Failed to start service
            echo [*] Cleaning up...
            sc delete GDRVDrv >nul 2>&1
        ) else (
            echo [+] gdrv.sys loaded successfully!
            set "LOADED_DRIVER=GDRVDrv"
            goto DRIVER_LOADED
        )
    }
)

echo.

REM ======= ATTEMPT 3: RTCore64.sys =======
echo [*] Testing RTCore64.sys...
if not exist "%RTCORE_DRIVER%" (
    echo [-] Driver not found: %RTCORE_DRIVER%
) else (
    echo [+] Driver found: %RTCORE_DRIVER%
    
    REM Attempt to create service
    echo [*] Creating service...
    sc create RTCoreDrv type= kernel binPath= "%RTCORE_DRIVER%" >nul 2>&1
    
    REM Check service creation
    sc query RTCoreDrv >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo [-] Failed to create service (likely blocked by Windows)
    ) else {
        echo [+] Service created successfully
        
        REM Attempt to start service
        echo [*] Starting service...
        sc start RTCoreDrv >nul 2>&1
        
        REM Check if service started
        sc query RTCoreDrv | find "RUNNING" >nul 2>&1
        if %ERRORLEVEL% NEQ 0 (
            echo [-] Failed to start service
            echo [*] Cleaning up...
            sc delete RTCoreDrv >nul 2>&1
        ) else (
            echo [+] RTCore64.sys loaded successfully!
            set "LOADED_DRIVER=RTCoreDrv"
            goto DRIVER_LOADED
        )
    }
)

echo.
echo [-] All driver loading attempts failed!
echo [!] Further troubleshooting needed - consider test mode
goto END

:DRIVER_LOADED
echo.
echo [+] Vulnerable driver loaded successfully: %LOADED_DRIVER%
echo [*] Now attempting to map memory driver...

REM Copy memory driver to current directory for easy access
echo [*] Preparing memory driver...
copy "%MEM_DRIVER%" "%CURRENT_DIR%memdriver.sys" >nul 2>&1

REM Check which driver was loaded and use the appropriate mapper
if "%LOADED_DRIVER%" == "HelloDrv" (
    echo [*] Using HelloWorldMapper for HelloDrv...
    cd "%CURRENT_DIR%"
    
    REM Compile the HelloWorldMapper.cpp if it doesn't exist
    if not exist "HelloWorldMapper.exe" (
        echo [*] Building HelloWorldMapper...
        cl.exe /EHsc /std:c++17 HelloWorldMapper.cpp /link /out:HelloWorldMapper.exe
        if not exist "HelloWorldMapper.exe" (
            echo [-] Failed to build HelloWorldMapper
            echo [!] Make sure Visual Studio Developer Command Prompt is available
            echo [!] You may need to manually build HelloWorldMapper.cpp
        )
    )
    
    REM If HelloWorldMapper.exe exists, run it
    if exist "HelloWorldMapper.exe" (
        echo [*] Running HelloWorldMapper...
        HelloWorldMapper.exe
    ) else (
        echo [-] HelloWorldMapper.exe not found
        echo [!] Cannot map memory driver without a mapper
    )
) else if "%LOADED_DRIVER%" == "GDRVDrv" (
    echo [*] GDRV driver loaded - would use GDRV-specific exploitation here
    echo [!] GDRV mapper not implemented in this script yet
) else if "%LOADED_DRIVER%" == "RTCoreDrv" (
    echo [*] RTCore driver loaded - would use RTCore-specific exploitation here
    echo [!] RTCore mapper not implemented in this script yet
) else (
    echo [!] No mapper available for the loaded driver: %LOADED_DRIVER%
)


REM Run the loader which will now find the device
echo [*] Running loader to interact with mapped driver...
cd "%CURRENT_DIR%loader\loader\x64\Release"
loader.exe

REM Clean up services
echo.
echo [*] Cleaning up...
if "%LOADED_DRIVER%" == "HelloDrv" (
    sc stop HelloDrv >nul 2>&1
    sc delete HelloDrv >nul 2>&1
)
if "%LOADED_DRIVER%" == "GDRVDrv" (
    sc stop GDRVDrv >nul 2>&1
    sc delete GDRVDrv >nul 2>&1
)
if "%LOADED_DRIVER%" == "RTCoreDrv" (
    sc stop RTCoreDrv >nul 2>&1
    sc delete RTCoreDrv >nul 2>&1
)

:END
echo.
echo [*] Testing complete
pause
