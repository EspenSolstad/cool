@echo off
echo Building KernelDriverLoader...

where /q msbuild.exe
if %ERRORLEVEL% neq 0 (
    echo MSBuild not found in PATH. Trying to find Visual Studio...
    
    set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
    if not exist "%VSWHERE%" (
        echo Error: Visual Studio installation not found
        exit /b 1
    )
    
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do (
        set "MSBUILD=%%i"
    )
    
    if not defined MSBUILD (
        echo Error: MSBuild not found
        exit /b 1
    )
) else (
    set "MSBUILD=msbuild.exe"
)

echo Using MSBuild: %MSBUILD%
echo.

echo Building Debug configuration...
"%MSBUILD%" KernelDriverLoader.sln /p:Configuration=Debug /p:Platform=x64 /m
if %ERRORLEVEL% neq 0 (
    echo Error: Debug build failed
    exit /b 1
)
echo Debug build completed successfully
echo.

echo Building Release configuration...
"%MSBUILD%" KernelDriverLoader.sln /p:Configuration=Release /p:Platform=x64 /m
if %ERRORLEVEL% neq 0 (
    echo Error: Release build failed
    exit /b 1
)
echo Release build completed successfully
echo.

echo Build completed successfully!
echo.
echo Debug binary: bin\Debug\KernelDriverLoader.exe
echo Release binary: bin\Release\KernelDriverLoader.exe
echo.
echo Run the application with administrator privileges.
