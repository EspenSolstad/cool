@echo off
echo Building UnifiedLoader with Visual Studio 2022...

rem Find Visual Studio installation
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: Visual Studio 2022 not found!
    echo Please install Visual Studio 2022 with C++ development workload.
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set "VS_PATH=%%i"
)

if not defined VS_PATH (
    echo ERROR: Visual Studio 2022 with C++ tools not found!
    exit /b 1
)

echo Found Visual Studio at: %VS_PATH%

rem Setup VS environment
call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to set up Visual Studio environment.
    exit /b 1
)

rem Build bin2header tool first
msbuild UnifiedLoader.sln /p:Configuration=Release /p:Platform=x64 /t:bin2header /m
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to build bin2header tool.
    exit /b 1
)

rem Then build main project
msbuild UnifiedLoader.sln /p:Configuration=Release /p:Platform=x64 /t:UnifiedLoader /m
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to build UnifiedLoader.
    exit /b 1
)

echo.
echo Build completed successfully!
echo Executable location: %~dp0bin\Release\UnifiedLoader.exe
echo.

pause
