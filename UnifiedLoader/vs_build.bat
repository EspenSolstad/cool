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

rem Create required directories
mkdir bin\Release 2>nul
mkdir bin\Debug 2>nul
mkdir obj 2>nul
mkdir include\drivers 2>nul

rem Build bin2header tool first
echo Building bin2header tool...
msbuild UnifiedLoader.sln /p:Configuration=Release /p:Platform=x64 /t:bin2header /m
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to build bin2header tool.
    exit /b 1
)

rem Create driver files placeholders if they don't exist
if not exist "src\drivers" mkdir "src\drivers"
if not exist "src\drivers\memdriver.sys" (
    echo Creating placeholder memdriver.sys...
    echo This is a placeholder file > src\drivers\memdriver.sys
)
if not exist "src\drivers\RwDrv.sys" (
    echo Creating placeholder RwDrv.sys...
    echo This is a placeholder file > src\drivers\RwDrv.sys
)
if not exist "src\drivers\ExternalCheat.exe" (
    echo Creating placeholder ExternalCheat.exe...
    echo This is a placeholder file > src\drivers\ExternalCheat.exe
)

rem Then build main project
echo Building UnifiedLoader...
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
