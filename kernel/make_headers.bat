@echo off
setlocal

:: Ensure the compiler exists
if not exist embed_to_header.exe (
    echo [!] embed_to_header.exe not found. Please compile embed_to_header.cpp first.
    pause
    exit /b
)

embed_to_header kdmapper.cpp kdmapper

embed_to_header portable_executable.cpp memdriver

echo.
echo [✓] All headers generated successfully.
pause
