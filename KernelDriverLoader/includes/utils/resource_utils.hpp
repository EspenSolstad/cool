#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <stdexcept>

namespace resource_utils {
    // Load a binary resource into a vector
    inline std::vector<uint8_t> LoadResourceData(HMODULE hModule, int resourceId) {
        HRSRC resourceInfo = FindResource(hModule, MAKEINTRESOURCE(resourceId), RT_RCDATA);
        if (!resourceInfo) {
            throw std::runtime_error("Failed to find resource");
        }

        DWORD size = SizeofResource(hModule, resourceInfo);
        HGLOBAL resourceData = LoadResource(hModule, resourceInfo);
        if (!resourceData) {
            throw std::runtime_error("Failed to load resource");
        }

        const void* data = LockResource(resourceData);
        if (!data) {
            throw std::runtime_error("Failed to lock resource");
        }

        std::vector<uint8_t> buffer(static_cast<const uint8_t*>(data),
                                   static_cast<const uint8_t*>(data) + size);
        return buffer;
    }

    // Extract a resource to a file
    inline bool ExtractResourceToFile(HMODULE hModule, int resourceId, const std::wstring& filePath) {
        try {
            auto resourceData = LoadResourceData(hModule, resourceId);
            
            HANDLE fileHandle = CreateFileW(
                filePath.c_str(),
                GENERIC_WRITE,
                0,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );
            
            if (fileHandle == INVALID_HANDLE_VALUE) {
                return false;
            }
            
            DWORD bytesWritten = 0;
            BOOL writeResult = WriteFile(
                fileHandle,
                resourceData.data(),
                static_cast<DWORD>(resourceData.size()),
                &bytesWritten,
                nullptr
            );
            
            CloseHandle(fileHandle);
            return writeResult && (bytesWritten == resourceData.size());
        }
        catch (const std::exception&) {
            return false;
        }
    }

    // Get a temporary filename with the specified extension
    inline std::wstring CreateTempFilePath(const std::wstring& extension) {
        wchar_t tempPath[MAX_PATH];
        wchar_t tempFileName[MAX_PATH];
        
        if (!GetTempPathW(MAX_PATH, tempPath)) {
            throw std::runtime_error("Failed to get temp path");
        }
        
        UINT result = GetTempFileNameW(tempPath, L"KDL", 0, tempFileName);
        if (result == 0) {
            throw std::runtime_error("Failed to get temp file name");
        }
        
        std::wstring resultPath(tempFileName);
        
        // Replace the .tmp extension with the requested one
        size_t dotPos = resultPath.find_last_of(L'.');
        if (dotPos != std::wstring::npos) {
            resultPath = resultPath.substr(0, dotPos) + extension;
        }
        else {
            resultPath += extension;
        }
        
        return resultPath;
    }
}
