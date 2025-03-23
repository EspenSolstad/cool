#pragma once
#include <Windows.h>
#include <string>

namespace service {
    // Service management functions
    bool RegisterAndStart(const std::wstring& driver_path, const std::wstring& service_name);
    bool StopAndRemove(const std::wstring& service_name);
}
