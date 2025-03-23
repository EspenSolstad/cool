#pragma once
#include <iostream>
#include <string>
#include <sstream>
#include <Windows.h>

class Logger {
public:
    static Logger& GetInstance() {
        static Logger instance;
        return instance;
    }

    template<typename T>
    void Log(const T& msg, bool error = false) {
        std::stringstream ss;
        ss << msg;
        LogString(ss.str(), error);
    }

    template<typename T>
    void LogInfo(const T& msg) {
        std::stringstream ss;
        ss << "[*] " << msg;
        LogString(ss.str(), false);
    }

    template<typename T>
    void LogSuccess(const T& msg) {
        std::stringstream ss;
        ss << "[+] " << msg;
        LogString(ss.str(), false);
    }

    template<typename T>
    void LogError(const T& msg) {
        std::stringstream ss;
        ss << "[-] " << msg;
        LogString(ss.str(), true);
    }

private:
    Logger() {
        // Get console handles
        console_out = GetStdHandle(STD_OUTPUT_HANDLE);
        console_err = GetStdHandle(STD_ERROR_HANDLE);
    }

    void LogString(const std::string& msg, bool error) {
        // Add newline if not present
        std::string output = msg;
        if (output.empty() || output.back() != '\n') {
            output += '\n';
        }

        // Write to appropriate handle
        HANDLE handle = error ? console_err : console_out;
        DWORD written;
        WriteConsoleA(handle, output.c_str(), static_cast<DWORD>(output.length()), &written, nullptr);
    }

    HANDLE console_out;
    HANDLE console_err;
};

#define LOG_INFO(msg) Logger::GetInstance().LogInfo(msg)
#define LOG_SUCCESS(msg) Logger::GetInstance().LogSuccess(msg)
#define LOG_ERROR(msg) Logger::GetInstance().LogError(msg)
