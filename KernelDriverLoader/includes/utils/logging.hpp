#pragma once
#include <iostream>
#include <string>
#include <Windows.h>
#include <format>

enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical
};

class Logger {
public:
    static void SetLogLevel(LogLevel level) {
        s_logLevel = level;
    }

    template<typename... Args>
    static void LogDebug(const std::string& fmt, Args&&... args) {
        if (s_logLevel <= LogLevel::Debug) {
            Log(LogLevel::Debug, fmt, std::forward<Args>(args)...);
        }
    }

    template<typename... Args>
    static void LogInfo(const std::string& fmt, Args&&... args) {
        if (s_logLevel <= LogLevel::Info) {
            Log(LogLevel::Info, fmt, std::forward<Args>(args)...);
        }
    }

    template<typename... Args>
    static void LogWarning(const std::string& fmt, Args&&... args) {
        if (s_logLevel <= LogLevel::Warning) {
            Log(LogLevel::Warning, fmt, std::forward<Args>(args)...);
        }
    }

    template<typename... Args>
    static void LogError(const std::string& fmt, Args&&... args) {
        if (s_logLevel <= LogLevel::Error) {
            Log(LogLevel::Error, fmt, std::forward<Args>(args)...);
        }
    }

    template<typename... Args>
    static void LogCritical(const std::string& fmt, Args&&... args) {
        if (s_logLevel <= LogLevel::Critical) {
            Log(LogLevel::Critical, fmt, std::forward<Args>(args)...);
        }
    }

private:
    static LogLevel s_logLevel;

    template<typename... Args>
    static void Log(LogLevel level, const std::string& fmt, Args&&... args) {
        HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
        WORD originalAttrs;
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(console, &csbi);
        originalAttrs = csbi.wAttributes;

        // Set color based on log level
        switch (level) {
        case LogLevel::Debug:
            SetConsoleTextAttribute(console, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << "[DEBUG] ";
            break;
        case LogLevel::Info:
            SetConsoleTextAttribute(console, FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << "[INFO] ";
            break;
        case LogLevel::Warning:
            SetConsoleTextAttribute(console, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN);
            std::cout << "[WARNING] ";
            break;
        case LogLevel::Error:
            SetConsoleTextAttribute(console, FOREGROUND_INTENSITY | FOREGROUND_RED);
            std::cout << "[ERROR] ";
            break;
        case LogLevel::Critical:
            SetConsoleTextAttribute(console, FOREGROUND_INTENSITY | FOREGROUND_RED | BACKGROUND_RED);
            std::cout << "[CRITICAL] ";
            break;
        }

        try {
            std::cout << std::vformat(fmt, std::make_format_args(args...)) << std::endl;
        }
        catch (const std::exception&) {
            std::cout << fmt << std::endl;
        }

        // Reset color
        SetConsoleTextAttribute(console, originalAttrs);
    }
};

// Initialize the static member
inline LogLevel Logger::s_logLevel = LogLevel::Info;
