#include "utils/service.hpp"
#include "utils/logging.hpp"
#include <Windows.h>
#include <string>

// Service implementation
namespace service {
    bool RegisterAndStart(const std::wstring& driver_path, const std::wstring& service_name) {
        LOG_INFO(L"Registering and starting service: " + service_name);

        const SC_HANDLE sc_manager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!sc_manager) {
            LOG_ERROR(L"Cannot open service manager");
            return false;
        }

        // Create the service
        const SC_HANDLE service = CreateServiceW(
            sc_manager,
            service_name.c_str(),
            service_name.c_str(),
            SERVICE_START | SERVICE_STOP | DELETE,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            driver_path.c_str(),
            nullptr, nullptr, nullptr, nullptr, nullptr);

        if (!service) {
            const auto last_error = GetLastError();
            if (last_error == ERROR_SERVICE_EXISTS) {
                // Service already exists, let's open it
                const SC_HANDLE service_exists = OpenServiceW(
                    sc_manager,
                    service_name.c_str(),
                    SERVICE_START | SERVICE_STOP | DELETE);

                if (!service_exists) {
                    LOG_ERROR(L"Cannot open existing service");
                    CloseServiceHandle(sc_manager);
                    return false;
                }

                // Try to start the service
                const bool start_status = StartServiceW(service_exists, 0, nullptr);
                if (!start_status) {
                    const auto start_error = GetLastError();
                    if (start_error != ERROR_SERVICE_ALREADY_RUNNING) {
                        LOG_ERROR(L"Failed to start service: " + std::to_wstring(start_error));
                        CloseServiceHandle(service_exists);
                        CloseServiceHandle(sc_manager);
                        return false;
                    }
                }

                LOG_SUCCESS(L"Service started");
                CloseServiceHandle(service_exists);
                CloseServiceHandle(sc_manager);
                return true;
            }

            LOG_ERROR(L"Failed to create service: " + std::to_wstring(last_error));
            CloseServiceHandle(sc_manager);
            return false;
        }

        // Start the service
        const bool start_status = StartServiceW(service, 0, nullptr);
        if (!start_status) {
            const auto start_error = GetLastError();
            if (start_error != ERROR_SERVICE_ALREADY_RUNNING) {
                LOG_ERROR(L"Failed to start service: " + std::to_wstring(start_error));
                CloseServiceHandle(service);
                CloseServiceHandle(sc_manager);
                return false;
            }
        }

        LOG_SUCCESS(L"Service started");
        CloseServiceHandle(service);
        CloseServiceHandle(sc_manager);
        return true;
    }

    bool StopAndRemove(const std::wstring& service_name) {
        LOG_INFO(L"Stopping and removing service: " + service_name);

        const SC_HANDLE sc_manager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!sc_manager) {
            LOG_ERROR(L"Cannot open service manager");
            return false;
        }

        const SC_HANDLE service = OpenServiceW(
            sc_manager,
            service_name.c_str(),
            SERVICE_STOP | DELETE);

        if (!service) {
            LOG_ERROR(L"Cannot open service");
            CloseServiceHandle(sc_manager);
            return GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST;
        }

        // Stop the service
        SERVICE_STATUS status{};
        if (ControlService(service, SERVICE_CONTROL_STOP, &status)) {
            LOG_INFO(L"Service stopped");
        }

        // Delete the service
        const bool delete_status = DeleteService(service);
        if (!delete_status) {
            LOG_ERROR(L"Failed to delete service");
            CloseServiceHandle(service);
            CloseServiceHandle(sc_manager);
            return false;
        }

        LOG_SUCCESS(L"Service removed");
        CloseServiceHandle(service);
        CloseServiceHandle(sc_manager);
        return true;
    }
}
