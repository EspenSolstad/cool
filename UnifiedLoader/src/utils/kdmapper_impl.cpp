#include "utils/kdmapper_impl.hpp"
#include "utils/intel_driver.hpp"
#include "utils/logging.hpp"
#include "nt.hpp"
#include <iostream>

namespace kdmapper {

ULONG64 AllocateIndependentPages(HANDLE device_handle, ULONG32 size) {
    const auto base = intel_driver::MmAllocateIndependentPagesEx(device_handle, size);
    if (!base) {
        LOG_ERROR(L"Error allocating independent pages");
        return 0;
    }

    if (!intel_driver::MmSetPageProtection(device_handle, base, size, PAGE_EXECUTE_READWRITE)) {
        LOG_ERROR(L"Failed to change page protections");
        intel_driver::MmFreeIndependentPages(device_handle, base, size);
        return 0;
    }

    return base;
}

void RelocateImageByDelta(portable_executable::vec_relocs relocs, const ULONG64 delta) {
    for (const auto& current_reloc : relocs) {
        for (auto i = 0u; i < current_reloc.count; ++i) {
            const uint16_t type = current_reloc.item[i] >> 12;
            const uint16_t offset = current_reloc.item[i] & 0xFFF;

            if (type == IMAGE_REL_BASED_DIR64)
                *reinterpret_cast<ULONG64*>(current_reloc.address + offset) += delta;
        }
    }
}

bool FixSecurityCookie(void* local_image, ULONG64 kernel_image_base) {
    auto headers = portable_executable::GetNtHeaders(local_image);
    if (!headers)
        return false;

    auto load_config_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
    if (!load_config_directory) {
        LOG_INFO(L"Load config directory wasn't found, probably StackCookie not defined, fix cookie skipped");
        return true;
    }

    auto load_config_struct = (PIMAGE_LOAD_CONFIG_DIRECTORY)((uintptr_t)local_image + load_config_directory);
    auto stack_cookie = load_config_struct->SecurityCookie;
    if (!stack_cookie) {
        LOG_INFO(L"StackCookie not defined, fix cookie skipped");
        return true;
    }

    stack_cookie = stack_cookie - (uintptr_t)kernel_image_base + (uintptr_t)local_image;

    if (*(uintptr_t*)(stack_cookie) != 0x2B992DDFA232) {
        LOG_ERROR(L"StackCookie already fixed!? this probably wrong");
        return false;
    }

    LOG_INFO(L"Fixing stack cookie");

    auto new_cookie = 0x2B992DDFA232 ^ GetCurrentProcessId() ^ GetCurrentThreadId();
    if (new_cookie == 0x2B992DDFA232)
        new_cookie = 0x2B992DDFA233;

    *(uintptr_t*)(stack_cookie) = new_cookie;
    return true;
}

bool ResolveImports(HANDLE device_handle, portable_executable::vec_imports imports) {
    for (const auto& current_import : imports) {
        ULONG64 Module = utils::GetKernelModuleAddress(current_import.module_name);
        if (!Module) {
            LOG_ERROR("Dependency " + current_import.module_name + " wasn't found");
            return false;
        }

        for (auto& current_function_data : current_import.function_datas) {
            ULONG64 function_address = intel_driver::GetKernelModuleExport(device_handle, Module, current_function_data.name);

            if (!function_address) {
                //Lets try with ntoskrnl
                if (Module != intel_driver::ntoskrnlAddr) {
                    function_address = intel_driver::GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, current_function_data.name);
                    if (!function_address) {
                        LOG_ERROR("Failed to resolve import " + current_function_data.name + " (" + current_import.module_name + ")");
                        return false;
                    }
                }
            }

            *current_function_data.address = function_address;
        }
    }

    return true;
}

ULONG64 MapDriver(HANDLE device_handle, BYTE* data, ULONG64 param1, ULONG64 param2, 
                 bool free, bool destroyHeader, AllocationMode mode, 
                 bool PassAllocationAddressAsFirstParam, mapCallback callback, NTSTATUS* exitCode) {
    
    const PIMAGE_NT_HEADERS64 nt_headers = portable_executable::GetNtHeaders(data);
    if (!nt_headers) {
        LOG_ERROR(L"Invalid format of PE image");
        return 0;
    }

    if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        LOG_ERROR(L"Image is not 64 bit");
        return 0;
    }

    ULONG32 image_size = nt_headers->OptionalHeader.SizeOfImage;

    void* local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!local_image_base)
        return 0;

    DWORD TotalVirtualHeaderSize = (IMAGE_FIRST_SECTION(nt_headers))->VirtualAddress;
    image_size = image_size - (destroyHeader ? TotalVirtualHeaderSize : 0);

    ULONG64 kernel_image_base = 0;
    if (mode == AllocationMode::AllocateIndependentPages) {
        kernel_image_base = AllocateIndependentPages(device_handle, image_size);
    }
    else { // AllocatePool by default
        kernel_image_base = intel_driver::AllocatePool(device_handle, nt::NonPagedPool, image_size);
    }

    if (!kernel_image_base) {
        LOG_ERROR(L"Failed to allocate remote image in kernel");
        VirtualFree(local_image_base, 0, MEM_RELEASE);
        return 0;
    }

    // Copy image headers
    memcpy(local_image_base, data, nt_headers->OptionalHeader.SizeOfHeaders);

    // Copy image sections
    const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);
    for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
        if ((current_image_section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
            continue;
        auto local_section = reinterpret_cast<void*>(reinterpret_cast<ULONG64>(local_image_base) + current_image_section[i].VirtualAddress);
        memcpy(local_section, reinterpret_cast<void*>(reinterpret_cast<ULONG64>(data) + current_image_section[i].PointerToRawData), current_image_section[i].SizeOfRawData);
    }

    ULONG64 realBase = kernel_image_base;
    if (destroyHeader) {
        kernel_image_base -= TotalVirtualHeaderSize;
        LOG_INFO(L"Skipped 0x" + std::to_wstring(TotalVirtualHeaderSize) + L" bytes of PE Header");
    }

    // Resolve relocs and imports
    RelocateImageByDelta(portable_executable::GetRelocs(local_image_base), kernel_image_base - nt_headers->OptionalHeader.ImageBase);
    
    if (!FixSecurityCookie(local_image_base, kernel_image_base)) {
        LOG_ERROR(L"Failed to fix cookie");
        VirtualFree(local_image_base, 0, MEM_RELEASE);
        return 0;
    }

    if (!ResolveImports(device_handle, portable_executable::GetImports(local_image_base))) {
        LOG_ERROR(L"Failed to resolve imports");
        VirtualFree(local_image_base, 0, MEM_RELEASE);
        return 0;
    }

    // Write fixed image to kernel
    if (!intel_driver::WriteMemory(device_handle, realBase, (PVOID)((uintptr_t)local_image_base + (destroyHeader ? TotalVirtualHeaderSize : 0)), image_size)) {
        LOG_ERROR(L"Failed to write local image to remote image");
        VirtualFree(local_image_base, 0, MEM_RELEASE);
        return 0;
    }

    // Call driver entry
    const ULONG64 address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;
    LOG_INFO(L"Calling DriverEntry 0x" + std::to_wstring((uintptr_t)address_of_entry_point));

    if (callback) {
        if (!callback(&param1, &param2, realBase, image_size)) {
            LOG_ERROR(L"Callback returns false, failed!");
            VirtualFree(local_image_base, 0, MEM_RELEASE);
            return 0;
        }
    }

    NTSTATUS status = 0;
    if (!intel_driver::CallKernelFunction(device_handle, &status, address_of_entry_point, 
                                         (PassAllocationAddressAsFirstParam ? realBase : param1), param2)) {
        LOG_ERROR(L"Failed to call driver entry");
        VirtualFree(local_image_base, 0, MEM_RELEASE);
        return 0;
    }

    if (exitCode)
        *exitCode = status;

    LOG_INFO(L"DriverEntry returned 0x" + std::to_wstring(status));

    // Cleanup if requested
    if (free) {
        LOG_INFO(L"Freeing memory");
        bool free_status = false;

        if (mode == AllocationMode::AllocateIndependentPages) {
            free_status = intel_driver::MmFreeIndependentPages(device_handle, realBase, image_size);
        }
        else {
            free_status = intel_driver::FreePool(device_handle, realBase);
        }

        if (free_status) {
            LOG_INFO(L"Memory has been released");
        }
        else {
            LOG_ERROR(L"WARNING: Failed to free memory!");
        }
    }

    VirtualFree(local_image_base, 0, MEM_RELEASE);
    return realBase;
}

} // namespace kdmapper
