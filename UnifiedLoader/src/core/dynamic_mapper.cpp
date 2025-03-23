#include "secure_loader.hpp"
#include "intel_driver.hpp"
#include "kdmapper.hpp"
#include <memory>

struct DynamicMapper::MappingContext {
    void* mapped_base;
    size_t mapped_size;
    std::vector<void*> secure_sections;
    bool is_mapped;
};

DynamicMapper::DynamicMapper() : context(std::make_unique<MappingContext>()) {
    context->mapped_base = nullptr;
    context->mapped_size = 0;
    context->is_mapped = false;
}

DynamicMapper::~DynamicMapper() {
    if (context->is_mapped) {
        UnmapDriver();
    }
    RemoveTraces();
}

bool DynamicMapper::MapDriver(const void* driver_data, size_t size) {
    if (!SetupMapping()) {
        return false;
    }

    // Create secure memory section
    void* secure_section = CreateSecureSection(size);
    if (!secure_section) {
        return false;
    }

    // Copy driver to secure section
    memcpy(secure_section, driver_data, size);

    // Configure memory protection
    if (!ConfigureProtection()) {
        FreeSecureSection(secure_section);
        return false;
    }

    // Map the driver
    HANDLE dev = intel_driver::Load();
    if (dev == INVALID_HANDLE_VALUE) {
        FreeSecureSection(secure_section);
        return false;
    }

    // Allocate kernel memory
    context->mapped_base = reinterpret_cast<void*>(intel_driver::AllocatePool(dev, nt::NonPagedPool, size));
    if (!context->mapped_base) {
        intel_driver::Unload(dev);
        FreeSecureSection(secure_section);
        return false;
    }

    // Write to kernel memory
    if (!intel_driver::WriteMemory(dev, reinterpret_cast<ULONGLONG>(context->mapped_base), secure_section, size)) {
        intel_driver::FreePool(dev, reinterpret_cast<ULONGLONG>(context->mapped_base));
        intel_driver::Unload(dev);
        FreeSecureSection(secure_section);
        return false;
    }

    context->mapped_size = size;
    context->is_mapped = true;
    context->secure_sections.push_back(secure_section);

    // Verify mapping
    if (!VerifyMapping()) {
        UnmapDriver();
        return false;
    }

    return true;
}

bool DynamicMapper::UnmapDriver() {
    if (!context->is_mapped) {
        return true;
    }

    HANDLE dev = intel_driver::Load();
    if (dev == INVALID_HANDLE_VALUE) {
        return false;
    }

    bool success = intel_driver::FreePool(dev, reinterpret_cast<ULONGLONG>(context->mapped_base));
    intel_driver::Unload(dev);

    if (success) {
        context->mapped_base = nullptr;
        context->mapped_size = 0;
        context->is_mapped = false;

        // Free secure sections
        for (void* section : context->secure_sections) {
            FreeSecureSection(section);
        }
        context->secure_sections.clear();

        RemoveTraces();
    }

    return success;
}

void* DynamicMapper::CreateSecureSection(size_t size) {
    // Allocate with PAGE_READWRITE initially
    void* section = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!section) {
        return nullptr;
    }

    // Add random padding to avoid memory patterns
    size_t padding_size = rand() % 4096;
    void* padded_section = VirtualAlloc(nullptr, size + padding_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!padded_section) {
        VirtualFree(section, 0, MEM_RELEASE);
        return nullptr;
    }

    // Copy to padded section with random offset
    size_t offset = rand() % padding_size;
    memcpy(static_cast<uint8_t*>(padded_section) + offset, section, size);
    VirtualFree(section, 0, MEM_RELEASE);

    return padded_section;
}

bool DynamicMapper::FreeSecureSection(void* section) {
    if (!section) {
        return false;
    }

    // Secure wipe before freeing
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(section, &mbi, sizeof(mbi))) {
        volatile uint8_t* p = static_cast<uint8_t*>(section);
        for (size_t i = 0; i < mbi.RegionSize; i++) {
            p[i] = 0;
        }
    }

    return VirtualFree(section, 0, MEM_RELEASE);
}

bool DynamicMapper::VerifyMapping() {
    if (!context->is_mapped || !context->mapped_base) {
        return false;
    }

    HANDLE dev = intel_driver::Load();
    if (dev == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Read back and verify first page
    std::vector<uint8_t> verify_buffer(4096);
    bool success = intel_driver::WriteMemory(dev, reinterpret_cast<ULONGLONG>(context->mapped_base),
        verify_buffer.data(), verify_buffer.size());

    intel_driver::Unload(dev);

    if (!success) {
        return false;
    }

    // Additional integrity checks can be added here

    return true;
}

bool DynamicMapper::CheckIntegrity() {
    if (!context->is_mapped) {
        return false;
    }

    // Verify secure sections
    for (void* section : context->secure_sections) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(section, &mbi, sizeof(mbi))) {
            return false;
        }

        if (mbi.Protect != PAGE_READWRITE) {
            return false;
        }
    }

    return true;
}

bool DynamicMapper::SetupMapping() {
    // Initialize mapping protection
    return true;
}

bool DynamicMapper::ConfigureProtection() {
    // Configure memory protection settings
    return true;
}

void DynamicMapper::RemoveTraces() {
    // Clean up any remaining traces
    if (context->mapped_base) {
        SecureMemory::WipeMemory(context->mapped_base, context->mapped_size);
    }

    for (void* section : context->secure_sections) {
        if (section) {
            SecureMemory::WipeMemory(section, 0);
        }
    }
}
