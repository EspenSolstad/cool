#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <memory>
#include <stdexcept>
#include "../utils/secure_memory.hpp"

class PortableExecutable {
public:
    // Constructor takes a pointer to PE file data
    PortableExecutable(void* data, size_t dataSize);
    
    // Check if a PE file is valid
    bool IsValid() const;
    
    // Get the image size
    ULONG GetImageSize() const;
    
    // Get the entry point RVA
    ULONG GetEntryPoint() const;
    
    // Map the PE file into memory
    void* MapImage(bool inProcess = false);
    
    // Process relocations
    bool ProcessRelocations(ULONG_PTR imageBase);
    
    // Process imports
    bool ProcessImports();
    
    // Map driver sections
    void* MapDriver(ULONG_PTR targetBase);
    
    // Get DOS header
    IMAGE_DOS_HEADER* GetDosHeader() const;
    
    // Get NT headers
    IMAGE_NT_HEADERS* GetNtHeaders() const;
    
    // Get header size
    ULONG GetHeaderSize() const;
    
    // Resolve imports for a driver
    void ResolveImports(ULONG_PTR kernelBase);
    
    // Apply relocations for a driver
    bool ApplyRelocations(ULONG_PTR imageBase, ULONG_PTR delta);
    
    // Get the image base from the NT headers
    ULONG_PTR GetImageBase() const;

private:
    // Return a specific directory from the PE optional header
    PIMAGE_DATA_DIRECTORY GetDataDirectory(DWORD directoryID) const;
    
    // Return a section by name
    IMAGE_SECTION_HEADER* GetSectionByName(const std::string& name) const;
    
    // Resolves RVA to a VA pointer
    void* RvaToVa(DWORD rva) const;
    
    // Memory buffer for the PE file
    std::unique_ptr<SecureMemory> m_data;
    
    // Pointer to the mapped image if mapped
    std::unique_ptr<SecureMemory> m_mappedImage;
    
    // DOS header
    IMAGE_DOS_HEADER* m_dosHeader;
    
    // NT headers
    IMAGE_NT_HEADERS* m_ntHeaders;
    
    // Section headers
    PIMAGE_SECTION_HEADER m_sectionHeaders;
    
    // Number of sections
    USHORT m_numberOfSections;
};
