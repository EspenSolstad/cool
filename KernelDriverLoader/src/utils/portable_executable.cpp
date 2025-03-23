#include "../../includes/utils/portable_executable.hpp"
#include "../../includes/utils/logging.hpp"

// Constructor - initialize with pointer to PE file data
PortableExecutable::PortableExecutable(void* data, size_t dataSize) 
    : m_data(std::make_unique<SecureMemory>(dataSize)),
      m_mappedImage(nullptr),
      m_dosHeader(nullptr),
      m_ntHeaders(nullptr),
      m_sectionHeaders(nullptr),
      m_numberOfSections(0) {
    
    // Copy the data to our secure buffer
    if (data && dataSize > 0) {
        memcpy(m_data->Get(), data, dataSize);
        
        // Initialize headers
        m_dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(m_data->Get());
        
        // Check for valid DOS header
        if (m_dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
            m_ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(
                reinterpret_cast<BYTE*>(m_dosHeader) + m_dosHeader->e_lfanew
            );
            
            // Check for valid NT headers
            if (m_ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
                m_sectionHeaders = reinterpret_cast<IMAGE_SECTION_HEADER*>(
                    reinterpret_cast<BYTE*>(&m_ntHeaders->OptionalHeader) + 
                    m_ntHeaders->FileHeader.SizeOfOptionalHeader
                );
                
                m_numberOfSections = m_ntHeaders->FileHeader.NumberOfSections;
            }
        }
    }
}

// Check if a PE file is valid
bool PortableExecutable::IsValid() const {
    return m_dosHeader && 
           m_dosHeader->e_magic == IMAGE_DOS_SIGNATURE &&
           m_ntHeaders && 
           m_ntHeaders->Signature == IMAGE_NT_SIGNATURE;
}

// Get the image size
ULONG PortableExecutable::GetImageSize() const {
    if (IsValid()) {
        return m_ntHeaders->OptionalHeader.SizeOfImage;
    }
    return 0;
}

// Get the entry point RVA
ULONG PortableExecutable::GetEntryPoint() const {
    if (IsValid()) {
        return m_ntHeaders->OptionalHeader.AddressOfEntryPoint;
    }
    return 0;
}

// Get DOS header
IMAGE_DOS_HEADER* PortableExecutable::GetDosHeader() const {
    return m_dosHeader;
}

// Get NT headers
IMAGE_NT_HEADERS* PortableExecutable::GetNtHeaders() const {
    return m_ntHeaders;
}

// Get header size
ULONG PortableExecutable::GetHeaderSize() const {
    if (IsValid()) {
        return m_ntHeaders->OptionalHeader.SizeOfHeaders;
    }
    return 0;
}

// Get the image base from the NT headers
ULONG_PTR PortableExecutable::GetImageBase() const {
    if (IsValid()) {
        return m_ntHeaders->OptionalHeader.ImageBase;
    }
    return 0;
}

// Return a specific directory from the PE optional header
PIMAGE_DATA_DIRECTORY PortableExecutable::GetDataDirectory(DWORD directoryID) const {
    if (IsValid() && directoryID < m_ntHeaders->OptionalHeader.NumberOfRvaAndSizes) {
        return &m_ntHeaders->OptionalHeader.DataDirectory[directoryID];
    }
    return nullptr;
}

// Return a section by name
IMAGE_SECTION_HEADER* PortableExecutable::GetSectionByName(const std::string& name) const {
    if (!IsValid() || name.empty() || name.length() > 8) {
        return nullptr;
    }
    
    for (USHORT i = 0; i < m_numberOfSections; i++) {
        char sectionName[9] = { 0 };
        memcpy(sectionName, m_sectionHeaders[i].Name, 8);
        
        if (name == sectionName) {
            return &m_sectionHeaders[i];
        }
    }
    
    return nullptr;
}

// Resolves RVA to a VA pointer
void* PortableExecutable::RvaToVa(DWORD rva) const {
    if (!IsValid() || !rva) {
        return nullptr;
    }
    
    // Check if the RVA is within the headers
    if (rva < m_ntHeaders->OptionalHeader.SizeOfHeaders) {
        return reinterpret_cast<BYTE*>(m_data->Get()) + rva;
    }
    
    // Find the section containing the RVA
    for (USHORT i = 0; i < m_numberOfSections; i++) {
        const auto& section = m_sectionHeaders[i];
        
        if (rva >= section.VirtualAddress && 
            rva < (section.VirtualAddress + section.Misc.VirtualSize)) {
            
            // Calculate the VA by adding the RVA to the base address minus the section's virtual address
            // plus the raw data pointer
            DWORD offset = rva - section.VirtualAddress;
            return reinterpret_cast<BYTE*>(m_data->Get()) + section.PointerToRawData + offset;
        }
    }
    
    return nullptr;
}

// Map the PE file into memory
void* PortableExecutable::MapImage(bool inProcess) {
    if (!IsValid()) {
        Logger::LogError("Cannot map invalid PE image");
        return nullptr;
    }
    
    ULONG imageSize = GetImageSize();
    if (imageSize == 0) {
        Logger::LogError("PE image has invalid size");
        return nullptr;
    }
    
    // Allocate memory for the mapped image
    m_mappedImage = std::make_unique<SecureMemory>(imageSize);
    if (!m_mappedImage->Get()) {
        Logger::LogError("Failed to allocate memory for mapped image");
        return nullptr;
    }
    
    // Zero out the memory
    memset(m_mappedImage->Get(), 0, imageSize);
    
    // Copy the headers
    ULONG headerSize = GetHeaderSize();
    memcpy(m_mappedImage->Get(), m_data->Get(), headerSize);
    
    // Copy each section to its virtual address
    for (USHORT i = 0; i < m_numberOfSections; i++) {
        const auto& section = m_sectionHeaders[i];
        
        // Calculate the destination address
        BYTE* destination = m_mappedImage->Get() + section.VirtualAddress;
        
        // Calculate the source address
        BYTE* source = reinterpret_cast<BYTE*>(m_data->Get()) + section.PointerToRawData;
        
        // Copy the section data
        memcpy(destination, source, section.SizeOfRawData);
    }
    
    // Process imports and relocations if needed
    if (inProcess) {
        ProcessImports();
        ProcessRelocations(reinterpret_cast<ULONG_PTR>(m_mappedImage->Get()));
    }
    
    return m_mappedImage->Get();
}

// Process relocations
bool PortableExecutable::ProcessRelocations(ULONG_PTR imageBase) {
    if (!IsValid() || !m_mappedImage->Get()) {
        return false;
    }
    
    // Calculate the delta between the preferred base and the actual base
    LONG_PTR delta = imageBase - m_ntHeaders->OptionalHeader.ImageBase;
    if (delta == 0) {
        // No relocation needed
        return true;
    }
    
    // Get the relocation directory
    auto relocationDir = GetDataDirectory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (!relocationDir || relocationDir->Size == 0) {
        // No relocations
        return true;
    }
    
    // Get the relocation table
    BYTE* relocationTable = reinterpret_cast<BYTE*>(m_mappedImage->Get()) + relocationDir->VirtualAddress;
    
    // Process each relocation block
    ULONG relocationSize = 0;
    while (relocationSize < relocationDir->Size) {
        auto relocationBlock = reinterpret_cast<IMAGE_BASE_RELOCATION*>(relocationTable + relocationSize);
        
        if (relocationBlock->SizeOfBlock == 0) {
            break;
        }
        
        // Calculate the number of entries in this block
        ULONG entryCount = (relocationBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        
        // Get the first entry
        WORD* entries = reinterpret_cast<WORD*>(relocationTable + relocationSize + sizeof(IMAGE_BASE_RELOCATION));
        
        // Process each entry
        for (ULONG i = 0; i < entryCount; i++) {
            WORD entry = entries[i];
            WORD type = (entry >> 12);
            WORD offset = entry & 0xFFF;
            
            // Calculate the relocation address
            BYTE* relocAddress = reinterpret_cast<BYTE*>(m_mappedImage->Get()) + relocationBlock->VirtualAddress + offset;
            
            // Apply the relocation based on type
            switch (type) {
                case IMAGE_REL_BASED_HIGHLOW:
                    *reinterpret_cast<ULONG*>(relocAddress) += static_cast<ULONG>(delta);
                    break;
                case IMAGE_REL_BASED_DIR64:
                    *reinterpret_cast<ULONG64*>(relocAddress) += delta;
                    break;
                case IMAGE_REL_BASED_ABSOLUTE:
                    // Do nothing, used for alignment
                    break;
                default:
                    Logger::LogWarning("Unsupported relocation type: {}", type);
                    break;
            }
        }
        
        // Move to the next block
        relocationSize += relocationBlock->SizeOfBlock;
    }
    
    return true;
}

// Process imports
bool PortableExecutable::ProcessImports() {
    if (!IsValid() || !m_mappedImage->Get()) {
        return false;
    }
    
    // Get the import directory
    auto importDir = GetDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!importDir || importDir->Size == 0) {
        // No imports
        return true;
    }
    
    // Get the import descriptor table
    auto importDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        reinterpret_cast<BYTE*>(m_mappedImage->Get()) + importDir->VirtualAddress
    );
    
    // Process each imported DLL
    for (int i = 0; importDescriptor[i].Characteristics != 0; i++) {
        const auto& descriptor = importDescriptor[i];
        
        // Get the name of the DLL
        char* dllName = reinterpret_cast<char*>(
            reinterpret_cast<BYTE*>(m_mappedImage->Get()) + descriptor.Name
        );
        
        // Load the DLL
        HMODULE module = LoadLibraryA(dllName);
        if (!module) {
            Logger::LogError("Failed to load import DLL: {}", dllName);
            return false;
        }
        
        // Get the import lookup table (ILT)
        auto thunkData = reinterpret_cast<IMAGE_THUNK_DATA*>(
            reinterpret_cast<BYTE*>(m_mappedImage->Get()) + descriptor.FirstThunk
        );
        
        // Process each imported function
        for (int j = 0; thunkData[j].u1.AddressOfData != 0; j++) {
            FARPROC function = nullptr;
            
            // Check if the import is by name or ordinal
            if (thunkData[j].u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                // Import by ordinal
                WORD ordinal = IMAGE_ORDINAL(thunkData[j].u1.Ordinal);
                function = GetProcAddress(module, reinterpret_cast<LPCSTR>(ordinal));
            }
            else {
                // Import by name
                auto importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                    reinterpret_cast<BYTE*>(m_mappedImage->Get()) + thunkData[j].u1.AddressOfData
                );
                function = GetProcAddress(module, importByName->Name);
            }
            
            if (!function) {
                Logger::LogError("Failed to resolve import from DLL: {}", dllName);
                return false;
            }
            
            // Fill in the IAT entry
            thunkData[j].u1.Function = reinterpret_cast<ULONG_PTR>(function);
        }
    }
    
    return true;
}

// Map driver sections
void* PortableExecutable::MapDriver(ULONG_PTR targetBase) {
    if (!IsValid()) {
        return nullptr;
    }
    
    // This is a simplified version that doesn't actually map to kernel memory
    // In a real implementation, this would use functions to allocate and map into kernel
    return MapImage(false);
}

// Resolve imports for a driver
void PortableExecutable::ResolveImports(ULONG_PTR kernelBase) {
    // This is a placeholder for what would be a complex operation
    // Requires actual kernel access to resolve kernel imports
    Logger::LogInfo("Resolving imports with kernel base at 0x{:X}", kernelBase);
}

// Apply relocations for a driver
bool PortableExecutable::ApplyRelocations(ULONG_PTR imageBase, ULONG_PTR delta) {
    if (!IsValid()) {
        return false;
    }
    
    return ProcessRelocations(imageBase + delta);
}
