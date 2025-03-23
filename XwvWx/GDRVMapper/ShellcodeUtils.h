#pragma once
#include <cstdint>
#include <vector>
#include <random>

// Shellcode structure for kernel execution
#pragma pack(push, 1)
struct KernelShellcode {
    uint8_t pushRcx;      // push rcx
    uint8_t pushRdx;      // push rdx
    uint8_t pushR8;       // push r8
    uint8_t pushR9;       // push r9
    uint8_t subRsp28h;    // sub rsp, 0x28
    uint8_t movRcx[10];   // mov rcx, imm64
    uint8_t movRdx[10];   // mov rdx, imm64
    uint8_t callRax[2];   // call rax
    uint8_t addRsp28h;    // add rsp, 0x28
    uint8_t popR9;        // pop r9
    uint8_t popR8;        // pop r8
    uint8_t popRdx;       // pop rdx
    uint8_t popRcx;       // pop rcx
    uint8_t ret;          // ret
};

// Structure for obfuscated shellcode
struct ObfuscatedShellcode {
    std::vector<uint8_t> code;        // The obfuscated shellcode
    std::vector<uint8_t> decoder;     // The decoder stub
    uint32_t key;                     // XOR key used for obfuscation
    size_t chunkSize;                 // Suggested chunk size for writing
    std::vector<size_t> safePoints;   // Safe points to split the shellcode
};
#pragma pack(pop)

class ShellcodeUtils {
public:
    // Original shellcode creation methods
    static std::vector<uint8_t> CreateFastReturnShellcode(uint64_t functionAddress);
    static std::vector<uint8_t> CreateCR3ReadShellcode();
    static std::vector<uint8_t> CreateKernelFunctionCallShellcode(uint64_t function, uint64_t arg1, uint64_t arg2);
    static std::vector<uint8_t> CreateJumpShellcode(uint64_t targetAddr);
    static std::vector<uint8_t> CreateExecShellcode(uint64_t shellcodeAddr);
    static std::vector<uint8_t> CreateAllocationShellcode(uint64_t exAllocatePoolAddr, uint64_t poolType, uint64_t size);
    
    // New obfuscation and chunking methods
    static ObfuscatedShellcode ObfuscateShellcode(const std::vector<uint8_t>& shellcode);
    static std::vector<std::vector<uint8_t>> ChunkShellcode(const std::vector<uint8_t>& shellcode, size_t chunkSize);
    static std::vector<uint8_t> CreateDecoderStub(uint32_t key, uint64_t targetAddr, size_t size);
    
    // Utility methods
    static void RandomizeNops(std::vector<uint8_t>& shellcode);
    static uint32_t GenerateRandomKey();
    static std::vector<uint8_t> XorEncode(const std::vector<uint8_t>& data, uint32_t key);
    
private:
    static constexpr size_t DEFAULT_CHUNK_SIZE = 8;
    static constexpr size_t MAX_CHUNK_SIZE = 32;
    
    // Random number generation
    static std::random_device rd;
    static std::mt19937 gen;
    static std::uniform_int_distribution<uint32_t> dist;
};
