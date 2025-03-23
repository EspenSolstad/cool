// embed_to_header.cpp — drag a binary, get a .hpp
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

void writeHeader(const std::string& inPath, const std::string& symbolName) {
    std::ifstream in(inPath, std::ios::binary);
    if (!in.is_open()) {
        std::cerr << "[-] Failed to open input file\n";
        return;
    }

    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(in), {});
    std::string outPath = symbolName + ".hpp";
    std::ofstream out(outPath);
    if (!out.is_open()) {
        std::cerr << "[-] Failed to write header file\n";
        return;
    }

    out << "#pragma once\n";
    out << "const unsigned char " << symbolName << "[] = {\n";
    for (size_t i = 0; i < buffer.size(); ++i) {
        out << "0x" << std::hex << (int)buffer[i];
        if (i < buffer.size() - 1) out << ", ";
        if ((i + 1) % 16 == 0) out << "\n";
    }
    out << "\n};\n";
    out << "const size_t " << symbolName << "_len = sizeof(" << symbolName << ");\n";

    std::cout << "[+] Wrote header to: " << outPath << "\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: embed_to_header <file> <symbol_name>\n";
        return -1;
    }

    writeHeader(argv[1], argv[2]);
    return 0;
}
