#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>

void writeHeader(const std::string& inputFile, const std::string& outputFile, const std::string& arrayName) {
    // Read input file
    std::ifstream input(inputFile, std::ios::binary);
    if (!input) {
        std::cerr << "Failed to open input file: " << inputFile << std::endl;
        return;
    }

    std::vector<unsigned char> buffer(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>()
    );

    // Create output file
    std::ofstream output(outputFile);
    if (!output) {
        std::cerr << "Failed to create output file: " << outputFile << std::endl;
        return;
    }

    // Write header
    output << "#pragma once\n\n";
    output << "const unsigned char " << arrayName << "[] = {\n    ";

    // Write data
    for (size_t i = 0; i < buffer.size(); ++i) {
        output << "0x" << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(buffer[i]);
        
        if (i < buffer.size() - 1)
            output << ", ";
            
        if ((i + 1) % 16 == 0)
            output << "\n    ";
    }

    output << "\n};\n\n";
    output << "const size_t " << arrayName << "_len = sizeof(" << arrayName << ");\n";
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <input_file> <output_file> <array_name>\n";
        return 1;
    }

    writeHeader(argv[1], argv[2], argv[3]);
    return 0;
}
