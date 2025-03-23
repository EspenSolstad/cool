cmake_minimum_required(VERSION 3.10)
project(UnifiedLoaderTools)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(bin2header bin2header.cpp)

if(MSVC)
    target_compile_options(bin2header PRIVATE /W4)
else()
    target_compile_options(bin2header PRIVATE -Wall -Wextra)
endif()

# Set output directory
set_target_properties(bin2header PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tools"
)
