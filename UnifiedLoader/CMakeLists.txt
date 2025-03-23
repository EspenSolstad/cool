cmake_minimum_required(VERSION 3.10)
project(UnifiedLoader)

# Add tools subdirectory first so we can use them during the build
add_subdirectory(tools)

# Main project settings
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Convert binary files to headers during build
add_custom_command(
    OUTPUT 
        ${CMAKE_CURRENT_SOURCE_DIR}/include/drivers/memdriver.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/drivers/rwdrv.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/drivers/cheat.hpp
    COMMAND ${CMAKE_BINARY_DIR}/tools/bin2header
        ${CMAKE_CURRENT_SOURCE_DIR}/src/drivers/memdriver.sys
        ${CMAKE_CURRENT_SOURCE_DIR}/include/drivers/memdriver.hpp
        memdriver
    COMMAND ${CMAKE_BINARY_DIR}/tools/bin2header
        ${CMAKE_CURRENT_SOURCE_DIR}/src/drivers/RwDrv.sys
        ${CMAKE_CURRENT_SOURCE_DIR}/include/drivers/rwdrv.hpp
        rwdrv
    COMMAND ${CMAKE_BINARY_DIR}/tools/bin2header
        ${CMAKE_CURRENT_SOURCE_DIR}/src/drivers/ExternalCheat.exe
        ${CMAKE_CURRENT_SOURCE_DIR}/include/drivers/cheat.hpp
        cheat
    DEPENDS bin2header
    COMMENT "Generating driver headers"
)

add_custom_target(generate_headers
    DEPENDS 
        ${CMAKE_CURRENT_SOURCE_DIR}/include/drivers/memdriver.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/drivers/rwdrv.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/drivers/cheat.hpp
)

# Source files
set(SOURCES
    src/core/secure_loader.cpp
    src/core/dynamic_mapper.cpp
    src/core/kernel_bridge.cpp
    src/utils/intel_driver.cpp
    src/utils/kdmapper_impl.cpp
    src/utils/portable_executable.cpp
    src/utils/utils.cpp
    src/utils/secure_memory.cpp
    src/main.cpp
)

# Create executable
add_executable(UnifiedLoader WIN32 ${SOURCES})
add_dependencies(UnifiedLoader generate_headers)

# Windows-specific settings
if(WIN32)
    target_compile_definitions(UnifiedLoader PRIVATE
        _CRT_SECURE_NO_WARNINGS
        UNICODE
        _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
    
    # Link Windows libraries
    target_link_libraries(UnifiedLoader PRIVATE
        ntdll
    )
endif()

# Compiler flags
if(MSVC)
    target_compile_options(UnifiedLoader PRIVATE
        /W4     # Warning level 4
        /WX     # Treat warnings as errors
        /GS     # Buffer security check
        /guard:cf # Control Flow Guard
        /DYNAMICBASE # Address Space Layout Randomization
        /NXCOMPAT # Data Execution Prevention
        /MANIFEST:NO # No manifest
    )
    
    # Linker flags
    target_link_options(UnifiedLoader PRIVATE
        /SUBSYSTEM:WINDOWS
        /ENTRY:mainCRTStartup
        /INCREMENTAL:NO
        /MANIFEST:NO
    )
endif()

# Include directories
target_include_directories(UnifiedLoader PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Set output directories
set_target_properties(UnifiedLoader PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

# Enable Link Time Optimization
include(CheckIPOSupported)
check_ipo_supported(RESULT supported OUTPUT error)
if(supported)
    set_target_properties(UnifiedLoader PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION TRUE
    )
endif()
