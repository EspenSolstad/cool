cmake_minimum_required(VERSION 3.10)
project(UnifiedLoader)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Source files
set(SOURCES
    main.cpp
    secure_loader.cpp
    dynamic_mapper.cpp
    kernel_bridge.cpp
    intel_driver.cpp
    kdmapper.cpp
    portable_executable.cpp
    utils.cpp
)

# Create executable
add_executable(UnifiedLoader ${SOURCES})

# Windows-specific settings
if(WIN32)
    target_compile_definitions(UnifiedLoader PRIVATE
        _CRT_SECURE_NO_WARNINGS
        UNICODE
        _UNICODE
        WIN32_LEAN_AND_MEAN
    )
    
    # Link Windows libraries
    target_link_libraries(UnifiedLoader PRIVATE
        ntdll.lib
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
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Post-build commands
add_custom_command(TARGET UnifiedLoader POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "Stripping debug information..."
    COMMAND ${CMAKE_STRIP} $<TARGET_FILE:UnifiedLoader>
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

# Add resource file for version info and icon
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/resource.rc.in
    ${CMAKE_CURRENT_BINARY_DIR}/resource.rc
    @ONLY
)
target_sources(UnifiedLoader PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/resource.rc)
