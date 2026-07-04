# DataVanger AMSI Provider — native shim (Windows / MSVC only).
#
# This target is intentionally NOT part of the .NET solution and is NOT built in
# CI (no C++ toolchain, and an AMSI provider cannot be exercised from CI). Build
# it manually on a Windows host with the MSVC toolchain. See docs/AMSI_PROVIDER.md.
#
#   cmake -S native/DataVanger.AmsiProvider -B build/amsi -A x64
#   cmake --build build/amsi --config Release
#
# For 32-bit hosts, also build the Win32 configuration (-A Win32) and register
# the resulting 32-bit DLL in the 32-bit COM view (see the docs).

cmake_minimum_required(VERSION 3.20)
project(DataVanger.AmsiProvider LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "DataVanger.AmsiProvider is a Windows-only AMSI provider and requires the MSVC toolchain.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(DataVanger.AmsiProvider SHARED
    dllmain.cpp
    AmsiIngestProtocol.h
    DataVanger.AmsiProvider.def)

# SEH is required for the fail-open __try/__except guard around Scan().
target_compile_options(DataVanger.AmsiProvider PRIVATE /EHa /W4 /permissive-)

# amsi.lib provides the AMSI interface GUIDs; ole32 for CoTaskMemAlloc/StringFromGUID2.
target_link_libraries(DataVanger.AmsiProvider PRIVATE amsi ole32 advapi32)

set_target_properties(DataVanger.AmsiProvider PROPERTIES
    OUTPUT_NAME "DataVanger.AmsiProvider"
    PREFIX "")
