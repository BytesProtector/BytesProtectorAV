cmake_minimum_required(VERSION 3.15)
project(bytes_av)

# Use C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Ensure the output is placed in the bytes_av folder
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bytes_av")

# Find Python and pybind11
find_package(Python COMPONENTS Interpreter Development REQUIRED)
find_package(pybind11 REQUIRED)

# Add the native extension
pybind11_add_module(_native
    src/_native.cpp
)

# Include Python headers
target_include_directories(_native PRIVATE ${Python_INCLUDE_DIRS})

# Optional: Set compiler flags for Windows
if(MSVC)
    target_compile_options(_native PRIVATE /W3 /bigobj)
else()
    target_compile_options(_native PRIVATE -Wall -O2)
endif()

message(STATUS "Python include dirs: ${Python_INCLUDE_DIRS}")
message(STATUS "Python library dirs: ${Python_LIBRARIES}")