cmake_minimum_required(VERSION 3.20)
project(pyav_core LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(pybind11 REQUIRED)

# ---- YARA (manual) ----
set(YARA_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/deps/yara-4.5.2-2050-win64")
set(YARA_INCLUDE_DIRS "${YARA_ROOT}/include")
set(YARA_LIBRARIES    "${YARA_ROOT}/lib/yara.lib")

# ---- native module ----
pybind11_add_module(_native
    src/bindings.cpp
    src/scanner.cpp
    src/yara_engine.cpp
    src/pe_parser.cpp
)
target_include_directories(_native PRIVATE ${YARA_INCLUDE_DIRS})
target_link_libraries(_native PRIVATE ${YARA_LIBRARIES})
set_target_properties(_native PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/pyav/_native
)