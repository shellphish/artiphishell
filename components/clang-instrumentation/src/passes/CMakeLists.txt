project(clang-instrumentation)
cmake_minimum_required(VERSION 3.22)

project(clang-instrumentation LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS NO)

# Try to find LLVM in common locations
find_package(LLVM REQUIRED CONFIG HINTS
    /usr/lib/llvm-18/cmake/llvm
)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

# Add LLVM definitions and include directories
add_definitions(${LLVM_DEFINITIONS})

include_directories(${LLVM_INCLUDE_DIRS})
add_subdirectory(FuncCov)
