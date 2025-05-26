cmake_minimum_required(VERSION 3.16)
project(LLVMBench LANGUAGES CXX)

# Require C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Paths to your LLVM project source and build directories
# Pass these on the command line or cache-set them:
#   -DLLVM_SOURCE_DIR=/path/to/llvm-project/llvm
#   -DLLVM_BINARY_DIR=/path/to/llvm-project/build
# Path to clang executable (used by the tool at runtime).
set(CLANG_PATH "${CLANG_PATH}" CACHE FILEPATH "Path to clang executable")

set(LLVM_SOURCE_DIR "${LLVM_SOURCE_DIR}" CACHE PATH "Path to LLVM source dir (llvm-project/llvm)")
set(LLVM_BINARY_DIR "${LLVM_BINARY_DIR}" CACHE PATH "Path to LLVM build dir")

# Validate paths
if(NOT EXISTS "${LLVM_SOURCE_DIR}")
  message(FATAL_ERROR "LLVM_SOURCE_DIR does not exist: ${LLVM_SOURCE_DIR}")
endif()
if(NOT EXISTS "${LLVM_BINARY_DIR}")
  message(FATAL_ERROR "LLVM_BINARY_DIR does not exist: ${LLVM_BINARY_DIR}")
endif()
if(NOT EXISTS "${CLANG_PATH}")
  message(FATAL_ERROR "CLANG_PATH does not exist: ${CLANG_PATH}")
endif()

# Locate pre-built LLVM and Clang
find_package(LLVM REQUIRED CONFIG PATHS "${LLVM_BINARY_DIR}/lib/cmake/llvm")
find_package(Clang REQUIRED CONFIG NO_DEFAULT_PATH HINTS "${LLVM_BINARY_DIR}/lib/cmake/clang")

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Found Clang ${Clang_PACKAGE_VERSION}")

add_definitions(${LLVM_DEFINITIONS})

# Select only the LLVM components needed
llvm_map_components_to_libnames(LLVM_LIBS
  MC
  MCParser
  Support
  X86
  AArch64
  RISCV
)

# Clang libraries (for any Clang Tooling usage)
set(CLANG_LIBS
  clangBasic
  clangFrontend
  clangTooling
)

# Gather source files
file(GLOB SRC_FILES
  ${CMAKE_SOURCE_DIR}/src/*.cpp
)

# Define the executable target
add_executable(LLVMBench ${SRC_FILES})

# Include LLVM and Clang headers
include_directories(LLVMBench SYSTEM PRIVATE
  ${LLVM_INCLUDE_DIRS}
  ${Clang_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/include-third-party
)

# Add backend include paths for target descriptions
target_include_directories(LLVMBench SYSTEM PRIVATE
  ${LLVM_SOURCE_DIR}/lib/Target/X86
  ${LLVM_BINARY_DIR}/lib/Target/X86
  ${LLVM_SOURCE_DIR}/lib/Target/AArch64
  ${LLVM_BINARY_DIR}/lib/Target/AArch64
  ${LLVM_SOURCE_DIR}/lib/Target/RISCV
  ${LLVM_BINARY_DIR}/lib/Target/RISCV
)

# Compiler warning flags
# target_compile_options(LLVMBench PRIVATE -Wall -Wextra -Wpedantic)

# Pass CLANG_PATH macro to the compiler
# It will be a quoted string literal in the C++ code
target_compile_definitions(LLVMBench PRIVATE
  CLANG_PATH="${CLANG_PATH}"
)

# Link against LLVM and Clang libraries
target_link_libraries(LLVMBench PRIVATE
  ${LLVM_LIBS}
  ${CLANG_LIBS}
)
