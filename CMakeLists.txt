cmake_minimum_required(VERSION 3.16)
project(winic VERSION 0.2.0 LANGUAGES CXX C)

# Require C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Path to clang executable (used by WINIC at runtime).
set(WINIC_CLANG_PATH "${WINIC_CLANG_PATH}" CACHE FILEPATH "Path to clang executable")

set(WINIC_LLVM_SOURCE_DIR "${WINIC_LLVM_SOURCE_DIR}" CACHE PATH "Path to LLVM source dir (llvm-project/llvm)")
set(WINIC_LLVM_BUILD_DIR "${WINIC_LLVM_BUILD_DIR}" CACHE PATH "Path to LLVM build dir")

# Validate paths
if(NOT EXISTS "${WINIC_LLVM_SOURCE_DIR}")
  message(FATAL_ERROR "WINIC_LLVM_SOURCE_DIR does not exist: ${WINIC_LLVM_SOURCE_DIR}")
endif()
if(NOT EXISTS "${WINIC_LLVM_BUILD_DIR}")
  message(FATAL_ERROR "WINIC_LLVM_BUILD_DIR does not exist: ${WINIC_LLVM_BUILD_DIR}")
endif()
if(NOT EXISTS "${WINIC_CLANG_PATH}")
  message(FATAL_ERROR "WINIC_CLANG_PATH does not exist: ${WINIC_CLANG_PATH}")
endif()

# Locate pre-built LLVM and Clang
find_package(LLVM REQUIRED CONFIG NO_DEFAULT_PATH PATHS "${WINIC_LLVM_BUILD_DIR}/lib/cmake/llvm")
find_package(Clang REQUIRED CONFIG NO_DEFAULT_PATH PATHS "${WINIC_LLVM_BUILD_DIR}/lib/cmake/clang")

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
add_executable(winic ${SRC_FILES})

# Include LLVM and Clang headers
include_directories(winic SYSTEM PRIVATE
  ${LLVM_INCLUDE_DIRS}
  ${Clang_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/include-third-party
)

# Add backend include paths for target descriptions
target_include_directories(winic SYSTEM PRIVATE
  ${WINIC_LLVM_SOURCE_DIR}/lib/Target/X86
  ${WINIC_LLVM_BUILD_DIR}/lib/Target/X86
  ${WINIC_LLVM_SOURCE_DIR}/lib/Target/AArch64
  ${WINIC_LLVM_BUILD_DIR}/lib/Target/AArch64
  ${WINIC_LLVM_SOURCE_DIR}/lib/Target/RISCV
  ${WINIC_LLVM_BUILD_DIR}/lib/Target/RISCV
)

# Compiler warning flags
# target_compile_options(winic PRIVATE -Wall -Wextra -Wpedantic)

# Pass WINIC_CLANG_PATH macro to the compiler
target_compile_definitions(winic PRIVATE
  WINIC_CLANG_PATH="${WINIC_CLANG_PATH}"
)

# Link against LLVM and Clang libraries
target_link_libraries(winic PRIVATE
  ${LLVM_LIBS}
  ${CLANG_LIBS}
)

# generate version header from template
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/version.h
    @ONLY
)

# use generated headers
target_include_directories(winic PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/generated
)
