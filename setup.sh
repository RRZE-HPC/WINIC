#!/bin/bash -l

set -e

# Clone llvm
if [ -d "llvm-project" ]; then
    echo "LLVM repo already cloned." 
else
    git clone -b release/20.x --depth=1 https://github.com/llvm/llvm-project.git
    cd llvm-project
    git sparse-checkout init --cone
    git sparse-checkout set llvm clang third-party cmake
    cd ..
fi

BUILD_DIR=""

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --dir) 
            BUILD_DIR="-$2"
            shift 
            ;;
        --help)
            qecho "Usage: $0 [--dir buildDirIdentifier]"
            exit 0 
            ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

BUILD_DIR="build$BUILD_DIR"

LLVM_BUILD_DIR="./llvm-$BUILD_DIR"

# Check if build dir exists
if [ -d "$LLVM_BUILD_DIR" ]; then
    echo "Using existing build dir '$LLVM_BUILD_DIR'."
    cd $LLVM_BUILD_DIR
else
    echo "Directory '$LLVM_BUILD_DIR' does not exist, building LLVM and Clang there."
    mkdir -p $LLVM_BUILD_DIR && cd $LLVM_BUILD_DIR
    # Build llvm and clang
    cmake -S ../llvm-project/llvm -B . \
    -DLLVM_ENABLE_PROJECTS=clang \
    -DLLVM_TARGETS_TO_BUILD="X86;AArch64;RISCV" \
    -DCMAKE_BUILD_TYPE=Release

    cmake --build . -- -j 90
fi

mkdir -p ../$BUILD_DIR && cd ../$BUILD_DIR
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_SOURCE_DIR=../llvm-project/llvm \
  -DLLVM_BINARY_DIR=../$LLVM_BUILD_DIR \
  -DLLVM_DIR=../$LLVM_BUILD_DIR/lib/cmake/llvm \
  -DClang_DIR=../$LLVM_BUILD_DIR/lib/cmake/clang \
  -DCLANG_PATH=../$LLVM_BUILD_DIR/bin/clang ..
  
cmake --build . -- -j 6
