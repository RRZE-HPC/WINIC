#!/bin/bash -l

set -e

# Clone llvm
git clone --branch=19.x --depth=1 https://github.com/llvm/llvm-project.git
cd llvm-project
git sparse-checkout init --cone
git sparse-checkout set llvm clang third-party cmake

DIR_ARG="build-llvm"

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --dir) DIR_ARG="$2"; shift ;;
        --help) echo "Usage: $0 [--dir buildDirName]"; exit 0 ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

#make path relative
DIR_ARG="./$DIR_ARG"


# Check if build dir exists
if [ -d "$DIR_ARG" ]; then
    echo "Build dir '$DIR_ARG' already exists."
    cd ./$DIR_ARG
else
    echo "Directory '$DIR_ARG' does not exist, building LLVM and Clang there."
    mkdir -p ./$DIR_ARG && cd ./$DIR_ARG
fi


# Build llvm and clang
cmake -S ./llvm-project/llvm -B . \
  -DLLVM_ENABLE_PROJECTS=clang \
  -DLLVM_TARGETS_TO_BUILD="X86;AArch64;RISCV" \
  -DCMAKE_BUILD_TYPE=Release

cmake --build . -- -j 90


# mkdir -p ../build && cd ../build
cmake -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_SOURCE_DIR=../llvm-project/llvm \
  -DLLVM_BINARY_DIR=../llvm-build \
  -DLLVM_DIR=../$DIR_ARG/lib/cmake/llvm \
  -DClang_DIR=../$DIR_ARG/lib/cmake/clang \
  -DCLANG_PATH=../$DIR_ARG/bin/clang ..
  
cmake --build . -- -j 6
