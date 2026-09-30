#!/bin/bash -l

set -e

BUILD_DIR=""
BUILD_LIBPFM=0

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --dir)
            BUILD_DIR="-$2"
            shift
            ;;
        --libpfm)
            BUILD_LIBPFM=1
            ;;
        --help)
            qecho "Usage: $0 [--dir buildDirIdentifier] [--libpfm]"
            exit 0
            ;;
        *)
            echo "Unknown parameter passed: $1"
            echo "Usage: $0 [--dir buildDirIdentifier] [--libpfm]"
            exit 1
            ;;
    esac
    shift
done

# Clone llvm
if [ -d "llvm-project" ]; then
    echo "LLVM repo already cloned." 
else
    git clone --branch=llvmorg-22.1.8 --depth=1 https://github.com/llvm/llvm-project.git
    cd llvm-project
    git sparse-checkout init --cone
    git sparse-checkout set llvm clang third-party cmake
    cd ..
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# build libfpm
LIBPFM_DIR="libpfm4$BUILD_DIR"
if [[ "$BUILD_LIBPFM" -eq 1 ]]; then
    mkdir -p $LIBPFM_DIR
    cd $LIBPFM_DIR
    # clone libpfm (yes we clone for each platform bc libpfm makefile does not support separate build dirs)
    if [ -d "libpfm4" ]; then
        echo "libpfm4 already cloned." 
    else
        echo "Cloning libpfm..."
        git clone --branch=v4.13.0 https://github.com/wcohen/libpfm4.git
    fi
    cd libpfm4
    make -j
    cd ../..
fi

BUILD_DIR="build$BUILD_DIR"

LLVM_BUILD_DIR="./llvm-$BUILD_DIR"

NUM_PROCS=$(nproc)

# Check if build dir exists
if [ -d "$LLVM_BUILD_DIR" ]; then
    echo "Using existing build dir '$LLVM_BUILD_DIR'."
    cd $LLVM_BUILD_DIR
else
    echo "Directory '$LLVM_BUILD_DIR' does not exist, building LLVM and Clang there."
    mkdir -p $LLVM_BUILD_DIR && cd $LLVM_BUILD_DIR
    # Build LLVM and clang
    if [[ "$BUILD_LIBPFM" -eq 1 ]]; then
        cmake -S ../llvm-project/llvm -B . \
        -DLLVM_ENABLE_PROJECTS=clang \
        -DLLVM_TARGETS_TO_BUILD="X86;AArch64;RISCV" \
        -DLLVM_ENABLE_LIBPFM=ON \
        -DCMAKE_C_FLAGS="-I$SCRIPT_DIR/$LIBPFM_DIR/libpfm4/include" \
        -DCMAKE_CXX_FLAGS="-I$SCRIPT_DIR/$LIBPFM_DIR/libpfm4/include" \
        -DCMAKE_LIBRARY_PATH="-L$SCRIPT_DIR/$LIBPFM_DIR/libpfm4/lib" \
        -DCMAKE_EXE_LINKER_FLAGS="-L$SCRIPT_DIR/$LIBPFM_DIR/libpfm4/lib -Wl,-rpath,$SCRIPT_DIR/$LIBPFM_DIR/libpfm4/lib -lpfm" \
        -DCMAKE_BUILD_TYPE=Release
    else
        cmake -S ../llvm-project/llvm -B . \
        -DLLVM_ENABLE_PROJECTS=clang \
        -DLLVM_TARGETS_TO_BUILD="X86;AArch64;RISCV" \
        -DCMAKE_BUILD_TYPE=Release
    fi

    cmake --build . -- -j "$NUM_PROCS"
fi

# Build WINIC
mkdir -p ../$BUILD_DIR && cd ../$BUILD_DIR
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Debug \
  -DWINIC_LLVM_SOURCE_DIR=../llvm-project/llvm \
  -DWINIC_LLVM_BUILD_DIR=../$LLVM_BUILD_DIR \
  -DLLVM_DIR=../$LLVM_BUILD_DIR/lib/cmake/llvm \
  -DWINIC_CLANG_PATH=../$LLVM_BUILD_DIR/bin/clang ..
  
cmake --build . -- -j 6
