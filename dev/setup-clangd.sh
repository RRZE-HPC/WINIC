#!/bin/bash -l

set -e

BUILD_DIR=""
BUILD_LIBPFM=0

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --help)
            qecho "Usage: $0"
            exit 0
            ;;
        *)
            echo "Unknown parameter passed: $1"
            echo "Usage: $0"
            exit 1
            ;;
    esac
    shift
done

# Clone llvm
if [ -d "llvm-project-clangd" ]; then
    echo "LLVM repo already cloned." 
else
    git clone --branch=llvmorg-19.1.2 --depth=1 https://github.com/llvm/llvm-project.git llvm-project-clangd
    cd llvm-project-clangd
    git sparse-checkout init --cone
    git sparse-checkout set llvm clang third-party cmake
    cd ..
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

LLVM_BUILD_DIR="./llvm-build-clangd"

NUM_PROCS=$(nproc)

# Check if build dir exists
if [ -d "$LLVM_BUILD_DIR" ]; then
    echo "Using existing build dir '$LLVM_BUILD_DIR'."
    cd $LLVM_BUILD_DIR
else
    echo "Directory '$LLVM_BUILD_DIR' does not exist, building LLVM and Clang there."
    mkdir -p $LLVM_BUILD_DIR && cd $LLVM_BUILD_DIR
    # Build LLVM and clang
    cmake -S ../llvm-project-clangd/llvm -B . \
    -DLLVM_ENABLE_PROJECTS=clang \
    -DLLVM_TARGETS_TO_BUILD="X86;AArch64;RISCV" \
    -DCMAKE_BUILD_TYPE=Release

    cmake --build . -- -j "$NUM_PROCS"
fi

repo_root=$(git rev-parse --show-toplevel)

cat > "$repo_root/.git/hooks/pre-commit" <<'EOF'
#!/bin/sh

files=$(git diff --cached --name-only --diff-filter=ACM | \
    grep -E '\.(c|cc|cpp|cxx|h|hh|hpp)$')

[ -z "$files" ] && exit 0

for f in $files; do
    "$(git rev-parse --show-toplevel)/llvm-build-clangd/bin/clang-format" --style=file -i "$f"
    git add "$f"
done
EOF

chmod +x "$repo_root/.git/hooks/pre-commit"
