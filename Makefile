CC = g++
CXXFLAGS = -std=c++17 -I./include -fexceptions

all: iwyu

LLVM_PROJECT="./llvm-project"
BUILD="./llvm-build-genoa20"
LLVM_CONFIG = $(BUILD)/bin/llvm-config
LDFLAGS_RAW = $(shell $(LLVM_CONFIG) --cxxflags --ldflags --system-libs --libs)
# remove -fno-exceptions
LDFLAGS = $(filter-out -fno-exceptions,$(LDFLAGS_RAW))
LDFLAGS += -I$(LLVM_PROJECT)/llvm/lib/Target/X86
LDFLAGS += -I$(BUILD)/lib/Target/X86
LDFLAGS += -I$(LLVM_PROJECT)/llvm/lib/Target/AArch64
LDFLAGS += -I$(BUILD)/lib/Target/AArch64

# Add Clang include directories
# LDFLAGS += -I$(LLVM_PROJECT)/llvm/include
LDFLAGS += -I$(BUILD)/include

IWYU = ./build-iwyu/bin/include-what-you-use
SRC_FILES = LLVMBench BenchmarkGenerator LLVMEnvironment AssemblyFile Templates ErrorCode CustomDebug Globals
# run include-what-you-use for the given source file
iwyu:
	@$(IWYU) -isystem /usr/include/c++/13 -isystem /usr/include/x86_64-linux-gnu/c++/13 $(CXXFLAGS) src/LLVMBench.cpp $(LDFLAGS)
	@$(IWYU) -isystem /usr/include/c++/13 -isystem /usr/include/x86_64-linux-gnu/c++/13 $(CXXFLAGS) src/BenchmarkGenerator.cpp $(LDFLAGS)
	@$(IWYU) -isystem /usr/include/c++/13 -isystem /usr/include/x86_64-linux-gnu/c++/13 $(CXXFLAGS) src/LLVMEnvironment.cpp $(LDFLAGS)
	@$(IWYU) -isystem /usr/include/c++/13 -isystem /usr/include/x86_64-linux-gnu/c++/13 $(CXXFLAGS) src/AssemblyFile.cpp $(LDFLAGS)
	@$(IWYU) -isystem /usr/include/c++/13 -isystem /usr/include/x86_64-linux-gnu/c++/13 $(CXXFLAGS) src/ErrorCode.cpp $(LDFLAGS)
	@$(IWYU) -isystem /usr/include/c++/13 -isystem /usr/include/x86_64-linux-gnu/c++/13 $(CXXFLAGS) src/CustomDebug.cpp $(LDFLAGS)
	@$(IWYU) -isystem /usr/include/c++/13 -isystem /usr/include/x86_64-linux-gnu/c++/13 $(CXXFLAGS) src/Globals.cpp $(LDFLAGS)

clean:
	rm -rf quick