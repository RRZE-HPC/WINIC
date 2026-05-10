CC = g++
CXXFLAGS = -std=c++17 -I./include -fexceptions

# Runs LLVMs include-what-you-use on all source files
# This is for development only
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))/..
all: iwyu

LLVM_PROJECT=$(ROOT)/llvm-project
BUILD=$(ROOT)/llvm-build-x86

LLVM_CONFIG = $(BUILD)/bin/llvm-config
LLVM_LDFLAGS = $(shell $(LLVM_CONFIG) --ldflags --system-libs --libs)
LLVM_CXXFLAGS += $(shell $(LLVM_CONFIG) --cxxflags)

# remove -fno-exceptions
CXXFLAGS = $(filter-out -fno-exceptions,$(LLVM_CXXFLAGS))

CXXFLAGS += -I$(LLVM_PROJECT)/llvm/lib/Target/X86
CXXFLAGS += -I$(BUILD)/lib/Target/X86
CXXFLAGS += -I$(LLVM_PROJECT)/llvm/lib/Target/AArch64
CXXFLAGS += -I$(BUILD)/lib/Target/AArch64
CXXFLAGS += -I$(LLVM_PROJECT)/llvm/lib/Target/RISCV
CXXFLAGS += -I$(BUILD)/lib/Target/RISCV

CXXFLAGS += -I$(ROOT)/include
CXXFLAGS += -I$(ROOT)/include-third-party
CXXFLAGS += -I$(ROOT)/build-x86/generated
CXXFLAGS += -I$(BUILD)/include

IWYU = $(ROOT)/build-iwyu/bin/include-what-you-use
SRC_FILES = WINIC BenchmarkGenerator LLVMEnvironment AssemblyFile Templates ErrorCode CustomDebug IOSystem Globals
# run include-what-you-use for the given source file
iwyu:
	@$(IWYU) -isystem /usr/include/c++/13 -isystem /usr/include/x86_64-linux-gnu/c++/13 $(CXXFLAGS) $(ROOT)/src/WINIC.cpp $(LDFLAGS)
	@$(IWYU) -isystem /usr/include/c++/13 -isystem /usr/include/x86_64-linux-gnu/c++/13 $(CXXFLAGS) $(ROOT)/src/BenchmarkGenerator.cpp $(LDFLAGS)
	@$(IWYU) -isystem /usr/include/c++/13 -isystem /usr/include/x86_64-linux-gnu/c++/13 $(CXXFLAGS) $(ROOT)/src/LLVMEnvironment.cpp $(LDFLAGS)
	@$(IWYU) -isystem /usr/include/c++/13 -isystem /usr/include/x86_64-linux-gnu/c++/13 $(CXXFLAGS) $(ROOT)/src/AssemblyFile.cpp $(LDFLAGS)
	@$(IWYU) -isystem /usr/include/c++/13 -isystem /usr/include/x86_64-linux-gnu/c++/13 $(CXXFLAGS) $(ROOT)/src/ErrorCode.cpp $(LDFLAGS)
	@$(IWYU) -isystem /usr/include/c++/13 -isystem /usr/include/x86_64-linux-gnu/c++/13 $(CXXFLAGS) $(ROOT)/src/CustomDebug.cpp $(LDFLAGS)
	@$(IWYU) -isystem /usr/include/c++/13 -isystem /usr/include/x86_64-linux-gnu/c++/13 $(CXXFLAGS) $(ROOT)/src/IOSystem.cpp $(LDFLAGS)
	@$(IWYU) -isystem /usr/include/c++/13 -isystem /usr/include/x86_64-linux-gnu/c++/13 $(CXXFLAGS) $(ROOT)/src/Globals.cpp $(LDFLAGS)
	@$(IWYU) -isystem /usr/include/c++/13 -isystem /usr/include/x86_64-linux-gnu/c++/13 $(CXXFLAGS) $(ROOT)/include/LLVMDebug.h $(LDFLAGS)
