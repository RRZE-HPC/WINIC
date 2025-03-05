CC = g++
CXXFLAGS = -std=c++17 
LLVM_PROJECT = /home/hpc/ihpc/ihpc149h/bachelor/llvm-project
# BUILD = build_x86
#this is aarch
BUILD = build_all
LLVM_CONFIG = $(LLVM_PROJECT)/$(BUILD)/bin/llvm-config
LDFLAGS = $(shell $(LLVM_CONFIG) --cxxflags --ldflags --system-libs --libs)
LDFLAGS += -I$(LLVM_PROJECT)/llvm/lib/Target/X86
LDFLAGS += -I$(LLVM_PROJECT)/$(BUILD)/lib/Target/X86
LDFLAGS += -I$(LLVM_PROJECT)/llvm/lib/Target/AArch64
LDFLAGS += -I$(LLVM_PROJECT)/$(BUILD)/lib/Target/AArch64
CLANG_PATH = "\"$(LLVM_PROJECT)/$(BUILD)/bin/clang\""

all: llvm_instr_gen


test: ./experiment.cpp
	@$(CC) $(CXXFLAGS) -g -O0 $^ -o $@ $(LDFLAGS)

llvm_instr_gen: ./llvm_instr_gen.cpp ./templates.cpp ./benchmarkGenerator.cpp ./customErrors.cpp
	@$(CC) $(CXXFLAGS) $^ -o $@ $(LDFLAGS) -DCLANG_PATH=$(CLANG_PATH)

quick: ./quick_exec.cpp
	@$(CC) $(CXXFLAGS) -g -O0 $^ -o $@ $(LDFLAGS)

clean:
	rm -f llvm_instr_gen experiment quick