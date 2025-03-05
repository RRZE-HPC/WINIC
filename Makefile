CC = g++
CXXFLAGS = -std=c++17 
LLVM_PROJECT = /home/hpc/ihpc/ihpc149h/bachelor/llvm-project
LLVM_CONFIG = $(LLVM_PROJECT)/build_aarch64/bin/llvm-config
LDFLAGS = $(shell $(LLVM_CONFIG) --cxxflags --ldflags --system-libs --libs)
LDFLAGS += -I$(LLVM_PROJECT)/llvm/lib/Target/X86
LDFLAGS += -I$(LLVM_PROJECT)/build/lib/Target/X86
LDFLAGS += -I$(LLVM_PROJECT)/llvm/lib/Target/AArch64
LDFLAGS += -I$(LLVM_PROJECT)/build/lib/Target/AArch64
CLANG_PATH = "\"$(LLVM_PROJECT)/build_all/bin/clang\""

all: llvm_instr_gen


test: ./experiment.cpp
	@$(CC) $(CXXFLAGS) -g -O0 $^ -o $@ $(LDFLAGS)

llvm_instr_gen: ./llvm_instr_gen.cpp ./templates.cpp ./benchmarkGenerator.cpp ./customErrors.cpp
	@$(CC) $(CXXFLAGS) $^ -o $@ $(LDFLAGS) -DCLANG_PATH=$(CLANG_PATH)

quick: ./quick_exec.cpp
	@$(CC) $(CXXFLAGS) -g -O0 $^ -o $@ $(LDFLAGS)

clean:
	rm -f llvm_instr_gen experiment