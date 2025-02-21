CC = clang++
CXXFLAGS = -std=c++17  #$(shell ../bin/llvm-config --cxxflags)
LDFLAGS = $(shell ../bin/llvm-config --cxxflags --ldflags --system-libs --libs)
# LDFLAGS = $(shell ../bin/llvm-config --cxxflags --ldflags --system-libs --libs x86)
LDFLAGS += -I/mnt/c/Users/User/Desktop/Bachelor_Local/llvm-project/llvm/lib/Target/X86
LDFLAGS += -I/mnt/c/Users/User/Desktop/Bachelor_Local/llvm-project/build/lib/Target/X86

all: llvm_instr_gen


test: ./experiment.cpp
	@$(CC) $(CXXFLAGS) -g -O0 $^ -o $@ $(LDFLAGS)

llvm_instr_gen: ./llvm_instr_gen.cpp ./templates.cpp ./benchmarkGenerator.cpp ./customErrors.cpp
	@$(CC) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

quick: ./quick_exec.cpp
	@$(CC) $(CXXFLAGS) -g -O0 $^ -o $@ $(LDFLAGS)

clean:
	rm -f llvm_instr_gen experiment