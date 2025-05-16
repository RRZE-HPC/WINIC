CC = g++
CXXFLAGS = -std=c++17

all: quick

quick: ./quick_exec.cpp
	@$(CC) $(CXXFLAGS) -g -O0 $^ -o $@

IWYU = /home/woody/ihpc/ihpc149h/bachelor/llvm-project/build/bin/include-what-you-use
SRC_FILES = LLVMBench BenchmarkGenerator LLVMEnvironment AssemblyFile Templates ErrorCode CustomDebug Globals
# run include-what-you-use for the given source file
iwyu:
	@$(IWYU) -isystem /usr/include/c++/13 -isystem /usr/include/x86_64-linux-gnu/c++/13 $(CXXFLAGS) src/LLVMBench.cpp

clean:
	rm -rf quick