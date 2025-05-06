CC = g++
# CC = "$(DEFAULT_PROJECT)/$(DEFAULT_BUILD)/bin/clang"
SRC = ./src
INCLUDE = /home/hpc/ihpc/ihpc149h/bachelor/llvm-project/own_tools/llvm-bench/include

# -fsanitize=address -fno-omit-frame-pointer or debug symbols: -g -O0
# CXXFLAGS = -std=c++17 -g -O0 -fsanitize=address -fno-omit-frame-pointer
CXXFLAGS = -std=c++17

#for valgrind (work build)
# CXXFLAGS = -std=c++17 -g -march=nehalem -mno-avx512f -O0
# LLVM_PROJECT = /home/woody/ihpc/ihpc149h/bachelor/llvm-project
# BUILD = build_haswell

LLVM_PROJECT = /home/hpc/ihpc/ihpc149h/bachelor/llvm-project
BUILD = build_x86
# this is aarch
# BUILD = build_all
CLANG_PATH = "\"$(LLVM_PROJECT)/$(BUILD)/bin/clang\""

LLVM_CONFIG = $(LLVM_PROJECT)/$(BUILD)/bin/llvm-config
LDFLAGS = $(shell $(LLVM_CONFIG) --cxxflags --ldflags --system-libs --libs)
LDFLAGS += -I$(LLVM_PROJECT)/llvm/lib/Target/X86
LDFLAGS += -I$(LLVM_PROJECT)/$(BUILD)/lib/Target/X86
LDFLAGS += -I$(LLVM_PROJECT)/llvm/lib/Target/AArch64
LDFLAGS += -I$(LLVM_PROJECT)/$(BUILD)/lib/Target/AArch64

# Add Clang include directories
# LDFLAGS += -I$(LLVM_PROJECT)/llvm/include
# LDFLAGS += -I$(LLVM_PROJECT)/$(BUILD)/include
LDFLAGS += -I$(LLVM_PROJECT)/clang/include/
LDFLAGS += -I$(LLVM_PROJECT)/$(BUILD)/tools/clang/include
LDFLAGS += -no-pie

# LDFLAGS += "-L$(LLVM_PROJECT)/llvm/lib/ -lclang"


CXXFLAGS += -I$(INCLUDE)
CXXFLAGS += -MMD -MP

SRC_FILES = LLVMBench BenchmarkGenerator LLVMEnvironment AssemblyFile Templates ErrorCode CustomDebug Globals
OBJ_DIR = obj
OBJS = $(addprefix $(OBJ_DIR)/, $(addsuffix .o, $(SRC_FILES)))
DEPS = $(OBJS:.o=.d)
SRC_CPP = $(addprefix $(SRC)/, $(addsuffix .cpp, $(SRC_FILES)))
SRC_H = $(addprefix $(SRC)/, $(addsuffix .h, $(SRC_FILES)))
IWYU = /home/woody/ihpc/ihpc149h/bachelor/llvm-project/build/bin/include-what-you-use

all: LLVMBench

# Rule to build each object file in obj/
$(OBJ_DIR)/%.o: $(SRC)/%.cpp
	@mkdir -p $(OBJ_DIR)
	@$(CC) $(CXXFLAGS) -c $< -o $@ $(LDFLAGS) -DCLANG_PATH=$(CLANG_PATH)

# Link object files into final executable
LLVMBench: $(OBJS)
	@$(CC) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

-include $(DEPS)

test: ./experiment.cpp
	@$(CC) $(CXXFLAGS) -g -O0 $^ -o $@ $(LDFLAGS)

quick: ./quick_exec.cpp
	@$(CC) $(CXXFLAGS) -g -O0 $^ -o $@ $(LDFLAGS)

# run include-what-you-use for the given source file
iwyu:
	@$(IWYU) -isystem /usr/include/c++/13 -isystem /usr/include/x86_64-linux-gnu/c++/13 $(CXXFLAGS) src/Globals.cpp $(LDFLAGS)

clean:
	rm -rf LLVMBench experiment quick $(OBJ_DIR)