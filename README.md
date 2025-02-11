
cd Desktop/Bachelor_Local/llvm-project/build/
clang++ -std=c++17 ./own_tools/llvm_instr_gen.cpp -o llvm_instr_gen `./bin/llvm-config --cxxflags --ldflags --system-libs --libs`