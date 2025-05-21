#include "Globals.h"

#include <iostream> 

LLVMEnvironment &getEnv() {
  static LLVMEnvironment env;
  return env;
}

std::unique_ptr<std::ofstream> fileStream;
std::ostream *ios = &std::cout;
