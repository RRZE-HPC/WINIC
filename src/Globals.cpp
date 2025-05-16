#include "Globals.h"

#include <iostream> // for cout

LLVMEnvironment &getEnv() {
  static LLVMEnvironment env;
  return env;
}

std::unique_ptr<std::ofstream> fileStream;
std::ostream *ios = &std::cout;