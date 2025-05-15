#include "Globals.h"

#include <iostream> // for cout

LLVMEnvironment env;

std::unique_ptr<std::ofstream> fileStream;
std::ostream *ios = &std::cout;