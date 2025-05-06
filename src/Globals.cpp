#include "Globals.h"

LLVMEnvironment env;

std::unique_ptr<std::ofstream> fileStream;
std::ostream* ios = &std::cout;