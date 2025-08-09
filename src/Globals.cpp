#include "Globals.h"
#
#include <iostream>

namespace winic {

LLVMEnvironment &getEnv() {
    static LLVMEnvironment env;
    return env;
}

std::unique_ptr<std::ofstream> fileStream;
std::ostream *ios = &std::cout;
bool includeX87FP;

void setOutputToFile(const std::string &Filename) {
    fileStream = std::make_unique<std::ofstream>(Filename);
    if (fileStream->is_open()) {
        ios = fileStream.get(); // Redirect global output
    } else {
        std::cerr << "Failed to open file: " << Filename << std::endl;
        ios = &std::cout; // Fallback
    }
}

} // namespace winic
