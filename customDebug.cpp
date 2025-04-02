#include <iostream>
#include <stack>
#include <string>

static bool debug = false;
static std::string dbgContext = "";
static std::stack<std::string> dbgContextStack;

template <typename... Args> static void dbg(const char *func, Args &&...args) {
    if (debug) {
        std::cout << "[" << func << "]: ";
        (std::cout << ... << args) << "\n" << std::flush;
    }
}
