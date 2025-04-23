#ifndef CUSTOM_DEBUG_H
#define CUSTOM_DEBUG_H

#include <iostream>
#include <set>
#include <string>
#include <vector>

extern bool debug;

extern std::set<std::string> functionBlacklist;

// override operator<< for any std::pair
template <typename T1, typename T2>
inline std::ostream &operator<<(std::ostream &OS, const std::pair<T1, T2> &P) {
    OS << P.first << "-" << P.second;
    return OS;
}

// override operator<< for any std::vector
template <typename T> inline std::ostream &operator<<(std::ostream &OS, const std::vector<T> &V) {
    OS << "[";
    for (size_t i = 0; i < V.size(); ++i) {
        OS << V[i];
        if (i + 1 < V.size()) OS << ", ";
    }
    OS << "]";
    return OS;
}

// debug function which can take any number of arguments
template <typename... Args> static void dbg(const char *Func, Args &&...Arguments) {
    if (debug && functionBlacklist.find(Func) == functionBlacklist.end()) {
        std::cout << "[" << Func << "]: ";
        (std::cout << ... << Arguments) << "\n" << std::flush;
    }
}

#endif // CUSTOM_DEBUG_H