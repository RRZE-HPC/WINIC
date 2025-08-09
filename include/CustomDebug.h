#ifndef CUSTOM_DEBUG_H
#define CUSTOM_DEBUG_H

#include <iostream>
#include <set>
#include <sstream>
#include <stddef.h>
#include <string>
#include <utility>
#include <vector>

namespace winic {

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

template <typename... Args> static void dbg(const char *Func, Args &&...Arguments) {
    if (debug && functionBlacklist.find(Func) == functionBlacklist.end()) {
        std::cout << "[" << Func << "]: ";
        (std::cout << ... << Arguments) << "\n" << std::flush;
    }
}

template <typename... Args> static void out(std::ostream &Osteam, Args &&...Arguments) {
    (Osteam << ... << Arguments) << "\n" << std::flush;
}

// concatenate all arguments into a string
template <typename... Args> static std::string str(Args &&...Arguments) {
    std::ostringstream oss;
    oss.precision(3);
    (oss << ... << Arguments) << std::flush;
    return oss.str();
}

} // namespace winic

#endif // CUSTOM_DEBUG_H
