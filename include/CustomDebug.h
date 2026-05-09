#ifndef CUSTOM_DEBUG_H
#define CUSTOM_DEBUG_H

#include <cstddef>
#include <iostream>
#include <list>
#include <map>
#include <set>
#include <sstream>
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

// override operator<< for any std::list
template <typename T> inline std::ostream &operator<<(std::ostream &OS, const std::list<T> &L) {
    std::vector<T> vec(L.begin(), L.end());
    OS << vec;
    return OS;
}

// override operator<< for any std::set
template <typename T> inline std::ostream &operator<<(std::ostream &OS, const std::set<T> &S) {
    OS << "set{";
    size_t count = 0;
    for (const auto &elem : S) {
        OS << elem;
        if (count + 1 < S.size()) OS << ", ";
        count++;
    }
    OS << "}";
    return OS;
}

// override operator<< for any std:map
template <typename K, typename V>
inline std::ostream &operator<<(std::ostream &OS, const std::map<K, V> &M) {
    OS << "map{";
    size_t count = 0;
    for (const auto &pair : M) {
        OS << pair.first << ": " << pair.second;
        if (count + 1 < M.size()) OS << ", ";
        count++;
    }
    OS << "}";
    return OS;
}

template <typename... Args> static void dbg(const char *Func, Args &&...Arguments) {
    if (debug && functionBlacklist.find(Func) == functionBlacklist.end()) {
        std::cout << "[" << Func << "]: ";
        (std::cout << ... << Arguments) << std::endl;
    }
}

template <typename... Args> static void out(std::ostream &Osteam, Args &&...Arguments) {
    (Osteam << ... << Arguments) << std::endl;
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
