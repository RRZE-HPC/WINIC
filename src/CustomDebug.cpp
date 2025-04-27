#include "CustomDebug.h"
// #include <iostream>
#include <set>

bool debug = false;

// clang-format off
std::set<std::string> functionBlacklist = {
    "isVariant",
    "calculateCycles",
    "genLatBenchmark4",
    "genLatMeasurements4",
    "findFullyConnected",
    "genInst",
    // "runBenchmark",
    // "measureThroughput",
    "buildLatDatabase4",
    "genTPInnerLoop",
    // "main",
    "setUp",
    "buildTPDatabase",
    // "genTPBenchmark",
};
// clang-format on


// class BenchmarkGenerator; // forward declaration

// class Debugger {
// public:
//     Debugger(const BenchmarkGenerator &gen) : gen(gen) {}

//     template <typename... Args>
//     void dbg(const char *func, Args&&... args) const {
//         if (debug && functionBlacklist.find(func) == functionBlacklist.end()) {
//             std::cout << "[" << func << "]: ";
//             (std::cout << ... << wrapArg(args)) << "\n" << std::flush;
//         }
//     }

// private:
//     const BenchmarkGenerator &gen;

//     template <typename T>
//     const T& wrapArg(const T &arg) const {
//         return arg;
//     }

//     std::string wrapArg(const LatMeasurement4 &m) const {
//         return gen.latMeasurement4ToString(m);
//     }

//     bool debug = true; // or configurable
//     static std::set<std::string> functionBlacklist = {
//         "genInst",
//         "signalHandler",
//         "calculateCycles",
//         "isVariant",
//         "runBenchmark",
//         "genLatBenchmark4",
//         "genLatMeasurements4",
//         "measureSafely",
//         "findFullyConnected",
//         // "buildLatDatabase4",
//         // "genTPInnerLoop",
//         // "main",
//         // "setUp",
//     };
// };

