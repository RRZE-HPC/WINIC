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
