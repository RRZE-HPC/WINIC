#include "CustomDebug.h"
// #include <iostream>
#include <set>

bool debug = false;

// clang-format off
std::set<std::string> functionBlacklist = {
    // "main",
    // "setUp",
    // "isVariant",
    // "runBenchmark",
    // "genLatBenchmark",
    "genLatMeasurements",
    // "buildLatDatabase",
    "findFullyConnected",
    "genInst",
    // "measureThroughput",
    "genTPInnerLoop",
    "buildTPDatabase",
    // "genTPBenchmark",
    // "calculateCycles",
};
// clang-format on
