#include "AssemblyFile.h"

#include "Templates.h"                // for Template
#include "llvm/Support/raw_ostream.h" // for raw_string_ostream, raw_ostream
#include <assert.h>                   // for assert
#include <cstdlib>                    // for size_t
#include <string>                     // for basic_string, string, operator<

// static std::string replaceFunctionName(std::string Str, std::string Name) {
//     size_t pos = Str.find("latency");
//     if (pos != std::string::npos) {
//         Str.replace(pos, 7, Name);
//     }
//     return Str;
// }
std::string replaceFunctionName(std::string Str, const std::string Name) {
    size_t startPos = 0;
    while ((startPos = Str.find("functionName", startPos)) != std::string::npos) {
        Str.replace(startPos, 12, Name);
        startPos += Name.length(); // Move past the last replaced part
    }
    return Str;
}
std::string replaceAllInstances(std::string Str, std::string ToReplace,
                                const std::string Replacement) {
    size_t startPos = 0;
    while ((startPos = Str.find(ToReplace, startPos)) != std::string::npos) {
        Str.replace(startPos, ToReplace.size(), Replacement);
        startPos += Replacement.length(); // Move past the last replaced part
    }
    return Str;
}

// void AssemblyFile::setArch(llvm::Triple::ArchType Arch) { this->Arch = Arch; }
ErrorCode AssemblyFile::addInitFunction(std::string Name, std::string InitCode) {
    initFunctions.insert({Name, InitCode});
    return SUCCESS;
}
ErrorCode AssemblyFile::addBenchFunction(std::string Name, std::string PreLoopCode,
                                         std::string LoopCode, std::string PostLoopCode,
                                         std::string InitFunction) {
    assert(getInitFunctionNames().find(InitFunction) != getInitFunctionNames().end() &&
           "Init function not found");
    benchFunctions.insert({Name, PreLoopCode, LoopCode, PostLoopCode, InitFunction});
    return SUCCESS;
}
/**
 * @brief Returns a list of all function names in the assembly file.
 * @return std::list<std::string> List of function names.
 */
std::set<std::string> AssemblyFile::getBenchFunctionNames() {
    std::set<std::string> functionNames;
    for (BenchFunction function : benchFunctions)
        functionNames.insert(function.name);
    return functionNames;
}

std::set<std::string> AssemblyFile::getInitFunctionNames() {
    std::set<std::string> functionNames;
    for (InitFunction function : initFunctions)
        functionNames.insert(function.name);
    return functionNames;
}

std::string AssemblyFile::getInitNameFor(std::string BenchName) {
    for (BenchFunction function : benchFunctions)
        if (function.name == BenchName) return function.initFunction;
    return "";
}

/**
 * @brief Generates an assembly file containing all functions in the list.
 * @return std::string Assembly code as a string.
 */
std::string AssemblyFile::generateAssembly() {
    std::string result;
    llvm::raw_string_ostream rso(result);
    Template benchTemplate = getTemplate(arch);
    rso << benchTemplate.prefix;
    for (BenchFunction function : benchFunctions)
        rso << generateBenchFunction(function) << "\n";
    for (InitFunction function : initFunctions)
        rso << generateInitFunction(function) << "\n";
    rso << benchTemplate.suffix;
    return result;
}

std::string AssemblyFile::generateBenchFunction(BenchFunction Function) {
    std::string result;
    llvm::raw_string_ostream rso(result);
    Template benchTemplate = getTemplate(arch);
    rso << replaceFunctionName(benchTemplate.preLoop, Function.name);
    rso << Function.preLoopCode;
    rso << replaceFunctionName(benchTemplate.beginLoop, Function.name);
    rso << Function.loopCode;
    rso << replaceFunctionName(benchTemplate.endLoop, Function.name);
    rso << Function.postLoopCode;
    rso << replaceFunctionName(benchTemplate.postLoop, Function.name);
    return result;
}

std::string AssemblyFile::generateInitFunction(InitFunction Function) {
    std::string result;
    llvm::raw_string_ostream rso(result);
    Template benchTemplate = getTemplate(arch);
    rso << replaceFunctionName(benchTemplate.preInit, Function.name);
    rso << Function.initCode;
    rso << replaceFunctionName(benchTemplate.postInit, Function.name);
    return result;
}
