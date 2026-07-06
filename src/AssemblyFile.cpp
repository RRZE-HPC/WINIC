#include "AssemblyFile.h"

#include "Templates.h"
#include "llvm/Support/raw_ostream.h"
#include <assert.h>
#include <cstdlib>
#include <iostream>
#include <string>

static std::string stripLine(std::string Line) {
    size_t start = Line.find_first_not_of(" \t");
    size_t end = Line.find_last_not_of(" \t");
    if (start == std::string::npos || end == std::string::npos) return "";
    return Line.substr(start, end - start + 1);
}

// strip each line of a block of code and indents it with the specified number of tabs
static std::string indentBlock(std::string Block, unsigned Tabs) {
    std::string result;
    llvm::raw_string_ostream rso(result);
    std::string tabString(Tabs, '\t');
    size_t pos = 0;
    while (pos < Block.size()) {
        size_t nextPos = Block.find('\n', pos);
        if (nextPos == std::string::npos) nextPos = Block.size();
        std::string line = Block.substr(pos, nextPos - pos);
        // strip leading tabs
        line = stripLine(line);
        rso << tabString << line << "\n";
        pos = nextPos + 1;
    }
    return result;
}

namespace winic {

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
    if (arch == 0) {
        std::cerr << "called generateAssembly on uninitialized AssemblyFile" << std::endl;
        return "";
    }
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
    rso << indentBlock(Function.preLoopCode, 2);
    rso << replaceFunctionName(benchTemplate.beginLoop, Function.name);
    rso << indentBlock(Function.loopCode, 2);
    rso << replaceFunctionName(benchTemplate.endLoop, Function.name);
    rso << indentBlock(Function.postLoopCode, 2);
    rso << replaceFunctionName(benchTemplate.postLoop, Function.name);
    return result;
}

std::string AssemblyFile::generateInitFunction(InitFunction Function) {
    std::string result;
    llvm::raw_string_ostream rso(result);
    Template benchTemplate = getTemplate(arch);
    rso << replaceFunctionName(benchTemplate.preInit, Function.name);
    rso << indentBlock(Function.initCode, 2);
    rso << replaceFunctionName(benchTemplate.postInit, Function.name);
    return result;
}

} // namespace winic
