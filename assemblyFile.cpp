#include "customErrors.cpp"
#include "templates.cpp"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/ARMTargetParser.h"
#include "llvm/TargetParser/Triple.h"
#include <cstdlib>
#include <list>
#include <string>

struct BenchFunction {
    std::string name;
    std::string preLoopCode;
    std::string loopCode;
    std::string postLoopCode;
};

struct InitFunction {
    std::string name;
    std::string initCode;
};

static std::string replaceFunctionName(std::string Str, std::string Name) {
    size_t pos = Str.find("latency");
    if (pos != std::string::npos) {
        Str.replace(pos, 7, Name);
    }
    return Str;
}

class AssemblyFile {
  public:
    AssemblyFile() = default;
    AssemblyFile(llvm::Triple::ArchType Arch) { this->Arch = Arch; }
    ~AssemblyFile() = default;

    void setArch(llvm::Triple::ArchType Arch) { this->Arch = Arch; }
    ErrorCode addInitFunction(std::string Name, std::string InitCode) {
        initFunctions.push_back({Name, InitCode});
        return SUCCESS;
    }
    ErrorCode addBenchFunction(std::string Name, std::string PreLoopCode, std::string LoopCode,
                               std::string PostLoopCode) {
        benchFunctions.push_back({Name, PreLoopCode, LoopCode, PostLoopCode});
        return SUCCESS;
    }
    /**
     * @brief Returns a list of all function names in the assembly file.
     * @return std::list<std::string> List of function names.
     */
    std::list<std::string> getFunctionNames() {
        std::list<std::string> functionNames;
        for (BenchFunction function : benchFunctions)
            functionNames.push_back(function.name);
        for (InitFunction function : initFunctions)
            functionNames.push_back(function.name);
        return functionNames;
    }

    /**
     * @brief Generates an assembly file containing all functions in the list.
     * @return std::string Assembly code as a string.
     */
    std::string generateAssembly() {
        std::string result;
        llvm::raw_string_ostream rso(result);
        Template benchTemplate = getTemplate(Arch);
        rso << benchTemplate.prefix;
        for (BenchFunction function : benchFunctions)
            rso << generateBenchFunction(function) << "\n";
        for (InitFunction function : initFunctions)
            rso << generateInitFunction(function) << "\n";

        return result;
    }

  private:
    llvm::Triple::ArchType Arch;
    // Template benchTemplate;
    std::list<BenchFunction> benchFunctions;
    std::list<InitFunction> initFunctions;
    std::string generateBenchFunction(BenchFunction Function) {
        std::string result;
        llvm::raw_string_ostream rso(result);
        Template benchTemplate = getTemplate(Arch);
        rso << replaceFunctionName(benchTemplate.preLoop, Function.name);
        rso << Function.preLoopCode;
        rso << benchTemplate.beginLoop;
        rso << Function.loopCode;
        rso << benchTemplate.endLoop;
        rso << Function.postLoopCode;
        rso << replaceFunctionName(benchTemplate.postLoop, Function.name);
        return result;
    }
    std::string generateInitFunction(InitFunction Function) {
        std::string result;
        llvm::raw_string_ostream rso(result);
        Template benchTemplate = getTemplate(Arch);
        rso << replaceFunctionName(benchTemplate.preInit, Function.name);
        rso << Function.initCode;
        rso << replaceFunctionName(benchTemplate.postInit, Function.name);
        return result;
    }
};
