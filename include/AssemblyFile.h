#ifndef ASSEMBLY_FILE_H
#define ASSEMBLY_FILE_H

#include "ErrorCode.h"
#include "llvm/TargetParser/Triple.h"
#include <set>
#include <string>

struct BenchFunction {
    std::string name;
    std::string preLoopCode;
    std::string loopCode;
    std::string postLoopCode;
    // BenchFunctions store the identifier of an init function that will be run before a benchmark
    std::string initFunction;

    bool operator<(const BenchFunction &Other) const { return name < Other.name; }
};

struct InitFunction {
    std::string name;
    std::string initCode;

    bool operator<(const InitFunction &Other) const { return name < Other.name; }
};

std::string replaceFunctionName(std::string Str, const std::string Name);
std::string replaceAllInstances(std::string Str, std::string ToReplace,
                                       const std::string Replacement);

class AssemblyFile {
  public:
    AssemblyFile() = default;
    AssemblyFile(llvm::Triple::ArchType Arch) { this->arch = Arch; }
    ~AssemblyFile() = default;

    void setArch(llvm::Triple::ArchType Arch) { this->arch = Arch; }
    ErrorCode addInitFunction(std::string Name, std::string InitCode);
    ErrorCode addBenchFunction(std::string Name, std::string PreLoopCode, std::string LoopCode,
                               std::string PostLoopCode, std::string InitFunction);
    /**
     * @brief Returns a list of all function names in the assembly file.
     * @return std::list<std::string> List of function names.
     */
    std::set<std::string> getBenchFunctionNames();

    std::set<std::string> getInitFunctionNames();

    std::string getInitNameFor(std::string BenchName);

    /**
     * @brief Generates an assembly file containing all functions in the list.
     * @return std::string Assembly code as a string.
     */
    std::string generateAssembly();

  private:
    llvm::Triple::ArchType arch;
    // Template benchTemplate;
    std::set<BenchFunction> benchFunctions;
    std::set<InitFunction> initFunctions;
    std::string generateBenchFunction(BenchFunction Function);
    std::string generateInitFunction(InitFunction Function);
};

#endif // ASSEMBLY_FILE
