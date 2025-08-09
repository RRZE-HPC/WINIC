#ifndef ASSEMBLY_FILE_H
#define ASSEMBLY_FILE_H

#include "ErrorCode.h"
#include "llvm/TargetParser/Triple.h"
#include <set>
#include <string>

namespace winic {

struct BenchFunction {
    std::string name;
    std::string preLoopCode;
    std::string loopCode;
    std::string postLoopCode;
    /// this initfunction will be called before the benchmark
    std::string initFunction;

    bool operator<(const BenchFunction &Other) const { return name < Other.name; }
};

struct InitFunction {
    std::string name;
    std::string initCode;

    bool operator<(const InitFunction &Other) const { return name < Other.name; }
};

/**
 * \brief Replaces all instances of "functionName" in the string with the given name.
 * \param Str The string to modify.
 * \param Name The function name to insert.
 * \return Modified string with replacements.
 */
std::string replaceFunctionName(std::string Str, const std::string Name);

/**
 * \brief Replaces all instances of a substring in a string with another string.
 * \param Str The string to modify.
 * \param ToReplace The substring to replace.
 * \param Replacement The string to replace with.
 * \return Modified string with replacements.
 */
std::string replaceAllInstances(std::string Str, std::string ToReplace,
                                const std::string Replacement);

class AssemblyFile {
  public:
    AssemblyFile() = default;
    AssemblyFile(llvm::Triple::ArchType Arch) { this->arch = Arch; }
    ~AssemblyFile() = default;

    void setArch(llvm::Triple::ArchType Arch) { this->arch = Arch; }

    /**
     * \brief Adds an initialization function to the assembly file.
     * \param Name Name of the initialization function.
     * \param InitCode Code for the initialization function.
     * \return ErrorCode indicating success or failure.
     */
    ErrorCode addInitFunction(std::string Name, std::string InitCode);

    /**
     * \brief Adds a benchmark function to the assembly file.
     * \param Name Name of the benchmark function.
     * \param PreLoopCode Code to execute before the loop.
     * \param LoopCode Code to execute inside the loop.
     * \param PostLoopCode Code to execute after the loop.
     * \param InitFunction Name of the initialization function to run before this benchmark.
     * \return ErrorCode indicating success or failure.
     */
    ErrorCode addBenchFunction(std::string Name, std::string PreLoopCode, std::string LoopCode,
                               std::string PostLoopCode, std::string InitFunction);

    /**
     * \brief Returns a set of all benchmark function names in the assembly file.
     * \return Set of function names.
     */
    std::set<std::string> getBenchFunctionNames();

    /**
     * \brief Returns a set of all initialization function names in the assembly file.
     * \return Set of initialization function names.
     */
    std::set<std::string> getInitFunctionNames();

    /**
     * \brief Returns the name of the initialization function for a given benchmark function.
     * \param BenchName Name of the benchmark function.
     * \return Name of the initialization function.
     */
    std::string getInitNameFor(std::string BenchName);

    std::string getName() const { return name; }

    void setName(std::string Name) { this->name = Name; }

    /**
     * \brief Generates an assembly file containing all functions in the list.
     * \return Assembly code as a string.
     */
    std::string generateAssembly();

  private:
    llvm::Triple::ArchType arch;
    std::string name;
    std::set<BenchFunction> benchFunctions;
    std::set<InitFunction> initFunctions;

    /**
     * \brief Generates the assembly code for a benchmark function.
     * \param Function The benchmark function to generate.
     * \return Assembly code as a string.
     */
    std::string generateBenchFunction(BenchFunction Function);

    /**
     * \brief Generates the assembly code for an initialization function.
     * \param Function The initialization function to generate.
     * \return Assembly code as a string.
     */
    std::string generateInitFunction(InitFunction Function);
};

} // namespace winic

#endif // ASSEMBLY_FILE
