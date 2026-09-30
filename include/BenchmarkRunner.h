#ifndef BENCHMARK_RUNNER_H
#define BENCHMARK_RUNNER_H

#include "AssemblyFile.h"
#include "ErrorCode.h"
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace winic {

class BenchmarkRunner {
  public:
    BenchmarkRunner(std::string SPath, std::string SOPath, double ClockFrequency,
                    double MaxCyclesPerInstruction, bool OutputASM)
        : sPath(SPath), soPath(SOPath), clockFrequency(ClockFrequency),
          maxCyclesPerInstruction(MaxCyclesPerInstruction), outputASM(OutputASM) {}

    /**
     * \brief Creates an assembly file and assembles it.
     *
     * \param Assembly The assembly file.
     * \return E_FILE if the file canntot be created, E_EXEC if execution fails, E_ASSEMBLY if
     * assembly itself fails or SUCCESS.
     */
    ErrorCode assembleBenchmark(AssemblyFile Assembly);

    /**
     * \brief Assembles the file at SPath to a shared object file.
     *
     * \param SPath the path of the input file
     * \return  E_EXEC if execution fails, E_ASSEMBLY if assembly itself fails or SUCCESS..
     */
    ErrorCode assembleBenchmark(std::string SPath);

    /**
     * \brief Runs a benchmark on the provided assembly file.
     *
     * \param Assembly The assembly file to benchmark.
     * \param N Number of loop iterations per run.
     * \param Runs Number of benchmark runs.
     * \return Pair of error code and a map from function names to vector of measured times.
     */
    std::pair<ErrorCode, std::unordered_map<std::string, std::vector<double>>>
    runBenchmark(AssemblyFile Assembly, unsigned N, unsigned Runs);

  private:
    std::string sPath;
    std::string soPath;
    double clockFrequency;
    double maxCyclesPerInstruction;
    bool outputASM;
};

} // namespace winic

#endif // BENCHMARK_RUNNER_H