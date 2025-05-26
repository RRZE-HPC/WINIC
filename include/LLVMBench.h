#ifndef LLVM_INSTR_GEN_H
#define LLVM_INSTR_GEN_H

#include "AssemblyFile.h"
#include "ErrorCode.h"
#include "Globals.h"
#include "llvm/MC/MCRegister.h"
#include <cmath>
#include <list>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

class LLVMEnvironment;

#ifndef CLANG_PATH
#define CLANG_PATH "usr/bin/clang"
#endif

using namespace llvm;

struct TPMeasurement {
    unsigned opcode;
    ErrorCode ec;
    double lowerTP;
    double upperTP;
};

static std::unordered_map<unsigned, TPMeasurement> throughputDatabase;
// opcodes in this list will be used as helpers wherever possible even when they
// define a superregister of the register we need a helper for
static std::list<unsigned> priorityTPHelper;
static std::list<std::tuple<unsigned, std::set<MCRegister>, std::set<MCRegister>>>
    helperInstructions; // opcode, read/write register
static std::map<unsigned, std::string> throughputOutputMessage;

static std::vector<LatMeasurement> latencyDatabase;
static std::map<DependencyType, LatMeasurement> helperInstructionsLat;
// append messages to be printed to the report file
static std::map<unsigned, std::string> latencyOutputMessage;

static bool dbgToFile = true;
extern LLVMEnvironment env;

inline bool equalWithTolerance(double A, double B) { return std::abs(A - B) <= 0.1 * A; }
inline bool smallerEqWithTolerance(double A, double B) { return A < B || equalWithTolerance(A, B); }
// usual latencies are close to an integer >= 1
inline bool isUnusualLat(double A) {
    if (A < 1) return true;
    if (A > 600) return true;
    return !equalWithTolerance(std::round(A), A);
}

/**
 * \brief Runs a benchmark on the provided assembly file.
 *
 * \param Assembly The assembly file to benchmark.
 * \param N Number of loop iterations per run.
 * \param Runs Number of benchmark runs.
 * \return Pair of error code and a map from function names to lists of measured times.
 */
std::pair<ErrorCode, std::unordered_map<std::string, std::list<double>>>
runBenchmark(AssemblyFile Assembly, unsigned N, unsigned Runs);

/**
 * \brief Manually runs a benchmark from an assembly file at a given path.
 *
 * \param SPath Path to the assembly file.
 * \param Runs Number of benchmark runs.
 * \param NumInst Number of instructions in the loop.
 * \param LoopCount Number of loop iterations.
 * \param Frequency CPU frequency in GHz.
 * \param FunctionName Name of the function to benchmark.
 * \param InitName (Optional) Name of the initialization function.
 * \return Pair of error code and a vector of measured times.
 */
std::pair<ErrorCode, std::vector<double>> runManual(std::string SPath, unsigned Runs,
                                                    unsigned NumInst, int LoopCount,
                                                    double Frequency, std::string FunctionName,
                                                    std::string InitName = "");

/**
 * \brief Calculates the cycles per instruction based on measured runtimes.
 *
 * \param Runtime Time for the original loop.
 * \param UnrolledRuntime Time for the unrolled loop.
 * \param NumInst Number of instructions in loop.
 * \param LoopCount Number of loop iterations.
 * \param Frequency CPU frequency in GHz.
 * \param Throughput Whether this is a throughput measurement.
 * \return Pair of error code and cycles per instruction.
 */
std::pair<ErrorCode, double> calculateCycles(double Runtime, double UnrolledRuntime,
                                             unsigned NumInst, unsigned LoopCount, double Frequency,
                                             bool Throughput);

/**
 * \brief Finds a helper instruction for throughput measurement if needed.
 *
 * \param Opcode The opcode to analyze.
 * \return Tuple of error code, helper opcode (or MAX_UNSIGNED if not needed), and helper
 * constraints. Returns ERROR_NO_HELPER if a helper is needed but none can be found.
 */
std::tuple<ErrorCode, unsigned, std::map<unsigned, MCRegister>>
getTPHelperInstruction(unsigned Opcode);

/**
 * \brief Measures the throughput of the instruction with the given opcode.
 *
 * Runs multiple benchmarks to correct overhead of loop instructions. This may segfault e.g.
 * on privileged instructions like CLGI. Returns a lower and an upper bound for the throughput.
 *
 * \param Opcode The opcode to measure.
 * \param Frequency CPU frequency in GHz.
 * \return Tuple of error code, lower bound, and upper bound for throughput.
 */
std::tuple<ErrorCode, double, double> measureThroughput(unsigned Opcode, double Frequency);

/**
 * \brief Measures the latency of the provided instruction chain.
 *
 * Runs two benchmarks to correct eventual interference with loop instructions.
 * This may segfault e.g. on privileged instructions like CLGI.
 *
 * \param Measurements List of latency measurements to perform.
 * \param LoopCount Number of loop iterations.
 * \param Frequency CPU frequency in GHz.
 * \return Pair of error code and measured latency.
 */
std::pair<ErrorCode, double> measureLatency(const std::list<LatMeasurement> &Measurements,
                                            unsigned LoopCount, double Frequency);

/**
 * \brief Calls measureThroughput in a subprocess to recover from segfaults during benchmarking.
 *
 * \param Opcode The opcode to measure.
 * \param Frequency CPU frequency in GHz.
 * \return Tuple of error code, lower bound, and upper bound for throughput.
 */
std::tuple<ErrorCode, double, double> measureInSubprocess(unsigned Opcode, double Frequency);

/**
 * \brief Calls measureLatency in a subprocess to recover from segfaults during benchmarking.
 *
 * \param Measurements List of latency measurements to perform.
 * \param LoopCount Number of loop iterations.
 * \param Frequency CPU frequency in GHz.
 * \return Pair of error code and measured latency.
 */
std::pair<ErrorCode, double> measureInSubprocess(const std::list<LatMeasurement> &Measurements,
                                                 unsigned LoopCount, double Frequency);

/**
 * \brief Calls runManual in a subprocess to recover from segfaults during benchmarking.
 *
 * \param SPath Path to the assembly file.
 * \param Runs Number of benchmark runs.
 * \param NumInst Number of instructions in the loop.
 * \param LoopCount Number of loop iterations.
 * \param Frequency CPU frequency in GHz.
 * \param FunctionName Name of the function to benchmark.
 * \param InitName (Optional) Name of the initialization function.
 * \return Pair of error code and a vector of measured times.
 */
std::pair<ErrorCode, std::vector<double>>
measureInSubprocess(std::string SPath, unsigned Runs, unsigned NumInst, unsigned LoopCount,
                    double Frequency, std::string FunctionName, std::string InitName = "");

/**
 * \brief Checks if two opcodes are variants of the same instruction with different operands.
 *
 * \param A First opcode.
 * \param B Second opcode.
 * \return True if A and B are variants, false otherwise.
 */
bool isVariant(unsigned A, unsigned B);

/**
 * \brief Runs a small test to check if execution results in ILLEGAL_INSTRUCTION or fails in any
 * other way.
 *
 * \param Measurement The latency measurement to test.
 * \param Frequency CPU frequency in GHz.
 * \return Error code indicating the result.
 */
ErrorCode canMeasure(LatMeasurement Measurement, double Frequency);

/**
 * \brief Measures the first MaxOpcode instructions or all if MaxOpcode is zero or not supplied.
 *
 * \param Frequency CPU frequency in GHz.
 * \param MinOpcode Minimum opcode to measure.
 * \param MaxOpcode Maximum opcode to measure.
 * \param OpcodeBlacklist Set of opcodes to skip.
 */
void buildTPDatabase(double Frequency, unsigned MinOpcode = 0, unsigned MaxOpcode = 0,
                     std::unordered_set<unsigned> OpcodeBlacklist = {});

/**
 * \brief Builds the latency database by measuring all relevant instructions.
 *
 * \param Frequency CPU frequency in GHz.
 */
void buildLatDatabase(double Frequency);

/**
 * \brief Main entry point for the LLVMBench program.
 *
 * \param argc Argument count.
 * \param argv Argument vector.
 * \return Program exit code.
 */
int main(int argc, char **argv);

#endif // LLVM_INSTR_GEN_H
