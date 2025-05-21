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
// opcodes in this list will be used as helpers wherever possible even when they define a
// superregister of the register we need a helper for
static std::list<unsigned> priorityTPHelper;
static std::list<std::tuple<unsigned, std::set<MCRegister>, std::set<MCRegister>>>
    helperInstructions; // opcode, read/write register

static std::map<DependencyType, LatMeasurement> helperInstructionsLat;
static std::vector<LatMeasurement> latencyDatabase;

static bool dbgToFile = true;
extern LLVMEnvironment env;

std::pair<ErrorCode, std::unordered_map<std::string, std::list<double>>>
runBenchmark(AssemblyFile Assembly, unsigned N, unsigned Runs);

std::pair<ErrorCode, std::vector<double>> runManual(std::string SPath, unsigned Runs,
                                                    unsigned NumInst, int LoopCount,
                                                    double Frequency, std::string FunctionName,
                                                    std::string InitName = "");

// if a helper is needed and one can be found returns {SUCCESS, helperOpcode, helperConstraints}
// if no helper is needed returns {SUCCESS, MAX_UNSIGNED, {}}
// if one is needed but none can be found returns {ERROR_NO_HELPER, MAX_UNSIGNED, {}}
std::tuple<ErrorCode, unsigned, std::map<unsigned, MCRegister>>
getTPHelperInstruction(unsigned Opcode);

// Measure the througput of the instructions with Opcode. Runs multiple benchmarks to correct
// overhead of loop instructions. This may segfault e.g. on privileged instructions like CLGI.
// returns a lower and an upper bound for the TP.
std::tuple<ErrorCode, double, double> measureThroughput(unsigned Opcode, double Frequency);

std::pair<ErrorCode, double> calculateCycles(double Runtime, double UnrolledRuntime,
                                             unsigned NumInst, unsigned LoopCount, double Frequency,
                                             bool Throughput);

// runs two benchmarks to correct eventual interference with loop instructions
// this may segfault e.g. on privileged instructions like CLGI
std::pair<ErrorCode, double> measureLatency(const std::list<LatMeasurement> &Measurements,
                                            unsigned LoopCount, double Frequency);

// calls measureThroughput in a subprocess to recover from segfaults during the
// benchmarking process
std::tuple<ErrorCode, double, double> measureInSubprocess(unsigned Opcode, double Frequency);

// calls measureLatency in a subprocess to recover from segfaults during the
// benchmarking process
std::pair<ErrorCode, double> measureInSubprocess(const std::list<LatMeasurement> &Measurements,
                                                 unsigned LoopCount, double Frequency);

// calls measureManual in a subprocess to recover from segfaults during the
// benchmarking process
std::pair<ErrorCode, std::vector<double>>
measureInSubprocess(std::string SPath, unsigned Runs, unsigned NumInst, unsigned LoopCount,
                    double Frequency, std::string FunctionName, std::string InitName = "");

// measure the first MaxOpcode instructions or all if MaxOpcode is zero or not supplied
int buildTPDatabase(double Frequency, unsigned MinOpcode = 0, unsigned MaxOpcode = 0,
                    std::unordered_set<unsigned> OpcodeBlacklist = {});

inline bool equalWithTolerance(double A, double B) { return std::abs(A - B) <= 0.1 * A; }
inline bool smallerEqWithTolerance(double A, double B) { return A < B || equalWithTolerance(A, B); }
// usual latencies are close to an integer >= 1
inline bool isUnusualLat(double A) {
    if (A < 1) return true;
    if (A > 600) return true;
    return !equalWithTolerance(std::round(A), A);
}

std::string pairVectorToString(std::vector<std::pair<unsigned, unsigned>> Values);

// check if a and b are the same instruction with different operands
bool isVariant(unsigned A, unsigned B);

// run small test to check if execution results in ILLEGAL_INSTRUCTION or fails in any other way
ErrorCode canMeasure(LatMeasurement Measurement, double Frequency);

void buildLatDatabase(double Frequency);

int main(int argc, char **argv);

#endif // LLVM_INSTR_GEN_H
