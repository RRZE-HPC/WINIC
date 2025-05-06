#ifndef LLVM_INSTR_GEN_H
#define LLVM_INSTR_GEN_H

#include "AssemblyFile.h"       // for AssemblyFile
#include "ErrorCode.h"          // for ErrorCode
#include "Globals.h"            // for LatMeasurement4 (ptr only), Dependen...
#include "llvm/MC/MCRegister.h" // for MCRegister
#include <cmath>                // for round, abs
#include <list>                 // for list
#include <map>                  // for map
#include <set>                  // for set
#include <string>               // for string, basic_string
#include <tuple>                // for tuple
#include <unordered_map>        // for unordered_map
#include <utility>              // for pair
#include <variant>              // for tuple
#include <vector>               // for vector

class LLVMEnvironment;
namespace llvm {
class MCInst;
}

class BenchmarkGenerator;
class LLVMEnvironment;
struct LatMeasurement4;

#ifndef CLANG_PATH
#define CLANG_PATH "usr/bin/clang"
#endif

using namespace llvm;

struct TPResult {
    ErrorCode ec;
    double lowerTP;
    double upperTP;
};

static std::unordered_map<unsigned, TPResult> throughputDatabase;
// opcodes in this list will be used as helpers wherever possible even when they define a
// superregister of the register we need a helper for
static std::list<unsigned> priorityTPHelper;

static std::vector<float> latencyDatabase;
static std::vector<ErrorCode> errorCodeDatabase;
static std::list<std::tuple<unsigned, std::set<MCRegister>, std::set<MCRegister>>>
    helperInstructions; // opcode, read/write register
static bool dbgToFile = true;
extern LLVMEnvironment env;

std::pair<ErrorCode, std::unordered_map<std::string, std::list<double>>>
runBenchmark(AssemblyFile Assembly, int N, unsigned Runs);

// returns a list of dependencies between Inst1 and Inst2, taking into account implicit and explicit
// defs/uses
std::list<DependencyType> getDependencies(MCInst Inst1, MCInst Inst2);

// if a helper is needed and one can be found returns {SUCCESS, helperOpcode, helperConstraints}
// if no helper is needed returns {SUCCESS, -1, {}}
// if one is needed but none can be found returns {ERROR_NO_HELPER, -1, {}}
std::tuple<ErrorCode, int, std::map<unsigned, MCRegister>>
getTPHelperInstruction(unsigned Opcode, bool BreakDependencyOnSuperreg);

// Measure the througput of the instructions with Opcode. Runs multiple benchmarks to correct
// overhead of loop instructions. This may segfault e.g. on privileged instructions like CLGI
std::pair<ErrorCode, double> measureThroughput(unsigned Opcode, double Frequency);

// Measure the latency of the instructions with Opcode. Runs multiple benchmarks to correct
// overhead of loop instructions.
// This may segfault e.g. on privileged instructions like CLGI
std::pair<ErrorCode, double> measureLatency(unsigned Opcode, double Frequency);

std::pair<ErrorCode, double> calculateCycles(double Runtime, double UnrolledRuntime,
                                             unsigned NumInst, unsigned LoopCount,
                                             double Frequency);

// runs two benchmarks to correct eventual interference with loop instructions
// this may segfault e.g. on privileged instructions like CLGI
std::pair<ErrorCode, double> measureLatency4(std::list<LatMeasurement4> Measurements,
                                             double Frequency);

// calls one of the measure functions in a subprocess to recover from segfaults during the
// benchmarking process Type = "t" for throughput or "l" for latency
std::pair<ErrorCode, double> measureInSubprocess(unsigned Opcode, double Frequency,
                                                 std::string Type);

std::pair<ErrorCode, double> measureInSubprocess(std::list<LatMeasurement4> Measurements,
                                                 double Frequency, std::string Type);

// measure the first MaxOpcode instructions or all if MaxOpcode is zero or not supplied
int buildTPDatabase(double Frequency, unsigned MinOpcode = 0, unsigned MaxOpcode = 0);

// measure the first MaxOpcode instructions or all if MaxOpcode is zero or not supplied
int buildLatDatabase(double Frequency, unsigned MinOpcode = 0, unsigned MaxOpcode = 0);

inline bool equalWithTolerance(double A, double B) { return std::abs(A - B) <= 0.1 * A; }
inline bool smallerEqWithTolerance(double A, double B) { return A < B || equalWithTolerance(A, B); }
inline bool isSus(double A) { return !equalWithTolerance(std::round(A), A); }

bool hasConnectionTo(std::vector<std::pair<unsigned, unsigned>> Values, unsigned First,
                     unsigned Second);

std::string pairVectorToString(std::vector<std::pair<unsigned, unsigned>> Values);

std::vector<std::pair<unsigned, unsigned>>
findFullyConnected(std::vector<std::pair<unsigned, unsigned>> Edges, unsigned Number);

bool isVariant(unsigned A, unsigned B);

void findHelperInstructions(std::vector<LatMeasurement4> Measurements, LLVMEnvironment &Env,
                            double Frequency);

// measure the first MaxOpcode instructions or all if MaxOpcode is zero or not supplied
int buildLatDatabase4(double Frequency, unsigned MinOpcode = 0, unsigned MaxOpcode = 0);

int main(int argc, char **argv);

#endif // LLVM_INSTR_GEN_H