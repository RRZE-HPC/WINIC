#ifndef LLVM_INSTR_GEN_H
#define LLVM_INSTR_GEN_H

#include "AssemblyFile.h"       // for AssemblyFile
#include "ErrorCode.h"          // for ErrorCode
#include "llvm/MC/MCRegister.h" // for MCRegister
#include <cmath>                // for round, abs
#include <csetjmp>              // for sigjmp_buf
#include <csignal>              // for sig_atomic_t
#include <list>                 // for list
#include <set>                  // for set
#include <string>               // for string
#include <tuple>                // for tuple
#include <unordered_map>        // for unordered_map
#include <utility>              // for pair
#include <vector>               // for vector

class BenchmarkGenerator;
class LLVMEnvironment;
struct LatMeasurement4;

#ifndef CLANG_PATH
#define CLANG_PATH "usr/bin/clang"
#endif

using namespace llvm;
static std::unordered_map<unsigned, float> throughputDatabase;
static std::vector<float> latencyDatabase;
static std::vector<ErrorCode> errorCodeDatabase;
static std::list<std::tuple<unsigned, std::set<MCRegister>, std::set<MCRegister>>>
    helperInstructions; // opcode, read/write register
// using dbg = BenchmarkGenerator::dbg;
static bool dbgToFile = true;
extern LLVMEnvironment env;

// Global jump buffer for recovery from illegal instruction
extern sigjmp_buf jumpBuffer;
extern volatile sig_atomic_t lastSignal;
extern void *globalHandle;

// Signal handler for illegal instruction
void signalHandler(int Signum);

void cleanupAfterSignal();

std::pair<ErrorCode, std::unordered_map<std::string, std::list<double>>>
runBenchmark(AssemblyFile Assembly, int N, unsigned Runs);

// runs two benchmarks to correct eventual interference with loop instructions
// this may segfault e.g. on privileged instructions like CLGI
std::pair<ErrorCode, double> measureThroughput(unsigned Opcode, BenchmarkGenerator *Generator,
                                               double Frequency);

// runs two benchmarks to correct eventual interference with loop instructions
// this may segfault e.g. on privileged instructions like CLGI
std::pair<ErrorCode, double> measureLatency(unsigned Opcode, BenchmarkGenerator *Generator,
                                            double Frequency);

std::pair<ErrorCode, double> calculateCycles(double Runtime, double UnrolledRuntime,
                                             unsigned NumInst, unsigned LoopCount,
                                             double Frequency);

// runs two benchmarks to correct eventual interference with loop instructions
// this may segfault e.g. on privileged instructions like CLGI
std::pair<ErrorCode, double> measureLatency4(std::list<LatMeasurement4> Measurements,
                                             BenchmarkGenerator *Generator, double Frequency);

// calls one of the measure functions in a subprocess to recover from segfaults during the
// benchmarking process Type = "t" for throughput or "l" for latency
std::pair<ErrorCode, double> measureInSubprocess(unsigned Opcode, BenchmarkGenerator *Generator,
                                                 double Frequency, std::string Type);

std::pair<ErrorCode, double> measureInSubprocess(std::list<LatMeasurement4> Measurements,
                                                 BenchmarkGenerator *Generator, double Frequency,
                                                 std::string Type);

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

// studies

void runOverlapStudy(unsigned Opcode1, unsigned Opcode2, unsigned InstLimit,
                     BenchmarkGenerator *Generator, double Frequency);

int main(int argc, char **argv);

#endif // LLVM_INSTR_GEN_H