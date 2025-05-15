#ifndef BENCHMARK_GENERATOR_H
#define BENCHMARK_GENERATOR_H

#include "AssemblyFile.h"           // for AssemblyFile
#include "ErrorCode.h"              // for ErrorCode
#include "Globals.h"                // for LatMeasurement4
#include "llvm/MC/MCInst.h"         // for MCInst
#include "llvm/MC/MCRegister.h"     // for MCRegister
#include "llvm/MC/MCRegisterInfo.h" // for MCRegisterClass
#include <list>                     // for list
#include <map>                      // for map
#include <set>                      // for set
#include <string>                   // for string
#include <tuple>                    // for tuple
#include <unordered_set>            // for unordered_set
#include <utility>                  // for pair
#include <vector>                   // for vector

namespace llvm {
class MCInstrDesc;
}
struct Template;

using namespace llvm;

std::string genRegInit(MCRegister Reg, std::string InitValue, Template BenchTemplate);

// generates all possible latency measurements for all instructions TODO swap args, put
// default=0
std::vector<LatMeasurement4> genLatMeasurements4(unsigned MinOpcode, unsigned MaxOpcode,
                                                 std::unordered_set<unsigned> SkipOpcodes);

/**
 * generates a benchmark based on the list of measurements
 * @param Measurements list of instructions, will be written to the loop in the given order
 * using the same registers on the useOps and defOps
 */
std::pair<ErrorCode, AssemblyFile> genLatBenchmark4(const std::list<LatMeasurement4> &Measurements,
                                                    unsigned *TargetInstrCount,
                                                    std::set<MCRegister> UsedRegisters = {});

std::pair<ErrorCode, AssemblyFile> genTPBenchmark(unsigned Opcode, unsigned *TargetInstrCount,
                                                  unsigned UnrollCount,
                                                  std::set<MCRegister> UsedRegisters,
                                                  std::map<unsigned, MCRegister> HelperConstraints,
                                                  int HelperOpcode);

/**
 * generate the inner loop for a throughput measurement. Doesnt introduce dependency between the
 * instructions, this doesnt account for possible implicit dependencies.
 * \param Opcodes sequence of instructions to generate
 * \param TargetInstrCount How often to generate the sequence. May generate less if not enough
 * registers are available to generate all instructions without introducing dependencies
 * \param UsedRegisters A register blacklist (will be updated).
 * \return a list of instructions
 */
std::pair<ErrorCode, std::list<MCInst>>
genTPInnerLoop4(std::vector<unsigned> Opcodes,
                std::vector<std::map<unsigned, MCRegister>> ConstraintsVector,
                unsigned TargetInstrCount, std::set<MCRegister> &UsedRegisters);

// generate a constraint (operand -> Register) to make an instruction use/def a specific register
// returns SUCCESS and a operand number
// returns SUCCESS and -1 if the instruction defs/uses the register implicitly
// returns Error if no operand can use/def the register
std::tuple<ErrorCode, int> whichOperandCanUse(unsigned Opcode, std::string Type,
                                              MCRegister RequiredRegister);

/**
 * \brief Generate an instruction TODO debug with VADDSSZrr
 *
 * This function takes an opcode and generates a valid MCInst. Adds registers used to
 * UsedRegisters. Remember to add implicit uses/defs of normal registers to usedRegisters before
 * calling this. otherwise they may be used for other operands and introduce unwanted
 * dependencies.
 *
 * \param Opcode Opcode of the instruction
 * \param Constraints A map of fixed registers to use.
 * \param UsedRegisters A blacklist of registers not to be used. Gets updated. If the
 * Constraints demand for a register to be used this will be overridden.
 * \return ErrorCode and generated instruction.
 */
std::pair<ErrorCode, MCInst> genInst4(unsigned Opcode, std::map<unsigned, MCRegister> Constraints,
                                      std::set<MCRegister> &UsedRegisters);

std::pair<ErrorCode, MCRegister> getSupermostRegister(MCRegister Reg);

std::pair<ErrorCode, MCRegisterClass> getBaseClass(MCRegister Reg);

MCRegister getFreeRegisterInClass(const MCRegisterClass &RegClass,
                                  std::set<MCRegister> UsedRegisters);
MCRegister getFreeRegisterInClass(short RegClassID, std::set<MCRegister> UsedRegisters);

// TODO find ISA independent function in llvm
std::pair<ErrorCode, std::string> genSaveRegister(MCRegister Reg);

// TODO find ISA independent function in llvm
std::pair<ErrorCode, std::string> genRestoreRegister(MCRegister Reg);

// filter which instructions get exludedd
ErrorCode isValid(const MCInstrDesc &Desc);

#endif // BENCHMARK_GENERATOR