#ifndef BENCHMARK_GENERATOR_H
#define BENCHMARK_GENERATOR_H

// #include <iterator>                  // for pair
#include "AssemblyFile.h"   // for AssemblyFile
#include "ErrorCode.h"      // for ErrorCode
#include "Globals.h"        // for env, LLVMEnvironment
#include "Templates.h"      // for AssemblyFile
#include "llvm/MC/MCInst.h" // for MCInst
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegister.h"     // for MCRegister
#include "llvm/MC/MCRegisterInfo.h" // for MCRegisterClass
#include <list>                     // for list
#include <map>                      // for map
#include <set>                      // for set
#include <string>                   // for string, basic_string
#include <tuple>                    // for tie, operator<, tuple
#include <unordered_set>            // for unordered_set
#include <utility>                  // for pair, get
#include <vector>                   // for vector
namespace llvm {
class MCInstrDesc;
} // namespace llvm

using namespace llvm;

// generates a latency benchmark for the instruction with Opcode. Generates
// TargetInstrCount instructions.
// If a InterleaveInst is provided it gets inserted after each generated instruction
// UsedRegisters has to contain all registers used by the InterleaveInst
// TargetInstructionCount will still be set to the number of generated instructions only
// returns an error code, the generated assembly code and the opcode of the interleave
// instruction if generated, -1 otherwise
std::tuple<ErrorCode, AssemblyFile, int> genLatBenchmark(
    unsigned Opcode, unsigned *TargetInstrCount,
    std::list<std::tuple<unsigned, std::set<MCRegister>, std::set<MCRegister>>> *HelperInstructions,
    std::set<MCRegister> UsedRegisters = {});

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
std::pair<ErrorCode, AssemblyFile> genLatBenchmark4(std::list<LatMeasurement4> Measurements,
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

/**
 * \brief Generate an instruction TODO debug with VADDSSZrr
 *
 * This function takes an opcode and generates a valid MCInst. By default it uses different
 * registers for each operand. This can be changed by setting RequireReadRegister,
 * RequireWriteRegister and EnforceRWDependency. In LLVM operands which are read are called
 * "uses" and operands which are written are called "defs".
 *
 * \param Opcode Opcode of the instruction.
 * \param UsedRegisters A register blacklist (will be updated).
 * \param EnforceRWDependency If true, the same register will be used for one read operand and
 * one write operand. If not possible, no instruction will be generated.
 * \param RequireUseRegister This register will be used for exactly one operand read if
 * possible, overriding UsedRegisters and ReuseRegisters. If not possible, no instruction will
 * be generated.
 * \param RequireDefRegister This register will be used for exactly one operand written if
 * possible, overriding UsedRegisters and ReuseRegisters. If not possible, no instruction will
 * be generated.
 * \return ErrorCode and generated instruction.
 */
std::pair<ErrorCode, MCInst> genInst(unsigned Opcode, std::set<MCRegister> &UsedRegisters,
                                     bool RequireRWDependency = false,
                                     MCRegister RequireUseRegister = -1,
                                     MCRegister RequireDefRegister = -1);

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
ErrorCode isValid(MCInstrDesc Desc);

#endif // BENCHMARK_GENERATOR