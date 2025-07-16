#ifndef BENCHMARK_GENERATOR_H
#define BENCHMARK_GENERATOR_H

#include "AssemblyFile.h"
#include "ErrorCode.h"
#include "Globals.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/MC/MCRegisterInfo.h"
#include <list>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <unordered_set>
#include <utility>
#include <vector>

namespace llvm {
class MCInstrDesc;
}
struct Template;

using namespace llvm;

/**
 * \brief Generates initialization code for a register.
 * \param Reg The register to initialize.
 * \param InitValue The value to initialize the register with.
 * \param BenchTemplate The template to use for initialization.
 * \return Assembly code string for register initialization.
 */
std::string genRegInit(MCRegister Reg, std::string InitValue, Template BenchTemplate);

/**
 * \brief Generates all possible latency measurements for all instructions.
 * \param MinOpcode Minimum opcode to consider.
 * \param MaxOpcode Maximum opcode to consider.
 * \param SkipOpcodes Set of opcodes to skip.
 * \return Vector of LatMeasurement objects.
 */
std::vector<LatMeasurement> genLatMeasurements(unsigned MinOpcode, unsigned MaxOpcode,
                                               std::unordered_set<unsigned> SkipOpcodes);

/**
 * \brief Generates a benchmark based on the list of latency measurements.
 * \param Measurements List of instructions, will be written to the loop in the given order using the same registers on the useOps and defOps.
 * \param TargetInstrCount Pointer to the target number of instructions.
 * \param UsedRegisters Set of registers to avoid using (optional).
 * \return Pair of ErrorCode and generated AssemblyFile.
 */
std::pair<ErrorCode, AssemblyFile> genLatBenchmark(const std::list<LatMeasurement> &Measurements,
                                                   unsigned *TargetInstrCount,
                                                   std::set<MCRegister> UsedRegisters = {});

/**
 * \brief Generates a throughput benchmark for a given opcode.
 * \param Opcode The opcode to benchmark.
 * \param TargetInstrCount Pointer to the target number of instructions.
 * \param UnrollCount Number of times to unroll the loop.
 * \param UsedRegisters Set of registers to avoid using.
 * \param HelperConstraints Constraints for the helper instruction.
 * \param HelperOpcode Opcode of the helper instruction.
 * \return Pair of ErrorCode and generated AssemblyFile.
 */
std::pair<ErrorCode, AssemblyFile> genTPBenchmark(unsigned Opcode, unsigned *TargetInstrCount,
                                                  unsigned UnrollCount,
                                                  std::set<MCRegister> UsedRegisters,
                                                  std::map<unsigned, MCRegister> HelperConstraints,
                                                  unsigned HelperOpcode);

/**
 * \brief Generates the inner loop for a throughput measurement.
 * 
 * Does not introduce dependencies between the instructions, but does not account for possible implicit dependencies.
 * 
 * \param Opcodes Sequence of instructions to generate.
 * \param ConstraintsVector Constraints for each instruction.
 * \param TargetInstrCount How often to generate the sequence. May generate less if not enough registers are available to generate all instructions without introducing dependencies.
 * \param UsedRegisters A register blacklist (will be updated).
 * \return Pair of ErrorCode and list of generated MCInst instructions.
 */
std::pair<ErrorCode, std::list<MCInst>>
genTPLoop(std::vector<unsigned> Opcodes,
               std::vector<std::map<unsigned, MCRegister>> ConstraintsVector,
               unsigned TargetInstrCount, std::set<MCRegister> &UsedRegisters);

/**
 * \brief Generates a constraint (operand -> Register) to make an instruction use/def a specific register.
 * 
 * \param Opcode The opcode to analyze.
 * \param Type "use" or "def" to specify operand type.
 * \param RequiredRegister The register required for the operand.
 * \return Tuple of ErrorCode and operand number. Returns SUCCESS and -1 if the instruction defs/uses the register implicitly. Returns Error if no operand can use/def the register.
 */
std::tuple<ErrorCode, int> whichOperandCanUse(unsigned Opcode, std::string Type,
                                              MCRegister RequiredRegister);

/**
 * \brief Generates an instruction for a given opcode and constraints.
 * 
 * This function takes an opcode and generates a valid MCInst. Adds registers used to UsedRegisters.
 * Remember to add implicit uses/defs of normal registers to UsedRegisters before calling this, otherwise they may be used for other operands and introduce unwanted dependencies.
 * 
 * \param Opcode Opcode of the instruction.
 * \param Constraints A map of fixed registers to use.
 * \param Immediate The immediate value to be used if needed
 * \param UsedRegisters A blacklist of registers not to be used. Gets updated. If the Constraints demand for a register to be used this will be overridden.
 * \return Pair of ErrorCode and generated MCInst instruction.
 */
std::pair<ErrorCode, MCInst> genInst(unsigned Opcode, std::map<unsigned, MCRegister> Constraints,
                                     std::set<MCRegister> &UsedRegisters, unsigned Immediate = 7);

/**
 * \brief Finds the supermost register for a given register.
 * \param Reg The register to analyze.
 * \return Pair of ErrorCode and the supermost MCRegister.
 */
std::pair<ErrorCode, MCRegister> getSupermostRegister(MCRegister Reg);

/**
 * \brief Finds a free register in the given register class.
 * \param RegClass The register class to search.
 * \param UsedRegisters Set of registers to avoid using.
 * \return Pair of ErrorCode and a free MCRegister.
 */
std::pair<ErrorCode, MCRegister> getFreeRegisterInClass(const MCRegisterClass &RegClass,
                                                        std::set<MCRegister> UsedRegisters);

/**
 * \brief Finds a free register in the register class with the given ID.
 * \param RegClassID The register class ID.
 * \param UsedRegisters Set of registers to avoid using.
 * \return Pair of ErrorCode and a free MCRegister.
 */
std::pair<ErrorCode, MCRegister> getFreeRegisterInClass(unsigned RegClassID,
                                                        std::set<MCRegister> UsedRegisters);

/**
 * \brief Returns a list of dependencies between two instructions, taking into account implicit and explicit defs/uses.
 * \param Inst1 The first instruction.
 * \param Inst2 The second instruction.
 * \return List of DependencyType objects.
 */
std::list<DependencyType> getDependencies(MCInst Inst1, MCInst Inst2);

/**
 * \brief Generates code to save a register.
 * \param Reg The register to save.
 * \return Pair of ErrorCode and assembly code string.
 */
std::pair<ErrorCode, std::string> genSaveRegister(MCRegister Reg);

/**
 * \brief Generates code to restore a register.
 * \param Reg The register to restore.
 * \return Pair of ErrorCode and assembly code string.
 */
std::pair<ErrorCode, std::string> genRestoreRegister(MCRegister Reg);

/**
 * \brief Checks if an instruction is valid for benchmarking.
 * \param Desc The instruction descriptor.
 * \return ErrorCode indicating validity.
 */
ErrorCode isValid(const MCInstrDesc &Desc);

#endif // BENCHMARK_GENERATOR
