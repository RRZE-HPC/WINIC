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
#include <iostream>
#include <list>          // for list
#include <map>           // for map
#include <set>           // for set
#include <string>        // for string, basic_string
#include <tuple>         // for tie, operator<, tuple
#include <unordered_set> // for unordered_set
#include <utility>       // for pair, get
#include <vector> // for vector
namespace llvm {
class MCInstrDesc;
} // namespace llvm

using namespace llvm;

// either regClassID or implicit Register
// using LatOperand = std::variant<unsigned, MCRegister>;

// static inline LatOperand regClass(short Val) { return static_cast<unsigned>(Val); }

enum class LatOperandKind { RegisterClass, Register };

struct LatOperand {
    LatOperandKind kind;
    union {
        unsigned regClass;
        MCRegister reg;
    };
    LatOperand() : kind(LatOperandKind::RegisterClass) {}

    static LatOperand fromRegClass(unsigned Val) {
        LatOperand op;
        op.kind = LatOperandKind::RegisterClass;
        op.regClass = Val;
        return op;
    }

    static LatOperand fromRegister(MCRegister R) {
        LatOperand op;
        op.kind = LatOperandKind::RegisterClass;
        op.reg = R;
        return op;
    }

    bool operator==(const LatOperand &Other) const {
        if (kind != Other.kind) return false;
        if (kind == LatOperandKind::RegisterClass) return regClass == Other.regClass;
        return reg == Other.reg;
    }
    bool operator<(const LatOperand &Other) const {
        if (kind != Other.kind) return kind < Other.kind;
        if (kind == LatOperandKind::RegisterClass) return regClass < Other.regClass;
        return reg < Other.reg;
    }

    bool isRegClass() const { return kind == LatOperandKind::RegisterClass; }
    bool isRegister() const { return kind == LatOperandKind::Register; }

    unsigned getRegClass() const {
        assert(isRegClass());
        return regClass;
    }
    MCRegister getRegister() const {
        assert(isRegister());
        return reg;
    }
};
inline std::ostream &operator<<(std::ostream &OS, const LatOperand &Op) {
    if (Op.isRegClass())
        return OS << "Class(" << env.MRI->getRegClassName(&env.MRI->getRegClass(Op.getRegClass()))
                  << ")";

    return OS << env.MRI->getName(Op.getRegister()) << " (" << Op.getRegister() << ")";
}

struct LatMeasurementType {
    LatOperand defOp;
    LatOperand useOp;

    LatMeasurementType(LatOperand DefOp, LatOperand UseOp) : defOp(DefOp), useOp(UseOp) {}
    bool operator==(const LatMeasurementType &Other) const {
        return defOp == Other.defOp && useOp == Other.useOp;
    }
    bool operator<(const LatMeasurementType &Other) const {
        return std::tie(defOp, useOp) < std::tie(Other.defOp, Other.useOp);
    }

    const LatMeasurementType reversedType() const { return LatMeasurementType(useOp, defOp); }
    bool isComplementaryTypeAs(LatMeasurementType &Other) {
        return defOp == Other.useOp && useOp == Other.defOp;
    }
};
inline std::ostream &operator<<(std::ostream &OS, const LatMeasurementType &Op) {
    return OS << Op.useOp << " -> " << Op.defOp;
}

struct LatMeasurement4 {
    unsigned opcode;
    LatMeasurementType type;
    unsigned defIndex;
    unsigned useIndex;
    double value;

    LatMeasurement4(unsigned Opcode, LatMeasurementType Type, unsigned DefIndex, unsigned UseIndex,
                    double Value)
        : opcode(Opcode), type(Type), defIndex(DefIndex), useIndex(UseIndex), value(Value) {}
    bool operator==(const LatMeasurement4 &Other) const {
        return opcode == Other.opcode && type == Other.type && defIndex == Other.defIndex &&
               useIndex == Other.useIndex;
    }
};
inline std::ostream &operator<<(std::ostream &OS, const LatMeasurement4 &Op) {
    return OS << env.MCII->getName(Op.opcode).str() << ": " << Op.type;
}

class BenchmarkGenerator {
  private:
  public:
    BenchmarkGenerator() {}

    // generates a latency benchmark for the instruction with Opcode. Generates
    // TargetInstrCount instructions.
    // If a InterleaveInst is provided it gets inserted after each generated instruction
    // UsedRegisters has to contain all registers used by the InterleaveInst
    // TargetInstructionCount will still be set to the number of generated instructions only
    // returns an error code, the generated assembly code and the opcode of the interleave
    // instruction if generated, -1 otherwise
    std::tuple<ErrorCode, AssemblyFile, int>
    genLatBenchmark(unsigned Opcode, unsigned *TargetInstrCount,
                    std::list<std::tuple<unsigned, std::set<MCRegister>, std::set<MCRegister>>>
                        *HelperInstructions,
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

    // generates a throughput benchmark for the instruction with Opcode. Tries to generate
    // TargetInstrCount different instructions and then unrolls them by UnrollCount. Updates
    // TargetInstrCount to the actual number of instructions in the loop (unrolls included)
    // If a InterleaveInst is provided it gets inserted after each generated instruction
    // UsedRegisters has to contain all registers used by the InterleaveInst
    // TargetInstructionCount will still be set to the number of generated instructions only
    std::pair<ErrorCode, AssemblyFile> genTPBenchmark(unsigned Opcode, unsigned *TargetInstrCount,
                                                      unsigned UnrollCount,
                                                      std::string InterleaveInst = "",
                                                      std::set<MCRegister> UsedRegisters = {});

    // generates a benchmark with TargetInstrCount1 times the instruction with Opcode1 and
    // TargetInstrCount2 times the instruction with Opcode2 and then unrolls them by UnrollCount.
    // Fails if not not enough registers were available to generate the requested number of
    // instructions.
    std::pair<ErrorCode, AssemblyFile> genOverlapBenchmark(unsigned Opcode1, unsigned Opcode2,
                                                           unsigned TargetInstrCount1,
                                                           unsigned TargetInstrCount2,
                                                           unsigned UnrollCount,
                                                           std::string FixedInstr2 = "");


    // generates a benchmark loop to measure throughput of an instruction
    // tries to generate targetInstrCount independent instructions for the inner
    // loop might generate less instructions than targetInstrCount if there are
    // not enough registers updates usedRegisters
    std::pair<ErrorCode, std::list<MCInst>>
    genTPInnerLoop(unsigned Opcode, unsigned TargetInstrCount, std::set<MCRegister> &UsedRegisters);

    /**
     * \brief Generate an instruction TODO debug with VADDSSZrr
     *
     * This function takes an opcode and generates a valid MCInst. By default it uses different
     * registers for each operand. This can be changed by setting RequireReadRegister,
     * RequireWriteRegister and EnforceRWDependency. In LLVM operands which are read are called
     * "uses" and operands which are written are called "defs".
     *
     * \param Opcode Opcode of the instruction.
     * \param UsedRegisters A blacklist of registers not to be used.
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

    /**
     * \brief Generate an instruction TODO debug with VADDSSZrr
     *
     * This function takes an opcode and generates a valid MCInst based on the information in
     * Measurement. Adds registers used to UsedRegisters. Remember to add implicit uses/defs of
     * normal registers t usedRegisters before calling this. otherwise they may be used for other
     * opearands
     *
     *\param Opcode Opcode of the instruction
     * \param Constraints A map of fixed regiters to use.
     * \param UsedRegisters A blacklist of registers not to be used. Gets updated. If the
     * Measurement demands for a register to be used this will be overridden.
     * \return ErrorCode and generated instruction.
     */
    std::pair<ErrorCode, MCInst> genInst4(unsigned Opcode,
                                          std::map<unsigned, MCRegister> Constraints,
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
};

#endif // BENCHMARK_GENERATOR