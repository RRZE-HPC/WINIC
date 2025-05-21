#include "llvm/Support/YAMLTraits.h"
#include <ErrorCode.h>
#include <Globals.h>
#include <LLVMBench.h>
#include <string>

// serializable structs for yaml output
struct IOOperand {
    std::string opClass;
    std::optional<std::string> name;
    std::optional<std::string> imd;
};
using StringUnsigedMap = std::map<std::string, unsigned>;
using IOLatType = std::map<std::string, StringUnsigedMap>;

struct IOInstruction {
    std::string llvmName;
    std::string name;
    std::vector<IOOperand> operands;
    unsigned latency;
    IOLatType operandLatencies;
    double throughput;
    double throughputMin;
    double throughputMax;
};

LLVM_YAML_IS_SEQUENCE_VECTOR(IOOperand)
LLVM_YAML_IS_SEQUENCE_VECTOR(IOInstruction)
LLVM_YAML_IS_STRING_MAP(unsigned)
LLVM_YAML_IS_STRING_MAP(StringUnsigedMap)

namespace llvm {
namespace yaml {

template <> struct MappingTraits<IOOperand> {
    static void mapping(IO &Io, IOOperand &Op) {
        Io.mapRequired("class", Op.opClass);
        Io.mapOptional("name", Op.name);
        Io.mapOptional("imd", Op.imd);
    }
};

template <> struct MappingTraits<IOInstruction> {
    static void mapping(IO &Io, IOInstruction &Inst) {
        Io.mapRequired("llvmName", Inst.llvmName);
        Io.mapRequired("name", Inst.name);
        Io.mapRequired("operands", Inst.operands);
        Io.mapRequired("latency", Inst.latency);
        Io.mapRequired("operandLatencies", Inst.operandLatencies);
        Io.mapRequired("throughput", Inst.throughput);
        Io.mapRequired("throughputMin", Inst.throughputMin);
        Io.mapRequired("throughputMax", Inst.throughputMax);
    }
};

} // namespace yaml
} // namespace llvm

static std::vector<IOInstruction> outputDatabase;

// converts an llvm-style operand number to a asm-style operand number
// llvm operand layout looks like this:
// operands: [op0: reg(w), op1: reg(r), op2: imm(r)], numDefs: 1, constraints: [op0 == op1]
// which corresponds to asm-style operand layout:
// operands: [op0: reg(rw), op1: imm(r)]
unsigned llvmOpNumToNormalOpNum(unsigned OpNum, const MCInstrDesc &Desc);

std::pair<ErrorCode, IOInstruction> createOpInstruction(unsigned Opcode);

ErrorCode updateDatabaseEntryTP(TPMeasurement Measurement);

ErrorCode updateDatabaseEntryLAT(LatMeasurement Measurement);

ErrorCode loadYaml(std::string Path);

ErrorCode saveYaml(std::string Path);
