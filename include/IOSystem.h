#include "llvm/Support/YAMLTraits.h"
#include <ErrorCode.h>
#include <Globals.h>
#include <LLVMBench.h>
#include <llvm/ADT/StringRef.h>
#include <optional>
#include <string>

// serializable structs for yaml output
struct IOOperand {
    std::string opClass;
    std::optional<std::string> name;
    std::optional<std::string> imd;
};
using StringOptionalDoubleMap = std::map<std::string, std::optional<double>>;
// map useOperand -> defOperand -> latency
using IOLatMap = std::map<std::string, StringOptionalDoubleMap>;

struct IOInstruction {
    std::string llvmName;
    std::string name;
    std::vector<IOOperand> operands;
    std::optional<double> latency;
    IOLatMap operandLatencies;
    std::optional<double> throughput;
    std::optional<double> throughputMin;
    std::optional<double> throughputMax;
};

LLVM_YAML_IS_SEQUENCE_VECTOR(IOOperand)
LLVM_YAML_IS_SEQUENCE_VECTOR(IOInstruction)
LLVM_YAML_IS_STRING_MAP(std::optional<double>)
LLVM_YAML_IS_STRING_MAP(StringOptionalDoubleMap)

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

template <> struct ScalarTraits<std::optional<double>> {
    static void output(const std::optional<double> &Val, void *, raw_ostream &Out) {
        if (Val)
            ScalarTraits<double>::output(*Val, nullptr, Out);
        else
            Out << "null";
    }
    static StringRef input(StringRef Scalar, void *, std::optional<double> &Val) {
        if (Scalar == "null" || Scalar == "~" || Scalar.empty()) {
            Val.reset();
            return {};
        }
        double tmp;
        auto Err = ScalarTraits<double>::input(Scalar, nullptr, tmp);
        if (Err.empty()) Val = tmp;
        return Err;
    }
    static QuotingType mustQuote(StringRef S) {
        if (S == "null" || S == "~" || S.empty()) return QuotingType::None;
        return ScalarTraits<double>::mustQuote(S);
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

// load a database into outputDatabase to add further measurements. Currently it is not supported to
// load the values back into the working databases! Therefore existing values cannot be used as
// helpers and all required helpers have to be measured in one run!
ErrorCode loadYaml(std::string Path);

ErrorCode saveYaml(std::string Path);
