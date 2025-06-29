#include <llvm/ADT/StringRef.h>
#include "llvm/Support/YAMLTraits.h"
#include <ErrorCode.h>
#include <Globals.h>
#include <LLVMBench.h>
#include <optional>
#include <string>

// serializable structs for yaml output

/**
 * \brief Represents an operand for YAML serialization.
 */
struct IOOperand {
    std::string opClass;             ///< Operand class (e.g., "register", "immediate")
    std::optional<std::string> name; ///< Optional operand name
    std::optional<std::string> imd;  ///< Optional immediate value type
    bool read;  ///< Is this operand read?
    bool write;  ///< Is this operand written?
};

using StringOptionalDoubleMap = std::map<std::string, std::optional<double>>;

/**
 * \brief Map from use operand to def operand to latency value.
 */
using IOLatMap = std::map<std::string, StringOptionalDoubleMap>;

/**
 * \brief Represents an instruction for YAML serialization.
 */
struct IOInstruction {
    std::string llvmName;                ///< LLVM instruction name
    std::string name;                    ///< Assembly mnemonic
    std::vector<IOOperand> operands;     ///< List of operands
    std::optional<double> latency;       ///< Overall instruction latency
    IOLatMap operandLatencies;           ///< Operand-level latencies
    std::optional<double> throughput;    ///< Throughput value
    std::optional<double> throughputMin; ///< Minimum throughput
    std::optional<double> throughputMax; ///< Maximum throughput
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
        Io.mapRequired("read", Op.read);
        Io.mapRequired("write", Op.write);
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

/**
 * \brief Converts an LLVM-style operand number to an asm-style operand number.
 *
 * LLVM operand layout looks like this:
 *   operands: [op0: reg(w), op1: reg(r), op2: imm(r)], numDefs: 1, constraints: [op0 == op1]
 * which corresponds to asm-style operand layout:
 *   operands: [op0: reg(rw), op1: imm(r)]
 *
 * \param OpNum The LLVM operand number.
 * \param Desc The instruction descriptor.
 * \return The corresponding asm-style operand number.
 */
unsigned llvmOpNumToNormalOpNum(unsigned OpNum, const MCInstrDesc &Desc);

/**
 * \brief Creates an IOInstruction from an opcode.
 * \param Opcode The instruction opcode.
 * \return Pair of ErrorCode and IOInstruction.
 */
std::pair<ErrorCode, IOInstruction> createOpInstruction(unsigned Opcode);

/**
 * \brief Updates the output database entry for throughput measurement.
 * \param Measurement The throughput measurement.
 * \return ErrorCode indicating success or failure.
 */
ErrorCode updateDatabaseEntryTP(TPMeasurement Measurement);

/**
 * \brief Updates the output database entry for latency measurement.
 * \param Measurement The latency measurement.
 * \return ErrorCode indicating success or failure.
 */
ErrorCode updateDatabaseEntryLAT(LatMeasurement Measurement);

/**
 * \brief Loads a database from a YAML file into outputDatabase.
 *
 * Note: Currently it is not supported to load the values back into the working databases!
 * Therefore existing values cannot be used as helpers and all required helpers have to be measured
 * in one run!
 *
 * \param Path Path to the YAML file.
 * \return ErrorCode indicating success or failure.
 */
ErrorCode loadYaml(std::string Path);

/**
 * \brief Saves the outputDatabase to a YAML file.
 * \param Path Path to the YAML file.
 * \return ErrorCode indicating success or failure.
 */
ErrorCode saveYaml(std::string Path);
