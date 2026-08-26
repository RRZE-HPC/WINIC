#ifndef GLOBALS_H
#define GLOBALS_H

#include "CustomDebug.h"
#include "ErrorCode.h"
#include "LLVMEnvironment.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/MC/MCRegisterInfo.h"
#include <algorithm>
#include <assert.h>
#include <fstream>
#include <limits>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace winic {

/**
 * \brief Returns a reference to the global LLVMEnvironment instance.
 * \return Reference to LLVMEnvironment.
 */
LLVMEnvironment &getEnv();

extern std::unique_ptr<std::ofstream> fileStream;
extern std::ostream *ios;
extern bool includeX87FP;
extern bool includeNonX87FP;
extern bool includeMemory;
extern bool includeNonMemory;
extern bool keepEmptyEntries; // if true, entries with only null values are included in the output

/**
 * \brief Sets the output stream to a file.
 * \param Filename The name of the file to write output to.
 * If the file cannot be opened, it falls back to std::cout.
 */
void setOutputToFile(const std::string &Filename);

template <typename T> inline bool contains(std::vector<T> Vector, T Element) {
    return std::find(Vector.begin(), Vector.end(), Element) != Vector.end();
}

const unsigned MAX_UNSIGNED = std::numeric_limits<unsigned>::max();
const unsigned NO_OP_INDEX = 999;

class RegisterClassOperand {
    unsigned regClassID;

  public:
    RegisterClassOperand(unsigned RegClassID) : regClassID(RegClassID) {};

    unsigned getRegClassID() const { return regClassID; }

    std::string toCompactString() const {
        return str("Class<", getEnv().MRI->getRegClassName(&getEnv().MRI->getRegClass(regClassID)),
                   ">");
    }

    std::string toFilenameString() const {
        return str(getEnv().MRI->getRegClassName(&getEnv().MRI->getRegClass(regClassID)));
    }

    bool operator==(const RegisterClassOperand &Other) const {
        return regClassID == Other.regClassID;
    }
};

class RegisterOperand {
    MCRegister reg;

  public:
    RegisterOperand(MCRegister Reg) : reg(Reg) {};

    unsigned getRegister() const { return reg; }

    std::string toCompactString() const { return str("Reg<", getEnv().MRI->getName(reg), ">"); }

    std::string toFilenameString() const { return str(getEnv().MRI->getName(reg)); }

    bool operator==(const RegisterOperand &Other) const { return reg == Other.reg; }
};

class ImmediateOperand {

  public:
    ImmediateOperand() {};

    std::string toCompactString() const { return "Imm"; }

    std::string toFilenameString() const { return "Imm"; }

    bool operator==(const ImmediateOperand &Other) const { return true; }
};

class MemoryOperand {
  public:
    MemoryOperand() {};

    std::string toCompactString() const { return "Mem"; }

    std::string toFilenameString() const { return "Mem"; }

    bool operator==(const MemoryOperand &Other) const { return true; }
};

class AArch64MemoryOperand : public MemoryOperand {
  public:
    AArch64MemoryOperand(std::vector<unsigned> BaseIndices, std::vector<unsigned> OffsetIndices)
        : baseIndices(BaseIndices), offsetIndices(OffsetIndices) {}

    std::vector<unsigned> baseIndices;
    std::vector<unsigned> offsetIndices;
};

class X86MemoryOperand : public MemoryOperand {
  public:
    X86MemoryOperand(std::vector<unsigned> BaseIndices, std::vector<unsigned> ScaleIndices,
                     std::vector<unsigned> IndexIndices, std::vector<unsigned> OffsetIndices,
                     std::vector<unsigned> SegmentIndices)
        : baseIndices(BaseIndices), scaleIndices(ScaleIndices), indexIndices(IndexIndices),
          offsetIndices(OffsetIndices), segmentIndices(SegmentIndices) {}

    std::vector<unsigned> baseIndices;
    std::vector<unsigned> scaleIndices;
    std::vector<unsigned> indexIndices;
    std::vector<unsigned> offsetIndices;
    std::vector<unsigned> segmentIndices;
};

class RISCVMemoryOperand : public MemoryOperand {
  public:
    // TODO
};

using OperandKind = std::variant<RegisterClassOperand, RegisterOperand, X86MemoryOperand,
                                 AArch64MemoryOperand, RISCVMemoryOperand, ImmediateOperand>;

inline bool operator==(const OperandKind &Lhs, OperandKind &Rhs) {
    return std::visit(
        [](const auto &A, const auto &B) -> bool {
            using aType = std::decay_t<decltype(A)>;
            using bType = std::decay_t<decltype(B)>;

            if constexpr (std::is_same_v<aType, bType>) return A == B;
            return false;
        },
        Lhs, Rhs);
}

/**
 * \brief Stream output operator for OperandKind.
 */
inline std::ostream &operator<<(std::ostream &OS, const OperandKind &Op) {
    return OS << std::visit([](const auto &Operand) { return Operand.toCompactString(); }, Op);
}

class OperandForm {
    unsigned index;
    bool def;
    bool use;
    std::vector<unsigned> mcIndices;

    OperandKind kind;

  private:
    /**
     * \brief Add enough dummy operands to an MCInst so the ones used by this OperandForm's
     * mcIndices are present,
     * \param Inst The instruction to initialize.
     */
    void initMCInst(MCInst *Inst) {
        int maxInd = *std::max_element(mcIndices.begin(), mcIndices.end());
        while (Inst->getNumOperands() <= maxInd) {
            Inst->addOperand(MCOperand::createImm(0));
        }
    }

  public:
    virtual ~OperandForm() = default;

    OperandForm(unsigned Index, std::vector<unsigned> MCIndices, OperandKind Kind)
        : index(Index), def(false), use(false), mcIndices(std::move(MCIndices)),
          kind(std::move(Kind)) {};

    OperandForm(unsigned Index, std::vector<unsigned> MCIndices, OperandKind Kind, bool Def,
                bool Use)
        : index(Index), def(Def), use(Use), mcIndices(std::move(MCIndices)),
          kind(std::move(Kind)) {};

    std::string toCompactString() const {
        return str(kind, str(isUse() && isDef() ? "(r/w)" : isUse() ? "(r)" : "(w)"));
    }

    bool isDef() const { return def; }

    bool isUse() const { return use; }

    bool isImplicit() const { return index == NO_OP_INDEX; }

    bool isRegClass() const { return std::holds_alternative<RegisterClassOperand>(kind); }

    bool isRegister() const { return std::holds_alternative<RegisterOperand>(kind); }

    bool isMemory() const {
        return std::holds_alternative<AArch64MemoryOperand>(kind) ||
               std::holds_alternative<X86MemoryOperand>(kind) ||
               std::holds_alternative<RISCVMemoryOperand>(kind);
    }

    bool isImmediate() const { return std::holds_alternative<ImmediateOperand>(kind); }

    MCRegister getRegister() const { return std::get_if<RegisterOperand>(&kind)->getRegister(); }

    unsigned getRegClassID() const {
        return std::get_if<RegisterClassOperand>(&kind)->getRegClassID();
    }

    unsigned getIndex() const { return index; }

    const std::vector<unsigned> getMCIndices() const { return mcIndices; }

    OperandKind getKind() const { return kind; }

    bool operator==(const OperandForm &Other) const { return kind == Other.kind; }

    void setRegClassOperand(MCInst *Inst, MCRegister Reg) {
        assert(isRegClass());
        initMCInst(Inst);
        for (auto mcInd : mcIndices) {
            Inst->getOperand(mcInd) = MCOperand::createReg(Reg);
        }
    }

    /**
     * \brief For a given MCInst, get the register that is used for this operand.
     * Has to be a registerClassOperand.
     */
    MCRegister getReg(MCInst *Inst) {
        assert(isRegClass());
        return Inst->getOperand(mcIndices[0]).getReg();
    }

    void setImmediateOperand(MCInst *Inst, unsigned Imm) {
        assert(isImmediate());
        initMCInst(Inst);
        for (auto mcInd : mcIndices) {
            Inst->getOperand(mcInd) = MCOperand::createImm(Imm);
        }
    }

    void setMemoryOperand(MCInst *Inst, MCRegister BaseRegister, unsigned Displacement) {
        assert(isMemory());
        initMCInst(Inst);
        if (getEnv().Arch == llvm::Triple::x86_64) {
            X86MemoryOperand *memOp = std::get_if<X86MemoryOperand>(&kind);

            for (unsigned index : memOp->baseIndices)
                Inst->getOperand(index) = MCOperand::createReg(BaseRegister);
            for (unsigned index : memOp->scaleIndices)
                Inst->getOperand(index) = MCOperand::createImm(0);
            for (unsigned index : memOp->indexIndices)
                Inst->getOperand(index) = MCOperand::createReg(0);
            for (unsigned index : memOp->offsetIndices)
                Inst->getOperand(index) = MCOperand::createImm(Displacement);
            for (unsigned index : memOp->segmentIndices)
                Inst->getOperand(index) = MCOperand::createReg(0);
        } else if (getEnv().Arch == llvm::Triple::aarch64) {
            AArch64MemoryOperand *memOp = std::get_if<AArch64MemoryOperand>(&kind);

            for (unsigned index : memOp->baseIndices)
                Inst->getOperand(index) = MCOperand::createReg(BaseRegister);
            for (unsigned index : memOp->offsetIndices)
                Inst->getOperand(index) = MCOperand::createImm(Displacement);
        } else if (getEnv().Arch == llvm::Triple::riscv64) {
            out(std::cerr, "RISCV memory not implemented yet");
        }
    }

    /**
     * \brief For a given MCInst, get the offset immediate of the memory access if present.
     */
    unsigned getMemoryOperandOffset(MCInst Inst) {
        assert(isMemory());
        if (getEnv().Arch == llvm::Triple::x86_64) {
            X86MemoryOperand *memOp = std::get_if<X86MemoryOperand>(&kind);
            return Inst.getOperand(memOp->offsetIndices[0]).getImm();
        }
        if (getEnv().Arch == llvm::Triple::aarch64) {
            AArch64MemoryOperand *memOp = std::get_if<AArch64MemoryOperand>(&kind);
            // dbg(__func__, memOp->offsetIndices);
            return Inst.getOperand(memOp->offsetIndices[0]).getImm();
        }
        if (getEnv().Arch == llvm::Triple::riscv64) {
            out(std::cerr, "RISCV memory not implemented yet");
        }
        return NO_OP_INDEX;
    }
};

/**
 * \brief Stream output operator for Operand.
 */
inline std::ostream &operator<<(std::ostream &OS, const OperandForm &Op) {
    return OS << Op.toCompactString();
}

class InstructionForm {
    unsigned opcode;
    std::vector<OperandForm> operands;

  public:
    InstructionForm(unsigned Opcode);

    std::vector<OperandForm> getDefOps() {
        std::vector<OperandForm> result;
        for (auto op : operands)
            if (op.isDef()) result.emplace_back(op);

        return result;
    }

    std::vector<OperandForm> getUseOps() {
        std::vector<OperandForm> result;
        for (auto op : operands)
            if (op.isUse()) result.emplace_back(op);

        return result;
    }

    std::vector<OperandForm> getUseOnlyOps() {
        std::vector<OperandForm> result;
        for (auto op : operands)
            if (op.isUse() && !op.isDef()) result.emplace_back(op);

        return result;
    }

    std::vector<OperandForm> getOperands() const { return operands; }

    unsigned getOpcode() const { return opcode; }

    std::string getName() const { return getEnv().MCII->getName(opcode).str(); }

    /**
     * \brief sorts operands by their indices.
     */
    void sortOperands() {
        std::sort(operands.begin(), operands.end(),
                  [](OperandForm A, OperandForm B) { return A.getIndex() < B.getIndex(); });
    }
};

inline std::ostream &operator<<(std::ostream &OS, const InstructionForm &Op) {
    return OS << Op.getName() << " " << Op.getOperands();
}

/**
 * \brief Represents a dependency type between two operands.
 */
struct DependencyType {
    OperandKind defOp; ///< Defining operand
    OperandKind useOp; ///< Using operand

    // DependencyType() = default;

    DependencyType(OperandKind DefOp, OperandKind UseOp) : defOp(DefOp), useOp(UseOp) {}

    bool operator==(const DependencyType &Other) const {
        return defOp == Other.defOp && useOp == Other.useOp;
    }

    // needed for using as key in a map
    bool operator<(const DependencyType &Other) const {
        return str(defOp, useOp) < str(Other.defOp, Other.useOp);
    }

    const DependencyType reversed() const { return DependencyType(useOp, defOp); }

    bool isComplementaryTypeAs(DependencyType &Other) {
        return defOp == Other.useOp && useOp == Other.defOp;
    }

    bool isSymmetric() { return defOp == useOp; }

    bool canCreateDependencyChain() {
        if (isSymmetric()) return true;
        if (auto *defRegClassOp = std::get_if<RegisterClassOperand>(&defOp))
            if (auto *useRegisterOperand = std::get_if<RegisterOperand>(&useOp))
                return getEnv().regInRegClass(useRegisterOperand->getRegister(),
                                              defRegClassOp->getRegClassID());

        if (auto *defRegisterOperand = std::get_if<RegisterOperand>(&defOp))
            if (auto *useRegClassOp = std::get_if<RegisterClassOperand>(&useOp))
                return getEnv().regInRegClass(defRegisterOperand->getRegister(),
                                              useRegClassOp->getRegClassID());
        return false; // unreachable
    }
};

/**
 * \brief Stream output operator for DependencyType.
 */
inline std::ostream &operator<<(std::ostream &OS, const DependencyType &Op) {
    return OS << Op.useOp << " -> " << Op.defOp;
}

/**
 * \brief Represents a latency measurement for an instruction and dependency type.
 */
struct LatMeasurement {
    unsigned opcode;     ///< Instruction opcode
    DependencyType type; ///< Dependency type (e.g. R64 -> EFLAGS)
    unsigned defIndex;   ///< Operand index for defOp (999 if implicit)
    unsigned useIndex;   ///< Operand index for useOp (999 if implicit)
    double lowerBound;   ///< Lower bound of measured latency
    double upperBound;   ///< Upper bound of measured latency
    ErrorCode ec;        ///< Error code for measurement

    LatMeasurement(unsigned Opcode, DependencyType Type, unsigned DefIndex, unsigned UseIndex,
                   double LowerBound = -1, double UpperBound = -1, ErrorCode EC = NO_ERROR_CODE)
        : opcode(Opcode), type(Type), defIndex(DefIndex), useIndex(UseIndex),
          lowerBound(LowerBound), upperBound(UpperBound), ec(EC) {}

    bool operator==(const LatMeasurement &Other) const {
        return opcode == Other.opcode && type == Other.type && defIndex == Other.defIndex &&
               useIndex == Other.useIndex;
    }

    /**
     * \brief Returns a string representation suitable to be used in a filename.
     */
    std::string toFilenameString() const {
        std::string useIndexStr = useIndex == NO_OP_INDEX ? "i" : std::to_string(useIndex);
        std::string defIndexStr = defIndex == NO_OP_INDEX ? "i" : std::to_string(defIndex);
        std::string useOpStr = std::visit(
            [](const auto &(Operand)) { return Operand.toFilenameString(); }, type.useOp);
        std::string defOpStr = std::visit(
            [](const auto &(Operand)) { return Operand.toFilenameString(); }, type.defOp);
        return str(getEnv().MCII->getName(opcode).str(), "_", useIndexStr, "-", useOpStr, "--",
                   defIndexStr, "-", defOpStr);
    }

    std::string toString() const {
        std::string useIndexStr = useIndex == NO_OP_INDEX ? "impl" : std::to_string(useIndex);
        std::string defIndexStr = defIndex == NO_OP_INDEX ? "impl" : std::to_string(defIndex);
        return str(getEnv().MCII->getName(opcode).str(), "(", useIndexStr, "(", type.useOp, ")",
                   " -> ", defIndexStr, "(", type.defOp, ")) ");
    }

    std::string toStringWithBounds() const {
        std::string outputString = toString();
        if (hasResultWith(ec))
            outputString += str(" [", lowerBound, ";", upperBound, "]");
        else
            outputString += str(" [", ecToString(ec), "]");
        return outputString;
    }
};

/**
 * \brief Stream output operator for LatMeasurement.
 */
inline std::ostream &operator<<(std::ostream &OS, const LatMeasurement &Op) {
    return OS << Op.toString();
}

struct TPMeasurement {
    unsigned opcode;
    ErrorCode ec;
    double lowerTP;
    double upperTP;

    std::string toStringWithBounds() const {
        std::string outputString = getEnv().MCII->getName(opcode).str();
        if (hasResultWith(ec))
            outputString += str(" [", lowerTP, ";", upperTP, "]");
        else
            outputString += str(" [", ecToString(ec), "]");
        return outputString;
    }
};

/**
 * \brief Stream output operator for TPMeasurement.
 */
inline std::ostream &operator<<(std::ostream &OS, const TPMeasurement &Op) {
    std::string name = getEnv().MCII->getName(Op.opcode).str();

    if (!isError(Op.ec)) return OS << str(name, " [", Op.lowerTP, ";", Op.upperTP, "]");
    return OS << str(name, " [", ecToString(Op.ec), "]");
}

} // namespace winic

#endif // GLOBALS_H
