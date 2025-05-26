#ifndef GLOBALS_H
#define GLOBALS_H

#include "ErrorCode.h"
#include "LLVMEnvironment.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/MC/MCRegisterInfo.h"
#include <assert.h>
#include <fstream>
#include <limits>
#include <memory>
#include <string>
#include <tuple>

/**
 * \brief Returns a reference to the global LLVMEnvironment instance.
 * \return Reference to LLVMEnvironment.
 */
LLVMEnvironment &getEnv();

extern std::unique_ptr<std::ofstream> fileStream;
extern std::ostream *ios;

const unsigned MAX_UNSIGNED = std::numeric_limits<unsigned>::max();

enum class LatOperandKind { RegisterClass, Register };

/**
 * \brief Represents an operand, which can be a register class or a specific register.
 */
struct Operand {
    LatOperandKind kind;
    union {
        unsigned regClass; ///< Register class ID
        MCRegister reg;    ///< Register
    };
    Operand() : kind(LatOperandKind::RegisterClass) {}

    static Operand fromRegClass(unsigned Val) {
        Operand op;
        op.kind = LatOperandKind::RegisterClass;
        op.regClass = Val;
        return op;
    }

    static Operand fromRegister(MCRegister R) {
        Operand op;
        op.kind = LatOperandKind::Register;
        op.reg = R;
        return op;
    }

    bool operator==(const Operand &Other) const {
        if (kind != Other.kind) return false;
        if (kind == LatOperandKind::RegisterClass) return regClass == Other.regClass;
        return reg == Other.reg;
    }
    bool operator<(const Operand &Other) const {
        if (kind != Other.kind) return kind < Other.kind;
        if (kind == LatOperandKind::RegisterClass) return regClass < Other.regClass;
        return reg < Other.reg;
    }

    /**
     * \brief Checks if this operand is a register class.
     * \return True if register class, false if register.
     */
    bool isRegClass() const { return kind == LatOperandKind::RegisterClass; }
    /**
     * \brief Checks if this operand is a register.
     * \return True if register, false if register class.
     */
    bool isRegister() const { return kind == LatOperandKind::Register; }

    /**
     * \brief Gets the register class ID.
     * \return Register class ID.
     */
    unsigned getRegClass() const {
        assert(isRegClass());
        return regClass;
    }
    /**
     * \brief Gets the register.
     * \return MCRegister.
     */
    MCRegister getRegister() const {
        assert(isRegister());
        return reg;
    }
};

/**
 * \brief Stream output operator for Operand.
 */
inline std::ostream &operator<<(std::ostream &OS, const Operand &Op) {
    if (Op.isRegClass())
        return OS << "Class<"
                  << getEnv().MRI->getRegClassName(&getEnv().MRI->getRegClass(Op.getRegClass()))
                  << ">";

    return OS << getEnv().MRI->getName(Op.getRegister()) << "<" << Op.getRegister() << ">";
}

/**
 * \brief Represents a dependency type between two operands.
 */
struct DependencyType {
    Operand defOp; ///< Defining operand
    Operand useOp; ///< Using operand

    DependencyType() = default;
    DependencyType(Operand DefOp, Operand UseOp) : defOp(DefOp), useOp(UseOp) {}
    bool operator==(const DependencyType &Other) const {
        return defOp == Other.defOp && useOp == Other.useOp;
    }
    bool operator<(const DependencyType &Other) const {
        return std::tie(defOp, useOp) < std::tie(Other.defOp, Other.useOp);
    }

    const DependencyType reversed() const { return DependencyType(useOp, defOp); }

    bool isComplementaryTypeAs(DependencyType &Other) {
        return defOp == Other.useOp && useOp == Other.defOp;
    }
    bool isSymmetric() { return defOp == useOp; }
    bool canCreateDependencyChain() {
        if (isSymmetric()) return true;
        if (defOp.isRegClass() && useOp.isRegister())
            return getEnv().regInRegClass(useOp.getRegister(), defOp.getRegClass());
        if (defOp.isRegister() && useOp.isRegClass())
            return getEnv().regInRegClass(defOp.getRegister(), useOp.getRegClass());
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

    LatMeasurement() : lowerBound(-1), upperBound(-1), ec(NO_ERROR_CODE) {}
    LatMeasurement(unsigned Opcode, DependencyType Type, unsigned DefIndex, unsigned UseIndex,
                   double LowerBound = -1, double UpperBound = -1, ErrorCode EC = NO_ERROR_CODE)
        : opcode(Opcode), type(Type), defIndex(DefIndex), useIndex(UseIndex),
          lowerBound(LowerBound), upperBound(UpperBound), ec(EC) {}
    bool operator==(const LatMeasurement &Other) const {
        return opcode == Other.opcode && type == Other.type && defIndex == Other.defIndex &&
               useIndex == Other.useIndex;
    }

    /**
     * \brief Returns the result as a string in the form [lower;upper].
     * \return String representation of the result.
     */
    std::string resToString() {
        return "[" + std::to_string(lowerBound) + ";" + std::to_string(upperBound) + "]";
    }
};

/**
 * \brief Stream output operator for LatMeasurement.
 */
inline std::ostream &operator<<(std::ostream &OS, const LatMeasurement &Op) {
    std::string useIndexString = std::to_string(Op.useIndex);
    std::string defIndexString = std::to_string(Op.defIndex);
    // useIndex == 999 means unused which means implicit
    if (Op.useIndex == 999) useIndexString = "impl";
    if (Op.defIndex == 999) defIndexString = "impl";

    if (!isError(Op.ec))
        return OS << getEnv().MCII->getName(Op.opcode).str() << "(" << useIndexString << "("
                  << Op.type.useOp << ")" << " -> " << defIndexString << "(" << Op.type.defOp
                  << ")) "
                  << " [" << Op.lowerBound << ";" << Op.upperBound << "]";

    return OS << getEnv().MCII->getName(Op.opcode).str() << "(" << useIndexString << "("
              << Op.type.useOp << ")" << " -> " << defIndexString << "(" << Op.type.defOp << "))";
}

#endif // GLOBALS_H
