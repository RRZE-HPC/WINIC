#ifndef GLOBALS_H
#define GLOBALS_H

#include "ErrorCode.h"              // for ErrorCode, isError
#include "LLVMEnvironment.h"        // for LLVMEnvironment
#include "llvm/ADT/StringRef.h"     // for StringRef
#include "llvm/MC/MCInstrInfo.h"    // for MCInstrInfo
#include "llvm/MC/MCRegister.h"     // for MCRegister
#include "llvm/MC/MCRegisterInfo.h" // for MCRegisterInfo
#include <assert.h>                 // for assert
#include <fstream>                  // for basic_ostream, operator<<, ostream
#include <limits>                   // for numeric_limits
#include <memory>                   // for unique_ptr
#include <string>                   // for char_traits, allocator, basic_st...
#include <tuple>                    // for tie, operator<, tuple

LLVMEnvironment &getEnv();

extern std::unique_ptr<std::ofstream> fileStream;
extern std::ostream *ios;

const unsigned MAX_UNSIGNED = std::numeric_limits<unsigned>::max();

enum class LatOperandKind { RegisterClass, Register };

struct Operand {
    LatOperandKind kind;
    union {
        unsigned regClass;
        MCRegister reg;
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

inline std::ostream &operator<<(std::ostream &OS, const Operand &Op) {
    if (Op.isRegClass())
        return OS << "Class("
                  << getEnv().MRI->getRegClassName(&getEnv().MRI->getRegClass(Op.getRegClass()))
                  << ")";

    return OS << getEnv().MRI->getName(Op.getRegister()) << "(" << Op.getRegister() << ")";
}

struct DependencyType {
    Operand defOp;
    Operand useOp;

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

inline std::ostream &operator<<(std::ostream &OS, const DependencyType &Op) {
    return OS << Op.useOp << " -> " << Op.defOp;
}

struct LatMeasurement {
    unsigned opcode;
    DependencyType type; // e.g. R64 -> EFLAGS
    unsigned defIndex;   // which operand is type.defOp (999 if implicit)
    unsigned useIndex;   // which operand is type.useOp (999 if implicit)
    // results
    double lowerBound;
    double upperBound;
    ErrorCode ec;

    LatMeasurement() : lowerBound(-1), upperBound(-1), ec(NO_ERROR_CODE) {}
    LatMeasurement(unsigned Opcode, DependencyType Type, unsigned DefIndex, unsigned UseIndex,
                   double LowerBound = -1, double UpperBound = -1, ErrorCode EC = NO_ERROR_CODE)
        : opcode(Opcode), type(Type), defIndex(DefIndex), useIndex(UseIndex),
          lowerBound(LowerBound), upperBound(UpperBound), ec(EC) {}
    bool operator==(const LatMeasurement &Other) const {
        return opcode == Other.opcode && type == Other.type && defIndex == Other.defIndex &&
               useIndex == Other.useIndex;
    }

    std::string resToString() {
        return "[" + std::to_string(lowerBound) + ";" + std::to_string(upperBound) + "]";
    }
};

inline std::ostream &operator<<(std::ostream &OS, const LatMeasurement &Op) {
    std::string useIndexString = std::to_string(Op.useIndex);
    std::string defIndexString = std::to_string(Op.defIndex);
    // useIndex == 999 means unused which means implicit
    if (Op.useIndex == 999) useIndexString = "impl";
    if (Op.defIndex == 999) defIndexString = "impl";

    if (!isError(Op.ec))
        return OS << getEnv().MCII->getName(Op.opcode).str() << "(" << useIndexString << "->"
                  << defIndexString << ") " << Op.type << " [" << Op.lowerBound << ";"
                  << Op.upperBound << "]";

    return OS << getEnv().MCII->getName(Op.opcode).str() << "(" << useIndexString << "->"
              << defIndexString << ") " << Op.type;
}

#endif // GLOBALS_H