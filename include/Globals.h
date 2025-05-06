#ifndef GLOBALS_H
#define GLOBALS_H

#include "ErrorCode.h"
#include "LLVMEnvironment.h"        // for LLVMEnvironment
#include "llvm/ADT/StringRef.h"     // for StringRef
#include "llvm/MC/MCInstrInfo.h"    // for MCInstrInfo
#include "llvm/MC/MCRegister.h"     // for MCRegister
#include "llvm/MC/MCRegisterInfo.h" // for MCRegisterInfo
#include <assert.h>                 // for assert
#include <fstream>
#include <iostream> // for basic_ostream, char_traits, oper...
#include <string>   // for basic_string, operator<<
#include <tuple>    // for tie, operator<, tuple

extern LLVMEnvironment env;

extern std::unique_ptr<std::ofstream> fileStream;
extern std::ostream *ios;

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
        return OS << "Class(" << env.MRI->getRegClassName(&env.MRI->getRegClass(Op.getRegClass()))
                  << ")";

    return OS << env.MRI->getName(Op.getRegister()) << " (" << Op.getRegister() << ")";
}

struct DependencyType {
    Operand defOp;
    Operand useOp;

    DependencyType(Operand DefOp, Operand UseOp) : defOp(DefOp), useOp(UseOp) {}
    bool operator==(const DependencyType &Other) const {
        return defOp == Other.defOp && useOp == Other.useOp;
    }
    bool operator<(const DependencyType &Other) const {
        return std::tie(defOp, useOp) < std::tie(Other.defOp, Other.useOp);
    }

    const DependencyType reversedType() const { return DependencyType(useOp, defOp); }
    bool isComplementaryTypeAs(DependencyType &Other) {
        return defOp == Other.useOp && useOp == Other.defOp;
    }
};
inline std::ostream &operator<<(std::ostream &OS, const DependencyType &Op) {
    return OS << Op.useOp << " -> " << Op.defOp;
}


struct LatMeasurement4 {
    unsigned opcode;
    DependencyType type; //e.g. R64 -> EFLAGS
    unsigned defIndex; //which operand is type.defOp
    unsigned useIndex; //which operand is type.useOp
    double value;

    LatMeasurement4(unsigned Opcode, DependencyType Type, unsigned DefIndex, unsigned UseIndex,
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

#endif // GLOBALS_H