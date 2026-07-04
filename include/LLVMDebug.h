#ifndef LLVM_DEBUG_H
#define LLVM_DEBUG_H

#include "Globals.h"
#include "LLVMEnvironment.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/MC/MCRegisterInfo.h"
#include <cstdint>
#include <llvm/MC/MCInstrDesc.h>
#include <memory>
#include <ostream>

namespace llvm {

inline std::ostream &operator<<(std::ostream &OS, const StringRef &Ref) { return OS << Ref.data(); }

inline std::ostream &operator<<(std::ostream &OS, const MCRegisterClass &RegClass) {
    return OS << ::winic::getEnv().MRI->getRegClassName(&RegClass);
}

inline std::ostream &operator<<(std::ostream &OS, const MCRegister &Reg) {
    return OS << ::winic::getEnv().MRI->getName(Reg);
}

inline std::ostream &operator<<(std::ostream &OS, const MCOperand &Op) {
    if (Op.isReg()) {
        OS << "Reg(" << ::winic::getEnv().MRI->getName(Op.getReg()) << ")";
    } else if (Op.isImm()) {
        OS << "Imm(" << Op.getImm() << ")";
    } else if (Op.isExpr()) {
        OS << "Expr";
    } else {
        OS << "Unknown";
    }
    return OS;
}

inline std::ostream &operator<<(std::ostream &OS, const MCInst &Inst) {
    OS << "MCInst<" << ::winic::getEnv().MCII->getName(Inst.getOpcode());
    for (unsigned i = 0; i < Inst.getNumOperands(); ++i) {
        OS << ", op" << i << ": " << Inst.getOperand(i);
    }
    return OS << ">";
}

constexpr std::string_view opToString(uint8_t OperandType) {
    switch (OperandType) {
    case MCOI::OPERAND_UNKNOWN:
        return "OPERAND_UNKNOWN";
    case MCOI::OPERAND_IMMEDIATE:
        return "OPERAND_IMMEDIATE";
    case MCOI::OPERAND_REGISTER:
        return "OPERAND_REGISTER";
    case MCOI::OPERAND_MEMORY:
        return "OPERAND_MEMORY";
    case MCOI::OPERAND_PCREL:
        return "OPERAND_PCREL";
    case MCOI::OPERAND_GENERIC_0:
        return "OPERAND_GENERIC_0";
    case MCOI::OPERAND_GENERIC_1:
        return "OPERAND_GENERIC_1";
    case MCOI::OPERAND_GENERIC_2:
        return "OPERAND_GENERIC_2";
    case MCOI::OPERAND_GENERIC_3:
        return "OPERAND_GENERIC_3";
    case MCOI::OPERAND_GENERIC_4:
        return "OPERAND_GENERIC_4";
    case MCOI::OPERAND_GENERIC_5:
        return "OPERAND_GENERIC_5";
    case MCOI::OPERAND_GENERIC_IMM_0:
        return "OPERAND_GENERIC_IMM_0";
    case MCOI::OPERAND_FIRST_TARGET:
        return "OPERAND_FIRST_TARGET";
    default:
        return "unknown";
    }
}

inline std::ostream &operator<<(std::ostream &OS, const MCOperandInfo &OpInfo) {
    return OS << opToString(OpInfo.OperandType);
}

inline std::ostream &operator<<(std::ostream &OS, const MCInstrDesc &InstrDesc) {
    OS << "MCInstrDesc<" << ::winic::getEnv().MCII->getName(InstrDesc.getOpcode());
    for (unsigned i = 0; i < InstrDesc.getNumOperands(); ++i) {
        OS << ", op" << i << ": " << InstrDesc.operands()[i];
    }
    return OS << " numDefs: " << InstrDesc.getNumDefs() << ">";
}

} // namespace llvm

#endif // LLVM_DEBUG_H