#ifndef LLVM_DEBUG_H
#define LLVM_DEBUG_H

#include "CustomDebug.h"
#include "Globals.h"

#include "llvm/MC/MCInst.h"
// #include "llvm/MC/MCOperand.h"
#include "llvm/MC/MCRegister.h"
#include <llvm/MC/MCRegisterInfo.h>

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

} // namespace llvm

#endif // LLVM_DEBUG_H