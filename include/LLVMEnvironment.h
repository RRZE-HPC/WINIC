#ifndef LLVM_ENVIRONMENT_H
#define LLVM_ENVIRONMENT_H

#include "ErrorCode.h"                      // for ErrorCode
#include "llvm/CodeGen/MachineFunction.h"   // for MachineFunction
#include "llvm/CodeGen/MachineModuleInfo.h" // for MachineModuleInfo
#include "llvm/IR/LLVMContext.h"            // for LLVMContext
#include "llvm/IR/Module.h"                 // for Module
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/Target/TargetMachine.h" // for TargetMachine
#include "llvm/TargetParser/Triple.h"  // for Triple
#include <memory> // for unique_ptr
#include <set>
#include <string> // for basic_string, string
namespace llvm {
class MCAsmInfo;
}
namespace llvm {
class MCInstPrinter;
}
namespace llvm {
class MCInstrInfo;
}
namespace llvm {
class MCRegisterInfo;
}
namespace llvm {
class MCSubtargetInfo;
}
// namespace llvm { class TargetRegisterInfo; }

using namespace llvm;

class LLVMEnvironment {
  public:
    LLVMContext Ctx;
    Triple TargetTriple;
    std::unique_ptr<Module> Mod;
    std::unique_ptr<TargetMachine> Machine;
    std::unique_ptr<MachineFunction> MF;
    std::unique_ptr<MachineModuleInfo> MMI;
    const TargetRegisterInfo *TRI;
    MCRegisterInfo *MRI;
    MCAsmInfo *MAI;
    MCInstrInfo *MCII;
    MCSubtargetInfo *MSTI;
    MCInstPrinter *MIP;
    unsigned MaxReg;
    Triple::ArchType Arch;

    LLVMEnvironment();
    LLVMEnvironment(const LLVMEnvironment &) = delete;
    LLVMEnvironment &operator=(const LLVMEnvironment &) = delete;

    ErrorCode setUp(std::string March = "", std::string Cpu = "");

    bool regInRegClass(MCRegister Reg, MCRegisterClass RegClass);
    bool regInRegClass(MCRegister Reg, unsigned RegClassID);

    std::string regToString(MCRegister Reg);
    std::string regClassToString(MCRegisterClass RegClass);
    std::string regClassToString(unsigned RegClassID);

    // get Opcode for instruction
    // TODO there probably is a mechanism for this in llvm -> find and use
    int getOpcode(std::string InstructionName);

    /**
     * get all registers which can be read by an instruction including implicit uses
     */
    std::set<MCRegister> getPossibleReadRegs(unsigned Opcode);

    /**
     * get all registers which can be written by an instruction including implicit defs
     */
    std::set<MCRegister> getPossibleWriteRegs(unsigned Opcode);

    std::set<MCRegister> regIntersect(std::set<MCRegister> A, std::set<MCRegister> B);

    std::set<MCRegister> regDifference(std::set<MCRegister> A, std::set<MCRegister> B);

    std::set<MCRegister> regUnion(std::set<MCRegister> A, std::set<MCRegister> B);
};

#endif // LLVM_ENVIRONMENT_H