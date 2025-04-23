#ifndef LLVM_ENVIRONMENT_H
#define LLVM_ENVIRONMENT_H

#include "ErrorCode.h"                       // for ErrorCode
#include "llvm/CodeGen/MachineFunction.h"    // for MachineFunction
#include "llvm/CodeGen/MachineModuleInfo.h"  // for MachineModuleInfo
#include "llvm/IR/LLVMContext.h"             // for LLVMContext
#include "llvm/IR/Module.h"                  // for Module
#include "llvm/Target/TargetMachine.h"       // for TargetMachine
#include "llvm/TargetParser/Triple.h"        // for Triple
#include <memory>                            // for unique_ptr
#include <string>                            // for basic_string, string
namespace llvm { class MCAsmInfo; }
namespace llvm { class MCInstPrinter; }
namespace llvm { class MCInstrInfo; }
namespace llvm { class MCRegisterInfo; }
namespace llvm { class MCSubtargetInfo; }
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
};

#endif // LLVM_ENVIRONMENT_H