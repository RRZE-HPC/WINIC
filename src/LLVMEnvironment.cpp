#include "LLVMEnvironment.h"

#include "llvm/ADT/StringRef.h"                // for StringRef
#include "llvm/ADT/Twine.h"                    // for Twine
#include "llvm/CodeGen/TargetRegisterInfo.h"   // for TargetRegisterInfo
#include "llvm/CodeGen/TargetSubtargetInfo.h"  // for TargetSubtargetInfo
#include "llvm/IR/DerivedTypes.h"              // for FunctionType
#include "llvm/IR/Function.h"                  // for Function
#include "llvm/IR/GlobalValue.h"               // for GlobalValue
#include "llvm/IR/Module.h"                    // for Module
#include "llvm/IR/Type.h"                      // for Type
#include "llvm/MC/MCSubtargetInfo.h"           // for MCSubtargetInfo
#include "llvm/MC/MCTargetOptions.h"           // for MCTargetOptions
#include "llvm/MC/TargetRegistry.h"            // for Target, TargetRegistry
#include "llvm/Support/CodeGen.h"              // for CodeGenOptLevel
#include "llvm/Support/TargetSelect.h"         // for LLVMInitializeAArch64A...
#include "llvm/Support/raw_ostream.h"          // for raw_fd_ostream, raw_os...
#include "llvm/Target/TargetMachine.h"         // for TargetMachine
#include "llvm/Target/TargetOptions.h"         // for TargetOptions
#include "llvm/TargetParser/Host.h"            // for getDefaultTargetTriple
#include <assert.h>                            // for assert
#include <optional>                            // for nullopt, nullopt_t



using namespace llvm;

LLVMEnvironment::LLVMEnvironment() : Ctx(), Mod(std::make_unique<Module>("beehives", Ctx)) {
    
}
ErrorCode LLVMEnvironment::setUp(std::string March, std::string Cpu) {

    // LLVMInitializeX86AsmParser();
    // LLVMInitializeX86Disassembler();
    // LLVMInitializeX86TargetMCA();
    // InitializeAllTargets();
    // InitializeAllTargetInfos();
    // InitializeAllTargetMCs();
    // InitializeAllAsmPrinters();
    // StringRef TargetTripleStr = "x86_64-pc-linux";
    std::string targetTripleStr;
    if (March.empty()) {
        targetTripleStr = llvm::sys::getDefaultTargetTriple();
    } else {
        targetTripleStr = (March + "-pc-linux").data();
    }
    TargetTriple = Triple(targetTripleStr);

    if (Cpu.empty()) Cpu = llvm::sys::getHostCPUName().str();
    if (Cpu.empty()) return ERROR_CPU_DETECT;
    outs() << "detected " << targetTripleStr << ", march: " << Cpu << "\n";
    outs().flush();
    if (TargetTriple.getArch() == Triple::ArchType::x86_64) {
        LLVMInitializeX86Target();
        LLVMInitializeX86TargetInfo();
        LLVMInitializeX86TargetMC();
        LLVMInitializeX86AsmPrinter();
    } else if (TargetTriple.getArch() == Triple::ArchType::aarch64) {
        LLVMInitializeAArch64Target();
        LLVMInitializeAArch64TargetInfo();
        LLVMInitializeAArch64TargetMC();
        LLVMInitializeAArch64AsmPrinter();
    } else if (TargetTriple.getArch() == Triple::ArchType::riscv64) {
        LLVMInitializeRISCVTarget();
        LLVMInitializeRISCVTargetInfo();
        LLVMInitializeRISCVTargetMC();
        LLVMInitializeRISCVAsmPrinter();
    } else {
        if (TargetTriple.getArch() != llvm::Triple::UnknownArch)
            errs() << "unsupported architecture: " << TargetTriple.getArchName() << "\n";
        return ERROR_TARGET_DETECT;
    }
    // StringRef TargetTripleStr = "x86_64--";
    // copied from InstrRefLDVTest.cpp
    Mod->setDataLayout("e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-"
                       "f80:128-n8:16:32:64-S128");
    std::string error;
    const Target *theTarget = TargetRegistry::lookupTarget("", TargetTriple, error);
    TargetOptions options;
    Machine = std::unique_ptr<TargetMachine>(
        theTarget->createTargetMachine(Triple::normalize(targetTripleStr), Cpu, "", options,
                                       std::nullopt, std::nullopt, CodeGenOptLevel::Aggressive));
    assert(Machine && "Unable to create Machine");
    FunctionType *type = FunctionType::get(Type::getVoidTy(Ctx), false);
    assert(type && "Unable to create Type");
    Function *f = Function::Create(type, GlobalValue::ExternalLinkage, "Test", &*Mod);
    assert(type && "Unable to create Function");
    // auto F = Function::Create(Type, GlobalValue::ExternalLinkage, "Test");
    // /own
    unsigned functionNum = 42;
    MMI = std::make_unique<MachineModuleInfo>(Machine.get());
    const TargetSubtargetInfo &stimpl = *Machine->getSubtargetImpl(*f);
    MF = std::make_unique<MachineFunction>(*f, *Machine, stimpl, MMI->getContext(), functionNum);
    TRI = MF->getSubtarget().getRegisterInfo();
    // copied from InstrRefLDVTest.cpp
    MaxReg = TRI->getNumSupportedRegs(*MF);
    MRI = theTarget->createMCRegInfo(targetTripleStr);
    assert(MRI && "Unable to create register info!");
    MCTargetOptions mcOptions;
    MAI = theTarget->createMCAsmInfo(*MRI, targetTripleStr, mcOptions);
    assert(MAI && "Unable to create asm info!");
    MCII = theTarget->createMCInstrInfo();
    assert(MCII && "Unable to create MCInnstr info!");
    MSTI = theTarget->createMCSubtargetInfo(targetTripleStr, Cpu, "");
    assert(MSTI && "Unable to create MCSubtargetInfo!");
    Arch = MSTI->getTargetTriple().getArch(); // for convenience
    // set syntaxVariant here
    if (Arch == Triple::ArchType::x86_64)
        MIP = theTarget->createMCInstPrinter(Triple(targetTripleStr), 1, *MAI, *MCII, *MRI);
    else
        MIP = theTarget->createMCInstPrinter(Triple(targetTripleStr), 1, *MAI, *MCII, *MRI);
    assert(MIP && "Unable to create MCInstPrinter!");
    return SUCCESS;
}
