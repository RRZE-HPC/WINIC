#include "LLVMEnvironment.h"

#include "CustomDebug.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/MC/MCInstrDesc.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/CodeGen.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/TargetParser/Host.h"
#include <algorithm>
#include <assert.h>
#include <iterator>
#include <limits>
#include <optional>

using namespace llvm;

LLVMEnvironment::LLVMEnvironment() : Ctx(), Mod(std::make_unique<Module>("my_module", Ctx)) {}

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
    if (Cpu.empty()) return E_CPU_DETECT;
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
        return E_UNSUPPORTED_ARCH;
    }
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
    unsigned functionNum = 42;

    // release/20.x
    MMI = std::make_unique<MachineModuleInfo>(Machine.get());
    const TargetSubtargetInfo &stimpl = *Machine->getSubtargetImpl(*f);
    MF = std::make_unique<MachineFunction>(*f, *Machine, stimpl, MMI->getContext(), functionNum);

    // pre release/20.x
    // MMI =
    //     std::make_unique<MachineModuleInfo>(static_cast<const LLVMTargetMachine
    //     *>(Machine.get()));
    // const TargetSubtargetInfo &stimpl = *Machine->getSubtargetImpl(*f);
    // MF = std::make_unique<MachineFunction>(*f,
    //                                        *static_cast<const LLVMTargetMachine
    //                                        *>(Machine.get()), stimpl, functionNum, *MMI.get());

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

bool LLVMEnvironment::regInRegClass(MCRegister Reg, MCRegisterClass RegClass) {
    for (MCRegister reg : RegClass)
        if (reg == Reg) return true;
    return false;
}

bool LLVMEnvironment::regInRegClass(MCRegister Reg, unsigned RegClassID) {
    const MCRegisterClass &regClass = MRI->getRegClass(RegClassID);
    return regInRegClass(Reg, regClass);
}

std::string LLVMEnvironment::regToString(MCRegister Reg) { return TRI->getName(Reg); }

std::string LLVMEnvironment::regClassToString(MCRegisterClass RegClass) {
    return MRI->getRegClassName(&RegClass);
}

std::string LLVMEnvironment::regClassToString(unsigned RegClassID) {
    const MCRegisterClass &regClass = MRI->getRegClass(RegClassID);
    return MRI->getRegClassName(&regClass);
}

unsigned LLVMEnvironment::getOpcode(std::string InstructionName) {
    for (unsigned i = 0; i < MCII->getNumOpcodes(); ++i)
        if (MCII->getName(i) == InstructionName) return i;

    dbg(__func__, "Instruction not found: ", InstructionName);
    return std::numeric_limits<unsigned>::max();
}

std::set<MCRegister> LLVMEnvironment::getPossibleUses(unsigned Opcode) {
    std::set<MCRegister> reads;
    const MCInstrDesc &desc = MCII->get(Opcode);
    for (unsigned i = desc.getNumDefs(); i < desc.getNumOperands(); i++) {
        if (desc.operands()[i].OperandType != MCOI::OPERAND_REGISTER) continue;
        auto regClass = MRI->getRegClass(desc.operands()[i].RegClass);
        for (auto reg : regClass) {
            reads.insert(reg);
        }
    }
    for (auto reg : desc.implicit_uses()) {
        reads.insert(MCRegister::from(reg));
    }
    return reads;
}

std::set<MCRegister> LLVMEnvironment::getPossibleDefs(unsigned Opcode) {
    std::set<MCRegister> writes;
    const MCInstrDesc &desc = MCII->get(Opcode);
    for (unsigned i = 0; i < desc.getNumDefs(); i++) {
        if (desc.operands()[i].OperandType != MCOI::OPERAND_REGISTER) continue;
        auto regClass = MRI->getRegClass(desc.operands()[i].RegClass);
        for (auto reg : regClass) {
            writes.insert(reg);
        }
    }
    for (auto reg : desc.implicit_defs()) {
        writes.insert(MCRegister::from(reg));
    }
    return writes;
}

std::set<MCRegister> LLVMEnvironment::regIntersect(std::set<MCRegister> A, std::set<MCRegister> B) {
    std::set<MCRegister> result;
    std::set_intersection(A.begin(), A.end(), B.begin(), B.end(),
                          std::inserter(result, result.begin()));
    return result;
}

std::set<MCRegister> LLVMEnvironment::regDifference(std::set<MCRegister> A,
                                                    std::set<MCRegister> B) {
    std::set<MCRegister> result;
    std::set_difference(A.begin(), A.end(), B.begin(), B.end(),
                        std::inserter(result, result.begin()));
    return result;
}

std::set<MCRegister> LLVMEnvironment::regUnion(std::set<MCRegister> A, std::set<MCRegister> B) {
    std::set<MCRegister> result;
    std::set_union(A.begin(), A.end(), B.begin(), B.end(), std::inserter(result, result.begin()));
    return result;
}
