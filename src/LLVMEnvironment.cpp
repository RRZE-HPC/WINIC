#include "LLVMEnvironment.h"

#include "AArch64InstrInfo.h"
#include "CustomDebug.h"
#include "ErrorCode.h"
#include "Globals.h"
#include "LLVMDebug.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/MC/MCInstrDesc.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/CodeGen.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/TargetParser/Host.h"
#include "llvm/TargetParser/Triple.h"
#include <algorithm>
#include <assert.h>
#include <iostream>
#include <iterator>
#include <limits>
#include <optional>
#include <vector>

using namespace llvm;

namespace winic {

LLVMEnvironment::LLVMEnvironment() : Ctx(), Mod(std::make_unique<Module>("my_module", Ctx)) {}

ErrorCode LLVMEnvironment::setUp(std::string March, std::string Cpu) {
    std::string targetTripleStr;
    if (March.empty()) {
        targetTripleStr = llvm::sys::getDefaultTargetTriple();
    } else {
        targetTripleStr = (March + "-pc-linux").data();
    }
    TargetTriple = Triple(targetTripleStr);

    if (Cpu.empty()) Cpu = llvm::sys::getHostCPUName().str();
    if (Cpu.empty()) return E_CPU_DETECT;
    if (Cpu.find("generic") != std::string::npos)
        std::cout << "Generic CPU detected, this may lead suboptimal results. Use --cpu to "
                     "specify a CPU."
                  << std::endl;

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
        out(std::cerr, "unsupported architecture: ", TargetTriple.getArchName().str(),
            " choose from: x86_64, aarch64, riscv64");
        return E_UNSUPPORTED_ARCH;
    }
    out(std::cout, "detected ", targetTripleStr, ", CPU: ", Cpu);
    // partially copied from InstrRefLDVTest.cpp InstrRefLDVTest.cpp
    // Mod->setDataLayout("e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-"
    //                    "f80:128-n8:16:32:64-S128");
    // Mod->setDataLayout(Machine->createDataLayout());
    std::string error;
    const Target *theTarget = TargetRegistry::lookupTarget("", TargetTriple, error);

    MRI.reset(theTarget->createMCRegInfo(TargetTriple));
    assert(MRI && "Unable to create register info!");
    MCTargetOptions mcOptions;
    MAI.reset(theTarget->createMCAsmInfo(*MRI, TargetTriple, mcOptions));
    assert(MAI && "Unable to create asm info!");
    MCII.reset(theTarget->createMCInstrInfo());
    assert(MCII && "Unable to create MCInnstr info!");
    MSTI.reset(theTarget->createMCSubtargetInfo(TargetTriple, Cpu, ""));
    assert(MSTI && "Unable to create MCSubtargetInfo!");
    // set syntaxVariant here
    MIP.reset(theTarget->createMCInstPrinter(Triple(targetTripleStr), 1, *MAI, *MCII, *MRI));
    assert(MIP && "Unable to create MCInstPrinter!");
    TargetOptions options;
    Machine.reset(theTarget->createTargetMachine(TargetTriple, Cpu, "", options, std::nullopt,
                                                 std::nullopt, CodeGenOptLevel::Aggressive));
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
    MaxReg = TRI->getNumSupportedRegs(*MF);
    Arch = MSTI->getTargetTriple().getArch(); // for convenience
    return SUCCESS;
}

unsigned LLVMEnvironment::getMemoryOperandWidthUpperBound(unsigned Opcode) {
    const MCInstrDesc &desc = getEnv().MCII->get(Opcode);

    if (getEnv().Arch == llvm::Triple::aarch64) {
        // check if the target specific helpers can provide an exact width
        TypeSize scale(0U, false), width(0U, false);
        int64_t minOffset, maxOffset;
        if (AArch64InstrInfo::getMemOpInfo(Opcode, scale, width, minOffset, maxOffset)) {
            // when width=8 and scale=4 this returns 2. LLVM later scales the immediate up by the
            // factor of 4 while printing the instruction
            if (width.isFixed()) return width / scale;
        }
    }

    // apply an ugly workaround: assume the memory accessed is smaller than the widest register of
    // the instruction. If you know better how llvm works, please replace this with a proper lookup
    unsigned maxRegWidth = 0;

    for (int i = 0; i < desc.getNumOperands(); i++) {
        const MCOperandInfo &opInfo = desc.operands()[i];
        if (opInfo.OperandType == MCOI::OPERAND_REGISTER) {
            maxRegWidth = std::max(maxRegWidth, MRI->getRegClass(opInfo.RegClass).getSizeInBits());
        }
    }
    return maxRegWidth / 8;

    // failed try to do this properly
    // #include "llvm/CodeGen/MachineBasicBlock.h"
    // #include "llvm/CodeGen/MachineInstrBuilder.h"
    // #include "llvm/CodeGen/TargetInstrInfo.h"

    // TII = MF->getSubtarget().getInstrInfo();
    // DebugLoc DL;
    // MachineInstr *MI = BuildMI(*MF, DL, TII->get(Desc.getOpcode()));
    // auto *MBB = MF->CreateMachineBasicBlock();
    // MBB->insert(MBB->end(), MI);
    // MF->push_back(MBB);
    // SmallVector<const MachineOperand *, 2> baseOps;
    // int64_t offset;
    // bool offsetIsScalable;
    // LocationSize size = LocationSize::mapEmpty();

    // bool ok = TII->getMemOperandsWithOffsetWidth(*MI, baseOps, offset, offsetIsScalable,
    // size, TRI); if (ok) {
    //     dbg(__func__, "getValue");
    //     return size.getValue().getFixedValue();
    // } else {
    //     dbg(__func__, "not ok ");
    //     return -1;
    // }
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

std::vector<MCRegisterClass> LLVMEnvironment::getRegClasses(MCRegister Reg) {
    std::vector<MCRegisterClass> result = {};
    for (unsigned i = 0; i < MRI->getNumRegClasses(); i++)
        if (regInRegClass(Reg, i)) result.emplace_back(MRI->getRegClass(i));

    return result;
}

std::string LLVMEnvironment::getRegAsmName(MCRegister Reg) {
    std::string regName;
    llvm::raw_string_ostream rss(regName);
    MIP->printRegName(rss, Reg);
    return regName;
}

unsigned LLVMEnvironment::getOpcode(std::string InstructionName) {
    for (unsigned i = 0; i < MCII->getNumOpcodes(); ++i)
        if (MCII->getName(i) == InstructionName) return i;

    return std::numeric_limits<unsigned>::max();
}

void LLVMEnvironment::printRegClassInfo() {
    for (unsigned i = 0; i < MRI->getNumRegClasses(); i++) {
        MCRegisterClass regClass = MRI->getRegClass(i);
        std::vector<std::string> regs;
        for (int j = 0; j < regClass.getNumRegs(); j++) {
            // TODO missing cast to MCRegister fixed in LLVM 21.1.0
            regs.push_back(str((MCRegister)regClass.getRegister(j)));
        }
        dbg(__func__, MRI->getRegClassName(&regClass), ": ", regs);
    }
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

unsigned LLVMEnvironment::getTiedToOperand(MCOperandInfo OpInfo) {
    if (OpInfo.Constraints & (1 << MCOI::TIED_TO))
        return (OpInfo.Constraints >> (4 + MCOI::TIED_TO * 4)) & 0xF;
    return NO_OP_INDEX;
}

unsigned LLVMEnvironment::getAArch64OffsetOperandIndex(unsigned Opcode) {
    if (getEnv().Arch != llvm::Triple::aarch64) return NO_OP_INDEX;
    // verify this is a memory instruction as llvm does in AArch64InstrInfo::verifyInstruction
    TypeSize scale(0U, false), width(0U, false);
    int64_t minOffset, maxOffset;
    if (!AArch64InstrInfo::getMemOpInfo(Opcode, scale, width, minOffset, maxOffset)) {
        dbg(__func__, "did not get a mem op info ");
        return NO_OP_INDEX;
    }

    return AArch64InstrInfo::getLoadStoreImmIdx(Opcode);
}

unsigned LLVMEnvironment::getAArch64BaseOperandIndex(unsigned Opcode) {
    if (getEnv().Arch != llvm::Triple::aarch64) return NO_OP_INDEX;
    TypeSize scale(0U, false), width(0U, false);
    int64_t minOffset, maxOffset;
    if (!AArch64InstrInfo::getMemOpInfo(Opcode, scale, width, minOffset, maxOffset))
        return NO_OP_INDEX;

    return getAArch64OffsetOperandIndex(Opcode) - 1;
}

bool LLVMEnvironment::mayAccessMemory(unsigned Opcode) {
    const MCInstrDesc &desc = MCII->get(Opcode);
    return desc.mayLoad() || desc.mayStore();
}

std::set<MCRegister> LLVMEnvironment::regIntersect(std::set<MCRegister> A, std::set<MCRegister> B) {
    std::set<MCRegister> result;
    std::set_intersection(A.begin(), A.end(), B.begin(), B.end(),
                          std::inserter(result, result.begin()));
    return result;
}

std::set<MCRegister>
LLVMEnvironment::regDifference(std::set<MCRegister> A, std::set<MCRegister> B) {
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

} // namespace winic
