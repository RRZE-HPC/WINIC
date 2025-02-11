#include "MCTargetDesc/X86MCTargetDesc.h"
#include "templates.cpp"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/RegisterBankInfo.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrDesc.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/TargetParser/Triple.h"
#include <algorithm>
#include <cstdlib>
#include <list>
#include <set>
#include <string>

// #include "llvm/lib/Target/X86/X86RegisterInfo.h"
// #include <llvm/include/llvm/ADT/StringRef.h>
// #include "llvm/MC/MCAsmInfo.h"
// #include "llvm/MC/MCTargetOptions.h"
// #include "llvm/MC/MCSubtargetInfo.h"
// #include "llvm/Support/raw_ostream.h"
// #include "llvm/MC/MCDisassembler/MCDisassembler.h"

/*
TODO
save callee saved registers
compile and run from inside llvm
check filtering memory instructions
test other arches
add templates for other arches
*/

// helpful
// TRI->getRegAsmName(MCRegister)

using namespace llvm;

class BenchmarkGenerator {
  public:
    LLVMContext Ctx;
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
    unsigned maxReg;

    BenchmarkGenerator() : Ctx(), Mod(std::make_unique<Module>("beehives", Ctx)) {}

    void SetUp() {
        LLVMInitializeX86Target();
        LLVMInitializeX86TargetInfo();
        LLVMInitializeX86TargetMC();

        // StringRef TargetTripleStr = "x86_64-pc-linux";
        StringRef TargetTripleStr = "x86_64--";

        // copied from InstrRefLDVTest.cpp
        Mod->setDataLayout("e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-"
                           "f80:128-n8:16:32:64-S128");
        Triple TargetTriple(TargetTripleStr);
        std::string Error;
        const Target *T = TargetRegistry::lookupTarget("", TargetTriple, Error);

        TargetOptions Options;
        Machine = std::unique_ptr<TargetMachine>(
            T->createTargetMachine(Triple::normalize("x86_64--"), "skylake", "", Options,
                                   std::nullopt, std::nullopt, CodeGenOptLevel::Aggressive));

        auto Type = FunctionType::get(Type::getVoidTy(Ctx), false);

        auto F = Function::Create(Type, GlobalValue::ExternalLinkage, "Test", &*Mod);
        // auto F = Function::Create(Type, GlobalValue::ExternalLinkage, "Test"); /own

        unsigned FunctionNum = 42;
        MMI = std::make_unique<MachineModuleInfo>(Machine.get());
        const TargetSubtargetInfo &STI = *Machine->getSubtargetImpl(*F);
        MF = std::make_unique<MachineFunction>(*F, *Machine, STI, MMI->getContext(), FunctionNum);
        TRI = MF->getSubtarget().getRegisterInfo();
        // copied from InstrRefLDVTest.cpp

        MRI = T->createMCRegInfo(TargetTripleStr);
        assert(MRI && "Unable to create register info!");

        MCTargetOptions MCOptions;
        MAI = T->createMCAsmInfo(*MRI, TargetTripleStr, MCOptions);
        assert(MAI && "Unable to create asm info!");

        MCII = T->createMCInstrInfo();
        assert(MCII && "Unable to create MCInnstr info!");

        MSTI = T->createMCSubtargetInfo(TargetTripleStr, "ivybridge", "");
        assert(MSTI && "Unable to create MCSubtargetInfo!");

        // set syntax variant here
        MIP = T->createMCInstPrinter(Triple(TargetTripleStr), 1, *MAI, *MCII, *MRI);
        assert(MIP && "Unable to create MCInstPrinter!");

        maxReg = TRI->getNumSupportedRegs(*MF);
    }

    int createAnyValidInstruction(unsigned opcode) {
        const MCInstrDesc &desc = MCII->get(opcode);
        if (!isValid(desc))
            return 1;
        unsigned numOperands = desc.getNumOperands();
        std::set<MCRegister> usedRegisters;

        MCInst tempInst;
        tempInst.setOpcode(opcode);
        tempInst.clear();

        for (unsigned j = 0; j < numOperands; ++j) {
            const MCOperandInfo &opInfo = desc.operands()[j];

            // TIED_TO points to operand which this has to be identical to see MCInstrDesc.h:41
            if (opInfo.Constraints & (1 << MCOI::TIED_TO)) {
                // this operand must be identical to another operand
                unsigned TiedToOp = (opInfo.Constraints >> (4 + MCOI::TIED_TO * 4)) & 0xF;
                tempInst.addOperand(tempInst.getOperand(TiedToOp));
                outs() << "added tied operand again: " << TiedToOp << "\n";
            } else {
                // search for unused register and add it as operand
                const MCRegisterClass &RegClass = MRI->getRegClass(opInfo.RegClass);
                for (MCRegister reg : RegClass) {
                    // outs() << "trying: " << Reg.id() << " name: " << TRI->getName(Reg) <<
                    // "\n";
                    if (reg.id() >= maxReg) {
                        outs() << "all supported registers of this class are in use" << "\n";
                        // TODO handle this case
                        break;
                    }
                    if (usedRegisters.find(reg) == usedRegisters.end()) {
                        tempInst.addOperand(MCOperand::createReg(reg));
                        usedRegisters.insert(reg);
                        break;
                    }
                }
            }
        }
        MIP->printInst(&tempInst, 0, "", *MSTI, outs());
        outs() << "\n";

        return 0;
    }

    int genTPBenchmark(unsigned opcode, unsigned targetInstrCount, raw_fd_ostream &stream()) {
        auto benchTemplate = x86Template();
        // extract list of registers used by the template
        std::set<MCRegister> usedRegisters;
        for (unsigned i = 0; i < MRI->getNumRegs(); i++) {
            MCRegister reg = MCRegister::from(i);

            if (benchTemplate.usedRegisters.find(TRI->getRegAsmName(reg).lower().data()) !=
                benchTemplate.usedRegisters.end())
                usedRegisters.insert(reg);
        }
        if (benchTemplate.usedRegisters.size() != usedRegisters.size())
            return -1; // probably error in template

        std::list<MCInst> instructions = genTPInnerLoop(opcode, targetInstrCount, usedRegisters);

        // save registers used (genTPInnerLoop updates usedRegisters)
        std::string saveRegs;
        std::string restoreRegs;
        for (MCRegister reg : usedRegisters) {
            if (TRI->isCalleeSavedPhysReg(reg, *MF)) {
                // generate code to save and restore register
                // this currently also saves registers already saved in the template
                // which is redundant but not harmful
                saveRegs.append(genSaveRegister(reg)).append("\n");
                restoreRegs.insert(0, genRestoreRegister(reg).append("\n"));
            }
        }
        stream() << "#define NINST " << instructions.size() << "\n";
        stream() << benchTemplate.preLoop;
        stream() << saveRegs;
        // init registers TODO
        stream() << benchTemplate.beginLoop;

        for (auto inst : instructions) {
            MIP->printInst(&inst, 0, "", *MSTI, stream());
            stream() << "\n";
        }

        stream() << benchTemplate.midLoop;
        stream() << benchTemplate.endLoop;
        stream() << restoreRegs;
        stream() << benchTemplate.postLoop << "\n";
        return 0;
    }

    // generates a benchmark loop to measure throughput of an instruction
    // tries to generate targetInstrCount independent instructions for the inner loop
    // might generate less instructions than targetInstrCount if there are not enough registers
    // updates usedRegisters
    std::list<MCInst> genTPInnerLoop(unsigned opcode, unsigned targetInstrCount,
                                     std::set<MCRegister> &usedRegisters) {
        std::list<MCInst> instructions;
        const MCInstrDesc &desc = MCII->get(opcode);
        if (!isValid(desc))
            return {};
        unsigned numOperands = desc.getNumOperands();

        // the first numDefs operands are destination operands
        // outs() << "desc.getNumDefs() " << desc.getNumDefs() << "\n";

        for (unsigned i = 0; i < targetInstrCount; ++i) {
            MCInst inst;
            inst.setOpcode(opcode);
            inst.clear();

            for (unsigned j = 0; j < numOperands; ++j) {
                const MCOperandInfo &opInfo = desc.operands()[j];

                // TIED_TO points to operand which this has to be identical to. see MCInstrDesc.h:41
                if (opInfo.Constraints & (1 << MCOI::TIED_TO)) {
                    // this operand must be identical to another operand
                    unsigned tiedToOp = (opInfo.Constraints >> (4 + MCOI::TIED_TO * 4)) & 0xF;
                    inst.addOperand(inst.getOperand(tiedToOp));
                } else {
                    switch (opInfo.OperandType) {
                    case MCOI::OPERAND_REGISTER: {
                        // search for unused register and add it as operand
                        const MCRegisterClass &RegClass = MRI->getRegClass(opInfo.RegClass);
                        bool foundRegister = false;
                        for (MCRegister reg : RegClass) {
                            if (reg.id() >= maxReg || reg.id() == 58)
                                // RIP register (58) is included in GR64 class which is a bug
                                // see X86RegisterInfo.td:586
                                continue;

                            // check if sub or superregisters are in use
                            if (std::any_of(
                                    usedRegisters.begin(), usedRegisters.end(),
                                    [reg, this](MCRegister r) { return TRI->regsOverlap(reg, r); }))
                                continue;

                            inst.addOperand(MCOperand::createReg(reg));
                            usedRegisters.insert(reg);
                            foundRegister = true;
                            break;
                        }
                        if (!foundRegister) {
                            outs() << "all supported registers of this class are in use" << "\n";
                            // TODO handle this case properly
                            return instructions;
                        }
                        break;
                    }
                    case MCOI::OPERAND_IMMEDIATE:
                        // Immediate operand (e.g., 42)
                        break;
                    case MCOI::OPERAND_MEMORY:
                        errs() << "instructions accessing memory are not supported at this time";
                        return {};
                    case MCOI::OPERAND_PCREL:
                        errs() << "branches are not supported at this time";
                        return {};
                    default:
                        errs() << "unknown operand type";
                        return {};
                    }
                }
            }
            instructions.push_back(inst);
        }
        return instructions;
    }

    // TODO find ISA independent function in llvm
    std::string genSaveRegister(MCRegister reg) {
        MCInst inst;
        inst.setOpcode(getOpcode("PUSH64r"));
        inst.clear();
        inst.addOperand(MCOperand::createReg(reg));
        std::string result;
        llvm::raw_string_ostream rso(result); // Wrap the string with raw_ostream
        MIP->printInst(&inst, 0, "", *MSTI, rso);
        return result;
    }

    // TODO find ISA independent function in llvm
    std::string genRestoreRegister(MCRegister reg) {
        MCInst inst;
        inst.setOpcode(getOpcode("POP64r"));
        inst.clear();
        inst.addOperand(MCOperand::createReg(reg));
        std::string result;
        llvm::raw_string_ostream rso(result); // Wrap the string with raw_ostream
        MIP->printInst(&inst, 0, "", *MSTI, rso);
        return result;
    }

    // filter which instructions get exluded
    bool isValid(MCInstrDesc instruction) {
        return !instruction.isPseudo() && !instruction.mayLoad() && !instruction.mayStore();
    }

    // get Opcode for instruction
    // TODO there probably is a mechanism for this in llvm -> find and use
    unsigned getOpcode(std::string instructionName) {
        for (unsigned i = 0; i < MCII->getNumOpcodes(); ++i) {
            if (MCII->getName(i) == instructionName) {
                return i;
            }
        }
        errs() << "Instruction not found: " << instructionName << "\n";
        return 1;
    }
};

int main(int argc, char **argv) {
    if (argc < 2) {
        errs() << "Usage: " << argv[0] << " <instruction_name>" << " num_instr\n";
        return 1;
    }
    int numInst = 6;
    if (argc == 3) {
        numInst = atoi(argv[2]);
    }

    auto generator = BenchmarkGenerator();
    generator.SetUp();
    StringRef instrName(argv[1]);
    unsigned opcode = generator.getOpcode(instrName.data());
    generator.genTPBenchmark(opcode, numInst, outs);
    return 0;
}

// Print the instruction
// MIP->printInst(&Inst, 0, "", *STI, outs());
// outs() << "\n";
// // Determine operand type
// switch (opType) {
// case MCOI::OPERAND_REGISTER:
//     // Register operand (e.g., reg1)
//     break;
// case MCOI::OPERAND_IMMEDIATE:
//     // Immediate operand (e.g., 42)
//     break;
// case MCOI::OPERAND_MEMORY:
//     // Memory operand (e.g., [rax])
//     break;
// case MCOI::OPERAND_PCREL:
//     // PC-relative offset (e.g., branch target)
//     break;
// default:
//     // Handle other types or unknown
//     break;
// }

// outs() << TRI->getNumSupportedRegs(*MF) << "\n";
// const X86Subtarget &ST = MF->getSubtarget<X86Subtarget>();
// const X86RegisterInfo *RegInfo = ST.getRegisterInfo();
// outs() << RegInfo->getNumSupportedRegs(*MF) << "\n";
// outs() << "RegInfo->getNumRegs()" << RegInfo->getNumRegs() << "\n";

// variant put loop increment in mid of instructions
// stream() << benchTemplate.preLoop;
// stream() << benchTemplate.beginLoop;
// unsigned halfSize = instructions.size() / 2;
// auto it = instructions.begin();
// for (unsigned i; i < instructions.size(); i++) {
//     MCInst inst = *it;
//     MIP->printInst(&inst, 0, "", *MSTI, stream());
//     stream() << "\n";
//     if (i == halfSize - 1)
//         stream() << benchTemplate.midLoop;
//     it++;
// }

void old_bad_code() {
    // auto model = STI->getSchedModel();
    // auto table = model.getSchedClassDesc(0);

    // outs() << "Trying TM" << "\n";
    // // MCCodeEmitter MCContext
    // TargetOptions Options;
    // auto TM =
    //     TheTarget->createTargetMachine(TargetTripleStr, "ivybridge", "", Options,
    //     std::nullopt);
    // assert(TM && "Unable to create TargetMachine!");
    // auto Machine = std::unique_ptr<TargetMachine>(
    //     TheTarget->createTargetMachine(Triple::normalize("x86_64--"), "", "", Options,
    //     std::nullopt,
    //                                    std::nullopt, CodeGenOptLevel::Aggressive));

    // LLVMContext Context;
    // // std::unique_ptr<Module> M = std::make_unique<Module>("dummy_module", Context);
    // // static FunctionType *get(Type * Result, ArrayRef<Type *> Params, bool isVarArg);
    // outs() << "Trying FTy" << "\n";
    // // Define a simple function: `void dummy() { }`
    // // auto FTy = FunctionType::get(Type::getInt64Ty(Context), false);
    // auto FTy = FunctionType::get(Type::getVoidTy(Context), false);
    // assert(FTy && "Unable to create FunctionType!");
    // // static Function *Create(FunctionType *Ty, LinkageTypes Linkage,unsigned AddrSpace)
    // outs() << "Trying Function" << "\n";
    // // TODO addrSpace??
    // Function *F = Function::Create(FTy, Function::ExternalLinkage, 0);
    // assert(F && "Unable to create Function!");
    // outs() << "Trying TSTI" << "\n";
    // const TargetSubtargetInfo &TSTI = *TM->getSubtargetImpl(*F);
    // // assert(TSTI && "Unable to create TargetSubtargetInfo!");
    // // explicit MCContext(const Triple &TheTriple, const MCAsmInfo *MAI,
    // //                  const MCRegisterInfo *MRI, const MCSubtargetInfo *MSTI,
    // outs() << "trying MachineFunction" << "\n";
    // MCContext Ctx = MCContext(Triple(TargetTripleStr), MAI, MRI, MSTI);
    // // assert(Ctx && "Unable to create MCContext!");
    // std::unique_ptr<MachineModuleInfo> MMI =
    // std::make_unique<MachineModuleInfo>(Machine.get()); const TargetSubtargetInfo &TSTI =
    // *Machine->getSubtargetImpl(*F);

    // unsigned FunctionNum = 42;
    // std::unique_ptr<MachineFunction> MF =
    //     std::make_unique<MachineFunction>(*F, *Machine, STI, MMI->getContext(), FunctionNum);

    // //  MachineFunction(Function &F, const TargetMachine &Target,
    // //   const TargetSubtargetInfo &STI, MCContext &Ctx,
    // //   unsigned FunctionNum);
    // outs() << "trying MachineFunction" << "\n";
    // auto MF = MachineFunction(*F, *TM, TSTI, Ctx, 42);

    // auto TRI = MF.getSubtarget().getRegisterInfo();
    // outs() << TRI->getNumSupportedRegs(MF) << "\n";

    /*



    // copied from InstrRefLDVTest.cpp
    LLVMContext Ctx;
    std::unique_ptr<Module> Mod;
    std::unique_ptr<TargetMachine> Machine;
    std::unique_ptr<MachineFunction> MF;
    std::unique_ptr<MachineModuleInfo> MMI;

    // InstrRefLDVTest() : Ctx(), Mod(std::make_unique<Module>("beehives", Ctx)) {}
    outs() << "trying SetDataLayout" << "\n";
    Mod->setDataLayout("e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-"
                       "f80:128-n8:16:32:64-S128");

    outs() << "trying Triple" << "\n";
    Triple TargetTriple("x86_64--");
    std::string Error;
    const Target *T = TargetRegistry::lookupTarget("", TargetTriple, Error);

    outs() << "trying Machine" << "\n";
    TargetOptions Options;
    Machine = std::unique_ptr<TargetMachine>(
        T->createTargetMachine(Triple::normalize("x86_64--"), "", "", Options, std::nullopt,
                               std::nullopt, CodeGenOptLevel::Aggressive));

    auto Type = FunctionType::get(Type::getVoidTy(Ctx), false);
    outs() << "trying F" << "\n";
    auto F = Function::Create(Type, GlobalValue::ExternalLinkage, "Test", &*Mod);
    // auto F = Function::Create(Type, GlobalValue::ExternalLinkage, "Test"); /own

    outs() << "trying MMI" << "\n";
    unsigned FunctionNum = 42;
    MMI = std::make_unique<MachineModuleInfo>(Machine.get());
    outs() << "trying STI" << "\n";
    const TargetSubtargetInfo &STI = *Machine->getSubtargetImpl(*F);

    outs() << "trying MachineFunction" << "\n";
    MF = std::make_unique<MachineFunction>(*F, *Machine, STI, MMI->getContext(), FunctionNum);

    // MF.init(); // TODO
    // outs() << "trying" << "\n";
    MF->print(outs());
    // outs() << "success" << "\n";

    auto TRI = MF->getSubtarget().getRegisterInfo();
    outs() << "TRI created" << "\n";

    for (unsigned i = 0; i < TRI->getNumRegs(); i++) {
        auto reg_name = TRI->getName(i);
        outs() << "getTargetRegisterInfo: " << reg_name << "\n";
    }*/

    // outs() << "STI->getCPU(): " << STI->getCPU() << "\n";
    // outs() << "STI->getFeatureString(): " << STI->getFeatureString() << "\n";
    // for (auto feature : STI->getEnabledProcessorFeatures()) {
    //     outs() << "STI->getEnabledProcessorFeatures(): " << feature.Key << "\n";
    // }
    // auto allocatableRegs = TRI->getAllocatableSet(MF);

    // for (unsigned Reg = 0; Reg < allocatableRegs.size(); ++Reg) {
    //     if (allocatableRegs.test(Reg)) { // Check if the register is allocatable
    //         outs() << TRI->getName(Reg) << "\n";
    //     }
    // }

    // auto &regInfo = MF.getRegInfo();
    // regInfo.isAllocatable(MCRegister PhysReg)

    // outs() << "MF.getSubtarget().getCPU(): " << MF.getSubtarget().getCPU() << "\n";
    // outs() << "TM->getTargetCPU(): " << TM->getTargetCPU() << "\n";

    // TODO
    // STI->isCPUStringValid();
}