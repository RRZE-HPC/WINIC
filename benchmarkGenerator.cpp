#include "MCTargetDesc/X86BaseInfo.h"
#include "MCTargetDesc/X86MCTargetDesc.h"
#include "customErrors.cpp"
#include "templates.cpp"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/RegisterBankInfo.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetLowering.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrDesc.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/TargetParser/X86TargetParser.h"
#include <algorithm>
#include <csetjmp>
#include <cstdlib>
#include <dlfcn.h>
#include <fcntl.h>
#include <getopt.h>
#include <list>
#include <math.h>
#include <memory>
#include <set>
#include <string>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace llvm;

class BenchmarkGenerator {
  public:
    LLVMContext Ctx;
    std::unique_ptr<Module> Mod;
    std::unique_ptr<TargetMachine> Machine;
    std::unique_ptr<MachineFunction> MF;
    std::unique_ptr<MachineModuleInfo> MMI;
    const TargetRegisterInfo *TRI;
    // MCAsmParser *Parser;
    // MCTargetAsmParser *TAP;
    MCRegisterInfo *MRI;
    MCAsmInfo *MAI;
    MCInstrInfo *MCII;
    MCSubtargetInfo *MSTI;
    MCInstPrinter *MIP;
    // SourceMgr SrcMgr;
    // SmallVector<char> outVector;
    unsigned MaxReg;
    BenchmarkGenerator() : Ctx(), Mod(std::make_unique<Module>("beehives", Ctx)) {}
    void setUp() {
        LLVMInitializeX86Target();
        LLVMInitializeX86TargetInfo();
        LLVMInitializeX86TargetMC();
        LLVMInitializeX86AsmPrinter();
        // LLVMInitializeX86AsmParser();
        // LLVMInitializeX86Disassembler();
        // LLVMInitializeX86TargetMCA();
        StringRef TargetTripleStr = "x86_64-pc-linux";
        // StringRef TargetTripleStr = "x86_64--";
        // copied from InstrRefLDVTest.cpp
        Mod->setDataLayout("e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-"
                           "f80:128-n8:16:32:64-S128");
        Triple TargetTriple(TargetTripleStr);
        std::string Error;
        const Target *TheTarget = TargetRegistry::lookupTarget("", TargetTriple, Error);
        TargetOptions Options;
        Machine = std::unique_ptr<TargetMachine>(TheTarget->createTargetMachine(
            Triple::normalize(TargetTripleStr), "znver4", "", Options, std::nullopt, std::nullopt,
            CodeGenOptLevel::Aggressive));
        assert(Machine && "Unable to create Machine");
        FunctionType *Type = FunctionType::get(Type::getVoidTy(Ctx), false);
        assert(Type && "Unable to create Type");
        Function *F = Function::Create(Type, GlobalValue::ExternalLinkage, "Test", &*Mod);
        assert(Type && "Unable to create Function");
        // auto F = Function::Create(Type, GlobalValue::ExternalLinkage, "Test");
        // /own
        unsigned FunctionNum = 42;
        MMI = std::make_unique<MachineModuleInfo>(Machine.get());
        const TargetSubtargetInfo &STI = *Machine->getSubtargetImpl(*F);
        MF = std::make_unique<MachineFunction>(*F, *Machine, STI, MMI->getContext(), FunctionNum);
        TRI = MF->getSubtarget().getRegisterInfo();
        // copied from InstrRefLDVTest.cpp
        MaxReg = TRI->getNumSupportedRegs(*MF);
        MRI = TheTarget->createMCRegInfo(TargetTripleStr);
        assert(MRI && "Unable to create register info!");
        MCTargetOptions MCOptions;
        MAI = TheTarget->createMCAsmInfo(*MRI, TargetTripleStr, MCOptions);
        assert(MAI && "Unable to create asm info!");
        MCII = TheTarget->createMCInstrInfo();
        assert(MCII && "Unable to create MCInnstr info!");
        MSTI = TheTarget->createMCSubtargetInfo(TargetTripleStr, "znver4", "");
        assert(MSTI && "Unable to create MCSubtargetInfo!");
        // set syntax variant here
        MIP = TheTarget->createMCInstPrinter(Triple(TargetTripleStr), 1, *MAI, *MCII, *MRI);
        assert(MIP && "Unable to create MCInstPrinter!");
    }
    // generates a throughput benchmark for the instruction with Opcode. Tries to generate
    // TargetInstrCount different instructions and ten unrolls them by UnrollCount. Updates
    // TargetInstrCount to the actual number of instructions in the loop (unrolls included)
    std::pair<ErrorCode, std::string> genTPBenchmark(unsigned Opcode, unsigned *TargetInstrCount,
                                                     unsigned UnrollCount) {
        std::string result;
        llvm::raw_string_ostream rso(result);
        auto benchTemplate = x86Template();
        // extract list of registers used by the template
        std::set<MCRegister> usedRegisters;
        for (unsigned i = 0; i < MRI->getNumRegs(); i++) {
            MCRegister reg = MCRegister::from(i);
            if (benchTemplate.usedRegisters.find(TRI->getRegAsmName(reg).lower().data()) !=
                benchTemplate.usedRegisters.end())
                usedRegisters.insert(reg);
        }
        if (benchTemplate.usedRegisters.size() != usedRegisters.size()) {
            errs() << "could not determine all registers used by the template\n";
            return {ERROR_TEMPLATE, ""}; // probably error in template TODO error type
        }
        auto [EC, instructions] = genTPInnerLoop(Opcode, *TargetInstrCount, usedRegisters);
        if (EC != SUCCESS) return {EC, ""};
        // update TargetInstructionCount to actual number of instructions generated
        *TargetInstrCount = instructions.size() * UnrollCount;
        // save registers used (genTPInnerLoop updates usedRegisters)
        std::string saveRegs;
        std::string restoreRegs;
        for (MCRegister reg : usedRegisters) {
            if (TRI->isCalleeSavedPhysReg(reg, *MF)) {
                // generate code to save and restore register
                // this currently also saves registers already saved in the template
                // which is redundant but not harmful
                auto [EC1, save] = genSaveRegister(reg);
                if (EC1 != SUCCESS) return {EC1, ""};
                saveRegs.append(save).append("\n");
                auto [EC2, restore] = genRestoreRegister(reg);
                if (EC2 != SUCCESS) return {EC2, ""};
                restoreRegs.insert(0, restore.append("\n"));
            }
        }
        rso << "#define NINST " << *TargetInstrCount << "\n";
        rso << benchTemplate.preLoop;
        rso << saveRegs;
        rso << benchTemplate.beginLoop;
        for (unsigned i = 0; i < UnrollCount; i++) {
            for (auto inst : instructions) {
                // TODO this is very ugly, these # instructions have isCodeGenOnly flag, how can we
                // check it? if found, add check to isValid()
                std::string temp;
                llvm::raw_string_ostream tso(temp);
                MIP->printInst(&inst, 0, "", *MSTI, tso);
                if (temp.find("#") != std::string::npos) return {IS_CODE_GEN_ONLY, ""};
                MIP->printInst(&inst, 0, "", *MSTI, rso);
                rso << "\n";
            }
        }
        rso << benchTemplate.midLoop;
        rso << benchTemplate.endLoop;
        rso << restoreRegs;
        rso << benchTemplate.postLoop << "\n";
        return {SUCCESS, result};
    }
    void temp(unsigned Opcode) {
        const MCInstrDesc &desc = MCII->get(Opcode);
        if (desc.TSFlags & X86::FEATURE_64BIT) outs() << "FEATURE_64BIT bit\n";
        if (desc.TSFlags & X86::FeatureSSE2) outs() << "FeatureSSE2 bit\n";
        if (desc.TSFlags & X86II::PrefixByte) outs() << "PrefixByte bit\n";
        outs().flush();
    }
    // generates a benchmark loop to measure throughput of an instruction
    // tries to generate targetInstrCount independent instructions for the inner
    // loop might generate less instructions than targetInstrCount if there are
    // not enough registers updates usedRegisters
    std::pair<ErrorCode, std::list<MCInst>> genTPInnerLoop(unsigned Opcode,
                                                           unsigned TargetInstrCount,
                                                           std::set<MCRegister> &UsedRegisters) {
        std::list<MCInst> instructions;
        const MCInstrDesc &desc = MCII->get(Opcode);
        if (isValid(desc) != SUCCESS) return {isValid(desc), {}};
        // MSTI->getFeatureBits().test(X86::FeatureFMA); TODO
        // STI.hasFeature(X86::Is16Bit) maybe also works
        unsigned numOperands = desc.getNumOperands();
        // the first numDefs operands are destination operands
        // outs() << "desc.getNumDefs() " << desc.getNumDefs() << "\n";
        for (unsigned i = 0; i < TargetInstrCount; ++i) {
            MCInst inst;
            inst.setOpcode(Opcode);
            inst.clear();
            for (unsigned j = 0; j < numOperands; ++j) {
                const MCOperandInfo &opInfo = desc.operands()[j];
                // TIED_TO points to operand which this has to be identical to.
                // see MCInstrDesc.h:41
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
                            if (reg.id() >= MaxReg || reg.id() == 58)
                                // RIP register (58) is included in GR64 class which is a bug
                                // see X86RegisterInfo.td:586
                                continue;
                            // check if sub or superregisters are in use
                            if (std::any_of(
                                    UsedRegisters.begin(), UsedRegisters.end(),
                                    [reg, this](MCRegister R) { return TRI->regsOverlap(reg, R); }))
                                continue;
                            inst.addOperand(MCOperand::createReg(reg));
                            UsedRegisters.insert(reg);
                            foundRegister = true;
                            break;
                        }
                        if (!foundRegister) {
                            // outs() << "all supported registers of this class are in use"
                            //        << "\n";
                            // TODO handle this case properly
                            return {SUCCESS, instructions};
                        }
                        break;
                    }
                    case MCOI::OPERAND_IMMEDIATE:
                        inst.addOperand(MCOperand::createImm(42));
                        break;
                    case MCOI::OPERAND_MEMORY:
                        // errs() << "instructions accessing memory are not supported at this "
                        //           "time\n";
                        return {MEMORY_OPERAND, {}};
                    case MCOI::OPERAND_PCREL:
                        // errs() << "branches are not supported at this time\n";
                        return {PCREL_OPERAND, {}};
                        ;
                    default:
                        // errs() << "unknown operand type\n";
                        return {UNKNOWN_OPERAND, {}};
                        ;
                    }
                }
            }
            instructions.push_back(inst);
        }
        return {SUCCESS, instructions};
    }
    std::pair<ErrorCode, MCRegister> getSupermostRegister(MCRegister Reg) {
        for (unsigned i = 0; i < 100; i++) {
            if (TRI->superregs(Reg).empty()) return {SUCCESS, Reg};
            Reg = *TRI->superregs(Reg).begin(); // take firs superreg
        }
        return {ERROR_GENERIC, NULL};
    }
    // TODO find ISA independent function in llvm
    std::pair<ErrorCode, std::string> genSaveRegister(MCRegister Reg) {
        ErrorCode EC;
        // we dont want to save sub registers
        std::tie(EC, Reg) = getSupermostRegister(Reg);
        if (EC != SUCCESS) return {EC, ""};
        MCInst inst;
        inst.setOpcode(getOpcode("PUSH64r"));
        inst.clear();
        inst.addOperand(MCOperand::createReg(Reg));
        std::string result;
        llvm::raw_string_ostream rso(result); // Wrap the string with raw_ostream
        MIP->printInst(&inst, 0, "", *MSTI, rso);
        return {SUCCESS, result};
    }
    // TODO find ISA independent function in llvm
    std::pair<ErrorCode, std::string> genRestoreRegister(MCRegister Reg) {
        ErrorCode EC;
        std::tie(EC, Reg) = getSupermostRegister(Reg);
        if (EC != SUCCESS) return {EC, ""};
        MCInst inst;
        inst.setOpcode(getOpcode("POP64r"));
        inst.clear();
        inst.addOperand(MCOperand::createReg(Reg));
        std::string result;
        llvm::raw_string_ostream rso(result);
        MIP->printInst(&inst, 0, "", *MSTI, rso);
        return {SUCCESS, result};
    }
    // filter which instructions get exluded
    ErrorCode isValid(MCInstrDesc Instruction) {
        if (Instruction.isPseudo()) return PSEUDO_INSTRUCTION;
        if (Instruction.mayLoad()) return MAY_LOAD;
        if (Instruction.mayStore()) return MAY_STORE;
        if (Instruction.isCall()) return IS_CALL;
        if (Instruction.isMetaInstruction()) return IS_META_INSTRUCTION;
        if (Instruction.isReturn()) return IS_RETURN;
        if (Instruction.isBranch()) return IS_BRANCH; // TODO uops has TP, how?
        if (X86II::isPrefix(Instruction.TSFlags)) return INSTRUCION_PREFIX;
        return SUCCESS;
    }
    // get Opcode for instruction
    // TODO there probably is a mechanism for this in llvm -> find and use
    unsigned getOpcode(std::string InstructionName) {
        for (unsigned i = 0; i < MCII->getNumOpcodes(); ++i) {
            if (MCII->getName(i) == InstructionName) {
                return i;
            }
        }
        errs() << "Instruction not found: " << InstructionName << "\n";
        return 1;
    }
};
